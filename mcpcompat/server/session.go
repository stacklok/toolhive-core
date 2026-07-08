// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"sync"
	"sync/atomic"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// ClientSession represents an active client session. It mirrors mcp-go's
// server.ClientSession.
type ClientSession interface {
	// Initialize marks the session as fully initialized.
	Initialize()
	// Initialized reports whether the session is ready for notifications.
	Initialized() bool
	// NotificationChannel provides a channel for sending notifications to the client.
	NotificationChannel() chan<- mcp.JSONRPCNotification
	// SessionID uniquely identifies the session.
	SessionID() string
}

// SessionWithTools is a ClientSession that carries per-session tools. ToolHive's
// vMCP layer uses this to project a per-session tool set.
//
// Overlays set here are stored and reconciled onto the session's live go-sdk
// server (syncSessionTools) once a server is bound to the session (at
// registration, or immediately if already bound): added tools are registered
// via srv.AddTool and removed tools via srv.RemoveTools, which also drives
// go-sdk's automatic notifications/tools/list_changed emission when
// WithToolCapabilities(true) is set. So per-session tool changes take effect
// on an already-connected session at runtime.
type SessionWithTools interface {
	ClientSession
	// GetSessionTools returns the session's tools. Thread-safe.
	GetSessionTools() map[string]ServerTool
	// SetSessionTools sets the session's tools. Thread-safe.
	SetSessionTools(tools map[string]ServerTool)
}

// SessionWithResources is a ClientSession that carries per-session resources.
type SessionWithResources interface {
	ClientSession
	// GetSessionResources returns the session's resources. Thread-safe.
	GetSessionResources() map[string]ServerResource
	// SetSessionResources sets the session's resources. Thread-safe.
	SetSessionResources(resources map[string]ServerResource)
}

// SessionIdManager governs MCP session ID lifecycle. It mirrors mcp-go's
// server.SessionIdManager so ToolHive's implementation can be supplied via
// WithSessionIdManager.
type SessionIdManager interface {
	// Generate returns a new session ID.
	Generate() string
	// Validate reports whether a session ID is valid; isTerminated is true if
	// the ID is valid but belongs to a terminated session.
	Validate(sessionID string) (isTerminated bool, err error)
	// Terminate marks a session ID terminated; isNotAllowed is true if policy
	// prevents client termination.
	Terminate(sessionID string) (isNotAllowed bool, err error)
}

// clientSession is the concrete ClientSession backed by a go-sdk ServerSession.
type clientSession struct {
	id          string
	initialized atomic.Bool
	registered  atomic.Bool
	notifCh     chan mcp.JSONRPCNotification
	goSession   atomic.Pointer[gosdk.ServerSession]

	// owner and boundServer are set when the session's go-sdk server is bound
	// (at registration). They let SetSessionTools/SetSessionResources reconcile
	// the per-session overlay onto the live go-sdk server at runtime.
	owner       *MCPServer
	boundServer atomic.Pointer[gosdk.Server]

	mu        sync.RWMutex
	tools     map[string]ServerTool
	resources map[string]ServerResource
	// sdkToolNames tracks the tool names this session has added to its go-sdk
	// server, so a later SetSessionTools can remove the ones that went away.
	sdkToolNames map[string]struct{}
}

func newClientSession(id string) *clientSession {
	cs := &clientSession{
		id:      id,
		notifCh: make(chan mcp.JSONRPCNotification, 64),
	}
	// Drain the notification channel to avoid blocking senders. Forwarding
	// server-initiated notifications onto the go-sdk session is a known gap.
	go func() {
		for range cs.notifCh { //nolint:revive // intentional drain
		}
	}()
	return cs
}

func (c *clientSession) SessionID() string { return c.id }

func (c *clientSession) Initialize() { c.initialized.Store(true) }

func (c *clientSession) Initialized() bool { return c.initialized.Load() }

func (c *clientSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return c.notifCh }

func (c *clientSession) GetSessionTools() map[string]ServerTool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]ServerTool, len(c.tools))
	for k, v := range c.tools {
		out[k] = v
	}
	return out
}

func (c *clientSession) SetSessionTools(tools map[string]ServerTool) {
	c.mu.Lock()
	c.tools = make(map[string]ServerTool, len(tools))
	for k, v := range tools {
		c.tools[k] = v
	}
	c.mu.Unlock()
	// Reconcile the overlay onto the live go-sdk server if one is bound.
	if srv := c.boundServer.Load(); srv != nil && c.owner != nil {
		c.owner.syncSessionTools(srv, c)
	}
}

func (c *clientSession) GetSessionResources() map[string]ServerResource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]ServerResource, len(c.resources))
	for k, v := range c.resources {
		out[k] = v
	}
	return out
}

func (c *clientSession) SetSessionResources(resources map[string]ServerResource) {
	c.mu.Lock()
	c.resources = make(map[string]ServerResource, len(resources))
	for k, v := range resources {
		c.resources[k] = v
	}
	c.mu.Unlock()
	if srv := c.boundServer.Load(); srv != nil && c.owner != nil {
		c.owner.syncSessionResources(srv, c)
	}
}

// sessionContextKey is the context key under which the ClientSession is stored.
type sessionContextKey struct{}

// contextWithSession looks up (or creates) the clientSession for the given
// go-sdk ServerSession and stores it in the context.
func (s *MCPServer) contextWithSession(ctx context.Context, ss *gosdk.ServerSession) context.Context {
	if ss == nil {
		return ctx
	}
	cs := s.sessionFor(ss.ID())
	cs.goSession.Store(ss)
	return context.WithValue(ctx, sessionContextKey{}, ClientSession(cs))
}

// sessionFor returns the registered clientSession for id, creating it if needed.
func (s *MCPServer) sessionFor(id string) *clientSession {
	if v, ok := s.sessions.Load(id); ok {
		return v.(*clientSession)
	}
	cs := newClientSession(id)
	actual, _ := s.sessions.LoadOrStore(id, cs)
	return actual.(*clientSession)
}

// registerAndSync registers the session for the given go-sdk ServerSession,
// firing the OnRegisterSession hooks exactly once and then reconciling any
// per-session tool/resource overlay the hooks installed onto srv (the go-sdk
// server bound to this session). It is invoked from the initialize dispatch
// middleware (matching mcp-go's on-initialize timing) and, defensively, from the
// InitializedHandler; the once-guard makes the second call a cheap no-op.
func (s *MCPServer) registerAndSync(ctx context.Context, ss *gosdk.ServerSession, srv *gosdk.Server) {
	if ss == nil {
		return
	}
	cs := s.sessionFor(ss.ID())
	cs.goSession.Store(ss)
	cs.owner = s
	cs.boundServer.Store(srv)
	// Mark the session local: it was initialized on this instance, so the go-sdk
	// StreamableHTTPHandler owns it and subsequent requests must route there
	// rather than through the cross-replica rehydration path.
	s.localSessions.Store(ss.ID(), struct{}{})
	if !cs.registered.CompareAndSwap(false, true) {
		return
	}
	cs.Initialize()
	if s.hooks != nil {
		s.hooks.registerSession(ctx, cs)
	}
	// The hooks may have installed per-session tools/resources via
	// SetSessionTools/SetSessionResources; those calls reconcile onto srv
	// themselves now that boundServer is set. Sync once more here to cover any
	// overlay set before the server was bound.
	s.syncSessionTools(srv, cs)
	s.syncSessionResources(srv, cs)
}

// syncSessionTools reconciles the session's tool overlay onto its go-sdk server:
// tools present in the overlay are added (overwriting by name) and tools that
// were previously added for this session but are no longer present are removed.
//
// go-sdk's AddTool panics unless the tool's input schema is non-nil with
// top-level type "object". normalizeObjectSchema only normalizes nil/empty
// schemas to {"type":"object"}; non-object schemas ($ref, oneOf, boolean, or an
// object schema with type omitted) pass through verbatim to mirror mcp-go, so
// AddTool can still panic here for a malformed overlay schema. This path runs on
// the live session goroutine (from before-hooks during a request), so an
// unrecovered panic would crash the session/process mid-request. Each tool is
// therefore registered via addSessionTool, which recovers such a panic, logs it,
// and skips the offending tool — one bad overlay schema does not take down the
// session, and the remaining tools in the same overlay still register.
func (s *MCPServer) syncSessionTools(srv *gosdk.Server, cs *clientSession) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	newNames := make(map[string]struct{}, len(cs.tools))
	for name, st := range cs.tools {
		gt, err := toGoSDKTool(st.Tool)
		if err != nil {
			if s.logger != nil {
				s.logger.Warn("skipping per-session tool: conversion failed", "tool", name, "error", err)
			}
			continue
		}
		if !s.addSessionTool(srv, gt, st.Handler) {
			if s.logger != nil {
				s.logger.Warn("skipping per-session tool: AddTool rejected its schema", "tool", name)
			}
			continue
		}
		newNames[name] = struct{}{}
	}
	var removed []string
	for name := range cs.sdkToolNames {
		if _, ok := newNames[name]; !ok {
			removed = append(removed, name)
		}
	}
	if len(removed) > 0 {
		srv.RemoveTools(removed...)
	}
	cs.sdkToolNames = newNames
}

// addSessionTool registers a tool on a per-session go-sdk server, recovering the
// panic go-sdk's AddTool raises when a tool's input schema is non-nil but not
// type:"object" (see normalizeObjectSchema). It returns false (and logs) when the
// tool could not be registered, so the caller skips it rather than crashing the
// session. This mirrors the fault-isolation recover pattern used in
// wrapToolHandler (server.go).
func (s *MCPServer) addSessionTool(srv *gosdk.Server, gt *gosdk.Tool, h ToolHandlerFunc) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			if s.logger != nil {
				s.logger.Error("per-session AddTool panicked; skipping tool",
					"tool", gt.Name, "panic", r)
			}
			ok = false
		}
	}()
	srv.AddTool(gt, s.wrapToolHandler(h))
	return true
}

// syncSessionResources adds the session's resource overlay onto its go-sdk
// server. Resources are add-only here (ToolHive sets them once at registration).
func (s *MCPServer) syncSessionResources(srv *gosdk.Server, cs *clientSession) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for _, sr := range cs.resources {
		gr := &gosdk.Resource{}
		if err := jsonConvert(sr.Resource, gr); err != nil {
			continue
		}
		srv.AddResource(gr, s.wrapResourceHandler(sr.Handler))
	}
}

// isLocalSession reports whether the session ID was initialized on this server
// instance (see MCPServer.localSessions).
func (s *MCPServer) isLocalSession(id string) bool {
	_, ok := s.localSessions.Load(id)
	return ok
}

// forgetSession drops all local bookkeeping for a session ID. It is called when
// a session is terminated (DELETE) so a later request with the same ID is not
// mistaken for a live local session.
func (s *MCPServer) forgetSession(id string) {
	s.localSessions.Delete(id)
	s.sessions.Delete(id)
}

// bindRehydratedSession binds the clientSession for a session that was created
// on another replica and is being rehydrated here (see StreamableHTTPServer's
// rehydration path). Unlike registerAndSync it does NOT fire OnRegisterSession
// and does NOT mark the session local: a rehydrated session skips the
// initialize handshake (and therefore ToolHive's Generate/CreateSession
// two-phase creation), and cross-replica capability projection is driven by the
// before-list/before-call hooks (ToolHive's lazy per-session tool injection),
// not by OnRegisterSession. Binding owner+boundServer here lets those hooks'
// SetSessionTools/SetSessionResources reconcile the overlay onto srv.
func (s *MCPServer) bindRehydratedSession(id string, ss *gosdk.ServerSession, srv *gosdk.Server) {
	cs := s.sessionFor(id)
	cs.goSession.Store(ss)
	cs.owner = s
	cs.boundServer.Store(srv)
	cs.Initialize()
}

// ClientSessionFromContext returns the ClientSession stored in ctx, or nil.
func ClientSessionFromContext(ctx context.Context) ClientSession {
	if v, ok := ctx.Value(sessionContextKey{}).(ClientSession); ok {
		return v
	}
	return nil
}
