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
// NOTE: overlays set here are stored and merged when a go-sdk server is built
// for the session (see MCPServer.buildServer). Making per-session tool changes
// take effect on an already-connected go-sdk session at runtime (live
// list_changed dispatch) is the integration point that needs validation against
// ToolHive's vMCP flow before this shim can fully replace mcp-go there.
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
	notifCh     chan mcp.JSONRPCNotification
	goSession   atomic.Pointer[gosdk.ServerSession]

	mu        sync.RWMutex
	tools     map[string]ServerTool
	resources map[string]ServerResource
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
	defer c.mu.Unlock()
	c.tools = make(map[string]ServerTool, len(tools))
	for k, v := range tools {
		c.tools[k] = v
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
	defer c.mu.Unlock()
	c.resources = make(map[string]ServerResource, len(resources))
	for k, v := range resources {
		c.resources[k] = v
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

// onInitialized fires when a go-sdk session finishes initialization. It
// registers the session and invokes the OnRegisterSession hooks.
func (s *MCPServer) onInitialized(ctx context.Context, req *gosdk.InitializedRequest) {
	if req == nil || req.Session == nil {
		return
	}
	cs := s.sessionFor(req.Session.ID())
	cs.goSession.Store(req.Session)
	cs.Initialize()
	if s.hooks != nil {
		s.hooks.registerSession(ctx, cs)
	}
}

// ClientSessionFromContext returns the ClientSession stored in ctx, or nil.
func ClientSessionFromContext(ctx context.Context) ClientSession {
	if v, ok := ctx.Value(sessionContextKey{}).(ClientSession); ok {
		return v
	}
	return nil
}
