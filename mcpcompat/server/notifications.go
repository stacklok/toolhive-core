// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ErrUnsupportedNotification is returned by SendNotificationToClient for a
// notification method the shim cannot map onto a typed go-sdk sender (the
// go-sdk exposes no generic notification sender; only the well-known
// progress/message methods are supported). It lets callers distinguish an
// unsupported method from a session/transport error.
var ErrUnsupportedNotification = errors.New("unsupported notification method")

// SendNotificationToClient sends a single server-initiated notification to the
// client bound to the session in ctx (the session a tool/prompt/resource
// handler is running under). It is the per-session counterpart to
// SendNotificationToAllClients and mirrors mcp-go's
// server.MCPServer.SendNotificationToClient, which ToolHive's vMCP layer uses
// to forward a backend's mid-call progress/logging notifications to the
// downstream client on the same session.
//
// It returns ErrNoActiveSession when ctx carries no session (e.g. a
// non-session context), a descriptive error when the session has no bound
// go-sdk session yet, and ErrUnsupportedNotification for a method the shim
// cannot map. Callers that forward best-effort (e.g. a relay) can treat a
// no-session error as a no-op.
//
// go-sdk backing and the same limitation as the broadcast variant: only the
// well-known MCP notification methods map onto go-sdk's typed senders:
//
//   - notifications/progress -> ServerSession.NotifyProgress
//   - notifications/message  -> ServerSession.Log (delivered only once the
//     client has set a logging level, per the go-sdk/spec behavior)
//
// Any other method returns ErrUnsupportedNotification rather than being
// silently dropped, so a caller can decide how to handle it.
func (*MCPServer) SendNotificationToClient(ctx context.Context, method string, params map[string]any) error {
	session := ClientSessionFromContext(ctx)
	if session == nil {
		return ErrNoActiveSession
	}
	cs, ok := session.(*clientSession)
	if !ok {
		return fmt.Errorf("session %q does not support server-initiated notifications", session.SessionID())
	}
	ss := cs.goSession.Load()
	if ss == nil {
		return fmt.Errorf("session %q has no bound go-sdk session", session.SessionID())
	}
	switch method {
	case "notifications/progress":
		var p gosdk.ProgressNotificationParams
		if err := jsonConvert(params, &p); err != nil {
			return fmt.Errorf("converting %s params: %w", method, err)
		}
		return ss.NotifyProgress(ctx, &p)
	case "notifications/message":
		var p gosdk.LoggingMessageParams
		if err := jsonConvert(params, &p); err != nil {
			return fmt.Errorf("converting %s params: %w", method, err)
		}
		return ss.Log(ctx, &p)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedNotification, method)
	}
}

// SendNotificationToAllClients broadcasts a server-initiated notification with
// the given method and params to every currently connected client session. It
// mirrors mcp-go's server.MCPServer.SendNotificationToAllClients, which
// ToolHive's stdio bridge uses to relay upstream notifications downstream.
//
// go-sdk backing and limitation: the go-sdk does not expose a public API to
// send an arbitrary (method, params) notification on a ServerSession; only
// typed senders are exported. This method therefore maps the well-known MCP
// notification methods onto the go-sdk's typed senders:
//
//   - notifications/progress -> ServerSession.NotifyProgress
//   - notifications/message  -> ServerSession.Log (delivered only once the
//     client has set a logging level, per the go-sdk/spec behavior)
//
// The list-changed notifications (tools/prompts/resources) are NOT re-broadcast
// through this method: the go-sdk server emits them automatically to connected
// clients whenever its registered feature set changes on a live session
// (per-session srv.AddTool / srv.RemoveTools, as driven by syncSessionTools
// when WithToolCapabilities(true) is set), so a manual broadcast would double
// them. Any list-changed method (and any other unrecognized method) is dropped
// here rather than forwarded. This is the one behavioral gap versus mcp-go's
// raw channel-based broadcast and is documented rather than silently ignored.
func (s *MCPServer) SendNotificationToAllClients(method string, params map[string]any) {
	ctx := context.Background()
	s.sessions.Range(func(_, v any) bool {
		cs, ok := v.(*clientSession)
		if !ok {
			return true
		}
		if ss := cs.goSession.Load(); ss != nil {
			s.sendOneNotification(ctx, ss, method, params)
		}
		return true
	})
}

// sendOneNotification dispatches a single notification to one go-sdk session,
// translating the method+params into the matching typed go-sdk sender. Errors
// are intentionally ignored to match mcp-go's best-effort broadcast semantics.
func (s *MCPServer) sendOneNotification(
	ctx context.Context, ss *gosdk.ServerSession, method string, params map[string]any,
) {
	switch method {
	case "notifications/progress":
		var p gosdk.ProgressNotificationParams
		if err := jsonConvert(params, &p); err != nil {
			s.logNotifyErr(method, err)
			return
		}
		_ = ss.NotifyProgress(ctx, &p)
	case "notifications/message":
		var p gosdk.LoggingMessageParams
		if err := jsonConvert(params, &p); err != nil {
			s.logNotifyErr(method, err)
			return
		}
		_ = ss.Log(ctx, &p)
	default:
		// See the doc comment on SendNotificationToAllClients: go-sdk offers no
		// public generic notification sender. The list-changed notifications are
		// emitted automatically by the go-sdk server on feature mutation, so
		// they (and any other unrecognized method) are dropped here to avoid
		// double-delivery.
		if s.logger != nil {
			s.logger.Debug("SendNotificationToAllClients: dropping unsupported notification method",
				"method", method)
		}
	}
}

// logNotifyErr logs a notification-conversion error if a logger is configured.
func (s *MCPServer) logNotifyErr(method string, err error) {
	if s.logger != nil {
		s.logger.Warn("SendNotificationToAllClients: failed to convert params",
			"method", method, "error", err)
	}
}
