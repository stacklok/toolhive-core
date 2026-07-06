// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

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
// The list-changed notifications (tools/prompts/resources) are emitted
// automatically by the go-sdk server when its registered feature set changes,
// so they cannot be re-broadcast through a public API here; they, and any other
// unrecognized method, are dropped (logged at debug level). This is the one
// behavioral gap versus mcp-go's raw channel-based broadcast and is documented
// rather than silently ignored.
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
		// public generic notification sender, so list-changed and other methods
		// cannot be forwarded and are dropped.
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
