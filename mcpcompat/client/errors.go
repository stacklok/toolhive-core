// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// enrichWithResponseBody re-attaches a captured non-2xx HTTP response body to
// err (go-sdk reports only the status text and drops the body). Matches mcp-go's
// "request failed with status N: <body>" so server-provided detail — e.g.
// ToolHive's authorization middleware writing "Unauthorized" into a 403 body —
// reaches callers. No-op when nothing was captured.
func enrichWithResponseBody(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	h := capturedErr(ctx)
	if h == nil || h.body == "" {
		return err
	}
	return fmt.Errorf("%w: request failed with status %d: %s", err, h.status, strings.TrimSpace(h.body))
}

// mapConnectError maps an error returned by the underlying go-sdk Connect call
// (the initialize handshake) onto the transport-level sentinels ToolHive checks
// for.
//
// mcp-go classified any 4xx (except 401) on the initialize POST as a legacy
// SSE-only server. We restore that behavior here using the captured HTTP status
// (set by captureErrorBody for non-2xx responses), falling back to best-effort
// string matching when no body was captured (e.g. a failure before any
// response). 401 stays ErrUnauthorized so ToolHive's OAuth refresh flow still
// triggers.
func mapConnectError(ctx context.Context, err error) error {
	err = enrichWithResponseBody(ctx, err)
	h := capturedErr(ctx)
	if h != nil && h.status >= 400 && h.status < 500 {
		if h.status == http.StatusUnauthorized {
			return transport.NewError(errors.Join(
				&transport.AuthorizationRequiredError{ResourceMetadataURL: extractResourceMetadataURL(err)},
				transport.ErrUnauthorized,
				err,
			))
		}
		return transport.NewError(errors.Join(transport.ErrLegacySSEServer, err))
	}
	return mapTransportError(err, h)
}

// mapCallError maps an error returned by an underlying go-sdk request call onto
// the sentinels ToolHive checks for. A JSON-RPC -32601 response is surfaced as
// mcp.ErrMethodNotFound (as mcp-go did) so callers that recover from a backend
// lacking an optional method — e.g. resources/list or prompts/list — via
// errors.Is(err, mcp.ErrMethodNotFound) keep working.
//
// JSON-RPC-level errors (a *jsonrpc.Error returned inside a 2xx response) that
// carry no captured HTTP status are application errors, not transport failures:
// they must NOT be reclassified as transport auth/session failures based on
// their text — otherwise a tool error whose message contains "unauthorized"
// would wrongly trigger ToolHive's OAuth refresh flow. Only errors that look
// like transport-level HTTP failures (a captured non-2xx status, or a plain
// non-RPC error from the transport) are passed to mapTransportError.
func mapCallError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	err = enrichWithResponseBody(ctx, err)
	h := capturedErr(ctx)
	var wireErr *jsonrpc.Error
	if errors.As(err, &wireErr) && wireErr.Code == jsonrpc.CodeMethodNotFound {
		return errors.Join(mcp.ErrMethodNotFound, err)
	}
	if (h == nil || h.status == 0) && errors.As(err, &wireErr) {
		// RPC-level error with no captured HTTP status: surface unchanged.
		return err
	}
	return mapTransportError(err, h)
}

// mapTransportError inspects err and, when it recognizes an HTTP auth/session
// failure, returns an error that satisfies the errors.Is/errors.As checks
// ToolHive performs against the transport package's sentinels.
//
// When the caller captured a non-2xx HTTP status (h.status set by
// captureErrorBody), classification is driven by the status code, which avoids
// false positives from server-provided body text. When no status was captured
// (e.g. a transport failure before any response, or a response whose body
// capture was skipped), detection falls back to best-effort string matching.
//
// NOTE: the go-sdk does not currently expose a typed error carrying the HTTP
// status code, so the string-matching fallback is inherently best-effort. When
// the pattern is not recognized the original error is returned unchanged. This is
// the one area of the client shim where exact parity with mcp-go's OAuth flow
// may need refinement as the go-sdk's error surface evolves.
func mapTransportError(err error, h *errBody) error {
	if err == nil {
		return nil
	}
	// Prefer the captured HTTP status over string matching: the status is
	// authoritative, while body text (re-attached by enrichWithResponseBody)
	// can legitimately contain words like "unauthorized" for non-401 responses.
	if h != nil && h.status >= 400 && h.status < 500 {
		switch h.status {
		case http.StatusUnauthorized:
			return transport.NewError(errors.Join(
				&transport.AuthorizationRequiredError{ResourceMetadataURL: extractResourceMetadataURL(err)},
				transport.ErrUnauthorized,
				err,
			))
		case http.StatusNotFound:
			return transport.NewError(errors.Join(transport.ErrSessionTerminated, err))
		default:
			// Other 4xx on a regular call are not legacy-SSE (that classification
			// is connect-time only, in mapConnectError); surface unchanged.
			return err
		}
	}
	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "401") || strings.Contains(msg, "unauthorized"):
		// 401: ToolHive checks both ErrAuthorizationRequired (and As
		// *AuthorizationRequiredError / *transport.Error) and ErrUnauthorized.
		return transport.NewError(errors.Join(
			&transport.AuthorizationRequiredError{ResourceMetadataURL: extractResourceMetadataURL(err)},
			transport.ErrUnauthorized,
			err,
		))
	case strings.Contains(msg, "404") && strings.Contains(msg, "session"):
		return transport.NewError(errors.Join(transport.ErrSessionTerminated, err))
	case strings.Contains(msg, "legacy") || strings.Contains(msg, "method not allowed") || strings.Contains(msg, "405"):
		return transport.NewError(errors.Join(transport.ErrLegacySSEServer, err))
	default:
		return err
	}
}

// extractResourceMetadataURL is a placeholder for parsing the RFC 9728
// resource_metadata parameter out of a WWW-Authenticate header. The go-sdk does
// not surface the header on the error today, so this returns empty for now.
func extractResourceMetadataURL(_ error) string {
	return ""
}
