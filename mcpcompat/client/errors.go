// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// mapConnectError maps an error returned by the underlying go-sdk Connect call
// onto the transport-level sentinels ToolHive checks for.
func mapConnectError(err error) error {
	return mapTransportError(err)
}

// mapCallError maps an error returned by an underlying go-sdk request call onto
// the sentinels ToolHive checks for. A JSON-RPC -32601 response is surfaced as
// mcp.ErrMethodNotFound (as mcp-go did) so callers that recover from a backend
// lacking an optional method — e.g. resources/list or prompts/list — via
// errors.Is(err, mcp.ErrMethodNotFound) keep working.
func mapCallError(err error) error {
	if err == nil {
		return nil
	}
	var wireErr *jsonrpc.Error
	if errors.As(err, &wireErr) && wireErr.Code == jsonrpc.CodeMethodNotFound {
		return errors.Join(mcp.ErrMethodNotFound, err)
	}
	return mapTransportError(err)
}

// mapTransportError inspects err and, when it recognizes an HTTP auth/session
// failure, returns an error that satisfies the errors.Is/errors.As checks
// ToolHive performs against the transport package's sentinels.
//
// NOTE: the go-sdk does not currently expose a typed error carrying the HTTP
// status code, so detection is best-effort based on the error text. When the
// pattern is not recognized the original error is returned unchanged. This is
// the one area of the client shim where exact parity with mcp-go's OAuth flow
// may need refinement as the go-sdk's error surface evolves.
func mapTransportError(err error) error {
	if err == nil {
		return nil
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
