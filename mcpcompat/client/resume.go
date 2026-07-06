// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

// resumeProtocolVersion is the MCP protocol version header sent on resumed
// requests. A resumed client skips the initialize handshake, so it advertises a
// widely-supported spec revision; the server seeds the session's negotiated
// version from this header when it rehydrates the session.
const resumeProtocolVersion = "2025-06-18"

// resumeState holds the minimal raw JSON-RPC-over-HTTP machinery used when a
// client resumes a pre-existing session (transport.WithSession) without calling
// Initialize. The go-sdk client always performs the initialize handshake and has
// no resume primitive, so a resumed session cannot use it; this path speaks the
// Streamable HTTP wire protocol directly, matching mcp-go's client resume.
type resumeState struct {
	nextID atomic.Int64
	client *http.Client
}

// isResume reports whether this client should use the raw resume path: a
// Streamable HTTP transport with a preset session ID (transport.WithSession) and
// no go-sdk session established (Initialize was not called).
func (c *Client) isResume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session == nil && c.streamable != nil && c.streamable.GetSessionId() != ""
}

// resumeCall issues a single JSON-RPC request over HTTP POST carrying the
// resumed session ID and decodes the result into out. It does not perform (and
// must not perform) initialization.
func (c *Client) resumeCall(ctx context.Context, method string, params, out any) error {
	c.mu.Lock()
	if c.resume == nil {
		c.resume = &resumeState{
			client: buildHTTPClient(
				c.streamable.HTTPClient(), c.streamable.Headers(), c.streamable.HeaderFunc(), c.streamable.Timeout(),
			),
		}
		if c.resume.client == nil {
			c.resume.client = http.DefaultClient
		}
	}
	rs := c.resume
	endpoint := c.streamable.Endpoint()
	sessionID := c.streamable.GetSessionId()
	c.mu.Unlock()

	id := rs.nextID.Add(1)
	reqMsg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		reqMsg["params"] = params
	}
	body, err := json.Marshal(reqMsg)
	if err != nil {
		return fmt.Errorf("marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	httpReq.Header.Set("Mcp-Session-Id", sessionID)
	httpReq.Header.Set("MCP-Protocol-Version", resumeProtocolVersion)

	resp, err := rs.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("sending %s request: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("resumed session %q not found or terminated", sessionID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s request failed: HTTP %d: %s", method, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	result, jsonErr, err := readRPCResponse(resp, id)
	if err != nil {
		return err
	}
	if jsonErr != nil {
		return fmt.Errorf("%s: %s", method, jsonErr.Message)
	}
	if out != nil && len(result) > 0 {
		if err := json.Unmarshal(result, out); err != nil {
			return fmt.Errorf("decoding %s result: %w", method, err)
		}
	}
	return nil
}

// rpcError is the JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpcEnvelope is a JSON-RPC response/notification envelope.
type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
	Method string          `json:"method"`
}

// readRPCResponse reads the JSON-RPC response matching wantID from an HTTP
// response, handling both application/json and text/event-stream bodies. It
// ignores server->client requests/notifications interleaved on an SSE stream
// (a resumed client does not service them).
func readRPCResponse(resp *http.Response, wantID int64) (result json.RawMessage, rpcErr *rpcError, err error) {
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var env rpcEnvelope
		if derr := json.NewDecoder(resp.Body).Decode(&env); derr != nil {
			return nil, nil, fmt.Errorf("decoding JSON response: %w", derr)
		}
		return env.Result, env.Error, nil
	}

	// SSE: scan for the message whose id matches wantID.
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data:")
		if !ok {
			continue
		}
		var env rpcEnvelope
		if json.Unmarshal([]byte(strings.TrimSpace(data)), &env) != nil {
			continue
		}
		// Only a response carries a result or error; skip server->client
		// requests/notifications (they have a method set).
		if env.Method != "" {
			continue
		}
		if !idMatches(env.ID, wantID) {
			continue
		}
		return env.Result, env.Error, nil
	}
	if scErr := sc.Err(); scErr != nil {
		return nil, nil, fmt.Errorf("reading SSE stream: %w", scErr)
	}
	return nil, nil, fmt.Errorf("no JSON-RPC response for id %d in stream", wantID)
}

// idMatches reports whether the raw JSON id equals wantID.
func idMatches(raw json.RawMessage, wantID int64) bool {
	if len(raw) == 0 {
		return false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n == wantID
	}
	return false
}
