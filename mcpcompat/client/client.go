// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package client is a drop-in compatibility shim for
// github.com/mark3labs/mcp-go/client, reimplemented on top of the official
// github.com/modelcontextprotocol/go-sdk.
//
// It presents mcp-go's flat client API (NewStreamableHttpClient, Start,
// Initialize, ListTools, CallTool, ...) while delegating the actual protocol to
// a go-sdk Client and ClientSession underneath. Data types are exchanged as the
// mcp-go-shaped types from mcpcompat/mcp; conversion to and from the go-sdk's
// own types happens at this boundary via JSON round-trips, which is robust
// because both encode the identical MCP wire format.
//
// Stability: Alpha.
package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// Client is an MCP client backed by the official go-sdk. It mirrors the subset
// of mcp-go's client.Client that ToolHive uses.
type Client struct {
	// transport configuration; exactly one of streamable/sse is non-nil.
	streamable *transport.StreamableHTTP
	sse        *transport.SSE

	mu       sync.Mutex
	client   *gosdk.Client
	session  *gosdk.ClientSession
	notifyMu sync.Mutex
	notify   []func(mcp.JSONRPCNotification)

	connLostMu   sync.Mutex
	connLost     func(error)
	watchStarted bool

	// resume holds the raw JSON-RPC-over-HTTP machinery used when the client
	// resumes a pre-existing session (transport.WithSession) without calling
	// Initialize. It is lazily created on the first resumed request. See resume.go.
	resume *resumeState
}

// NewStreamableHttpClient creates a Streamable HTTP MCP client for baseURL. Like
// mcp-go, the returned client is not yet connected; call Start then Initialize.
func NewStreamableHttpClient(baseURL string, options ...transport.StreamableHTTPCOption) (*Client, error) {
	return &Client{streamable: transport.NewStreamableHTTP(baseURL, options...)}, nil
}

// NewSSEMCPClient creates an SSE MCP client for baseURL. The returned client is
// not yet connected; call Start then Initialize.
func NewSSEMCPClient(baseURL string, options ...transport.ClientOption) (*Client, error) {
	return &Client{sse: transport.NewSSE(baseURL, options...)}, nil
}

// Start prepares the client. The go-sdk performs connection and initialization
// together in a single Connect call, which this shim issues from Initialize;
// Start is therefore a no-op retained for API compatibility.
func (*Client) Start(_ context.Context) error { return nil }

// Initialize connects the underlying go-sdk client and performs the MCP
// initialize handshake using the supplied client info and capabilities.
func (c *Client) Initialize(ctx context.Context, request mcp.InitializeRequest) (*mcp.InitializeResult, error) {
	ctx = withErrCapture(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session != nil {
		return nil, fmt.Errorf("client already initialized")
	}

	impl := &gosdk.Implementation{}
	if err := jsonConvert(request.Params.ClientInfo, impl); err != nil {
		return nil, fmt.Errorf("converting client info: %w", err)
	}
	if impl.Name == "" {
		impl.Name = "toolhive"
	}
	if impl.Version == "" {
		impl.Version = "0.0.0"
	}

	opts := &gosdk.ClientOptions{}
	if !isZeroCapabilities(request.Params.Capabilities) {
		caps := &gosdk.ClientCapabilities{}
		if err := jsonConvert(request.Params.Capabilities, caps); err != nil {
			return nil, fmt.Errorf("converting client capabilities: %w", err)
		}
		opts.Capabilities = caps
	}
	c.installNotificationHandlers(opts)

	gc := gosdk.NewClient(impl, opts)

	tr, err := c.buildTransport()
	if err != nil {
		return nil, err
	}

	session, err := gc.Connect(ctx, tr, nil)
	if err != nil {
		return nil, mapConnectError(ctx, err)
	}

	c.client = gc
	c.session = session
	if c.streamable != nil {
		c.streamable.SetSessionID(session.ID())
	}
	c.maybeStartConnLostWatch(session)

	result := &mcp.InitializeResult{}
	if err := jsonConvert(session.InitializeResult(), result); err != nil {
		return nil, fmt.Errorf("converting initialize result: %w", err)
	}
	return result, nil
}

// buildTransport constructs the go-sdk transport from the configured options.
func (c *Client) buildTransport() (gosdk.Transport, error) {
	switch {
	case c.streamable != nil:
		return &gosdk.StreamableClientTransport{
			Endpoint: c.streamable.Endpoint(),
			HTTPClient: buildHTTPClient(
				c.streamable.HTTPClient(), c.streamable.Headers(), c.streamable.HeaderFunc(), c.streamable.Timeout(),
			),
			DisableStandaloneSSE: !c.streamable.ContinuousListening(),
		}, nil
	case c.sse != nil:
		return &gosdk.SSEClientTransport{
			Endpoint:   c.sse.Endpoint(),
			HTTPClient: buildHTTPClient(c.sse.HTTPClient(), c.sse.Headers(), nil, 0),
		}, nil
	default:
		return nil, fmt.Errorf("no transport configured")
	}
}

// Close terminates the session.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil
	}
	err := c.session.Close()
	c.session = nil
	return err
}

// Ping verifies the server is responsive.
func (c *Client) Ping(ctx context.Context) error {
	if c.isResume() {
		return c.resumeCall(ctx, "ping", struct{}{}, nil)
	}
	s, err := c.sessionFor()
	if err != nil {
		return err
	}
	return s.Ping(ctx, nil)
}

// SetLoggingLevel sets the server's logging level. This is a renamed and
// simplified counterpart to mcp-go's client.Client.SetLevel: rather than
// taking an mcp.SetLevelRequest, it accepts the mcp.LoggingLevel directly.
// The SetLevel, SetLevelRequest and SetLevelParams types from mcp-go are
// intentionally NOT re-exported by this shim. The server only delivers
// notifications/message notifications at or above the requested level, so this
// must be called before the OnNotification handler will see logging
// notifications. level is one of the MCP logging levels ("debug", "info",
// "notice", "warning", "error", "critical", "alert", "emergency").
func (c *Client) SetLoggingLevel(ctx context.Context, level mcp.LoggingLevel) error {
	s, err := c.sessionFor()
	if err != nil {
		return err
	}
	return s.SetLoggingLevel(ctx, &gosdk.SetLoggingLevelParams{Level: gosdk.LoggingLevel(level)})
}

// ListTools lists the server's tools.
func (c *Client) ListTools(ctx context.Context, request mcp.ListToolsRequest) (*mcp.ListToolsResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.ListToolsResult{}
		return out, c.resumeCall(ctx, "tools/list", request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.ListTools(ctx, &gosdk.ListToolsParams{Cursor: string(request.Params.Cursor)})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.ListToolsResult](res)
}

// CallTool invokes a tool.
func (c *Client) CallTool(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.CallToolResult{}
		return out, c.resumeCall(ctx, "tools/call", request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	params := &gosdk.CallToolParams{
		Name:      request.Params.Name,
		Arguments: request.Params.Arguments,
	}
	// Preserve the request _meta (ToolHive propagates metadata through vMCP to
	// backends via this field). mcp-go's *Meta flattens its AdditionalFields to
	// top-level _meta keys, so convert via JSON into go-sdk's Meta (map[string]any).
	if request.Params.Meta != nil {
		m := gosdk.Meta{}
		if err := jsonConvert(request.Params.Meta, &m); err != nil {
			return nil, fmt.Errorf("converting call meta: %w", err)
		}
		params.Meta = m
	}
	res, err := s.CallTool(ctx, params)
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.CallToolResult](res)
}

// ReadResource reads a resource by URI.
func (c *Client) ReadResource(ctx context.Context, request mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		raw := &gosdk.ReadResourceResult{}
		if err := c.resumeCall(ctx, "resources/read", request.Params, raw); err != nil {
			return nil, err
		}
		return convertReadResourceResult(raw), nil
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.ReadResource(ctx, &gosdk.ReadResourceParams{URI: request.Params.URI})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertReadResourceResult(res), nil
}

// convertReadResourceResult converts a go-sdk ReadResourceResult into its
// mcp-go-shaped equivalent. mcp-go's ReadResourceResult.Contents is a slice of
// the mcp.ResourceContents interface with no custom unmarshaler, so a JSON
// round-trip cannot populate it; each go-sdk ResourceContents struct is mapped
// explicitly to the concrete text/blob mcp-go type instead.
func convertReadResourceResult(res *gosdk.ReadResourceResult) *mcp.ReadResourceResult {
	out := &mcp.ReadResourceResult{}
	if len(res.Meta) > 0 {
		out.Meta = mcp.NewMetaFromMap(map[string]any(res.Meta))
	}
	for _, rc := range res.Contents {
		if rc == nil {
			continue
		}
		var meta map[string]any
		if len(rc.Meta) > 0 {
			meta = map[string]any(rc.Meta)
		}
		if len(rc.Blob) > 0 {
			out.Contents = append(out.Contents, mcp.BlobResourceContents{
				URI:      rc.URI,
				MIMEType: rc.MIMEType,
				Blob:     base64.StdEncoding.EncodeToString(rc.Blob),
				Meta:     meta,
			})
			continue
		}
		out.Contents = append(out.Contents, mcp.TextResourceContents{
			URI:      rc.URI,
			MIMEType: rc.MIMEType,
			Text:     rc.Text,
			Meta:     meta,
		})
	}
	return out
}

// GetPrompt gets a prompt, rendered with the provided arguments.
func (c *Client) GetPrompt(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		raw := &gosdk.GetPromptResult{}
		if err := c.resumeCall(ctx, "prompts/get", request.Params, raw); err != nil {
			return nil, err
		}
		return convertGetPromptResult(raw)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.GetPrompt(ctx, &gosdk.GetPromptParams{
		Name:      request.Params.Name,
		Arguments: request.Params.Arguments,
	})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertGetPromptResult(res)
}

// convertGetPromptResult converts a go-sdk GetPromptResult into its mcp-go-shaped
// equivalent. mcp-go's PromptMessage.Content is the mcp.Content interface with no
// custom unmarshaler, so a JSON round-trip cannot populate it; each message's
// content is re-marshaled and decoded via mcp.UnmarshalContent instead.
func convertGetPromptResult(res *gosdk.GetPromptResult) (*mcp.GetPromptResult, error) {
	out := &mcp.GetPromptResult{Description: res.Description}
	if len(res.Meta) > 0 {
		out.Meta = mcp.NewMetaFromMap(map[string]any(res.Meta))
	}
	for _, pm := range res.Messages {
		if pm == nil {
			continue
		}
		msg := mcp.PromptMessage{Role: mcp.Role(pm.Role)}
		if pm.Content != nil {
			cb, err := json.Marshal(pm.Content)
			if err != nil {
				return nil, fmt.Errorf("marshaling prompt content: %w", err)
			}
			content, err := mcp.UnmarshalContent(cb)
			if err != nil {
				return nil, fmt.Errorf("converting prompt content: %w", err)
			}
			msg.Content = content
		}
		out.Messages = append(out.Messages, msg)
	}
	return out, nil
}

// ListResources lists the server's resources.
func (c *Client) ListResources(ctx context.Context, request mcp.ListResourcesRequest) (*mcp.ListResourcesResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.ListResourcesResult{}
		return out, c.resumeCall(ctx, "resources/list", request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.ListResources(ctx, &gosdk.ListResourcesParams{Cursor: string(request.Params.Cursor)})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.ListResourcesResult](res)
}

// ListPrompts lists the server's prompts.
func (c *Client) ListPrompts(ctx context.Context, request mcp.ListPromptsRequest) (*mcp.ListPromptsResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.ListPromptsResult{}
		return out, c.resumeCall(ctx, "prompts/list", request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.ListPrompts(ctx, &gosdk.ListPromptsParams{Cursor: string(request.Params.Cursor)})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.ListPromptsResult](res)
}

// ListResourceTemplates lists the server's resource templates.
func (c *Client) ListResourceTemplates(
	ctx context.Context, request mcp.ListResourceTemplatesRequest,
) (*mcp.ListResourceTemplatesResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.ListResourceTemplatesResult{}
		return out, c.resumeCall(ctx, "resources/templates/list", request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	res, err := s.ListResourceTemplates(ctx, &gosdk.ListResourceTemplatesParams{Cursor: string(request.Params.Cursor)})
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.ListResourceTemplatesResult](res)
}

// OnNotification registers a handler invoked for server-initiated notifications.
// Handlers must be registered before Initialize so they can be wired into the
// underlying go-sdk client. The go-sdk exposes typed notification handlers
// rather than a single catch-all, so this shim synthesizes JSONRPCNotification
// values (method + params) for the list-changed, progress and logging
// notifications, forwarding each to every registered handler.
//
// Server-initiated notifications (including the list_changed notifications,
// which the server emits outside any in-flight request) are only delivered if
// the client enabled continuous listening via
// transport.WithContinuousListening(). Without it the go-sdk streamable
// transport has no standalone SSE stream to carry such notifications and they
// are silently dropped; no callback fires.
func (c *Client) OnNotification(handler func(notification mcp.JSONRPCNotification)) {
	c.notifyMu.Lock()
	defer c.notifyMu.Unlock()
	c.notify = append(c.notify, handler)
}

// dispatch fans a synthesized JSONRPCNotification out to every registered
// OnNotification handler. params is converted into mcp-go's
// JSONRPCNotificationParams (Meta + AdditionalFields) when non-nil, so the
// notification carries its params as mcp-go would; nil leaves the params empty
// (used by the list_changed notifications, which carry no params on the wire).
func (c *Client) dispatch(method string, params any) {
	c.notifyMu.Lock()
	handlers := make([]func(mcp.JSONRPCNotification), len(c.notify))
	copy(handlers, c.notify)
	c.notifyMu.Unlock()
	n := mcp.JSONRPCNotification{JSONRPC: mcp.JSONRPC_VERSION}
	n.Method = method
	if params != nil {
		n.Params = toNotificationParams(params)
	}
	for _, h := range handlers {
		h(n)
	}
}

// toNotificationParams converts a go-sdk notification params value into the
// mcp-go NotificationParams shape (Meta + AdditionalFields). Both encode to the
// same MCP wire JSON, so a JSON round-trip faithfully maps the go-sdk struct's
// fields onto mcp-go's AdditionalFields map. This mirrors the jsonConvert
// convention used elsewhere in the shim for cross-type conversion.
func toNotificationParams(src any) mcp.NotificationParams {
	// Marshal the go-sdk params and unmarshal into a generic map, then split the
	// reserved "_meta" key (if present) from the remaining fields, which become
	// AdditionalFields.
	b, err := json.Marshal(src)
	if err != nil {
		return mcp.NotificationParams{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return mcp.NotificationParams{}
	}
	out := mcp.NotificationParams{AdditionalFields: make(map[string]any, len(m))}
	for k, v := range m {
		if k == "_meta" {
			if mm, ok := v.(map[string]any); ok {
				out.Meta = mm
			}
			continue
		}
		out.AdditionalFields[k] = v
	}
	return out
}

func (c *Client) installNotificationHandlers(opts *gosdk.ClientOptions) {
	opts.ToolListChangedHandler = func(_ context.Context, _ *gosdk.ToolListChangedRequest) {
		c.dispatch("notifications/tools/list_changed", nil)
	}
	opts.PromptListChangedHandler = func(_ context.Context, _ *gosdk.PromptListChangedRequest) {
		c.dispatch("notifications/prompts/list_changed", nil)
	}
	opts.ResourceListChangedHandler = func(_ context.Context, _ *gosdk.ResourceListChangedRequest) {
		c.dispatch("notifications/resources/list_changed", nil)
	}
	// Forward server->client progress notifications. go-sdk hands the params via
	// *ProgressNotificationClientRequest; convert them to mcp-go's notification
	// params (progressToken, progress, total, message) and dispatch.
	opts.ProgressNotificationHandler = newProgressNotificationHandler(c.dispatch)
	// Forward server->client logging notifications. go-sdk hands the params via
	// *LoggingMessageRequest; convert them to mcp-go's notification params
	// (level, data, logger) and dispatch.
	opts.LoggingMessageHandler = newLoggingMessageHandler(c.dispatch)
}

// dispatchFunc is the signature of Client.dispatch, factored out so the
// notification handlers can be unit-tested in isolation without a live session.
type dispatchFunc func(method string, params any)

// newProgressNotificationHandler builds the go-sdk progress-notification
// handler that forwards notifications/progress to the supplied dispatch func.
// If the go-sdk request or its params are nil, dispatch is called with nil
// params (an empty NotificationParams) rather than panicking.
func newProgressNotificationHandler(dispatch dispatchFunc) func(context.Context, *gosdk.ProgressNotificationClientRequest) {
	return func(_ context.Context, req *gosdk.ProgressNotificationClientRequest) {
		if req == nil || req.Params == nil {
			dispatch("notifications/progress", nil)
			return
		}
		dispatch("notifications/progress", req.Params)
	}
}

// newLoggingMessageHandler builds the go-sdk logging-notification handler that
// forwards notifications/message to the supplied dispatch func. If the go-sdk
// request or its params are nil, dispatch is called with nil params rather than
// panicking.
func newLoggingMessageHandler(dispatch dispatchFunc) func(context.Context, *gosdk.LoggingMessageRequest) {
	return func(_ context.Context, req *gosdk.LoggingMessageRequest) {
		if req == nil || req.Params == nil {
			dispatch("notifications/message", nil)
			return
		}
		dispatch("notifications/message", req.Params)
	}
}

// OnConnectionLost registers a handler invoked when the connection to the
// server is lost. It mirrors mcp-go's client.Client.OnConnectionLost, which is
// used to handle transport-level disconnections (e.g. an HTTP/2 idle timeout)
// that should not be treated as fatal errors.
//
// The go-sdk signals a dropped connection by having ClientSession.Wait return.
// The handler is invoked once, with the error Wait reports (nil on a clean
// close). If registered before Initialize, the watch starts once the session
// connects; if registered after, it starts immediately.
func (c *Client) OnConnectionLost(handler func(error)) {
	c.connLostMu.Lock()
	c.connLost = handler
	c.connLostMu.Unlock()

	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session != nil {
		c.maybeStartConnLostWatch(session)
	}
}

// maybeStartConnLostWatch starts, at most once, a goroutine that blocks on the
// session's Wait and invokes the registered connection-lost handler when the
// connection drops.
func (c *Client) maybeStartConnLostWatch(session *gosdk.ClientSession) {
	c.connLostMu.Lock()
	defer c.connLostMu.Unlock()
	if c.connLost == nil || c.watchStarted {
		return
	}
	c.watchStarted = true
	handler := c.connLost
	go func() {
		err := session.Wait()
		handler(err)
	}()
}

// GetTransport returns the transport handle. For a Streamable HTTP client the
// dynamic type is *transport.StreamableHTTP (as ToolHive expects); otherwise it
// is nil.
func (c *Client) GetTransport() transport.Interface {
	if c.streamable != nil {
		return c.streamable
	}
	return nil
}

// GetSessionId returns the current MCP session ID, if any.
func (c *Client) GetSessionId() string {
	if c.streamable != nil {
		return c.streamable.GetSessionId()
	}
	return ""
}

// IsInitialized reports whether the client has completed initialization.
func (c *Client) IsInitialized() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session != nil
}

func (c *Client) sessionFor() (*gosdk.ClientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil, fmt.Errorf("client not initialized: call Initialize first")
	}
	return c.session, nil
}

// --- helpers ---------------------------------------------------------------

// jsonConvert marshals src and unmarshals it into dst. Both mcp-go-shaped and
// go-sdk types encode the identical MCP wire format, so this is a faithful
// structural conversion.
func jsonConvert(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// convertResult converts a go-sdk result into its mcp-go-shaped equivalent.
func convertResult[T any](src any) (*T, error) {
	out := new(T)
	if err := jsonConvert(src, out); err != nil {
		return nil, fmt.Errorf("converting result: %w", err)
	}
	return out, nil
}

func isZeroCapabilities(c mcp.ClientCapabilities) bool {
	b, err := json.Marshal(c)
	return err == nil && string(b) == "{}"
}

// headerRoundTripper injects static and/or per-request headers on every request.
type headerRoundTripper struct {
	headers    map[string]string
	headerFunc transport.HTTPHeaderFunc
	base       http.RoundTripper
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.headerFunc != nil {
		for k, v := range h.headerFunc(req.Context()) {
			req.Header.Set(k, v)
		}
	}
	base := h.base
	if base == nil {
		base = http.DefaultTransport
	}
	resp, err := base.RoundTrip(req)
	if err == nil {
		// Capture non-2xx bodies so the error mappers can re-attach the server's
		// message (go-sdk drops it). Restores resp.Body for downstream readers.
		captureErrorBody(req, resp)
	}
	return resp, err
}

// buildHTTPClient returns an *http.Client honoring the given base client, static
// headers, per-request header function and timeout. It returns nil when no
// customization is needed so the go-sdk uses its default client.
func buildHTTPClient(
	base *http.Client, headers map[string]string, headerFunc transport.HTTPHeaderFunc, timeout time.Duration,
) *http.Client {
	hc := &http.Client{}
	if base != nil {
		*hc = *base
	}
	if timeout > 0 {
		hc.Timeout = timeout
	}
	// Always install the RoundTripper: besides applying static/dynamic headers it
	// captures non-2xx response bodies for error enrichment (see errorbody.go).
	hc.Transport = &headerRoundTripper{headers: headers, headerFunc: headerFunc, base: hc.Transport}
	return hc
}
