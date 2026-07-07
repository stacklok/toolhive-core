// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// go-sdk's Streamable HTTP client reports a non-2xx response using only
// http.StatusText(code) (e.g. "403 Forbidden") and discards the response body.
// mcp-go instead included the body ("request failed with status N: <body>"),
// which is where servers put actionable detail — e.g. ToolHive's authorization
// middleware writes "Unauthorized" into a 403 body. To preserve that, the client
// installs a RoundTripper that captures the body of a non-2xx response into a
// per-call holder carried on the request context, and the error mappers
// re-attach it to the returned error.

// maxCapturedErrBody bounds how much of an error response body we read.
const maxCapturedErrBody = 8 << 10 // 8 KiB

type errBody struct {
	status int
	body   string
}

type errBodyKey struct{}

// withErrCapture returns a context carrying a holder for a captured non-2xx
// response body. Pass the returned context to the underlying request so the
// RoundTripper can populate it, then hand the same context to mapCallError /
// mapConnectError to enrich the error.
func withErrCapture(ctx context.Context) context.Context {
	return context.WithValue(ctx, errBodyKey{}, &errBody{})
}

func capturedErr(ctx context.Context) *errBody {
	if v, ok := ctx.Value(errBodyKey{}).(*errBody); ok {
		return v
	}
	return nil
}

// captureErrorBody records a non-2xx response body into the context holder (if
// present) and restores resp.Body so downstream readers are unaffected. Safe on
// nil/2xx responses (no-op).
func captureErrorBody(req *http.Request, resp *http.Response) {
	if resp == nil || resp.StatusCode < 400 || resp.Body == nil {
		return
	}
	h := capturedErr(req.Context())
	if h == nil || h.body != "" {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCapturedErrBody))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err == nil && len(data) > 0 {
		h.status = resp.StatusCode
		h.body = string(data)
	}
}
