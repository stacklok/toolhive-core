// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultSinkTimeout = 5 * time.Second

// httpWriter POSTs every Write's bytes, unmodified, to a configured URL.
// Each call is synchronous and bounded by Timeout — matching the
// best-effort, at-most-once delivery: a slow or unreachable endpoint costs at
// most one timeout, never a queue or a retry.
type httpWriter struct {
	url     string
	headers map[string]string
	client  *http.Client
	timeout time.Duration
}

func newHTTPWriter(cfg HTTPConfig) *httpWriter {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultSinkTimeout
	}
	return &httpWriter{
		url:     cfg.URL,
		headers: cfg.Headers,
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

func (w *httpWriter) Write(p []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(p))
	if err != nil {
		return 0, fmt.Errorf("build audit http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post audit event: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("audit sink returned status %d", resp.StatusCode)
	}
	return len(p), nil
}

// Close is a no-op: httpWriter holds no persistent connection to release —
// http.Client manages its own connection pool.
func (*httpWriter) Close() error { return nil }
