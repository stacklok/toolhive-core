// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"log/slog"
	"mime"
	"net/http"
	"sync"
	"time"
)

// keepAliveComment is the SSE comment written on each heartbeat tick. SSE
// comments (lines beginning with ':') are ignored by every spec-conforming SSE
// parser: go-sdk's client-side scanEvents cuts each line on the first ':', and
// an empty key yields no event. The payload MUST contain the colon — a line
// without one is a malformed SSE event. This deliberately diverges from
// mcp-go, which sent a full JSON-RPC ping REQUEST as the heartbeat: a
// conforming client would answer that ping with a response carrying an ID the
// go-sdk server never issued, generating unknown-request-ID handling on every
// tick. A comment is invisible at the JSON-RPC layer and costs the client
// nothing.
var keepAliveComment = []byte(": keep-alive\n\n")

// keepAliveWriter wraps the http.ResponseWriter handed to the go-sdk GET handler
// and injects keepAliveComment at each heartbeat interval once — and only once —
// the response is established as an SSE stream (status 200 and Content-Type
// text/event-stream). All writes and flushes, the handler's and the keep-alive
// tick's alike, are serialized by mu. go-sdk writes one whole SSE frame per
// Write call (writeEvent buffers the full frame before issuing a single Write),
// so serializing at the call boundary preserves frame atomicity: a comment can
// never land in the middle of an event. This depends on go-sdk v1.6.1's
// frame-atomic writeEvent; the module is version-pinned and the end-to-end test
// would surface any regression (the client-side SSE scanner errors loudly on a
// malformed line).
//
// The wrapper forwards http.Flusher (routing go-sdk's ResponseController.Flush
// through mu) and Unwrap (preserving ResponseController deadline capabilities on
// the underlying writer). It deliberately does not forward http.Hijacker or
// http.Pusher: go-sdk's streamable GET path uses neither.
type keepAliveWriter struct {
	interval time.Duration
	logger   *slog.Logger // may be nil; guarded at every use

	mu          sync.Mutex
	w           http.ResponseWriter
	rc          *http.ResponseController // controller over the underlying w; used only under mu
	wroteHeader bool                     // an explicit or implicit WriteHeader happened
	streaming   bool                     // SSE stream established; ticker running
	stopped     bool                     // stopKeepAlive called; no new tick write may start

	stop     chan struct{} // closed by stopKeepAlive (via stopOnce)
	stopOnce sync.Once
	done     chan struct{} // closed when the ticker goroutine exits (lifecycle state, assertable in tests)
}

// newKeepAliveWriter wraps w for the passive SSE keep-alive at the given
// interval. The ticker is not started until the response is established as an
// SSE stream (see maybeStartLocked).
func newKeepAliveWriter(w http.ResponseWriter, interval time.Duration, logger *slog.Logger) *keepAliveWriter {
	return &keepAliveWriter{
		interval: interval,
		logger:   logger,
		w:        w,
		rc:       http.NewResponseController(w),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Header delegates to the underlying writer. No lock is needed: the handler
// mutates the header map only on its own goroutine, before WriteHeader (which
// takes mu), and the ticker goroutine never touches the header.
func (k *keepAliveWriter) Header() http.Header {
	return k.w.Header()
}

// WriteHeader delegates the status to the underlying writer and, on an SSE 200,
// starts the keep-alive ticker.
func (k *keepAliveWriter) WriteHeader(code int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.w.WriteHeader(code)
	k.wroteHeader = true
	k.maybeStartLocked(code)
}

// Write delegates to the underlying writer. A Write before any WriteHeader is
// treated as an implicit WriteHeader(200) (net/http semantics), which also
// covers go-sdk's replay-stream path that writes without an explicit
// WriteHeader.
func (k *keepAliveWriter) Write(b []byte) (int, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.wroteHeader {
		k.wroteHeader = true
		k.maybeStartLocked(http.StatusOK)
	}
	return k.w.Write(b)
}

// Flush flushes the underlying writer under mu. Implementing http.Flusher
// directly is what routes go-sdk's http.ResponseController.Flush through our
// mutex (ResponseController resolves http.Flusher before Unwrap), guaranteeing
// a handler flush cannot interleave with a keep-alive write. Errors are ignored,
// matching go-sdk's own best-effort flush handling.
func (k *keepAliveWriter) Flush() {
	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.rc.Flush()
}

// Unwrap returns the underlying writer so http.ResponseController can reach its
// deadline/flush capabilities. This does not create a lock bypass for writes:
// ResponseController resolves http.Flusher (our locked Flush) before Unwrap, and
// the deadline setters reached through Unwrap do not write response bytes.
func (k *keepAliveWriter) Unwrap() http.ResponseWriter {
	return k.w
}

// stopKeepAlive releases the keep-alive. It is idempotent and is the single
// authoritative teardown path: the caller defers it, so it runs when the
// handler's ServeHTTP returns (context cancel, stream completion, session close,
// or panic unwind). After it returns, any in-flight tick write completed before
// it acquired mu (strictly before ServeHTTP returned to net/http, which is
// legal), and no subsequent tick write can start because stopped is set under
// the same mu every write checks. The ticker goroutine exits promptly via the
// closed stop channel.
func (k *keepAliveWriter) stopKeepAlive() {
	k.stopOnce.Do(func() { close(k.stop) })
	k.mu.Lock()
	k.stopped = true
	k.mu.Unlock()
}

// maybeStartLocked starts the ticker goroutine exactly once, and only for an
// established SSE stream. Precondition: mu is held. It is a no-op if the ticker
// already runs, the keep-alive was stopped, the interval is non-positive, the
// status is not 200, or the Content-Type is not text/event-stream — so error
// responses (denial 403, session 404/409/503, any http.Error) and non-SSE GETs
// never spawn a goroutine.
func (k *keepAliveWriter) maybeStartLocked(status int) {
	if k.streaming || k.stopped || k.interval <= 0 || status != http.StatusOK {
		return
	}
	mediaType, _, err := mime.ParseMediaType(k.w.Header().Get("Content-Type"))
	if err != nil || mediaType != "text/event-stream" {
		return
	}
	k.streaming = true
	go k.run()
}

// run is the per-connection ticker goroutine. It emits the first comment after
// one full interval (mcp-go parity: a positive interval opts in, the first
// heartbeat is not immediate) and exits when the keep-alive is stopped or a
// write fails (client gone, ServeHTTP unwinding).
func (k *keepAliveWriter) run() {
	defer close(k.done)
	t := time.NewTicker(k.interval)
	defer t.Stop()
	for {
		select {
		case <-k.stop:
			return
		case <-t.C:
			if !k.writeComment() {
				return
			}
		}
	}
}

// writeComment writes and flushes one keep-alive comment under mu. It returns
// false — signaling run to exit — if the keep-alive was stopped or the
// underlying write failed (the stream is dead; the deferred stopKeepAlive is
// about to run, so there is no point spinning).
func (k *keepAliveWriter) writeComment() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.stopped {
		return false
	}
	if _, err := k.w.Write(keepAliveComment); err != nil {
		if k.logger != nil {
			k.logger.Debug("keep-alive write failed; stopping heartbeat", "error", err)
		}
		return false
	}
	_ = k.rc.Flush()
	return true
}
