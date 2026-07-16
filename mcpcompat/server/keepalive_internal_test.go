// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingWriter is a fake http.ResponseWriter that records writes, flushes and
// the status code. It is safe for concurrent use because keepAliveWriter
// serializes every Write/WriteHeader/Flush through its own mutex; the internal
// lock here guards the recording state against test-goroutine reads.
type recordingWriter struct {
	mu       sync.Mutex
	hdr      http.Header
	buf      bytes.Buffer
	status   int
	flushes  int
	writeN   int
	writeErr error // when non-nil, Write returns it after recording nothing
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{hdr: make(http.Header)}
}

func (w *recordingWriter) Header() http.Header { return w.hdr }

func (w *recordingWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = code
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	w.writeN++
	return w.buf.Write(b)
}

func (w *recordingWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushes++
}

func (w *recordingWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

func (w *recordingWriter) commentCount() int {
	return bytes.Count(w.bytes(), keepAliveComment)
}

func (w *recordingWriter) flushCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushes
}

func (w *recordingWriter) setSSEHeaders() {
	w.hdr.Set("Content-Type", "text/event-stream")
}

// waitFor polls cond until it is true or a generous fixed deadline elapses; it
// fails the test on timeout so a broken expectation cannot hang the suite.
func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	const timeout = 2 * time.Second
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	require.Failf(t, "timeout waiting for condition", "%s (waited %s)", msg, timeout)
}

// requireClosed asserts ch is closed within a generous fixed window, so a stuck
// goroutine fails the test rather than hanging the suite.
func requireClosed(t *testing.T, ch <-chan struct{}, msg string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		require.FailNow(t, "timeout waiting for channel close", msg)
	}
}

// requireNotClosed asserts ch is NOT closed within the window.
func requireNotClosed(t *testing.T, ch <-chan struct{}, window time.Duration, msg string) {
	t.Helper()
	select {
	case <-ch:
		require.FailNow(t, "channel closed unexpectedly", msg)
	case <-time.After(window):
	}
}

func TestKeepAlive_SSE200_EmitsCommentsWithFlush(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	k := newKeepAliveWriter(rw, 10*time.Millisecond, nil)

	k.WriteHeader(http.StatusOK)

	// Wait for several comments, then quiesce the ticker BEFORE asserting on the
	// buffer. The test-goroutine reads (commentCount/flushCount/bytes) each take
	// the recordingWriter lock independently, so reading them while the ticker is
	// live is a TOCTOU race: a tick landing between the Write and Flush of one
	// comment could skew flushCount below commentCount. stopKeepAlive +
	// requireClosed(done) guarantee no further writes, so the state is stable.
	waitFor(t, func() bool { return rw.commentCount() >= 3 },
		"expected at least 3 keep-alive comments on an SSE 200 stream")
	k.stopKeepAlive()
	requireClosed(t, k.done, "goroutine must exit after stop")

	// Stable state: every comment was followed by a flush, and the only bytes on
	// the wire are keep-alive comments.
	assert.Equal(t, rw.commentCount(), rw.flushCount(),
		"each keep-alive comment must be followed by exactly one flush")
	assert.Equal(t, rw.commentCount()*len(keepAliveComment), len(rw.bytes()),
		"stream must carry only keep-alive comments")
}

func TestKeepAlive_ImplicitHeader_ReplayPath(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders() // Content-Type pre-set, as go-sdk's replay path does
	k := newKeepAliveWriter(rw, 10*time.Millisecond, nil)
	defer k.stopKeepAlive()

	// A Write with no prior WriteHeader is an implicit 200 (replay-stream path).
	_, err := k.Write([]byte("event: message\ndata: {}\n\n"))
	require.NoError(t, err)

	waitFor(t, func() bool { return rw.commentCount() >= 2 },
		"implicit-header SSE write must start the ticker")
	requireClosed(t, doneAfterStop(k), "goroutine must exit after stop")
}

// doneAfterStop stops the keep-alive and returns its done channel, for the
// common "assert the goroutine exits" pattern.
func doneAfterStop(k *keepAliveWriter) <-chan struct{} {
	k.stopKeepAlive()
	return k.done
}

func TestKeepAlive_NeverStarts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(rw *recordingWriter, k *keepAliveWriter)
	}{
		{
			name: "non-SSE 200 (application/json)",
			setup: func(rw *recordingWriter, k *keepAliveWriter) {
				rw.hdr.Set("Content-Type", "application/json")
				k.WriteHeader(http.StatusOK)
			},
		},
		{
			name: "SSE content-type but non-200 status",
			setup: func(rw *recordingWriter, k *keepAliveWriter) {
				rw.setSSEHeaders()
				k.WriteHeader(http.StatusForbidden)
			},
		},
		{
			name: "SSE content-type set but handler returns without writing",
			setup: func(rw *recordingWriter, _ *keepAliveWriter) {
				// SSE Content-Type is present, but the handler calls neither
				// WriteHeader nor Write (e.g. it returns immediately): with no
				// established response the ticker must never start.
				rw.setSSEHeaders()
			},
		},
		{
			name: "empty content-type 200",
			setup: func(_ *recordingWriter, k *keepAliveWriter) {
				k.WriteHeader(http.StatusOK)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rw := newRecordingWriter()
			k := newKeepAliveWriter(rw, 5*time.Millisecond, nil)
			defer k.stopKeepAlive()

			tc.setup(rw, k)

			// Wait well past several intervals: the ticker must never have run.
			requireNotClosed(t, k.done, 60*time.Millisecond, "ticker goroutine must never start")
			assert.Zero(t, rw.commentCount(), "no keep-alive comment must be written")
			assert.False(t, k.streaming, "streaming must stay false when no SSE stream is established")
		})
	}
}

// TestKeepAlive_FirstCommentNotImmediate locks in mcp-go parity: run() waits one
// full interval before the first comment, so no comment may appear immediately
// on SSE establishment. A regression to an immediate first tick would fail here.
func TestKeepAlive_FirstCommentNotImmediate(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	// A long interval makes the "nothing yet" window unambiguous.
	k := newKeepAliveWriter(rw, time.Second, nil)
	defer k.stopKeepAlive()

	k.WriteHeader(http.StatusOK)

	// Shortly after the SSE 200 header — well before the first interval elapses —
	// there must be no comment yet.
	time.Sleep(50 * time.Millisecond)
	assert.True(t, k.streaming, "ticker must be running after an SSE 200")
	assert.Zero(t, rw.commentCount(), "first keep-alive comment must not be immediate (fires after one full interval)")
}

// TestKeepAlive_ContentTypeWithParams verifies maybeStartLocked parses the
// media type (mime.ParseMediaType) rather than comparing the raw header, so an
// SSE Content-Type carrying parameters still starts the ticker.
func TestKeepAlive_ContentTypeWithParams(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.hdr.Set("Content-Type", "text/event-stream; charset=utf-8")
	k := newKeepAliveWriter(rw, 5*time.Millisecond, nil)
	defer k.stopKeepAlive()

	k.WriteHeader(http.StatusOK)

	waitFor(t, func() bool { return rw.commentCount() >= 1 },
		"a parameterized text/event-stream Content-Type must start the ticker")
}

// TestKeepAlive_StopBeforeStart verifies the stopped guard in maybeStartLocked:
// if the keep-alive is stopped before the SSE stream is established, a later
// WriteHeader(200) on an SSE stream must NOT start the ticker.
func TestKeepAlive_StopBeforeStart(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	k := newKeepAliveWriter(rw, 5*time.Millisecond, nil)

	k.stopKeepAlive()            // stop first
	k.WriteHeader(http.StatusOK) // then establish the SSE stream

	requireNotClosed(t, k.done, 60*time.Millisecond, "ticker must not start after stopKeepAlive")
	assert.Zero(t, rw.commentCount(), "no comment may be written when stopped before start")
	assert.False(t, k.streaming, "streaming must stay false when stopped before start")
}

func TestKeepAlive_StopPreventsLaterWrites(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	k := newKeepAliveWriter(rw, 10*time.Millisecond, nil)
	k.WriteHeader(http.StatusOK)

	waitFor(t, func() bool { return rw.commentCount() >= 1 },
		"expected at least one comment before stop")

	k.stopKeepAlive()
	requireClosed(t, k.done, "goroutine must exit promptly after stop")

	// No bytes may be written after stopKeepAlive returns.
	after := len(rw.bytes())
	time.Sleep(50 * time.Millisecond) // > 2 intervals
	assert.Equal(t, after, len(rw.bytes()), "no bytes may be written after stopKeepAlive returns")

	// stopKeepAlive is idempotent.
	assert.NotPanics(t, k.stopKeepAlive, "stopKeepAlive must be idempotent")
}

func TestKeepAlive_WriteErrorStopsGoroutine(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	rw.writeErr = errors.New("client gone")
	k := newKeepAliveWriter(rw, 5*time.Millisecond, nil)
	defer k.stopKeepAlive()

	// Establish the stream via an explicit WriteHeader (does not write bytes),
	// so the ticker starts and the first tick's Write fails.
	k.WriteHeader(http.StatusOK)

	requireClosed(t, k.done, "goroutine must exit when the underlying write errors")
	assert.Zero(t, rw.commentCount(), "a failed write records no bytes")
}

// TestKeepAlive_ConcurrentFramesNoInterleaving hammers Write with whole SSE
// frames while the ticker runs at a tiny interval and asserts that no frame or
// comment is ever split or interleaved. This is the core concurrency guarantee
// and is meaningful under the -race detector.
func TestKeepAlive_ConcurrentFramesNoInterleaving(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	k := newKeepAliveWriter(rw, time.Millisecond, nil)

	// Establish the SSE stream and start the ticker.
	k.WriteHeader(http.StatusOK)

	const (
		writers         = 8
		framesPerWriter = 200
	)
	frame := []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n\n")

	var wg sync.WaitGroup
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < framesPerWriter; j++ {
				_, err := k.Write(frame)
				assert.NoError(t, err)
			}
		}()
	}
	wg.Wait()
	k.stopKeepAlive()
	requireClosed(t, k.done, "goroutine must exit after stop")

	// Every emitted token must be one of exactly two whole units: the frame or
	// the keep-alive comment. Walk the buffer and match one whole unit at a time;
	// any split or interleaving leaves an unmatched prefix and fails.
	out := rw.bytes()
	var frames, comments int
	for len(out) > 0 {
		switch {
		case bytes.HasPrefix(out, frame):
			out = out[len(frame):]
			frames++
		case bytes.HasPrefix(out, keepAliveComment):
			out = out[len(keepAliveComment):]
			comments++
		default:
			require.Failf(t, "interleaved output",
				"output is not a clean concatenation of whole frames/comments; %d bytes unmatched", len(out))
		}
	}
	assert.Equal(t, writers*framesPerWriter, frames, "every whole frame must appear intact")
	assert.Positive(t, comments, "the ticker should have emitted at least one comment")
}

func TestKeepAlive_DisabledInterval(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	// A non-positive interval must never start the ticker even on a valid SSE 200.
	k := newKeepAliveWriter(rw, 0, nil)
	defer k.stopKeepAlive()

	k.WriteHeader(http.StatusOK)
	requireNotClosed(t, k.done, 40*time.Millisecond, "ticker must not start when interval <= 0")
	assert.Zero(t, rw.commentCount(), "disabled keep-alive must write no comments")
}

// TestKeepAlive_UnwrapReturnsUnderlying verifies Unwrap exposes the underlying
// writer so http.ResponseController can reach it, and Flush routes through the
// wrapper under lock.
func TestKeepAlive_UnwrapAndFlush(t *testing.T) {
	t.Parallel()
	rw := newRecordingWriter()
	rw.setSSEHeaders()
	k := newKeepAliveWriter(rw, time.Hour, nil) // interval large: no tick during test
	defer k.stopKeepAlive()

	assert.Same(t, rw, k.Unwrap(), "Unwrap must return the underlying writer")

	// A ResponseController built over the wrapper must resolve Flush through our
	// locked Flush (Flusher is checked before Unwrap).
	rc := http.NewResponseController(k)
	require.NoError(t, rc.Flush())
	assert.Equal(t, 1, rw.flushCount(), "Flush via ResponseController must reach the underlying writer once")
}
