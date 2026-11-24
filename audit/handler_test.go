// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/stacklok/toolhive-core/logging"
)

// testEvent returns a neutral audit event for the middleware tests.
func testEvent() *AuditEvent {
	return NewAuditEvent(
		"widgets.widget.update",
		EventSource{Type: SourceTypeNetwork, Value: "10.0.0.1"},
		OutcomeSuccess,
		map[string]string{SubjectKeyUser: "alice"},
		"example-service",
	)
}

// lockedBuffer is a bytes.Buffer safe for concurrent writes and reads.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// failingWriter fails every write without writing anything.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// shortOnceWriter writes only half of the first line it is given and reports
// io.ErrShortWrite, then passes every later write through.
type shortOnceWriter struct {
	buf   bytes.Buffer
	short bool
}

func (w *shortOnceWriter) Write(p []byte) (int, error) {
	if !w.short {
		w.short = true
		n, _ := w.buf.Write(p[:len(p)/2])
		return n, io.ErrShortWrite
	}
	return w.buf.Write(p)
}

// jsonLines splits s into non-empty lines and parses each as one JSON object.
func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		require.NoErrorf(t, json.Unmarshal([]byte(line), &m), "line is not one JSON object: %q", line)
		out = append(out, m)
	}
	return out
}

// newMeter returns a meter provider backed by a manual reader, and a function
// that reads the current value of the write-failures counter.
func newMeter(t *testing.T) (*sdkmetric.MeterProvider, func() int64) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	return mp, func() int64 {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(t.Context(), &rm))
		var total int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != WriteFailuresMetricName {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "the write-failures counter must be an int64 sum")
				for _, dp := range sum.DataPoints {
					assert.Zero(t, dp.Attributes.Len(), "the write-failures counter must have no attributes")
					total += dp.Value
				}
			}
		}
		return total
	}
}

func TestHandlerMiddleware_RoutesAuditRecordToAuditWriter(t *testing.T) {
	t.Parallel()

	var auditOut, opOut bytes.Buffer
	logger := logging.New(
		logging.WithOutput(&opOut),
		logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(&auditOut))),
	)

	event := testEvent()
	event.LogTo(t.Context(), logger, LevelAudit)

	assert.Empty(t, opOut.String(), "audit record must not reach the operator output")
	require.True(t, strings.HasSuffix(auditOut.String(), "\n"), "audit line must end with a newline")
	lines := jsonLines(t, auditOut.String())
	require.Len(t, lines, 1)
	line := lines[0]
	assert.Equal(t, "audit_event", line["msg"])
	assert.Equal(t, "AUDIT", line["level"])
	assert.Equal(t, "audit", line["logger"])
	assert.Equal(t, event.Metadata.AuditID, line["audit_id"])
	assert.Equal(t, "widgets.widget.update", line["type"])
	assert.Equal(t, "example-service", line["component"])
}

func TestHandlerMiddleware_LeavesOperatorRecordsUnchanged(t *testing.T) {
	t.Parallel()

	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	levels := []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError}
	formats := map[string]logging.Format{"json": logging.FormatJSON, "text": logging.FormatText}

	for name, format := range formats {
		for _, level := range levels {
			t.Run(name+"/"+level.String(), func(t *testing.T) {
				t.Parallel()

				var plainOut, opOut, auditOut bytes.Buffer
				plain := logging.NewHandler(
					logging.WithOutput(&plainOut),
					logging.WithFormat(format),
					logging.WithLevel(slog.LevelDebug),
				)
				wrapped := logging.NewHandler(
					logging.WithOutput(&opOut),
					logging.WithFormat(format),
					logging.WithLevel(slog.LevelDebug),
					logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(&auditOut))),
				)

				assert.Equal(t, plain.Enabled(t.Context(), level), wrapped.Enabled(t.Context(), level))

				r := slog.NewRecord(fixed, level, "jobs.cleanup finished", 0)
				r.AddAttrs(slog.Int("removed", 3), slog.Group("job", slog.String("id", "j-1")))
				require.NoError(t, plain.Handle(t.Context(), r.Clone()))
				require.NoError(t, wrapped.Handle(t.Context(), r.Clone()))

				assert.NotEmpty(t, opOut.String())
				assert.Equal(t, plainOut.String(), opOut.String(), "operator output must be byte-for-byte unchanged")
				assert.Empty(t, auditOut.String(), "operator records must never reach the audit writer")
			})
		}
	}
}

func TestHandlerMiddleware_DropsWithAttrsAndGroups(t *testing.T) {
	t.Parallel()

	var auditOut, opOut bytes.Buffer
	logger := logging.New(
		logging.WithOutput(&opOut),
		logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(&auditOut))),
	).With("k", "v").WithGroup("g")

	testEvent().LogTo(t.Context(), logger, LevelAudit)
	logger.Info("operator", "inner", "x")

	auditLines := jsonLines(t, auditOut.String())
	require.Len(t, auditLines, 1)
	assert.NotContains(t, auditLines[0], "k", "With attributes must not appear on audit records")
	assert.NotContains(t, auditLines[0], "g", "WithGroup must not apply to audit records")
	assert.Equal(t, "widgets.widget.update", auditLines[0]["type"], "audit keys stay at the top level")

	opLines := jsonLines(t, opOut.String())
	require.Len(t, opLines, 1)
	assert.Equal(t, "v", opLines[0]["k"])
	group, ok := opLines[0]["g"].(map[string]any)
	require.True(t, ok, "operator record must carry the group")
	assert.Equal(t, "x", group["inner"])
}

func TestHandlerMiddleware_IgnoresOperatorLevel(t *testing.T) {
	t.Parallel()

	for _, level := range []slog.Level{slog.LevelWarn, slog.LevelError} {
		t.Run(level.String(), func(t *testing.T) {
			t.Parallel()

			var auditOut, opOut bytes.Buffer
			logger := logging.New(
				logging.WithOutput(&opOut),
				logging.WithLevel(level),
				logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(&auditOut))),
			)

			assert.True(t, logger.Enabled(t.Context(), LevelAudit))
			testEvent().LogTo(t.Context(), logger, LevelAudit)
			logger.Info("filtered")

			assert.Len(t, jsonLines(t, auditOut.String()), 1, "audit record must be written whatever the operator level")
			assert.Empty(t, opOut.String(), "info record must still be filtered")
		})
	}
}

// traceStamper is an inner middleware that adds a trace_id to every record.
type traceStamper struct{ slog.Handler }

func (h traceStamper) Handle(ctx context.Context, r slog.Record) error {
	r.AddAttrs(slog.String("trace_id", "0123456789abcdef"))
	return h.Handler.Handle(ctx, r)
}

// everySecondDropper is an inner middleware that drops every second record.
type everySecondDropper struct {
	slog.Handler
	n *atomic.Int64
}

func (h everySecondDropper) Handle(ctx context.Context, r slog.Record) error {
	if h.n.Add(1)%2 == 0 {
		return nil
	}
	return h.Handler.Handle(ctx, r)
}

func TestHandlerMiddleware_InnerMiddlewareCannotTouchAuditRecords(t *testing.T) {
	t.Parallel()

	formats := map[string]logging.Format{"json": logging.FormatJSON, "text": logging.FormatText}
	for name, format := range formats {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var auditOut, opOut bytes.Buffer
			var seen atomic.Int64
			logger := logging.New(
				logging.WithOutput(&opOut),
				logging.WithFormat(format),
				logging.WithHandlerMiddleware(func(h slog.Handler) slog.Handler { return traceStamper{h} }),
				logging.WithHandlerMiddleware(func(h slog.Handler) slog.Handler {
					return everySecondDropper{Handler: h, n: &seen}
				}),
				logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(&auditOut))),
			)

			const n = 10
			for range n {
				testEvent().LogTo(t.Context(), logger, LevelAudit)
				logger.Info("operator")
			}

			lines := jsonLines(t, auditOut.String())
			require.Len(t, lines, n, "every audit record must be written exactly once")
			for _, line := range lines {
				assert.NotContains(t, line, "trace_id")
				assert.Equal(t, "AUDIT", line["level"])
			}
			assert.Equal(t, int64(n), seen.Load(), "inner middleware must see only operator records")
			assert.Contains(t, opOut.String(), "trace_id", "inner middleware still applies to operator records")
		})
	}
}

func TestHandlerMiddleware_GateOff(t *testing.T) {
	t.Parallel()

	var auditOut, opOut, plainOut bytes.Buffer
	logger := logging.New(
		logging.WithOutput(&opOut),
		logging.WithHandlerMiddleware(HandlerMiddleware(WithEnabled(false), WithWriter(&auditOut))),
	)
	plain := logging.New(logging.WithOutput(&plainOut))

	assert.False(t, logger.Enabled(t.Context(), LevelAudit))
	assert.Equal(t, plain.Enabled(t.Context(), slog.LevelInfo), logger.Enabled(t.Context(), slog.LevelInfo))

	testEvent().LogTo(t.Context(), logger, LevelAudit)
	// Handle must drop audit records even when a caller skips Enabled.
	require.NoError(t, logger.Handler().Handle(t.Context(), slog.NewRecord(time.Now(), LevelAudit, "audit_event", 0)))
	logger.Info("operator")

	assert.Empty(t, auditOut.String())
	opLines := jsonLines(t, opOut.String())
	require.Len(t, opLines, 1)
	assert.Equal(t, "operator", opLines[0]["msg"])
}

func TestHandlerMiddleware_FailedWriteCounted(t *testing.T) {
	t.Parallel()

	mp, failures := newMeter(t)
	var opOut bytes.Buffer
	logger := logging.New(
		logging.WithOutput(&opOut),
		logging.WithHandlerMiddleware(HandlerMiddleware(
			WithWriter(failingWriter{}),
			WithMeterProvider(mp),
		)),
	)

	// Each iteration fails two audit records: one through LogTo and one
	// through a direct Handle call.
	const failuresPerIteration = 2
	for i := range 3 {
		require.NotPanics(t, func() { testEvent().LogTo(t.Context(), logger, LevelAudit) })
		require.NoError(t, logger.Handler().Handle(t.Context(), slog.NewRecord(time.Now(), LevelAudit, "audit_event", 0)))
		assert.Equal(t, int64(failuresPerIteration*(i+1)), failures(), "one failure per failed audit record")
	}

	logger.Info("after failure")
	opLines := jsonLines(t, opOut.String())
	require.Len(t, opLines, 1)
	assert.Equal(t, "after failure", opLines[0]["msg"])
}

func TestHandlerMiddleware_FailedWriteNotLogged(t *testing.T) {
	t.Parallel()

	var opOut bytes.Buffer
	logger := logging.New(
		logging.WithOutput(&opOut),
		logging.WithLevel(slog.LevelDebug),
		logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(failingWriter{}))),
	)

	for range 5 {
		testEvent().LogTo(t.Context(), logger, LevelAudit)
	}
	assert.Empty(t, opOut.String(), "a failed audit write must not be reported on the operator output")
}

func TestHandlerMiddleware_ShortWriteRestoresLineBoundary(t *testing.T) {
	t.Parallel()

	mp, failures := newMeter(t)
	w := &shortOnceWriter{}
	logger := logging.New(
		logging.WithOutput(io.Discard),
		logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(w), WithMeterProvider(mp))),
	)

	testEvent().LogTo(t.Context(), logger, LevelAudit)
	assert.Equal(t, int64(1), failures(), "a short write counts as a failure")

	second := testEvent()
	second.LogTo(t.Context(), logger, LevelAudit)
	assert.Equal(t, int64(1), failures(), "the following write succeeds")

	lines := strings.Split(strings.TrimSuffix(w.buf.String(), "\n"), "\n")
	require.Len(t, lines, 2, "the partial line and the next record must be on separate lines")
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &m), "the next record must parse as one JSON object")
	assert.Equal(t, second.Metadata.AuditID, m["audit_id"])

	third := testEvent()
	third.LogTo(t.Context(), logger, LevelAudit)
	assert.Len(t, strings.Split(strings.TrimSuffix(w.buf.String(), "\n"), "\n"), 3,
		"once the boundary is restored no extra newline is added")
}

func TestHandlerMiddleware_ConcurrentWritesWholeLines(t *testing.T) {
	t.Parallel()

	const goroutines, perGoroutine = 64, 100

	// One middleware applied to two loggers: both must serialize on the same
	// lock. overlapWriter fails the test if two Write calls overlap, so the
	// assertion does not depend on the race detector.
	auditOut := &overlapWriter{}
	var opOut lockedBuffer
	mw := HandlerMiddleware(WithWriter(auditOut))
	loggers := []*slog.Logger{
		logging.New(logging.WithOutput(&opOut), logging.WithHandlerMiddleware(mw)),
		logging.New(logging.WithOutput(&opOut), logging.WithHandlerMiddleware(mw)),
	}

	var wg sync.WaitGroup
	for g := range goroutines {
		logger := loggers[g%len(loggers)]
		wg.Go(func() {
			for range perGoroutine {
				testEvent().LogTo(t.Context(), logger, LevelAudit)
				logger.Info("operator")
			}
		})
	}
	wg.Wait()

	assert.False(t, auditOut.overlapped.Load(), "audit writes must never overlap")
	lines := jsonLines(t, auditOut.buf.String())
	assert.Len(t, lines, goroutines*perGoroutine)
	for _, line := range lines {
		assert.Equal(t, "AUDIT", line["level"])
	}
	assert.Len(t, jsonLines(t, opOut.String()), goroutines*perGoroutine)
}

func TestHandlerMiddleware_Options(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        []MiddlewareOption
		wantEnabled bool
		wantStdout  bool
	}{
		{name: "defaults", wantEnabled: true, wantStdout: true},
		{name: "nil writer keeps stdout", opts: []MiddlewareOption{WithWriter(nil)}, wantEnabled: true, wantStdout: true},
		{name: "nil meter provider keeps default", opts: []MiddlewareOption{WithMeterProvider(nil)}, wantEnabled: true, wantStdout: true},
		{name: "gate off", opts: []MiddlewareOption{WithEnabled(false)}, wantEnabled: false, wantStdout: true},
		{name: "custom writer", opts: []MiddlewareOption{WithWriter(io.Discard)}, wantEnabled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := HandlerMiddleware(tt.opts...)(slog.NewJSONHandler(io.Discard, nil))
			ah, ok := h.(*auditHandler)
			require.True(t, ok)
			assert.Equal(t, tt.wantEnabled, h.Enabled(t.Context(), LevelAudit))
			assert.Equal(t, tt.wantStdout, ah.sink.w == io.Writer(os.Stdout))
			assert.NotNil(t, ah.sink.failures)
		})
	}
}

func TestHandlerMiddleware_ApplicationsShareOneSink(t *testing.T) {
	t.Parallel()

	mw := HandlerMiddleware(WithWriter(io.Discard))
	a := mw(slog.NewJSONHandler(io.Discard, nil)).(*auditHandler)
	b := mw(slog.NewJSONHandler(io.Discard, nil)).(*auditHandler)
	assert.Same(t, a.sink, b.sink, "every application of one middleware shares its sink and lock")

	derived := a.WithAttrs([]slog.Attr{slog.String("k", "v")}).WithGroup("g").(*auditHandler)
	assert.Same(t, a.sink, derived.sink, "derived handlers share the parent's sink")
}

func TestRenderAuditLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		attrs []slog.Attr
		check func(t *testing.T, m map[string]any)
	}{
		{
			name: "no attributes",
			check: func(t *testing.T, m map[string]any) {
				t.Helper()
				assert.Equal(t, "AUDIT", m["level"])
				assert.Equal(t, "audit", m["logger"])
				assert.Equal(t, "audit_event", m["msg"])
			},
		},
		{
			name:  "nested level key is not rewritten",
			attrs: []slog.Attr{slog.Group("data", slog.Any("level", LevelAudit))},
			check: func(t *testing.T, m map[string]any) {
				t.Helper()
				assert.Equal(t, "AUDIT", m["level"])
				data, ok := m["data"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "INFO+2", data["level"])
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := slog.NewRecord(time.Now(), LevelAudit, "audit_event", 0)
			r.AddAttrs(tt.attrs...)
			line, err := renderAuditLine(t.Context(), r)
			require.NoError(t, err)
			require.True(t, bytes.HasSuffix(line, []byte("\n")))
			assert.Equal(t, 1, bytes.Count(line, []byte("\n")), "one line per record")

			var m map[string]any
			require.NoError(t, json.Unmarshal(line, &m))
			tt.check(t, m)
		})
	}
}

// overlapWriter records whether two Write calls were ever in flight at once.
// It yields inside Write to widen the window an unsynchronized caller would
// hit.
type overlapWriter struct {
	inFlight   atomic.Int32
	overlapped atomic.Bool
	buf        lockedBuffer
}

func (w *overlapWriter) Write(p []byte) (int, error) {
	if w.inFlight.Add(1) != 1 {
		w.overlapped.Store(true)
	}
	defer w.inFlight.Add(-1)
	runtime.Gosched()
	return w.buf.Write(p)
}

// writeStep scripts one Write call: n bytes land (n < 0 means all of them)
// and err is returned.
type writeStep struct {
	n   int
	err error
}

// scriptedWriter plays its steps in order, then accepts every later write in
// full.
type scriptedWriter struct {
	steps []writeStep
	buf   bytes.Buffer
}

func (w *scriptedWriter) Write(p []byte) (int, error) {
	if len(w.steps) == 0 {
		return w.buf.Write(p)
	}
	step := w.steps[0]
	w.steps = w.steps[1:]
	n := step.n
	if n < 0 || n > len(p) {
		n = len(p)
	}
	w.buf.Write(p[:n])
	return n, step.err
}

func TestHandlerMiddleware_LineBoundaryTransitions(t *testing.T) {
	t.Parallel()

	const partial = 10 // bytes of a record that land on a short write
	errBroken := errors.New("broken pipe")

	tests := []struct {
		name      string
		steps     []writeStep
		wantFails int64
	}{
		{
			name:      "short write with nil error",
			steps:     []writeStep{{n: partial}},
			wantFails: 1,
		},
		{
			name:      "short write with error",
			steps:     []writeStep{{n: partial, err: io.ErrShortWrite}},
			wantFails: 1,
		},
		{
			name:      "zero-byte failure after a partial line keeps the repair pending",
			steps:     []writeStep{{n: partial, err: io.ErrShortWrite}, {n: 0, err: errBroken}},
			wantFails: 2,
		},
		{
			name:      "write that lands only the repair newline restores the boundary",
			steps:     []writeStep{{n: partial, err: io.ErrShortWrite}, {n: 1, err: io.ErrShortWrite}},
			wantFails: 2,
		},
		{
			name:      "short write of a repaired line leaves a new partial line",
			steps:     []writeStep{{n: partial, err: io.ErrShortWrite}, {n: 1 + partial, err: io.ErrShortWrite}},
			wantFails: 2,
		},
		{
			name:      "zero-byte failure on a clean boundary adds no newline",
			steps:     []writeStep{{n: 0, err: errBroken}},
			wantFails: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mp, failures := newMeter(t)
			w := &scriptedWriter{steps: append([]writeStep(nil), tt.steps...)}
			logger := logging.New(
				logging.WithOutput(io.Discard),
				logging.WithHandlerMiddleware(HandlerMiddleware(WithWriter(w), WithMeterProvider(mp))),
			)

			// One record per scripted step, then one record that must land
			// whole on its own line.
			for range tt.steps {
				testEvent().LogTo(t.Context(), logger, LevelAudit)
			}
			last := testEvent()
			last.LogTo(t.Context(), logger, LevelAudit)

			assert.Equal(t, tt.wantFails, failures())

			out := w.buf.String()
			require.True(t, strings.HasSuffix(out, "\n"))
			lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
			for i, line := range lines {
				assert.NotEmptyf(t, line, "line %d is blank: no stray newline may be written", i)
			}
			var m map[string]any
			require.NoError(t, json.Unmarshal([]byte(lines[len(lines)-1]), &m),
				"the record after the failures must parse as one JSON object")
			assert.Equal(t, last.Metadata.AuditID, m["audit_id"])
		})
	}
}

// failingMeterProvider returns meters whose instrument creation fails.
type failingMeterProvider struct{ noop.MeterProvider }

func (failingMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter { return failingMeter{} }

type failingMeter struct{ noop.Meter }

func (failingMeter) Int64Counter(string, ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return nil, errors.New("instrument rejected")
}

func TestHandlerMiddleware_CounterCreationFailureFallsBackToNoop(t *testing.T) {
	t.Parallel()

	var opOut bytes.Buffer
	h := HandlerMiddleware(
		WithWriter(failingWriter{}),
		WithMeterProvider(failingMeterProvider{}),
	)(logging.NewHandler(logging.WithOutput(&opOut)))

	require.NotNil(t, h.(*auditHandler).sink.failures, "a no-op counter must replace the failed one")
	logger := slog.New(h)
	require.NotPanics(t, func() { testEvent().LogTo(t.Context(), logger, LevelAudit) })
	require.NoError(t, h.Handle(t.Context(), slog.NewRecord(time.Now(), LevelAudit, "audit_event", 0)))
	assert.Empty(t, opOut.String())

	// Audit output still works when the counter could not be created.
	var auditOut bytes.Buffer
	ok := HandlerMiddleware(WithWriter(&auditOut), WithMeterProvider(failingMeterProvider{}))(slog.NewJSONHandler(io.Discard, nil))
	testEvent().LogTo(t.Context(), slog.New(ok), LevelAudit)
	assert.Len(t, jsonLines(t, auditOut.String()), 1)
}
