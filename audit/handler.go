// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

const (
	// levelAuditName is how [LevelAudit] is rendered on an audit line, so log
	// pipelines that filter on standard level names see "AUDIT" rather than
	// slog's default "INFO+2".
	levelAuditName = "AUDIT"

	// loggerKey and loggerAudit form the attribute stamped on every audit line,
	// so a collector can select audit records with a single rule.
	loggerKey   = "logger"
	loggerAudit = "audit"

	// meterName is the instrumentation scope of the middleware's metrics.
	meterName = "github.com/stacklok/toolhive-core/audit"

	// writeFailuresMetric counts audit records whose write to the audit
	// writer failed or was short.
	writeFailuresMetric = "audit.write.failures"
)

// MiddlewareOption configures [HandlerMiddleware].
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	enabled       bool
	writer        io.Writer
	meterProvider metric.MeterProvider
}

// WithEnabled sets the audit gate. When false, [LevelAudit] records are
// dropped and the handler reports them as disabled, so callers skip building
// their attributes. The default is true.
func WithEnabled(enabled bool) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.enabled = enabled
	}
}

// WithAuditWriter sets where audit lines are written. The default is
// [os.Stdout]. A nil writer keeps the default.
func WithAuditWriter(w io.Writer) MiddlewareOption {
	return func(c *middlewareConfig) {
		if w != nil {
			c.writer = w
		}
	}
}

// WithMeterProvider sets the meter provider used for the
// audit.write.failures counter. The default is the global provider returned
// by [otel.GetMeterProvider]. A nil provider keeps the default.
func WithMeterProvider(mp metric.MeterProvider) MiddlewareOption {
	return func(c *middlewareConfig) {
		if mp != nil {
			c.meterProvider = mp
		}
	}
}

// HandlerMiddleware returns a [log/slog.Handler] wrapper that routes
// [LevelAudit] records to a dedicated audit writer as JSON, and passes every
// other record to the wrapped handler unchanged. It is designed for
// logging.WithHandlerMiddleware and must be registered last, so that it is the
// outermost handler and no other middleware sees audit records.
//
// For audit records the returned handler:
//   - reports Enabled according to the gate alone, regardless of the wrapped
//     handler's level;
//   - writes one JSON line per record to the audit writer, with the level
//     rendered as "AUDIT" and the attribute logger=audit;
//   - never calls the wrapped handler, so attributes and groups added with
//     [log/slog.Logger.With] or [log/slog.Logger.WithGroup] do not appear;
//   - never returns a write error to the caller. Each failed or short write
//     increments the audit.write.failures counter and is otherwise silent.
//
// The returned function may be applied to several handlers; each application
// gets its own audit sink.
func HandlerMiddleware(opts ...MiddlewareOption) func(slog.Handler) slog.Handler {
	cfg := middlewareConfig{
		enabled: true,
		writer:  os.Stdout,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.meterProvider == nil {
		cfg.meterProvider = otel.GetMeterProvider()
	}

	return func(next slog.Handler) slog.Handler {
		return &auditHandler{
			next: next,
			sink: newAuditSink(cfg),
		}
	}
}

// auditHandler is the handler returned by [HandlerMiddleware].
type auditHandler struct {
	next slog.Handler
	sink *auditSink
}

// Enabled implements [log/slog.Handler].
func (h *auditHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if level == LevelAudit {
		return h.sink.enabled
	}
	return h.next.Enabled(ctx, level)
}

// Handle implements [log/slog.Handler]. Audit records go to the audit writer
// only; all other records go to the wrapped handler.
func (h *auditHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level != LevelAudit {
		return h.next.Handle(ctx, r)
	}
	if !h.sink.enabled {
		return nil
	}
	h.sink.write(ctx, r)
	return nil
}

// WithAttrs implements [log/slog.Handler]. The attributes apply to the wrapped
// handler only; audit records keep their keys at the top level.
func (h *auditHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &auditHandler{next: h.next.WithAttrs(attrs), sink: h.sink}
}

// WithGroup implements [log/slog.Handler]. The group applies to the wrapped
// handler only; audit records keep their keys at the top level.
func (h *auditHandler) WithGroup(name string) slog.Handler {
	return &auditHandler{next: h.next.WithGroup(name), sink: h.sink}
}

// auditSink is the audit writer and its state, shared by every handler
// derived from one [HandlerMiddleware] application.
type auditSink struct {
	enabled  bool
	failures metric.Int64Counter

	mu sync.Mutex
	w  io.Writer
	// midLine is true when the last write was short, leaving a partial line
	// on the writer. The next record then starts with a newline.
	midLine bool
}

func newAuditSink(cfg middlewareConfig) *auditSink {
	counter, err := cfg.meterProvider.Meter(meterName).Int64Counter(
		writeFailuresMetric,
		metric.WithDescription("Number of audit records whose write to the audit writer failed or was short."),
		metric.WithUnit("{record}"),
	)
	if err != nil {
		// The SDK returns a usable instrument alongside a name or unit
		// validation error, but the API does not promise it. Fall back to a
		// no-op counter so a metrics problem never blocks audit output.
		counter, _ = noop.NewMeterProvider().Meter(meterName).Int64Counter(writeFailuresMetric)
	}
	return &auditSink{
		enabled:  cfg.enabled,
		failures: counter,
		w:        cfg.writer,
	}
}

// write renders r and writes it as one line in a single Write call. Failures
// are counted, never returned or logged, so a broken audit writer neither
// fails the caller nor floods another output.
func (s *auditSink) write(ctx context.Context, r slog.Record) {
	line, err := renderAuditLine(ctx, r)
	if err != nil {
		s.failures.Add(ctx, 1)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.midLine {
		line = append([]byte{'\n'}, line...)
	}
	n, err := s.w.Write(line)
	if n > 0 {
		s.midLine = n < len(line)
	}
	if err != nil || n < len(line) {
		s.failures.Add(ctx, 1)
	}
}

// auditHandlerOptions renders the level of audit records as "AUDIT".
var auditHandlerOptions = &slog.HandlerOptions{
	Level: LevelAudit,
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.LevelKey {
			if level, ok := a.Value.Any().(slog.Level); ok && level == LevelAudit {
				a.Value = slog.StringValue(levelAuditName)
			}
		}
		return a
	},
}

// renderAuditLine returns the exact bytes the middleware writes for an audit
// record: one JSON object terminated by a newline, with the level rendered as
// "AUDIT" and logger=audit. Anything that measures or checks audit lines must
// use this function so it sees the same bytes.
func renderAuditLine(ctx context.Context, r slog.Record) ([]byte, error) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, auditHandlerOptions).
		WithAttrs([]slog.Attr{slog.String(loggerKey, loggerAudit)})
	if err := h.Handle(ctx, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
