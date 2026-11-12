// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"fmt"
	"io"
	"os"
	"time"
)

// Type names a supported audit sink.
type Type string

const (
	// TypeStdout writes audit lines to os.Stdout. The default when no
	// sinks are configured, preserving every existing emitter's behavior.
	TypeStdout Type = "stdout"
	// TypeHTTP POSTs each audit line to an HTTP endpoint.
	TypeHTTP Type = "http"
)

// HTTPConfig configures an HTTP webhook sink.
type HTTPConfig struct {
	// URL is the endpoint every audit line is POSTed to.
	URL string
	// Headers are added to every request (e.g. an Authorization bearer).
	Headers map[string]string
	// Timeout bounds each POST. Defaults to 5s when zero.
	Timeout time.Duration
}

// Entry configures one audit sink. HTTP is required when Type is TypeHTTP
// and nil for TypeStdout.
type Entry struct {
	Type Type
	HTTP *HTTPConfig
}

// Config lists the sinks an audit writer fans out to.
type Config struct {
	// Sinks to write every audit line to. Empty or nil defaults to
	// stdout-only — the pre-existing behavior of every audit emitter in the
	// platform, so leaving this unset changes nothing.
	Sinks []Entry
}

// NewWriter builds an io.WriteCloser that fans every Write out to all of
// cfg's configured sinks. One sink failing does not prevent the others from
// receiving the write (see fanoutWriter) — audit delivery is best-effort, and
// a flaky network sink must never starve stdout or any other configured sink.
func NewWriter(cfg Config) (io.WriteCloser, error) {
	if len(cfg.Sinks) == 0 {
		return nopWriteCloser{os.Stdout}, nil
	}

	writers := make([]io.WriteCloser, 0, len(cfg.Sinks))
	for i, s := range cfg.Sinks {
		w, err := newSinkWriter(s)
		if err != nil {
			return nil, fmt.Errorf("audit sink %d (%s): %w", i, s.Type, err)
		}
		writers = append(writers, w)
	}
	if len(writers) == 1 {
		return writers[0], nil
	}
	return &fanoutWriter{writers: writers}, nil
}

func newSinkWriter(s Entry) (io.WriteCloser, error) {
	switch s.Type {
	case TypeStdout, "":
		return nopWriteCloser{os.Stdout}, nil
	case TypeHTTP:
		if s.HTTP == nil {
			return nil, fmt.Errorf("http sink requires HTTP config")
		}
		return newHTTPWriter(*s.HTTP), nil
	default:
		return nil, fmt.Errorf("unknown audit sink type %q", s.Type)
	}
}

// nopWriteCloser adapts an io.Writer (os.Stdout, which must never be
// closed) to io.WriteCloser.
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

// fanoutWriter writes to every writer unconditionally, unlike
// io.MultiWriter, which aborts on the first writer's error. A flaky HTTP
// sink must never prevent stdout — or any other configured sink —
// from receiving the same line.
type fanoutWriter struct {
	writers []io.WriteCloser
}

func (f *fanoutWriter) Write(p []byte) (int, error) {
	var firstErr error
	for _, w := range f.writers {
		if _, err := w.Write(p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return len(p), firstErr
}

// Close closes every writer, continuing past a failure so one sink cannot
// prevent the others from releasing their resources. Returns the first
// error encountered, if any.
func (f *fanoutWriter) Close() error {
	var firstErr error
	for _, w := range f.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
