// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingWriter always fails, and records whether it was written to.
type failingWriter struct {
	written bool
	err     error
}

func (f *failingWriter) Write(_ []byte) (int, error) {
	f.written = true
	return 0, f.err
}

func (*failingWriter) Close() error { return nil }

// recordingWriter records every byte slice it receives.
type recordingWriter struct {
	writes [][]byte
	closed bool
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	r.writes = append(r.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (r *recordingWriter) Close() error {
	r.closed = true
	return nil
}

func TestFanoutWriter_AttemptsEveryWriterDespiteOneFailing(t *testing.T) {
	t.Parallel()

	failing := &failingWriter{err: errors.New("boom")}
	recording := &recordingWriter{}

	// failing is listed first, so io.MultiWriter would have aborted before
	// ever reaching recording — this is exactly the behavior fanoutWriter
	// must not have.
	f := &fanoutWriter{writers: []io.WriteCloser{failing, recording}}

	n, err := f.Write([]byte(`{"type":"test"}`))
	require.Error(t, err)
	assert.Equal(t, len(`{"type":"test"}`), n)
	assert.True(t, failing.written)
	require.Len(t, recording.writes, 1)
	assert.Equal(t, `{"type":"test"}`, string(recording.writes[0]))
}

func TestFanoutWriter_ReturnsFirstErrorOnly(t *testing.T) {
	t.Parallel()

	first := &failingWriter{err: errors.New("first")}
	second := &failingWriter{err: errors.New("second")}
	f := &fanoutWriter{writers: []io.WriteCloser{first, second}}

	_, err := f.Write([]byte("x"))
	require.Error(t, err)
	assert.Equal(t, "first", err.Error())
	assert.True(t, first.written)
	assert.True(t, second.written, "second writer must still be attempted")
}

func TestFanoutWriter_CloseClosesEveryWriter(t *testing.T) {
	t.Parallel()

	a := &recordingWriter{}
	b := &recordingWriter{}
	f := &fanoutWriter{writers: []io.WriteCloser{a, b}}

	require.NoError(t, f.Close())
	assert.True(t, a.closed)
	assert.True(t, b.closed)
}

func TestNewWriter_DefaultsToStdoutWhenNoSinksConfigured(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(Config{})
	require.NoError(t, err)
	assert.IsType(t, nopWriteCloser{}, w)
}

func TestNewWriter_RejectsUnknownSinkType(t *testing.T) {
	t.Parallel()

	_, err := NewWriter(Config{Sinks: []Entry{{Type: "carrier-pigeon"}}})
	require.Error(t, err)
}

func TestNewWriter_RejectsHTTPSinkWithoutConfig(t *testing.T) {
	t.Parallel()

	_, err := NewWriter(Config{Sinks: []Entry{{Type: TypeHTTP}}})
	require.Error(t, err)
}

func TestNewWriter_FansOutAcrossMultipleSinks(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(Config{Sinks: []Entry{
		{Type: TypeStdout},
		{Type: TypeStdout},
	}})
	require.NoError(t, err)
	assert.IsType(t, &fanoutWriter{}, w)
}

func TestNewWriter_SingleSinkSkipsFanout(t *testing.T) {
	t.Parallel()

	w, err := NewWriter(Config{Sinks: []Entry{{Type: TypeStdout}}})
	require.NoError(t, err)
	assert.IsType(t, nopWriteCloser{}, w)
}
