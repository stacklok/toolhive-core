// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPWriter_PostsBodyToConfiguredURL(t *testing.T) {
	t.Parallel()

	var gotBody []byte
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Api-Key")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	w := newHTTPWriter(HTTPConfig{
		URL:     srv.URL,
		Headers: map[string]string{"X-Api-Key": "secret"},
		Timeout: time.Second,
	})

	n, err := w.Write([]byte(`{"type":"test"}`))
	require.NoError(t, err)
	assert.Equal(t, len(`{"type":"test"}`), n)
	assert.Equal(t, `{"type":"test"}`, string(gotBody))
	assert.Equal(t, "secret", gotHeader)
	require.NoError(t, w.Close())
}

func TestHTTPWriter_NonSuccessStatusIsAnError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	w := newHTTPWriter(HTTPConfig{URL: srv.URL, Timeout: time.Second})

	_, err := w.Write([]byte("x"))
	require.Error(t, err)
}

func TestHTTPWriter_UnreachableURLIsAnError(t *testing.T) {
	t.Parallel()

	w := newHTTPWriter(HTTPConfig{URL: "http://127.0.0.1:0", Timeout: 100 * time.Millisecond})

	_, err := w.Write([]byte("x"))
	require.Error(t, err)
}
