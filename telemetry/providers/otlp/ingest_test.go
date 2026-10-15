// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// delayedOTLPIngest serves OTLP/HTTP and accepts every batch, but takes delay
// to answer — the shape that trips an export deadline.
//
// Teardown releases the handler rather than waiting out delay, so a test can
// name a delay far longer than it intends to run and still close the server
// instead of leaving the goroutine parked until the binary exits.
func delayedOTLPIngest(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()

	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case <-time.After(delay):
			w.WriteHeader(http.StatusOK)
		case <-done:
			// Tearing down; answer at once so Close has nothing to wait for.
		}
	}))

	t.Cleanup(func() {
		close(done)
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}

// recordingOTLPIngest accepts every OTLP/HTTP request at once and records its
// RequestURI, the request target exactly as sent, rather than the decoded
// r.URL.Path, which would hide an escaped "/" turning into a real one. The
// returned func snapshots the targets seen so far.
func recordingOTLPIngest(t *testing.T, newServer func(http.Handler) *httptest.Server) (*httptest.Server, func() []string) {
	t.Helper()

	var (
		mu    sync.Mutex
		paths []string
	)
	srv := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.RequestURI)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

// silentTCPPeer accepts connections and then says nothing, the shape that
// leaves a gRPC export waiting on its own deadline rather than on a refusal.
//
// Accepted connections are held open deliberately — that silence is the point —
// and closed from a single cleanup registered on the test goroutine, since
// t.Cleanup from the accept loop would race teardown.
func silentTCPPeer(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	lis, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
	)
	t.Cleanup(func() {
		_ = lis.Close()

		mu.Lock()
		defer mu.Unlock()
		closed = true
		for _, conn := range conns {
			_ = conn.Close()
		}
	})

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			mu.Lock()
			if closed {
				// Raced teardown: nothing will come back for this one.
				_ = conn.Close()
			} else {
				conns = append(conns, conn)
			}
			mu.Unlock()
		}
	}()
	return lis.Addr().String()
}
