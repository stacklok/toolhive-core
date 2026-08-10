// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/networking"
)

func TestValidateCallbackPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		port      int
		clientID  string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid port with client ID",
			port:      8090,
			clientID:  "test-client",
			wantError: false,
		},
		{
			name:      "valid port without client ID",
			port:      8090,
			clientID:  "",
			wantError: false,
		},
		{
			name:      "port zero is allowed (dynamic allocation)",
			port:      0,
			clientID:  "test-client",
			wantError: false,
		},
		{
			name:      "negative port is not allowed",
			port:      -1,
			clientID:  "",
			wantError: true,
			errorMsg:  "OAuth callback port must be between 1024 and 65535, got: -1",
		},
		{
			name:      "port less than 1024",
			port:      1000,
			clientID:  "",
			wantError: true,
			errorMsg:  "OAuth callback port must be between 1024 and 65535, got: 1000",
		},
		{
			name:      "port too large",
			port:      123456778,
			clientID:  "",
			wantError: true,
			errorMsg:  "OAuth callback port must be between 1024 and 65535, got: 123456778",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := networking.ValidateCallbackPort(tt.port, tt.clientID)

			if tt.wantError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					require.EqualError(t, err, tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetProcessOnPort_InvalidPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"port too large", 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pid, err := networking.GetProcessOnPort(tt.port)
			require.Error(t, err)
			assert.Equal(t, 0, pid)
		})
	}
}

func TestGetProcessOnPort_FreePort(t *testing.T) {
	t.Parallel()

	// Use a port that FindAvailable guarantees is free
	port := networking.FindAvailable()
	require.NotZero(t, port, "FindAvailable should find a free port")

	pid, err := networking.GetProcessOnPort(port)
	require.NoError(t, err)
	assert.Equal(t, 0, pid)
}

func TestGetProcessOnPort_PortInUse(t *testing.T) {
	t.Parallel()

	// Bind to a port, then verify GetProcessOnPort returns our process
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	port := tcpAddr.Port

	pid, err := networking.GetProcessOnPort(port)
	require.NoError(t, err)
	assert.NotZero(t, pid, "port is in use, GetProcessOnPort should return the process PID")
}

func TestFindAvailableListener_ConcurrentCallsGetDistinctPorts(t *testing.T) {
	t.Parallel()

	const numGoroutines = 20

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		listeners = make([]*net.TCPListener, 0, numGoroutines)
		ports     = make(map[int]int) // port -> count
	)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			l, err := networking.FindAvailableListener()
			if err != nil {
				return
			}

			addr, ok := l.Addr().(*net.TCPAddr)
			require.True(t, ok)

			mu.Lock()
			listeners = append(listeners, l)
			ports[addr.Port]++
			mu.Unlock()
		}()
	}
	wg.Wait()

	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	require.Len(t, listeners, numGoroutines, "all goroutines should have obtained a listener")

	for port, count := range ports {
		assert.Equal(t, 1, count, "port %d was handed out to more than one goroutine", port)
	}
}

func TestFindOrUsePort_InvalidPortRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		port      int
		wantError bool
	}{
		{"negative port is rejected", -1, true},
		{"zero means auto-select", 0, false},
		{"port 1 is a valid boundary", 1, false},
		{"port 65535 is a valid boundary", 65535, false},
		{"port 65536 is rejected", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := networking.FindOrUsePort(tt.port)
			if tt.wantError {
				require.Error(t, err)
				assert.Equal(t, 0, got)
				return
			}
			require.NoError(t, err)
			assert.NotZero(t, got)
		})
	}
}

func TestFindOrUseListener_InvalidPortRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		port      int
		wantError bool
	}{
		{"negative port is rejected", -1, true},
		{"zero means auto-select", 0, false},
		{"port 1 is a valid boundary", 1, false},
		{"port 65535 is a valid boundary", 65535, false},
		{"port 65536 is rejected", 65536, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, err := networking.FindOrUseListener(tt.port)
			if tt.wantError {
				require.Error(t, err)
				assert.Nil(t, l)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, l)
			defer l.Close()
		})
	}
}

func TestFindOrUseListener(t *testing.T) {
	t.Parallel()

	t.Run("zero port finds an available one", func(t *testing.T) {
		t.Parallel()

		l, err := networking.FindOrUseListener(0)
		require.NoError(t, err)
		defer l.Close()

		addr, ok := l.Addr().(*net.TCPAddr)
		require.True(t, ok)
		assert.GreaterOrEqual(t, addr.Port, networking.MinPort)
		assert.LessOrEqual(t, addr.Port, networking.MaxPort)
	})

	t.Run("specific free port is honored", func(t *testing.T) {
		t.Parallel()

		// Find a free port first (and release it) to request specifically.
		probe, err := networking.FindAvailableListener()
		require.NoError(t, err)
		addr, ok := probe.Addr().(*net.TCPAddr)
		require.True(t, ok)
		wantPort := addr.Port
		require.NoError(t, probe.Close())

		l, err := networking.FindOrUseListener(wantPort)
		require.NoError(t, err)
		defer l.Close()

		gotAddr, ok := l.Addr().(*net.TCPAddr)
		require.True(t, ok)
		assert.Equal(t, wantPort, gotAddr.Port)
	})

	t.Run("already-listened-on port falls back to a different one", func(t *testing.T) {
		t.Parallel()

		held, err := networking.FindAvailableListener()
		require.NoError(t, err)
		defer held.Close()

		heldAddr, ok := held.Addr().(*net.TCPAddr)
		require.True(t, ok)

		l, err := networking.FindOrUseListener(heldAddr.Port)
		require.NoError(t, err)
		defer l.Close()

		gotAddr, ok := l.Addr().(*net.TCPAddr)
		require.True(t, ok)
		assert.NotEqual(t, heldAddr.Port, gotAddr.Port)
	})
}

func TestParsePortSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		portSpec          string
		expectedHostPort  string
		expectedContainer int
		wantError         bool
	}{
		{
			name:              "host:container",
			portSpec:          "8003:8001",
			expectedHostPort:  "8003",
			expectedContainer: 8001,
			wantError:         false,
		},
		{
			name:              "container only",
			portSpec:          "8001",
			expectedHostPort:  "", // Random
			expectedContainer: 8001,
			wantError:         false,
		},
		{
			name:              "invalid format",
			portSpec:          "invalid",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "invalid host port",
			portSpec:          "abc:8001",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "negative host port is rejected",
			portSpec:          "-1:0",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "host port above range is rejected",
			portSpec:          "70000:8001",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "container port above range is rejected",
			portSpec:          "8000:99999",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "container-only port above range is rejected",
			portSpec:          "99999",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "container-only port zero is rejected",
			portSpec:          "0",
			expectedHostPort:  "",
			expectedContainer: 0,
			wantError:         true,
		},
		{
			name:              "host port 0 is passed through as Docker dynamic-port marker",
			portSpec:          "0:8080",
			expectedHostPort:  "0",
			expectedContainer: 8080,
			wantError:         false,
		},
		{
			name:              "host and container port 1 is a valid boundary",
			portSpec:          "1:1",
			expectedHostPort:  "1",
			expectedContainer: 1,
			wantError:         false,
		},
		{
			name:              "host and container port 65535 is a valid boundary",
			portSpec:          "65535:65535",
			expectedHostPort:  "65535",
			expectedContainer: 65535,
			wantError:         false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hostPort, containerPort, err := networking.ParsePortSpec(tt.portSpec)

			if tt.wantError {
				require.Error(t, err, "ParsePortSpec(%s) expected error", tt.portSpec)
				return
			}

			require.NoError(t, err, "ParsePortSpec(%s) unexpected error", tt.portSpec)

			if tt.expectedHostPort != "" {
				require.Equal(t, tt.expectedHostPort, hostPort, "ParsePortSpec(%s) unexpected host port", tt.portSpec)
			} else {
				require.NotEmpty(t, hostPort, "ParsePortSpec(%s) hostPort is empty, want random port", tt.portSpec)
			}

			require.Equal(t, tt.expectedContainer, containerPort, "ParsePortSpec(%s) unexpected container port", tt.portSpec)
		})
	}
}
