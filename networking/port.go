// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"

	gopsutilnet "github.com/shirou/gopsutil/v4/net"
)

const (
	// MinPort is the minimum port number to use
	MinPort = 10000
	// MaxPort is the maximum port number to use
	MaxPort = 65535
	// MaxAttempts is the maximum number of attempts to find an available port
	MaxAttempts = 10
)

// tryListenTCP attempts to bind a TCP listener on 127.0.0.1:port, returning the
// open listener and true on success, or nil and false if the port is unavailable.
func tryListenTCP(port int) (*net.TCPListener, bool) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, false
	}
	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return nil, false
	}
	return tcpListener, true
}

// IsAvailable checks if a port is available.
//
// Known limitation: this binds a probe listener, closes it, then returns a bool —
// there is a time-of-check-to-time-of-use window between the close and whenever the
// caller actually binds the port, during which another process can grab it. Callers
// that intend to bind the port themselves moments later in the same process should
// prefer FindAvailableListener/FindOrUseListener instead, which keep the listener
// open until the caller is ready and so close that window entirely.
func IsAvailable(port int) bool {
	// Check TCP
	tcpListener, ok := tryListenTCP(port)
	if !ok {
		return false
	}
	if err := tcpListener.Close(); err != nil {
		// Log the error but continue, as we're just checking if the port is available
		slog.Warn("Failed to close TCP listener", "error", err)
	}

	// Check UDP
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return false
	}
	if err := udpConn.Close(); err != nil {
		// Log the error but continue, as we're just checking if the port is available
		slog.Warn("Failed to close UDP connection", "error", err)
	}

	return true
}

// FindAvailable finds an available port.
//
// Known limitation: like IsAvailable, this has a bind-then-close-then-return race —
// the port can be taken by another process between this call returning and the
// caller binding it. Prefer FindAvailableListener when you will bind the port
// yourself shortly afterward in the same process.
func FindAvailable() int {
	for i := 0; i < MaxAttempts; i++ {
		// Generate a cryptographically secure random number
		n, err := rand.Int(rand.Reader, big.NewInt(int64(MaxPort-MinPort)))
		if err != nil {
			// Fall back to sequential search if random generation fails
			break
		}
		port := int(n.Int64()) + MinPort
		if IsAvailable(port) {
			return port
		}
	}

	// If we can't find a random port, try sequential ports
	for port := MinPort; port <= MaxPort; port++ {
		if IsAvailable(port) {
			return port
		}
	}

	// If we still can't find a port, return 0
	return 0
}

// FindOrUsePort checks if the provided port is available or finds an available port if none is provided.
// If port is 0, it will find an available port.
// If port is not 0, it will check if the port is available.
// Returns the selected port and an error if any.
//
// Known limitation: this has the same bind-then-close-then-return race as IsAvailable
// and FindAvailable. Prefer FindOrUseListener when you will bind the port yourself
// shortly afterward in the same process.
func FindOrUsePort(port int) (int, error) {
	if port != 0 && (port < 1 || port > 65535) {
		return 0, fmt.Errorf("invalid port %d: must be 0 (auto-select) or in range 1-65535", port)
	}

	if port == 0 {
		// Find an available port
		port = FindAvailable()
		if port == 0 {
			return 0, fmt.Errorf("could not find an available port")
		}
		return port, nil
	}

	if IsAvailable(port) {
		return port, nil
	}

	// Requested port is busy — find an alternative
	alt := FindAvailable()
	if alt == 0 {
		return 0, fmt.Errorf("failed to find an alternative port after requested port %d was unavailable", port)
	}
	return alt, nil
}

// FindAvailableListener finds an available port and returns it as a still-open
// *net.TCPListener, closing the find-then-bind race that FindAvailable has:
// since the listener stays open, nothing else can grab the port before the
// caller is ready to use it. The caller is responsible for closing the
// listener (or handing it to something like http.Serve).
func FindAvailableListener() (*net.TCPListener, error) {
	for i := 0; i < MaxAttempts; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(MaxPort-MinPort)))
		if err != nil {
			// Fall back to sequential search if random generation fails
			break
		}
		port := int(n.Int64()) + MinPort
		if l, ok := tryListenTCP(port); ok {
			return l, nil
		}
	}

	for port := MinPort; port <= MaxPort; port++ {
		if l, ok := tryListenTCP(port); ok {
			return l, nil
		}
	}

	return nil, fmt.Errorf("could not find an available port")
}

// FindOrUseListener is the race-free counterpart to FindOrUsePort: if port is 0,
// it behaves like FindAvailableListener; otherwise it tries to bind the requested
// port directly, falling back to FindAvailableListener only if that port is
// unavailable. The returned listener is still open; the caller is responsible
// for closing it.
func FindOrUseListener(port int) (*net.TCPListener, error) {
	if port != 0 && (port < 1 || port > 65535) {
		return nil, fmt.Errorf("invalid port %d: must be 0 (auto-select) or in range 1-65535", port)
	}

	if port == 0 {
		return FindAvailableListener()
	}

	if l, ok := tryListenTCP(port); ok {
		return l, nil
	}

	l, err := FindAvailableListener()
	if err != nil {
		return nil, fmt.Errorf("failed to find an alternative port after requested port %d was unavailable: %w", port, err)
	}
	return l, nil
}

// ValidateCallbackPort validates that the specified callback port is valid and available.
// It checks that the port is within the valid range (1-65535) and, for pre-registered
// clients (with clientID), it returns an error if the port is not available.
func ValidateCallbackPort(callbackPort int, clientID string) error {
	// If port is 0, we'll find an available port later, so no need to validate
	if callbackPort == 0 {
		return nil
	}

	// Validate port range
	if callbackPort < 1024 || callbackPort > 65535 {
		return fmt.Errorf("OAuth callback port must be between 1024 and 65535, got: %d", callbackPort)
	}

	// Check if this is a pre-registered client (has client credentials)
	// For pre-registered clients, we need strict port checking
	isPreRegisteredClient := IsPreRegisteredClient(clientID)

	if isPreRegisteredClient {
		// For pre-registered clients, the port must be available
		// The user likely configured this port in their IdP/app
		if !IsAvailable(callbackPort) {
			return fmt.Errorf("OAuth callback port %d is not available - please choose a different port", callbackPort)
		}
	}

	return nil
}

// IsPreRegisteredClient determines if the OAuth client is pre-registered (has client ID)
func IsPreRegisteredClient(clientID string) bool {
	return clientID != ""
}

// GetProcessOnPort returns the PID of the process listening on the given TCP port.
// Returns 0 if the port is free or if the holder cannot be determined.
// Uses gopsutil which provides cross-platform support (Linux: /proc, Windows: GetExtendedTcpTable,
// Darwin/FreeBSD: lsof).
func GetProcessOnPort(port int) (int, error) {
	if port <= 0 || port > MaxPort {
		return 0, fmt.Errorf("invalid port %d", port)
	}

	conns, err := gopsutilnet.Connections("tcp")
	if err != nil {
		return 0, fmt.Errorf("failed to get TCP connections: %w", err)
	}

	for _, c := range conns {
		if c.Laddr.Port == uint32(port) && c.Status == "LISTEN" && c.Pid > 0 { //nolint:gosec // G115 - port validated in [1, 65535]
			return int(c.Pid), nil
		}
	}
	return 0, nil
}

// ParsePortSpec parses a port specification string in the format "hostPort:containerPort" or just "containerPort".
// Returns the host port string and container port integer.
// If only a container port is provided, a random available host port is selected
// locally via FindAvailable.
//
// Host port 0 (explicit "0:containerPort" form) is passed through unchanged as
// the string "0" and is NOT resolved to a concrete port here — this is
// intentional. Docker's own PortBinding.HostPort treats "0" as "assign a port
// dynamically at container start", which is a distinct mechanism from this
// function's own container-only path (no ":") that calls FindAvailable to pick
// a host port up front.
func ParsePortSpec(portSpec string) (string, int, error) {
	slog.Debug("Parsing port spec", "spec", portSpec)
	// Check if it's in host:container format
	if strings.Contains(portSpec, ":") {
		parts := strings.Split(portSpec, ":")
		if len(parts) != 2 {
			return "", 0, fmt.Errorf("invalid port specification: %s (expected 'hostPort:containerPort')", portSpec)
		}

		hostPortStr := parts[0]
		containerPortStr := parts[1]

		// Verify host port is a valid integer (or empty string if we supported random host port with :, but here we expect explicit)
		hostPort, err := strconv.Atoi(hostPortStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid host port in spec '%s': %w", portSpec, err)
		}
		if hostPort < 0 || hostPort > 65535 {
			return "", 0, fmt.Errorf("invalid host port in spec '%s': %d must be in range 0-65535", portSpec, hostPort)
		}

		containerPort, err := strconv.Atoi(containerPortStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid container port in spec '%s': %w", portSpec, err)
		}
		if containerPort < 1 || containerPort > 65535 {
			return "", 0, fmt.Errorf("invalid container port in spec '%s': %d must be in range 1-65535", portSpec, containerPort)
		}

		return hostPortStr, containerPort, nil
	}

	// Try parsing as just container port
	containerPort, err := strconv.Atoi(portSpec)
	if err == nil {
		if containerPort < 1 || containerPort > 65535 {
			return "", 0, fmt.Errorf("invalid container port in spec '%s': %d must be in range 1-65535", portSpec, containerPort)
		}
		// Find a random available host port
		hostPort := FindAvailable()
		if hostPort == 0 {
			return "", 0, fmt.Errorf("could not find an available port for container port %d", containerPort)
		}
		return fmt.Sprintf("%d", hostPort), containerPort, nil
	}

	return "", 0, fmt.Errorf("invalid port specification: %s (expected 'hostPort:containerPort' or 'containerPort')", portSpec)
}
