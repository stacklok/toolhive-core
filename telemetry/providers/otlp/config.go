// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides OpenTelemetry Protocol (OTLP) provider implementations
package otlp

// Protocol values accepted by Config.Protocol. An empty/unset Protocol is
// equivalent to ProtocolHTTPProtobuf.
const (
	// ProtocolHTTPProtobuf selects the OTLP/HTTP transport with protobuf payloads.
	// This is the default when Protocol is left unset.
	ProtocolHTTPProtobuf = "http/protobuf"
	// ProtocolGRPC selects the OTLP/gRPC transport.
	ProtocolGRPC = "grpc"
)

// Config holds OTLP-specific configuration
type Config struct {
	Endpoint     string
	Headers      map[string]string
	Insecure     bool
	SamplingRate float64
	CACertPath   string
	// Protocol selects the OTLP transport: ProtocolGRPC ("grpc") or
	// ProtocolHTTPProtobuf ("http/protobuf"). An empty value means
	// ProtocolHTTPProtobuf, preserving this package's original HTTP-only
	// behavior for callers that don't set it.
	Protocol string
}

// isGRPC reports whether the config selects the OTLP/gRPC transport.
func (c Config) isGRPC() bool {
	return c.Protocol == ProtocolGRPC
}
