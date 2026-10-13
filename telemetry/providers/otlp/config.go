// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides OpenTelemetry Protocol (OTLP) provider implementations
package otlp

import "time"

// Protocol values accepted by Config.Protocol. An empty/unset Protocol is
// equivalent to ProtocolHTTPProtobuf.
const (
	// ProtocolHTTPProtobuf selects the OTLP/HTTP transport with protobuf payloads.
	// This is the default when Protocol is left unset.
	ProtocolHTTPProtobuf = "http/protobuf"
	// ProtocolGRPC selects the OTLP/gRPC transport.
	ProtocolGRPC = "grpc"
)

// DefaultExportTimeout bounds one trace export when Config.ExportTimeout is
// unset. It replaces the SDK exporters' own 10s default, which is tight for
// the off-cluster destinations this package exists to reach — a custom base
// path on Endpoint is how a caller targets a third-party ingest route.
//
// The value matters because the SDK's two timeouts are asymmetric. Under
// OTLP/HTTP — this package's default transport — the exporter's timeout is
// the HTTP client's PER-REQUEST deadline, and a request that trips it is
// classified retryable and sent again; only the span processor's export
// budget bounds that retry. A destination that accepts a batch but answers
// slower than the exporter's deadline is therefore handed the same batch
// twice, and because the retry succeeds nothing is logged on this side. A
// receiver that counts what it receives then counts those spans twice.
// Giving both the same budget leaves that re-send no room.
const DefaultExportTimeout = 30 * time.Second

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
	// ExportTimeout bounds a single trace export. It is applied to both the
	// exporter and the span processor, so neither can outlive the other. Set
	// it above the destination's worst-case response time. Zero or negative
	// means DefaultExportTimeout — see that constant for why the default is
	// not the SDK's.
	ExportTimeout time.Duration
}

// isGRPC reports whether the config selects the OTLP/gRPC transport.
func (c Config) isGRPC() bool {
	return c.Protocol == ProtocolGRPC
}

// exportTimeout resolves the export deadline, falling back to
// DefaultExportTimeout for an unset or nonsensical value.
func (c Config) exportTimeout() time.Duration {
	if c.ExportTimeout <= 0 {
		return DefaultExportTimeout
	}
	return c.ExportTimeout
}
