// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides OpenTelemetry Protocol (OTLP) provider implementations
package otlp

import (
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Protocol values accepted by Config.Protocol. An empty/unset Protocol is
// equivalent to ProtocolHTTPProtobuf.
const (
	// ProtocolHTTPProtobuf selects the OTLP/HTTP transport with protobuf payloads.
	// This is the default when Protocol is left unset.
	ProtocolHTTPProtobuf = "http/protobuf"
	// ProtocolGRPC selects the OTLP/gRPC transport.
	ProtocolGRPC = "grpc"
)

// DefaultExportTimeout bounds one export when Config.ExportTimeout is unset and
// no OTel timeout variable applies. It replaces the SDK exporters' own 10s
// default, which is tight for the off-cluster destinations this package exists
// to reach — a custom base path on Endpoint is how a caller targets a
// third-party ingest route.
//
// The value matters because the SDK's two timeouts are asymmetric. Under
// OTLP/HTTP — this package's default transport — the exporter's timeout is the
// HTTP client's PER-REQUEST deadline, and a request that trips it is classified
// retryable and sent again; only the processor's or reader's export budget
// bounds that retry. A destination that accepts a batch but answers slower than
// the exporter's deadline is therefore handed the same batch twice, and because
// the retry succeeds nothing is logged on this side. A receiver that counts what
// it receives then counts those spans, points or records twice. Giving both the
// same budget leaves that re-send no room.
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
	// ExportTimeout bounds a single export, for traces, metrics and logs alike.
	// It is applied to both the exporter and the processor or reader driving it,
	// so neither can outlive the other. Set it above the destination's worst-case
	// response time.
	//
	// Zero or negative means the OTel environment variables for the signal, and
	// DefaultExportTimeout when those are unset too — see exportTimeoutFor for the
	// precedence and why this package resolves those variables itself.
	ExportTimeout time.Duration
	// Sampler, when non-nil, is the tracer provider's sampler and SamplingRate
	// is ignored. Nil keeps the default,
	// ParentBased(TraceIDRatioBased(SamplingRate)), which follows a remote
	// parent's sampled flag in both directions. Set this when an unsampled
	// parent from upstream (e.g. an edge proxy sampling at a low rate) must not
	// suppress this service's spans.
	Sampler sdktrace.Sampler
	// TracesEndpoint, when set, is the full URL traces are POSTed to, used
	// verbatim: no "/v1/traces" suffix is appended and its scheme alone decides
	// TLS (Insecure is not consulted for it). It overrides Endpoint for traces
	// only; metrics and logs keep using Endpoint, which may be left empty for a
	// traces-only setup. Exact paths are an OTLP/HTTP concept, so setting it
	// with ProtocolGRPC is a configuration error.
	TracesEndpoint string
}

// isGRPC reports whether the config selects the OTLP/gRPC transport.
func (c Config) isGRPC() bool {
	return c.Protocol == ProtocolGRPC
}

// hasTracesDestination reports whether traces have somewhere to be exported,
// through either TracesEndpoint or Endpoint.
func (c Config) hasTracesDestination() bool {
	return c.TracesEndpoint != "" || c.Endpoint != ""
}
