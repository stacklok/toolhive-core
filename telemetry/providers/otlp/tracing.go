// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/credentials"
)

func createTraceExporter(ctx context.Context, config Config) (sdktrace.SpanExporter, error) {
	if config.isGRPC() {
		return createGRPCTraceExporter(ctx, config)
	}
	return createHTTPTraceExporter(ctx, config)
}

func createHTTPTraceExporter(ctx context.Context, config Config) (sdktrace.SpanExporter, error) {
	host, basePath := splitEndpointPath(config.Endpoint)
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(host),
	}

	if basePath != "" {
		opts = append(opts, otlptracehttp.WithURLPath(basePath+otlpTracesPath))
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for trace exporter: %w", err)
		}
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsCfg))
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}
	return exporter, nil
}

// createGRPCTraceExporter builds an OTLP/gRPC trace exporter.
//
// gRPC targets are a bare host:port with no URL path concept, unlike OTLP/HTTP
// where a custom base path (e.g. "/api/public/otel" for Langfuse) can be used
// to reach an exact ingest route via WithURLPath. Any base path present in
// config.Endpoint is therefore intentionally ignored under gRPC: it is not an
// operator error (the same Endpoint value may be shared across signals or
// carried over from an HTTP configuration), it simply has no effect, since
// every known OTLP gRPC collector listens on a fixed, well-known service path
// baked into the protobuf service definition rather than a configurable one.
func createGRPCTraceExporter(ctx context.Context, config Config) (sdktrace.SpanExporter, error) {
	host, _ := splitEndpointPath(config.Endpoint)
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(host),
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlptracegrpc.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	// When CACertPath is unset and Insecure is false, otlptracegrpc's own
	// default (credentials.NewTLS(nil), trusting the host's root CA pool)
	// applies, matching the HTTP exporter's default TLS behavior above.
	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for trace exporter: %w", err)
		}
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}
	return exporter, nil
}

// NewTracerProviderWithShutdown creates an OTLP tracer provider with a shutdown function.
// Additional span processors (e.g. a Sentry bridge) can be registered via extraProcessors.
// When endpoint is empty but extra processors are provided, a real SDK provider is created
// without an OTLP exporter so the processors still receive spans.
func NewTracerProviderWithShutdown(
	ctx context.Context,
	config Config,
	res *resource.Resource,
	extraProcessors ...sdktrace.SpanProcessor,
) (trace.TracerProvider, func(context.Context) error, error) {
	// True no-op only when there is nothing at all to do.
	if config.Endpoint == "" && len(extraProcessors) == 0 {
		return tracenoop.NewTracerProvider(), nil, nil
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		// ParentBased ensures that when an incoming W3C traceparent header marks
		// the parent as sampled (e.g. from ToolHive Studio), the child span is
		// always sampled regardless of the local ratio. Without ParentBased, a
		// bare TraceIDRatioBased sampler could drop a span even when the remote
		// parent was sampled, breaking end-to-end distributed trace correlation.
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(config.SamplingRate))),
	}

	// Only wire an OTLP exporter when an endpoint is actually configured.
	if config.Endpoint != "" {
		exporter, err := createTraceExporter(ctx, config)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create trace provider: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(exporter))
	}

	for _, p := range extraProcessors {
		opts = append(opts, sdktrace.WithSpanProcessor(p))
	}

	provider := sdktrace.NewTracerProvider(opts...)
	return provider, provider.Shutdown, nil
}
