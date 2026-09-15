// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"
)

func createLogExporter(ctx context.Context, config Config) (sdklog.Exporter, error) {
	if config.isGRPC() {
		return createGRPCLogExporter(ctx, config)
	}
	return createHTTPLogExporter(ctx, config)
}

func createHTTPLogExporter(ctx context.Context, config Config) (sdklog.Exporter, error) {
	host, basePath := splitEndpointPath(config.Endpoint)
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(host),
	}

	if basePath != "" {
		opts = append(opts, otlploghttp.WithURLPath(basePath+otlpLogsPath))
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlploghttp.WithInsecure())
	}

	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for log exporter: %w", err)
		}
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
	}

	exporter, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create log exporter: %w", err)
	}
	return exporter, nil
}

// createGRPCLogExporter builds an OTLP/gRPC log exporter. See the comment on
// createGRPCTraceExporter for why a base path in config.Endpoint is silently
// ignored under gRPC.
func createGRPCLogExporter(ctx context.Context, config Config) (sdklog.Exporter, error) {
	host, _ := splitEndpointPath(config.Endpoint)
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(host),
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlploggrpc.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for log exporter: %w", err)
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	}

	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create log exporter: %w", err)
	}
	return exporter, nil
}

// NewLoggerProviderWithShutdown creates an OTLP logger provider with a shutdown function.
// When no endpoint is configured, it returns a no-op provider with a nil shutdown function.
//
// The Logs API/SDK used here (go.opentelemetry.io/otel/log, go.opentelemetry.io/otel/sdk/log,
// and the otlploghttp exporter) implements the OpenTelemetry specification's Logs API, which
// is marked Stable (https://opentelemetry.io/docs/specs/otel/logs/api/). Their Go module
// version (v0.21.0 as of writing) hasn't crossed 1.0 yet, but that mirrors the Prometheus
// metrics exporter this package already depends on (go.opentelemetry.io/otel/exporters/prometheus,
// also 0.x): pre-1.0 module versioning here tracks release cadence, not spec/API stability.
func NewLoggerProviderWithShutdown(
	ctx context.Context,
	config Config,
	res *resource.Resource,
) (log.LoggerProvider, func(context.Context) error, error) {
	if config.Endpoint == "" {
		return lognoop.NewLoggerProvider(), nil, nil
	}

	exporter, err := createLogExporter(ctx, config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create logger provider: %w", err)
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	return provider, provider.Shutdown, nil
}
