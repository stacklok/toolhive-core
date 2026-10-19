// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides OpenTelemetry Protocol (OTLP) provider implementations
package otlp

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/credentials"
)

// NewMetricReader creates an OTLP metric reader for use in a unified meter provider
func NewMetricReader(ctx context.Context, config Config) (sdkmetric.Reader, error) {
	if config.Endpoint == "" {
		return nil, fmt.Errorf("OTLP endpoint is required")
	}

	exporter, err := createMetricExporter(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP metric exporter: %w", err)
	}

	// Same budget as the exporter, deliberately. The reader's own default is
	// 30s, so a larger ExportTimeout would otherwise be silently truncated; and
	// under OTLP/HTTP this is what bounds the exporter's retry of a batch the
	// destination may already have.
	return sdkmetric.NewPeriodicReader(exporter,
		sdkmetric.WithTimeout(config.exportTimeoutFor(metricsTimeoutEnv)),
	), nil
}

func createMetricExporter(ctx context.Context, config Config) (sdkmetric.Exporter, error) {
	if config.isGRPC() {
		return createGRPCMetricExporter(ctx, config)
	}
	return createHTTPMetricExporter(ctx, config)
}

func createHTTPMetricExporter(ctx context.Context, config Config) (sdkmetric.Exporter, error) {
	host, basePath := splitEndpointPath(config.Endpoint)
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(host),
		otlpmetrichttp.WithTimeout(config.exportTimeoutFor(metricsTimeoutEnv)),
	}

	if basePath != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(basePath+otlpMetricsPath))
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for metric exporter: %w", err)
		}
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsCfg))
	}

	return otlpmetrichttp.New(ctx, opts...)
}

// createGRPCMetricExporter builds an OTLP/gRPC metric exporter. See the
// comment on createGRPCTraceExporter for why a base path in config.Endpoint
// is silently ignored under gRPC.
func createGRPCMetricExporter(ctx context.Context, config Config) (sdkmetric.Exporter, error) {
	host, _ := splitEndpointPath(config.Endpoint)
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(host),
		otlpmetricgrpc.WithTimeout(config.exportTimeoutFor(metricsTimeoutEnv)),
	}

	if len(config.Headers) > 0 {
		opts = append(opts, otlpmetricgrpc.WithHeaders(config.Headers))
	}

	if config.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}

	if config.CACertPath != "" {
		tlsCfg, err := newTLSConfigFromCA(config.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS for metric exporter: %w", err)
		}
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	}

	return otlpmetricgrpc.New(ctx, opts...)
}
