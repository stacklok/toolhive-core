// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// traceExporterClientTypeName returns the concrete type name of the unexported
// otlptrace.Client embedded in an *otlptrace.Exporter (both otlptracehttp.New
// and otlptracegrpc.New return the same *otlptrace.Exporter type, so this is
// the only way to tell which transport was actually selected).
func traceExporterClientTypeName(t *testing.T, exporter interface{}) string {
	t.Helper()
	v := reflect.ValueOf(exporter).Elem().FieldByName("client")
	require.True(t, v.IsValid(), "exporter has no client field")
	return v.Elem().Type().String()
}

func TestCreateTraceExporter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		ctx     func() context.Context
		wantErr bool
		errMsg  string
	}{
		{
			name: testNameValid,
			config: Config{
				Endpoint: testEndpointLocal,
				Headers:  map[string]string{testAuthHeader: testBearerToken},
				Insecure: true,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "config with headers",
			config: Config{
				Endpoint: testEndpointLocal,
				Headers: map[string]string{
					testAPIKeyHeader: testSecretValue,
					testEnvHeaderKey: "test",
				},
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "secure config",
			config: Config{
				Endpoint: "secure.example.com:4318",
				Insecure: false,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: testNameCustomPath,
			config: Config{
				Endpoint: testEndpointLangfuse,
				Headers:  map[string]string{testAuthHeader: testBasicCred},
				Insecure: false,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "error creating sdk-span-exporter due to error (cancelled context)",
			config: Config{
				Endpoint: "secure.example.com:4318",
				Insecure: true,
			},
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr: true,
			errMsg:  "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.ctx()
			exporter, err := createTraceExporter(ctx, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, exporter)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, exporter)
				// Clean up
				_ = exporter.Shutdown(ctx)
			}
		})
	}
}

func TestCreateTraceExporter_ProtocolSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protocol       string
		wantClientType string
	}{
		{
			name:           testNameProtocolUnsetDefaultsHTTP,
			protocol:       "",
			wantClientType: "*otlptracehttp.client",
		},
		{
			name:           testNameProtocolExplicitHTTP,
			protocol:       ProtocolHTTPProtobuf,
			wantClientType: "*otlptracehttp.client",
		},
		{
			name:           testNameProtocolGRPC,
			protocol:       ProtocolGRPC,
			wantClientType: "*otlptracegrpc.client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			config := Config{
				Endpoint: testEndpointLocal,
				Insecure: true,
				Protocol: tt.protocol,
			}

			exporter, err := createTraceExporter(ctx, config)
			require.NoError(t, err)
			require.NotNil(t, exporter)
			defer func() { _ = exporter.Shutdown(ctx) }()

			assert.Equal(t, tt.wantClientType, traceExporterClientTypeName(t, exporter))
		})
	}
}

func TestNewTracerProviderWithShutdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         Config
		ctx            func() context.Context
		wantErr        bool
		errMsg         string
		expectNoOp     bool
		expectShutdown bool
	}{
		{
			name: "valid config with endpoint returns SDK provider with shutdown",
			config: Config{
				Endpoint:     testEndpointLocal,
				SamplingRate: 0.5,
				Headers:      map[string]string{testAuthHeader: testBearerToken},
				Insecure:     true,
			},
			ctx:            func() context.Context { return context.Background() },
			wantErr:        false,
			expectNoOp:     false,
			expectShutdown: true,
		},
		{
			name: "no endpoint returns noop provider with nil shutdown",
			config: Config{
				SamplingRate: 0.1,
			},
			ctx:            func() context.Context { return context.Background() },
			wantErr:        false,
			expectNoOp:     true,
			expectShutdown: false,
		},
		{
			name: "config with custom sampling returns SDK provider with shutdown",
			config: Config{
				Endpoint:     testEndpointLocal,
				SamplingRate: 1.0, // Always sample
				Insecure:     true,
			},
			ctx:            func() context.Context { return context.Background() },
			wantErr:        false,
			expectNoOp:     false,
			expectShutdown: true,
		},
		{
			name: "error creating trace exporter propagates error",
			config: Config{
				Endpoint:     testEndpointLocal,
				SamplingRate: 1.0,
				Insecure:     true,
			},
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			wantErr:        true,
			errMsg:         "failed to create trace exporter",
			expectNoOp:     false,
			expectShutdown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.ctx()
			res, err := resource.New(ctx,
				resource.WithAttributes(
					semconv.ServiceName("test-service"),
					semconv.ServiceVersion("1.0.0"),
				),
			)
			require.NoError(t, err)

			provider, shutdown, err := NewTracerProviderWithShutdown(ctx, tt.config, res)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
				assert.Nil(t, shutdown)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				// Check provider type
				providerType := fmt.Sprintf("%T", provider)
				if tt.expectNoOp {
					assert.Contains(t, providerType, "noop")
				} else {
					assert.NotContains(t, providerType, "noop")
				}

				// Check shutdown function
				if tt.expectShutdown {
					assert.NotNil(t, shutdown)
					// Test that shutdown function works
					shutdownCtx := context.Background()
					err := shutdown(shutdownCtx)
					assert.NoError(t, err)
				} else {
					assert.Nil(t, shutdown)
				}
			}
		})
	}
}

func TestCreateTraceExporter_AppliesExportTimeout(t *testing.T) {
	t.Parallel()

	// A boundary pair against ONE ingest: the only difference between the two
	// runs is ExportTimeout, so an outcome that flips can only be attributed to
	// it. The permissive run also proves the endpoint is sound, so the strict
	// run's failure is not a dial or handshake error wearing the right costume.
	const answersIn = 400 * time.Millisecond

	t.Run("a timeout under the ingest's response time abandons the export", func(t *testing.T) {
		t.Parallel()

		srv := delayedOTLPIngest(t, answersIn)
		exporter, err := createTraceExporter(t.Context(), Config{
			Endpoint:      srv.Listener.Addr().String(),
			Insecure:      true,
			ExportTimeout: 100 * time.Millisecond,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

		// Bounds the exporter's retry backoff, which is otherwise minutes.
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()

		err = exporter.ExportSpans(ctx, endedSpans(t))

		require.Error(t, err, "an ingest answering in %s must not satisfy a 100ms timeout — "+
			"it would under the SDK's own 10s default", answersIn)
		var netErr net.Error
		require.ErrorAs(t, err, &netErr, "export failed for some reason other than a deadline: %v", err)
		assert.True(t, netErr.Timeout(), "export failed on %v, not on its deadline", netErr)
	})

	t.Run("a timeout above the ingest's response time lets the export through", func(t *testing.T) {
		t.Parallel()

		srv := delayedOTLPIngest(t, answersIn)
		exporter, err := createTraceExporter(t.Context(), Config{
			Endpoint:      srv.Listener.Addr().String(),
			Insecure:      true,
			ExportTimeout: 3 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

		assert.NoError(t, exporter.ExportSpans(t.Context(), endedSpans(t)))
	})
}

func TestCreateTraceExporter_GRPCAppliesExportTimeout(t *testing.T) {
	t.Parallel()

	// Under gRPC the timeout bounds the whole export rather than one request,
	// so it shows up as how long ExportSpans takes against a peer that accepts
	// the connection and then says nothing.
	const exportTimeout = 300 * time.Millisecond

	exporter, err := createTraceExporter(t.Context(), Config{
		Endpoint:      silentTCPPeer(t),
		Insecure:      true,
		Protocol:      ProtocolGRPC,
		ExportTimeout: exportTimeout,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = exporter.Shutdown(context.Background()) })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	start := time.Now()
	err = exporter.ExportSpans(ctx, endedSpans(t))
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Less(t, elapsed, 2*time.Second,
		"export ran %s against a silent peer — the configured %s is not in force", elapsed, exportTimeout)
	assert.GreaterOrEqual(t, elapsed, exportTimeout-20*time.Millisecond,
		"export gave up after %s, before the configured %s", elapsed, exportTimeout)
}

func TestNewTracerProviderWithShutdown_BatcherBudgetFollowsExportTimeout(t *testing.T) {
	t.Parallel()

	// Without this the processor keeps its own 30s default, which both caps a
	// larger ExportTimeout and leaves the HTTP exporter's retry loop room to
	// re-send a batch the destination already has.
	srv := delayedOTLPIngest(t, 30*time.Second)

	provider, shutdown, err := NewTracerProviderWithShutdown(t.Context(), Config{
		Endpoint:      srv.Listener.Addr().String(),
		Insecure:      true,
		SamplingRate:  1.0,
		ExportTimeout: 150 * time.Millisecond,
	}, resource.Empty())
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	sdkProvider, ok := provider.(*sdktrace.TracerProvider)
	require.True(t, ok, "expected a real tracer provider, got %T", provider)

	_, span := sdkProvider.Tracer("test").Start(t.Context(), "batch-budget")
	span.End()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_ = sdkProvider.ForceFlush(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second,
		"flush against an unresponsive ingest took %s — the processor is still on its own 30s budget "+
			"rather than the configured 150ms", elapsed)
}

// silentTCPPeer accepts connections and then says nothing, so a gRPC client
// stalls in its handshake until its own deadline rather than failing to dial.

// endedSpans returns one ended span in the read-only form an exporter takes.
func endedSpans(t *testing.T) []sdktrace.ReadOnlySpan {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	_, span := provider.Tracer("test").Start(t.Context(), "export-timeout")
	span.End()
	spans := recorder.Ended()
	require.Len(t, spans, 1)
	return spans
}

func TestNewTracerProviderWithShutdown_Sampler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		sampler      sdktrace.Sampler
		samplingRate float64
		// remoteUnsampled starts the span under a remote parent whose
		// traceparent says "not sampled", as an edge proxy forwards it.
		remoteUnsampled bool
		wantExported    bool
	}{
		{
			name:         "nil sampler keeps the ratio default for a root span",
			samplingRate: 1.0,
			wantExported: true,
		},
		{
			name:            "nil sampler keeps following an unsampled remote parent",
			samplingRate:    1.0,
			remoteUnsampled: true,
			wantExported:    false,
		},
		{
			name:         "a never-sample sampler wins over the sampling rate",
			sampler:      sdktrace.NeverSample(),
			samplingRate: 1.0,
			wantExported: false,
		},
		{
			name: "a remote-not-sampled override samples under an unsampled remote parent",
			sampler: sdktrace.ParentBased(sdktrace.TraceIDRatioBased(1.0),
				sdktrace.WithRemoteParentNotSampled(sdktrace.TraceIDRatioBased(1.0))),
			remoteUnsampled: true,
			wantExported:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv, paths := recordingOTLPIngest(t, httptest.NewServer)
			provider, shutdown, err := NewTracerProviderWithShutdown(t.Context(), Config{
				Endpoint:     srv.Listener.Addr().String(),
				Insecure:     true,
				SamplingRate: tt.samplingRate,
				Sampler:      tt.sampler,
			}, resource.Empty())
			require.NoError(t, err)
			t.Cleanup(func() { _ = shutdown(context.Background()) })

			ctx := t.Context()
			if tt.remoteUnsampled {
				ctx = trace.ContextWithRemoteSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
					TraceID: trace.TraceID{0x01},
					SpanID:  trace.SpanID{0x01},
					Remote:  true,
				}))
			}
			_, span := provider.Tracer("test").Start(ctx, "sampler")
			assert.Equal(t, tt.wantExported, span.SpanContext().IsSampled())
			span.End()

			sdkProvider, ok := provider.(*sdktrace.TracerProvider)
			require.True(t, ok, "expected a real tracer provider, got %T", provider)
			require.NoError(t, sdkProvider.ForceFlush(t.Context()))

			// The batcher only exports a non-empty batch, so any request at all
			// means the span reached the exporter.
			if tt.wantExported {
				assert.Equal(t, []string{otlpTracesPath}, paths())
			} else {
				assert.Empty(t, paths())
			}
		})
	}
}

func TestNewTracerProviderWithShutdown_TracesEndpoint(t *testing.T) {
	t.Parallel()

	const exactPath = "/v2/telemetry/sink-abc"

	t.Run("posts to the exact URL with no signal suffix", func(t *testing.T) {
		t.Parallel()

		traceSrv, tracePaths := recordingOTLPIngest(t, httptest.NewServer)
		collector, collectorPaths := recordingOTLPIngest(t, httptest.NewServer)

		exportOneSpan(t, Config{
			Endpoint:       collector.Listener.Addr().String() + "/base",
			TracesEndpoint: traceSrv.URL + exactPath,
			Insecure:       true,
			SamplingRate:   1.0,
		})

		assert.Equal(t, []string{exactPath}, tracePaths())
		assert.Empty(t, collectorPaths(), "traces also went to Endpoint")
	})

	t.Run("works with Endpoint unset and Insecure off when the scheme is http", func(t *testing.T) {
		t.Parallel()

		traceSrv, tracePaths := recordingOTLPIngest(t, httptest.NewServer)

		exportOneSpan(t, Config{
			TracesEndpoint: traceSrv.URL + exactPath,
			SamplingRate:   1.0,
		})

		assert.Equal(t, []string{exactPath}, tracePaths())
	})

	t.Run("an https scheme keeps TLS even with Insecure set", func(t *testing.T) {
		t.Parallel()

		// Insecure describes Endpoint. Were it applied to TracesEndpoint, the
		// exporter would speak plain HTTP to this TLS server and fail.
		traceSrv, tracePaths := recordingOTLPIngest(t, httptest.NewTLSServer)
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(caPath,
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: traceSrv.Certificate().Raw}), 0o600))

		exportOneSpan(t, Config{
			TracesEndpoint: traceSrv.URL + exactPath,
			Insecure:       true,
			CACertPath:     caPath,
			SamplingRate:   1.0,
		})

		assert.Equal(t, []string{exactPath}, tracePaths())
	})
}

func TestCreateTraceExporter_TracesEndpointErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name:    "grpc protocol",
			config:  Config{TracesEndpoint: "https://ingest.example.com/v2/sink", Protocol: ProtocolGRPC},
			wantErr: "requires the http/protobuf protocol",
		},
		{
			name:    "missing scheme",
			config:  Config{TracesEndpoint: "ingest.example.com/v2/sink"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "unsupported scheme",
			config:  Config{TracesEndpoint: "grpc://ingest.example.com:4317"},
			wantErr: "scheme must be http or https",
		},
		{
			name:    "missing host",
			config:  Config{TracesEndpoint: "https:///v2/sink"},
			wantErr: "missing host",
		},
		{
			name:    "query string would be dropped by the SDK",
			config:  Config{TracesEndpoint: "https://ingest.example.com/v2/sink?key=abc"},
			wantErr: "query and fragment are not supported",
		},
		{
			name:    "unparseable URL",
			config:  Config{TracesEndpoint: "https://ingest.example.com/%zz"},
			wantErr: "invalid traces endpoint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			exporter, err := createTraceExporter(t.Context(), tt.config)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, exporter)

			// The provider surfaces the same error rather than going no-op.
			provider, shutdown, err := NewTracerProviderWithShutdown(t.Context(), tt.config, resource.Empty())
			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, provider)
			assert.Nil(t, shutdown)
		})
	}
}

// exportOneSpan builds a tracer provider from config, records one span and
// flushes it, failing the test if the export does not succeed.
func exportOneSpan(t *testing.T, config Config) {
	t.Helper()

	provider, shutdown, err := NewTracerProviderWithShutdown(t.Context(), config, resource.Empty())
	require.NoError(t, err)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	sdkProvider, ok := provider.(*sdktrace.TracerProvider)
	require.True(t, ok, "expected a real tracer provider, got %T", provider)

	_, span := sdkProvider.Tracer("test").Start(t.Context(), "traces-endpoint")
	span.End()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	require.NoError(t, sdkProvider.ForceFlush(ctx))
}
