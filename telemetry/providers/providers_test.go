// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/stacklok/toolhive-core/telemetry/providers/otlp"
)

func TestConfig_EffectiveTracesProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protocol       string
		tracesProtocol string
		want           string
	}{
		{
			name:           "unset Protocol and unset TracesProtocol default to empty (backward compat)",
			protocol:       "",
			tracesProtocol: "",
			want:           "",
		},
		{
			name:           "TracesProtocol unset falls back to Protocol",
			protocol:       otlp.ProtocolGRPC,
			tracesProtocol: "",
			want:           otlp.ProtocolGRPC,
		},
		{
			name:           "TracesProtocol overrides Protocol independently",
			protocol:       otlp.ProtocolGRPC,
			tracesProtocol: otlp.ProtocolHTTPProtobuf,
			want:           otlp.ProtocolHTTPProtobuf,
		},
		{
			name:           "TracesProtocol set with Protocol unset still applies",
			protocol:       "",
			tracesProtocol: otlp.ProtocolGRPC,
			want:           otlp.ProtocolGRPC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := Config{Protocol: tt.protocol, TracesProtocol: tt.tracesProtocol}
			assert.Equal(t, tt.want, config.effectiveTracesProtocol())
		})
	}
}

func TestWithProtocol(t *testing.T) {
	t.Parallel()

	config := &Config{}
	require.NoError(t, WithProtocol(otlp.ProtocolGRPC)(config))
	assert.Equal(t, otlp.ProtocolGRPC, config.Protocol)
}

func TestWithTracesProtocol(t *testing.T) {
	t.Parallel()

	config := &Config{}
	require.NoError(t, WithTracesProtocol(otlp.ProtocolHTTPProtobuf)(config))
	assert.Equal(t, otlp.ProtocolHTTPProtobuf, config.TracesProtocol)
	// Setting TracesProtocol must not touch the general Protocol field.
	assert.Empty(t, config.Protocol)
}

func TestOTLPTracerStrategy_CreateTracerProvider_TracesProtocolOverride(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("test-service"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	require.NoError(t, err)

	// Protocol is set to gRPC generally, but the traces-specific override
	// selects http/protobuf instead; the tracer provider must still build
	// successfully, proving the override is honored independently.
	strategy := &OTLPTracerStrategy{}
	config := Config{
		OTLPEndpoint:   testEndpointLocal,
		Insecure:       true,
		TracingEnabled: true,
		Protocol:       otlp.ProtocolGRPC,
		TracesProtocol: otlp.ProtocolHTTPProtobuf,
	}

	provider, shutdown, err := strategy.CreateTracerProvider(ctx, config, res)
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(ctx))
}

func TestCompositeProvider_LoggerProvider(t *testing.T) {
	t.Parallel()

	t.Run("logging disabled returns no-op logger provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		provider, err := NewCompositeProvider(ctx,
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
		)
		require.NoError(t, err)

		assert.Contains(t, fmt.Sprintf("%T", provider.LoggerProvider()), "noop")
		assert.NoError(t, provider.Shutdown(ctx))
	})

	t.Run("logging enabled with endpoint returns real logger provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		provider, err := NewCompositeProvider(ctx,
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
			WithOTLPEndpoint(testEndpointLocal),
			WithInsecure(true),
			WithLoggingEnabled(true),
		)
		require.NoError(t, err)

		assert.NotContains(t, fmt.Sprintf("%T", provider.LoggerProvider()), "noop")
		assert.NoError(t, provider.Shutdown(ctx))
	})
}

func TestWithExportTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "explicit value is stored as given", timeout: 90 * time.Second, want: 90 * time.Second},
		// The option is a plain setter: normalizing a non-positive value to the
		// default is otlp.Config's job, so the provider layer must not quietly
		// substitute one here and hide what the caller actually asked for.
		{name: "zero is passed through untouched", timeout: 0, want: 0},
		{name: "negative is passed through untouched", timeout: -time.Second, want: -time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{}
			require.NoError(t, WithExportTimeout(tt.timeout)(config))
			assert.Equal(t, tt.want, config.ExportTimeout)
		})
	}
}

func TestOTLPTracerStrategy_CreateTracerProvider_AppliesExportTimeout(t *testing.T) {
	t.Parallel()

	// The gap this covers is wiring, not the timeout itself: ExportTimeout
	// reaching otlp.Config is what a struct-field assertion would miss, so this
	// drives the built provider against an ingest that never answers in time
	// and asserts the flush gives up on the configured budget.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(30 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.CloseClientConnections)

	res, err := resource.New(t.Context(), resource.WithAttributes(semconv.ServiceName("test-service")))
	require.NoError(t, err)

	strategy := &OTLPTracerStrategy{}
	provider, shutdown, err := strategy.CreateTracerProvider(t.Context(), Config{
		OTLPEndpoint:   srv.Listener.Addr().String(),
		Insecure:       true,
		TracingEnabled: true,
		SamplingRate:   1.0,
		ExportTimeout:  150 * time.Millisecond,
	}, res)
	require.NoError(t, err)
	require.NotNil(t, shutdown)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	sdkProvider, ok := provider.(*sdktrace.TracerProvider)
	require.True(t, ok, "expected a real tracer provider, got %T", provider)

	_, span := sdkProvider.Tracer("test").Start(t.Context(), "export-timeout")
	span.End()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_ = sdkProvider.ForceFlush(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second,
		"flush against an unresponsive ingest took %s — ExportTimeout is not reaching otlp.Config, "+
			"leaving the export on the 30s default", elapsed)
}

// The traces path is covered by TestOTLPTracerStrategy_CreateTracerProvider_AppliesExportTimeout;
// these cover the other two strategies, which build their own otlp.Config and
// so can drop the field independently.
func TestStrategies_CreateProvider_AppliesExportTimeoutForEverySignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// flush builds the signal's provider from config and forces an export,
		// returning how long that took.
		flush func(t *testing.T, config Config) time.Duration
	}{
		{
			name: "logs",
			flush: func(t *testing.T, config Config) time.Duration {
				t.Helper()

				provider, shutdown, err := (&OTLPLoggerStrategy{}).CreateLoggerProvider(t.Context(), config, resource.Empty())
				require.NoError(t, err)
				t.Cleanup(func() { _ = shutdown(context.Background()) })

				sdkProvider, ok := provider.(*sdklog.LoggerProvider)
				require.True(t, ok, "expected a real logger provider, got %T", provider)

				var record log.Record
				record.SetBody(attribute.StringValue("export-timeout"))
				sdkProvider.Logger("test").Emit(t.Context(), record)

				return timeFlush(t, sdkProvider.ForceFlush)
			},
		},
		{
			name: "metrics",
			flush: func(t *testing.T, config Config) time.Duration {
				t.Helper()

				result, err := (&UnifiedMeterStrategy{EnableOTLP: true}).CreateMeterProvider(t.Context(), config, resource.Empty())
				require.NoError(t, err)
				require.NotNil(t, result)

				sdkProvider, ok := result.MeterProvider.(*sdkmetric.MeterProvider)
				require.True(t, ok, "expected a real meter provider, got %T", result.MeterProvider)
				t.Cleanup(func() { _ = sdkProvider.Shutdown(context.Background()) })

				counter, err := sdkProvider.Meter("test").Int64Counter("export.timeout")
				require.NoError(t, err)
				counter.Add(t.Context(), 1)

				return timeFlush(t, sdkProvider.ForceFlush)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(30 * time.Second)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.CloseClientConnections)

			elapsed := tt.flush(t, Config{
				OTLPEndpoint:   srv.Listener.Addr().String(),
				Insecure:       true,
				MetricsEnabled: true,
				LoggingEnabled: true,
				ExportTimeout:  150 * time.Millisecond,
			})

			assert.Less(t, elapsed, 3*time.Second,
				"flush against an unresponsive ingest took %s — ExportTimeout is not reaching otlp.Config "+
					"for this signal, leaving the export on the 30s default", elapsed)
		})
	}
}

// timeFlush runs a provider's ForceFlush under a ceiling that keeps a failing
// case from running to the package timeout, and reports how long it took.
func timeFlush(t *testing.T, forceFlush func(context.Context) error) time.Duration {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_ = forceFlush(ctx)
	return time.Since(start)
}

func TestWithTracesEndpoint(t *testing.T) {
	t.Parallel()

	config := &Config{}
	require.NoError(t, WithTracesEndpoint("https://ingest.example.com/v2/telemetry/sink")(config))
	assert.Equal(t, "https://ingest.example.com/v2/telemetry/sink", config.TracesEndpoint)
	// The traces override must not touch the endpoint metrics and logs use.
	assert.Empty(t, config.OTLPEndpoint)
}

func TestWithSampler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		sampler sdktrace.Sampler
	}{
		{name: "custom sampler is stored as given", sampler: sdktrace.NeverSample()},
		// Nil is the "use the default" value, resolved by otlp.Config.
		{name: "nil is passed through untouched", sampler: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := &Config{}
			require.NoError(t, WithSampler(tt.sampler)(config))
			assert.Equal(t, tt.sampler, config.Sampler)
		})
	}
}

func TestNewCompositeProvider_SamplerReachesTracerProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		sampler     sdktrace.Sampler
		wantSampled bool
	}{
		{name: "nil sampler keeps the sampling rate", sampler: nil, wantSampled: true},
		{name: "custom sampler overrides the sampling rate", sampler: sdktrace.NeverSample(), wantSampled: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewCompositeProvider(t.Context(),
				WithServiceName("test-service"),
				WithServiceVersion("1.0.0"),
				WithOTLPEndpoint(testEndpointLocal),
				WithInsecure(true),
				WithTracingEnabled(true),
				WithSamplingRate(1.0),
				WithSampler(tt.sampler),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

			_, span := provider.TracerProvider().Tracer("test").Start(t.Context(), "sampler")
			defer span.End()
			assert.Equal(t, tt.wantSampled, span.SpanContext().IsSampled())
		})
	}
}

func TestNewCompositeProvider_TracesEndpoint(t *testing.T) {
	t.Parallel()

	const exactPath = "/v2/telemetry/sink-abc"

	t.Run("traces go to the exact URL while metrics keep the OTLP endpoint", func(t *testing.T) {
		t.Parallel()

		traceSrv, tracePaths := recordingIngest(t)
		collector, collectorPaths := recordingIngest(t)

		provider, err := NewCompositeProvider(t.Context(),
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
			WithOTLPEndpoint(collector.Listener.Addr().String()),
			WithTracesEndpoint(traceSrv.URL+exactPath),
			WithInsecure(true),
			WithTracingEnabled(true),
			WithMetricsEnabled(true),
			WithSamplingRate(1.0),
		)
		require.NoError(t, err)

		emitSpanAndMetric(t, provider)
		// Shutdown flushes both the batcher and the periodic reader.
		require.NoError(t, provider.Shutdown(t.Context()))

		assert.Equal(t, []string{exactPath}, tracePaths())
		assert.Equal(t, []string{"/v1/metrics"}, collectorPaths())
	})

	t.Run("traces export with no OTLP endpoint and metrics and logs stay off", func(t *testing.T) {
		t.Parallel()

		traceSrv, tracePaths := recordingIngest(t)

		provider, err := NewCompositeProvider(t.Context(),
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
			WithTracesEndpoint(traceSrv.URL+exactPath),
			WithTracingEnabled(true),
			WithMetricsEnabled(true),
			WithLoggingEnabled(true),
			WithSamplingRate(1.0),
		)
		require.NoError(t, err)

		assert.NotContains(t, fmt.Sprintf("%T", provider.TracerProvider()), "noop")
		assert.Contains(t, fmt.Sprintf("%T", provider.MeterProvider()), "noop")
		assert.Contains(t, fmt.Sprintf("%T", provider.LoggerProvider()), "noop")

		emitSpanAndMetric(t, provider)
		require.NoError(t, provider.Shutdown(t.Context()))

		assert.Equal(t, []string{exactPath}, tracePaths())
	})
}

func TestNewCompositeProvider_TracesEndpointRejectsGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opt  ProviderOption
	}{
		{name: "grpc for all signals", opt: WithProtocol(otlp.ProtocolGRPC)},
		{name: "grpc for traces only", opt: WithTracesProtocol(otlp.ProtocolGRPC)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := NewCompositeProvider(t.Context(),
				WithServiceName("test-service"),
				WithServiceVersion("1.0.0"),
				WithTracesEndpoint("https://ingest.example.com/v2/telemetry/sink"),
				WithTracingEnabled(true),
				tt.opt,
			)
			require.ErrorContains(t, err, "requires the http/protobuf protocol")
			assert.Nil(t, provider)
		})
	}
}

// recordingIngest accepts every OTLP/HTTP request at once and records its
// RequestURI, the request target exactly as sent. The returned func snapshots
// the targets seen so far.
func recordingIngest(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()

	var (
		mu    sync.Mutex
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

// emitSpanAndMetric records one span and one counter increment on provider.
func emitSpanAndMetric(t *testing.T, provider *CompositeProvider) {
	t.Helper()

	_, span := provider.TracerProvider().Tracer("test").Start(t.Context(), "traces-endpoint")
	span.End()

	counter, err := provider.MeterProvider().Meter("test").Int64Counter("traces.endpoint")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)
}

func TestRedactEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, raw, want string
	}{
		{name: "path is dropped", raw: "https://ingest.example.com/v2/telemetry/sink", want: "https://ingest.example.com"},
		{name: "port is kept", raw: "http://127.0.0.1:4318/v2/sink", want: "http://127.0.0.1:4318"},
		{name: "userinfo and query are dropped", raw: "https://user:SECRET@ingest.example.com/x?key=SECRET", want: "https://ingest.example.com"},
		{name: "no host is a placeholder", raw: "ingest.example.com/SECRET", want: "<unparseable endpoint>"},
		{name: "unparseable is a placeholder", raw: "https://ingest.example.com/%zzSECRET", want: "<unparseable endpoint>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, redactEndpoint(tt.raw))
		})
	}
}

// Drives the traces endpoint through NewCompositeProvider with a sentinel
// credential in each part of the URL that can carry one, and asserts it
// reaches neither the returned error nor the debug logs.
//
//nolint:paralleltest // Swaps the process-wide default slog logger
func TestNewCompositeProvider_TracesEndpointNeverLeaksURL(t *testing.T) {
	traceSrv, _ := recordingIngest(t)

	tests := []struct {
		name     string
		endpoint string
		protocol string
		wantErr  bool
	}{
		{name: "accepted URL with a credential in the path", endpoint: traceSrv.URL + "/SECRET-sink"},
		{name: "userinfo", endpoint: "https://user:SECRET@ingest.example.com/v2/sink", wantErr: true},
		{name: "query", endpoint: "https://ingest.example.com/v2/sink?key=SECRET", wantErr: true},
		{name: "path the exporter would rewrite", endpoint: "https://ingest.example.com/SECRET%2Fblue", wantErr: true},
		{name: "unparseable", endpoint: "https://ingest.example.com/%zzSECRET", wantErr: true},
		{name: "grpc", endpoint: "https://ingest.example.com/SECRET", protocol: otlp.ProtocolGRPC, wantErr: true},
	}

	logs := captureDebugLogs(t)

	for _, tt := range tests { //nolint:paralleltest // Shares the swapped logger above
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewCompositeProvider(t.Context(),
				WithServiceName("test-service"),
				WithServiceVersion("1.0.0"),
				WithTracesEndpoint(tt.endpoint),
				WithTracesProtocol(tt.protocol),
				WithTracingEnabled(true),
			)
			if tt.wantErr {
				require.Error(t, err)
				assert.NotContains(t, err.Error(), "SECRET")
			} else {
				require.NoError(t, err)
				require.NoError(t, provider.Shutdown(t.Context()))
			}
		})
	}

	got := logs()
	// Proves the logger was capturing, so the absence below means something.
	assert.Contains(t, got, "creating OTLP tracer provider")
	assert.NotContains(t, got, "SECRET")
}

// captureDebugLogs routes the default slog logger, at debug level, to a buffer
// for the rest of the test and returns a snapshot func.
func captureDebugLogs(t *testing.T) func() string {
	t.Helper()

	var (
		mu  sync.Mutex
		buf bytes.Buffer
	)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}), &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
