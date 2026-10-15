// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive-core/env/mocks"
)

// Not parallel, here or below: t.Setenv forbids it, and these cases are about
// process-wide environment.
func TestConfig_ExportTimeoutFor_Precedence(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		env     map[string]string
		want    time.Duration
		signals []signalTimeoutEnv
	}{
		{
			name: "nothing set falls back to this package's default, not the SDK's 10s",
			want: DefaultExportTimeout,
		},
		{
			name:   "an explicit config value wins over every variable",
			config: Config{ExportTimeout: 90 * time.Second},
			env: map[string]string{
				tracesTimeoutEnv.exporter:  "1000",
				envGeneralTimeout:          "2000",
				tracesTimeoutEnv.processor: "3000",
			},
			want:    90 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "the signal's own variable is read as milliseconds",
			env:     map[string]string{tracesTimeoutEnv.exporter: "45000"},
			want:    45 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "the signal's variable wins over the general one",
			env:     map[string]string{tracesTimeoutEnv.exporter: "45000", envGeneralTimeout: "5000"},
			want:    45 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name: "the general variable applies to every signal that lacks its own",
			env:  map[string]string{envGeneralTimeout: "20000"},
			want: 20 * time.Second,
		},
		{
			// Set alone it would otherwise leave the exporter on the SDK's 10s
			// default, which is the split this package exists to avoid.
			name:    "a processor variable alone sets the whole budget",
			env:     map[string]string{tracesTimeoutEnv.processor: "60000"},
			want:    60 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "the exporter variable outranks the processor one",
			env:     map[string]string{tracesTimeoutEnv.exporter: "45000", tracesTimeoutEnv.processor: "60000"},
			want:    45 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "an unparseable value is skipped rather than honored as zero",
			env:     map[string]string{tracesTimeoutEnv.exporter: "soon", envGeneralTimeout: "20000"},
			want:    20 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "a non-positive value is skipped, since it would disable export entirely",
			env:     map[string]string{tracesTimeoutEnv.exporter: "0", envGeneralTimeout: "20000"},
			want:    20 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
		{
			name:    "surrounding whitespace is tolerated",
			env:     map[string]string{tracesTimeoutEnv.exporter: "  45000 "},
			want:    45 * time.Second,
			signals: []signalTimeoutEnv{tracesTimeoutEnv},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, value := range tt.env {
				t.Setenv(name, value)
			}

			// Cases naming no signal assert behavior common to all three, so
			// run them against each rather than privileging traces.
			signals := tt.signals
			if len(signals) == 0 {
				signals = []signalTimeoutEnv{tracesTimeoutEnv, metricsTimeoutEnv, logsTimeoutEnv}
			}
			for _, signal := range signals {
				assert.Equal(t, tt.want, tt.config.exportTimeoutFor(signal),
					"signal with exporter variable %s", signal.exporter)
			}
		})
	}
}

// Each signal must read its own variables and ignore its siblings', or a caller
// tuning one destination would silently retime the others.
func TestConfig_ExportTimeoutFor_SignalsAreIndependent(t *testing.T) {
	t.Setenv(tracesTimeoutEnv.exporter, "11000")
	t.Setenv(metricsTimeoutEnv.exporter, "22000")
	t.Setenv(logsTimeoutEnv.exporter, "33000")

	var config Config
	assert.Equal(t, 11*time.Second, config.exportTimeoutFor(tracesTimeoutEnv))
	assert.Equal(t, 22*time.Second, config.exportTimeoutFor(metricsTimeoutEnv))
	assert.Equal(t, 33*time.Second, config.exportTimeoutFor(logsTimeoutEnv))
}

func TestConfig_ExportTimeoutFor_ProcessorVariablesAreSignalScoped(t *testing.T) {
	t.Setenv(metricsTimeoutEnv.processor, "25000")

	var config Config
	assert.Equal(t, 25*time.Second, config.exportTimeoutFor(metricsTimeoutEnv))
	assert.Equal(t, DefaultExportTimeout, config.exportTimeoutFor(tracesTimeoutEnv),
		"the metrics processor variable must not reach the traces budget")
}

// The rest of this file drives the variables through tracesTimeoutEnv and its
// siblings, so the spelling that actually reaches the env.Reader is asserted
// here, once. A rename would otherwise retarget every case above in step and
// go unnoticed.
func TestSignalTimeoutEnv_Names(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "OTEL_EXPORTER_OTLP_TIMEOUT", envGeneralTimeout)

	assert.Equal(t, "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", tracesTimeoutEnv.exporter)
	assert.Equal(t, "OTEL_BSP_EXPORT_TIMEOUT", tracesTimeoutEnv.processor)

	assert.Equal(t, "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT", metricsTimeoutEnv.exporter)
	assert.Equal(t, "OTEL_METRIC_EXPORT_TIMEOUT", metricsTimeoutEnv.processor)

	assert.Equal(t, "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", logsTimeoutEnv.exporter)
	assert.Equal(t, "OTEL_BLRP_EXPORT_TIMEOUT", logsTimeoutEnv.processor)
}

// The cases above go through the process environment, which a nil EnvReader
// falls back to; this pins that an injected reader is consulted instead.
func TestConfig_ExportTimeoutFor_ReadsInjectedEnvReader(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	reader := mocks.NewMockReader(ctrl)
	reader.EXPECT().LookupEnv(tracesTimeoutEnv.exporter).Return("45000", true)

	config := Config{EnvReader: reader}
	assert.Equal(t, 45*time.Second, config.exportTimeoutFor(tracesTimeoutEnv))
}

//nolint:paralleltest // Swaps the process-wide OTel error handler
func TestConfig_ExportTimeoutFor_ReportsUnusableValues(t *testing.T) {
	tests := []struct {
		name       string
		exporter   string
		set        bool
		want       time.Duration
		wantReport bool
	}{
		{name: "an unparseable value is reported and skipped", exporter: "soon", set: true, want: 20 * time.Second, wantReport: true},
		{name: "a non-positive value is reported and skipped", exporter: "0", set: true, want: 20 * time.Second, wantReport: true},
		{name: "a valid value is not reported", exporter: "45000", set: true, want: 45 * time.Second},
		{name: "an absent value is not reported", want: 20 * time.Second},
	}

	reports := captureOTelErrors(t)

	for _, tt := range tests { //nolint:paralleltest // Shares the swapped handler above
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			reader := mocks.NewMockReader(ctrl)
			reader.EXPECT().LookupEnv(tracesTimeoutEnv.exporter).Return(tt.exporter, tt.set)
			reader.EXPECT().LookupEnv(envGeneralTimeout).Return("20000", true).MaxTimes(1)

			before := len(reports())
			config := Config{EnvReader: reader}
			assert.Equal(t, tt.want, config.exportTimeoutFor(tracesTimeoutEnv))

			got := reports()[before:]
			if !tt.wantReport {
				assert.Empty(t, got)
				return
			}
			if assert.Len(t, got, 1) {
				assert.Contains(t, got[0], tracesTimeoutEnv.exporter)
				assert.Contains(t, got[0], tt.exporter)
			}
		})
	}
}

// captureOTelErrors routes the global OTel error handler to a recorder for the
// rest of the test and returns a snapshot func. Only reports about timeout
// variables are kept, so errors from exporters in other tests can't leak in.
func captureOTelErrors(t *testing.T) func() []string {
	t.Helper()

	var (
		mu   sync.Mutex
		msgs []string
	)
	previous := otel.GetErrorHandler()
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		if !strings.Contains(err.Error(), "ignoring OTEL_") {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, err.Error())
	}))
	t.Cleanup(func() { otel.SetErrorHandler(previous) })

	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), msgs...)
	}
}
