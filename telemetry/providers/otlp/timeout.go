// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package otlp provides OpenTelemetry Protocol (OTLP) provider implementations
package otlp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/stacklok/toolhive-core/env"
)

// envGeneralTimeout is the OTel variable that sets the export budget for every
// signal that has no variable of its own set.
const envGeneralTimeout = "OTEL_EXPORTER_OTLP_TIMEOUT"

// signalTimeoutEnv names the two OTel variables that bear on one signal's
// export budget: the exporter's own, and the one belonging to the processor or
// reader that drives it.
//
// Both feed a single resolved budget rather than their own components. That
// looks lossy and is deliberate: this package's reason for setting a timeout at
// all is that the exporter and the processor must not disagree. Honoring each
// variable on its own component would reinstate exactly the split that
// motivated the field — a processor variable set alone would leave the exporter
// on the SDK's 10s default with room to re-send a batch the destination already
// has, and an exporter variable set alone would be truncated by the processor's
// 30s budget.
type signalTimeoutEnv struct {
	exporter  string
	processor string
}

var (
	tracesTimeoutEnv = signalTimeoutEnv{
		exporter:  "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
		processor: "OTEL_BSP_EXPORT_TIMEOUT",
	}
	metricsTimeoutEnv = signalTimeoutEnv{
		exporter:  "OTEL_EXPORTER_OTLP_METRICS_TIMEOUT",
		processor: "OTEL_METRIC_EXPORT_TIMEOUT",
	}
	logsTimeoutEnv = signalTimeoutEnv{
		exporter:  "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT",
		processor: "OTEL_BLRP_EXPORT_TIMEOUT",
	}
)

// exportTimeoutFor resolves one signal's export budget, in descending
// precedence: an explicit Config.ExportTimeout, the signal's own exporter
// variable, the general variable, the signal's processor variable, and finally
// DefaultExportTimeout.
//
// The env tiers exist because this package passes the resolved budget to the
// SDK as an explicit option, and an explicit option beats the SDK's own reading
// of these variables — it applies env config first and options after. Resolving
// them here is what keeps them working for a caller that sets no timeout in
// code; without it, setting this package's default would silently disable a
// lever callers already use.
func (c Config) exportTimeoutFor(vars signalTimeoutEnv) time.Duration {
	if c.ExportTimeout > 0 {
		return c.ExportTimeout
	}
	reader := c.envReader()
	for _, name := range []string{vars.exporter, envGeneralTimeout, vars.processor} {
		if timeout, ok := envTimeoutMillis(reader, name); ok {
			return timeout
		}
	}
	return DefaultExportTimeout
}

// envTimeoutMillis reads an OTel timeout variable, whose value the spec defines
// as whole milliseconds. A value that is absent, empty, unparseable or
// non-positive reports false so the caller falls through to the next tier,
// matching how the SDK itself treats one it cannot use.
//
// A value that is set but unusable is also reported through otel.Handle, as
// the SDK does, so a typo in a variable is visible rather than silently
// replaced by the next tier. An empty value counts as unset, not as a typo.
func envTimeoutMillis(reader env.Reader, name string) (time.Duration, bool) {
	raw, ok := reader.LookupEnv(name)
	if !ok || strings.TrimSpace(raw) == "" {
		return 0, false
	}

	millis, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || millis <= 0 {
		otel.Handle(fmt.Errorf("ignoring %s=%q: want a positive whole number of milliseconds", name, raw))
		return 0, false
	}
	return time.Duration(millis) * time.Millisecond, true
}
