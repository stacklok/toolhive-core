// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package providers composes OpenTelemetry tracer and meter providers from a
declarative Config, with OTLP HTTP and Prometheus exporters.

[NewCompositeProvider] builds the tracer/meter pair for a service in one
call: OTLP tracing and/or metrics when an endpoint is configured, a
Prometheus scrape endpoint when enabled, or no-ops when neither is. The
strategy selector in providers_strategy.go decides which exporters to wire
based on the Config, so callers get a single composite to hand to their
instrumentation and a single Shutdown to call on exit.

This package is Alpha stability. The API may change significantly before
reaching stable status in v1.0.0.
*/
package providers
