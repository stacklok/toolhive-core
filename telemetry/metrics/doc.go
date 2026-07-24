// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package metrics provides shared histogram bucket presets, label-key
constants, and emitter-ownership vocabulary for OpenTelemetry metrics across
the ToolHive ecosystem.

The section and decision numbers cited throughout this package (e.g. "RFC
§3.3", "D8") refer to the internal Stacklok Platform Metrics Standardization
RFC, which defines the canonical vocabulary this package pins.

This package is construction helpers and vocabulary only: importing it
installs no global providers and emits no metrics of its own. The one
exception is RegisterBuildInfo, which registers an observable gauge on the
meter the caller passes in — see "Build Info" below; it still constructs no
meter or provider itself. Consumers (the ToolHive proxy, vMCP, and the
registry) use the rest of this package to build their own instruments
consistently.

# Bucket Presets

Three histogram bucket presets cover fast HTTP calls, MCP/proxy operations,
and long-running operations such as sync, reconcile, or composite-tool
execution. This package does not construct meters or instruments; callers
import go.opentelemetry.io/otel and go.opentelemetry.io/otel/metric
themselves and pass a preset's boundaries when constructing a histogram:

	meter := otel.Meter("stacklok.toolhive.proxy")
	histogram, err := meter.Float64Histogram(
	    "stacklok.toolhive.proxy.request.duration",
	    metric.WithExplicitBucketBoundaries(metrics.BucketsFastHTTP()...),
	)

# Label Keys

Canonical label-key constants ensure every consumer spells the same concept
the same way. As with the bucket presets, callers attach these to their own
OTel instruments via go.opentelemetry.io/otel/attribute:

	counter.Add(ctx, 1, metric.WithAttributes(
	    attribute.String(metrics.LabelOutcome, "success"),
	))

This package exports only canonical common keys: concepts more than one
component emits and that a cross-component dashboard joins or groups on.
Component-local keys used by a single emitter are not exported here; they
are defined by that component.

# Emitter Ownership

AttrStacklokComponent and AttrStacklokProduct are resource attributes (RFC
§3.3, D8), not metric labels: a component sets them once on its OTel resource,
and the Prometheus exporter promotes them to per-series labels via
WithResourceAsConstantLabels. ProductStacklokPlatform is the frozen value
every component stamps verbatim; the per-component stacklok.component value is
supplied by each component, not enumerated here.

# Build Info

RegisterBuildInfo registers the fleet-wide stacklok.build_info observable
gauge on a caller-provided meter, for release correlation across components:

	err := metrics.RegisterBuildInfo(meter, "toolhive", version, commit)

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package metrics
