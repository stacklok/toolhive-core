// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package metrics provides shared histogram bucket presets and label-key
constants for OpenTelemetry metrics across the ToolHive ecosystem.

This package provides construction helpers only. Importing it registers no
instruments and emits no metrics; consumers (the ToolHive proxy, vMCP, and the
registry) use it to build their own instruments consistently.

# Bucket Presets

Three histogram bucket presets cover fast HTTP calls, MCP/proxy operations,
and long-running operations such as sync, reconcile, or composite-tool
execution:

	meter := otel.Meter("stacklok.toolhive.proxy")
	histogram, err := meter.Float64Histogram(
	    "stacklok.toolhive.proxy.request.duration",
	    metric.WithExplicitBucketBoundaries(metrics.BucketsFastHTTP()...),
	)

# Label Keys

Canonical label-key constants ensure every consumer spells the same concept
the same way:

	counter.Add(ctx, 1, metric.WithAttributes(
	    attribute.String(metrics.LabelOutcome, "success"),
	))

This package exports only canonical common keys: concepts more than one
component emits and that a cross-component dashboard joins or groups on.
Component-local keys used by a single emitter are not exported here; they
are defined by that component.

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package metrics
