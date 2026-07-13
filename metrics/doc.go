// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package metrics provides shared meter creation, histogram bucket presets, and
label-key constants for OpenTelemetry metrics across the ToolHive ecosystem.

This package provides construction helpers only. Importing it registers no
instruments and emits no metrics; consumers (the ToolHive proxy, vMCP, and the
registry) use it to build their own instruments consistently.

# Meter Creation

Obtain an OTel meter for an instrument scope:

	meter := metrics.Meter("stacklok.toolhive")
	counter, err := meter.Int64Counter("stacklok.toolhive.requests")

# Bucket Presets

Three histogram bucket presets cover fast HTTP calls, MCP/proxy operations,
and long-running operations such as sync, reconcile, or composite-tool
execution:

	histogram, err := meter.Float64Histogram(
	    "stacklok.toolhive.request.duration",
	    metric.WithExplicitBucketBoundaries(metrics.BucketsFastHTTP()...),
	)

# Label Keys

Canonical label-key constants ensure every consumer spells the same concept
the same way:

	counter.Add(ctx, 1, metric.WithAttributes(
	    attribute.String(metrics.LabelOutcome, "success"),
	))

# Validation

ValidateName and ValidateLabelKind are build-time lints, intended for use in
tests and tooling rather than on any runtime path. ValidateName rejects a
dotted metric name that uses "gateway" as its service segment; ValidateLabelKind
rejects a boolean-typed label value.

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package metrics
