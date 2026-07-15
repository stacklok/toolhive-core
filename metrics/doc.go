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

	meter := metrics.Meter("stacklok.toolhive.proxy")
	counter, err := meter.Int64Counter("stacklok.toolhive.proxy.requests")

# Bucket Presets

Three histogram bucket presets cover fast HTTP calls, MCP/proxy operations,
and long-running operations such as sync, reconcile, or composite-tool
execution:

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

# Validation

ValidateName and ValidateLabel are build-time lints, intended for use in
tests and tooling rather than on any runtime path. ValidateName rejects a
metric name that does not match the stacklok.<service>.<subsystem>.<name>
shape (missing prefix, too few segments, or a segment containing characters
outside [a-z0-9_]), and rejects a name that uses "gateway" as its service
segment.
ValidateLabel rejects a label key that re-spells a canonical concept under a
banned alias (e.g. "server" instead of "mcp_server") instead of its
canonical key, so the join-key contract holds even for emitters that mirror
these constants locally rather than importing them, and rejects a
boolean-typed label value.

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package metrics
