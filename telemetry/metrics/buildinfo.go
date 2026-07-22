// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// BuildInfoMetricName is the fleet-wide build/release-correlation gauge. It is
// the one Stacklok-authored metric with no <service> segment (RFC §3.4), shared
// verbatim by every component.
const BuildInfoMetricName = "stacklok.build_info"

// unknownBuildInfoValue is the fallback for an empty version or commit.
const unknownBuildInfoValue = "unknown"

// RegisterBuildInfo registers the stacklok.build_info observable gauge on the
// given meter. The gauge always observes 1; the identity rides its labels
// (component, version, commit). Empty version/commit fall back to unknownBuildInfoValue.
//
// The component label uses the bare "component" key, not the dotted
// stacklok.component resource attribute (AttrStacklokComponent), so it does not
// collide with the stacklok_component constant label the Prometheus exporter
// promotes from the resource (D8). Pass a Component* roster value.
//
// As with the rest of this package, RegisterBuildInfo is a construction helper:
// the caller supplies the meter (typically otel.Meter(scope) after installing
// its provider). It registers no global state of its own.
func RegisterBuildInfo(meter metric.Meter, component, version, commit string) error {
	if meter == nil {
		return fmt.Errorf("metrics: meter must not be nil")
	}
	if component == "" {
		return fmt.Errorf("metrics: component must not be empty")
	}
	if version == "" {
		version = unknownBuildInfoValue
	}
	if commit == "" {
		commit = unknownBuildInfoValue
	}

	_, err := meter.Int64ObservableGauge(BuildInfoMetricName,
		metric.WithUnit("1"),
		metric.WithDescription("Build information; always 1, identity carried on labels."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(1, metric.WithAttributes(
				attribute.String("component", component),
				attribute.String("version", version),
				attribute.String("commit", commit),
			))
			return nil
		}),
	)
	if err != nil {
		return fmt.Errorf("register build_info gauge: %w", err)
	}
	return nil
}
