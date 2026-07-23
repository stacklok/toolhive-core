// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

// Emitter-ownership resource attributes (RFC §3.3 / D8). Each Stacklok
// component stamps these two attributes on its OpenTelemetry resource; the
// Prometheus exporter promotes them to per-series labels (stacklok_component,
// stacklok_product) via WithResourceAsConstantLabels, so a single selector
// stacklok_product="stacklok-platform" spans the whole fleet, and
// stacklok_component distinguishes emitters.
//
// These are resource attributes, not metric labels: they are set once on the
// provider, not per instrument. Do not attach them via attribute.String on an
// individual Record/Add call — that would collide with the exporter-promoted
// per-series label of the same name. See buildinfo.go's RegisterBuildInfo for a
// parallel, deliberately distinct bare-string "component" label attached per
// data point.
//
// This package defines only the attribute keys, not the per-component value
// strings: each component supplies its own AttrStacklokComponent value (e.g.
// "toolhive", "registry", "ai_gateway"). A foundational library names the
// concept, not the roster of apps that consume it.
const (
	// AttrStacklokComponent is the resource-attribute key naming the emitting
	// component. Each component supplies its own value.
	AttrStacklokComponent = "stacklok.component"

	// AttrStacklokProduct is the resource-attribute key naming the product.
	// Its value is frozen at ProductStacklokPlatform for every component.
	AttrStacklokProduct = "stacklok.product"
)

// ProductStacklokPlatform is the frozen stacklok.product value stamped by every
// component. Unlike the per-component AttrStacklokComponent value, this one
// string is shared verbatim across the whole fleet: a single selector
// stacklok_product="stacklok-platform" spans every emitter, so the value must
// not drift per component. It is deliberately "stacklok-platform" (not
// "stacklok-enterprise") so it survives the toolhive-enterprise to
// toolhive-platform rename; the value lands in customer dashboards and must not
// churn.
const ProductStacklokPlatform = "stacklok-platform"
