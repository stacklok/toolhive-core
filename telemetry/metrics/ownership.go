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
// provider, not per instrument.
const (
	// AttrStacklokComponent is the resource-attribute key naming the emitting
	// component. Its value is one of the Component* roster below.
	AttrStacklokComponent = "stacklok.component"

	// AttrStacklokProduct is the resource-attribute key naming the product.
	// Its value is frozen at ProductStacklokPlatform for every component.
	AttrStacklokProduct = "stacklok.product"
)

// ProductStacklokPlatform is the frozen stacklok.product value stamped by every
// component. It is deliberately "stacklok-platform" (not "stacklok-enterprise")
// so it survives the toolhive-enterprise to toolhive-platform rename; the value
// lands in customer dashboards and must not churn.
const ProductStacklokPlatform = "stacklok-platform"

// Component roster: the canonical stacklok.component values. This is an open
// set (a new component picks its own value), but the known values are listed
// here so cross-component dashboards and this package's guard test share one
// source of truth. Each emitter passes its own value; the roster does not force
// a closed enum.
const (
	ComponentToolhive         = "toolhive"
	ComponentVMCP             = "vmcp"
	ComponentRegistry         = "registry"
	ComponentAIGateway        = "ai_gateway"
	ComponentOperator         = "operator"
	ComponentConnectorGateway = "connector_gateway"
	ComponentDirectory        = "directory"
	ComponentConfigServer     = "config_server"
)
