// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package reconcile constructs the unified operator reconcile instrument
// triplet (RFC D12) on a caller-provided meter. Every Stacklok Kubernetes
// operator emits the same three instruments under the
// stacklok.operator.reconcile.* namespace, distinguished only by the caller's
// component label, so one set of reconcile dashboards covers all operators.
//
// This package is construction-only: New builds the instruments on the meter
// the caller passes and returns an Emitter whose methods record samples. It
// installs no global providers and registers no instruments on import. The
// caller owns the meter and supplies its component identity once at
// construction; the recording methods do not take it again.
//
// The three instruments are:
//
//   - stacklok.operator.reconcile.duration — Float64Histogram, unit "s",
//     long-running bucket preset, labels component/namespace/name/outcome.
//   - stacklok.operator.reconcile.errors — Int64Counter, unit "{error}",
//     labels component/namespace/name/phase.
//   - stacklok.operator.reconcile.managed_resources — Int64ObservableGauge,
//     unit "{resource}", labels component/namespace/name/kind. Its samples
//     come from a caller callback registered via RegisterManagedResources.
//
// The name/namespace labels carry the reconciled object's identity, which is
// a deliberate, bounded exception to the per-request cardinality policy (RFC
// §3.3): unlike a per-request metric, a reconcile sample is emitted once per
// object per reconcile, and the number of managed custom resources in a
// cluster is orders of magnitude below per-request cardinality.
//
// # Stability
//
// This package is Alpha stability. The API may change without notice.
package reconcile

import (
	"context"
	"fmt"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/stacklok/toolhive-core/telemetry/metrics"
)

// Instrument names for the unified operator reconcile triplet (RFC D12).
const (
	nameReconcileDuration = "stacklok.operator.reconcile.duration"
	nameReconcileErrors   = "stacklok.operator.reconcile.errors"
	nameManagedResources  = "stacklok.operator.reconcile.managed_resources"
)

// Label keys for the reconcile triplet. LabelOutcome mirrors the shared
// canonical key; component/namespace/name/phase/kind are operator-reconcile
// local and defined here.
const (
	// LabelComponent identifies which operator emitted the series (e.g.
	// "ai_gateway", "operator"). It is fixed per binary and set once at
	// construction. This bare key is deliberately distinct from
	// metrics.AttrStacklokComponent (a resource attribute, not a per-datapoint
	// label); see metrics.AttrStacklokComponent's doc comment for why the two
	// must not collide.
	LabelComponent = "component"
	// LabelNamespace and LabelName identify the reconciled object.
	LabelNamespace = "namespace"
	LabelName      = "name"
	// LabelPhase names the reconcile sub-phase a detailed error is attributed
	// to (errors counter only).
	LabelPhase = "phase"
	// LabelKind names the managed child-resource kind (managed_resources gauge
	// only).
	LabelKind = "kind"
	// LabelOutcome carries the terminal reconcile result on the duration
	// histogram; its value is one of the shared outcome-set values.
	LabelOutcome = metrics.LabelOutcome
)

// Emitter records the unified operator reconcile metrics for one component.
// Build it once per operator with New and share it across reconciles.
// RecordReconcile and RecordReconcileError are safe for concurrent use (the
// underlying OTel instruments are). RegisterManagedResources is a one-time
// setup call, not intended for repeated or concurrent invocation; see its
// doc comment.
type Emitter struct {
	component        string
	reconcileDur     metric.Float64Histogram
	reconcileErrors  metric.Int64Counter
	managedResources metric.Int64ObservableGauge

	managedResourcesMu         sync.Mutex
	managedResourcesRegistered bool
}

// New constructs the reconcile triplet on meter and returns an Emitter that
// stamps every series with component. The duration histogram uses the
// long-running bucket preset. New does not register the managed-resources
// callback; call RegisterManagedResources with an observer to start emitting
// that gauge.
func New(meter metric.Meter, component string) (*Emitter, error) {
	if meter == nil {
		return nil, fmt.Errorf("reconcile: meter must not be nil")
	}
	if component == "" {
		return nil, fmt.Errorf("reconcile: component must not be empty")
	}

	dur, err := meter.Float64Histogram(
		nameReconcileDuration,
		metric.WithUnit("s"),
		metric.WithDescription("Operator reconcile duration, keyed by component, object, and outcome."),
		metric.WithExplicitBucketBoundaries(metrics.BucketsLongRunning()...),
	)
	if err != nil {
		return nil, fmt.Errorf("reconcile: create duration histogram: %w", err)
	}

	errs, err := meter.Int64Counter(
		nameReconcileErrors,
		metric.WithUnit("{error}"),
		metric.WithDescription("Per-phase operator reconcile errors, keyed by component and object."),
	)
	if err != nil {
		return nil, fmt.Errorf("reconcile: create errors counter: %w", err)
	}

	gauge, err := meter.Int64ObservableGauge(
		nameManagedResources,
		metric.WithUnit("{resource}"),
		metric.WithDescription("Count of managed child resources per reconciled object, by kind."),
	)
	if err != nil {
		return nil, fmt.Errorf("reconcile: create managed resources gauge: %w", err)
	}

	return &Emitter{
		component:        component,
		reconcileDur:     dur,
		reconcileErrors:  errs,
		managedResources: gauge,
	}, nil
}

// RecordReconcile records one reconcile duration sample (seconds) tagged with
// the object identity and terminal outcome.
func (e *Emitter) RecordReconcile(ctx context.Context, namespace, name, outcome string, seconds float64) {
	e.reconcileDur.Record(ctx, seconds, metric.WithAttributes(
		attribute.String(LabelComponent, e.component),
		attribute.String(LabelNamespace, namespace),
		attribute.String(LabelName, name),
		attribute.String(LabelOutcome, outcome),
	))
}

// RecordReconcileError increments the per-phase reconcile error counter for
// the given object and phase. extra lets a caller attach additional
// disambiguating attributes (e.g. a provider name) without a schema change;
// pass none for the common case. Per the cardinality policy (RFC §3.3), extra
// attributes must come from a bounded, closed set of values (e.g. a fixed
// provider enum) — never an unbounded or per-request value such as an error
// message, a resource ID, or a user identifier.
func (e *Emitter) RecordReconcileError(
	ctx context.Context, namespace, name, phase string, extra ...attribute.KeyValue,
) {
	attrs := make([]attribute.KeyValue, 0, 4+len(extra))
	attrs = append(attrs,
		attribute.String(LabelComponent, e.component),
		attribute.String(LabelNamespace, namespace),
		attribute.String(LabelName, name),
		attribute.String(LabelPhase, phase),
	)
	attrs = append(attrs, extra...)
	e.reconcileErrors.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// ManagedResource is one observation of the managed-resources gauge: the count
// of child resources of Kind belonging to the object Namespace/Name.
type ManagedResource struct {
	Namespace string
	Name      string
	Kind      string
	Count     int64
}

// RegisterManagedResources wires an observable-gauge callback that emits one
// series per ManagedResource returned by observe on each collection cycle. It
// returns the registration so the caller can Unregister it on shutdown. observe
// is invoked by the OTel SDK; it must not block, and it must be safe for
// concurrent, reentrant invocation, per the OTel callback contract. The
// component label is stamped automatically.
//
// RegisterManagedResources may succeed at most once per Emitter; a call made
// after a prior successful registration returns an error rather than
// silently registering a duplicate callback against the same gauge, which
// would double-count observations. A call that fails (e.g. a transient SDK
// error) leaves the Emitter free to retry: only a successful registration
// is latched.
//
// meter must be the same meter instance passed to New — RegisterCallback is
// invoked on meter, but it observes the gauge instrument created against
// New's meter, so a mismatched meter registers the callback against the
// wrong instrument's collection cycle.
func (e *Emitter) RegisterManagedResources(
	meter metric.Meter, observe func(context.Context) []ManagedResource,
) (metric.Registration, error) {
	if observe == nil {
		return nil, fmt.Errorf("reconcile: observe callback must not be nil")
	}

	e.managedResourcesMu.Lock()
	defer e.managedResourcesMu.Unlock()

	if e.managedResourcesRegistered {
		return nil, fmt.Errorf("reconcile: managed-resources callback already registered")
	}

	reg, err := meter.RegisterCallback(
		func(ctx context.Context, obs metric.Observer) error {
			for _, r := range observe(ctx) {
				obs.ObserveInt64(e.managedResources, r.Count, metric.WithAttributes(
					attribute.String(LabelComponent, e.component),
					attribute.String(LabelNamespace, r.Namespace),
					attribute.String(LabelName, r.Name),
					attribute.String(LabelKind, r.Kind),
				))
			}
			return nil
		},
		e.managedResources,
	)
	if err != nil {
		return nil, fmt.Errorf("reconcile: register managed-resources callback: %w", err)
	}
	e.managedResourcesRegistered = true
	return reg, nil
}
