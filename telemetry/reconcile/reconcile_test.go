// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestConstructionValidation(t *testing.T) {
	t.Parallel()

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	meter := mp.Meter("test")

	_, err := New(nil, "operator")
	assert.Error(t, err, "nil meter rejected")

	_, err = New(meter, "")
	assert.Error(t, err, "empty component rejected")

	_, err = New(meter, "operator")
	assert.NoError(t, err, "valid construction")
}

// TestInstrumentNamesAndLabels pins the three metric names and the exact label
// key set each carries by scraping a real manual reader. A silent respelling
// of a name or label key breaks the unified operator dashboards this triplet
// exists to guarantee.
func TestInstrumentNamesAndLabels(t *testing.T) {
	t.Parallel()

	const component = "operator"
	ctx := context.Background()

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(ctx) })
	meter := mp.Meter("test-operator")

	e, err := New(meter, component)
	require.NoError(t, err)

	e.RecordReconcile(ctx, "ns1", "obj1", "success", 0.5)
	e.RecordReconcileError(ctx, "ns1", "obj1", "compile")
	reg, err := e.RegisterManagedResources(meter, func(context.Context) []ManagedResource {
		return []ManagedResource{{Namespace: "ns1", Name: "obj1", Kind: "configmap", Count: 3}}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg.Unregister() })

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(ctx, &rm))
	require.Len(t, rm.ScopeMetrics, 1, "one instrumentation scope")

	byName := map[string]metricdata.Metrics{}
	for _, m := range rm.ScopeMetrics[0].Metrics {
		byName[m.Name] = m
	}

	want := map[string]struct {
		unit string
		keys []string
	}{
		"stacklok.operator.reconcile.duration":          {"s", []string{"component", "name", "namespace", "outcome"}},
		"stacklok.operator.reconcile.errors":            {"{error}", []string{"component", "name", "namespace", "phase"}},
		"stacklok.operator.reconcile.managed_resources": {"{resource}", []string{"component", "kind", "name", "namespace"}},
	}

	for name, exp := range want {
		m, ok := byName[name]
		require.Truef(t, ok, "instrument %q must be emitted; got %v", name, sortedNames(byName))
		assert.Equalf(t, exp.unit, m.Unit, "%s unit", name)
		assert.ElementsMatchf(t, exp.keys, firstDataPointKeys(t, m), "%s label keys", name)
	}

	// Values on each instrument.
	dur := byName["stacklok.operator.reconcile.duration"].Data.(metricdata.Histogram[float64])
	require.Len(t, dur.DataPoints, 1)
	assert.Equal(t, component, attrValue(dur.DataPoints[0].Attributes, "component"))
	assert.Equal(t, "success", attrValue(dur.DataPoints[0].Attributes, "outcome"))

	sum := byName["stacklok.operator.reconcile.errors"].Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(1), sum.DataPoints[0].Value, "one error counted")
	assert.Equal(t, "compile", attrValue(sum.DataPoints[0].Attributes, "phase"))

	gauge := byName["stacklok.operator.reconcile.managed_resources"].Data.(metricdata.Gauge[int64])
	require.Len(t, gauge.DataPoints, 1)
	assert.Equal(t, int64(3), gauge.DataPoints[0].Value)
	assert.Equal(t, "configmap", attrValue(gauge.DataPoints[0].Attributes, "kind"))
}

// firstDataPointKeys returns the attribute keys on the first data point of m,
// regardless of aggregation type.
func firstDataPointKeys(t *testing.T, m metricdata.Metrics) []string {
	t.Helper()
	var attrs attribute.Set
	switch d := m.Data.(type) {
	case metricdata.Histogram[float64]:
		require.NotEmpty(t, d.DataPoints)
		attrs = d.DataPoints[0].Attributes
	case metricdata.Sum[int64]:
		require.NotEmpty(t, d.DataPoints)
		attrs = d.DataPoints[0].Attributes
	case metricdata.Gauge[int64]:
		require.NotEmpty(t, d.DataPoints)
		attrs = d.DataPoints[0].Attributes
	default:
		t.Fatalf("unexpected aggregation for %s: %T", m.Name, m.Data)
	}
	var keys []string
	for _, kv := range attrs.ToSlice() {
		keys = append(keys, string(kv.Key))
	}
	return keys
}

func attrValue(set attribute.Set, key string) string {
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		return ""
	}
	return v.AsString()
}

func sortedNames(byName map[string]metricdata.Metrics) []string {
	var names []string
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
