// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"sync"
	"testing"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestToNotificationParams covers the conversion helper in isolation: the JSON
// round-trip, the reserved "_meta" key extraction into Meta, and the silent
// dropping of a non-map _meta. It is otherwise only exercised by e2e tests.
func TestToNotificationParams(t *testing.T) {
	t.Parallel()

	// fooKey is the JSON key used across the test structs and assertions.
	const fooKey = "foo"

	type scalarsOnly struct {
		// Only top-level scalar fields; no _meta.
		Foo string `json:"foo"`
		Bar int    `json:"bar"`
	}

	type withMeta struct {
		Foo  string         `json:"foo"`
		Meta map[string]any `json:"_meta"`
	}

	type withNonMapMeta struct {
		Foo  string `json:"foo"`
		Meta string `json:"_meta"`
	}

	type unmarshalable struct {
		Ch chan struct{} `json:"ch"`
	}

	tests := []struct {
		name      string
		src       any
		wantMeta  map[string]any // nil means expect Meta unset (nil).
		wantExtra map[string]any // expected AdditionalFields (subset checked).
	}{
		{
			name:      "scalar fields land in AdditionalFields, Meta empty",
			src:       scalarsOnly{Foo: "x", Bar: 7},
			wantExtra: map[string]any{fooKey: "x", "bar": float64(7)},
		},
		{
			name: "populated _meta lands in Meta, not AdditionalFields",
			src: withMeta{
				Foo:  "x",
				Meta: map[string]any{"trace-id": "abc"},
			},
			wantMeta:  map[string]any{"trace-id": "abc"},
			wantExtra: map[string]any{fooKey: "x"},
		},
		{
			name:      "non-map _meta silently dropped, other fields preserved",
			src:       withNonMapMeta{Foo: "x", Meta: "not-a-map"},
			wantExtra: map[string]any{fooKey: "x"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := toNotificationParams(tc.src)

			require.NotNil(t, out.AdditionalFields, "AdditionalFields map must be initialized")
			for k, v := range tc.wantExtra {
				assert.Equal(t, v, out.AdditionalFields[k], "AdditionalFields[%q]", k)
			}
			// _meta must never leak into AdditionalFields.
			_, hasMetaKey := out.AdditionalFields["_meta"]
			assert.False(t, hasMetaKey, "_meta must not appear in AdditionalFields")

			if tc.wantMeta == nil {
				assert.Nil(t, out.Meta, "Meta should be unset/nil")
			} else {
				assert.Equal(t, tc.wantMeta, out.Meta, "Meta mismatch")
			}
		})
	}

	// Nil input: marshal of nil yields "null", unmarshal into a map leaves it
	// nil, so the loop body never runs and we get an empty (but non-nil
	// AdditionalFields) NotificationParams. Assert no panic and an empty result.
	t.Run("nil input returns empty params without panic", func(t *testing.T) {
		t.Parallel()
		out := toNotificationParams(nil)
		assert.NotNil(t, out.AdditionalFields, "AdditionalFields map still initialized")
		assert.Empty(t, out.AdditionalFields)
		assert.Nil(t, out.Meta)
	})

	// Unmarshalable input (channel) makes json.Marshal fail; the helper must
	// swallow the error and return the zero-value NotificationParams (nil
	// AdditionalFields, nil Meta), not panic.
	t.Run("marshal error swallowed, empty params returned", func(t *testing.T) {
		t.Parallel()
		out := toNotificationParams(unmarshalable{Ch: make(chan struct{})})
		assert.Nil(t, out.AdditionalFields)
		assert.Nil(t, out.Meta)
	})
}

// TestProgressNotificationHandler_NilGuards exercises the nil-req / nil-params
// branches of the progress notification handler directly, asserting no panic
// and that dispatch is invoked with nil params (matching the guard behavior).
func TestProgressNotificationHandler_NilGuards(t *testing.T) {
	t.Parallel()

	type dispatched struct {
		method string
		params any
	}

	// newRecorder builds a dispatch func that appends to a fresh slice guarded
	// by a mutex, returning a snapshot accessor. Each subtest gets its own
	// recorder so the subtests are independent and can run in parallel.
	newRecorder := func() (func(string, any), func() []dispatched) {
		var (
			mu  sync.Mutex
			got []dispatched
		)
		dispatch := func(method string, params any) {
			mu.Lock()
			got = append(got, dispatched{method: method, params: params})
			mu.Unlock()
		}
		snapshot := func() []dispatched {
			mu.Lock()
			defer mu.Unlock()
			out := make([]dispatched, len(got))
			copy(out, got)
			return out
		}
		return dispatch, snapshot
	}
	hOf := func(dispatch func(string, any)) func(context.Context, *gosdk.ProgressNotificationClientRequest) {
		return newProgressNotificationHandler(dispatch)
	}

	t.Run("nil request dispatches progress with nil params", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() { h(context.Background(), nil) })
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/progress", got[0].method)
		assert.Nil(t, got[0].params)
	})

	t.Run("nil params dispatches progress with nil params", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() {
			h(context.Background(), &gosdk.ProgressNotificationClientRequest{Params: nil})
		})
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/progress", got[0].method)
		assert.Nil(t, got[0].params)
	})

	t.Run("populated params dispatched through", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() {
			h(context.Background(), &gosdk.ProgressNotificationClientRequest{
				Params: &gosdk.ProgressNotificationParams{ProgressToken: "t", Progress: 0.5},
			})
		})
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/progress", got[0].method)
		assert.NotNil(t, got[0].params)
	})
}

// TestLoggingMessageHandler_NilGuards exercises the nil-req / nil-params
// branches of the logging notification handler directly, asserting no panic
// and that dispatch is invoked with nil params.
func TestLoggingMessageHandler_NilGuards(t *testing.T) {
	t.Parallel()

	type dispatched struct {
		method string
		params any
	}
	newRecorder := func() (func(string, any), func() []dispatched) {
		var (
			mu  sync.Mutex
			got []dispatched
		)
		dispatch := func(method string, params any) {
			mu.Lock()
			got = append(got, dispatched{method: method, params: params})
			mu.Unlock()
		}
		snapshot := func() []dispatched {
			mu.Lock()
			defer mu.Unlock()
			out := make([]dispatched, len(got))
			copy(out, got)
			return out
		}
		return dispatch, snapshot
	}
	hOf := func(dispatch func(string, any)) func(context.Context, *gosdk.LoggingMessageRequest) {
		return newLoggingMessageHandler(dispatch)
	}

	t.Run("nil request dispatches message with nil params", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() { h(context.Background(), nil) })
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/message", got[0].method)
		assert.Nil(t, got[0].params)
	})

	t.Run("nil params dispatches message with nil params", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() {
			h(context.Background(), &gosdk.LoggingMessageRequest{Params: nil})
		})
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/message", got[0].method)
		assert.Nil(t, got[0].params)
	})

	t.Run("populated params dispatched through", func(t *testing.T) {
		t.Parallel()
		dispatch, snapshot := newRecorder()
		h := hOf(dispatch)
		assert.NotPanics(t, func() {
			h(context.Background(), &gosdk.LoggingMessageRequest{
				Params: &gosdk.LoggingMessageParams{Level: gosdk.LoggingLevel("info"), Data: "hi"},
			})
		})
		got := snapshot()
		require.Len(t, got, 1)
		assert.Equal(t, "notifications/message", got[0].method)
		assert.NotNil(t, got[0].params)
	})
}

// TestListChangedHandlers_MethodStrings guards against a typo in the three
// list-changed method strings wired up by installNotificationHandlers. It
// installs the handlers onto a real (unconnected) Client, invokes each go-sdk
// handler directly, and asserts the dispatched method string matches the MCP
// spec name. A regression here would silently break consumers expecting
// notifications/{tools,prompts,resources}/list_changed.
func TestListChangedHandlers_MethodStrings(t *testing.T) {
	t.Parallel()

	c := &Client{}
	var (
		mu  sync.Mutex
		got []string
	)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		mu.Lock()
		got = append(got, n.Method)
		mu.Unlock()
	})

	opts := &gosdk.ClientOptions{}
	c.installNotificationHandlers(opts)

	require.NotNil(t, opts.ToolListChangedHandler)
	require.NotNil(t, opts.PromptListChangedHandler)
	require.NotNil(t, opts.ResourceListChangedHandler)

	opts.ToolListChangedHandler(context.Background(), nil)
	opts.PromptListChangedHandler(context.Background(), nil)
	opts.ResourceListChangedHandler(context.Background(), nil)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{
		"notifications/tools/list_changed",
		"notifications/prompts/list_changed",
		"notifications/resources/list_changed",
	}, got, "list-changed method strings must match the MCP spec names")
}
