// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package rawmsg

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParams_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		raw      string
		setMeta  map[string]any
		wantJSON string
		wantMeta map[string]any
	}{
		{
			name:     "members pass through unchanged",
			raw:      `{"cursor":"c1","filter":{"tag":"docs"}}`,
			wantJSON: `{"cursor":"c1","filter":{"tag":"docs"}}`,
		},
		{
			name:     "_meta is decoded",
			raw:      `{"uri":"skill://a/SKILL.md","_meta":{"k":"v"}}`,
			wantJSON: `{"uri":"skill://a/SKILL.md","_meta":{"k":"v"}}`,
			wantMeta: map[string]any{"k": "v"},
		},
		{
			name:     "SetMeta is merged into the object",
			raw:      `{"uri":"skill://a/SKILL.md","_meta":{"old":1}}`,
			setMeta:  newMeta(),
			wantJSON: `{"uri":"skill://a/SKILL.md","_meta":{"fresh":"x"}}`,
			wantMeta: newMeta(),
		},
		{
			name:     "empty params with SetMeta",
			raw:      ``,
			setMeta:  newMeta(),
			wantJSON: `{"_meta":{"fresh":"x"}}`,
			wantMeta: newMeta(),
		},
		{
			name:     "empty params encode as the empty object",
			raw:      ``,
			wantJSON: `{}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := NewParams(json.RawMessage(tc.raw))
			require.NoError(t, err)
			if tc.setMeta != nil {
				p.SetMeta(tc.setMeta)
			}
			got, err := json.Marshal(p)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(got))
			if tc.wantMeta == nil {
				assert.Empty(t, p.GetMeta())
			} else {
				assert.Equal(t, tc.wantMeta, p.GetMeta())
			}
		})
	}
}

func TestResult_RoundTrip(t *testing.T) {
	t.Parallel()

	r, err := NewResult(json.RawMessage(`{"skills":[{"name":"pdf"}],"nextCursor":"n"}`))
	require.NoError(t, err)
	r.SetMeta(map[string]any{"io.modelcontextprotocol/serverInfo": map[string]any{"name": "s"}})

	got, err := json.Marshal(r)
	require.NoError(t, err)
	assert.JSONEq(t,
		`{"skills":[{"name":"pdf"}],"nextCursor":"n","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"s"}}}`,
		string(got))

	// An empty result stands for the empty object: a JSON-RPC result cannot be
	// absent.
	empty, err := NewResult(nil)
	require.NoError(t, err)
	got, err = json.Marshal(empty)
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(got))
}

func TestParams_UnmarshalViaJSON(t *testing.T) {
	t.Parallel()

	// go-sdk decodes incoming params with json.Unmarshal into a *Params.
	var p *Params
	require.NoError(t, json.Unmarshal([]byte(`{"a":1,"_meta":{"m":true}}`), &p))
	require.NotNil(t, p)
	assert.Equal(t, map[string]any{"m": true}, p.GetMeta())
	raw, err := p.Raw()
	require.NoError(t, err)
	assert.JSONEq(t, `{"a":1,"_meta":{"m":true}}`, string(raw))
}

func TestNew_RejectsNonObjects(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{`[]`, `"s"`, `1`, `null`, `{`, `{"_meta":"not-an-object"}`} {
		_, err := NewParams(json.RawMessage(raw))
		assert.Error(t, err, "params %s", raw)
		_, err = NewResult(json.RawMessage(raw))
		assert.Error(t, err, "result %s", raw)
	}
}

// newMeta returns the metadata the round-trip tests set with SetMeta.
func newMeta() map[string]any {
	return map[string]any{"fresh": "x"}
}
