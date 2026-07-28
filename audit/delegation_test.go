// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test-local constants to satisfy goconst across repeated use in fixtures.
const (
	testAliceEmail  = "alice@example.com"
	testAdminRole   = "admin"
	testSourceIP    = "10.0.0.1"
	testActorAlice  = "alice"
	extraClaimEmail = "email"
)

// nestedAct builds a deeply nested act chain map of the given depth where
// each hop has iss=<label>. The outermost hop is labeled with labels[0].
// Each hop's act points to the next, forming a chain of `depth` hops total.
func nestedAct(depth int, labels []string) map[string]any {
	if depth <= 0 {
		return nil
	}
	hop := map[string]any{
		hopClaimIss: labels[0],
		hopClaimSub: labels[0] + "-sub",
	}
	if depth > 1 {
		hop[hopClaimAct] = nestedAct(depth-1, labels[1:])
	}
	return hop
}

// labelsABC returns labels C,B,A,... so that nestedAct produces outermost=C
// (Chain[0]=C) down to A as the innermost.
func labelsABC(n int) []string {
	all := []string{"C", "B", "A", "Z", "Y", "X", "W", "V", "U", "T", "S", "R", "Q", "P", "O", "N"}
	if n <= len(all) {
		return all[:n]
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = all[i%len(all)]
	}
	return out
}

func TestParseDelegationChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		raw         any
		maxDepth    int
		wantErr     bool
		errContains string
		wantErrIs   error
		check       func(t *testing.T, c *DelegationChain)
	}{
		{
			name:     "nil input returns empty non-nil chain",
			raw:      nil,
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.NotNil(t, c)
				assert.True(t, c.IsEmpty(), "nil input should yield empty chain")
				assert.False(t, c.Truncated)
				assert.Equal(t, 0, c.Omitted)
			},
		},
		{
			name:        "string scalar returns error naming kind",
			raw:         "not-an-object",
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "string",
			wantErrIs:   ErrNotJSONObject,
		},
		{
			name:        "float64 scalar returns error naming kind",
			raw:         float64(3.14),
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "float64",
			wantErrIs:   ErrNotJSONObject,
		},
		{
			name:        "bool scalar returns error naming kind",
			raw:         true,
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "bool",
			wantErrIs:   ErrNotJSONObject,
		},
		{
			name:        "slice returns error naming kind",
			raw:         []any{"x"},
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "[]interface",
			wantErrIs:   ErrNotJSONObject,
		},
		{
			name:     "empty map yields one hop with empty subject/issuer",
			raw:      map[string]any{},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.NotNil(t, c)
				require.Len(t, c.Chain, 1)
				assert.Empty(t, c.Chain[0].Subject)
				assert.Empty(t, c.Chain[0].Issuer)
				assert.False(t, c.Truncated)
			},
		},
		{
			name:     "sub only sets subject",
			raw:      map[string]any{hopClaimSub: testActorAlice},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.Equal(t, testActorAlice, c.Chain[0].Subject)
				assert.Empty(t, c.Chain[0].Issuer)
			},
		},
		{
			name:     "iss and sub both set",
			raw:      map[string]any{hopClaimIss: "issuer-1", hopClaimSub: "subject-1"},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.Equal(t, "issuer-1", c.Chain[0].Issuer)
				assert.Equal(t, "subject-1", c.Chain[0].Subject)
			},
		},
		{
			name: "one hop with nested act yields two entries outermost-first",
			raw: map[string]any{
				hopClaimIss: "outer",
				hopClaimSub: "outer-sub",
				hopClaimAct: map[string]any{
					hopClaimIss: "inner",
					hopClaimSub: "inner-sub",
				},
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 2)
				assert.Equal(t, "outer", c.Chain[0].Issuer)
				assert.Equal(t, "inner", c.Chain[1].Issuer)
				assert.False(t, c.Truncated)
				assert.Equal(t, 0, c.Omitted)
			},
		},
		{
			name:     "two hops produce three entries ordered C,B,A",
			raw:      nestedAct(3, labelsABC(3)),
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 3)
				// outermost-first: Chain[0]=C, Chain[1]=B, Chain[2]=A
				assert.Equal(t, "C", c.Chain[0].Issuer)
				assert.Equal(t, "B", c.Chain[1].Issuer)
				assert.Equal(t, "A", c.Chain[2].Issuer)
				assert.False(t, c.Truncated)
			},
		},
		{
			name:     "depth exactly at cap yields no truncation",
			raw:      nestedAct(16, labelsABC(16)),
			maxDepth: 16,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 16)
				assert.False(t, c.Truncated)
				assert.Equal(t, 0, c.Omitted)
			},
		},
		{
			name:     "depth over cap keeps outermost maxDepth hops truncates inner",
			raw:      nestedAct(20, labelsABC(20)),
			maxDepth: 16,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 16)
				assert.True(t, c.Truncated)
				// dropped inner hops = 20 - 16 = 4
				assert.Equal(t, 4, c.Omitted)
				// The kept hops must be the OUTERMOST (C,B,A,...), not middle/inner.
				assert.Equal(t, "C", c.Chain[0].Issuer)
				// The 16th kept hop should be the 16th outermost label, NOT the
				// innermost. labelsABC(20) => [C,B,A,Z,Y,X,W,V,U,T,S,R,Q,P,O,N,...]
				// so index 15 (the 16th) is "N".
				assert.Equal(t, "N", c.Chain[15].Issuer)
			},
		},
		{
			name: "act present but not a map returns error",
			raw: map[string]any{
				hopClaimSub: "x",
				hopClaimAct: "not-a-map",
			},
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "act claim must be a JSON object",
			wantErrIs:   ErrNestedActNotObject,
		},
		{
			name: "extra claims retained in memory",
			raw: map[string]any{
				hopClaimSub:     testActorAlice,
				extraClaimEmail: testAliceEmail,
				"role":          testAdminRole,
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				extra := c.Chain[0].Extra()
				require.NotNil(t, extra)
				assert.Equal(t, testAliceEmail, extra[extraClaimEmail])
				assert.Equal(t, testAdminRole, extra["role"])
			},
		},
		{
			name:     "maxDepth 0 uses default 16 no truncation at depth 3",
			raw:      nestedAct(3, labelsABC(3)),
			maxDepth: 0,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 3)
				assert.False(t, c.Truncated)
			},
		},
		{
			name:     "negative maxDepth uses default 16 no truncation at depth 3",
			raw:      nestedAct(3, labelsABC(3)),
			maxDepth: -5,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 3)
				assert.False(t, c.Truncated)
			},
		},
		{
			name:     "depth 1000 with maxDepth 16 truncates omitted 984 no panic",
			raw:      nestedAct(1000, labelsABC(1000)),
			maxDepth: 16,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 16)
				assert.True(t, c.Truncated)
				assert.Equal(t, 984, c.Omitted)
				// outermost preserved
				assert.Equal(t, "C", c.Chain[0].Issuer)
			},
		},
		{
			name:        "json.Number scalar returns ErrNotJSONObject",
			raw:         json.Number("123"),
			maxDepth:    DefaultMaxDelegationDepth,
			wantErr:     true,
			errContains: "json.Number",
			wantErrIs:   ErrNotJSONObject,
		},
		{
			name:     "depth one over cap Omits exactly 1 outermost preserved",
			raw:      nestedAct(17, labelsABC(17)),
			maxDepth: 16,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 16)
				assert.True(t, c.Truncated, "must be truncated at depth 17 vs cap 16")
				assert.Equal(t, 1, c.Omitted, "exactly one hop must be omitted")
				// Chain[0] is the outermost actor, preserved.
				assert.Equal(t, "C", c.Chain[0].Issuer)
			},
		},
		{
			name: "extra claims with rich types stored in Extra",
			raw: map[string]any{
				hopClaimSub: "x",
				"extra_obj": map[string]any{"nested": "value"},
				"extra_arr": []any{1, 2, 3},
				"extra_num": float64(42),
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				extra := c.Chain[0].Extra()
				require.NotNil(t, extra)

				obj, ok := extra["extra_obj"].(map[string]any)
				require.True(t, ok)
				assert.Equal(t, "value", obj["nested"])

				arr, ok := extra["extra_arr"].([]any)
				require.True(t, ok)
				assert.Equal(t, []any{1, 2, 3}, arr)

				num, ok := extra["extra_num"].(float64)
				require.True(t, ok)
				assert.Equal(t, float64(42), num)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := ParseDelegationChain(tt.raw, tt.maxDepth)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				if tt.wantErrIs != nil {
					assert.ErrorIs(t, err, tt.wantErrIs)
				}
				assert.Nil(t, c)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, c)
			}
		})
	}
}

func TestDelegatedActor_Extra(t *testing.T) {
	t.Parallel()

	t.Run("returns a copy mutation does not affect internal state", func(t *testing.T) {
		t.Parallel()
		a := DelegatedActor{
			Issuer:  "i",
			Subject: "s",
			extra:   map[string]any{extraClaimEmail: testAliceEmail, "n": 42},
		}
		got := a.Extra()
		require.Equal(t, testAliceEmail, got[extraClaimEmail])

		// Mutate the returned copy; internal state must be unchanged.
		got[extraClaimEmail] = "mutated"
		got["newkey"] = "newval"
		again := a.Extra()
		assert.Equal(t, testAliceEmail, again[extraClaimEmail])
		_, hasNew := again["newkey"]
		assert.False(t, hasNew, "internal extra must not gain new keys")
	})

	t.Run("nil for zero value", func(t *testing.T) {
		t.Parallel()
		var a DelegatedActor
		assert.Nil(t, a.Extra())
	})
}

func TestDelegationChain_IsEmpty(t *testing.T) {
	t.Parallel()

	t.Run("nil chain is empty", func(t *testing.T) {
		t.Parallel()
		var c *DelegationChain
		assert.True(t, c.IsEmpty())
	})

	t.Run("zero value is empty", func(t *testing.T) {
		t.Parallel()
		var c DelegationChain
		assert.True(t, c.IsEmpty())
	})

	t.Run("one empty hop is not empty", func(t *testing.T) {
		t.Parallel()
		c := &DelegationChain{Chain: []DelegatedActor{{}}}
		assert.False(t, c.IsEmpty())
	})
}

func TestAuditEventWithDelegationChain(t *testing.T) {
	t.Parallel()

	chain := &DelegationChain{
		Chain: []DelegatedActor{
			{Issuer: "iss-1", Subject: "sub-1"},
			{Issuer: "iss-2", Subject: "sub-2"},
		},
	}

	t.Run("attach non-empty sets field", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{subjKeyUser: testActorAlice}, "svc")
		result := event.WithDelegationChain(chain)
		assert.Equal(t, event, result)
		require.NotNil(t, event.DelegationChain)
		assert.Equal(t, chain, event.DelegationChain)
	})

	t.Run("attach nil clears field", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(chain)
		require.NotNil(t, event.DelegationChain)
		event.WithDelegationChain(nil)
		assert.Nil(t, event.DelegationChain)
	})

	t.Run("attach empty chain clears field", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(chain)
		require.NotNil(t, event.DelegationChain)
		event.WithDelegationChain(&DelegationChain{})
		assert.Nil(t, event.DelegationChain)
	})

	t.Run("attach then nil clears field", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(chain)
		event.WithDelegationChain(nil)
		assert.Nil(t, event.DelegationChain)
	})

	t.Run("Subjects unchanged after attach no side effect", func(t *testing.T) {
		t.Parallel()
		subjects := map[string]string{subjKeyUser: testActorAlice, "role": testAdminRole}
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, subjects, "svc")
		before := cloneStringMap(event.Subjects)
		event.WithDelegationChain(chain)
		assert.Equal(t, before, event.Subjects, "Subjects must not be modified by WithDelegationChain")
		// deep-equal guard: ensure map is the same reference and contents
		assert.Equal(t, subjects, event.Subjects)
	})
}

func cloneStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func TestAuditEventLogTo_Delegation(t *testing.T) {
	t.Parallel()

	// Build a 3-hop chain with an extra (PII) claim on hop 0, then parse with
	// maxDepth 2 so it truncates to 2 kept hops, Omitted=1.
	raw := map[string]any{
		hopClaimIss:     "outer-iss",
		hopClaimSub:     "current-actor",
		extraClaimEmail: "secret@example.com", // PII extra claim
		hopClaimAct: map[string]any{
			hopClaimIss: "mid-iss",
			hopClaimSub: "mid-sub",
			hopClaimAct: map[string]any{
				hopClaimIss: "inner-iss",
				hopClaimSub: "inner-sub",
			},
		},
	}
	chain, err := ParseDelegationChain(raw, 2)
	require.NoError(t, err)
	require.True(t, chain.Truncated)
	assert.Equal(t, 1, chain.Omitted)
	require.Len(t, chain.Chain, 2)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	event := NewAuditEvent("mcp_tool_call", EventSource{Type: SourceTypeNetwork, Value: testSourceIP},
		OutcomeSuccess, map[string]string{subjKeyUser: testActorAlice}, "svc")
	event.WithDelegationChain(chain)

	event.LogTo(context.Background(), logger, LevelAudit)

	out := buf.String()
	require.NotEmpty(t, out)

	var entry map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &entry))

	delegation, ok := entry["delegation"].(map[string]any)
	require.True(t, ok, "delegation group must be present")

	hops, ok := delegation["hops"].(map[string]any)
	require.True(t, ok, "hops must be a map")
	assert.Len(t, hops, 2, "hops length must be 2 (truncated)")

	hop0, ok := hops["hop_0"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "current-actor", hop0["sub"], "hop_0.sub must be the current actor")
	assert.Equal(t, "outer-iss", hop0["iss"])

	assert.Equal(t, true, delegation["truncated"])
	assert.Equal(t, float64(1), delegation["omitted"])

	// PII guard: the extra-claim key must NOT appear anywhere in the output.
	assert.NotContains(t, out, "secret@example.com")
	assert.NotContains(t, out, "\"email\"", "extra claims must not be serialized")
}

func TestAuditEventJSON_RoundTrip(t *testing.T) {
	t.Parallel()

	chain := &DelegationChain{
		Chain: []DelegatedActor{
			{Issuer: "iss-1", Subject: "sub-1", extra: map[string]any{extraClaimEmail: testAliceEmail}},
			{Issuer: "iss-2", Subject: "sub-2"},
		},
		Truncated: true,
		Omitted:   3,
	}

	event := NewAuditEvent("mcp_tool_call", EventSource{Type: SourceTypeNetwork, Value: testSourceIP},
		OutcomeSuccess, map[string]string{subjKeyUser: testActorAlice}, "svc")
	event.WithDelegationChain(chain)

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded AuditEvent
	require.NoError(t, json.Unmarshal(data, &decoded))

	// Chain (iss/sub only) and Truncated/Omitted must round-trip.
	require.NotNil(t, decoded.DelegationChain)
	require.Len(t, decoded.DelegationChain.Chain, 2)
	assert.Equal(t, "iss-1", decoded.DelegationChain.Chain[0].Issuer)
	assert.Equal(t, "sub-1", decoded.DelegationChain.Chain[0].Subject)
	assert.Equal(t, "iss-2", decoded.DelegationChain.Chain[1].Issuer)
	assert.Equal(t, "sub-2", decoded.DelegationChain.Chain[1].Subject)
	assert.True(t, decoded.DelegationChain.Truncated)
	assert.Equal(t, 3, decoded.DelegationChain.Omitted)

	// Extra must NOT round-trip (in-memory only).
	assert.Nil(t, decoded.DelegationChain.Chain[0].Extra())
}

func TestAuditEventJSON_OmitEmpty(t *testing.T) {
	t.Parallel()

	t.Run("nil chain omits delegation key", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		data, err := json.Marshal(event)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "delegation")
	})

	t.Run("empty chain omits delegation key", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(&DelegationChain{})
		data, err := json.Marshal(event)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "delegation")
	})
}
