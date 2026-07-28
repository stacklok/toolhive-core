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
	testHopOuter    = "outer"
	testHopInner    = "inner"
	testIss1        = "iss-1"
	testSub1        = "sub-1"
	testAdminRole   = "admin"
	testSourceIP    = "10.0.0.1"
	testActorAlice  = "alice"
	extraClaimEmail = "email"
)

// mapClaims mimics jwt.MapClaims: a named map type that does not satisfy a
// direct .(map[string]any) type assertion.
type mapClaims map[string]any

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
		name     string
		raw      any
		maxDepth int
		check    func(t *testing.T, c *DelegationChain)
	}{
		{
			name:     "nil input returns zero non-nil chain",
			raw:      nil,
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				assert.True(t, c.IsZero(), "nil input should yield zero chain")
				assert.NotNil(t, c.Chain, "Chain must be allocated, never nil")
				assert.False(t, c.Malformed)
				assert.Empty(t, c.MalformedReason)
			},
		},
		{
			name:     "string scalar flags act_not_object",
			raw:      "not-an-object",
			maxDepth: DefaultMaxDelegationDepth,
			check:    checkTopLevelMalformed,
		},
		{
			name:     "float64 scalar flags act_not_object",
			raw:      float64(3.14),
			maxDepth: DefaultMaxDelegationDepth,
			check:    checkTopLevelMalformed,
		},
		{
			name:     "bool scalar flags act_not_object",
			raw:      true,
			maxDepth: DefaultMaxDelegationDepth,
			check:    checkTopLevelMalformed,
		},
		{
			name:     "slice flags act_not_object",
			raw:      []any{"x"},
			maxDepth: DefaultMaxDelegationDepth,
			check:    checkTopLevelMalformed,
		},
		{
			name:     "json.Number scalar flags act_not_object",
			raw:      json.Number("123"),
			maxDepth: DefaultMaxDelegationDepth,
			check:    checkTopLevelMalformed,
		},
		{
			name:     "empty map yields one hop with empty subject/issuer",
			raw:      map[string]any{},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.Empty(t, c.Chain[0].Subject)
				assert.Empty(t, c.Chain[0].Issuer)
				assert.False(t, c.Truncated)
				assert.False(t, c.Malformed)
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
				assert.False(t, c.Malformed)
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
				hopClaimIss: testHopOuter,
				hopClaimSub: "outer-sub",
				hopClaimAct: map[string]any{
					hopClaimIss: testHopInner,
					hopClaimSub: "inner-sub",
				},
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 2)
				assert.Equal(t, testHopOuter, c.Chain[0].Issuer)
				assert.Equal(t, testHopInner, c.Chain[1].Issuer)
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
				assert.False(t, c.Malformed, "well-formed truncated chain must not be malformed")
			},
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
			name: "nested act not a map keeps parsed hops and flags malformed",
			raw: map[string]any{
				hopClaimSub: "x",
				hopClaimAct: "not-a-map",
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1, "the outer hop must be preserved")
				assert.Equal(t, "x", c.Chain[0].Subject)
				assert.True(t, c.Malformed)
				assert.Equal(t, MalformedReasonNestedActNotObject, c.MalformedReason)
				assert.False(t, c.Truncated)
				assert.Equal(t, 0, c.Omitted)
			},
		},
		{
			name: "explicit null act ends the chain without malformation",
			raw: map[string]any{
				hopClaimSub: "x",
				hopClaimAct: nil,
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.False(t, c.Malformed, "JSON null act asserts no delegation, like absence")
			},
		},
		{
			name: "non-string sub flags malformed and retains raw value in extra",
			raw: map[string]any{
				hopClaimSub: float64(123),
				hopClaimIss: "issuer-1",
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.Empty(t, c.Chain[0].Subject, "non-string sub must not be coerced")
				assert.Equal(t, "issuer-1", c.Chain[0].Issuer)
				assert.True(t, c.Malformed)
				assert.Equal(t, MalformedReasonSubNotString, c.MalformedReason)
				extra := c.Chain[0].Extra()
				require.NotNil(t, extra, "raw non-string sub must stay inspectable in memory")
				assert.Equal(t, float64(123), extra[hopClaimSub])
			},
		},
		{
			name: "non-string iss flags malformed and retains raw value in extra",
			raw: map[string]any{
				hopClaimIss: []any{"not", "a", "string"},
				hopClaimSub: "subject-1",
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 1)
				assert.Empty(t, c.Chain[0].Issuer)
				assert.Equal(t, "subject-1", c.Chain[0].Subject)
				assert.True(t, c.Malformed)
				assert.Equal(t, MalformedReasonIssNotString, c.MalformedReason)
				extra := c.Chain[0].Extra()
				require.NotNil(t, extra)
				assert.Equal(t, []any{"not", "a", "string"}, extra[hopClaimIss])
			},
		},
		{
			name: "first malformed reason wins",
			raw: map[string]any{
				hopClaimSub: float64(1), // sub_not_string, encountered first
				hopClaimAct: "scalar",   // nested_act_not_object, encountered second
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				assert.True(t, c.Malformed)
				assert.Equal(t, MalformedReasonSubNotString, c.MalformedReason)
			},
		},
		{
			name: "malformed node past the cap flags malformed without counting it",
			raw: map[string]any{
				hopClaimSub: testHopOuter,
				hopClaimAct: map[string]any{
					hopClaimSub: "mid",
					hopClaimAct: map[string]any{
						hopClaimSub: testHopInner,
						hopClaimAct: "scalar-tail",
					},
				},
			},
			maxDepth: 2,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 2)
				assert.True(t, c.Truncated)
				assert.Equal(t, 1, c.Omitted, "only the well-formed inner hop counts as omitted")
				assert.True(t, c.Malformed)
				assert.Equal(t, MalformedReasonNestedActNotObject, c.MalformedReason)
			},
		},
		{
			name: "named map type is accepted at top level and nested",
			raw: mapClaims{
				hopClaimSub: testHopOuter,
				hopClaimAct: mapClaims{
					hopClaimSub: testHopInner,
				},
			},
			maxDepth: DefaultMaxDelegationDepth,
			check: func(t *testing.T, c *DelegationChain) {
				t.Helper()
				require.Len(t, c.Chain, 2, "jwt.MapClaims-shaped input must parse, not vanish")
				assert.Equal(t, testHopOuter, c.Chain[0].Subject)
				assert.Equal(t, testHopInner, c.Chain[1].Subject)
				assert.False(t, c.Malformed)
			},
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := ParseDelegationChain(tt.raw, tt.maxDepth)
			require.NotNil(t, c, "ParseDelegationChain never returns nil")
			require.NotNil(t, c.Chain, "Chain must always be allocated")
			tt.check(t, c)
		})
	}
}

// checkTopLevelMalformed is the shared assertion for non-object top-level
// input: no hops, Malformed=true with act_not_object, no truncation.
func checkTopLevelMalformed(t *testing.T, c *DelegationChain) {
	t.Helper()
	assert.Empty(t, c.Chain)
	assert.NotNil(t, c.Chain, "even a malformed chain must serialize chain as [], not null")
	assert.True(t, c.Malformed)
	assert.Equal(t, MalformedReasonActNotObject, c.MalformedReason)
	assert.False(t, c.Truncated)
	assert.Equal(t, 0, c.Omitted)
	assert.True(t, c.IsEmpty())
	assert.False(t, c.IsZero(), "a malformed chain carries information and is not zero")
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

func TestDelegationChain_IsEmptyIsZero(t *testing.T) {
	t.Parallel()

	t.Run("nil chain is empty and zero", func(t *testing.T) {
		t.Parallel()
		var c *DelegationChain
		assert.True(t, c.IsEmpty())
		assert.True(t, c.IsZero())
	})

	t.Run("zero value is empty and zero", func(t *testing.T) {
		t.Parallel()
		var c DelegationChain
		assert.True(t, c.IsEmpty())
		assert.True(t, c.IsZero())
	})

	t.Run("one empty hop is not empty and not zero", func(t *testing.T) {
		t.Parallel()
		c := &DelegationChain{Chain: []DelegatedActor{{}}}
		assert.False(t, c.IsEmpty())
		assert.False(t, c.IsZero())
	})

	t.Run("hopless malformed chain is empty but not zero", func(t *testing.T) {
		t.Parallel()
		c := &DelegationChain{Chain: []DelegatedActor{}, Malformed: true}
		assert.True(t, c.IsEmpty())
		assert.False(t, c.IsZero())
	})
}

func TestAuditEventWithDelegationChain(t *testing.T) {
	t.Parallel()

	chain := &DelegationChain{
		Chain: []DelegatedActor{
			{Issuer: testIss1, Subject: testSub1},
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

	t.Run("attach zero chain clears field", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(chain)
		require.NotNil(t, event.DelegationChain)
		event.WithDelegationChain(&DelegationChain{})
		assert.Nil(t, event.DelegationChain)
	})

	t.Run("attach hopless malformed chain is kept", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		malformed := ParseDelegationChain("not-an-object", 0)
		event.WithDelegationChain(malformed)
		require.NotNil(t, event.DelegationChain,
			"a malformed delegation assertion is audit-relevant and must not be dropped")
		assert.True(t, event.DelegationChain.Malformed)
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
	chain := ParseDelegationChain(raw, 2)
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
	require.True(t, ok, "delegation object must be present")

	// The slog shape must be structurally identical to the event's JSON
	// marshaling: a "chain" ARRAY of {iss,sub} hops (not hop_N-keyed groups).
	hops, ok := delegation["chain"].([]any)
	require.True(t, ok, "chain must be a JSON array")
	require.Len(t, hops, 2, "chain length must be 2 (truncated)")

	hop0, ok := hops[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "current-actor", hop0["sub"], "chain[0].sub must be the current actor")
	assert.Equal(t, "outer-iss", hop0["iss"])

	assert.Equal(t, true, delegation["truncated"])
	assert.Equal(t, float64(1), delegation["omitted"])
	assert.Equal(t, false, delegation["malformed"])

	// PII guard: the extra-claim key must NOT appear anywhere in the output.
	assert.NotContains(t, out, "secret@example.com")
	assert.NotContains(t, out, "\"email\"", "extra claims must not be serialized")
}

// TestAuditEventLogTo_SlogMatchesJSON pins the contract that the "delegation"
// object in slog output is structurally equal to the "delegation" object in
// json.Marshal(event) output, so consumers can use one parser for both wire
// shapes.
func TestAuditEventLogTo_SlogMatchesJSON(t *testing.T) {
	t.Parallel()

	chain := ParseDelegationChain(map[string]any{
		hopClaimIss: testIss1,
		hopClaimSub: testSub1,
		hopClaimAct: "broken", // exercises malformed + malformedReason too
	}, 0)

	event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
	event.WithDelegationChain(chain)

	data, err := json.Marshal(event)
	require.NoError(t, err)
	var fromJSON map[string]any
	require.NoError(t, json.Unmarshal(data, &fromJSON))

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	event.LogTo(context.Background(), logger, LevelAudit)
	var fromSlog map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &fromSlog))

	require.Contains(t, fromJSON, "delegation")
	require.Contains(t, fromSlog, "delegation")
	assert.Equal(t, fromJSON["delegation"], fromSlog["delegation"],
		"slog and JSON delegation shapes must be identical")
}

func TestAuditEventJSON_RoundTrip(t *testing.T) {
	t.Parallel()

	chain := &DelegationChain{
		Chain: []DelegatedActor{
			{Issuer: testIss1, Subject: testSub1, extra: map[string]any{extraClaimEmail: testAliceEmail}},
			{Issuer: "iss-2", Subject: "sub-2"},
		},
		Truncated:       true,
		Omitted:         3,
		Malformed:       true,
		MalformedReason: MalformedReasonNestedActNotObject,
	}

	event := NewAuditEvent("mcp_tool_call", EventSource{Type: SourceTypeNetwork, Value: testSourceIP},
		OutcomeSuccess, map[string]string{subjKeyUser: testActorAlice}, "svc")
	event.WithDelegationChain(chain)

	data, err := json.Marshal(event)
	require.NoError(t, err)

	var decoded AuditEvent
	require.NoError(t, json.Unmarshal(data, &decoded))

	// Chain (iss/sub only) and Truncated/Omitted/Malformed must round-trip.
	require.NotNil(t, decoded.DelegationChain)
	require.Len(t, decoded.DelegationChain.Chain, 2)
	assert.Equal(t, testIss1, decoded.DelegationChain.Chain[0].Issuer)
	assert.Equal(t, testSub1, decoded.DelegationChain.Chain[0].Subject)
	assert.Equal(t, "iss-2", decoded.DelegationChain.Chain[1].Issuer)
	assert.Equal(t, "sub-2", decoded.DelegationChain.Chain[1].Subject)
	assert.True(t, decoded.DelegationChain.Truncated)
	assert.Equal(t, 3, decoded.DelegationChain.Omitted)
	assert.True(t, decoded.DelegationChain.Malformed)
	assert.Equal(t, MalformedReasonNestedActNotObject, decoded.DelegationChain.MalformedReason)

	// Extra must NOT round-trip (in-memory only).
	assert.Nil(t, decoded.DelegationChain.Chain[0].Extra())
}

// TestDelegationChainJSON_WireKeys asserts the EMITTED JSON key names, not Go
// struct fields, so a tag rename cannot slip through with a green suite.
func TestDelegationChainJSON_WireKeys(t *testing.T) {
	t.Parallel()

	t.Run("well-formed chain emits exactly the contracted keys", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(&DelegationChain{
			Chain: []DelegatedActor{{Issuer: testIss1, Subject: testSub1}},
		})
		data, err := json.Marshal(event)
		require.NoError(t, err)

		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &raw))
		require.Contains(t, raw, "delegation")

		var delegation map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw["delegation"], &delegation))
		assert.ElementsMatch(t,
			[]string{"chain", "truncated", "omitted", "malformed"},
			keysOf(delegation),
			"delegation wire keys are a contract; malformedReason is omitempty")

		var hops []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(delegation["chain"], &hops))
		require.Len(t, hops, 1)
		assert.ElementsMatch(t, []string{"iss", "sub"}, keysOf(hops[0]),
			"hop wire keys are a contract")
	})

	t.Run("hopless malformed chain emits chain as empty array not null", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(ParseDelegationChain(float64(1), 0))
		data, err := json.Marshal(event)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"chain":[]`,
			"a nil slice would marshal to null and break array-iterating consumers")
		assert.Contains(t, string(data), `"malformed":true`)
		assert.Contains(t, string(data), `"malformedReason":"act_not_object"`)
	})
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
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

	t.Run("zero chain omits delegation key", func(t *testing.T) {
		t.Parallel()
		event := NewAuditEvent("t", EventSource{}, OutcomeSuccess, map[string]string{}, "svc")
		event.WithDelegationChain(&DelegationChain{})
		data, err := json.Marshal(event)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "delegation")
	})
}
