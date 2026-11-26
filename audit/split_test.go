// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Expected payload states in TestNewEvent_CutOrderAndTruncatedRecord.
const (
	descAfterField = "changes.description.after"
	payloadPartial = "partial"
	payloadEmpty   = "empty"
)

// listEntries collects every list entry from rendered lines: value and secret
// changes by field, member ids, and delegation hops.
type listEntries struct {
	fields  []string
	added   []string
	removed []string
	hops    []string
}

func collectEntries(t *testing.T, lines [][]byte) listEntries {
	t.Helper()
	var out listEntries
	for _, line := range lines {
		m := decode(t, line)
		extra := m["metadata"].(map[string]any)["extra"].(map[string]any)
		changes, _ := extra["changes"].([]any)
		for _, c := range changes {
			cm := c.(map[string]any)
			added, isMembers := cm["added"].([]any)
			if !isMembers {
				out.fields = append(out.fields, cm["field"].(string))
				continue
			}
			for _, id := range added {
				out.added = append(out.added, id.(string))
			}
			for _, id := range cm["removed"].([]any) {
				out.removed = append(out.removed, id.(string))
			}
		}
		if d, ok := m["delegation"].(map[string]any); ok {
			for _, h := range d["chain"].([]any) {
				out.hops = append(out.hops, h.(map[string]any)["sub"].(string))
			}
		}
	}
	return out
}

func ids(prefix string, n, width int) []string {
	out := make([]string, n)
	for i := range out {
		id := fmt.Sprintf("%s-%06d-", prefix, i)
		out[i] = id + strings.Repeat("x", max(0, width-len(id)))
	}
	return out
}

func TestNewEvent_SplitsListsIntoContinuations(t *testing.T) {
	t.Parallel()

	manyFields := make([]Change, 300)
	fieldNames := make([]string, len(manyFields))
	for i := range manyFields {
		fieldNames[i] = fmt.Sprintf("field_%03d", i)
		manyFields[i] = FieldChange(fieldNames[i], strings.Repeat("b", 150), strings.Repeat("a", 150))
	}
	added, removed := ids("add", 3000, 36), ids("rm", 1200, 36)
	hopSubs := ids("agent", 400, 100)
	hops := make([]DelegatedActor, len(hopSubs))
	for i, s := range hopSubs {
		hops[i] = DelegatedActor{Issuer: testIssuer, Subject: s}
	}

	tests := []struct {
		name        string
		changes     []Change
		chain       *DelegationChain
		wantFields  []string
		wantAdded   []string
		wantRemoved []string
		wantHops    []string
	}{
		{name: "field changes", changes: manyFields, wantFields: fieldNames},
		{
			name:        "membership lists",
			changes:     []Change{MembersChange("members", added, removed)},
			wantAdded:   added,
			wantRemoved: removed,
		},
		{
			name:     "delegation chain",
			chain:    &DelegationChain{Chain: hops, Truncated: true, Omitted: 3},
			wantHops: hopSubs,
		},
		{
			name: "all lists together",
			changes: append(append([]Change{SecretFieldChange("api_key")}, manyFields...),
				MembersChange("members", added, removed)),
			chain:       &DelegationChain{Chain: hops},
			wantFields:  append([]string{"api_key"}, fieldNames...),
			wantAdded:   added,
			wantRemoved: removed,
			wantHops:    hopSubs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			opts := []EventOption{WithCause("caller-cause"), WithReason("bulk_update"), WithChanges(tt.changes...)}
			if tt.chain != nil {
				opts = append(opts, WithDelegation(tt.chain))
			}
			events := mustBuild(userCtx(), t, b, opts...)
			require.Greater(t, len(events), 1)

			lines := render(t, events)
			seen := map[string]bool{}
			for i, line := range lines {
				assert.LessOrEqual(t, len(line), MaxLineBytes, "line %d", i)
				if i < len(lines)-1 {
					assert.Greater(t, len(line), targetLineBytes-1000, "line %d is packed close to the target", i)
				}
				e := events[i]
				assert.False(t, seen[e.Metadata.AuditID], "audit ids are unique")
				seen[e.Metadata.AuditID] = true
				assert.Equal(t, i+1, e.Metadata.Extra[MetadataExtraKeyPart])
				assert.Equal(t, len(events), e.Metadata.Extra[MetadataExtraKeyParts])
				wantCause := events[0].Metadata.AuditID
				if i == 0 {
					wantCause = "caller-cause"
				}
				assert.Equal(t, wantCause, e.Metadata.Extra[MetadataExtraKeyCause], "cause of part %d", i+1)
			}

			got := collectEntries(t, lines)
			assert.Equal(t, tt.wantFields, got.fields)
			assert.Equal(t, tt.wantAdded, got.added)
			assert.Equal(t, tt.wantRemoved, got.removed)
			assert.Equal(t, tt.wantHops, got.hops)
			if tt.chain != nil {
				for _, e := range events {
					if e.DelegationChain != nil {
						assert.Equal(t, tt.chain.Truncated, e.DelegationChain.Truncated)
						assert.Equal(t, tt.chain.Omitted, e.DelegationChain.Omitted)
					}
				}
			}
		})
	}
}

func TestNewEvent_CutOrderAndTruncatedRecord(t *testing.T) {
	t.Parallel()

	bigPayload := `{"body":"` + strings.Repeat("p", 30000) + `"}`
	bigName := strings.Repeat("n", 30000)
	bigValue := strings.Repeat("v", 30000)
	bigID := strings.Repeat("i", 30000)

	tests := []struct {
		name          string
		target        Target
		opts          []EventOption
		wantEvents    int
		wantPayload   string // "" means the payload is unchanged or absent
		wantNameCut   bool
		wantCut       map[string]string // field -> full value
		wantValuesCut bool
	}{
		{
			name:        "payload is cut first and becomes a string of its leading bytes",
			target:      Target{Type: testTargetType, ID: testTargetID, Name: "short"},
			opts:        []EventOption{WithPayload(json.RawMessage(bigPayload))},
			wantEvents:  1,
			wantPayload: payloadPartial,
			wantCut:     map[string]string{"data": bigPayload},
		},
		{
			name:        "target name is cut only after the payload is gone",
			target:      Target{Type: testTargetType, ID: testTargetID, Name: bigName},
			opts:        []EventOption{WithPayload(json.RawMessage(bigPayload))},
			wantEvents:  1,
			wantPayload: payloadEmpty,
			wantNameCut: true,
			wantCut:     map[string]string{"data": bigPayload, "target.name": bigName},
		},
		{
			name:          "a change value over 4 KiB is cut when it cannot fit on its own",
			target:        testTarget,
			opts:          []EventOption{WithChanges(FieldChange("description", "old", bigValue))},
			wantEvents:    1,
			wantCut:       map[string]string{descAfterField: bigValue},
			wantValuesCut: true,
		},
		{
			name:          "a member id over 4 KiB is cut when it cannot fit on its own",
			target:        testTarget,
			opts:          []EventOption{WithChanges(MembersChange("members", []string{bigID}, nil))},
			wantEvents:    1,
			wantCut:       map[string]string{"changes.members.added": bigID},
			wantValuesCut: true,
		},
		{
			name:   "escaped characters are measured in encoded bytes",
			target: testTarget,
			opts: []EventOption{WithChanges(FieldChange("description",
				strings.Repeat("<", 6000), strings.Repeat("\x01", 6000)))},
			wantEvents: 1,
			wantCut: map[string]string{
				"changes.description.before": strings.Repeat("<", 6000),
				descAfterField:               strings.Repeat("\x01", 6000),
			},
			wantValuesCut: true,
		},
		{
			name:          "both values of one change are cut",
			target:        testTarget,
			opts:          []EventOption{WithChanges(FieldChange("description", bigValue, bigValue+"!"))},
			wantEvents:    1,
			wantCut:       map[string]string{"changes.description.before": bigValue, descAfterField: bigValue + "!"},
			wantValuesCut: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			events, err := b.NewEvent(userCtx(), testType, tt.target, OutcomeSuccess, tt.opts...)
			require.NoError(t, err)
			require.Len(t, events, tt.wantEvents)
			for i, line := range render(t, events) {
				assert.LessOrEqual(t, len(line), MaxLineBytes, "line %d", i)
			}

			first := events[0]
			switch tt.wantPayload {
			case payloadPartial:
				var s string
				require.NoError(t, json.Unmarshal(*first.Data, &s), "a cut payload is a JSON string")
				assert.NotEmpty(t, s)
				assert.True(t, strings.HasPrefix(bigPayload, s))
			case payloadEmpty:
				assert.JSONEq(t, `""`, string(*first.Data))
			}
			if tt.wantNameCut {
				name := first.Target[TargetKeyName]
				assert.NotEmpty(t, name)
				assert.Less(t, len(name), len(bigName))
				assert.True(t, strings.HasPrefix(bigName, name))
			} else {
				assert.Equal(t, tt.target.Name, first.Target[TargetKeyName])
			}

			holder := events[0]
			for field, full := range tt.wantCut {
				tr, ok := findTruncation(holder, field)
				require.True(t, ok, "missing record for %s", field)
				assert.Equal(t, len(full), tr.Length)
				assert.Equal(t, digest(full), tr.SHA256)
				assert.False(t, tr.Dropped)
			}
			if tt.wantValuesCut {
				changes := holder.Metadata.Extra[MetadataExtraKeyChanges].([]Change)
				require.Len(t, changes, 1)
				c := changes[0]
				for _, v := range append([]string{c.before, c.after}, c.added...) {
					assert.LessOrEqual(t, encodedLen(v), maxFieldValueBytes)
					if len(v) > 3 {
						assert.Greater(t, encodedLen(v), maxFieldValueBytes-8, "a value is cut to 4 KiB, no further")
					}
				}
			}
		})
	}
}

func TestNewEvent_NeverCutFieldsKept(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuilder(t, WithSubjectEnricher(func(context.Context) map[string]string {
		return map[string]string{testTenantKey: testTenant}
	}))
	ctx := ContextWithActor(context.Background(),
		NewUserActor(testUserID, testIssuer, WithDisplayName("Alice"), WithClientID("cli")))
	ctx = ContextWithRequestID(ctx, "req-77")
	target := Target{Type: testTargetType, ID: testTargetID, Name: strings.Repeat("n", 20000)}
	events, err := b.NewEvent(ctx, testType, target, OutcomeFailure,
		WithReason("conflict"),
		WithCause("caller-cause"),
		WithPayload(json.RawMessage(`"`+strings.Repeat("p", 20000)+`"`)),
		WithChanges(MembersChange("members", ids("m", 2000, 36), nil)),
	)
	require.NoError(t, err)
	require.Greater(t, len(events), 1)

	wantSubjects := map[string]string{
		SubjectKeyPrincipalKind: string(PrincipalKindUser), SubjectKeyUserID: testUserID, SubjectKeyIssuer: testIssuer,
		SubjectKeyUser: "Alice", "client_id": "cli", testTenantKey: testTenant,
	}
	first := events[0]
	for i, e := range events {
		assert.Equal(t, testType, e.Type, "part %d", i+1)
		assert.Equal(t, OutcomeFailure, e.Outcome, "part %d", i+1)
		assert.Equal(t, "conflict", e.Metadata.Extra[MetadataExtraKeyReason], "part %d", i+1)
		assert.Equal(t, "req-77", e.Metadata.Extra[MetadataExtraKeyRequestID], "part %d", i+1)
		assert.Equal(t, wantSubjects, e.Subjects, "part %d", i+1)
		assert.Equal(t, testTargetType, e.Target[TargetKeyType], "part %d", i+1)
		assert.Equal(t, testTargetID, e.Target[TargetKeyID], "part %d", i+1)
		assert.Equal(t, first.LoggedAt, e.LoggedAt, "part %d", i+1)
		if i > 0 {
			assert.NotContains(t, e.Target, TargetKeyName, "continuations carry the target's type and id")
			assert.Nil(t, e.Data, "continuations carry no payload")
		}
	}
	assert.Equal(t, "caller-cause", first.Metadata.Extra[MetadataExtraKeyCause])
	for i, line := range render(t, events) {
		assert.LessOrEqual(t, len(line), MaxLineBytes, "line %d", i)
	}
}

func TestNewEvent_TargetIDCapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
	}{
		{name: "ascii", id: strings.Repeat("i", 300)},
		{name: "multibyte at the boundary", id: strings.Repeat("i", 255) + strings.Repeat("ü", 40)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			target := Target{Type: testTargetType, ID: tt.id}
			events, err := b.NewEvent(userCtx(), testType, target, OutcomeSuccess,
				WithChanges(MembersChange("members", ids("m", 1500, 36), nil)))
			require.NoError(t, err)
			require.Greater(t, len(events), 1, "the cap holds on continuations too")
			for _, e := range events {
				got := e.Target[TargetKeyID]
				assert.LessOrEqual(t, len(got), MaxActorStringBytes)
				assert.True(t, strings.HasPrefix(tt.id, got))
				assert.Greater(t, len(got), MaxActorStringBytes-4)
				tr, ok := findTruncation(e, "target.id")
				require.True(t, ok)
				assert.Equal(t, len(tt.id), tr.Length)
				assert.Equal(t, digest(tt.id), tr.SHA256)
			}
		})
	}
}

func TestNewEvent_DelegationHopStringsCapped(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuilder(t)
	long := strings.Repeat("s", 400)
	chain := &DelegationChain{Chain: []DelegatedActor{{Issuer: testIssuer, Subject: long}}}
	e := mustBuild(userCtx(), t, b, WithDelegation(chain))[0]
	require.Len(t, e.DelegationChain.Chain, 1)
	assert.Len(t, e.DelegationChain.Chain[0].Subject, MaxActorStringBytes)
	tr, ok := findTruncation(e, "delegation.chain[0].sub")
	require.True(t, ok)
	assert.Equal(t, digest(long), tr.SHA256)
	assert.Equal(t, long, chain.Chain[0].Subject, "the caller's chain is not modified")
}

func TestNewEvent_OversizedHeadWithoutListsIsBestEffort(t *testing.T) {
	t.Parallel()

	// A type the builder never cuts can exceed the limit on its own; the
	// builder still returns one event rather than failing the action.
	b, _ := newTestBuilder(t)
	events, err := b.NewEvent(userCtx(), strings.Repeat("t", 20000), testTarget, OutcomeSuccess)
	require.NoError(t, err)
	require.Len(t, events, 1)
}

func TestCapString(t *testing.T) {
	t.Parallel()

	const abc = "abc"

	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "short", in: abc, n: 5, want: abc},
		{name: "exact", in: abc, n: 3, want: abc},
		{name: "cut", in: "abcdef", n: 3, want: abc},
		{name: "rune boundary", in: "aé", n: 2, want: "a"},
		{name: "negative", in: abc, n: -1, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, capString(tt.in, tt.n))
		})
	}
}

func TestNewEvent_OversizedNeverCutFieldsDoNotMultiplyEvents(t *testing.T) {
	t.Parallel()

	t.Run("never-cut fields over the target", func(t *testing.T) {
		t.Parallel()
		b, _ := newTestBuilder(t)
		events, err := b.NewEvent(userCtx(), strings.Repeat("t", 17000), testTarget, OutcomeSuccess,
			WithChanges(MembersChange("members", ids("m", 200, 36), nil)))
		require.NoError(t, err)
		require.Len(t, events, 1, "splitting cannot help, so one best-effort event is returned")
		got := collectEntries(t, render(t, events))
		assert.Len(t, got.added, 200, "no list entry is lost")
		assert.Equal(t, testTarget.Name, events[0].Target[TargetKeyName], "a futile cut leaves the target name")
		assert.NotContains(t, events[0].Metadata.Extra, MetadataExtraKeyTruncated)
	})

	// Never-cut fields in the band just under the target: an empty
	// continuation fits, but no continuation can hold an entry.
	for _, size := range []int{15000, 15350, 15450, 15700} {
		t.Run(fmt.Sprintf("event type of %d bytes", size), func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			events, err := b.NewEvent(userCtx(), strings.Repeat("t", size), testTarget, OutcomeSuccess,
				WithChanges(MembersChange("members", ids("m", 200, 36), nil)))
			require.NoError(t, err)
			assert.LessOrEqual(t, len(events), 200/2, "events are not multiplied per entry")
			got := collectEntries(t, render(t, events))
			assert.Len(t, got.added, 200)
			for _, id := range got.added {
				assert.Len(t, id, 36, "no member id is cut")
			}
		})
	}
}

func TestNewEvent_DropRecordsBounded(t *testing.T) {
	t.Parallel()

	keys := func(n int) map[string]string {
		m := make(map[string]string, n)
		for i := 0; i < n; i++ {
			m[fmt.Sprintf("k%04d", i)] = "v"
		}
		return m
	}
	anyKeys := func(n int) map[string]any {
		m := make(map[string]any, n)
		for k, v := range keys(n) {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name    string
		builder []BuilderOption
		opts    []EventOption
		prefix  string
	}{
		{
			name:    "enricher",
			builder: []BuilderOption{WithSubjectEnricher(func(context.Context) map[string]string { return keys(500) })},
			prefix:  "subjects",
		},
		{name: "component extra", opts: []EventOption{WithExtra(anyKeys(500))}, prefix: "metadata.extra"},
		{
			name:   "source extra",
			opts:   []EventOption{WithSource(EventSource{Type: SourceTypeLocal, Extra: anyKeys(500)})},
			prefix: "source.extra",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t, tt.builder...)
			events := mustBuild(userCtx(), t, b, append(tt.opts,
				WithChanges(MembersChange("members", ids("m", 2, 36), nil)))...)
			require.Len(t, events, 1)
			line := render(t, events)[0]
			assert.LessOrEqual(t, len(line), MaxLineBytes)

			var individual int
			var summary *truncation
			for _, tr := range truncations(events[0]) {
				if tr.Field == tt.prefix {
					summary = &tr
				} else if strings.HasPrefix(tr.Field, tt.prefix+".") && tr.Dropped {
					individual++
				}
			}
			assert.Equal(t, maxDropRecords, individual)
			require.NotNil(t, summary)
			assert.True(t, summary.Dropped)
			assert.Equal(t, 500-maxExtraKeys-maxDropRecords, summary.Count)
			var rest []string
			for i := maxExtraKeys + maxDropRecords; i < 500; i++ {
				rest = append(rest, fmt.Sprintf("k%04d", i))
			}
			assert.Equal(t, digest(strings.Join(rest, "\n")), summary.SHA256)
		})
	}
}

func TestNewEvent_CallerStringsCapped(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("f", 20000)
	b, _ := newTestBuilder(t)
	events := mustBuild(userCtx(), t, b,
		WithSource(EventSource{Type: SourceTypeNetwork, Value: long}),
		WithChanges(SecretFieldChange(long), MembersChange(long, []string{"m-1"}, nil)))
	require.Len(t, events, 1)
	e := events[0]
	assert.Len(t, e.Source.Value, MaxActorStringBytes)
	for _, c := range e.Metadata.Extra[MetadataExtraKeyChanges].([]Change) {
		assert.Len(t, c.field, MaxActorStringBytes)
	}
	tr, ok := findTruncation(e, "source.value")
	require.True(t, ok)
	assert.Equal(t, digest(long), tr.SHA256)
	var fieldRecords int
	for _, tr := range truncations(e) {
		if tr.Field == "changes.field" {
			fieldRecords++
		}
	}
	assert.Equal(t, 2, fieldRecords)
	assert.LessOrEqual(t, len(render(t, events)[0]), MaxLineBytes)
}

func TestCapEncoded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{name: "plain", in: "xyzw", n: 3, want: "xyz"},
		{name: "fits", in: "xy", n: 2, want: "xy"},
		{name: "escaped quote", in: `a"b`, n: 2, want: "a"},
		{name: "html escaped", in: "<<", n: 6, want: "<"},
		{name: "control character", in: "\x01a", n: 5, want: ""},
		{name: "newline", in: "\na", n: 3, want: "\na"},
		{name: "multibyte", in: "éé", n: 3, want: "é"},
		{name: "invalid byte", in: "\xffa", n: 6, want: "\xff"},
		{name: "line separator", in: "\u2028", n: 3, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, capEncoded(tt.in, tt.n))
		})
	}
}
