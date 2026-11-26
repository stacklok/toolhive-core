// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const (
	testComponent  = "example-service"
	testType       = "widgets.widget.update"
	testIssuer     = "https://issuer.example.com"
	testUserID     = "u-1"
	testTargetID   = "w-1"
	testTenant     = "t-1"
	testSCIMIssuer = "scim-1"
	testTargetType = "widget"
	testTenantKey  = "tenant"
	keyNote        = "note"
	keyTags        = "tags"
	valueFast      = "fast"
	keyMode        = "mode"
)

var testTarget = Target{Type: testTargetType, ID: testTargetID, Name: "Blue widget"}

// newTestBuilder returns a builder with a manual metric reader, and a function
// that reads the error counter by reason.
func newTestBuilder(t *testing.T, opts ...BuilderOption) (*EventBuilder, func() map[string]int64) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	opts = append([]BuilderOption{WithBuilderMeterProvider(mp), WithSourceName("example-pod")}, opts...)
	b := NewEventBuilder(testComponent, opts...)
	return b, func() map[string]int64 {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		out := map[string]int64{}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != EventErrorsMetricName {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					reason, _ := dp.Attributes.Value("reason")
					out[reason.AsString()] += dp.Value
				}
			}
		}
		return out
	}
}

func userCtx() context.Context {
	ctx := ContextWithActor(context.Background(), NewUserActor("u-123", testIssuer))
	return ContextWithRequestID(ctx, "req-1")
}

// render logs events through the audit handler middleware and returns each
// line, newline included.
func render(t *testing.T, events []*AuditEvent) [][]byte {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(HandlerMiddleware(WithWriter(&buf))(slog.NewTextHandler(io.Discard, nil)))
	for _, e := range events {
		e.LogTo(context.Background(), logger, LevelAudit)
	}
	lines := bytes.SplitAfter(buf.Bytes(), []byte("\n"))
	require.Empty(t, lines[len(lines)-1])
	lines = lines[:len(lines)-1]
	require.Len(t, lines, len(events))
	return lines
}

func decode(t *testing.T, line []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(line, &m))
	return m
}

func mustBuild(ctx context.Context, t *testing.T, b *EventBuilder, opts ...EventOption) []*AuditEvent {
	t.Helper()
	events, err := b.NewEvent(ctx, testType, testTarget, OutcomeSuccess, opts...)
	require.NoError(t, err)
	require.NotEmpty(t, events)
	return events
}

func truncations(e *AuditEvent) []truncation {
	tr, _ := e.Metadata.Extra[MetadataExtraKeyTruncated].([]truncation)
	return tr
}

func findTruncation(e *AuditEvent, field string) (truncation, bool) {
	for _, tr := range truncations(e) {
		if tr.Field == field {
			return tr, true
		}
	}
	return truncation{}, false
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestNewEvent_SubjectsPerPrincipalKind(t *testing.T) {
	t.Parallel()

	optional := []ActorOption{
		WithDisplayName("Alice"),
		WithClientID("cli"),
		WithClientInfo("example-client", "1.2.3"),
	}
	tests := []struct {
		name  string
		actor Actor
		want  map[string]string
	}{
		{
			name:  "user",
			actor: NewUserActor(testUserID, testIssuer),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindUser), SubjectKeyUserID: testUserID, SubjectKeyIssuer: testIssuer},
		},
		{
			name:  "service account",
			actor: NewServiceAccountActor("sa-1"),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindServiceAccount), SubjectKeyUserID: "sa-1"},
		},
		{
			name:  "scim issuer",
			actor: NewSCIMIssuerActor(testSCIMIssuer, "fp-abc"),
			want: map[string]string{
				SubjectKeyPrincipalKind: string(PrincipalKindSCIMIssuer), SubjectKeyUserID: testSCIMIssuer, SubjectKeyIssuer: testSCIMIssuer, "token_fingerprint": "fp-abc",
			},
		},
		{
			name:  "system",
			actor: NewSystemActor("jobs.cleanup"),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindSystem), SubjectKeyUserID: "jobs.cleanup"},
		},
		{
			name:  "anonymous",
			actor: NewAnonymousActor(),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindAnonymous)},
		},
		{
			name:  "anonymous keeps what the caller presented",
			actor: NewAnonymousActor(WithActorIssuer(testSCIMIssuer), WithTokenFingerprint("fp-x")),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindAnonymous), SubjectKeyIssuer: testSCIMIssuer, "token_fingerprint": "fp-x"},
		},
		{
			name:  "user with every optional field",
			actor: NewUserActor(testUserID, testIssuer, optional...),
			want: map[string]string{
				SubjectKeyPrincipalKind: string(PrincipalKindUser), SubjectKeyUserID: testUserID, SubjectKeyIssuer: testIssuer, SubjectKeyUser: "Alice",
				"client_id": "cli", "client_name": "example-client", "client_version": "1.2.3",
			},
		},
		{
			name:  "service account with issuer option",
			actor: NewServiceAccountActor("sa-1", WithActorIssuer(testIssuer)),
			want:  map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindServiceAccount), SubjectKeyUserID: "sa-1", SubjectKeyIssuer: testIssuer},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			ctx := ContextWithActor(context.Background(), tt.actor)
			outcome := OutcomeSuccess
			if tt.actor.Kind() == PrincipalKindAnonymous {
				outcome = OutcomeDenied
			}
			events, err := b.NewEvent(ctx, testType, testTarget, outcome)
			require.NoError(t, err)
			require.Len(t, events, 1)
			assert.Equal(t, tt.want, events[0].Subjects)

			line := decode(t, render(t, events)[0])
			assert.Equal(t, len(tt.want), len(line["subjects"].(map[string]any)))
		})
	}
}

func TestNewEvent_NoActorIsErrorAndCounted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no actor", ctx: context.Background()},
		{name: "zero actor", ctx: ContextWithActor(context.Background(), Actor{})},
		{name: "user without id", ctx: ContextWithActor(context.Background(), NewUserActor("", testIssuer))},
		{name: "system without name", ctx: ContextWithActor(context.Background(), NewSystemActor(""))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, counts := newTestBuilder(t)
			events, err := b.NewEvent(tt.ctx, testType, testTarget, OutcomeSuccess)
			require.ErrorIs(t, err, ErrNoActor)
			assert.Nil(t, events)
			assert.Equal(t, map[string]int64{eventErrorNoActor: 1}, counts())
		})
	}
}

func TestNewEvent_AnonymousOnlyDenied(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome string
		wantErr bool
	}{
		{outcome: OutcomeDenied},
		{outcome: OutcomeError},
		{outcome: OutcomeSuccess, wantErr: true},
		{outcome: OutcomeFailure, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			t.Parallel()
			b, counts := newTestBuilder(t)
			ctx := ContextWithActor(context.Background(), NewAnonymousActor())
			events, err := b.NewEvent(ctx, "auth.token.verify", testTarget, tt.outcome, WithReason("invalid_token"))
			if !tt.wantErr {
				require.NoError(t, err)
				require.Len(t, events, 1)
				assert.Empty(t, counts())
				return
			}
			require.ErrorIs(t, err, ErrAnonymousOutcome)
			assert.Nil(t, events)
			assert.Equal(t, map[string]int64{eventErrorAnonymousInvalidOutcome: 1}, counts())
		})
	}
}

func TestNewEvent_EnricherNeverSetsContractKeys(t *testing.T) {
	t.Parallel()

	enricher := func(context.Context) map[string]string {
		m := map[string]string{testTenantKey: testTenant, "": "empty key"}
		for k := range contractSubjectKeys {
			m[k] = "from-enricher"
		}
		return m
	}
	tests := []struct {
		name    string
		actor   Actor
		outcome string
		want    map[string]string
	}{
		{
			name:    "user keeps its own keys",
			actor:   NewUserActor(testUserID, testIssuer),
			outcome: OutcomeSuccess,
			want:    map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindUser), SubjectKeyUserID: testUserID, SubjectKeyIssuer: testIssuer, testTenantKey: testTenant},
		},
		{
			name:    "anonymous gets no user_id",
			actor:   NewAnonymousActor(),
			outcome: OutcomeDenied,
			want:    map[string]string{SubjectKeyPrincipalKind: string(PrincipalKindAnonymous), testTenantKey: testTenant},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t, WithSubjectEnricher(enricher))
			ctx := ContextWithActor(context.Background(), tt.actor)
			events, err := b.NewEvent(ctx, testType, testTarget, tt.outcome)
			require.NoError(t, err)
			assert.Equal(t, tt.want, events[0].Subjects)
		})
	}
}

func TestNewEvent_EnricherOutputBounded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("v", 300)
	longKey := strings.Repeat("k", 300)
	tests := []struct {
		name        string
		enriched    map[string]string
		wantKept    []string
		wantCount   int
		wantDropped []string
		wantCut     []string
	}{
		{
			name: "keys past the first 16 in sorted order are dropped",
			enriched: func() map[string]string {
				m := map[string]string{}
				for i := 0; i < 20; i++ {
					m[fmt.Sprintf("key%02d", i)] = "v"
				}
				return m
			}(),
			wantKept:    []string{"key00", "key15"},
			wantCount:   3 + 16,
			wantDropped: []string{"subjects.key16", "subjects.key17", "subjects.key18", "subjects.key19"},
		},
		{
			name:      "long values are cut",
			enriched:  map[string]string{keyNote: long},
			wantKept:  []string{keyNote},
			wantCount: 3 + 1,
			wantCut:   []string{"subjects.note"},
		},
		{
			name:        "overlong keys are dropped",
			enriched:    map[string]string{longKey: "v", "ok": "v"},
			wantKept:    []string{"ok"},
			wantCount:   3 + 1,
			wantDropped: []string{"subjects." + strings.Repeat("k", maxExtraKeyBytes)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t, WithSubjectEnricher(func(context.Context) map[string]string { return tt.enriched }))
			e := mustBuild(userCtx(), t, b)[0]
			for _, k := range tt.wantKept {
				assert.Contains(t, e.Subjects, k)
				assert.LessOrEqual(t, len(e.Subjects[k]), MaxActorStringBytes)
			}
			assert.Len(t, e.Subjects, tt.wantCount)
			for _, f := range tt.wantDropped {
				tr, ok := findTruncation(e, f)
				require.True(t, ok, "missing drop record for %s", f)
				assert.True(t, tr.Dropped)
			}
			for _, f := range tt.wantCut {
				tr, ok := findTruncation(e, f)
				require.True(t, ok, "missing cut record for %s", f)
				assert.False(t, tr.Dropped)
				assert.Equal(t, len(long), tr.Length)
				assert.Equal(t, digest(long), tr.SHA256)
			}
		})
	}
}

func TestNewEvent_ActorStringCapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "ascii", value: strings.Repeat("a", 400)},
		{name: "multibyte rune at the boundary", value: strings.Repeat("a", 255) + strings.Repeat("é", 50)},
		{name: "four byte runes", value: strings.Repeat("😀", 100)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			ctx := ContextWithActor(context.Background(), NewUserActor(tt.value, testIssuer, WithDisplayName(tt.value)))
			ctx = ContextWithRequestID(ctx, "req-1")
			e := mustBuild(ctx, t, b)[0]
			for _, key := range []string{SubjectKeyUserID, SubjectKeyUser} {
				got := e.Subjects[key]
				assert.LessOrEqual(t, len(got), MaxActorStringBytes)
				assert.True(t, strings.HasPrefix(tt.value, got))
				assert.True(t, utf8.ValidString(got), "cut is not at a rune boundary")
				tr, ok := findTruncation(e, "subjects."+key)
				require.True(t, ok)
				assert.Equal(t, len(tt.value), tr.Length)
				assert.Equal(t, digest(tt.value), tr.SHA256)
			}
			_, ok := findTruncation(e, "subjects.issuer")
			assert.False(t, ok, "short values are not recorded")
		})
	}
}

func TestNewEvent_RejectsUnboundedOutcomeAndReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		outcome    string
		reason     string
		wantErr    error
		wantReason string
	}{
		{name: "unknown outcome", outcome: "unknown", wantErr: ErrInvalidOutcome, wantReason: eventErrorInvalidOutcome},
		{name: "empty outcome", outcome: "", wantErr: ErrInvalidOutcome, wantReason: eventErrorInvalidOutcome},
		{name: "capitalised outcome", outcome: "Success", wantErr: ErrInvalidOutcome, wantReason: eventErrorInvalidOutcome},
		{name: "free text reason", outcome: OutcomeFailure, reason: "row not found", wantErr: ErrInvalidReason,
			wantReason: eventErrorInvalidReason},
		{name: "camel case reason", outcome: OutcomeFailure, reason: "notFound", wantErr: ErrInvalidReason,
			wantReason: eventErrorInvalidReason},
		{name: "trailing underscore", outcome: OutcomeFailure, reason: "not_", wantErr: ErrInvalidReason,
			wantReason: eventErrorInvalidReason},
		{name: "reason over 64 bytes", outcome: OutcomeFailure, reason: strings.Repeat("a", 65), wantErr: ErrInvalidReason,
			wantReason: eventErrorInvalidReason},
		{name: "reason of 64 bytes", outcome: OutcomeFailure, reason: strings.Repeat("a", 64)},
		{name: "snake case reason", outcome: OutcomeFailure, reason: "not_found"},
		{name: "reason with digits", outcome: OutcomeError, reason: "http_503"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, counts := newTestBuilder(t)
			events, err := b.NewEvent(userCtx(), testType, testTarget, tt.outcome, WithReason(tt.reason))
			if tt.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tt.reason, events[0].Metadata.Extra[MetadataExtraKeyReason])
				assert.Empty(t, counts())
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			assert.Nil(t, events)
			assert.Equal(t, map[string]int64{tt.wantReason: 1}, counts())
		})
	}
}

func TestNewEvent_ComponentExtraBounded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 300)
	tests := []struct {
		name        string
		extra       map[string]any
		want        map[string]any
		wantDropped []string
		wantCut     []string
	}{
		{
			name:  "scalar values kept",
			extra: map[string]any{MetadataExtraKeyDuration: 12, "cached": true, keyMode: valueFast, "nothing": nil},
			want:  map[string]any{MetadataExtraKeyDuration: 12, "cached": true, keyMode: valueFast, "nothing": nil},
		},
		{
			name: "reserved keys dropped",
			extra: map[string]any{
				"reason": "x", "request_id": "spoofed", "cause": "c", "changes": "c", "truncated": "t",
				"part": 9, "parts": 9, "schema_version": 2, "suppressed": 5, keyMode: valueFast,
			},
			want: map[string]any{keyMode: valueFast},
		},
		{
			name:    "long string cut",
			extra:   map[string]any{keyNote: long},
			want:    map[string]any{keyNote: long[:MaxActorStringBytes]},
			wantCut: []string{"metadata.extra.note"},
		},
		{
			name:  "small composite kept",
			extra: map[string]any{keyTags: []string{"a", "b"}},
			want:  map[string]any{keyTags: []string{"a", "b"}},
		},
		{
			name:    "large composite replaced by its cut encoding",
			extra:   map[string]any{keyTags: []string{long}},
			want:    map[string]any{keyTags: `["` + long[:MaxActorStringBytes-2]},
			wantCut: []string{"metadata.extra.tags"},
		},
		{
			name:        "unencodable value dropped",
			extra:       map[string]any{"fn": func() {}, keyMode: valueFast},
			want:        map[string]any{keyMode: valueFast},
			wantDropped: []string{"metadata.extra.fn"},
		},
		{
			name: "keys past the first 16 dropped",
			extra: func() map[string]any {
				m := map[string]any{}
				for i := 0; i < 18; i++ {
					m[fmt.Sprintf("k%02d", i)] = i
				}
				return m
			}(),
			want: func() map[string]any {
				m := map[string]any{}
				for i := 0; i < 16; i++ {
					m[fmt.Sprintf("k%02d", i)] = i
				}
				return m
			}(),
			wantDropped: []string{"metadata.extra.k16", "metadata.extra.k17"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			e := mustBuild(userCtx(), t, b, WithExtra(tt.extra))[0]
			for k, v := range tt.want {
				assert.Equal(t, v, e.Metadata.Extra[k], k)
			}
			for k := range tt.extra {
				if _, kept := tt.want[k]; !kept {
					if _, reserved := reservedExtraKeys[k]; reserved {
						assert.NotEqual(t, tt.extra[k], e.Metadata.Extra[k], k)
					} else {
						assert.NotContains(t, e.Metadata.Extra, k)
					}
				}
			}
			assert.Equal(t, "req-1", e.Metadata.Extra[MetadataExtraKeyRequestID])
			for _, f := range tt.wantDropped {
				tr, ok := findTruncation(e, f)
				require.True(t, ok, f)
				assert.True(t, tr.Dropped)
			}
			for _, f := range tt.wantCut {
				tr, ok := findTruncation(e, f)
				require.True(t, ok, f)
				assert.False(t, tr.Dropped)
			}
			render(t, []*AuditEvent{e})
		})
	}
}

func TestNewEvent_EnvelopeFields(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuilder(t)
	before := time.Now()
	first := mustBuild(userCtx(), t, b)[0]
	second := mustBuild(userCtx(), t, b)[0]

	for _, e := range []*AuditEvent{first, second} {
		assert.Equal(t, SchemaVersion, e.Metadata.Extra[MetadataExtraKeySchemaVersion])
		_, err := uuid.Parse(e.Metadata.AuditID)
		require.NoError(t, err)
		assert.Equal(t, time.UTC, e.LoggedAt.Location())
		assert.False(t, e.LoggedAt.Before(before.Add(-time.Second)))
		assert.Equal(t, testComponent, e.Component)
		assert.Equal(t, testType, e.Type)
		assert.Equal(t, OutcomeSuccess, e.Outcome)
		assert.Equal(t, EventSource{Type: SourceTypeLocal, Value: "example-pod"}, e.Source)
		assert.Equal(t, map[string]string{"type": testTargetType, "id": testTargetID, "name": "Blue widget"}, e.Target)
		assert.NotContains(t, e.Metadata.Extra, MetadataExtraKeyPart)
	}
	assert.NotEqual(t, first.Metadata.AuditID, second.Metadata.AuditID)

	line := decode(t, render(t, []*AuditEvent{first})[0])
	extra := line["metadata"].(map[string]any)["extra"].(map[string]any)
	assert.Equal(t, float64(1), extra["schema_version"])
	assert.Equal(t, "1", string(mustJSON(t, extra["schema_version"])), "schema_version is an integer")
	assert.True(t, strings.HasSuffix(line["logged_at"].(string), "Z"), "loggedAt is UTC")
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func TestNewEvent_RequestIDFromContext(t *testing.T) {
	t.Parallel()

	actorCtx := ContextWithActor(context.Background(), NewUserActor(testUserID, testIssuer))
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{name: "with request id", ctx: ContextWithRequestID(actorCtx, "req-42"), want: "req-42"},
		{name: "without request id", ctx: actorCtx},
		{name: "empty request id", ctx: ContextWithRequestID(actorCtx, "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			e := mustBuild(tt.ctx, t, b)[0]
			line := decode(t, render(t, []*AuditEvent{e})[0])
			extra := line["metadata"].(map[string]any)["extra"].(map[string]any)
			if tt.want == "" {
				assert.NotContains(t, extra, "request_id")
				return
			}
			assert.Equal(t, tt.want, extra["request_id"])
		})
	}
}

func TestNewEvent_OptionalInputs(t *testing.T) {
	t.Parallel()

	b, _ := newTestBuilder(t)
	chain := &DelegationChain{Chain: []DelegatedActor{{Issuer: testIssuer, Subject: "agent"}}}
	source := EventSource{Type: SourceTypeNetwork, Value: testSourceIP}
	events := mustBuild(userCtx(), t, b,
		WithCause("cause-id"),
		WithDelegation(chain),
		WithPayload(json.RawMessage(`{"a":1}`)),
		WithSource(source),
		WithExtra(map[string]any{"a": 1}),
		WithExtra(map[string]any{"b": 2}),
		WithChanges(FieldChange("color", "blue", "red")),
		WithChanges(SecretFieldChange("api_key")),
	)
	require.Len(t, events, 1)
	e := events[0]
	assert.Equal(t, "cause-id", e.Metadata.Extra[MetadataExtraKeyCause])
	assert.Equal(t, chain.Chain, e.DelegationChain.Chain)
	assert.JSONEq(t, `{"a":1}`, string(*e.Data))
	assert.Equal(t, source, e.Source)
	assert.Equal(t, 1, e.Metadata.Extra["a"])
	assert.Equal(t, 2, e.Metadata.Extra["b"])
	assert.Len(t, e.Metadata.Extra[MetadataExtraKeyChanges], 2)
	assert.NotContains(t, e.Metadata.Extra, MetadataExtraKeyTruncated)
}

func TestNewEventBuilder_Defaults(t *testing.T) {
	t.Parallel()

	b := NewEventBuilder(testComponent, WithBuilderMeterProvider(nil))
	assert.Equal(t, SourceTypeLocal, b.source.Type)
	assert.NotNil(t, b.errors)
	_, err := b.NewEvent(context.Background(), testType, testTarget, OutcomeSuccess)
	require.ErrorIs(t, err, ErrNoActor)
}

func TestIsValidOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		outcome string
		want    bool
	}{
		{OutcomeSuccess, true}, {OutcomeFailure, true}, {OutcomeError, true}, {OutcomeDenied, true},
		{"unknown", false}, {"", false},
	}
	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsValidOutcome(tt.outcome))
		})
	}
}
