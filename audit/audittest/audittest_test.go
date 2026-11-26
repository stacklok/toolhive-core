// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audittest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/audit"
	"github.com/stacklok/toolhive-core/audit/audittest"
)

// conformingLine builds a conforming event with the builder and returns the
// line the audit handler middleware writes for it.
func conformingLine(t *testing.T) []byte {
	t.Helper()
	ctx := audit.ContextWithActor(context.Background(), audit.NewUserActor("u-1", "https://issuer.example.com"))
	ctx = audit.ContextWithRequestID(ctx, "req-1")
	return logged(ctx, t, "widgets.widget.update", audit.OutcomeSuccess)
}

func logged(ctx context.Context, t *testing.T, eventType, outcome string, opts ...audit.EventOption) []byte {
	t.Helper()
	b := audit.NewEventBuilder("example-service")
	events, err := b.NewEvent(ctx, eventType, audit.Target{Type: "widget", ID: "w-1"}, outcome, opts...)
	require.NoError(t, err)
	var buf bytes.Buffer
	logger := slog.New(audit.HandlerMiddleware(audit.WithWriter(&buf))(slog.NewTextHandler(io.Discard, nil)))
	for _, e := range events {
		e.LogTo(ctx, logger, audit.LevelAudit)
	}
	return buf.Bytes()
}

// mutate decodes line, applies fn to the decoded object and re-encodes it.
func mutate(t *testing.T, line []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(line, &m))
	fn(m)
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return append(out, '\n')
}

func extra(m map[string]any) map[string]any {
	return m["metadata"].(map[string]any)["extra"].(map[string]any)
}

func subjects(m map[string]any) map[string]any {
	return m["subjects"].(map[string]any)
}

func checks(err error) []string {
	var out []string
	var walk func(error)
	walk = func(err error) {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, e := range joined.Unwrap() {
				walk(e)
			}
			return
		}
		var v audittest.Violation
		if errors.As(err, &v) {
			out = append(out, v.Check)
		}
	}
	if err != nil {
		walk(err)
	}
	return out
}

func TestConformance_EachRule(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-token-value"
	// JSON escapes the quote and Go's encoder the angle bracket, so this
	// secret never appears verbatim in the raw line.
	const escaped = `pa"ss<word`
	base := conformingLine(t)
	checker := audittest.NewChecker(
		audittest.WithLegacyTypes("widget_update"),
		audittest.WithSecrets(secret, escaped, ""),
	)

	tests := []struct {
		name string
		line []byte
		want string // "" means the line conforms
	}{
		{name: "conforming event", line: base},
		{name: "legacy type", line: mutate(t, base, func(m map[string]any) { m["type"] = "widget_update" })},
		{name: "not json", line: []byte("{not json\n"), want: audittest.CheckJSON},
		{name: "message", line: mutate(t, base, func(m map[string]any) { m["msg"] = "widget updated" }),
			want: audittest.CheckMessage},
		{name: "level", line: mutate(t, base, func(m map[string]any) { m["level"] = "INFO+2" }),
			want: audittest.CheckLevel},
		{name: "logger", line: mutate(t, base, func(m map[string]any) { delete(m, "logger") }),
			want: audittest.CheckLogger},
		{name: "type with two segments", line: mutate(t, base, func(m map[string]any) { m["type"] = "widget.update" }),
			want: audittest.CheckType},
		{name: "type not snake case", line: mutate(t, base, func(m map[string]any) { m["type"] = "widgets.Widget.update" }),
			want: audittest.CheckType},
		{name: "outcome", line: mutate(t, base, func(m map[string]any) { m["outcome"] = "unknown" }),
			want: audittest.CheckOutcome},
		{name: "reason", line: mutate(t, base, func(m map[string]any) { extra(m)["reason"] = "Row not found" }),
			want: audittest.CheckReason},
		{name: "schema version", line: mutate(t, base, func(m map[string]any) { extra(m)["schema_version"] = 2 }),
			want: audittest.CheckSchemaVersion},
		{name: "size", line: mutate(t, base, func(m map[string]any) {
			m["target"].(map[string]any)["name"] = strings.Repeat("n", audit.MaxLineBytes)
		}), want: audittest.CheckSize},
		{name: "actor string length", line: mutate(t, base, func(m map[string]any) {
			subjects(m)["user"] = strings.Repeat("a", audit.MaxActorStringBytes+1)
		}), want: audittest.CheckActorLength},
		{name: "request id", line: mutate(t, base, func(m map[string]any) { delete(extra(m), "request_id") }),
			want: audittest.CheckRequestID},
		{name: "principal kind missing", line: mutate(t, base, func(m map[string]any) {
			delete(subjects(m), "principal_kind")
		}), want: audittest.CheckPrincipalKind},
		{name: "principal kind unknown", line: mutate(t, base, func(m map[string]any) {
			subjects(m)["principal_kind"] = "robot"
		}), want: audittest.CheckPrincipalKind},
		{name: "user id missing", line: mutate(t, base, func(m map[string]any) { delete(subjects(m), "user_id") }),
			want: audittest.CheckUserID},
		{name: "anonymous with user id", line: mutate(t, base, func(m map[string]any) {
			subjects(m)["principal_kind"] = "anonymous"
			m["outcome"] = "denied"
		}), want: audittest.CheckUserID},
		{name: "anonymous outcome", line: mutate(t, base, func(m map[string]any) {
			subjects(m)["principal_kind"] = "anonymous"
			delete(subjects(m), "user_id")
		}), want: audittest.CheckAnonymousOutcome},
		{name: "secret in a value", line: mutate(t, base, func(m map[string]any) {
			m["target"].(map[string]any)["name"] = "token=" + secret
		}), want: audittest.CheckSecret},
		{name: "secret hidden by escaping", line: mutate(t, base, func(m map[string]any) {
			extra(m)["note"] = "x " + escaped + " y"
		}), want: audittest.CheckSecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := checker.CheckLine(tt.line)
			if tt.want == "" {
				require.NoError(t, err)
				assert.Empty(t, checker.Violations(tt.line))
				return
			}
			require.Error(t, err)
			assert.Equal(t, []string{tt.want}, checks(err), "the line breaks only %s", tt.want)
			assert.Contains(t, err.Error(), `"`+tt.want+`"`, "the message names the check")
			if tt.want == audittest.CheckSecret {
				assert.NotContains(t, err.Error(), secret, "the message does not print the secret")
				assert.NotContains(t, err.Error(), escaped, "the message does not print the secret")
			}
		})
	}
}

func TestConformance_RequestIDRequiredForRequestScoped(t *testing.T) {
	t.Parallel()

	checker := audittest.NewChecker()
	userCtx := audit.ContextWithActor(context.Background(), audit.NewUserActor("u-1", "iss"))
	anonCtx := audit.ContextWithActor(context.Background(), audit.NewAnonymousActor())
	systemCtx := audit.ContextWithActor(context.Background(), audit.NewSystemActor("jobs.cleanup"))

	tests := []struct {
		name string
		line []byte
		want []string
	}{
		{name: "user event without request id", line: logged(userCtx, t, "widgets.widget.update", audit.OutcomeSuccess),
			want: []string{audittest.CheckRequestID}},
		{name: "anonymous event without request id",
			line: logged(anonCtx, t, "auth.token.verify", audit.OutcomeDenied),
			want: []string{audittest.CheckRequestID}},
		{name: "user event with request id",
			line: logged(audit.ContextWithRequestID(userCtx, "req-1"), t, "widgets.widget.update", audit.OutcomeSuccess)},
		{name: "system event without request id", line: logged(systemCtx, t, "jobs.cleanup.run", audit.OutcomeSuccess)},
		{name: "refusal summary without request id",
			line: mutate(t, logged(anonCtx, t, "auth.token.verify", audit.OutcomeDenied), func(m map[string]any) {
				extra(m)["suppressed"] = 41
			})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, checks(checker.CheckLine(tt.line)))
		})
	}
}

func TestConformance_RejectsForeignKeys(t *testing.T) {
	t.Parallel()

	checker := audittest.NewChecker()
	base := conformingLine(t)
	tests := []struct {
		name string
		key  string
	}{
		{name: "trace id from another handler", key: "trace_id"},
		{name: "logger context attribute", key: "service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			line := mutate(t, base, func(m map[string]any) { m[tt.key] = "x" })
			err := checker.CheckLine(line)
			assert.Equal(t, []string{audittest.CheckEnvelopeKeys}, checks(err))
			assert.Contains(t, err.Error(), tt.key)
		})
	}
}

func TestConformance_BuilderOutputConforms(t *testing.T) {
	t.Parallel()

	ctx := audit.ContextWithActor(context.Background(),
		audit.NewSCIMIssuerActor("scim-1", "fp", audit.WithDisplayName(strings.Repeat("d", 400))))
	ctx = audit.ContextWithRequestID(ctx, "req-1")
	added := make([]string, 3000)
	for i := range added {
		added[i] = strings.Repeat("m", 30) + string(rune('a'+i%26))
	}
	const secret = "the-old-bearer-token"
	out := logged(ctx, t, "provisioning.user.update", audit.OutcomeSuccess,
		audit.WithChanges(audit.SecretFieldChange("token"), audit.MembersChange("groups", added, nil)),
		audit.WithPayload(json.RawMessage(`"`+strings.Repeat("p", 20000)+`"`)),
	)
	require.Greater(t, bytes.Count(out, []byte("\n")), 1, "the output has continuation events")

	checker := audittest.NewChecker(audittest.WithSecrets(secret))
	require.NoError(t, checker.CheckOutput(out))
	checker.AssertConforms(t, out)
}

func TestConformance_OutputErrors(t *testing.T) {
	t.Parallel()

	checker := audittest.NewChecker()
	good := conformingLine(t)
	bad := mutate(t, good, func(m map[string]any) { m["outcome"] = "maybe" })

	err := checker.CheckOutput(append(append([]byte{}, good...), bad...))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit line 2")
	assert.Equal(t, []string{audittest.CheckOutcome}, checks(err))

	rec := &recorder{}
	checker.AssertConforms(rec, bad)
	assert.Len(t, rec.errors, 1)
	assert.Contains(t, rec.errors[0], audittest.CheckOutcome)

	rec = &recorder{}
	checker.AssertConforms(rec, nil)
	assert.Equal(t, []string{"audit conformance: no audit lines in output"}, rec.errors)
}

// recorder captures the errors AssertConforms reports.
type recorder struct {
	testing.TB
	errors []string
}

func (*recorder) Helper() {}

func (r *recorder) Error(args ...any) {
	r.errors = append(r.errors, strings.TrimSpace(fmt.Sprint(args...)))
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}
