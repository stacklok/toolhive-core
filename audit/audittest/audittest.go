// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package audittest checks a component's audit output against the rules the
audit package's event builder and audit handler middleware enforce.

A component runs the checker in its unit tests against every event type it
declares. It logs the events through a logger built with
audit.HandlerMiddleware and a buffer as the writer, then checks the buffer:

	var buf bytes.Buffer
	logger := slog.New(audit.HandlerMiddleware(audit.WithWriter(&buf))(slog.Default().Handler()))
	// ... exercise the code that logs audit events through logger ...

	checker := audittest.NewChecker(
		audittest.WithLegacyTypes("widget_update"),
		audittest.WithSecrets("s3cr3t-api-key"),
	)
	checker.AssertConforms(t, buf.Bytes())

Each failed rule is reported as a [Violation] that names the check, so a
failure points at the rule that was broken. The checks are:

  - [CheckJSON]: the line is one JSON object.
  - [CheckMessage], [CheckLevel], [CheckLogger]: the message is
    "audit_event", the level is "AUDIT", and logger=audit is present.
  - [CheckEnvelopeKeys]: the line has no top-level key outside the audit
    envelope, such as a trace id stamped by another handler.
  - [CheckType]: the type is three dot-separated lower snake case segments,
    <area>.<resource>.<verb>, or is one of the component's shipped legacy
    types.
  - [CheckOutcome], [CheckReason]: the outcome is in the closed set and the
    reason, when present, is a bounded lower snake case token.
  - [CheckSchemaVersion]: metadata.extra.schema_version is the integer
    [audit.SchemaVersion].
  - [CheckSize], [CheckActorLength]: the line, newline included, is at most
    [audit.MaxLineBytes], and no subjects value is longer than
    [audit.MaxActorStringBytes].
  - [CheckRequestID]: a request-scoped event has metadata.extra.request_id.
    An event whose actor is a system actor, and a refusal summary (an event
    with metadata.extra.suppressed), are not request scoped.
  - [CheckPrincipalKind], [CheckUserID], [CheckAnonymousOutcome]: subjects
    has a known principal_kind; it has user_id for every kind except
    anonymous, and an anonymous event has none; an anonymous event's outcome
    is denied or error.
  - [CheckSecret]: no value the test marks as secret appears anywhere in the
    line.

# Stability

This package is Alpha stability. The API may change without notice.
*/
package audittest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stacklok/toolhive-core/audit"
)

// Names of the checks, as reported in [Violation.Check].
const (
	CheckJSON             = "json"
	CheckMessage          = "message"
	CheckLevel            = "level"
	CheckLogger           = "logger"
	CheckEnvelopeKeys     = "envelope_keys"
	CheckType             = "type"
	CheckOutcome          = "outcome"
	CheckReason           = "reason"
	CheckSchemaVersion    = "schema_version"
	CheckSize             = "size"
	CheckActorLength      = "actor_length"
	CheckRequestID        = "request_id"
	CheckPrincipalKind    = "principal_kind"
	CheckUserID           = "user_id"
	CheckAnonymousOutcome = "anonymous_outcome"
	CheckSecret           = "secret"
)

// envelopeKeys are the top-level keys an audit line may carry.
var envelopeKeys = map[string]struct{}{
	"time": {}, "level": {}, "msg": {}, "logger": {},
	"audit_id": {}, "type": {}, "logged_at": {}, "outcome": {}, "component": {},
	"source": {}, "subjects": {}, "target": {}, "metadata": {}, "data": {}, "delegation": {},
}

var typePattern = regexp.MustCompile(
	`^[a-z][a-z0-9]*(_[a-z0-9]+)*\.[a-z][a-z0-9]*(_[a-z0-9]+)*\.[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// Violation is one broken rule on one audit line.
type Violation struct {
	// Check is the name of the broken check, one of the Check constants.
	Check string
	// Detail says how the line broke it.
	Detail string
}

// Error implements error.
func (v Violation) Error() string {
	return fmt.Sprintf("audit conformance check %q failed: %s", v.Check, v.Detail)
}

// Option configures a [Checker].
type Option func(*Checker)

// WithLegacyTypes lists event types the component shipped before the
// <area>.<resource>.<verb> naming rule. A shipped type is never renamed,
// because SIEM rules match on it, so these pass the type check.
func WithLegacyTypes(types ...string) Option {
	return func(c *Checker) {
		for _, t := range types {
			c.legacy[t] = struct{}{}
		}
	}
}

// WithSecrets lists secret values, such as a token or key the test used,
// that must not appear anywhere in an audit line. Empty values are ignored.
func WithSecrets(values ...string) Option {
	return func(c *Checker) {
		for _, v := range values {
			if v != "" {
				c.secrets = append(c.secrets, v)
			}
		}
	}
}

// Checker checks audit lines. Create one with [NewChecker].
type Checker struct {
	legacy  map[string]struct{}
	secrets []string
}

// NewChecker returns a [Checker].
func NewChecker(opts ...Option) *Checker {
	c := &Checker{legacy: make(map[string]struct{})}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AssertConforms reports a test error for every violation on every line of
// output, the bytes the audit handler middleware wrote. It also fails when
// output holds no audit line, so a test cannot pass by logging nothing.
func (c *Checker) AssertConforms(tb testing.TB, output []byte) {
	tb.Helper()
	lines := splitLines(output)
	if len(lines) == 0 {
		tb.Error("audit conformance: no audit lines in output")
		return
	}
	for i, line := range lines {
		for _, v := range c.Violations(line) {
			tb.Errorf("audit line %d: %v", i+1, v)
		}
	}
}

// CheckOutput checks every line of output and returns the violations
// joined, or nil when every line conforms.
func (c *Checker) CheckOutput(output []byte) error {
	var errs []error
	for i, line := range splitLines(output) {
		for _, v := range c.Violations(line) {
			errs = append(errs, fmt.Errorf("audit line %d: %w", i+1, v))
		}
	}
	return errors.Join(errs...)
}

// CheckLine checks one audit line and returns its violations joined, or nil
// when it conforms. The line may or may not end with its newline.
func (c *Checker) CheckLine(line []byte) error {
	var errs []error
	for _, v := range c.Violations(line) {
		errs = append(errs, v)
	}
	return errors.Join(errs...)
}

// Violations returns every rule one audit line breaks. The line may or may
// not end with its newline.
func (c *Checker) Violations(line []byte) []Violation {
	line = bytes.TrimSuffix(line, []byte("\n"))
	var out []Violation
	fail := func(check, format string, args ...any) {
		out = append(out, Violation{Check: check, Detail: fmt.Sprintf(format, args...)})
	}

	if size := len(line) + 1; size > audit.MaxLineBytes {
		fail(CheckSize, "line is %d bytes with its newline, over %d", size, audit.MaxLineBytes)
	}
	c.checkSecrets(line, fail)

	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil {
		fail(CheckJSON, "line is not a JSON object: %v", err)
		return out
	}
	c.checkHeader(rec, fail)
	c.checkEvent(rec, fail)
	return out
}

type failFunc func(check, format string, args ...any)

func (*Checker) checkHeader(rec map[string]any, fail failFunc) {
	if msg, _ := rec["msg"].(string); msg != "audit_event" {
		fail(CheckMessage, "msg is %q, want %q", msg, "audit_event")
	}
	if level, _ := rec["level"].(string); level != "AUDIT" {
		fail(CheckLevel, "level is %q, want %q", level, "AUDIT")
	}
	if logger, _ := rec["logger"].(string); logger != "audit" {
		fail(CheckLogger, "logger is %q, want %q", logger, "audit")
	}
	for k := range rec {
		if _, ok := envelopeKeys[k]; !ok {
			fail(CheckEnvelopeKeys, "top-level key %q is not part of the audit envelope", k)
		}
	}
}

func (c *Checker) checkEvent(rec map[string]any, fail failFunc) {
	eventType, _ := rec["type"].(string)
	if _, legacy := c.legacy[eventType]; !legacy && !typePattern.MatchString(eventType) {
		fail(CheckType, "type %q is not <area>.<resource>.<verb> in lower snake case nor a declared legacy type", eventType)
	}
	outcome, _ := rec["outcome"].(string)
	if !audit.IsValidOutcome(outcome) {
		fail(CheckOutcome, "outcome %q is not success, failure, error or denied", outcome)
	}

	metadata, _ := rec["metadata"].(map[string]any)
	extra, _ := metadata["extra"].(map[string]any)
	if reason, present := extra[audit.MetadataExtraKeyReason]; present {
		if s, _ := reason.(string); !audit.IsValidReason(s) {
			fail(CheckReason, "reason %v is not a lower snake case token of at most %d bytes", reason, audit.MaxReasonBytes)
		}
	}
	if v, _ := extra[audit.MetadataExtraKeySchemaVersion].(float64); v != audit.SchemaVersion {
		fail(CheckSchemaVersion, "metadata.extra.schema_version is %v, want %d",
			extra[audit.MetadataExtraKeySchemaVersion], audit.SchemaVersion)
	}

	subjects, _ := rec["subjects"].(map[string]any)
	kind := checkActor(subjects, outcome, fail)

	_, summary := extra[audit.MetadataExtraKeySuppressed]
	requestScoped := kind != audit.PrincipalKindSystem && !summary
	if id, _ := extra[audit.MetadataExtraKeyRequestID].(string); requestScoped && id == "" {
		fail(CheckRequestID, "request-scoped event has no metadata.extra.request_id")
	}
}

// checkActor checks the actor in subjects and returns its principal kind.
func checkActor(subjects map[string]any, outcome string, fail failFunc) audit.PrincipalKind {
	for k, v := range subjects {
		if s, _ := v.(string); len(s) > audit.MaxActorStringBytes {
			fail(CheckActorLength, "subjects.%s is %d bytes, over %d", k, len(s), audit.MaxActorStringBytes)
		}
	}
	kindValue, _ := subjects[audit.SubjectKeyPrincipalKind].(string)
	kind := audit.PrincipalKind(kindValue)
	userID, hasUserID := subjects[audit.SubjectKeyUserID].(string)
	switch kind {
	case audit.PrincipalKindAnonymous:
		if hasUserID {
			fail(CheckUserID, "anonymous event has user_id")
		}
		if outcome != audit.OutcomeDenied && outcome != audit.OutcomeError {
			fail(CheckAnonymousOutcome, "anonymous event has outcome %q, want denied or error", outcome)
		}
	case audit.PrincipalKindUser, audit.PrincipalKindServiceAccount,
		audit.PrincipalKindSCIMIssuer, audit.PrincipalKindSystem:
		if userID == "" {
			fail(CheckUserID, "%s event has no user_id", kind)
		}
	default:
		fail(CheckPrincipalKind, "subjects.principal_kind is %q, not a known principal kind", kindValue)
	}
	return kind
}

// checkSecrets looks for each secret in the raw line and in every decoded
// string, so JSON escaping cannot hide one.
func (c *Checker) checkSecrets(line []byte, fail failFunc) {
	if len(c.secrets) == 0 {
		return
	}
	var decoded any
	_ = json.Unmarshal(line, &decoded) // an undecodable line is still searched raw
	strs := collectStrings(decoded, nil)
	for i, secret := range c.secrets {
		found := bytes.Contains(line, []byte(secret))
		for _, s := range strs {
			found = found || strings.Contains(s, secret)
		}
		if found {
			// Name the secret by position only, so the failure message does
			// not print it.
			fail(CheckSecret, "secret value #%d appears in the line", i+1)
		}
	}
}

func collectStrings(v any, out []string) []string {
	switch tv := v.(type) {
	case string:
		out = append(out, tv)
	case map[string]any:
		for k, e := range tv {
			out = append(out, k)
			out = collectStrings(e, out)
		}
	case []any:
		for _, e := range tv {
			out = collectStrings(e, out)
		}
	}
	return out
}

func splitLines(output []byte) [][]byte {
	var lines [][]byte
	for _, line := range bytes.Split(output, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}
