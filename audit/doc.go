// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package audit provides audit event structures and utilities for the ToolHive
ecosystem, ensuring NIST SP 800-53 compliance.

The core type is [AuditEvent], which captures the minimal information needed
to audit an event in a uniform, serializable format. Use [NewAuditEvent] to
create events with a generated audit ID and UTC timestamp, or
[NewAuditEventWithID] when the caller provides the ID.

# Event Structure

Each audit event records:
  - Type: a short identifier for what happened (e.g. "mcp_tool_call")
  - Source: where the request originated (network address, local process)
  - Outcome: success, failure, error, or denied
  - Subjects: identity of who triggered the event
  - Component: which system component logged the event
  - Target: optional target of the operation
  - Data: optional extra payload for forensic analysis

# Builder Pattern

Events support a fluent builder pattern for optional fields:

	event := audit.NewAuditEvent(
		"mcp_tool_call",
		audit.EventSource{Type: audit.SourceTypeNetwork, Value: "10.0.0.1"},
		audit.OutcomeSuccess,
		map[string]string{"user": "alice"},
		"my-service",
	).WithTarget(map[string]string{
		"type": "tool",
		"name": "calculator",
	})

# Delegation Chains

When an actor acted on behalf of another actor (RFC 8693 `act` claim), attach
a [DelegationChain] to the event via [AuditEvent.WithDelegationChain]. The
chain is additive to the flat [AuditEvent.Subjects] map; Subjects remains the
backward-compatible identity map and is not modified by setting a chain.

Parse raw `act` claims with [ParseDelegationChain], which applies a defensive
depth cap ([DefaultMaxDelegationDepth], overridable via maxDepth) to bound the
size of the retained chain and of the emitted record — not parsing work, since
the caller has already decoded the claim — and reports explicit truncation
(Truncated/Omitted are never silently omitted). Per-hop identity is the issuer
(iss) and subject (sub) pair only: (iss, sub) is the only stable, unique actor
identifier (OpenID Connect Core §5.7), and RFC 8693 §6 calls for data
minimization. Any extra claims present on a hop are retained in memory for
inspection via [DelegatedActor.Extra] but are never serialized or logged, to
avoid leaking Personally Identifiable Information.

The chain is ordered outermost-first: Chain[0] is the current actor and the
last entry is the least recent (earliest) actor. The delegating end user is
not part of the chain — it is the token's top-level sub, recorded in Subjects.
Only the top-level event claims and Chain[0] should drive access-control
decisions; prior hops are informational only (RFC 8693 §4.1) and exist for
audit.

Parsing never fails: an audit record must be producible for exactly the
tokens that violate expectations, since a malformed delegation assertion from
a signature-validated token is itself security-relevant (it indicates an
issuer bug or tampering), and dropping the record would let malformed input
suppress audit (CWE-223, CWE-778). Non-conformant input is recorded on the
chain via Malformed and a low-cardinality MalformedReason, with all hops that
parsed successfully preserved. Strict rejection of malformed `act` claims
belongs on the token-issuance path, not in the audit sink; consumers that
alert can key on the malformed field.

# Logging

Use [AuditEvent.LogTo] to emit the event to a [log/slog.Logger] at a
specified level. This produces structured JSON output suitable for audit log
collection.

# Audit Handler Middleware

A service that already has one operator logger does not need a second logger
for audit events. [HandlerMiddleware] wraps the service's [log/slog.Handler]
so that [LevelAudit] records go to a dedicated audit writer, while every other
record goes to the wrapped handler unchanged. Register it with
logging.WithHandlerMiddleware when building the logger, as the last
middleware:

	logger := logging.New(
		logging.WithLevel(slog.LevelWarn),
		logging.WithHandlerMiddleware(traceContextMiddleware),
		logging.WithHandlerMiddleware(audit.HandlerMiddleware(
			audit.WithEnabled(cfg.AuditEnabled),
			audit.WithMeterProvider(meterProvider),
		)), // must be last
	)

	event := audit.NewAuditEvent("widgets.widget.update", source,
		audit.OutcomeSuccess, subjects, "example-service")
	event.LogTo(ctx, logger, audit.LevelAudit)

The middleware behaves as follows, and each rule has a reason:

  - Audit records are written to [os.Stdout] by default (override with
    [WithWriter]); operator records keep their own output, normally
    stderr. Keeping audit events on their own stream lets a log collector
    ship them without parsing operator output.
  - Each audit record is one JSON line, whatever format the operator logger
    uses. The level is rendered as "AUDIT" rather than slog's "INFO+2", and
    every line carries logger=audit, so a collector selects audit events from
    every service with a single rule. Only the middleware stamps logger=audit;
    lines written through [NewAuditLogger] do not carry it.
  - Audit records ignore the operator log level. A service running at warn or
    error still writes its audit events.
  - [WithEnabled] is the only gate. When it is false, Enabled reports
    [LevelAudit] as disabled, so slog neither constructs nor dispatches the
    record, and any audit record that reaches the handler is dropped.
  - Attributes and groups added with [log/slog.Logger.With] and
    [log/slog.Logger.WithGroup] apply to operator records only. An audit
    line contains only the fields of its event, plus time, level, msg and
    logger=audit, all at the top level, so
    request-scoped logger context cannot leak into or reshape the audit
    record.
  - The middleware must be registered last, making it the outermost handler.
    It handles audit records itself and never passes them to the handler it
    wraps, so no middleware registered before it can see, change or drop an
    audit record. A middleware registered after it would see audit records,
    and the library cannot prevent that.
  - The write is synchronous, and each record is written with one Write call
    under a lock shared by every handler built from one [HandlerMiddleware]
    result, so concurrent records never interleave. Applying two separate
    HandlerMiddleware results to one writer gives two locks; build the
    middleware once per writer. A failed or short
    write never returns an error to the caller and is never logged, so a
    broken audit stream neither fails the action being audited nor floods
    the operator output. Instead each failed record increments the
    [WriteFailuresMetricName] counter (no attributes) on the meter provider set
    with [WithMeterProvider], or the global provider by default. After a
    short write, the next record starts on a new line so it still parses.

# Actor From Context

Call sites do not pass the actor. The authentication middleware that verifies
a caller stores one [Actor] in the request context with [ContextWithActor],
and the [EventBuilder] writes every actor key of the event's subjects from it.
This removes the class of defect where a call site forgets the actor or names
it differently, and gives one place to change how actors are identified.

Each principal kind has its own constructor, and each writes a fixed set of
subjects keys, plus any optional field set with an [ActorOption]:

  - [NewUserActor]: principal_kind, user_id, issuer. The user id is the stable
    id the issuer assigns, never a mutable attribute such as an email, so the
    trail survives a rename.
  - [NewServiceAccountActor]: principal_kind, user_id.
  - [NewSCIMIssuerActor]: principal_kind, user_id and issuer (both the issuer
    id), token_fingerprint. The fingerprint is keyed, because a static token
    can be weak and an unkeyed hash kept for years can be guessed offline.
  - [NewSystemActor]: principal_kind, user_id (the fixed name of the
    runnable). Only work that no caller started, such as a boot-time job,
    builds one.
  - [NewAnonymousActor]: principal_kind and never user_id. Only an
    authentication refusal builds one, so its outcome is denied, or error when
    the service failed before it could verify the caller.

A [SubjectEnricher], set with [WithSubjectEnricher], adds component keys to
the subjects. It can never set an actor key: any it returns is dropped, so an
enricher cannot give an anonymous event a user id. At most 16 enricher keys
are kept, in sorted key order.

The component generates a request id when a request arrives and stores it
with [ContextWithRequestID]; the builder copies it to
metadata.extra.request_id, which joins the event to the access logs. It never
reuses an id the client sent, because a client can choose it.

# Event Builder

[EventBuilder.NewEvent] takes the context, the type, the [Target], the
outcome and optional inputs, and returns the events to log:

	builder := audit.NewEventBuilder("example-service",
		audit.WithBuilderMeterProvider(meterProvider))

	// In the authentication middleware:
	ctx = audit.ContextWithActor(ctx, audit.NewUserActor(userID, issuer))
	ctx = audit.ContextWithRequestID(ctx, requestID)

	// At the call site:
	events, err := builder.NewEvent(ctx, "widgets.widget.update",
		audit.Target{Type: "widget", ID: widget.ID, Name: widget.Name},
		audit.OutcomeSuccess,
		audit.WithChanges(
			audit.FieldChange("color", "blue", "red"),
			audit.SecretFieldChange("api_key"),
			audit.MembersChange("owners", added, removed),
		),
	)
	if err != nil {
		return err // a defect in the call site; see below
	}
	for _, event := range events {
		event.LogTo(ctx, logger, audit.LevelAudit)
	}

Every event it builds has metadata.extra.schema_version equal to
[SchemaVersion], a new audit id and a UTC loggedAt. The default source is
[SourceTypeLocal] with the host name, which in a Kubernetes pod is the pod
name; override it with [WithSourceName] or, per event, [WithSource].

NewEvent refuses to build an event, returns an error and no event, and
increments the [EventErrorsMetricName] counter with a "reason" attribute,
when:

  - the context has no actor, or a non-anonymous actor with no user id
    ([ErrNoActor], reason no_actor). Every audited request needs a known
    actor;
  - the outcome is not success, failure, error or denied
    ([ErrInvalidOutcome], reason invalid_outcome). The set is closed so a
    SIEM rule can enumerate it;
  - the reason set with [WithReason] is not a lower snake case token of at
    most 64 bytes ([ErrInvalidReason], reason invalid_reason). A reason is a
    bounded token such as "not_found", never free text, an error message or
    a value the caller controls;
  - an anonymous actor has an outcome other than denied or error
    ([ErrAnonymousOutcome], reason anonymous_invalid_outcome).

Component keys passed with [WithExtra] go to metadata.extra. At most 16 are
kept, in sorted key order, each value is capped at [MaxActorStringBytes], and
a key the builder writes itself, such as "reason" or "request_id", is
dropped, so a component cannot forge one.

# Change Detail

[WithChanges] records what a write changed in metadata.extra.changes.
[FieldChange] records a field's value before and after the write, so the trail
shows every value a field has held. [MembersChange] records the ids of the
members added and removed. [SecretFieldChange] records a secret-bearing field
by name only: it has no slot for a value, so a call site cannot put a secret
in the trail by mistake. [WithCause] links an event to the event that caused
it, such as the deletion that cascaded to it.

# Size Limit

Container runtimes split a stdout line longer than 16 KiB into partial
records, and a collector that does not join them breaks the event. The
builder therefore keeps each line, measured with the audit handler
middleware's own renderer and newline included, within [MaxLineBytes]. It
packs to 16,000 bytes, which leaves headroom for the record time.

  - Each actor string, enricher value and component value is capped at
    [MaxActorStringBytes], because actor strings come from token claims with
    no length limit. The target id, the source value, each source extra
    value, each change field name and each delegation hop's issuer and
    subject are capped the same way. At most 16 enricher, component and
    source extra keys are kept.
  - The change list, the member ids and the delegation chain are split, never
    cut, so an auditor can still find when a given member was added. When they
    do not fit, the first event is followed by continuation events. Each has
    its own audit id, sets metadata.extra.cause to the first event's audit id,
    and repeats the type, outcome, reason, request id, actor and the target's
    type and id. Every event of the set carries metadata.extra.part and
    metadata.extra.parts, and each list entry appears in exactly one of them.
    The first event keeps the caller's cause, the component keys, the payload
    and the target name.
  - Any other overflow is cut, in order: the payload set with [WithPayload],
    which becomes a JSON string of its leading bytes; then the target name;
    then each change value or member id whose encoding is over 4 KiB, cut to
    4 KiB, when its entry does not fit in an event on its own. Sizes are
    measured in encoded bytes, so characters JSON escapes count in full.
  - The builder never cuts the audit id, the time, the type, the outcome, the
    reason, the request id, the actor (beyond its cap), the cause, the
    component or the target type. These are set by the component, not the
    caller, and normally take a few hundred bytes. If they alone leave no
    room, the builder cuts nothing that would not help and returns a single
    event, best effort, rather than one oversized event per list entry.

Every cut or dropped value is listed in metadata.extra.truncated with its
field name, original length and SHA-256 digest. A digest lets an auditor
match a value they already hold; it does not recover the value. At most 16
dropped keys of one source are listed individually; one summary record, whose
field is the source, counts the rest and digests their sorted names.

# Conformance Helper

The audittest subpackage checks a component's audit output against these
rules. Each component runs it in its unit tests against every event type it
declares; see that package for the checks.

# Well-Known Constants

The package defines well-known constants for event types, outcomes, source
types, target types, and map keys used in Subjects, Target, Source.Extra,
and Metadata.Extra fields. Using these constants ensures consistency across
the ToolHive ecosystem.

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package audit
