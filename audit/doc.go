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
