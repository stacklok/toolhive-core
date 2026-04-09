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
		audit.EventTypeMCPToolCall,
		audit.EventSource{Type: audit.SourceTypeNetwork, Value: "10.0.0.1"},
		audit.OutcomeSuccess,
		map[string]string{audit.SubjectKeyUser: "alice"},
		"my-service",
	).WithTarget(map[string]string{
		audit.TargetKeyType: audit.TargetTypeTool,
		audit.TargetKeyName: "calculator",
	})

# Logging

Use [AuditEvent.LogTo] to emit the event to a [log/slog.Logger] at a
specified level. This produces structured JSON output suitable for audit log
collection.

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
