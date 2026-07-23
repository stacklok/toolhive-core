// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

// Canonical label-key constants for Stacklok-authored metrics (RFC §3.3
// label dictionary). One key per concept, snake_case, no boolean-typed keys.
//
// This set is scoped to canonical common keys only: concepts more than one
// component emits and that a cross-component dashboard joins or groups on.
// Component-local keys used by only one emitter (e.g. operator reconcile's
// "phase", the circuit breaker's "from"/"to", the registry's "source") are
// defined by the emitting component, not exported here.
const (
	// LabelMCPServer identifies the upstream MCP server.
	LabelMCPServer = "mcp_server"

	// LabelOutcome carries the result of an operation. Its value is one of
	// "success", "error", or "rejected".
	LabelOutcome = "outcome"

	// LabelMCPMethod identifies the MCP method invoked.
	LabelMCPMethod = "mcp_method"

	// LabelToolName identifies the tool invoked.
	LabelToolName = "tool_name"

	// LabelCompositeTool identifies a vMCP composite tool.
	LabelCompositeTool = "composite_tool"

	// LabelTransport identifies the transport used (e.g. stdio, sse, http).
	LabelTransport = "transport"

	// LabelErrorType carries the failure classification on a Stacklok-authored
	// metric (coexists with semconv error.type on OTel semconv metrics).
	LabelErrorType = "error_type"
)

// Canonical outcome-label values. The LabelOutcome key carries one of these on
// a Stacklok-authored counter, distinguishing success from failure without a
// separate _succeed/_failed metric name (RFC §3.4 / D4). A metric may extend
// this set with a documented, bounded per-metric outcome where the standard
// three do not capture a distinct terminal state (e.g. the journal lifecycle
// outcomes, the vMCP optimizer's "not_found"); such extensions are owned by the
// emitting component, not exported here.
const (
	// OutcomeSuccess marks a successful operation.
	OutcomeSuccess = "success"

	// OutcomeError marks a failed operation.
	OutcomeError = "error"

	// OutcomeRejected marks an operation refused before execution (e.g. rate
	// limited, circuit open, admission denied).
	OutcomeRejected = "rejected"
)
