// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

// Canonical label-key constants for Stacklok-authored metrics (RFC §3.3
// label dictionary). One key per concept, snake_case, no boolean-typed keys.
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

	// LabelProvider identifies the upstream LLM provider.
	LabelProvider = "provider"

	// LabelModel identifies the LLM model.
	LabelModel = "model"

	// LabelErrorType carries the failure classification on a Stacklok-authored
	// metric (coexists with semconv error.type on OTel semconv metrics).
	LabelErrorType = "error_type"
)
