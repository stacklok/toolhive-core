// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

// MCPMethod is the type of MCP method-name constants.
// MCPMethod is the type of MCP method-name constants.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type MCPMethod string

// MCP method names.
const (
	// MethodInitialize initiates connection and negotiates protocol capabilities.
	MethodInitialize MCPMethod = "initialize"

	// MethodPing verifies connection liveness between client and server.
	MethodPing MCPMethod = "ping"

	// MethodResourcesList lists all available server resources.
	MethodResourcesList MCPMethod = "resources/list"

	// MethodResourcesTemplatesList provides URI templates for constructing resource URIs.
	MethodResourcesTemplatesList MCPMethod = "resources/templates/list"

	// MethodResourcesRead retrieves content of a specific resource by URI.
	MethodResourcesRead MCPMethod = "resources/read"

	// MethodPromptsList lists all available prompt templates.
	MethodPromptsList MCPMethod = "prompts/list"

	// MethodPromptsGet retrieves a specific prompt template with filled parameters.
	MethodPromptsGet MCPMethod = "prompts/get"

	// MethodToolsList lists all available executable tools.
	MethodToolsList MCPMethod = "tools/list"

	// MethodToolsCall invokes a specific tool with provided parameters.
	MethodToolsCall MCPMethod = "tools/call"

	// MethodSetLogLevel configures the minimum log level for client.
	MethodSetLogLevel MCPMethod = "logging/setLevel"

	// MethodElicitationCreate requests additional information from the user during interactions.
	MethodElicitationCreate MCPMethod = "elicitation/create"

	// MethodComplete requests argument-completion options from the server.
	MethodComplete MCPMethod = "completion/complete"

	// MethodListRoots requests roots list from the client during interactions.
	MethodListRoots MCPMethod = "roots/list"

	// MethodNotificationInitialized indicates that the client completed initialization.
	MethodNotificationInitialized MCPMethod = "notifications/initialized"
)

// Content type constants.
const (
	ContentTypeText       = "text"
	ContentTypeImage      = "image"
	ContentTypeAudio      = "audio"
	ContentTypeLink       = "resource_link"
	ContentTypeResource   = "resource"
	ContentTypeToolUse    = "tool_use"
	ContentTypeToolResult = "tool_result"

	ElicitationModeForm = "form"
	ElicitationModeURL  = "url"
)
