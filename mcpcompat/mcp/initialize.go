// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// IconTheme is the background theme an icon is designed to be displayed on.
type IconTheme string

// Icon theme constants.
const (
	// IconThemeLight indicates the icon is designed for use with a light background.
	IconThemeLight IconTheme = "light"
	// IconThemeDark indicates the icon is designed for use with a dark background.
	IconThemeDark IconTheme = "dark"
)

// Icon represents a visual identifier for MCP entities.
type Icon struct {
	// URI pointing to the icon resource (HTTPS URL or data URI)
	Src string `json:"src"`

	// Optional MIME type (e.g., "image/png", "image/svg+xml")
	MIMEType string `json:"mimeType,omitempty"`

	// Optional size specifications (e.g., ["48x48"], ["any"] for SVG)
	Sizes []string `json:"sizes,omitempty"`

	// Theme is an optional specifier for the background theme this icon is designed for.
	// Use IconThemeLight for light backgrounds or IconThemeDark for dark backgrounds.
	Theme IconTheme `json:"theme,omitempty"`
}

// Implementation describes the name and version of an MCP implementation.
type Implementation struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
	// Icons provides visual identifiers for the implementation
	Icons []Icon `json:"icons,omitempty"`
}

// ElicitationCapability represents the elicitation capabilities of a client or server.
type ElicitationCapability struct {
	Form *struct{} `json:"form,omitempty"` // Supports form mode
	URL  *struct{} `json:"url,omitempty"`  // Supports URL mode
}

// SamplingCapability represents the sampling capabilities of a client or server
// as defined by the 2025-11-25 protocol revision.
type SamplingCapability struct {
	// Context, if non-nil, advertises that the client honours the
	// CreateMessageParams.IncludeContext field.
	Context *struct{} `json:"context,omitempty"`
	// Tools, if non-nil, advertises that the client honours the
	// CreateMessageParams.Tools and CreateMessageParams.ToolChoice fields
	// (sampling with tools).
	Tools *struct{} `json:"tools,omitempty"`
}

// TasksCapability represents the task capabilities that a client or server may support.
type TasksCapability struct {
	// Whether the party supports the tasks/list operation.
	List *struct{} `json:"list,omitempty"`
	// Whether the party supports the tasks/cancel operation.
	Cancel *struct{} `json:"cancel,omitempty"`
	// Requests that can be augmented with task metadata.
	Requests *TaskRequestsCapability `json:"requests,omitempty"`
}

// TaskRequestsCapability indicates which request types support task augmentation.
type TaskRequestsCapability struct {
	// Tool-related capabilities.
	Tools *struct {
		// Whether tools/call can be augmented with task metadata.
		Call *struct{} `json:"call,omitempty"`
	} `json:"tools,omitempty"`
	// Sampling-related capabilities.
	Sampling *struct {
		// Whether sampling/createMessage can be augmented with task metadata.
		CreateMessage *struct{} `json:"createMessage,omitempty"`
	} `json:"sampling,omitempty"`
	// Elicitation-related capabilities.
	Elicitation *struct {
		// Whether elicitation/create can be augmented with task metadata.
		Create *struct{} `json:"create,omitempty"`
	} `json:"elicitation,omitempty"`
}

// TaskParams represents the task metadata included when augmenting a request.
type TaskParams struct {
	// Requested duration in milliseconds to retain task from creation.
	TTL *int64 `json:"ttl,omitempty"`
}

// ClientCapabilities represents capabilities a client may support. Known
// capabilities are defined here, in this schema, but this is not a closed set: any
// client can define its own, additional capabilities.
type ClientCapabilities struct {
	// Optional, present if the client is advertising extension support.
	Extensions map[string]any `json:"extensions,omitempty"`
	// Experimental, non-standard capabilities that the client supports.
	Experimental map[string]any `json:"experimental,omitempty"`
	// Present if the client supports listing roots.
	Roots *struct {
		// Whether the client supports notifications for changes to the roots list.
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"roots,omitempty"`
	// Present if the client supports sampling from an LLM.
	Sampling *SamplingCapability `json:"sampling,omitempty"`
	// Present if the client supports elicitation requests from the server.
	Elicitation *ElicitationCapability `json:"elicitation,omitempty"`
	// Present if the client supports task-based execution.
	Tasks *TasksCapability `json:"tasks,omitempty"`
}

// ServerCapabilities represents capabilities that a server may support. Known
// capabilities are defined here, in this schema, but this is not a closed set: any
// server can define its own, additional capabilities.
type ServerCapabilities struct {
	// Optional, present if the server is advertising extension support.
	Extensions map[string]any `json:"extensions,omitempty"`
	// Experimental, non-standard capabilities that the server supports.
	Experimental map[string]any `json:"experimental,omitempty"`
	// Present if the server supports sending log messages to the client.
	Logging *struct{} `json:"logging,omitempty"`
	// Present if the server offers any prompt templates.
	Prompts *struct {
		// Whether this server supports notifications for changes to the prompt list.
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"prompts,omitempty"`
	// Present if the server offers any resources to read.
	Resources *struct {
		// Whether this server supports subscribing to resource updates.
		Subscribe bool `json:"subscribe,omitempty"`
		// Whether this server supports notifications for changes to the resource
		// list.
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"resources,omitempty"`
	// Present if the server supports sending sampling requests to clients.
	Sampling *SamplingCapability `json:"sampling,omitempty"`
	// Present if the server offers any tools to call.
	Tools *struct {
		// Whether this server supports notifications for changes to the tool list.
		ListChanged bool `json:"listChanged,omitempty"`
	} `json:"tools,omitempty"`
	// Present if the server supports elicitation requests to the client.
	Elicitation *ElicitationCapability `json:"elicitation,omitempty"`
	// Present if the server supports roots requests to the client.
	Roots *struct{} `json:"roots,omitempty"`
	// Present if the server supports task-based execution.
	Tasks *TasksCapability `json:"tasks,omitempty"`
	// Present if the server supports completions requests to the client.
	Completions *struct{} `json:"completions,omitempty"`
}

// InitializeRequest is sent from the client to the server when it first
// connects, asking it to begin initialization.
type InitializeRequest struct {
	Request
	Params InitializeParams `json:"params"`
	Header http.Header      `json:"-"`
}

// InitializeParams are the params of an initialize request.
type InitializeParams struct {
	// The latest version of the Model Context Protocol that the client supports.
	// The client MAY decide to support older versions as well.
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is sent after receiving an initialize request from the
// client.
type InitializeResult struct {
	Result
	// The version of the Model Context Protocol that the server wants to use.
	// This may not match the version that the client requested. If the client cannot
	// support this version, it MUST disconnect.
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	// Instructions describing how to use the server and its features.
	Instructions string `json:"instructions,omitempty"`
}
