// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// Role represents the sender or recipient of messages and data in a
// conversation.
type Role string

// Message roles.
const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Prompt represents a prompt or prompt template that the server offers.
// If Arguments is non-nil and non-empty, this indicates the prompt is a template
// that requires argument values to be provided when calling prompts/get.
// If Arguments is nil or empty, this is a static prompt that takes no arguments.
type Prompt struct {
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta `json:"_meta,omitempty"`
	// The name of the prompt or prompt template.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for the prompt.
	// If not provided, clients should fall back to Name.
	Title string `json:"title,omitempty"`
	// An optional description of what this prompt provides
	Description string `json:"description,omitempty"`
	// A list of arguments to use for templating the prompt.
	// The presence of arguments indicates this is a template prompt.
	Arguments []PromptArgument `json:"arguments,omitempty"`
	// Icons provides visual identifiers for the prompt
	Icons []Icon `json:"icons,omitempty"`
}

// GetName returns the name of the prompt.
func (p Prompt) GetName() string {
	return p.Name
}

// PromptArgument describes an argument that a prompt template can accept.
// When a prompt includes arguments, clients must provide values for all
// required arguments when making a prompts/get request.
type PromptArgument struct {
	// The name of the argument.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for the argument.
	// If not provided, clients should fall back to Name.
	Title string `json:"title,omitempty"`
	// A human-readable description of the argument.
	Description string `json:"description,omitempty"`
	// Whether this argument must be provided.
	// If true, clients must include this argument when calling prompts/get.
	Required bool `json:"required,omitempty"`
}

// PromptMessage describes a message returned as part of a prompt.
//
// This is similar to `SamplingMessage`, but also supports the embedding of
// resources from the MCP server.
type PromptMessage struct {
	Role    Role    `json:"role"`
	Content Content `json:"content"` // Can be TextContent, ImageContent, AudioContent or EmbeddedResource
}

// ListPromptsRequest is sent from the client to request a list of prompts and
// prompt templates the server has.
type ListPromptsRequest struct {
	PaginatedRequest
	Header http.Header `json:"-"`
}

// ListPromptsResult is the server's response to a prompts/list request from
// the client.
type ListPromptsResult struct {
	PaginatedResult
	Prompts []Prompt `json:"prompts"`
}

// GetPromptRequest is used by the client to get a prompt provided by the
// server.
type GetPromptRequest struct {
	Request
	Params GetPromptParams `json:"params"`
	Header http.Header     `json:"-"`
}

// GetPromptParams contains parameters for a prompts/get request.
type GetPromptParams struct {
	// The name of the prompt or prompt template.
	Name string `json:"name"`
	// Arguments to use for templating the prompt.
	Arguments map[string]string `json:"arguments,omitempty"`
	// Meta carries protocol-level metadata (e.g. W3C traceparent, progressToken).
	Meta *Meta `json:"_meta,omitempty"`
}

// GetPromptResult is the server's response to a prompts/get request from the
// client.
type GetPromptResult struct {
	Result
	// An optional description for the prompt.
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptOption is a function that configures a Prompt.
// It provides a flexible way to set various properties of a Prompt using the functional options pattern.
type PromptOption func(*Prompt)

// NewPrompt creates a new Prompt with the given name and options.
// The prompt will be configured based on the provided options.
// Options are applied in order, allowing for flexible prompt configuration.
func NewPrompt(name string, opts ...PromptOption) Prompt {
	prompt := Prompt{
		Name: name,
	}

	for _, opt := range opts {
		opt(&prompt)
	}

	return prompt
}

// WithPromptDescription adds a description to the Prompt.
// The description should provide a clear, human-readable explanation of what the prompt does.
func WithPromptDescription(description string) PromptOption {
	return func(p *Prompt) {
		p.Description = description
	}
}

// NewPromptMessage creates a new PromptMessage.
func NewPromptMessage(role Role, content Content) PromptMessage {
	return PromptMessage{
		Role:    role,
		Content: content,
	}
}
