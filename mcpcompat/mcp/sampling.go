// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

// CreateMessageRequest is a server->client request asking the client to sample
// an LLM (the sampling/createMessage method). It mirrors mcp-go's
// mcp.CreateMessageRequest so callers that construct it against the shim keep
// working; conversion to/from the go-sdk's CreateMessageParams happens at the
// server/client boundary via a JSON round-trip.
type CreateMessageRequest struct {
	Request
	CreateMessageParams `json:"params"`
}

// CreateMessageParams carries the sampling request parameters. It mirrors
// mcp-go's mcp.CreateMessageParams. The tool-related fields (Tools/ToolChoice)
// present in newer mcp-go releases are intentionally omitted: the shim maps
// sampling onto go-sdk's ServerSession.CreateMessage (single-content sampling),
// not CreateMessageWithTools.
type CreateMessageParams struct {
	// Messages is the conversation history to sample from.
	Messages []SamplingMessage `json:"messages"`
	// ModelPreferences expresses the server's model-selection preferences. The
	// client may ignore them.
	ModelPreferences *ModelPreferences `json:"modelPreferences,omitempty"`
	// SystemPrompt is an optional system prompt the server wants to use. The
	// client may modify or omit it.
	SystemPrompt string `json:"systemPrompt,omitempty"`
	// IncludeContext requests context from one or more MCP servers be attached to
	// the prompt ("none", "thisServer", "allServers"). The client may ignore it.
	IncludeContext string `json:"includeContext,omitempty"`
	// Temperature is the sampling temperature.
	Temperature float64 `json:"temperature,omitempty"`
	// MaxTokens is the maximum number of tokens to sample. The client may sample
	// fewer.
	MaxTokens int `json:"maxTokens"`
	// StopSequences are sequences that, when generated, stop sampling.
	StopSequences []string `json:"stopSequences,omitempty"`
	// Metadata is optional provider-specific metadata passed through to the LLM.
	Metadata any `json:"metadata,omitempty"`
}

// CreateMessageResult is the client's response to a sampling/createMessage
// request. It mirrors mcp-go's mcp.CreateMessageResult, embedding the sampled
// SamplingMessage (role + content) alongside the model name and stop reason.
type CreateMessageResult struct {
	Result
	SamplingMessage
	// Model is the name of the model that generated the message.
	Model string `json:"model"`
	// StopReason is the reason sampling stopped, if known (e.g. "endTurn",
	// "stopSequence", "maxTokens").
	StopReason string `json:"stopReason,omitempty"`
}

// SamplingMessage describes a message issued to or received from an LLM. It
// mirrors mcp-go's mcp.SamplingMessage; Content is typed as any (a TextContent,
// ImageContent or AudioContent) to match mcp-go, which does not decode it into
// the Content interface.
type SamplingMessage struct {
	Role Role `json:"role"`
	// Content can be TextContent, ImageContent or AudioContent.
	Content any `json:"content"`
}

// ModelPreferences expresses the server's preferences for model selection
// during sampling. It mirrors mcp-go's mcp.ModelPreferences. All fields are
// advisory; the client may ignore them.
type ModelPreferences struct {
	// Hints are ordered model-selection hints; the client evaluates them in
	// order and takes the first match.
	Hints []ModelHint `json:"hints,omitempty"`
	// CostPriority weights cost in model selection (0..1).
	CostPriority float64 `json:"costPriority,omitempty"`
	// SpeedPriority weights latency in model selection (0..1).
	SpeedPriority float64 `json:"speedPriority,omitempty"`
	// IntelligencePriority weights capability in model selection (0..1).
	IntelligencePriority float64 `json:"intelligencePriority,omitempty"`
}

// ModelHint is a single model-selection hint. It mirrors mcp-go's mcp.ModelHint.
type ModelHint struct {
	// Name is treated by the client as a substring of a model name.
	Name string `json:"name,omitempty"`
}
