// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// CompleteRequest is a request from the client to the server asking for
// argument-completion options (the completion/complete method). It mirrors
// mcp-go's mcp.CompleteRequest.
type CompleteRequest struct {
	Request
	Params CompleteParams `json:"params"`
	Header http.Header    `json:"-"`
}

// CompleteParams carries the completion reference, the argument being
// completed, and optional resolved context.
type CompleteParams struct {
	// Ref identifies what is being completed: a PromptReference
	// ({"type":"ref/prompt","name":...}) or a ResourceReference
	// ({"type":"ref/resource","uri":...}). It is typed as any to mirror
	// mcp-go, which accepts either reference shape.
	Ref any `json:"ref"`
	// Argument is the argument whose value is being completed.
	Argument CompleteArgument `json:"argument"`
	// Context carries previously-resolved argument values for multi-argument
	// completion. It is not present in older mcp-go releases; the shim adds it
	// (additively) so callers can forward the MCP completion "context" field.
	Context *CompleteContext `json:"context,omitempty"`
}

// CompleteArgument is the argument being completed.
type CompleteArgument struct {
	// The name of the argument.
	Name string `json:"name"`
	// The value of the argument to use for completion matching.
	Value string `json:"value"`
}

// CompleteContext carries additional, optional context for completions:
// previously-resolved variables in a URI template or prompt.
type CompleteContext struct {
	// Arguments maps already-resolved argument names to their values.
	Arguments map[string]string `json:"arguments,omitempty"`
}

// CompleteResult is the server's response to a completion/complete request. It
// mirrors mcp-go's mcp.CompleteResult.
type CompleteResult struct {
	Result
	Completion CompletionResultDetails `json:"completion"`
}

// CompletionResultDetails carries the completion values and pagination hints.
type CompletionResultDetails struct {
	// An array of completion values. Must not exceed 100 items.
	Values []string `json:"values"`
	// The total number of completion options available. This can exceed the
	// number of values actually sent in the response.
	Total int `json:"total,omitempty"`
	// Indicates whether there are additional completion options beyond those
	// provided in the current response, even if the exact total is unknown.
	HasMore bool `json:"hasMore,omitempty"`
}

// ResourceReference is a reference to a resource or resource-template
// definition, used as the CompleteParams.Ref for resource completions.
type ResourceReference struct {
	Type string `json:"type"`
	// The URI or URI template of the resource.
	URI string `json:"uri"`
}

// PromptReference identifies a prompt, used as the CompleteParams.Ref for
// prompt-argument completions.
type PromptReference struct {
	Type string `json:"type"`
	// The name of the prompt or prompt template.
	Name string `json:"name"`
}
