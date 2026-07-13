// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

var errToolSchemaConflict = errors.New("provide either InputSchema or RawInputSchema, not both")

// ListToolsRequest is sent from the client to request a list of tools the
// server has.
type ListToolsRequest struct {
	PaginatedRequest
	Header http.Header `json:"-"`
}

// ListToolsResult is the server's response to a tools/list request from the
// client.
type ListToolsResult struct {
	PaginatedResult
	Tools []Tool `json:"tools"`
}

// CallToolResult is the server's response to a tool call.
//
// Any errors that originate from the tool SHOULD be reported inside the result
// object, with `isError` set to true, _not_ as an MCP protocol-level error
// response. Otherwise, the LLM would not be able to see that an error occurred
// and self-correct.
//
// However, any errors in _finding_ the tool, an error indicating that the
// server does not support tool calls, or any other exceptional conditions,
// should be reported as an MCP error response.
type CallToolResult struct {
	Result
	Content []Content `json:"content"` // Can be TextContent, ImageContent, AudioContent, or EmbeddedResource
	// Structured content returned as a JSON object in the structuredContent field of a result.
	// For backwards compatibility, a tool that returns structured content SHOULD also return
	// functionally equivalent unstructured content.
	StructuredContent any `json:"structuredContent,omitempty"`
	// Whether the tool call ended in an error.
	//
	// If not set, this is assumed to be false (the call was successful).
	IsError bool `json:"isError,omitempty"`
}

// CallToolRequest is used by the client to invoke a tool provided by the server.
type CallToolRequest struct {
	Request
	Header http.Header    `json:"-"` // HTTP headers from the original request
	Params CallToolParams `json:"params"`
}

// CallToolParams are the params of a tool call.
type CallToolParams struct {
	Name      string      `json:"name"`
	Arguments any         `json:"arguments,omitempty"`
	Meta      *Meta       `json:"_meta,omitempty"`
	Task      *TaskParams `json:"task,omitempty"`
}

// GetArguments returns the Arguments as map[string]any for backward compatibility
// If Arguments is not a map, it returns an empty map
func (r CallToolRequest) GetArguments() map[string]any {
	if args, ok := r.Params.Arguments.(map[string]any); ok {
		return args
	}
	return nil
}

// GetRawArguments returns the Arguments as-is without type conversion
// This allows users to access the raw arguments in any format
func (r CallToolRequest) GetRawArguments() any {
	return r.Params.Arguments
}

// BindArguments unmarshals the Arguments into the provided struct
// This is useful for working with strongly-typed arguments
func (r CallToolRequest) BindArguments(target any) error {
	if target == nil {
		return fmt.Errorf("target must be a non-nil pointer")
	}
	// Fast-path: already raw JSON
	if raw, ok := r.Params.Arguments.(json.RawMessage); ok {
		return json.Unmarshal(raw, target)
	}
	data, err := json.Marshal(r.Params.Arguments)
	if err != nil {
		return fmt.Errorf("failed to marshal arguments: %w", err)
	}
	return json.Unmarshal(data, target)
}

// GetString returns a string argument by key, or the default value if not found
func (r CallToolRequest) GetString(key string, defaultValue string) string {
	args := r.GetArguments()
	if val, ok := args[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

// RequireString returns a string argument by key, or an error if not found or not a string
func (r CallToolRequest) RequireString(key string) (string, error) {
	args := r.GetArguments()
	if val, ok := args[key]; ok {
		if str, ok := val.(string); ok {
			return str, nil
		}
		return "", fmt.Errorf("argument %q is not a string", key)
	}
	return "", fmt.Errorf("required argument %q not found", key)
}

// GetInt returns an int argument by key, or the default value if not found
func (r CallToolRequest) GetInt(key string, defaultValue int) int {
	args := r.GetArguments()
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultValue
}

// GetFloat returns a float64 argument by key, or the default value if not found
func (r CallToolRequest) GetFloat(key string, defaultValue float64) float64 {
	args := r.GetArguments()
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case float64:
			return v
		case int:
			return float64(v)
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	}
	return defaultValue
}

// GetBool returns a bool argument by key, or the default value if not found
func (r CallToolRequest) GetBool(key string, defaultValue bool) bool {
	args := r.GetArguments()
	if val, ok := args[key]; ok {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			if b, err := strconv.ParseBool(v); err == nil {
				return b
			}
		case int:
			return v != 0
		case float64:
			return v != 0
		}
	}
	return defaultValue
}

// MarshalJSON implements custom JSON marshaling for CallToolResult
func (r CallToolResult) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)

	// Marshal Meta if present
	if r.Meta != nil {
		m["_meta"] = r.Meta
	}

	// Marshal Content array
	content := make([]any, len(r.Content))
	for i, c := range r.Content {
		content[i] = c
	}
	m["content"] = content

	// Marshal StructuredContent if present
	if r.StructuredContent != nil {
		m["structuredContent"] = r.StructuredContent
	}

	// Marshal IsError if true
	if r.IsError {
		m["isError"] = r.IsError
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling for CallToolResult
func (r *CallToolResult) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Unmarshal Meta
	if meta, ok := raw["_meta"]; ok {
		if metaMap, ok := meta.(map[string]any); ok {
			r.Meta = NewMetaFromMap(metaMap)
		}
	}

	// Unmarshal Content array
	if contentRaw, ok := raw["content"]; ok {
		if contentArray, ok := contentRaw.([]any); ok {
			r.Content = make([]Content, len(contentArray))
			for i, item := range contentArray {
				itemBytes, err := json.Marshal(item)
				if err != nil {
					return err
				}
				content, err := UnmarshalContent(itemBytes)
				if err != nil {
					return err
				}
				r.Content[i] = content
			}
		}
	}

	// Unmarshal StructuredContent if present
	if structured, ok := raw["structuredContent"]; ok {
		r.StructuredContent = structured
	}

	// Unmarshal IsError
	if isError, ok := raw["isError"]; ok {
		if isErrorBool, ok := isError.(bool); ok {
			r.IsError = isErrorBool
		}
	}

	return nil
}

// TaskSupport indicates how a tool supports task augmentation.
type TaskSupport string

const (
	// TaskSupportForbidden means the tool cannot be invoked as a task (default).
	TaskSupportForbidden TaskSupport = "forbidden"
	// TaskSupportOptional means the tool can be invoked as a task or normally.
	TaskSupportOptional TaskSupport = "optional"
	// TaskSupportRequired means the tool must be invoked as a task.
	TaskSupportRequired TaskSupport = "required"
)

// ToolExecution describes execution behavior for a tool.
type ToolExecution struct {
	// TaskSupport indicates whether the tool supports task augmentation.
	TaskSupport TaskSupport `json:"taskSupport,omitempty"`
}

// Tool represents the definition for a tool the client can call.
type Tool struct {
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta `json:"_meta,omitempty"`
	// The name of the tool.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for the tool.
	// If not provided, clients should use Annotations.Title (if set) and fall back to Name.
	Title string `json:"title,omitempty"`
	// A human-readable description of the tool.
	Description string `json:"description,omitempty"`
	// A JSON Schema object defining the expected parameters for the tool.
	InputSchema ToolInputSchema `json:"inputSchema"`
	// Alternative to InputSchema - allows arbitrary JSON Schema to be provided
	RawInputSchema json.RawMessage `json:"-"` // Hide this from JSON marshaling
	// A JSON Schema object defining the expected output returned by the tool .
	OutputSchema ToolOutputSchema `json:"outputSchema,omitzero"`
	// Optional JSON Schema defining expected output structure
	RawOutputSchema json.RawMessage `json:"-"` // Hide this from JSON marshaling
	// Optional properties describing tool behavior
	Annotations ToolAnnotation `json:"annotations"`
	// Support for deferred loading
	DeferLoading bool `json:"defer_loading,omitempty"`
	// Icons provides visual identifiers for the tool
	Icons []Icon `json:"icons,omitempty"`
	// Execution describes execution behavior for the tool
	Execution *ToolExecution `json:"execution,omitempty"`
}

// GetName returns the name of the tool.
func (t Tool) GetName() string {
	return t.Name
}

// MarshalJSON implements the json.Marshaler interface for Tool.
// It handles marshaling either InputSchema or RawInputSchema based on which is set.
func (t Tool) MarshalJSON() ([]byte, error) {
	// Create a map to build the JSON structure
	m := make(map[string]any, 5)

	// Add the name and description
	m["name"] = t.Name
	if t.Title != "" {
		m["title"] = t.Title
	}
	if t.Description != "" {
		m["description"] = t.Description
	}

	// Determine which input schema to use
	if t.RawInputSchema != nil {
		if t.InputSchema.Type != "" {
			return nil, fmt.Errorf("tool %s has both InputSchema and RawInputSchema set: %w", t.Name, errToolSchemaConflict)
		}
		m["inputSchema"] = t.RawInputSchema
	} else {
		// Use the structured InputSchema
		m["inputSchema"] = t.InputSchema
	}

	// Add output schema if present
	if t.RawOutputSchema != nil {
		if t.OutputSchema.Type != "" {
			return nil, fmt.Errorf("tool %s has both OutputSchema and RawOutputSchema set: %w", t.Name, errToolSchemaConflict)
		}
		m["outputSchema"] = t.RawOutputSchema
	} else if t.OutputSchema.Type != "" { // If no output schema is specified, do not return anything
		m["outputSchema"] = t.OutputSchema
	}

	m["annotations"] = t.Annotations

	if t.DeferLoading {
		m["defer_loading"] = t.DeferLoading
	}

	// Marshal Meta if present
	if t.Meta != nil {
		m["_meta"] = t.Meta
	}

	if t.Icons != nil {
		m["icons"] = t.Icons
	}

	if t.Execution != nil {
		m["execution"] = t.Execution
	}

	return json.Marshal(m)
}

// ToolArgumentsSchema represents a JSON Schema for tool arguments.
type ToolArgumentsSchema struct {
	Defs                 map[string]any `json:"$defs,omitempty"`
	Type                 string         `json:"type"`
	Properties           map[string]any `json:"properties"`
	Required             []string       `json:"required,omitempty"`
	AdditionalProperties any            `json:"additionalProperties,omitempty"`
}

// ToolInputSchema remains a named type for retro-compatibility, so its JSON
// methods explicitly forward to ToolArgumentsSchema.
type ToolInputSchema ToolArgumentsSchema

// ToolOutputSchema is a tool's output JSON schema.
type ToolOutputSchema ToolArgumentsSchema

// MarshalJSON implements the json.Marshaler interface for ToolInputSchema.
func (tis ToolInputSchema) MarshalJSON() ([]byte, error) {
	return ToolArgumentsSchema(tis).MarshalJSON()
}

// MarshalJSON implements the json.Marshaler interface for ToolOutputSchema.
func (tos ToolOutputSchema) MarshalJSON() ([]byte, error) {
	return ToolArgumentsSchema(tos).MarshalJSON()
}

// MarshalJSON implements the json.Marshaler interface for ToolArgumentsSchema.
func (tas ToolArgumentsSchema) MarshalJSON() ([]byte, error) {
	m := make(map[string]any)
	m["type"] = tas.Type

	if tas.Defs != nil {
		m["$defs"] = tas.Defs
	}

	// Marshal Properties to '{}' rather than `nil` when its length equals zero
	if tas.Properties != nil {
		m["properties"] = tas.Properties
	} else {
		m["properties"] = map[string]any{}
	}

	// Marshal Required to '[]' rather than `nil` when its length equals zero
	if len(tas.Required) > 0 {
		m["required"] = tas.Required
	} else {
		m["required"] = []string{}
	}

	if tas.AdditionalProperties != nil {
		m["additionalProperties"] = tas.AdditionalProperties
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements the json.Unmarshaler interface for ToolInputSchema.
func (tis *ToolInputSchema) UnmarshalJSON(data []byte) error {
	return (*ToolArgumentsSchema)(tis).UnmarshalJSON(data)
}

// UnmarshalJSON implements the json.Unmarshaler interface for ToolOutputSchema.
func (tos *ToolOutputSchema) UnmarshalJSON(data []byte) error {
	return (*ToolArgumentsSchema)(tos).UnmarshalJSON(data)
}

// UnmarshalJSON implements the json.Unmarshaler interface for ToolArgumentsSchema.
func (tas *ToolArgumentsSchema) UnmarshalJSON(data []byte) error {
	// Use a temporary type to avoid infinite recursion
	type Alias ToolArgumentsSchema
	aux := &struct {
		Definitions map[string]any `json:"definitions,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(tas),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	// If $defs wasn't provided but definitions was, use definitions
	if tas.Defs == nil && aux.Definitions != nil {
		tas.Defs = aux.Definitions
	}

	return nil
}

// ToolAnnotation carries tool behavior hints.
type ToolAnnotation struct {
	// Human-readable title for the tool
	Title string `json:"title,omitempty"`
	// If true, the tool does not modify its environment
	ReadOnlyHint *bool `json:"readOnlyHint,omitempty"`
	// If true, the tool may perform destructive updates
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	// If true, repeated calls with same args have no additional effect
	IdempotentHint *bool `json:"idempotentHint,omitempty"`
	// If true, tool interacts with external entities
	OpenWorldHint *bool `json:"openWorldHint,omitempty"`
}

// ToolOption is a function that configures a Tool.
// It provides a flexible way to set various properties of a Tool using the functional options pattern.
type ToolOption func(*Tool)

// PropertyOption is a function that configures a property in a Tool's input schema.
// It allows for flexible configuration of JSON Schema properties using the functional options pattern.
type PropertyOption func(map[string]any)

// NewTool creates a new Tool with the given name and options.
// The tool will have an object-type input schema with configurable properties.
// Options are applied in order, allowing for flexible tool configuration.
func NewTool(name string, opts ...ToolOption) Tool {
	tool := Tool{
		Name: name,
		InputSchema: ToolInputSchema{
			Type:       "object",
			Properties: make(map[string]any),
			Required:   nil, // Will be omitted from JSON if empty
		},
		Annotations: ToolAnnotation{
			Title:           "",
			ReadOnlyHint:    ToBoolPtr(false),
			DestructiveHint: ToBoolPtr(true),
			IdempotentHint:  ToBoolPtr(false),
			OpenWorldHint:   ToBoolPtr(true),
		},
	}

	for _, opt := range opts {
		opt(&tool)
	}

	return tool
}

// NewToolWithRawSchema creates a new Tool with the given name and a raw JSON
// Schema. This allows for arbitrary JSON Schema to be used for the tool's input
// schema.
//
// NOTE a [Tool] built in such a way is incompatible with the [ToolOption] and
// runtime errors will result from supplying a [ToolOption] to a [Tool] built
// with this function.
func NewToolWithRawSchema(name, description string, schema json.RawMessage) Tool {
	tool := Tool{
		Name:           name,
		Description:    description,
		RawInputSchema: schema,
	}

	return tool
}

// WithDescription adds a description to the Tool.
// The description should provide a clear, human-readable explanation of what the tool does.
func WithDescription(description string) ToolOption {
	return func(t *Tool) {
		t.Description = description
	}
}

// WithString adds a string property to the tool schema.
// It accepts property options to configure the string property's behavior and constraints.
func WithString(name string, opts ...PropertyOption) ToolOption {
	return func(t *Tool) {
		schema := map[string]any{
			"type": "string",
		}

		for _, opt := range opts {
			opt(schema)
		}

		// Remove required from property schema and add to InputSchema.required
		if required, ok := schema["required"].(bool); ok && required {
			delete(schema, "required")
			t.InputSchema.Required = append(t.InputSchema.Required, name)
		}

		t.InputSchema.Properties[name] = schema
	}
}

// Description adds a description to a property in the JSON Schema.
// The description should explain the purpose and expected values of the property.
func Description(desc string) PropertyOption {
	return func(schema map[string]any) {
		schema["description"] = desc
	}
}

// Required marks a property as required in the tool's input schema.
// Required properties must be provided when using the tool.
func Required() PropertyOption {
	return func(schema map[string]any) {
		schema["required"] = true
	}
}

// NewToolResultText creates a new CallToolResult with a text content
func NewToolResultText(text string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			TextContent{
				Type: ContentTypeText,
				Text: text,
			},
		},
	}
}

// NewToolResultError creates a new CallToolResult with an error message.
// Any errors that originate from the tool SHOULD be reported inside the result object.
func NewToolResultError(text string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{
			TextContent{
				Type: ContentTypeText,
				Text: text,
			},
		},
		IsError: true,
	}
}

// NewToolResultStructuredOnly creates a new CallToolResult with structured
// content and creates a JSON string fallback for backwards compatibility.
// This is useful when you want to provide structured data without any specific text fallback.
func NewToolResultStructuredOnly(structured any) *CallToolResult {
	var fallbackText string
	// Convert to JSON string for backward compatibility
	jsonBytes, err := json.Marshal(structured)
	if err != nil {
		fallbackText = fmt.Sprintf("Error serializing structured content: %v", err)
	} else {
		fallbackText = string(jsonBytes)
	}

	return &CallToolResult{
		Content: []Content{
			TextContent{
				Type: "text",
				Text: fallbackText,
			},
		},
		StructuredContent: structured,
	}
}
