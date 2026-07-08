// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

// This file is the single point in the compatibility layer that references
// mcp-go. Every symbol below is re-exported from github.com/mark3labs/mcp-go/mcp
// so that migrating call sites is a pure import swap. To eventually drop the
// mcp-go dependency, replace each alias/assignment here with a standalone
// definition copied from the mcp-go source (see doc.go). The wire-format tests
// guard that conversion.

import (
	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// ----------------------------------------------------------------------------
// Protocol constants
// ----------------------------------------------------------------------------

// LATEST_PROTOCOL_VERSION mirrors mcp-go's latest supported protocol version.
//
//nolint:revive,staticcheck // name intentionally matches mcp-go for drop-in compatibility.
const LATEST_PROTOCOL_VERSION = mcpgo.LATEST_PROTOCOL_VERSION

// JSONRPC_VERSION is the JSON-RPC version used by MCP ("2.0").
//
//nolint:revive,staticcheck // name intentionally matches mcp-go for drop-in compatibility.
const JSONRPC_VERSION = mcpgo.JSONRPC_VERSION

// MCP method names.
const (
	MethodInitialize             = mcpgo.MethodInitialize
	MethodToolsList              = mcpgo.MethodToolsList
	MethodToolsCall              = mcpgo.MethodToolsCall
	MethodResourcesList          = mcpgo.MethodResourcesList
	MethodResourcesTemplatesList = mcpgo.MethodResourcesTemplatesList
	MethodResourcesRead          = mcpgo.MethodResourcesRead
	MethodPromptsList            = mcpgo.MethodPromptsList
	MethodPromptsGet             = mcpgo.MethodPromptsGet
	MethodListRoots              = mcpgo.MethodListRoots
	MethodSetLogLevel            = mcpgo.MethodSetLogLevel
	MethodPing                   = mcpgo.MethodPing
	MethodElicitationCreate      = mcpgo.MethodElicitationCreate

	// MethodNotificationInitialized indicates the client finished initialization.
	MethodNotificationInitialized = mcpgo.MethodNotificationInitialized
)

// JSON-RPC / MCP error codes.
//
//nolint:revive,staticcheck // names intentionally match mcp-go for drop-in compatibility.
const (
	PARSE_ERROR        = mcpgo.PARSE_ERROR
	INVALID_REQUEST    = mcpgo.INVALID_REQUEST
	METHOD_NOT_FOUND   = mcpgo.METHOD_NOT_FOUND
	INVALID_PARAMS     = mcpgo.INVALID_PARAMS
	INTERNAL_ERROR     = mcpgo.INTERNAL_ERROR
	RESOURCE_NOT_FOUND = mcpgo.RESOURCE_NOT_FOUND
)

// MCPMethod is the type of MCP method-name constants.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type MCPMethod = mcpgo.MCPMethod

// ----------------------------------------------------------------------------
// Errors
// ----------------------------------------------------------------------------

// ErrMethodNotFound indicates the requested method does not exist.
var ErrMethodNotFound = mcpgo.ErrMethodNotFound

// ----------------------------------------------------------------------------
// Core protocol types
// ----------------------------------------------------------------------------

type (
	// Implementation describes the name and version of an MCP implementation.
	Implementation = mcpgo.Implementation
	// ClientCapabilities represents capabilities a client may support.
	ClientCapabilities = mcpgo.ClientCapabilities
	// ServerCapabilities represents capabilities a server may support.
	ServerCapabilities = mcpgo.ServerCapabilities

	// Meta is metadata attached to a request's parameters or a result.
	Meta = mcpgo.Meta
	// Result is the base type embedded in protocol result messages.
	Result = mcpgo.Result
	// Request is the base type embedded in protocol request messages.
	Request = mcpgo.Request
	// RequestParams is the base params type carrying _meta.
	RequestParams = mcpgo.RequestParams

	// JSONRPCNotification is a JSON-RPC notification (no response expected).
	JSONRPCNotification = mcpgo.JSONRPCNotification
	// JSONRPCMessage is any JSON-RPC request/response/notification/error.
	JSONRPCMessage = mcpgo.JSONRPCMessage
	// JSONRPCResponse is a successful JSON-RPC response.
	JSONRPCResponse = mcpgo.JSONRPCResponse
	// JSONRPCError is a JSON-RPC error response.
	JSONRPCError = mcpgo.JSONRPCError
	// JSONRPCErrorDetails carries the code/message/data of a JSON-RPC error.
	JSONRPCErrorDetails = mcpgo.JSONRPCErrorDetails
	// RequestId is a JSON-RPC request identifier.
	RequestId = mcpgo.RequestId //nolint:revive // name intentionally matches mcp-go for drop-in compatibility.

	// Notification is the base of a JSON-RPC notification (method + params).
	Notification = mcpgo.Notification
	// NotificationParams carries a notification's params.
	NotificationParams = mcpgo.NotificationParams

	// EmptyResult is an empty MCP result (e.g. the response to ping).
	EmptyResult = mcpgo.EmptyResult
	// PingRequest is a ping request.
	PingRequest = mcpgo.PingRequest
)

// JSON-RPC message constructors.
var (
	// NewRequestId wraps a raw id value in a RequestId.
	NewRequestId = mcpgo.NewRequestId //nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
	// NewJSONRPCErrorDetails builds a JSONRPCErrorDetails value.
	NewJSONRPCErrorDetails = mcpgo.NewJSONRPCErrorDetails
	// NewJSONRPCResultResponse builds a successful JSONRPCResponse.
	NewJSONRPCResultResponse = mcpgo.NewJSONRPCResultResponse
)

// ----------------------------------------------------------------------------
// Initialization
// ----------------------------------------------------------------------------

type (
	// InitializeRequest is sent by the client to begin initialization.
	InitializeRequest = mcpgo.InitializeRequest
	// InitializeParams are the params of an initialize request.
	InitializeParams = mcpgo.InitializeParams
	// InitializeResult is the server's response to initialize.
	InitializeResult = mcpgo.InitializeResult
)

// ----------------------------------------------------------------------------
// Content
// ----------------------------------------------------------------------------

type (
	// Content is a polymorphic content element (text/image/audio/resource/...).
	Content = mcpgo.Content
	// Annotated is the base carrying optional Annotations.
	Annotated = mcpgo.Annotated
	// Annotations describe audience/priority/lastModified for content.
	Annotations = mcpgo.Annotations
	// Role is the role of a sampling/prompt message ("user"/"assistant").
	Role = mcpgo.Role

	// TextContent is text content.
	TextContent = mcpgo.TextContent
	// ImageContent is base64-encoded image content.
	ImageContent = mcpgo.ImageContent
	// AudioContent is base64-encoded audio content.
	AudioContent = mcpgo.AudioContent
	// EmbeddedResource embeds a resource in content.
	EmbeddedResource = mcpgo.EmbeddedResource
	// ResourceLink links to a resource.
	ResourceLink = mcpgo.ResourceLink

	// ResourceContents is the contents of a resource (text or blob).
	ResourceContents = mcpgo.ResourceContents
	// TextResourceContents is text resource contents.
	TextResourceContents = mcpgo.TextResourceContents
	// BlobResourceContents is base64 blob resource contents.
	BlobResourceContents = mcpgo.BlobResourceContents
)

// Message roles.
const (
	RoleUser      = mcpgo.RoleUser
	RoleAssistant = mcpgo.RoleAssistant
)

// Content constructors.
var (
	NewTextContent      = mcpgo.NewTextContent
	NewImageContent     = mcpgo.NewImageContent
	NewAudioContent     = mcpgo.NewAudioContent
	NewEmbeddedResource = mcpgo.NewEmbeddedResource
	NewResourceLink     = mcpgo.NewResourceLink
)

// Content type-assertion helpers.
var (
	AsTextContent          = mcpgo.AsTextContent
	AsImageContent         = mcpgo.AsImageContent
	AsAudioContent         = mcpgo.AsAudioContent
	AsEmbeddedResource     = mcpgo.AsEmbeddedResource
	AsTextResourceContents = mcpgo.AsTextResourceContents
	AsBlobResourceContents = mcpgo.AsBlobResourceContents
)

// GetTextFromContent extracts text from a content value, if any.
var GetTextFromContent = mcpgo.GetTextFromContent

// UnmarshalContent decodes a single JSON content object into the concrete
// mcp.Content implementation (TextContent, ImageContent, ...). It is used by the
// client shim to populate the Content interface fields of PromptMessage, which
// mcp-go cannot unmarshal generically.
var UnmarshalContent = mcpgo.UnmarshalContent

// NewMetaFromMap builds a *Meta from a raw map.
var NewMetaFromMap = mcpgo.NewMetaFromMap

// ----------------------------------------------------------------------------
// Logging
// ----------------------------------------------------------------------------

// LoggingLevel is the severity of a server log message, mirrored from mcp-go.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type LoggingLevel = mcpgo.LoggingLevel

// MCP logging levels, mirrored from mcp-go.
const (
	LoggingLevelDebug     = mcpgo.LoggingLevelDebug
	LoggingLevelInfo      = mcpgo.LoggingLevelInfo
	LoggingLevelNotice    = mcpgo.LoggingLevelNotice
	LoggingLevelWarning   = mcpgo.LoggingLevelWarning
	LoggingLevelError     = mcpgo.LoggingLevelError
	LoggingLevelCritical  = mcpgo.LoggingLevelCritical
	LoggingLevelAlert     = mcpgo.LoggingLevelAlert
	LoggingLevelEmergency = mcpgo.LoggingLevelEmergency
)

// ----------------------------------------------------------------------------
// Tools
// ----------------------------------------------------------------------------

type (
	// Tool describes a callable tool.
	Tool = mcpgo.Tool
	// ToolInputSchema is a tool's input JSON schema.
	ToolInputSchema = mcpgo.ToolInputSchema
	// ToolOutputSchema is a tool's output JSON schema.
	ToolOutputSchema = mcpgo.ToolOutputSchema
	// ToolAnnotation carries tool behavior hints.
	ToolAnnotation = mcpgo.ToolAnnotation

	// ToolOption configures a Tool built via NewTool.
	ToolOption = mcpgo.ToolOption
	// PropertyOption configures a schema property.
	PropertyOption = mcpgo.PropertyOption

	// CallToolRequest is a request to invoke a tool.
	CallToolRequest = mcpgo.CallToolRequest
	// CallToolParams are the params of a tool call.
	CallToolParams = mcpgo.CallToolParams
	// CallToolResult is the result of a tool call.
	CallToolResult = mcpgo.CallToolResult

	// ListToolsRequest requests the tool list.
	ListToolsRequest = mcpgo.ListToolsRequest
	// ListToolsResult is the tool list response.
	ListToolsResult = mcpgo.ListToolsResult
)

// Tool builders and result constructors.
var (
	NewTool              = mcpgo.NewTool
	NewToolWithRawSchema = mcpgo.NewToolWithRawSchema
	WithDescription      = mcpgo.WithDescription
	WithString           = mcpgo.WithString
	Required             = mcpgo.Required
	Description          = mcpgo.Description

	NewToolResultText           = mcpgo.NewToolResultText
	NewToolResultError          = mcpgo.NewToolResultError
	NewToolResultStructuredOnly = mcpgo.NewToolResultStructuredOnly
)

// ----------------------------------------------------------------------------
// Resources
// ----------------------------------------------------------------------------

type (
	// Resource is a readable resource.
	Resource = mcpgo.Resource
	// ResourceTemplate is a URI-templated resource description.
	ResourceTemplate = mcpgo.ResourceTemplate

	// ReadResourceRequest reads a resource by URI.
	ReadResourceRequest = mcpgo.ReadResourceRequest
	// ReadResourceParams are the params of a read.
	ReadResourceParams = mcpgo.ReadResourceParams
	// ReadResourceResult is the read response.
	ReadResourceResult = mcpgo.ReadResourceResult

	// ListResourcesRequest requests the resource list.
	ListResourcesRequest = mcpgo.ListResourcesRequest
	// ListResourcesResult is the resource list response.
	ListResourcesResult = mcpgo.ListResourcesResult
	// ListResourceTemplatesRequest requests the resource-template list.
	ListResourceTemplatesRequest = mcpgo.ListResourceTemplatesRequest
	// ListResourceTemplatesResult is the resource-template list response.
	ListResourceTemplatesResult = mcpgo.ListResourceTemplatesResult
)

// ----------------------------------------------------------------------------
// Prompts
// ----------------------------------------------------------------------------

type (
	// Prompt describes a prompt template.
	Prompt = mcpgo.Prompt
	// PromptArgument is a prompt template argument.
	PromptArgument = mcpgo.PromptArgument
	// PromptMessage is a message within a prompt result.
	PromptMessage = mcpgo.PromptMessage
	// PromptOption configures a Prompt built via NewPrompt.
	PromptOption = mcpgo.PromptOption

	// GetPromptRequest gets a prompt.
	GetPromptRequest = mcpgo.GetPromptRequest
	// GetPromptParams are the params of a get.
	GetPromptParams = mcpgo.GetPromptParams
	// GetPromptResult is the get response.
	GetPromptResult = mcpgo.GetPromptResult

	// ListPromptsRequest requests the prompt list.
	ListPromptsRequest = mcpgo.ListPromptsRequest
	// ListPromptsResult is the prompt list response.
	ListPromptsResult = mcpgo.ListPromptsResult
)

// Prompt builders.
var (
	NewPrompt             = mcpgo.NewPrompt
	WithPromptDescription = mcpgo.WithPromptDescription
)

// ----------------------------------------------------------------------------
// Elicitation
// ----------------------------------------------------------------------------

type (
	// ElicitationRequest is a server->client elicitation request.
	ElicitationRequest = mcpgo.ElicitationRequest
	// ElicitationParams are the params of an elicitation.
	ElicitationParams = mcpgo.ElicitationParams
	// ElicitationResult is the result of an elicitation.
	ElicitationResult = mcpgo.ElicitationResult
	// ElicitationResponse is the user's response payload.
	ElicitationResponse = mcpgo.ElicitationResponse
	// ElicitationResponseAction indicates accept/decline/cancel.
	ElicitationResponseAction = mcpgo.ElicitationResponseAction
)

// Elicitation response actions.
const (
	ElicitationResponseActionAccept  = mcpgo.ElicitationResponseActionAccept
	ElicitationResponseActionDecline = mcpgo.ElicitationResponseActionDecline
	ElicitationResponseActionCancel  = mcpgo.ElicitationResponseActionCancel
)
