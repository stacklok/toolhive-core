// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "errors"

// Sentinel errors for common JSON-RPC error codes.
var (
	// ErrParseError indicates a JSON parsing error (code: PARSE_ERROR).
	ErrParseError = errors.New("parse error")

	// ErrInvalidRequest indicates an invalid JSON-RPC request (code: INVALID_REQUEST).
	ErrInvalidRequest = errors.New("invalid request")

	// ErrMethodNotFound indicates the requested method does not exist (code: METHOD_NOT_FOUND).
	ErrMethodNotFound = errors.New("method not found")

	// ErrInvalidParams indicates invalid method parameters (code: INVALID_PARAMS).
	ErrInvalidParams = errors.New("invalid params")

	// ErrInternalError indicates an internal JSON-RPC error (code: INTERNAL_ERROR).
	ErrInternalError = errors.New("internal error")

	// ErrRequestInterrupted indicates a request was cancelled or timed out (code: REQUEST_INTERRUPTED).
	ErrRequestInterrupted = errors.New("request interrupted")

	// ErrResourceNotFound indicates a requested resource was not found (code: RESOURCE_NOT_FOUND).
	ErrResourceNotFound = errors.New("resource not found")
)

// ToBoolPtr returns a pointer to the given boolean value
func ToBoolPtr(b bool) *bool {
	return &b
}

// NewJSONRPCResponse creates a new JSONRPCResponse with the given id and result.
// NOTE: This function expects a Result struct, but JSONRPCResponse.Result is typed as `any`.
// The Result struct wraps the actual result data with optional metadata.
// For direct result assignment, use NewJSONRPCResultResponse instead.
func NewJSONRPCResponse(id RequestId, result Result) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPC_VERSION,
		ID:      id,
		Result:  result,
	}
}

// NewJSONRPCResultResponse creates a new JSONRPCResponse with the given id and result.
// This function accepts any type for the result, matching the JSONRPCResponse.Result field type.
func NewJSONRPCResultResponse(id RequestId, result any) JSONRPCResponse {
	return JSONRPCResponse{
		JSONRPC: JSONRPC_VERSION,
		ID:      id,
		Result:  result,
	}
}

// NewJSONRPCErrorDetails creates a new JSONRPCErrorDetails with the given code, message, and data.
func NewJSONRPCErrorDetails(code int, message string, data any) JSONRPCErrorDetails {
	return JSONRPCErrorDetails{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// NewTextContent creates a new TextContent with the given text.
func NewTextContent(text string) TextContent {
	return TextContent{
		Type: ContentTypeText,
		Text: text,
	}
}

// NewImageContent creates a new ImageContent with the given base64-encoded data and MIME type.
func NewImageContent(data, mimeType string) ImageContent {
	return ImageContent{
		Type:     ContentTypeImage,
		Data:     data,
		MIMEType: mimeType,
	}
}

// NewAudioContent creates a new AudioContent with the given base64-encoded data and MIME type.
func NewAudioContent(data, mimeType string) AudioContent {
	return AudioContent{
		Type:     ContentTypeAudio,
		Data:     data,
		MIMEType: mimeType,
	}
}

// NewResourceLink creates a new ResourceLink with the given URI, name, description, and MIME type.
func NewResourceLink(uri, name, description, mimeType string) ResourceLink {
	return ResourceLink{
		Type:        ContentTypeLink,
		URI:         uri,
		Name:        name,
		Description: description,
		MIMEType:    mimeType,
	}
}

// NewEmbeddedResource creates a new EmbeddedResource wrapping the given ResourceContents.
func NewEmbeddedResource(resource ResourceContents) EmbeddedResource {
	return EmbeddedResource{
		Type:     ContentTypeResource,
		Resource: resource,
	}
}
