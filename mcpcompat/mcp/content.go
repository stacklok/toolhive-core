// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
)

// Content is a polymorphic content element (text/image/audio/resource/...).
type Content interface {
	isContent()
}

// Annotated is the base for objects that include optional annotations for the
// client. The client can use annotations to inform how objects are used or
// displayed
type Annotated struct {
	Annotations *Annotations `json:"annotations,omitempty"`
}

// Annotations describe audience/priority/lastModified for content.
type Annotations struct {
	// Describes who the intended customer of this object or data is.
	//
	// It can include multiple entries to indicate content useful for multiple
	// audiences (e.g., `["user", "assistant"]`).
	Audience []Role `json:"audience,omitempty"`

	// Describes how important this data is for operating the server.
	//
	// A value of 1 means "most important," and indicates that the data is
	// effectively required, while 0 means "least important," and indicates that
	// the data is entirely optional.
	// Priority ranges from 0.0 to 1.0 (1 = most important, 0 = least important).
	Priority *float64 `json:"priority,omitempty"`
	// ISO 8601 formatted timestamp (e.g., "2025-01-12T15:00:58Z")
	LastModified string `json:"lastModified,omitempty"`
}

// TextContent represents text provided to or from an LLM.
// It must have Type set to "text".
type TextContent struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta  `json:"_meta,omitempty"`
	Type string `json:"type"` // Must be "text"
	// The text content of the message.
	Text string `json:"text"`
}

func (TextContent) isContent() {}

// ImageContent represents an image provided to or from an LLM.
// It must have Type set to "image".
type ImageContent struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta  `json:"_meta,omitempty"`
	Type string `json:"type"` // Must be "image"
	// The base64-encoded image data.
	Data string `json:"data"`
	// The MIME type of the image. Different providers may support different image types.
	MIMEType string `json:"mimeType"`
}

func (ImageContent) isContent() {}

// AudioContent represents the contents of audio, embedded into a prompt or tool call result.
// It must have Type set to "audio".
type AudioContent struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta  `json:"_meta,omitempty"`
	Type string `json:"type"` // Must be "audio"
	// The base64-encoded audio data.
	Data string `json:"data"`
	// The MIME type of the audio. Different providers may support different audio types.
	MIMEType string `json:"mimeType"`
}

func (AudioContent) isContent() {}

// ResourceLink represents a link to a resource that the client can access.
type ResourceLink struct {
	Annotated
	Type string `json:"type"` // Must be "resource_link"
	// The URI of the resource.
	URI string `json:"uri"`
	// The name of the resource.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for this resource.
	// If not provided, clients should fall back to Name.
	Title string `json:"title,omitempty"`
	// The description of the resource.
	Description string `json:"description"`
	// The MIME type of the resource.
	MIMEType string `json:"mimeType"`
	// Size is the size of the raw resource content, in bytes (i.e., before base64
	// encoding or any tokenization), if known. This can be used by hosts to
	// display file sizes and estimate context window usage.
	//
	// A pointer is used so that an explicit zero size remains distinguishable
	// from an unset value.
	Size *int64 `json:"size,omitempty"`
}

func (ResourceLink) isContent() {}

// EmbeddedResource represents the contents of a resource, embedded into a prompt or tool call result.
//
// It is up to the client how best to render embedded resources for the
// benefit of the LLM and/or the user.
type EmbeddedResource struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta     *Meta            `json:"_meta,omitempty"`
	Type     string           `json:"type"`
	Resource ResourceContents `json:"resource"`
}

func (EmbeddedResource) isContent() {}

// embeddedResourceJSON is a helper type for unmarshaling EmbeddedResource. It
// mirrors EmbeddedResource but keeps the resource as a raw message so the
// ResourceContents interface field can be decoded into a concrete type.
type embeddedResourceJSON struct {
	Annotated
	Meta     *Meta           `json:"_meta,omitempty"`
	Type     string          `json:"type"`
	Resource json.RawMessage `json:"resource"`
}

// UnmarshalJSON implements custom JSON unmarshaling for EmbeddedResource.
// The Resource field is a ResourceContents interface, which encoding/json
// cannot populate directly. The nested resource object is decoded into the
// concrete TextResourceContents or BlobResourceContents type based on the
// presence of the "blob" (blob resource) or "text" (text resource) field,
// mirroring the text/blob selection used elsewhere in the shim.
func (er *EmbeddedResource) UnmarshalJSON(data []byte) error {
	var raw embeddedResourceJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	er.Annotated = raw.Annotated
	er.Meta = raw.Meta
	er.Type = raw.Type

	// An absent or JSON-null resource leaves Resource nil.
	if len(raw.Resource) == 0 || string(raw.Resource) == "null" {
		er.Resource = nil
		return nil
	}

	resource, err := unmarshalResourceContents(raw.Resource)
	if err != nil {
		return fmt.Errorf("unmarshaling embedded resource contents: %w", err)
	}
	er.Resource = resource
	return nil
}

// unmarshalResourceContents decodes a single JSON resource-contents object into
// the concrete ResourceContents implementation. A blob resource carries a
// "blob" field; a text resource carries "text". This mirrors the text/blob
// selection performed by the client shim's convertReadResourceResult.
func unmarshalResourceContents(data []byte) (ResourceContents, error) {
	var probe struct {
		Blob *string `json:"blob"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	if probe.Blob != nil {
		var blob BlobResourceContents
		if err := json.Unmarshal(data, &blob); err != nil {
			return nil, err
		}
		return blob, nil
	}
	var text TextResourceContents
	if err := json.Unmarshal(data, &text); err != nil {
		return nil, err
	}
	return text, nil
}

// ToolUseContent represents a request from the assistant to call a tool within a sampling message.
// It must have Type set to "tool_use".
type ToolUseContent struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta  `json:"_meta,omitempty"`
	Type string `json:"type"` // Must be "tool_use"
	// ID is a unique identifier for this tool use, used to match tool results to their corresponding tool uses.
	ID string `json:"id"`
	// Name is the name of the tool to call.
	Name string `json:"name"`
	// Input contains the arguments to pass to the tool, conforming to the tool's input schema.
	Input any `json:"input"`
}

func (ToolUseContent) isContent() {}

// ToolResultContent represents the result of a tool invocation within a sampling message.
// It must have Type set to "tool_result".
type ToolResultContent struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta  `json:"_meta,omitempty"`
	Type string `json:"type"` // Must be "tool_result"
	// ToolUseID is the ID of the tool use this result corresponds to.
	// This MUST match the ID from a previous ToolUseContent.
	ToolUseID string `json:"toolUseId"`
	// Content is the unstructured result content of the tool use.
	Content []Content `json:"content"`
	// Whether the tool use resulted in an error.
	IsError bool `json:"isError,omitempty"`
}

func (ToolResultContent) isContent() {}

// toolResultContentJSON is a helper type for unmarshaling ToolResultContent.
type toolResultContentJSON struct {
	Annotated
	Meta      *Meta             `json:"_meta,omitempty"`
	Type      string            `json:"type"`
	ToolUseID string            `json:"toolUseId"`
	Content   []json.RawMessage `json:"content"`
	IsError   bool              `json:"isError,omitempty"`
}

// UnmarshalJSON implements custom JSON unmarshaling for ToolResultContent
// to handle the nested Content interface slice.
func (t *ToolResultContent) UnmarshalJSON(data []byte) error {
	var raw toolResultContentJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t.Annotated = raw.Annotated
	t.Meta = raw.Meta
	t.Type = raw.Type
	t.ToolUseID = raw.ToolUseID
	t.IsError = raw.IsError

	if len(raw.Content) > 0 {
		t.Content = make([]Content, 0, len(raw.Content))
		for _, rawContent := range raw.Content {
			c, err := UnmarshalContent(rawContent)
			if err != nil {
				return fmt.Errorf("unmarshaling tool result content: %w", err)
			}
			t.Content = append(t.Content, c)
		}
	}
	return nil
}

// MarshalContent marshals a Content value to JSON.
func MarshalContent(content Content) ([]byte, error) {
	return json.Marshal(content)
}

// UnmarshalContent decodes a single JSON content object into the concrete
// Content implementation (TextContent, ImageContent, ...). It is used by the
// client shim to populate the Content interface fields of PromptMessage, which
// cannot be unmarshaled generically.
func UnmarshalContent(data []byte) (Content, error) {
	var raw struct {
		Type any `json:"type"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	contentType, ok := raw.Type.(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid type field")
	}

	switch contentType {
	case ContentTypeText:
		var content TextContent
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeImage:
		var content ImageContent
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeAudio:
		var content AudioContent
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeLink:
		var content ResourceLink
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeResource:
		var content EmbeddedResource
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeToolUse:
		var content ToolUseContent
		err := json.Unmarshal(data, &content)
		return content, err
	case ContentTypeToolResult:
		var content ToolResultContent
		err := json.Unmarshal(data, &content)
		return content, err
	default:
		return nil, fmt.Errorf("unknown content type: %s", contentType)
	}
}

// asType attempts to cast the given interface to the given type
func asType[T any](content any) (*T, bool) {
	tc, ok := content.(T)
	if !ok {
		return nil, false
	}
	return &tc, true
}

// AsTextContent attempts to cast the given interface to TextContent
func AsTextContent(content any) (*TextContent, bool) {
	return asType[TextContent](content)
}

// AsImageContent attempts to cast the given interface to ImageContent
func AsImageContent(content any) (*ImageContent, bool) {
	return asType[ImageContent](content)
}

// AsAudioContent attempts to cast the given interface to AudioContent
func AsAudioContent(content any) (*AudioContent, bool) {
	return asType[AudioContent](content)
}

// AsEmbeddedResource attempts to cast the given interface to EmbeddedResource
func AsEmbeddedResource(content any) (*EmbeddedResource, bool) {
	return asType[EmbeddedResource](content)
}

// AsToolUseContent attempts to cast the given interface to ToolUseContent
func AsToolUseContent(content any) (*ToolUseContent, bool) {
	return asType[ToolUseContent](content)
}

// AsToolResultContent attempts to cast the given interface to ToolResultContent
func AsToolResultContent(content any) (*ToolResultContent, bool) {
	return asType[ToolResultContent](content)
}

// AsTextResourceContents attempts to cast the given interface to TextResourceContents
func AsTextResourceContents(content any) (*TextResourceContents, bool) {
	return asType[TextResourceContents](content)
}

// AsBlobResourceContents attempts to cast the given interface to BlobResourceContents
func AsBlobResourceContents(content any) (*BlobResourceContents, bool) {
	return asType[BlobResourceContents](content)
}

// GetTextFromContent extracts text from a Content interface that might be a TextContent struct
// or a map[string]any that was unmarshaled from JSON. This is useful when dealing with content
// that comes from different transport layers that may handle JSON differently.
//
// This function uses fallback behavior for non-text content - it returns a string representation
// via fmt.Sprintf for any content that cannot be extracted as text. This is a lossy operation
// intended for convenience in logging and display scenarios.
func GetTextFromContent(content any) string {
	switch c := content.(type) {
	case TextContent:
		return c.Text
	case map[string]any:
		// Handle JSON unmarshaled content
		if contentType, exists := c["type"]; exists && contentType == "text" {
			if text, exists := c["text"].(string); exists {
				return text
			}
		}
		return fmt.Sprintf("%v", content)
	case string:
		return c
	default:
		return fmt.Sprintf("%v", content)
	}
}
