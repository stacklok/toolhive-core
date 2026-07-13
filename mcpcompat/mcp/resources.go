// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// ResourceContents represents the contents of a specific resource or sub-
// resource.
type ResourceContents interface {
	isResourceContents()
}

// TextResourceContents is text resource contents.
type TextResourceContents struct {
	// Raw per-resource metadata; pass-through as defined by MCP. Not the same as Meta.
	// Allows _meta to be used for MCP-UI features for example. Does not assume any specific format.
	Meta map[string]any `json:"_meta,omitempty"`
	// The URI of this resource.
	URI string `json:"uri"`
	// The MIME type of this resource, if known.
	MIMEType string `json:"mimeType,omitempty"`
	// The text of the item. This must only be set if the item can actually be
	// represented as text (not binary data).
	Text string `json:"text"`
}

func (TextResourceContents) isResourceContents() {}

// BlobResourceContents is base64 blob resource contents.
type BlobResourceContents struct {
	// Raw per-resource metadata; pass-through as defined by MCP. Not the same as Meta.
	// Allows _meta to be used for MCP-UI features for example. Does not assume any specific format.
	Meta map[string]any `json:"_meta,omitempty"`
	// The URI of this resource.
	URI string `json:"uri"`
	// The MIME type of this resource, if known.
	MIMEType string `json:"mimeType,omitempty"`
	// A base64-encoded string representing the binary data of the item.
	Blob string `json:"blob"`
}

func (BlobResourceContents) isResourceContents() {}

// Resource represents a known resource that the server is capable of reading.
type Resource struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta `json:"_meta,omitempty"`
	// The URI of this resource.
	URI string `json:"uri"`
	// A human-readable name for this resource.
	//
	// This can be used by clients to populate UI elements.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for this resource.
	// If not provided, clients should fall back to Name.
	Title string `json:"title,omitempty"`
	// A description of what this resource represents.
	//
	// This can be used by clients to improve the LLM's understanding of
	// available resources. It can be thought of like a "hint" to the model.
	Description string `json:"description,omitempty"`
	// The MIME type of this resource, if known.
	MIMEType string `json:"mimeType,omitempty"`
	// Icons provides visual identifiers for the resource
	Icons []Icon `json:"icons,omitempty"`
	// Size is the size of the raw resource content, in bytes (i.e., before base64
	// encoding or any tokenization), if known. This can be used by hosts to
	// display file sizes and estimate context window usage.
	//
	// A pointer is used so that an explicit zero size remains distinguishable
	// from an unset value.
	Size *int64 `json:"size,omitempty"`
}

// GetName returns the name of the resource.
func (r Resource) GetName() string {
	return r.Name
}

// ResourceTemplate represents a template description for resources available
// on the server.
type ResourceTemplate struct {
	Annotated
	// Meta is a metadata object that is reserved by MCP for storing additional information.
	Meta *Meta `json:"_meta,omitempty"`
	// A URI template (according to RFC 6570) that can be used to construct
	// resource URIs.
	URITemplate string `json:"uriTemplate"`
	// A human-readable name for the type of resource this template refers to.
	//
	// This can be used by clients to populate UI elements.
	Name string `json:"name"`
	// Title is an optional human-readable, UI-friendly display name for this resource template.
	// If not provided, clients should fall back to Name.
	Title string `json:"title,omitempty"`
	// A description of what this template is for.
	//
	// This can be used by clients to improve the LLM's understanding of
	// available resources. It can be thought of like a "hint" to the model.
	Description string `json:"description,omitempty"`
	// The MIME type for all resources that match this template. This should only
	// be included if all resources matching this template have the same type.
	MIMEType string `json:"mimeType,omitempty"`
	// Icons provides visual identifiers for the resource template
	Icons []Icon `json:"icons,omitempty"`
}

// GetName returns the name of the resourceTemplate.
func (rt ResourceTemplate) GetName() string {
	return rt.Name
}

// PaginatedRequest is the base for paginated list requests.
type PaginatedRequest struct {
	Request
	Params PaginatedParams `json:"params,omitzero"`
}

// PaginatedParams carries the cursor and _meta for a paginated request.
type PaginatedParams struct {
	// An opaque token representing the current pagination position.
	// If provided, the server should return results starting after this cursor.
	Cursor Cursor `json:"cursor,omitempty"`
	// Meta carries protocol-level metadata. PaginatedRequest embeds Request
	// and shadows its Params with this type, so Meta must be declared here
	// to be marshaled on paginated requests (tools/list, resources/list,
	// resources/templates/list, prompts/list, tasks/list).
	Meta *Meta `json:"_meta,omitempty"`
}

// PaginatedResult is the base for paginated list results.
type PaginatedResult struct {
	Result
	// An opaque token representing the pagination position after the last
	// returned result.
	// If present, there may be more results available.
	NextCursor Cursor `json:"nextCursor,omitempty"`
}

// ListResourcesRequest is sent from the client to request a list of resources
// the server has.
type ListResourcesRequest struct {
	PaginatedRequest
	Header http.Header `json:"-"`
}

// ListResourcesResult is the server's response to a resources/list request
// from the client.
type ListResourcesResult struct {
	PaginatedResult
	Resources []Resource `json:"resources"`
}

// ListResourceTemplatesRequest is sent from the client to request a list of
// resource templates the server has.
type ListResourceTemplatesRequest struct {
	PaginatedRequest
	Header http.Header `json:"-"`
}

// ListResourceTemplatesResult is the server's response to a
// resources/templates/list request from the client.
type ListResourceTemplatesResult struct {
	PaginatedResult
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
}

// ReadResourceRequest is sent from the client to the server, to read a
// specific resource URI.
type ReadResourceRequest struct {
	Request
	Header http.Header        `json:"-"`
	Params ReadResourceParams `json:"params"`
}

// ReadResourceParams are the params of a read.
type ReadResourceParams struct {
	// The URI of the resource to read. The URI can use any protocol; it is up
	// to the server how to interpret it.
	URI string `json:"uri"`
	// Arguments to pass to the resource handler
	Arguments map[string]any `json:"arguments,omitempty"`
	// Meta carries protocol-level metadata (e.g. W3C traceparent, progressToken).
	Meta *Meta `json:"_meta,omitempty"`
}

// ReadResourceResult is the server's response to a resources/read request
// from the client.
type ReadResourceResult struct {
	Result
	Contents []ResourceContents `json:"contents"` // Can be TextResourceContents or BlobResourceContents
}
