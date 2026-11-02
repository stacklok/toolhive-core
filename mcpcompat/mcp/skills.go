// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The Skills extension (SEP-2640) serves Agent Skills over MCP: each file of a
// skill is a resource, skills/list enumerates the skills a server serves and
// skills/get returns one skill's entry by URI. Both are required of a server
// declaring the extension. The optional resources/directory/read lists the
// direct children of a directory resource; a server serves it only when it
// declares the directoryRead setting. mcp-go has no equivalent; the shim
// models all three methods so a server can serve them and a client, such as a
// proxy, can call them. See
// https://modelcontextprotocol.io/seps/2640-skills-extension.
const (
	// ExtensionSkills is the name a server declares the Skills extension under,
	// in its capabilities.extensions.
	ExtensionSkills = "io.modelcontextprotocol/skills"

	// MethodSkillsList enumerates the skills a server serves.
	MethodSkillsList MCPMethod = "skills/list"

	// MethodSkillsGet returns the entry for a single skill by URI.
	MethodSkillsGet MCPMethod = "skills/get"

	// MethodResourcesDirectoryRead lists the direct children of a directory
	// resource. It is optional, gated by SkillsSettingDirectoryRead.
	MethodResourcesDirectoryRead MCPMethod = "resources/directory/read"

	// SkillsSettingDirectoryRead is the Skills extension setting a server
	// declares, as true, when it serves resources/directory/read.
	SkillsSettingDirectoryRead = "directoryRead"

	// MIMETypeDirectory is the MIME type of a directory resource, as listed by
	// resources/directory/read.
	MIMETypeDirectory = "inode/directory"

	// SkillResourcesDynamic is the wire value of a skill's resources when its
	// content is generated dynamically and cannot carry stable digests.
	SkillResourcesDynamic = "dynamic"
)

// ListSkillsRequest is a skills/list request. It carries an optional
// pagination cursor.
type ListSkillsRequest struct {
	PaginatedRequest
}

// ListSkillsResult is the server's response to a skills/list request. The
// listing may be empty or partial; a host must not take it as proof that the
// server has no other skills.
type ListSkillsResult struct {
	PaginatedResult
	Skills []Skill `json:"skills"`
}

// GetSkillRequest is a skills/get request.
type GetSkillRequest struct {
	Request
	Params GetSkillParams `json:"params"`
}

// GetSkillParams names the skill to return.
type GetSkillParams struct {
	// URI is the URI of the skill's SKILL.md.
	URI string `json:"uri"`
	// Meta carries protocol-level metadata. GetSkillRequest shadows Request's
	// Params with this type, so Meta must be declared here to be marshaled.
	Meta *Meta `json:"_meta,omitempty"`
}

// GetSkillResult is the server's response to a skills/get request. A server
// answers a URI that names no skill it serves with JSON-RPC error -32602
// (INVALID_PARAMS).
type GetSkillResult struct {
	Result
	Skill Skill `json:"skill"`
}

// ReadDirectoryRequest is a resources/directory/read request.
type ReadDirectoryRequest struct {
	Request
	Params ReadDirectoryParams `json:"params"`
}

// ReadDirectoryParams names the directory to list.
type ReadDirectoryParams struct {
	// URI is the directory resource's URI, written without a trailing slash.
	URI string `json:"uri"`
	// Cursor continues a paginated listing, as for resources/list.
	Cursor Cursor `json:"cursor,omitempty"`
	// Meta carries protocol-level metadata. ReadDirectoryRequest shadows
	// Request's Params with this type, so Meta must be declared here to be
	// marshaled.
	Meta *Meta `json:"_meta,omitempty"`
}

// ReadDirectoryResult is the server's response to a resources/directory/read
// request: the resource metadata of the directory's direct children, files
// with their ordinary metadata and subdirectories with MIMEType
// MIMETypeDirectory. The listing is not recursive. A server answers a URI
// that does not exist, or is not a directory, with JSON-RPC error -32602
// (INVALID_PARAMS).
type ReadDirectoryResult struct {
	PaginatedResult
	Resources []Resource `json:"resources"`
}

// Skill is a skill entry, as skills/list and skills/get return it.
type Skill struct {
	// URI is the resource URI of the skill's SKILL.md. Its final path segment
	// before SKILL.md equals Frontmatter["name"].
	URI string `json:"uri"`
	// Frontmatter is the SKILL.md YAML frontmatter rendered as JSON, verbatim.
	// It always holds name and description; every other field the author
	// wrote passes through.
	Frontmatter map[string]any `json:"frontmatter"`
	// Resources lists the skill's files, or marks its content as dynamic.
	Resources SkillResources `json:"resources"`
}

// SkillResources is the resources member of a skill entry, which is either
// the complete list of the skill's files or the string "dynamic".
type SkillResources struct {
	// Dynamic reports that the skill's content is generated dynamically, so
	// it carries no file list. Files is ignored when Dynamic is true.
	Dynamic bool
	// Files lists every file of the skill, SKILL.md included.
	Files []SkillResource
}

// SkillResource is one file of a skill.
type SkillResource struct {
	// URI is the resource URI of the file.
	URI string `json:"uri"`
	// Digest is the SHA-256 of the file's raw bytes, as "sha256:{hex}".
	Digest string `json:"digest"`
	// Size is the length in bytes of the file's raw content.
	Size int64 `json:"size"`
}

// MarshalJSON encodes the resources as "dynamic" or as the file list. A
// non-dynamic value with no Files encodes as null rather than an empty list,
// so an entry that arrived without resources, which the extension defines as
// invalid, stays recognizably invalid when passed on.
func (r SkillResources) MarshalJSON() ([]byte, error) {
	if r.Dynamic {
		return json.Marshal(SkillResourcesDynamic)
	}
	return json.Marshal(r.Files)
}

// UnmarshalJSON decodes either form of the resources member. It rejects any
// string other than "dynamic", and any other non-array value except null.
func (r *SkillResources) UnmarshalJSON(data []byte) error {
	// Branch on the token rather than trying a string decode first: JSON null
	// decodes into a Go string without error, which would misread it as "".
	if trimmed := bytes.TrimSpace(data); len(trimmed) > 0 && trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return fmt.Errorf("skill resources: %w", err)
		}
		if s != SkillResourcesDynamic {
			return fmt.Errorf("skill resources: unexpected string %q", s)
		}
		*r = SkillResources{Dynamic: true}
		return nil
	}
	var files []SkillResource
	if err := json.Unmarshal(data, &files); err != nil {
		return fmt.Errorf("skill resources: %w", err)
	}
	*r = SkillResources{Files: files}
	return nil
}
