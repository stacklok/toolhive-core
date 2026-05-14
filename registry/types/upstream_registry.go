// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	upstreamv0 "github.com/modelcontextprotocol/registry/pkg/api/v0"
)

// UpstreamRegistrySchemaURL is the canonical URL for the upstream registry JSON schema.
const UpstreamRegistrySchemaURL = "https://raw.githubusercontent.com/stacklok/toolhive-core/main/" +
	"registry/types/data/upstream-registry.schema.json"

// UpstreamRegistry is the unified registry format that stores servers in upstream
// ServerJSON format with proper meta/data separation.
type UpstreamRegistry struct {
	// Schema is the JSON schema URL for validation
	Schema string `json:"$schema" yaml:"$schema"`

	// Version is the schema version (e.g., "1.0.0")
	Version string `json:"version" yaml:"version"`

	// Meta contains registry metadata
	Meta UpstreamMeta `json:"meta" yaml:"meta"`

	// Data contains the actual registry content
	Data UpstreamData `json:"data" yaml:"data"`
}

// UpstreamMeta contains metadata about the registry
type UpstreamMeta struct {
	// LastUpdated is the timestamp when registry was last updated in RFC3339 format
	LastUpdated string `json:"last_updated" yaml:"last_updated"`
}

// UpstreamData contains the actual registry content (servers and skills)
type UpstreamData struct {
	// Servers contains the server definitions in upstream MCP format
	Servers []upstreamv0.ServerJSON `json:"servers" yaml:"servers"`

	// Skills contains the skill definitions
	Skills []Skill `json:"skills,omitempty" yaml:"skills,omitempty"`
}
