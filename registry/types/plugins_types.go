// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

// Plugin is a single plugin in list and get responses or publish requests.
type Plugin struct {
	// Namespace is the namespace of the plugin.
	// The format is reverse-DNS, e.g. "io.github.user".
	Namespace string `json:"namespace"`
	// Name is the name of the plugin.
	// The format is that of identifiers, e.g. "my-plugin".
	Name string `json:"name"`
	// Description is the description of the plugin.
	Description string `json:"description"`
	// Version is the version of the plugin.
	// Any non-empty string is valid, but ideally it should be either a
	// semantic version or a commit hash.
	Version string `json:"version"`
	// Status is the status of the plugin.
	// Can be one of "active", "deprecated", or "archived".
	Status string `json:"status,omitempty"` // active, deprecated, archived
	// Title is the title of the plugin.
	// This is for human consumption, not an identifier.
	Title string `json:"title,omitempty"`
	// License is the SPDX license identifier of the plugin.
	License string `json:"license,omitempty"`
	// Repository is the source repository of the plugin.
	Repository *SkillRepository `json:"repository,omitempty"`
	// Icons is the list of icons for the plugin.
	Icons []SkillIcon `json:"icons,omitempty"`
	// Packages is the list of packages for the plugin.
	Packages []SkillPackage `json:"packages,omitempty"`
	// Metadata is the official metadata of the plugin as reported in the
	// plugin manifest file.
	Metadata map[string]any `json:"metadata,omitempty"`
	// Meta is an opaque payload with extended meta data details of the plugin.
	Meta map[string]any `json:"_meta,omitempty"`
}
