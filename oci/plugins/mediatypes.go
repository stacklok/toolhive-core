// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Artifact type for plugin identification.
const (
	// ArtifactTypePlugin identifies plugin artifacts in manifests.
	ArtifactTypePlugin = "dev.toolhive.plugins.v1"
)

// Annotation keys for plugin metadata in manifests.
const (
	// AnnotationPluginName is the annotation key for plugin name.
	AnnotationPluginName = "dev.toolhive.plugins.name"

	// AnnotationPluginDescription is the annotation key for plugin description.
	AnnotationPluginDescription = "dev.toolhive.plugins.description"

	// AnnotationPluginVersion is the annotation key for plugin version.
	AnnotationPluginVersion = "dev.toolhive.plugins.version"

	// AnnotationPluginLicense is the annotation key for plugin license.
	AnnotationPluginLicense = "dev.toolhive.plugins.license"

	// AnnotationPluginFiles is the annotation key for plugin files (JSON array).
	AnnotationPluginFiles = "dev.toolhive.plugins.files"

	// AnnotationPluginComponents is the annotation key for plugin component inventory (JSON object).
	AnnotationPluginComponents = "dev.toolhive.plugins.components"

	// AnnotationPluginRequires is the annotation key for plugin external dependencies (JSON array of OCI references).
	AnnotationPluginRequires = "dev.toolhive.plugins.requires"
)

// Label keys for plugin metadata in OCI image config.
const (
	// LabelPluginName is the label key for plugin name.
	LabelPluginName = "dev.toolhive.plugins.name"

	// LabelPluginDescription is the label key for plugin description.
	LabelPluginDescription = "dev.toolhive.plugins.description"

	// LabelPluginVersion is the label key for plugin version.
	LabelPluginVersion = "dev.toolhive.plugins.version"

	// LabelPluginLicense is the label key for plugin license.
	LabelPluginLicense = "dev.toolhive.plugins.license"

	// LabelPluginFiles is the label key for plugin files (JSON array).
	LabelPluginFiles = "dev.toolhive.plugins.files"

	// LabelPluginComponents is the label key for plugin component inventory (JSON object).
	LabelPluginComponents = "dev.toolhive.plugins.components"

	// LabelPluginRequires is the label key for plugin external dependencies (JSON array of OCI references).
	LabelPluginRequires = "dev.toolhive.plugins.requires"
)

// ComponentInventory summarizes the component types declared by a plugin.
type ComponentInventory map[string]int

// PluginConfig represents plugin metadata extracted from OCI image config labels.
type PluginConfig struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Version     string             `json:"version,omitempty"`
	License     string             `json:"license,omitempty"`
	Files       []string           `json:"files"`
	Components  ComponentInventory `json:"components,omitempty"`
	Requires    []string           `json:"requires,omitempty"`
}

// PluginConfigFromImageConfig extracts PluginConfig from OCI image config labels.
func PluginConfigFromImageConfig(imgConfig *ocispec.Image) (*PluginConfig, error) {
	if imgConfig == nil {
		return nil, fmt.Errorf("image config is nil")
	}

	labels := imgConfig.Config.Labels
	if labels == nil {
		return nil, fmt.Errorf("oci config has no labels")
	}

	config := &PluginConfig{
		Name:        labels[LabelPluginName],
		Description: labels[LabelPluginDescription],
		Version:     labels[LabelPluginVersion],
		License:     labels[LabelPluginLicense],
	}

	if config.Name == "" {
		return nil, fmt.Errorf("plugin name is required in labels")
	}

	// Parse JSON-encoded metadata.
	if filesJSON := labels[LabelPluginFiles]; filesJSON != "" {
		if err := json.Unmarshal([]byte(filesJSON), &config.Files); err != nil {
			return nil, fmt.Errorf("parsing files: %w", err)
		}
	}

	if componentsJSON := labels[LabelPluginComponents]; componentsJSON != "" {
		if err := json.Unmarshal([]byte(componentsJSON), &config.Components); err != nil {
			return nil, fmt.Errorf("parsing components: %w", err)
		}
	}

	if requiresJSON := labels[LabelPluginRequires]; requiresJSON != "" {
		if err := json.Unmarshal([]byte(requiresJSON), &config.Requires); err != nil {
			return nil, fmt.Errorf("parsing requires: %w", err)
		}
	}

	return config, nil
}

// ParseComponentsAnnotation parses plugin component inventory from manifest annotations.
// Returns nil if the annotation is missing or invalid.
func ParseComponentsAnnotation(annotations map[string]string) ComponentInventory {
	componentsJSON := annotations[AnnotationPluginComponents]
	if componentsJSON == "" {
		return nil
	}

	var components ComponentInventory
	if err := json.Unmarshal([]byte(componentsJSON), &components); err != nil {
		// Invalid annotation format - return nil rather than propagating error
		// since annotations may come from older versions or external sources.
		return nil
	}
	return components
}

// ParseRequiresAnnotation parses plugin dependency references from manifest annotations.
// Returns nil if the annotation is missing or invalid.
func ParseRequiresAnnotation(annotations map[string]string) []string {
	requiresJSON := annotations[AnnotationPluginRequires]
	if requiresJSON == "" {
		return nil
	}

	var refs []string
	if err := json.Unmarshal([]byte(requiresJSON), &refs); err != nil {
		// Invalid annotation format - return nil rather than propagating error
		// since annotations may come from older versions or external sources.
		return nil
	}
	return refs
}
