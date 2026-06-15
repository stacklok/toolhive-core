// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Artifact type for skill identification.
const (
	// ArtifactTypeSkill identifies skill artifacts in manifests.
	ArtifactTypeSkill = "dev.toolhive.skills.v1"
)

// Annotation keys for skill metadata in manifests.
const (
	// AnnotationSkillName is the annotation key for skill name.
	AnnotationSkillName = "dev.toolhive.skills.name"

	// AnnotationSkillDescription is the annotation key for skill description.
	AnnotationSkillDescription = "dev.toolhive.skills.description"

	// AnnotationSkillVersion is the annotation key for skill version.
	AnnotationSkillVersion = "dev.toolhive.skills.version"

	// AnnotationSkillRequires is the annotation key for skill external dependencies (JSON array of OCI references).
	AnnotationSkillRequires = "dev.toolhive.skills.requires"
)

// Label keys for skill metadata in OCI image config.
const (
	// LabelSkillName is the label key for skill name.
	LabelSkillName = "dev.toolhive.skills.name"

	// LabelSkillDescription is the label key for skill description.
	LabelSkillDescription = "dev.toolhive.skills.description"

	// LabelSkillVersion is the label key for skill version.
	LabelSkillVersion = "dev.toolhive.skills.version"

	// LabelSkillAllowedTools is the label key for allowed tools (JSON array).
	LabelSkillAllowedTools = "dev.toolhive.skills.allowedTools"

	// LabelSkillLicense is the label key for skill license.
	LabelSkillLicense = "dev.toolhive.skills.license"

	// LabelSkillFiles is the label key for skill files (JSON array).
	LabelSkillFiles = "dev.toolhive.skills.files"
)

// SkillConfig represents skill metadata extracted from OCI image config labels.
type SkillConfig struct {
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Version       string            `json:"version,omitempty"`
	AllowedTools  []string          `json:"allowedTools,omitempty"`
	License       string            `json:"license,omitempty"`
	Compatibility string            `json:"compatibility,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Files         []string          `json:"files"`
}

// SkillConfigFromImageConfig extracts SkillConfig from OCI image config labels.
func SkillConfigFromImageConfig(imgConfig *ocispec.Image) (*SkillConfig, error) {
	if imgConfig == nil {
		return nil, fmt.Errorf("image config is nil")
	}

	labels := imgConfig.Config.Labels
	if labels == nil {
		return nil, fmt.Errorf("oci config has no labels")
	}

	config := &SkillConfig{
		Name:        labels[LabelSkillName],
		Description: labels[LabelSkillDescription],
		Version:     labels[LabelSkillVersion],
		License:     labels[LabelSkillLicense],
	}

	if config.Name == "" {
		return nil, fmt.Errorf("skill name is required in labels")
	}

	// Parse JSON-encoded arrays
	if toolsJSON := labels[LabelSkillAllowedTools]; toolsJSON != "" {
		if err := json.Unmarshal([]byte(toolsJSON), &config.AllowedTools); err != nil {
			return nil, fmt.Errorf("parsing allowed tools: %w", err)
		}
	}

	if filesJSON := labels[LabelSkillFiles]; filesJSON != "" {
		if err := json.Unmarshal([]byte(filesJSON), &config.Files); err != nil {
			return nil, fmt.Errorf("parsing files: %w", err)
		}
	}

	return config, nil
}

// ParseRequiresAnnotation parses skill dependency references from manifest annotations.
// Returns nil if the annotation is missing or invalid.
func ParseRequiresAnnotation(annotations map[string]string) []string {
	requiresJSON := annotations[AnnotationSkillRequires]
	if requiresJSON == "" {
		return nil
	}

	var refs []string
	if err := json.Unmarshal([]byte(requiresJSON), &refs); err != nil {
		// Invalid annotation format - return nil rather than propagating error
		// since annotations may come from older versions or external sources
		return nil
	}
	return refs
}
