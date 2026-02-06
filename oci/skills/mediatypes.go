// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Artifact type for skill identification.
const (
	// ArtifactTypeSkill identifies skill artifacts in manifests.
	ArtifactTypeSkill = "dev.toolhive.skills.v1"
)

// OCI Image Index media type.
const (
	// MediaTypeImageIndex is the OCI image index media type.
	MediaTypeImageIndex = "application/vnd.oci.image.index.v1+json"
)

// Standard OCI media types for Kubernetes image volume compatibility.
const (
	// MediaTypeImageManifest is the OCI image manifest media type.
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"

	// MediaTypeImageConfig is the standard OCI image config media type.
	MediaTypeImageConfig = "application/vnd.oci.image.config.v1+json"

	// MediaTypeImageLayer is the standard OCI image layer media type.
	MediaTypeImageLayer = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// Annotation keys for skill metadata in manifests.
const (
	// AnnotationCreated is the OCI standard annotation for creation time.
	AnnotationCreated = "org.opencontainers.image.created"

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

// ImageConfig represents a standard OCI image configuration.
// This structure is required for Kubernetes image volume compatibility.
type ImageConfig struct {
	Architecture string          `json:"architecture"`
	OS           string          `json:"os"`
	Config       ImageConfigData `json:"config,omitempty"`
	RootFS       RootFS          `json:"rootfs"`
	History      []HistoryEntry  `json:"history,omitempty"`
}

// ImageConfigData contains container configuration including labels.
type ImageConfigData struct {
	Labels map[string]string `json:"Labels,omitempty"`
}

// RootFS describes the rootfs of the image.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// HistoryEntry describes a layer in the image history.
type HistoryEntry struct {
	Created   string `json:"created,omitempty"`
	CreatedBy string `json:"created_by,omitempty"`
}

// SkillConfigFromImageConfig extracts SkillConfig from OCI image config labels.
func SkillConfigFromImageConfig(imgConfig *ImageConfig) (*SkillConfig, error) {
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

// Platform represents a target platform for OCI artifacts.
type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

// String returns the platform in "os/arch" format.
func (p Platform) String() string {
	return p.OS + "/" + p.Architecture
}

// ParsePlatform parses a platform string in "os/arch" format.
func ParsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return Platform{}, fmt.Errorf("invalid platform format: %q (expected os/arch)", s)
	}
	osName := strings.TrimSpace(parts[0])
	arch := strings.TrimSpace(parts[1])
	if osName == "" || arch == "" {
		return Platform{}, fmt.Errorf("invalid platform format: %q (os and arch cannot be empty)", s)
	}
	return Platform{OS: osName, Architecture: arch}, nil
}

// DefaultPlatforms are the default platforms for skill artifacts.
// These cover most Kubernetes clusters.
var DefaultPlatforms = []Platform{
	{OS: "linux", Architecture: "amd64"},
	{OS: "linux", Architecture: "arm64"},
}

// ImageIndex represents an OCI image index (multi-platform manifest list).
type ImageIndex struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType,omitempty"`
	Manifests     []IndexDescriptor `json:"manifests"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// IndexDescriptor describes a manifest in an image index.
type IndexDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
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
