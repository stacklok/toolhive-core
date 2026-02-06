// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package skills provides OCI artifact types, media types, and local storage for
ToolHive skill packages.

A skill is an OCI artifact containing MCP server configuration, prompt files,
and metadata. This package defines the constants, data structures, and storage
layer that the rest of the ToolHive ecosystem uses to package, push, pull, and
cache skills as OCI images.

# Media Types and Constants

Standard OCI media types and ToolHive-specific annotation/label keys:

	// Artifact type identifies a skill manifest
	skills.ArtifactTypeSkill // "dev.toolhive.skills.v1"

	// Annotations carry metadata in manifests
	skills.AnnotationSkillName
	skills.AnnotationSkillVersion

	// Labels carry metadata in OCI image configs
	skills.LabelSkillName
	skills.LabelSkillFiles

# Stability

This package is Alpha. Breaking changes are possible between minor versions.
*/
package skills
