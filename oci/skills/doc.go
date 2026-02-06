// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package skills provides OCI artifact types, media types, local storage, and
remote registry operations for ToolHive skill packages.

A skill is an OCI artifact containing MCP server configuration, prompt files,
and metadata. This package defines the constants, data structures, storage
layer, and registry client that the rest of the ToolHive ecosystem uses to
package, push, pull, and cache skills as OCI images.

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

# Registry Client

The [Registry] type implements [RegistryClient] for pushing and pulling skill
artifacts to/from OCI-compliant registries (GHCR, ECR, Docker Hub, etc.).
It uses ORAS for registry operations and the Docker credential store for
authentication by default:

	reg, err := skills.NewRegistry()
	// Push an artifact
	err = reg.Push(ctx, store, indexDigest, "ghcr.io/myorg/my-skill:v1.0.0")
	// Pull an artifact
	digest, err := reg.Pull(ctx, store, "ghcr.io/myorg/my-skill:v1.0.0")

Use functional options to customise behaviour:

	reg, err := skills.NewRegistry(
	    skills.WithPlainHTTP(true),           // for local dev registries
	    skills.WithCredentialStore(myStore),   // custom auth
	)

# Stability

This package is Alpha. Breaking changes are possible between minor versions.
*/
package skills
