// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package plugins provides OCI artifact types, media types, local storage, and
remote registry operations for ToolHive plugin packages.

A plugin is an OCI artifact containing a .claude-plugin/plugin.json manifest and
its component directories. This package defines the constants, data structures,
storage layer, packager, and registry client that the rest of the ToolHive
ecosystem uses to package, push, pull, and cache plugins as OCI images.

# Media Types and Constants

Standard OCI media types and ToolHive-specific annotation/label keys:

	// Artifact type identifies a plugin manifest
	plugins.ArtifactTypePlugin // "dev.toolhive.plugins.v1"

	// Annotations carry metadata in manifests
	plugins.AnnotationPluginName
	plugins.AnnotationPluginVersion
	plugins.AnnotationPluginComponents

	// Labels carry metadata in OCI image configs
	plugins.LabelPluginName
	plugins.LabelPluginFiles

# Registry Client

The [Registry] type implements [RegistryClient] for pushing and pulling plugin
artifacts to/from OCI-compliant registries (GHCR, ECR, Docker Hub, etc.). It
uses ORAS for registry operations and the Docker credential store for
authentication by default:

	reg, err := plugins.NewRegistry()
	// Push an artifact
	err = reg.Push(ctx, store, indexDigest, "ghcr.io/myorg/my-plugin:v1.0.0")
	// Pull an artifact
	digest, err := reg.Pull(ctx, store, "ghcr.io/myorg/my-plugin:v1.0.0")

Use functional options to customise behaviour:

	reg, err := plugins.NewRegistry(
	    plugins.WithPlainHTTP(true),           // for local dev registries
	    plugins.WithCredentialStore(myStore),  // custom auth
	)

# Stability

This package is Alpha. Breaking changes are possible between minor versions.
*/
package plugins
