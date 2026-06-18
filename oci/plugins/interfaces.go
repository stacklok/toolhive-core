// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

//go:generate mockgen -copyright_file=../../.github/license-header.txt -source=interfaces.go -destination=mocks/mock_interfaces.go -package=mocks

import (
	"context"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// RegistryClient provides remote OCI registry operations for plugins.
type RegistryClient interface {
	// Push pushes an artifact from the local store to a remote registry.
	Push(ctx context.Context, store *Store, manifestDigest digest.Digest, ref string) error

	// Pull pulls an artifact from a remote registry into the local store.
	Pull(ctx context.Context, store *Store, ref string) (digest.Digest, error)
}

// PluginPackager creates OCI artifacts from plugin directories.
type PluginPackager interface {
	// Package packages a plugin directory into an OCI artifact in the local store.
	Package(ctx context.Context, pluginDir string, opts PackageOptions) (*PackageResult, error)
}

// PackageOptions configures plugin packaging.
type PackageOptions struct {
	// Epoch is the timestamp to use for reproducible builds.
	Epoch time.Time

	// Platforms specifies target platforms for the image index.
	// If empty, defaults to DefaultPlatforms.
	Platforms []ocispec.Platform
}

// PackageResult contains the result of packaging a plugin.
type PackageResult struct {
	IndexDigest    digest.Digest
	ManifestDigest digest.Digest
	ConfigDigest   digest.Digest
	LayerDigest    digest.Digest
	Config         *PluginConfig
	Platforms      []ocispec.Platform
}
