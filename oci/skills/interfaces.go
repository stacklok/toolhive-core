// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

//go:generate mockgen -source=interfaces.go -destination=mocks/mock_interfaces.go -package=mocks

import (
	"context"
	"time"

	"github.com/opencontainers/go-digest"
)

// RegistryClient provides remote OCI registry operations for skills.
type RegistryClient interface {
	// Push pushes an artifact from the local store to a remote registry.
	Push(ctx context.Context, store *Store, manifestDigest digest.Digest, ref string) error

	// Pull pulls an artifact from a remote registry into the local store.
	Pull(ctx context.Context, store *Store, ref string) (digest.Digest, error)
}

// SkillPackager creates OCI artifacts from skill directories.
type SkillPackager interface {
	// Package packages a skill directory into an OCI artifact in the local store.
	Package(ctx context.Context, skillDir string, opts PackageOptions) (*PackageResult, error)
}

// PackageOptions configures skill packaging.
type PackageOptions struct {
	// Epoch is the timestamp to use for reproducible builds.
	Epoch time.Time

	// Platforms specifies target platforms for the image index.
	// If empty, defaults to DefaultPlatforms.
	Platforms []Platform
}

// PackageResult contains the result of packaging a skill.
type PackageResult struct {
	IndexDigest    digest.Digest
	ManifestDigest digest.Digest
	ConfigDigest   digest.Digest
	LayerDigest    digest.Digest
	Config         *SkillConfig
	Platforms      []Platform
}
