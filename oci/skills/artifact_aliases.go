// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	artifact "github.com/stacklok/toolhive-core/oci/artifact"
)

// This file re-exports the artifact-agnostic OCI primitives that were extracted
// into the oci/artifact package. The aliases preserve the public surface of
// oci/skills so existing importers keep working unchanged.
//
// These are backward-compatibility re-exports of github.com/stacklok/toolhive-core/oci/artifact.
// NEW code should import github.com/stacklok/toolhive-core/oci/artifact directly
// rather than depending on these aliases.

// Type aliases for tar/gzip primitives.
type (
	// FileEntry represents a file to include in a tar archive.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.FileEntry.
	FileEntry = artifact.FileEntry
	// TarOptions configures reproducible tar archive creation.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.TarOptions.
	TarOptions = artifact.TarOptions
	// GzipOptions configures reproducible gzip compression.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.GzipOptions.
	GzipOptions = artifact.GzipOptions
)

// Function forwarding for tar primitives.
var (
	// DefaultTarOptions returns default options for reproducible tar archives.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.DefaultTarOptions.
	DefaultTarOptions = artifact.DefaultTarOptions
	// CreateTar creates a reproducible tar archive from the given files.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.CreateTar.
	CreateTar = artifact.CreateTar
	// ExtractTar extracts files from a tar archive.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.ExtractTar.
	ExtractTar = artifact.ExtractTar
	// ExtractTarWithLimit extracts files from a tar archive with a per-file size limit.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.ExtractTarWithLimit.
	ExtractTarWithLimit = artifact.ExtractTarWithLimit
)

// Function forwarding for gzip primitives.
var (
	// DefaultGzipOptions returns default options for reproducible gzip compression.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.DefaultGzipOptions.
	DefaultGzipOptions = artifact.DefaultGzipOptions
	// Compress creates a reproducible gzip compressed byte slice.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.Compress.
	Compress = artifact.Compress
	// Decompress decompresses gzip data.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.Decompress.
	Decompress = artifact.Decompress
	// DecompressWithLimit decompresses gzip data with a size limit.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.DecompressWithLimit.
	DecompressWithLimit = artifact.DecompressWithLimit
	// CompressTar creates a reproducible .tar.gz from the given files.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.CompressTar.
	CompressTar = artifact.CompressTar
	// DecompressTar extracts files from a .tar.gz archive.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.DecompressTar.
	DecompressTar = artifact.DecompressTar
)

// Function forwarding for platform helpers.
var (
	// PlatformString returns the platform in "os/arch" or "os/arch/variant" format.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.PlatformString.
	PlatformString = artifact.PlatformString
	// ParsePlatform parses a platform string in "os/arch" or "os/arch/variant" format.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.ParsePlatform.
	ParsePlatform = artifact.ParsePlatform
	// DefaultPlatforms are the default platforms for artifacts.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.DefaultPlatforms.
	DefaultPlatforms = artifact.DefaultPlatforms
)

// Size limit constants re-exported from the artifact package.
const (
	// MaxTarFileSize is the maximum size of a single file in a tar archive (100MB).
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.MaxTarFileSize.
	MaxTarFileSize = artifact.MaxTarFileSize
	// MaxDecompressedSize is the maximum size of decompressed data (100MB).
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.MaxDecompressedSize.
	MaxDecompressedSize = artifact.MaxDecompressedSize
	// MaxManifestSize is the maximum size of a manifest (1MB).
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.MaxManifestSize.
	MaxManifestSize = artifact.MaxManifestSize
	// MaxBlobSize is the maximum size of a blob (100MB).
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.MaxBlobSize.
	MaxBlobSize = artifact.MaxBlobSize
)

// OS and architecture constants for OCI platform specifications.
const (
	// OSLinux is the Linux OS identifier used in OCI platform specs.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.OSLinux.
	OSLinux = artifact.OSLinux
	// ArchAMD64 is the x86-64 architecture identifier used in OCI platform specs.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.ArchAMD64.
	ArchAMD64 = artifact.ArchAMD64
	// ArchARM64 is the 64-bit ARM architecture identifier used in OCI platform specs.
	// Deprecated: use github.com/stacklok/toolhive-core/oci/artifact.ArchARM64.
	ArchARM64 = artifact.ArchARM64
)
