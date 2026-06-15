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
	FileEntry = artifact.FileEntry
	// TarOptions configures reproducible tar archive creation.
	TarOptions = artifact.TarOptions
	// GzipOptions configures reproducible gzip compression.
	GzipOptions = artifact.GzipOptions
)

// Function forwarding for tar primitives.
var (
	// DefaultTarOptions returns default options for reproducible tar archives.
	DefaultTarOptions = artifact.DefaultTarOptions
	// CreateTar creates a reproducible tar archive from the given files.
	CreateTar = artifact.CreateTar
	// ExtractTar extracts files from a tar archive.
	ExtractTar = artifact.ExtractTar
	// ExtractTarWithLimit extracts files from a tar archive with a per-file size limit.
	ExtractTarWithLimit = artifact.ExtractTarWithLimit
)

// Function forwarding for gzip primitives.
var (
	// DefaultGzipOptions returns default options for reproducible gzip compression.
	DefaultGzipOptions = artifact.DefaultGzipOptions
	// Compress creates a reproducible gzip compressed byte slice.
	Compress = artifact.Compress
	// Decompress decompresses gzip data.
	Decompress = artifact.Decompress
	// DecompressWithLimit decompresses gzip data with a size limit.
	DecompressWithLimit = artifact.DecompressWithLimit
	// CompressTar creates a reproducible .tar.gz from the given files.
	CompressTar = artifact.CompressTar
	// DecompressTar extracts files from a .tar.gz archive.
	DecompressTar = artifact.DecompressTar
)

// Function forwarding for platform helpers.
var (
	// PlatformString returns the platform in "os/arch" or "os/arch/variant" format.
	PlatformString = artifact.PlatformString
	// ParsePlatform parses a platform string in "os/arch" or "os/arch/variant" format.
	ParsePlatform = artifact.ParsePlatform
	// DefaultPlatforms are the default platforms for artifacts.
	DefaultPlatforms = artifact.DefaultPlatforms
)

// Size limit constants re-exported from the artifact package.
const (
	// MaxTarFileSize is the maximum size of a single file in a tar archive (100MB).
	MaxTarFileSize = artifact.MaxTarFileSize
	// MaxDecompressedSize is the maximum size of decompressed data (100MB).
	MaxDecompressedSize = artifact.MaxDecompressedSize
	// MaxManifestSize is the maximum size of a manifest (1MB).
	MaxManifestSize = artifact.MaxManifestSize
	// MaxBlobSize is the maximum size of a blob (100MB).
	MaxBlobSize = artifact.MaxBlobSize
)

// OS and architecture constants for OCI platform specifications.
const (
	// OSLinux is the Linux OS identifier used in OCI platform specs.
	OSLinux = artifact.OSLinux
	// ArchAMD64 is the x86-64 architecture identifier used in OCI platform specs.
	ArchAMD64 = artifact.ArchAMD64
	// ArchARM64 is the 64-bit ARM architecture identifier used in OCI platform specs.
	ArchARM64 = artifact.ArchARM64
)
