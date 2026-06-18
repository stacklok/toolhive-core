// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// PlatformString returns the platform in "os/arch" or "os/arch/variant" format.
func PlatformString(p ocispec.Platform) string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// ParsePlatform parses a platform string in "os/arch" or "os/arch/variant" format.
func ParsePlatform(s string) (ocispec.Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return ocispec.Platform{}, fmt.Errorf("invalid platform format: %q (expected os/arch or os/arch/variant)", s)
	}
	osName := strings.TrimSpace(parts[0])
	arch := strings.TrimSpace(parts[1])
	if osName == "" || arch == "" {
		return ocispec.Platform{}, fmt.Errorf("invalid platform format: %q (os and arch cannot be empty)", s)
	}
	p := ocispec.Platform{OS: osName, Architecture: arch}
	if len(parts) == 3 {
		variant := strings.TrimSpace(parts[2])
		if variant == "" {
			return ocispec.Platform{}, fmt.Errorf("invalid platform format: %q (variant cannot be empty)", s)
		}
		p.Variant = variant
	}
	return p, nil
}

// OS and architecture constants for OCI platform specifications.
const (
	// OSLinux is the Linux OS identifier used in OCI platform specs.
	OSLinux = "linux"
	// ArchAMD64 is the x86-64 architecture identifier used in OCI platform specs.
	ArchAMD64 = "amd64"
	// ArchARM64 is the 64-bit ARM architecture identifier used in OCI platform specs.
	ArchARM64 = "arm64"
)

// DefaultPlatforms are the default platforms for artifacts.
// These cover most Kubernetes clusters.
var DefaultPlatforms = []ocispec.Platform{
	{OS: OSLinux, Architecture: ArchAMD64},
	{OS: OSLinux, Architecture: ArchARM64},
}
