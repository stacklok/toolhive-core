// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testArchARM is the 32-bit ARM architecture identifier used in test platform specs.
const testArchARM = "arm"

func TestParsePlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    ocispec.Platform
		wantErr bool
	}{
		{
			name:  "os/arch",
			input: "linux/amd64",
			want:  ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64},
		},
		{
			name:  "os/arch/variant",
			input: "linux/arm/v7",
			want:  ocispec.Platform{OS: OSLinux, Architecture: testArchARM, Variant: "v7"},
		},
		{
			name:    "fewer than 2 parts (no slash)",
			input:   "linuxamd64",
			wantErr: true,
		},
		{
			name:    "more than 3 parts",
			input:   "linux/amd64/v8/extra",
			wantErr: true,
		},
		{
			name:    "empty os",
			input:   "/amd64",
			wantErr: true,
		},
		{
			name:    "empty arch",
			input:   "linux/",
			wantErr: true,
		},
		{
			name:    "empty variant",
			input:   "linux/arm/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParsePlatform(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPlatformString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		platform ocispec.Platform
		want     string
	}{
		{
			name:     "os/arch",
			platform: ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64},
			want:     "linux/amd64",
		},
		{
			name:     "os/arch/variant",
			platform: ocispec.Platform{OS: OSLinux, Architecture: testArchARM, Variant: "v7"},
			want:     "linux/arm/v7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, PlatformString(tt.platform))
		})
	}
}

func TestParsePlatform_PlatformString_Roundtrip(t *testing.T) {
	t.Parallel()

	platforms := []ocispec.Platform{
		{OS: OSLinux, Architecture: ArchAMD64},
		{OS: OSLinux, Architecture: ArchARM64},
		{OS: OSLinux, Architecture: testArchARM, Variant: "v7"},
	}

	for _, p := range platforms {
		parsed, err := ParsePlatform(PlatformString(p))
		require.NoError(t, err)
		assert.Equal(t, p, parsed)
	}
}

func TestDefaultPlatforms(t *testing.T) {
	t.Parallel()

	require.Len(t, DefaultPlatforms, 2)
	assert.Equal(t, ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64}, DefaultPlatforms[0])
	assert.Equal(t, ocispec.Platform{OS: OSLinux, Architecture: ArchARM64}, DefaultPlatforms[1])
}
