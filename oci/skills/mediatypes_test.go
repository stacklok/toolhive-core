// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkillConfigFromImageConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *ocispec.Image
		wantName  string
		wantErr   bool
		wantTools []string
		wantFiles []string
	}{
		{
			name: "all fields populated",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelSkillName:         testSkillMySkill,
						LabelSkillDescription:  "A test skill",
						LabelSkillVersion:      "1.0.0",
						LabelSkillLicense:      "Apache-2.0",
						LabelSkillAllowedTools: `["tool1","tool2"]`,
						LabelSkillFiles:        `["file1.txt","file2.txt"]`,
					},
				},
			},
			wantName:  testSkillMySkill,
			wantTools: []string{"tool1", "tool2"},
			wantFiles: []string{"file1.txt", "file2.txt"},
		},
		{
			name: "minimal config",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelSkillName: "minimal-skill",
					},
				},
			},
			wantName: "minimal-skill",
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "nil labels",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{Labels: nil},
			},
			wantErr: true,
		},
		{
			name: "missing name",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelSkillDescription: "no name",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid allowed tools JSON",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelSkillName:         "bad-tools",
						LabelSkillAllowedTools: testNotJSON,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid files JSON",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelSkillName:  "bad-files",
						LabelSkillFiles: testNotJSON,
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := SkillConfigFromImageConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.Name)
			if tt.wantTools != nil {
				assert.Equal(t, tt.wantTools, got.AllowedTools)
			}
			if tt.wantFiles != nil {
				assert.Equal(t, tt.wantFiles, got.Files)
			}
		})
	}
}

func TestParsePlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    ocispec.Platform
		wantErr bool
	}{
		{
			name:  testPlatformAMD64,
			input: testPlatformAMD64,
			want:  ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64},
		},
		{
			name:  "linux/arm64",
			input: "linux/arm64",
			want:  ocispec.Platform{OS: OSLinux, Architecture: ArchARM64},
		},
		{
			name:  testPlatformARMv7,
			input: testPlatformARMv7,
			want:  ocispec.Platform{OS: OSLinux, Architecture: testArchARM, Variant: "v7"},
		},
		{
			name:    "no slash",
			input:   "linuxamd64",
			wantErr: true,
		},
		{
			name:    "too many parts",
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
			want:     testPlatformAMD64,
		},
		{
			name:     "os/arch/variant",
			platform: ocispec.Platform{OS: OSLinux, Architecture: testArchARM, Variant: "v7"},
			want:     testPlatformARMv7,
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

func TestParseRequiresAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		want        []string
	}{
		{
			name: "valid refs",
			annotations: map[string]string{
				AnnotationSkillRequires: `["ghcr.io/org/skill1:v1","ghcr.io/org/skill2:v2"]`,
			},
			want: []string{"ghcr.io/org/skill1:v1", "ghcr.io/org/skill2:v2"},
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			want:        nil,
		},
		{
			name: "missing annotation",
			annotations: map[string]string{
				"other.key": "value",
			},
			want: nil,
		},
		{
			name: "invalid JSON",
			annotations: map[string]string{
				AnnotationSkillRequires: testNotJSON,
			},
			want: nil,
		},
		{
			name:        "nil annotations",
			annotations: nil,
			want:        nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ParseRequiresAnnotation(tt.annotations)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDefaultPlatforms(t *testing.T) {
	t.Parallel()

	require.Len(t, DefaultPlatforms, 2)
	assert.Equal(t, ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64}, DefaultPlatforms[0])
	assert.Equal(t, ocispec.Platform{OS: OSLinux, Architecture: ArchARM64}, DefaultPlatforms[1])
}
