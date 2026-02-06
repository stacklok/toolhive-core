// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkillConfigFromImageConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *ImageConfig
		wantName  string
		wantErr   bool
		wantTools []string
		wantFiles []string
	}{
		{
			name: "all fields populated",
			config: &ImageConfig{
				Config: ImageConfigData{
					Labels: map[string]string{
						LabelSkillName:         "my-skill",
						LabelSkillDescription:  "A test skill",
						LabelSkillVersion:      "1.0.0",
						LabelSkillLicense:      "Apache-2.0",
						LabelSkillAllowedTools: `["tool1","tool2"]`,
						LabelSkillFiles:        `["file1.txt","file2.txt"]`,
					},
				},
			},
			wantName:  "my-skill",
			wantTools: []string{"tool1", "tool2"},
			wantFiles: []string{"file1.txt", "file2.txt"},
		},
		{
			name: "minimal config",
			config: &ImageConfig{
				Config: ImageConfigData{
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
			config: &ImageConfig{
				Config: ImageConfigData{Labels: nil},
			},
			wantErr: true,
		},
		{
			name: "missing name",
			config: &ImageConfig{
				Config: ImageConfigData{
					Labels: map[string]string{
						LabelSkillDescription: "no name",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid allowed tools JSON",
			config: &ImageConfig{
				Config: ImageConfigData{
					Labels: map[string]string{
						LabelSkillName:         "bad-tools",
						LabelSkillAllowedTools: "not-json",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid files JSON",
			config: &ImageConfig{
				Config: ImageConfigData{
					Labels: map[string]string{
						LabelSkillName:  "bad-files",
						LabelSkillFiles: "not-json",
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
		want    Platform
		wantErr bool
	}{
		{
			name:  "linux/amd64",
			input: "linux/amd64",
			want:  Platform{OS: "linux", Architecture: "amd64"},
		},
		{
			name:  "linux/arm64",
			input: "linux/arm64",
			want:  Platform{OS: "linux", Architecture: "arm64"},
		},
		{
			name:    "no slash",
			input:   "linuxamd64",
			wantErr: true,
		},
		{
			name:    "too many parts",
			input:   "linux/amd64/v8",
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

	p := Platform{OS: "linux", Architecture: "amd64"}
	assert.Equal(t, "linux/amd64", p.String())
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
				AnnotationSkillRequires: "not-json",
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
	assert.Equal(t, Platform{OS: "linux", Architecture: "amd64"}, DefaultPlatforms[0])
	assert.Equal(t, Platform{OS: "linux", Architecture: "arm64"}, DefaultPlatforms[1])
}
