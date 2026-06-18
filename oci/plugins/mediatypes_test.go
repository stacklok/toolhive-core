// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/json"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginConfigFromImageConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         *ocispec.Image
		wantName       string
		wantErr        bool
		wantFiles      []string
		wantComponents ComponentInventory
		wantRequires   []string
	}{
		{
			name: "all fields populated",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelPluginName:        testPluginMyPlugin,
						LabelPluginDescription: "A test plugin",
						LabelPluginVersion:     "1.0.0",
						LabelPluginLicense:     "Apache-2.0",
						LabelPluginFiles:       `[".claude-plugin/plugin.json","commands/test.md"]`,
						LabelPluginComponents:  `{"commands":1,"skills":2}`,
						LabelPluginRequires:    `["ghcr.io/org/server:v1"]`,
					},
				},
			},
			wantName:       testPluginMyPlugin,
			wantFiles:      []string{ManifestFileName, "commands/test.md"},
			wantComponents: ComponentInventory{testComponentCommands: 1, "skills": 2},
			wantRequires:   []string{"ghcr.io/org/server:v1"},
		},
		{
			name: "minimal config",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelPluginName: testPluginMinimal,
					},
				},
			},
			wantName: testPluginMinimal,
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
						LabelPluginDescription: "no name",
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
						LabelPluginName:  "bad-files",
						LabelPluginFiles: testNotJSON,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid components JSON",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelPluginName:       "bad-components",
						LabelPluginComponents: testNotJSON,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid requires JSON",
			config: &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: map[string]string{
						LabelPluginName:     "bad-requires",
						LabelPluginRequires: testNotJSON,
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := PluginConfigFromImageConfig(tt.config)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.Name)
			if tt.wantFiles != nil {
				assert.Equal(t, tt.wantFiles, got.Files)
			}
			if tt.wantComponents != nil {
				assert.Equal(t, tt.wantComponents, got.Components)
			}
			if tt.wantRequires != nil {
				assert.Equal(t, tt.wantRequires, got.Requires)
			}
		})
	}
}

// pluginConfigToLabels serializes a PluginConfig into OCI image config Labels
// exactly the way createOCIConfig does in packager.go. Keeping this helper in
// lock-step with createOCIConfig lets the round-trip test guard the full
// serialize → parse cycle without duplicating that logic in each case.
func pluginConfigToLabels(t *testing.T, cfg *PluginConfig) map[string]string {
	t.Helper()

	filesJSON, err := json.Marshal(cfg.Files)
	require.NoError(t, err)
	componentsJSON, err := json.Marshal(cfg.Components)
	require.NoError(t, err)
	requiresJSON, err := json.Marshal(cfg.Requires)
	require.NoError(t, err)

	return map[string]string{
		LabelPluginName:        cfg.Name,
		LabelPluginDescription: cfg.Description,
		LabelPluginVersion:     cfg.Version,
		LabelPluginLicense:     cfg.License,
		LabelPluginFiles:       string(filesJSON),
		LabelPluginComponents:  string(componentsJSON),
		LabelPluginRequires:    string(requiresJSON),
	}
}

// TestPluginConfig_RoundTrip locks in that a PluginConfig serialized into OCI
// image config labels (the way createOCIConfig does) and parsed back with
// PluginConfigFromImageConfig deep-equals the original.
func TestPluginConfig_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *PluginConfig
	}{
		{
			name: "fully populated",
			cfg: &PluginConfig{
				Name:        testPluginMyPlugin,
				Description: "A fully populated plugin",
				Version:     "1.2.3",
				License:     "Apache-2.0",
				Files:       []string{ManifestFileName, "commands/test.md", "agents/reviewer.md"},
				Components:  ComponentInventory{testComponentCommands: 1, testComponentSkills: 2},
				Requires:    []string{testRequireServerV1, testRequireSkillV1},
			},
		},
		{
			name: "minimal name only",
			cfg: &PluginConfig{
				Name:  testPluginMinimal,
				Files: []string{ManifestFileName},
			},
		},
		{
			// Regression guard for the Fix-1 nil behaviour: componentInventory
			// returns nil for a zero-component plugin so the empty map dropped
			// by `omitempty` round-trips back to nil rather than an empty map.
			name: "zero components and zero requires",
			cfg: &PluginConfig{
				Name:        "no-components-plugin",
				Description: "A plugin with no components or dependencies",
				Version:     "0.1.0",
				Files:       []string{ManifestFileName, "README.md"},
				Components:  nil,
				Requires:    nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			img := &ocispec.Image{
				Config: ocispec.ImageConfig{
					Labels: pluginConfigToLabels(t, tt.cfg),
				},
			}

			got, err := PluginConfigFromImageConfig(img)
			require.NoError(t, err)
			assert.Equal(t, tt.cfg, got)
		})
	}
}

func TestParseComponentsAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		want        ComponentInventory
	}{
		{
			name: "valid components",
			annotations: map[string]string{
				AnnotationPluginComponents: `{"commands":3,"agents":1}`,
			},
			want: ComponentInventory{testComponentCommands: 3, "agents": 1},
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
			name: testNameInvalidJSON,
			annotations: map[string]string{
				AnnotationPluginComponents: testNotJSON,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ParseComponentsAnnotation(tt.annotations)
			assert.Equal(t, tt.want, got)
		})
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
				AnnotationPluginRequires: `["ghcr.io/org/plugin1:v1","ghcr.io/org/plugin2:v2"]`,
			},
			want: []string{"ghcr.io/org/plugin1:v1", "ghcr.io/org/plugin2:v2"},
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
			name: testNameInvalidJSON,
			annotations: map[string]string{
				AnnotationPluginRequires: testNotJSON,
			},
			want: nil,
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
