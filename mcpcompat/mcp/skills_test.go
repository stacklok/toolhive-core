// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSkillResources_JSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wire    string
		want    SkillResources
		wantErr bool
		// reencode is the expected encoding when it differs from wire.
		reencode string
	}{
		{
			name: "file list",
			wire: `[{"uri":"skill://a/SKILL.md","digest":"sha256:ab","size":12}]`,
			want: SkillResources{Files: []SkillResource{{URI: "skill://a/SKILL.md", Digest: "sha256:ab", Size: 12}}},
		},
		{
			name: "dynamic",
			wire: `"dynamic"`,
			want: SkillResources{Dynamic: true},
		},
		{
			name: "null stays null so an invalid entry stays invalid",
			wire: `null`,
			want: SkillResources{},
		},
		{
			name:     "empty list",
			wire:     `[]`,
			want:     SkillResources{Files: []SkillResource{}},
			reencode: `[]`,
		},
		{name: "unknown string", wire: `"static"`, wantErr: true},
		{name: "object", wire: `{}`, wantErr: true},
		{name: "number", wire: `1`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got SkillResources
			err := json.Unmarshal([]byte(tc.wire), &got)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)

			out, err := json.Marshal(got)
			require.NoError(t, err)
			want := tc.wire
			if tc.reencode != "" {
				want = tc.reencode
			}
			assert.JSONEq(t, want, string(out))
		})
	}
}

func TestSkill_JSONMatchesSpecExample(t *testing.T) {
	t.Parallel()

	// The skills/get result from SEP-2640, trimmed to one resource.
	const wire = `{
		"skill": {
			"uri": "skill://pdf-processing/SKILL.md",
			"frontmatter": {
				"name": "pdf-processing",
				"description": "Extract, fill, and assemble PDF documents",
				"metadata": {"version": "2.1.0"}
			},
			"resources": [
				{"uri": "skill://pdf-processing/SKILL.md", "digest": "sha256:d5e6f7a8", "size": 5120}
			]
		}
	}`
	var res GetSkillResult
	require.NoError(t, json.Unmarshal([]byte(wire), &res))
	assert.Equal(t, "pdf-processing", res.Skill.Frontmatter["name"])
	require.Len(t, res.Skill.Resources.Files, 1)
	assert.Equal(t, int64(5120), res.Skill.Resources.Files[0].Size)

	out, err := json.Marshal(res)
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(out))
}
