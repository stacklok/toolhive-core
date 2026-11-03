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

func TestReadDirectoryResult_JSONMatchesSpecExample(t *testing.T) {
	t.Parallel()

	// The resources/directory/read result from SEP-2640, trimmed to two
	// children, plus a nextCursor.
	const wire = `{
		"resources": [
			{"uri": "skill://pdf-processing/templates/invoice.md", "name": "invoice.md", "mimeType": "text/markdown"},
			{"uri": "skill://pdf-processing/templates/regional", "name": "regional", "mimeType": "inode/directory"}
		],
		"nextCursor": "n"
	}`
	var res ReadDirectoryResult
	require.NoError(t, json.Unmarshal([]byte(wire), &res))
	require.Len(t, res.Resources, 2)
	assert.Equal(t, MIMETypeDirectory, res.Resources[1].MIMEType)
	assert.Equal(t, Cursor("n"), res.NextCursor)

	out, err := json.Marshal(res)
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(out))
}

func TestSkillsResults_EmptyListsEncodeAsArrays(t *testing.T) {
	t.Parallel()

	// The extension defines both as arrays; a nil slice must not encode as
	// null. Pagination and _meta are unaffected.
	list, err := json.Marshal(ListSkillsResult{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"skills":[]}`, string(list))

	page := ListSkillsResult{}
	page.NextCursor = "n"
	list, err = json.Marshal(page)
	require.NoError(t, err)
	assert.JSONEq(t, `{"skills":[],"nextCursor":"n"}`, string(list))

	dir, err := json.Marshal(ReadDirectoryResult{})
	require.NoError(t, err)
	assert.JSONEq(t, `{"resources":[]}`, string(dir))
}

func TestSkillFrontmatter_KeepsNumberPrecision(t *testing.T) {
	t.Parallel()

	// 2^53 + 1 cannot be represented as a float64; decoding into map[string]any
	// without json.Number would round it to 9007199254740992.
	const wire = `{"name":"n","description":"d","metadata":{"build":9007199254740993,"ratio":0.1}}`
	var fm SkillFrontmatter
	require.NoError(t, json.Unmarshal([]byte(wire), &fm))

	out, err := json.Marshal(fm)
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(out))
	assert.Contains(t, string(out), "9007199254740993")
}
