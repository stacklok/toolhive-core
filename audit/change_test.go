// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChanges_SecretFieldNameOnly(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-api-key-value"
	tests := []struct {
		name   string
		change Change
		want   string
	}{
		{
			name:   "plain field",
			change: FieldChange("limit", "1000", "1000000"),
			want:   `{"field":"limit","before":"1000","after":"1000000"}`,
		},
		{
			name:   "plain field created",
			change: FieldChange("color", "", "blue"),
			want:   `{"field":"color","before":"","after":"blue"}`,
		},
		{
			name:   "secret field",
			change: SecretFieldChange("api_key"),
			want:   `{"field":"api_key","secret":true}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			enc, err := json.Marshal(tt.change)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(enc))
		})
	}

	t.Run("secret value appears nowhere in the line", func(t *testing.T) {
		t.Parallel()
		// The caller holds the secret, but the secret change has no slot
		// for it: only the field name reaches the event.
		b, _ := newTestBuilder(t)
		events := mustBuild(userCtx(), t, b, WithChanges(SecretFieldChange("api_key")))
		line := render(t, events)[0]
		assert.False(t, bytes.Contains(line, []byte(secret)))
		changes := decode(t, line)["metadata"].(map[string]any)["extra"].(map[string]any)["changes"]
		assert.Equal(t, []any{map[string]any{"field": "api_key", "secret": true}}, changes)
	})

	t.Run("fmt never prints values", func(t *testing.T) {
		t.Parallel()
		c := FieldChange("password_hint", secret, secret)
		for _, verb := range []string{"%v", "%+v", "%s"} {
			assert.NotContains(t, fmt.Sprintf(verb, c), secret, verb)
		}
	})
}

func TestChanges_MembersAddedRemoved(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		added   []string
		removed []string
		want    string
	}{
		{
			name:    "added and removed",
			added:   []string{testUserID, "u-2"},
			removed: []string{"u-3"},
			want:    `{"field":"members","added":["u-1","u-2"],"removed":["u-3"]}`,
		},
		{
			name:  "only added",
			added: []string{testUserID},
			want:  `{"field":"members","added":["u-1"],"removed":[]}`,
		},
		{
			name: "no members",
			want: `{"field":"members","added":[],"removed":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, _ := newTestBuilder(t)
			events := mustBuild(userCtx(), t, b, WithChanges(MembersChange("members", tt.added, tt.removed)))
			require.Len(t, events, 1)
			changes := decode(t, render(t, events)[0])["metadata"].(map[string]any)["extra"].(map[string]any)["changes"]
			got, err := json.Marshal(changes.([]any)[0])
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}

	t.Run("input slices are copied", func(t *testing.T) {
		t.Parallel()
		added := []string{testUserID}
		c := MembersChange("members", added, nil)
		added[0] = "changed"
		enc, err := json.Marshal(c)
		require.NoError(t, err)
		assert.Contains(t, string(enc), testUserID)
	})
}
