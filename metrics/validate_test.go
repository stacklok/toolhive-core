// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metric  string
		wantErr bool
	}{
		{
			name:    "rejects gateway as the service segment",
			metric:  "stacklok.gateway.request.duration",
			wantErr: true,
		},
		{
			name:    "accepts a qualified gateway service segment",
			metric:  "stacklok.llm_gateway.token.usage",
			wantErr: false,
		},
		{
			name:    "accepts a well-formed name with no gateway segment",
			metric:  "stacklok.toolhive.request.duration",
			wantErr: false,
		},
		{
			name:    "rejects an empty name",
			metric:  "",
			wantErr: true,
		},
		{
			name:    "rejects a name with too few segments",
			metric:  "stacklok.gateway",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateName(tc.metric)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLabelKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		value   any
		wantErr bool
	}{
		{"rejects a bool value", "is_healthy", true, true},
		{"rejects a bool pointer value", "is_healthy", func() *bool { b := true; return &b }(), true},
		{"accepts a string value", "outcome", "success", false},
		{"accepts an int value", "count", 42, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLabelKind(tc.key, tc.value)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
