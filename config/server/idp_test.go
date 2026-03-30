// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapReader is a map-backed env.Reader used in tests.
// Because map lookups are two-valued, it also satisfies lookupEnvReader.
type mapReader map[string]string

func (m mapReader) Getenv(key string) string {
	return m[key]
}

func (m mapReader) LookupEnv(key string) (string, bool) {
	v, ok := m[key]
	return v, ok
}

// plainReader wraps a map but only exposes Getenv, so it does NOT satisfy
// lookupEnvReader. This exercises the fallback path in resolveRequiredScope.
type plainReader map[string]string

func (p plainReader) Getenv(key string) string {
	return p[key]
}

func TestLoadIDPConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		env           map[string]string
		useLookup     bool // true → mapReader (lookupEnvReader), false → plainReader
		wantConfig    IDPConfig
		wantErrSubstr string
	}{
		{
			name:      "all variables set",
			useLookup: true,
			env: map[string]string{
				EnvIssuer:        "https://issuer.example.com",
				EnvAudience:      "my-audience",
				EnvRequiredScope: "openid profile",
			},
			wantConfig: IDPConfig{
				Issuer:        "https://issuer.example.com",
				Audience:      "my-audience",
				RequiredScope: "openid profile",
			},
		},
		{
			name:      "scope absent uses default (lookupEnvReader)",
			useLookup: true,
			env: map[string]string{
				EnvIssuer:   "https://issuer.example.com",
				EnvAudience: "my-audience",
				// EnvRequiredScope intentionally absent
			},
			wantConfig: IDPConfig{
				Issuer:        "https://issuer.example.com",
				Audience:      "my-audience",
				RequiredScope: DefaultRequiredScope,
			},
		},
		{
			name:      "scope present-but-empty disables scope checking (lookupEnvReader)",
			useLookup: true,
			env: map[string]string{
				EnvIssuer:        "https://issuer.example.com",
				EnvAudience:      "my-audience",
				EnvRequiredScope: "",
			},
			wantConfig: IDPConfig{
				Issuer:        "https://issuer.example.com",
				Audience:      "my-audience",
				RequiredScope: "", // empty → scope checking disabled
			},
		},
		{
			name:      "scope empty without lookupEnvReader falls back to default",
			useLookup: false,
			env: map[string]string{
				EnvIssuer:   "https://issuer.example.com",
				EnvAudience: "my-audience",
				// EnvRequiredScope absent (indistinguishable from empty without Lookupenv)
			},
			wantConfig: IDPConfig{
				Issuer:        "https://issuer.example.com",
				Audience:      "my-audience",
				RequiredScope: DefaultRequiredScope,
			},
		},
		{
			name:      "scope set without lookupEnvReader uses the value",
			useLookup: false,
			env: map[string]string{
				EnvIssuer:        "https://issuer.example.com",
				EnvAudience:      "my-audience",
				EnvRequiredScope: "custom-scope",
			},
			wantConfig: IDPConfig{
				Issuer:        "https://issuer.example.com",
				Audience:      "my-audience",
				RequiredScope: "custom-scope",
			},
		},
		{
			name:          "missing issuer returns error",
			useLookup:     true,
			env:           map[string]string{EnvAudience: "my-audience"},
			wantErrSubstr: "CONFIG_SERVER_ISSUER",
		},
		{
			name:          "empty issuer returns error",
			useLookup:     true,
			env:           map[string]string{EnvIssuer: "", EnvAudience: "my-audience"},
			wantErrSubstr: "CONFIG_SERVER_ISSUER",
		},
		{
			name:          "missing audience returns error",
			useLookup:     true,
			env:           map[string]string{EnvIssuer: "https://issuer.example.com"},
			wantErrSubstr: "CONFIG_SERVER_AUDIENCE",
		},
		{
			name:          "empty audience returns error",
			useLookup:     true,
			env:           map[string]string{EnvIssuer: "https://issuer.example.com", EnvAudience: ""},
			wantErrSubstr: "CONFIG_SERVER_AUDIENCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var got IDPConfig
			var err error
			if tt.useLookup {
				got, err = LoadIDPConfig(mapReader(tt.env))
			} else {
				got, err = LoadIDPConfig(plainReader(tt.env))
			}

			if tt.wantErrSubstr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrSubstr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantConfig, got)
		})
	}
}
