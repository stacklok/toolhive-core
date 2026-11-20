// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testChanged = "changed"

func TestParseScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   []string
	}{
		{"none", jwt.MapClaims{}, nil},
		{"scope string", jwt.MapClaims{claimScope: " a  b c "}, []string{"a", "b", "c"}},
		{"tab is not a delimiter", jwt.MapClaims{claimScope: "a\tb c"}, []string{"a\tb", "c"}},
		{"no-break space is not a delimiter", jwt.MapClaims{claimSCP: "a\u00a0b c"}, []string{"a\u00a0b", "c"}},
		{"scp string", jwt.MapClaims{claimSCP: "a b"}, []string{"a", "b"}},
		{"scp array drops empty", jwt.MapClaims{claimSCP: []any{"a", "", "b"}}, []string{"a", "b"}},
		{"scp array with non-string", jwt.MapClaims{claimSCP: []any{"a", 1.0}}, nil},
		{"scope wins over scp", jwt.MapClaims{claimScope: "a", claimSCP: "b"}, []string{"a"}},
		{"non-string scope hides scp", jwt.MapClaims{claimScope: 1.0, claimSCP: "b"}, nil},
		{"blank scope", jwt.MapClaims{claimScope: "  "}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, parseScopes(tt.claims))
		})
	}
}

func TestRequireScopes(t *testing.T) {
	t.Parallel()

	p := Principal{Scopes: []string{"read", "write"}}
	require.NoError(t, p.RequireScopes())
	require.NoError(t, p.RequireScopes("read", "write"))

	err := p.RequireScopes("read", "admin")
	var e *Error
	require.ErrorAs(t, err, &e)
	assert.Equal(t, CodeInsufficientScope, e.Code)
	assert.Equal(t, ReasonScope, e.Reason)
	assert.Equal(t, []string{"read", "admin"}, e.RequiredScopes())
}

func TestBuildPrincipalCopiesClaims(t *testing.T) {
	t.Parallel()

	claims := jwt.MapClaims{"sub": "a", claimScope: "x", "nested": map[string]any{"k": "v"}, "list": []any{"i"}}
	p := buildPrincipal(claims)
	p.Claims["nested"].(map[string]any)["k"] = testChanged
	p.Claims["list"].([]any)[0] = testChanged
	assert.Equal(t, "v", claims["nested"].(map[string]any)["k"])
	assert.Equal(t, "i", claims["list"].([]any)[0])
	assert.Equal(t, []string{"x"}, p.Scopes)
}

func TestAlgs(t *testing.T) {
	t.Parallel()

	key := mintRSA(t, "k1")
	js := newJWKSServer(t, key.jwk)
	cfg := js.configFor()
	cfg.Algs = []string{testAlgES256}
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), key.mint(t, js.srv.URL))
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnsupportedAlg)
}
