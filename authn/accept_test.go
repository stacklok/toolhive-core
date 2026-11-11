// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/jose"
)

const (
	testAudB = "https://other.example.com"
	typJWT   = "JWT"
)

// missing marks an absent claim, so nil can mean JSON null.
var missing = new(int)

// audShapeCases are the `aud` shapes accept must handle. The result is the
// reason accept reports, empty meaning accepted.
var audShapeCases = []struct {
	name string
	aud  any // missing means absent
	want Reason
}{
	{"string match", testAPIAud, ""},
	{"array any-match", []any{testAudB, testAPIAud}, ""},
	{"string mismatch", testAudB, ReasonAudience},
	{"array mismatch", []any{testAudB}, ReasonAudience},
	{"absent", missing, ReasonAudience},
	{"empty string", "", ReasonAudience},
	{"empty array", []any{}, ReasonAudience},
	{"empty element", []any{testAPIAud, ""}, ReasonAudience},
	{"mixed array", []any{testAPIAud, 7.0}, ReasonAudience},
	{"number", 7.0, ReasonAudience},
	{"null", nil, ReasonAudience},
	{"object", map[string]any{"a": "b"}, ReasonAudience},
	{"case differs", "HTTPS://API.EXAMPLE.COM", ReasonAudience},
}

// typCNFCases are the `typ` and `cnf` shapes accept must handle, under the
// accepted types in allow.
var typCNFCases = []struct {
	name   string
	header map[string]any
	claims jwt.MapClaims
	allow  []string
	want   Reason
}{
	{"no typ, no policy", nil, nil, nil, ""},
	{"plain typ, no policy", map[string]any{headerTyp: typJWT}, nil, nil, ""},
	{"non-string typ", map[string]any{headerTyp: 42.0}, nil, nil, ReasonTokenType},
	{"id-jag denied", map[string]any{headerTyp: jose.JWTTypeIDJAG}, nil, nil, ReasonTokenKind},
	{"id-jag denied with prefix and case", map[string]any{headerTyp: "Application/OAuth-ID-JAG+JWT"}, nil, nil, ReasonTokenKind},
	{"logout denied", map[string]any{headerTyp: jose.JWTTypeLogout}, nil, nil, ReasonTokenKind},
	{"secevent denied", map[string]any{headerTyp: jose.JWTTypeSecEvent}, nil, nil, ReasonTokenKind},
	{"dpop denied", map[string]any{headerTyp: jose.JWTTypeDPoP}, nil, nil, ReasonTokenKind},
	{"introspection denied", map[string]any{headerTyp: jose.JWTTypeTokenIntrospection}, nil, nil, ReasonTokenKind},
	{"denied typ with parameter is not matched", map[string]any{headerTyp: jose.JWTTypeIDJAG + "; v=1"}, nil, nil, ""},
	{"allow overrides deny", map[string]any{headerTyp: jose.JWTTypeIDJAG}, nil, []string{jose.JWTTypeIDJAG}, ""},
	{"allow match", map[string]any{headerTyp: "application/AT+JWT"}, nil, []string{jose.JWTTypeAccessToken}, ""},
	{"allow miss", map[string]any{headerTyp: typJWT}, nil, []string{jose.JWTTypeAccessToken}, ReasonTokenType},
	{"allow set, typ absent", nil, nil, []string{jose.JWTTypeAccessToken}, ReasonTokenType},
	{"allow set, typ empty", map[string]any{headerTyp: ""}, nil, []string{jose.JWTTypeAccessToken}, ReasonTokenType},
	{"allow set, denied typ not listed", map[string]any{headerTyp: jose.JWTTypeLogout}, nil, []string{jose.JWTTypeAccessToken}, ReasonTokenKind},
	{"cnf refused", nil, jwt.MapClaims{claimCNF: map[string]any{"jkt": "x"}}, nil, ReasonTokenKind},
	{"null cnf refused", nil, jwt.MapClaims{claimCNF: nil}, nil, ReasonTokenKind},
}

func reasonOf(t *testing.T, err error) Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	var e *Error
	require.ErrorAs(t, err, &e)
	require.Equal(t, CodeInvalidToken, e.Code)
	return e.Reason
}

func TestAcceptAudience(t *testing.T) {
	t.Parallel()

	for _, tt := range audShapeCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := acceptPolicy{audiences: []string{testAPIAud}}
			claims := jwt.MapClaims{}
			if tt.aud != missing {
				claims["aud"] = tt.aud
			}
			require.Equal(t, tt.want, reasonOf(t, accept(&p, claims, nil, time.Time{})))
		})
	}

	t.Run("AllowAnyAudience skips the check", func(t *testing.T) {
		t.Parallel()
		p := acceptPolicy{allowAnyAudience: true}
		require.NoError(t, accept(&p, jwt.MapClaims{"aud": 7.0}, nil, time.Time{}))
	})
}

func TestAcceptTypeAndCNF(t *testing.T) {
	t.Parallel()

	for _, tt := range typCNFCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := acceptPolicy{allowAnyAudience: true, types: typePolicy{allow: tt.allow}}
			require.Equal(t, tt.want, reasonOf(t, accept(&p, tt.claims, tt.header, time.Time{})))
		})
	}

	t.Run("AllowCNF accepts cnf", func(t *testing.T) {
		t.Parallel()
		p := acceptPolicy{allowAnyAudience: true, allowCNF: true}
		require.NoError(t, accept(&p, jwt.MapClaims{claimCNF: map[string]any{}}, nil, time.Time{}))
	})
}

func TestValidateTypeEntries(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateTypeEntries("f", []string{typAccessToken, "application/" + typAccessToken}))
	for _, bad := range []string{"", "application/", "Application/", " at+jwt", "at+jwt "} {
		require.Error(t, validateTypeEntries("f", []string{bad}), "entry %q", bad)
	}
}

// TestValidateRunsAccept proves Validate wires accept in after verify.
func TestValidateRunsAccept(t *testing.T) {
	t.Parallel()

	key := mintRSA(t, "k1")
	js := newJWKSServer(t, key.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)
	stranger := mintRSA(t, "unknown")

	tests := []struct {
		name  string
		token string
		want  Reason
	}{
		{"denied typ", key.mint(t, js.srv.URL, withHeader(headerTyp, jose.JWTTypeIDJAG)), ReasonTokenKind},
		{"typ is checked after the signature", stranger.mint(t, js.srv.URL, withHeader(headerTyp, jose.JWTTypeIDJAG)), ReasonUnknownKID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := v.Validate(context.Background(), tt.token)
			require.Equal(t, tt.want, reasonOf(t, err))
		})
	}
}
