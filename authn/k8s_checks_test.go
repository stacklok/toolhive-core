// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/authn"
)

// This file expresses the rules for a Kubernetes projected service-account
// token as Checks, using only the exported API.

const (
	k8sAudience      = "https://directory.example.com"
	k8sSubjectPrefix = "system:serviceaccount:"
	k8sNamespace     = "team-a"
	k8sServiceAcct   = "worker"
	k8sKeyID         = "k8s-key"
	k8sClaimsKey     = "kubernetes.io"
)

// singleAudience requires aud to be one string or a one-element array.
var singleAudience = authn.CheckFunc(func(claims map[string]any, _ time.Time) error {
	switch aud := claims["aud"].(type) {
	case string:
		return nil
	case []any:
		if len(aud) == 1 {
			return nil
		}
	}
	return errors.New("aud must hold exactly one value")
})

// projectedServiceAccount requires the kubernetes.io claims to agree with sub
// and to carry a UID.
var projectedServiceAccount = authn.CheckFunc(func(claims map[string]any, _ time.Time) error {
	sub, _ := claims["sub"].(string)
	rest, ok := strings.CutPrefix(sub, k8sSubjectPrefix)
	namespace, name, _ := strings.Cut(rest, ":")
	k8s, _ := claims[k8sClaimsKey].(map[string]any)
	sa, _ := k8s["serviceaccount"].(map[string]any)
	if uid, _ := sa["uid"].(string); !ok || namespace == "" || name == "" ||
		k8s["namespace"] != namespace || sa["name"] != name || uid == "" {
		return errors.New("kubernetes.io claims do not match sub")
	}
	return nil
})

// staticKeys is a KeyProvider holding one RSA key.
type staticKeys struct {
	key *rsa.PrivateKey
}

func (s staticKeys) PublicKeys(context.Context) ([]authn.PublicKey, error) {
	return []authn.PublicKey{{KeyID: k8sKeyID, Key: crypto.PublicKey(&s.key.PublicKey)}}, nil
}

// k8sClaims returns the claims of a valid projected token.
func k8sClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "https://kubernetes.default.svc",
		"sub": k8sSubjectPrefix + k8sNamespace + ":" + k8sServiceAcct,
		"aud": []string{k8sAudience},
		"iat": now.Unix(),
		"exp": now.Add(30 * time.Minute).Unix(),
		k8sClaimsKey: map[string]any{
			"namespace": k8sNamespace,
			"serviceaccount": map[string]any{
				"name": k8sServiceAcct,
				"uid":  "uid-1",
			},
		},
	}
}

// localIssuer serves OIDC discovery and an empty JWKS on loopback.
func localIssuer(t *testing.T) string {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestKubernetesProjectedServiceAccountChecks(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := localIssuer(t)
	v, err := authn.NewValidator(context.Background(), authn.Config{
		Issuer:               issuer,
		InsecureAllowHTTP:    true,
		AllowPrivateIP:       true,
		KeyProvider:          staticKeys{key: key},
		Audiences:            []string{k8sAudience},
		MaxRemainingLifetime: time.Hour,
		Checks:               []authn.Check{singleAudience, projectedServiceAccount},
	})
	require.NoError(t, err)
	t.Cleanup(v.Close)

	mint := func(t *testing.T, mutate func(jwt.MapClaims)) string {
		t.Helper()
		claims := k8sClaims()
		claims["iss"] = issuer
		if mutate != nil {
			mutate(claims)
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = k8sKeyID
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		return signed
	}
	tests := []struct {
		name       string
		mutate     func(jwt.MapClaims)
		wantReason authn.Reason
	}{
		{name: "good token"},
		{name: "good token with aud as a string", mutate: func(c jwt.MapClaims) { c["aud"] = k8sAudience }},
		{name: "namespace disagrees with sub", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) { c[k8sClaimsKey].(map[string]any)["namespace"] = "team-b" }},
		{name: "service account name disagrees with sub", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) {
				c[k8sClaimsKey].(map[string]any)["serviceaccount"].(map[string]any)["name"] = "admin"
			}},
		{name: "sub is not a service account", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) { c["sub"] = "alice" }},
		{name: "kubernetes.io claims missing", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) { delete(c, k8sClaimsKey) }},
		{name: "UID missing", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) {
				delete(c[k8sClaimsKey].(map[string]any)["serviceaccount"].(map[string]any), "uid")
			}},
		{name: "two audiences", wantReason: authn.ReasonCheck,
			mutate: func(c jwt.MapClaims) { c["aud"] = []string{k8sAudience, "https://other.example.com"} }},
		{name: "remaining lifetime above the ceiling", wantReason: authn.ReasonLifetime,
			mutate: func(c jwt.MapClaims) { c["exp"] = time.Now().Add(24 * time.Hour).Unix() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := v.Validate(context.Background(), mint(t, tt.mutate))
			if tt.wantReason == "" {
				require.NoError(t, err)
				assert.Equal(t, k8sSubjectPrefix+k8sNamespace+":"+k8sServiceAcct, p.Subject)
				return
			}
			var authnErr *authn.Error
			require.ErrorAs(t, err, &authnErr)
			assert.Equal(t, authn.CodeInvalidToken, authnErr.Code)
			assert.Equal(t, tt.wantReason, authnErr.Reason)
		})
	}
}
