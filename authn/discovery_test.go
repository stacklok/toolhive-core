// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testDiscoveryConfig returns a Config with no JWKSURL, forcing the OIDC
// discovery path, with plain http permitted for httptest.
func testDiscoveryConfig(issuer string) Config {
	cfg := validConfig()
	cfg.Issuer = issuer
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	return cfg
}

// discoveryServer builds an httptest server whose handler is configured with
// the server's own URL (for issuer fields). newHandler receives the server
// URL and returns the handler.
func discoveryServer(t *testing.T, newHandler func(srvURL string) http.HandlerFunc) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		newHandler(srv.URL).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newDiscoveryOnlyServer builds an httptest server that serves a well-formed
// discovery document and the empty JWKS, for tests outside the discovery test
// file that need NewValidator to succeed via the discovery path.
func newDiscoveryOnlyServer(t *testing.T) *httptest.Server {
	t.Helper()
	return discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return serveDiscovery(srvURL, srvURL+"/jwks.json", nil)
	})
}

// serveDiscovery returns a handler serving a discovery document with the
// given issuer/jwksURI at the well-known path (on both the bare and
// multi-path variants), plus the empty JWKS at every */jwks.json.
func serveDiscovery(issuer, jwksURI string, jwksHits *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == oidcDiscoveryPath || strings.HasSuffix(r.URL.Path, oidcDiscoveryPath):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, jwksURI)
		case strings.HasSuffix(r.URL.Path, "/jwks.json"):
			if jwksHits != nil {
				jwksHits.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(emptyJWKS))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// TestDiscoveryHappyPath covers the empty-JWKSURL path: the JWKS URL is
// discovered from the issuer metadata, added to the whitelist, registered,
// and fetched during construction (fail closed with key material available).
func TestDiscoveryHappyPath(t *testing.T) {
	t.Parallel()

	var jwksFetches atomic.Int32
	srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return serveDiscovery(srvURL, srvURL+"/jwks.json", &jwksFetches)
	})

	v, err := NewValidator(context.Background(), testDiscoveryConfig(srv.URL))
	require.NoError(t, err)
	require.NotNil(t, v)
	t.Cleanup(v.Close)

	wantJWKSURL := srv.URL + "/jwks.json"
	assert.Equal(t, wantJWKSURL, v.jwksURL, "jwksURL must be the discovered jwks_uri")
	assert.True(t, v.jwksWhitelist.IsAllowed(wantJWKSURL), "discovered jwks_uri must be whitelisted")
	assert.False(t, v.jwksWhitelist.IsAllowed(srv.URL+"/other.json"))
	assert.Positive(t, jwksFetches.Load(), "discovered JWKS must be fetched during construction")
	set, err := v.jwksCache.Lookup(t.Context(), wantJWKSURL)
	require.NoError(t, err, "key material must be available immediately after construction")
	assert.Equal(t, 0, set.Len())
}

// TestDiscoveryIssuerWithPath proves the issuer/path join preserves a
// multi-path issuer (https://host/realms/X): the well-known segment is
// appended, not joined in a way that strips leading path segments.
func TestDiscoveryIssuerWithPath(t *testing.T) {
	t.Parallel()

	// The configured issuer may or may not end in a trailing slash; either
	// way the discovery URL must have exactly one "/" before .well-known.
	for _, hasTrailingSlash := range []bool{false, true} {
		name := "no trailing slash"
		if hasTrailingSlash {
			name = "trailing slash"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
				issuer := srvURL + "/realms/X"
				if hasTrailingSlash {
					// Byte-exact issuer assertion: the document must echo the
					// configured issuer exactly, trailing slash included.
					issuer += "/"
				}
				return serveDiscovery(issuer, strings.TrimSuffix(issuer, "/")+"/jwks.json", nil)
			})

			suffix := ""
			if hasTrailingSlash {
				suffix = "/"
			}
			cfg := testDiscoveryConfig(srv.URL + "/realms/X" + suffix)
			v, err := NewValidator(context.Background(), cfg)
			require.NoError(t, err)
			require.NotNil(t, v)
			t.Cleanup(v.Close)
			assert.Equal(t, srv.URL+"/realms/X/jwks.json", v.jwksURL)
		})
	}
}

// TestDiscoveryIssuerMismatch pins the byte-exact issuer assertion (OIDC
// Discovery §4.3 / RFC 8414 §3.3): ANY difference between the discovered
// issuer and the configured one is a construction error, fail closed. Without
// this check a poisoned well-known could repoint jwks_uri at an attacker JWKS
// while every downstream check still passes.
func TestDiscoveryIssuerMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// docIssuer receives the configured issuer; return the value to
		// serve in the discovery document's issuer field.
		docIssuer func(cfgIssuer string) string
	}{
		{name: "trailing slash added", docIssuer: func(iss string) string { return iss + "/" }},
		{name: "different host", docIssuer: func(string) string { return "https://evil.example.com" }},
		{name: "padded whitespace", docIssuer: func(iss string) string { return iss + " \n" }},
		{name: "case difference", docIssuer: func(iss string) string { return strings.ToUpper(iss) }},
		{name: "issuer field missing", docIssuer: func(string) string { return "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
				return serveDiscovery(tt.docIssuer(srvURL), srvURL+"/jwks.json", nil)
			})

			v, err := NewValidator(context.Background(), testDiscoveryConfig(srv.URL))
			require.Error(t, err)
			assert.Nil(t, v)
			assert.Contains(t, err.Error(), "does not match configured issuer")
			var authnErr *Error
			assert.NotErrorAs(t, err, &authnErr, "discovery failures are ordinary construction errors, not *Error")
		})
	}
}

// TestDiscoveryFailures covers the fail-closed discovery error cases.
func TestDiscoveryFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler func(srvURL string) http.HandlerFunc
		wantErr string
	}{
		{
			name: "missing jwks_uri",
			handler: func(srvURL string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"issuer":%q}`, srvURL)
				}
			},
			wantErr: "missing jwks_uri",
		},
		{
			name: "non-200 status",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}
			},
			wantErr: "returned status 500",
		},
		{
			name: "non-JSON HTML body",
			handler: func(string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<html><body>not json</body></html>"))
				}
			},
			wantErr: "failed to decode",
		},
		{
			name: "jwks_uri not a URI",
			handler: func(srvURL string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"not a uri"}`, srvURL)
				}
			},
			wantErr: "discovered jwks_uri",
		},
		{
			name: "jwks_uri without host",
			handler: func(srvURL string) http.HandlerFunc {
				return func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"https:///jwks.json"}`, srvURL)
				}
			},
			wantErr: "discovered jwks_uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := discoveryServer(t, tt.handler)

			v, err := NewValidator(context.Background(), testDiscoveryConfig(srv.URL))
			require.Error(t, err)
			assert.Nil(t, v)
			assert.Contains(t, err.Error(), tt.wantErr)
			var authnErr *Error
			assert.NotErrorAs(t, err, &authnErr)
		})
	}
}

// TestDiscoveryUnreachableJWKSEndpoint proves fail-closed behavior when the
// discovered jwks_uri points at an unreachable host: discovery itself
// succeeds but the construction-time first fetch must fail NewValidator.
func TestDiscoveryUnreachableJWKSEndpoint(t *testing.T) {
	t.Parallel()

	// Bind and close to obtain an address that refuses connections.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return serveDiscovery(srvURL, deadURL+"/jwks.json", nil)
	})

	v, err := NewValidator(context.Background(), testDiscoveryConfig(srv.URL))
	require.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
	var authnErr *Error
	assert.NotErrorAs(t, err, &authnErr)
}

// TestDiscoveryNonHTTPSJWKSURIRejected proves the discovered jwks_uri is
// validated exactly as if configured: an http jwks_uri is rejected when
// InsecureAllowHTTP is false.
func TestDiscoveryNonHTTPSJWKSURIRejected(t *testing.T) {
	t.Parallel()

	// Discovery is served over TLS so the issuer passes validation without
	// InsecureAllowHTTP; the document then advertises a plain-http jwks_uri.
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == oidcDiscoveryPath {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":"http://%s/jwks.json"}`, srv.URL, srv.Listener.Addr().String())
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.HTTPClient = srv.Client() // trusts the test server's CA
	v, err := NewValidator(context.Background(), cfg)
	require.Error(t, err)
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "discovered jwks_uri")
	assert.Contains(t, err.Error(), "https")
}
