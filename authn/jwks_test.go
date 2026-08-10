// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyJWKS is a syntactically valid JWKS document with no keys. jwk.Parse
// accepts it, so it is enough to satisfy Register's first-fetch readiness
// check; key material is not exercised until Step 4 (keyfunc) / Step 5
// (Validate).
const emptyJWKS = `{"keys":[]}`

// testJWKSConfig returns a Config pointing at srv with plain http permitted.
func testJWKSConfig(srv *httptest.Server) Config {
	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.JWKSURL = srv.URL + "/jwks.json"
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	return cfg
}

// TestNewValidatorJWKSRegistration covers the construction-time JWKS
// registration contract: the first fetch must complete during NewValidator
// (fail closed), and registration failures are ordinary construction errors,
// never the *Error type.
func TestNewValidatorJWKSRegistration(t *testing.T) {
	t.Parallel()

	newValidatorFromHandler := func(t *testing.T, handler http.Handler) (*Validator, error) {
		t.Helper()
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		return NewValidator(context.Background(), testJWKSConfig(srv))
	}

	t.Run("reachable JWKS succeeds", func(t *testing.T) {
		t.Parallel()

		var fetches atomic.Int32
		v, err := newValidatorFromHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			fetches.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(emptyJWKS))
		}))
		require.NoError(t, err)
		require.NotNil(t, v)
		t.Cleanup(v.Close)

		assert.Equal(t, v.cfg.JWKSURL, v.jwksURL)
		// The background worker's immediate first fetch races with
		// construction's synchronous Refresh; both hit the server, so assert
		// the invariant (first fetch completed during construction) rather
		// than an exact count.
		assert.Positive(t, fetches.Load(), "first fetch must complete during construction")
		assert.True(t, v.jwksCache.IsRegistered(t.Context(), v.jwksURL))
		set, err := v.jwksCache.Lookup(t.Context(), v.jwksURL)
		require.NoError(t, err, "key set must be available immediately after construction")
		assert.Equal(t, 0, set.Len())
	})

	t.Run("unreachable JWKS fails construction", func(t *testing.T) {
		t.Parallel()

		// Bind a listener and close it immediately to obtain an address that
		// refuses connections.
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.Close()

		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.JWKSURL = srv.URL + "/jwks.json"
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err)
		assert.Nil(t, v)
		assert.Contains(t, err.Error(), "failed to fetch JWKS")
		var authnErr *Error
		assert.NotErrorAs(t, err, &authnErr, "construction failures are ordinary errors, not *Error")
	})

	t.Run("JWKS 404 fails construction", func(t *testing.T) {
		t.Parallel()

		v, err := newValidatorFromHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		require.Error(t, err)
		assert.Nil(t, v)
	})

	t.Run("JWKS 500 fails construction", func(t *testing.T) {
		t.Parallel()

		v, err := newValidatorFromHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		require.Error(t, err)
		assert.Nil(t, v)
	})

	t.Run("non-JWKS content fails construction", func(t *testing.T) {
		t.Parallel()

		v, err := newValidatorFromHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>not a jwks</body></html>"))
		}))
		require.Error(t, err)
		assert.Nil(t, v)
	})

	t.Run("malformed JSON fails construction", func(t *testing.T) {
		t.Parallel()

		v, err := newValidatorFromHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not json"))
		}))
		require.Error(t, err)
		assert.Nil(t, v)
	})
}

// TestJWKSRefreshIntervalPinned proves the refresh cadence is pinned to
// jwksRefreshInterval and not derived from the issuer's Cache-Control header:
// serving max-age=1 must NOT trigger a re-fetch once that second has passed
// (the 15m pin is far outside the observation window).
func TestJWKSRefreshIntervalPinned(t *testing.T) {
	t.Parallel()

	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=1")
		_, _ = w.Write([]byte(emptyJWKS))
	}))
	t.Cleanup(srv.Close)

	v, err := NewValidator(context.Background(), testJWKSConfig(srv))
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// The background worker's immediate first fetch races with construction's
	// synchronous Refresh; both hit the server. Let any such in-flight fetch
	// settle, then record the baseline.
	time.Sleep(100 * time.Millisecond)
	baseline := fetches.Load()
	require.Positive(t, baseline, "first fetch must complete during construction")

	// Well past max-age=1, far under the 15m pinned interval. If the issuer's
	// Cache-Control controlled the cadence, the background refresh would have
	// re-fetched by now.
	time.Sleep(3 * time.Second)
	assert.Equal(t, baseline, fetches.Load(),
		"Cache-Control: max-age=1 must not drive re-fetches; the interval is pinned at %s", jwksRefreshInterval)
}

// TestJWKSWhitelistRestrictsFetches proves the httprc client is whitelisted to
// the registered JWKS URL only: after construction, any URL that was not
// registered must be blocked by the whitelist, while the registered URL
// remains refreshable.
func TestJWKSWhitelistRestrictsFetches(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyJWKS))
	}))
	t.Cleanup(srv.Close)

	v, err := NewValidator(context.Background(), testJWKSConfig(srv))
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// A URL that was never registered must not pass the whitelist.
	err = v.jwksCache.Register(t.Context(), srv.URL+"/evil.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "whitelist")

	// The registered URL still passes: a forced refresh re-fetches it.
	_, err = v.jwksCache.Refresh(t.Context(), v.jwksURL)
	require.NoError(t, err)
}

// TestJWKSRegistrationUsesConfiguredHTTPClient proves the HTTP client supplied
// via Config is the one performing the first fetch (per-resource injection
// point in jwx v3).
func TestJWKSRegistrationUsesConfiguredHTTPClient(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyJWKS))
	}))
	t.Cleanup(srv.Close)

	var used atomic.Int32
	cfg := testJWKSConfig(srv)
	cfg.HTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		used.Add(1)
		return http.DefaultTransport.RoundTrip(req)
	})}

	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)
	assert.Positive(t, used.Load(), "the configured HTTP client must perform the JWKS fetch")
}

// TestJWKSRegistrationFailsWhenContextCanceled covers a caller canceling the
// context passed to NewValidator before construction: the first fetch aborts
// and NewValidator fails rather than returning a validator with no key
// material.
func TestJWKSRegistrationFailsWhenContextCanceled(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(emptyJWKS))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, err := NewValidator(ctx, testJWKSConfig(srv))
	require.Error(t, err)
	assert.Nil(t, v)
}
