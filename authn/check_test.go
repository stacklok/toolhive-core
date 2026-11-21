// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const checkDetail = "check-detail"

func TestAcceptChecks(t *testing.T) {
	t.Parallel()

	now := time.Now()
	errReject := errors.New(checkDetail)
	reject := CheckFunc(func(map[string]any, time.Time) error { return errReject })
	explode := CheckFunc(func(map[string]any, time.Time) error { panic(checkDetail) })
	pass := CheckFunc(func(map[string]any, time.Time) error { return nil })

	tests := []struct {
		name      string
		checks    []Check
		trustID   string
		detail    string
		wantsWrap bool
	}{
		{"error rejects", []Check{pass, reject}, "", "check 1 rejected the token: " + checkDetail, true},
		{"error rejects in a trust", []Check{pass, reject}, "t1", `check 1 of trust "t1" rejected the token: ` + checkDetail, true},
		{"panic rejects", []Check{explode}, "", "check 0 panicked", false},
		{"panic rejects in a trust", []Check{explode}, "t1", `check 0 of trust "t1" panicked`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := acceptPolicy{allowAnyAudience: true, checks: tt.checks, trustID: tt.trustID}
			err := accept(&p, jwt.MapClaims{}, nil, now)
			require.Equal(t, ReasonCheck, reasonOf(t, err))
			assert.Contains(t, err.Error(), tt.detail)
			assert.Equal(t, tt.wantsWrap, errors.Is(err, errReject))
			if !tt.wantsWrap {
				assert.NotContains(t, err.Error(), checkDetail, "a panic value is not recorded")
			}
			assert.False(t, PossiblyOpaque(err))
		})
	}

	t.Run("each check gets its own copy and the policy's now", func(t *testing.T) {
		t.Parallel()
		claims := jwt.MapClaims{"nested": map[string]any{"a": "b"}}
		mutate := CheckFunc(func(c map[string]any, got time.Time) error {
			assert.Equal(t, now, got)
			c["nested"].(map[string]any)["a"] = testChanged
			return nil
		})
		verify := CheckFunc(func(c map[string]any, _ time.Time) error {
			assert.Equal(t, "b", c["nested"].(map[string]any)["a"])
			return nil
		})
		p := acceptPolicy{allowAnyAudience: true, checks: []Check{mutate, verify}}
		require.NoError(t, accept(&p, claims, nil, now))
		assert.Equal(t, "b", claims["nested"].(map[string]any)["a"])
	})
}

func TestAcceptMaxRemainingLifetime(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name string
		max  time.Duration
		exp  time.Duration
		want Reason
	}{
		{"within", time.Hour, 30 * time.Minute, ""},
		{"above", time.Hour, 2 * time.Hour, ReasonLifetime},
		{"disabled", 0, 1000 * time.Hour, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := acceptPolicy{allowAnyAudience: true, maxRemaining: tt.max}
			claims := jwt.MapClaims{"exp": float64(now.Add(tt.exp).Unix())}
			require.Equal(t, tt.want, reasonOf(t, accept(&p, claims, nil, now)))
		})
	}
}

func TestRejectIDTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{"access token", map[string]any{"sub": "a"}, false},
		{"at_hash", map[string]any{"at_hash": "x"}, true},
		{"c_hash", map[string]any{"c_hash": "x"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, RejectIDTokens.Check(tt.claims, time.Now()) != nil)
		})
	}
}
