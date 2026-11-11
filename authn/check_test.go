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

const secretDetail = "secret-detail"

func TestAcceptChecks(t *testing.T) {
	t.Parallel()

	now := time.Now()
	reject := CheckFunc(func(map[string]any, time.Time) error { return errors.New(secretDetail) })
	explode := CheckFunc(func(map[string]any, time.Time) error { panic(secretDetail) })
	pass := CheckFunc(func(map[string]any, time.Time) error { return nil })

	tests := []struct {
		name   string
		checks []Check
		want   Reason
		detail string
	}{
		{"error rejects", []Check{pass, reject}, ReasonCheck, "check 1 rejected the token"},
		{"panic rejects", []Check{explode}, ReasonCheck, "check 0 panicked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := acceptPolicy{allowAnyAudience: true, checks: tt.checks, profile: "prof", trustID: "t1"}
			err := accept(&p, jwt.MapClaims{}, nil, now)
			require.Equal(t, tt.want, reasonOf(t, err))
			if err != nil {
				assert.Contains(t, err.Error(), tt.detail+` (profile "prof", trust "t1")`)
				assert.NotContains(t, err.Error(), secretDetail)
				assert.False(t, PossiblyOpaque(err))
			}
		})
	}

	t.Run("each check gets its own copy and the policy's now", func(t *testing.T) {
		t.Parallel()
		claims := jwt.MapClaims{"nested": map[string]any{"a": "b"}}
		mutate := CheckFunc(func(c map[string]any, got time.Time) error {
			assert.Equal(t, now, got)
			c["nested"].(map[string]any)["a"] = "changed"
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
