// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

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
