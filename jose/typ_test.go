// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package jose

import "testing"

func TestIsJOSEType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		headerTyp string
		mediaType string
		want      bool
	}{
		{"exact", JWTTypeAccessToken, JWTTypeAccessToken, true},
		{"case-insensitive", "AT+JWT", JWTTypeAccessToken, true},
		{"prefix on header", "application/at+jwt", JWTTypeAccessToken, true},
		{"prefix on media type", JWTTypeAccessToken, "application/at+jwt", true},
		{"different type", "JWT", JWTTypeAccessToken, false},
		{"empty header", "", JWTTypeAccessToken, false},
		{"prefix only", "application/", "application/", false},
		{"whitespace not trimmed", " at+jwt", JWTTypeAccessToken, false},
		{"double prefix", "application/application/at+jwt", JWTTypeAccessToken, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsJOSEType(tt.headerTyp, tt.mediaType); got != tt.want {
				t.Errorf("IsJOSEType(%q, %q) = %v, want %v", tt.headerTyp, tt.mediaType, got, tt.want)
			}
		})
	}
}

func TestIsIDJAG(t *testing.T) {
	t.Parallel()

	if !IsIDJAG("application/OAUTH-ID-JAG+JWT") || IsIDJAG(JWTTypeAccessToken) {
		t.Error("IsIDJAG must match only the ID-JAG type")
	}
}
