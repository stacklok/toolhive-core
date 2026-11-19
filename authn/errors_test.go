// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPossiblyOpaque(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "non-*Error error",
			err:  errors.New("boom"),
			want: false,
		},
		{
			name: "wrapped *Error traversed via errors.As",
			err: fmt.Errorf("wrapped: %w", &Error{
				Code: CodeInvalidToken, Reason: ReasonMalformed,
			}),
			want: true,
		},
		{
			name: "Validate malformed token is possibly opaque",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonMalformed},
			want: true,
		},
		{
			name: "ParseBearer malformed header is not possibly opaque",
			err:  &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed},
			want: false,
		},
		{
			name: "invalid claims parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonInvalidClaims},
			want: false,
		},
		{
			name: "unsupported alg parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonUnsupportedAlg},
			want: false,
		},
		{
			name: "signature failure parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonSignature},
			want: false,
		},
		{
			name: "expired token parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonExpired},
			want: false,
		},
		{
			name: "issuer mismatch parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonIssuer},
			want: false,
		},
		{
			name: "audience mismatch parsed as a JWT",
			err:  &Error{Code: CodeInvalidToken, Reason: ReasonAudience},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, PossiblyOpaque(tt.err))
		})
	}
}

func TestCodeHTTPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code Code
		want int
	}{
		{CodeInvalidRequest, http.StatusBadRequest},
		{CodeInvalidToken, http.StatusUnauthorized},
		{CodeInsufficientScope, http.StatusForbidden},
		{CodeUnavailable, http.StatusServiceUnavailable},
		{Code("other"), http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.code.HTTPStatus())
		})
	}
}

func TestErrorRetryAfterAndScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        *Error
		wantRetry  time.Duration
		wantScopes []string
	}{
		{"nil", nil, 0, nil},
		{"unavailable default", &Error{Code: CodeUnavailable}, defaultRetryAfter, nil},
		{"unavailable explicit", &Error{Code: CodeUnavailable, retryAfter: time.Minute}, time.Minute, nil},
		{"retry ignored for other codes", &Error{Code: CodeInvalidToken, retryAfter: time.Minute}, 0, nil},
		{"scopes", &Error{Code: CodeInsufficientScope, scopes: []string{"a", "b"}}, 0, []string{"a", "b"}},
		{"scopes ignored for other codes", &Error{Code: CodeInvalidToken, scopes: []string{"a"}}, 0, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantRetry, tt.err.RetryAfter())
			assert.Equal(t, tt.wantScopes, tt.err.RequiredScopes())
		})
	}
}

func TestErrorMissingCredentialsAndHTTPStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		err         *Error
		wantMissing bool
		wantStatus  int
	}{
		{"missing header", &Error{Code: CodeInvalidRequest, Reason: ReasonMissingHeader}, true, http.StatusUnauthorized},
		{"unsupported scheme", &Error{Code: CodeInvalidRequest, Reason: ReasonUnsupportedScheme}, true, http.StatusUnauthorized},
		{"malformed header", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed}, false, http.StatusBadRequest},
		{"invalid token", &Error{Code: CodeInvalidToken, Reason: ReasonSignature}, false, http.StatusUnauthorized},
		{"insufficient scope", &Error{Code: CodeInsufficientScope, Reason: ReasonScope}, false, http.StatusForbidden},
		{"unavailable", &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable}, false, http.StatusServiceUnavailable},
		{"nil", nil, false, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.wantMissing, tt.err.MissingCredentials())
			assert.Equal(t, tt.wantStatus, tt.err.HTTPStatus())
		})
	}
}
