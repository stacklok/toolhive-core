// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"fmt"
	"testing"

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
