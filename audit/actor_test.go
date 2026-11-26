// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestActorFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ctx      context.Context
		wantOK   bool
		wantKind PrincipalKind
		wantID   string
	}{
		{name: "none", ctx: context.Background()},
		{name: "zero actor", ctx: ContextWithActor(context.Background(), Actor{})},
		{name: "unknown kind", ctx: ContextWithActor(context.Background(), Actor{kind: "robot", userID: "r"})},
		{name: "service account without id", ctx: ContextWithActor(context.Background(), NewServiceAccountActor(""))},
		{name: "scim issuer without id", ctx: ContextWithActor(context.Background(), NewSCIMIssuerActor("", "fp"))},
		{
			name:     "user",
			ctx:      ContextWithActor(context.Background(), NewUserActor(testUserID, testIssuer)),
			wantOK:   true,
			wantKind: PrincipalKindUser,
			wantID:   testUserID,
		},
		{
			name:     "anonymous",
			ctx:      ContextWithActor(context.Background(), NewAnonymousActor()),
			wantOK:   true,
			wantKind: PrincipalKindAnonymous,
		},
		{
			name: "latest actor wins",
			ctx: ContextWithActor(
				ContextWithActor(context.Background(), NewUserActor(testUserID, testIssuer)),
				NewSystemActor("jobs.cleanup")),
			wantOK:   true,
			wantKind: PrincipalKindSystem,
			wantID:   "jobs.cleanup",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a, ok := ActorFromContext(tt.ctx)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantKind, a.Kind())
			assert.Equal(t, tt.wantID, a.UserID())
		})
	}
}

func TestRequestIDFromContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ctx    context.Context
		want   string
		wantOK bool
	}{
		{name: "none", ctx: context.Background()},
		{name: "empty", ctx: ContextWithRequestID(context.Background(), "")},
		{name: "set", ctx: ContextWithRequestID(context.Background(), "req-1"), want: "req-1", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := RequestIDFromContext(tt.ctx)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
