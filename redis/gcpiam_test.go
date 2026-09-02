// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// blockingTokenSource is a stub oauth2.TokenSource that blocks until unblock
// is closed, then returns token/err. It stands in for a stalled GCP token
// refresh so tokenWithContext's cancellation behavior can be tested without
// real network calls or credentials.
type blockingTokenSource struct {
	unblock chan struct{}
	token   *oauth2.Token
	err     error
}

func (b *blockingTokenSource) Token() (*oauth2.Token, error) {
	<-b.unblock
	return b.token, b.err
}

func TestTokenWithContext_ReturnsPromptlyOnCancellation(t *testing.T) {
	t.Parallel()

	ts := &blockingTokenSource{unblock: make(chan struct{})} // never closed: Token() blocks forever
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	var gotErr error
	go func() {
		_, gotErr = tokenWithContext(ctx, ts)
		close(done)
	}()

	cancel()
	select {
	case <-done:
		require.Error(t, gotErr)
		assert.ErrorIs(t, gotErr, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("tokenWithContext did not return promptly after ctx cancellation")
	}
}

func TestTokenWithContext_ReturnsTokenOnSuccess(t *testing.T) {
	t.Parallel()

	want := &oauth2.Token{AccessToken: "test-access-token"}
	ts := &blockingTokenSource{unblock: make(chan struct{}), token: want}
	close(ts.unblock)

	got, err := tokenWithContext(t.Context(), ts)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestTokenWithContext_PropagatesUnderlyingError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("token refresh failed")
	ts := &blockingTokenSource{unblock: make(chan struct{}), err: wantErr}
	close(ts.unblock)

	_, err := tokenWithContext(t.Context(), ts)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}
