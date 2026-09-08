// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const testAccessToken = "access-token"

type tokenSource struct {
	unblock  chan struct{}
	returned chan struct{}
	token    *oauth2.Token
	err      error
}

func (s *tokenSource) Token() (*oauth2.Token, error) {
	if s.returned != nil {
		defer close(s.returned)
	}
	if s.unblock != nil {
		<-s.unblock
	}
	return s.token, s.err
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		enabled bool
		want    string
	}{{"missing marker", false, "marker"}, {"enabled", true, ""}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := (Config{MemorystoreIAM: tt.enabled}).Validate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(strings.ToLower(err.Error()), tt.want)) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTokenWithContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		token  *oauth2.Token
		err    error
		cancel bool
	}{
		{"success", &oauth2.Token{AccessToken: testAccessToken}, nil, false},
		{"source error", nil, errors.New("refresh failed"), false},
		{"canceled", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			source := &tokenSource{token: tt.token, err: tt.err}
			ctx := t.Context()
			if tt.cancel {
				source.unblock = make(chan struct{})
				source.returned = make(chan struct{})
				t.Cleanup(func() {
					close(source.unblock)
					<-source.returned
				})
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			got, err := tokenWithContext(ctx, source)
			if tt.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
			if !tt.cancel && !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want %v", err, tt.err)
			}
			if !tt.cancel && got != tt.token {
				t.Fatalf("token = %#v", got)
			}
		})
	}
}

func TestDynamicAuthTokenOnlyAndLifetime(t *testing.T) {
	t.Parallel()
	auth := dynamicAuth(&tokenSource{token: &oauth2.Token{AccessToken: testAccessToken}})
	if auth.ConnMaxLifetime != DefaultConnMaxLifetime {
		t.Fatalf("lifetime = %v", auth.ConnMaxLifetime)
	}
	username, password, err := auth.CredentialsProviderContext(t.Context())
	if err != nil || username != "" || password != testAccessToken {
		t.Fatalf("credentials = %q, %q, %v", username, password, err)
	}
}

func TestDynamicAuthHonorsCancellation(t *testing.T) {
	t.Parallel()
	source := &tokenSource{unblock: make(chan struct{}), returned: make(chan struct{})}
	t.Cleanup(func() {
		close(source.unblock)
		<-source.returned
	})
	auth := dynamicAuth(source)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { _, _, err := auth.CredentialsProviderContext(ctx); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("credential callback ignored cancellation")
	}
}
