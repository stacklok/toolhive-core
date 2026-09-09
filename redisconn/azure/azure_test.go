// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeCredential struct {
	token  string
	err    error
	scopes []string
}

func (f *fakeCredential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.scopes = options.Scopes
	return azcore.AccessToken{Token: f.token}, f.err
}

const testPrincipalID = "principal-id"

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, username, want string }{{"missing", "", "username"}, {"valid", testPrincipalID, ""}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := (Config{Username: tt.username}).Validate()
			if tt.want == "" && err != nil {
				t.Fatal(err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestNewDynamicAuthIsLazy(t *testing.T) {
	t.Parallel()
	auth, err := NewDynamicAuth(Config{Username: testPrincipalID})
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil || auth.CredentialsProviderContext == nil || auth.ConnMaxLifetime != DefaultConnMaxLifetime {
		t.Fatalf("auth = %#v", auth)
	}
}

func TestDynamicAuthCredentials(t *testing.T) {
	t.Parallel()
	credential := &fakeCredential{token: "access-token"}
	auth := dynamicAuth(testPrincipalID, credential)
	username, password, err := auth.CredentialsProviderContext(t.Context())
	if err != nil || username != testPrincipalID || password != "access-token" {
		t.Fatalf("credentials = %q, %q, %v", username, password, err)
	}
	if len(credential.scopes) != 1 || credential.scopes[0] != Scope {
		t.Fatalf("scopes = %v", credential.scopes)
	}
}

func TestDynamicAuthErrorIsRedacted(t *testing.T) {
	t.Parallel()
	credential := &fakeCredential{err: errors.New("token acquisition failed")}
	auth := dynamicAuth(testPrincipalID, credential)
	username, password, err := auth.CredentialsProviderContext(t.Context())
	if err == nil || username != "" || password != "" || !strings.Contains(err.Error(), "dynamic auth (azureAd)") {
		t.Fatalf("credentials = %q, %q, %v", username, password, err)
	}
}
