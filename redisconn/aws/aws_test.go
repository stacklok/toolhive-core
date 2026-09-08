// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

const (
	testRegion  = "us-east-1"
	testCluster = "example-cache"
	testUser    = "appuser"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"username", Config{Region: testRegion, ClusterName: testCluster}, "username"},
		{"region", Config{Username: testUser, ClusterName: testCluster}, "region"},
		{"cluster", Config{Username: testUser, Region: testRegion}, "cluster"},
		{"service", Config{Username: testUser, Region: testRegion, ClusterName: testCluster, ServiceName: "bad"}, "service name"},
		{"resource", Config{Username: testUser, Region: testRegion, ClusterName: testCluster, ResourceType: "bad"}, "resource type"},
		{"elasticache", Config{Username: testUser, Region: testRegion, ClusterName: testCluster}, ""},
		{"memorydb serverless", Config{Username: testUser, Region: testRegion, ClusterName: testCluster, ServiceName: ServiceMemoryDB, ResourceType: ResourceTypeServerlessCache}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.want == "" && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestResolveRegion(t *testing.T) {
	region, err := resolveRegion(t.Context(), testRegion)
	if err != nil || region != testRegion {
		t.Fatalf("resolveRegion() = %q, %v", region, err)
	}
	if _, err := resolveRegion(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("empty region error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := resolveRegion(ctx, RegionDetect); err == nil || !strings.Contains(err.Error(), "IMDS") {
		t.Fatalf("detect error = %v", err)
	}
}

var fakeCredentials = awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
	return awssdk.Credentials{AccessKeyID: "AKIAFAKEFAKEFAKEFAKE", SecretAccessKey: "fakefakefakefakefakefakefakefakefakefake"}, nil
})

func TestBuildToken(t *testing.T) {
	tests := []struct {
		name, service, resource string
	}{
		{"provisioned", ServiceElastiCache, ""},
		{"serverless", ServiceElastiCache, ResourceTypeServerlessCache},
		{"memorydb", ServiceMemoryDB, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := buildToken(t.Context(), fakeCredentials, testRegion, tt.service, testCluster, tt.resource, testUser)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(token, "https://") {
				t.Fatal("token retained URL scheme")
			}
			u, err := url.Parse("https://" + token)
			if err != nil {
				t.Fatal(err)
			}
			query := u.Query()
			if u.Host != testCluster || query.Get("Action") != "connect" || query.Get("User") != testUser {
				t.Fatalf("unexpected token URL %q", token)
			}
			if query.Get("X-Amz-Expires") != tokenExpirySeconds || query.Get("ResourceType") != tt.resource || query.Get("X-Amz-Signature") == "" {
				t.Fatalf("unexpected token query %v", query)
			}
			if !strings.Contains(query.Get("X-Amz-Credential"), "/"+testRegion+"/"+tt.service+"/") {
				t.Fatalf("unexpected credential scope %q", query.Get("X-Amz-Credential"))
			}
		})
	}
}

func TestDynamicAuthLifetimeAndCredentials(t *testing.T) {
	cfg := Config{Username: testUser, Region: testRegion, ClusterName: testCluster}
	auth := dynamicAuth(cfg, fakeCredentials, testRegion, ServiceElastiCache)
	if auth.ConnMaxLifetime != DefaultConnMaxLifetime {
		t.Fatalf("lifetime = %v", auth.ConnMaxLifetime)
	}
	username, token, err := auth.CredentialsProviderContext(t.Context())
	if err != nil || username != testUser || token == "" {
		t.Fatalf("credentials = %q, %q, %v", username, token, err)
	}
}

func TestCredentialErrorIsRedacted(t *testing.T) {
	const secret = "private-credential-value"
	provider := awssdk.CredentialsProviderFunc(func(context.Context) (awssdk.Credentials, error) {
		return awssdk.Credentials{}, errors.New("credential retrieval failed")
	})
	auth := dynamicAuth(Config{Username: testUser, ClusterName: testCluster}, provider, testRegion, ServiceElastiCache)
	_, _, err := auth.CredentialsProviderContext(t.Context())
	if err == nil || !strings.Contains(err.Error(), "dynamic auth (awsElastiCacheIam)") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked credential: %v", err)
	}
}
