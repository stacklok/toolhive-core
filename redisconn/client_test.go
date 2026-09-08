// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisconn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

const testAddr = "redis:6379"

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	provider := func(context.Context) (string, string, error) { return "user", "token", nil }
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil", nil, "config is nil"},
		{"missing topology", &Config{}, "one of addr"},
		{"conflicting topology", &Config{Addr: testAddr, SentinelConfig: &SentinelConfig{}}, "mutually exclusive"},
		{"sentinel master", &Config{SentinelConfig: &SentinelConfig{SentinelAddrs: []string{"s:26379"}}}, "master name"},
		{"sentinel addresses", &Config{SentinelConfig: &SentinelConfig{MasterName: "main"}}, "sentinel address"},
		{"mTLS pair", &Config{Addr: testAddr, TLS: &TLSConfig{ClientCert: []byte("cert")}}, "provided together"},
		{"dynamic provider", &Config{Addr: testAddr, DynamicAuth: &DynamicAuth{AllowInsecureTransport: true}}, "credentials provider"},
		{"dynamic static password", &Config{Addr: testAddr, Password: "secret", DynamicAuth: &DynamicAuth{CredentialsProviderContext: provider, AllowInsecureTransport: true}}, "password must not"},
		{"dynamic plaintext", &Config{Addr: testAddr, DynamicAuth: &DynamicAuth{CredentialsProviderContext: provider}}, "TLS is required"},
		{"dynamic unverified TLS", &Config{Addr: testAddr, TLS: &TLSConfig{InsecureSkipVerify: true}, DynamicAuth: &DynamicAuth{CredentialsProviderContext: provider}}, "TLS must verify"},
		{"dynamic verified TLS", &Config{Addr: testAddr, TLS: &TLSConfig{}, DynamicAuth: &DynamicAuth{CredentialsProviderContext: provider}}, ""},
		{"dynamic insecure opt-out", &Config{Addr: testAddr, DynamicAuth: &DynamicAuth{CredentialsProviderContext: provider, AllowInsecureTransport: true}}, ""},
		{"standalone", &Config{Addr: testAddr}, ""},
		{"cluster", &Config{Addr: testAddr, ClusterMode: true}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
			} else if err == nil || !contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestNewClientStaticAuthAndDatabase(t *testing.T) {
	t.Parallel()
	const password = "test-token"
	srv := miniredis.RunT(t)
	srv.RequireAuth(password)
	client, err := NewClient(t.Context(), &Config{Addr: srv.Addr(), Password: password, DB: 3})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Set(t.Context(), "key", "value", 0).Err(); err != nil {
		t.Fatal(err)
	}
	if got, err := client.Get(t.Context(), "key").Result(); err != nil || got != "value" {
		t.Fatalf("Get() = %q, %v", got, err)
	}
}

func TestNewClientDynamicAuthReceivesConnectionContext(t *testing.T) {
	t.Parallel()
	const password = "dynamic-token"
	type key struct{}
	srv := miniredis.RunT(t)
	srv.RequireAuth(password)
	var got any
	provider := func(ctx context.Context) (string, string, error) {
		got = ctx.Value(key{})
		return "", password, nil
	}
	ctx := context.WithValue(t.Context(), key{}, "connection-context")
	client, err := NewClient(ctx, &Config{Addr: srv.Addr(), DB: 2, DynamicAuth: &DynamicAuth{
		CredentialsProviderContext: provider, ConnMaxLifetime: 12 * time.Minute, AllowInsecureTransport: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if got != "connection-context" {
		t.Fatalf("provider context value = %v", got)
	}
	opts := client.(*goredis.Client).Options()
	if opts.CredentialsProviderContext == nil || opts.OnConnect != nil {
		t.Fatal("dynamic provider was not installed before HELLO/AUTH")
	}
	if opts.ConnMaxLifetime != 12*time.Minute {
		t.Fatalf("ConnMaxLifetime = %v", opts.ConnMaxLifetime)
	}
}

func TestNewClientDoesNotMutateAndDefaultsTimeouts(t *testing.T) {
	t.Parallel()
	srv := miniredis.RunT(t)
	cfg := &Config{Addr: srv.Addr()}
	client, err := NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if cfg.DialTimeout != 0 || cfg.ReadTimeout != 0 || cfg.WriteTimeout != 0 {
		t.Fatal("caller config mutated")
	}
	opts := client.(*goredis.Client).Options()
	if opts.DialTimeout != DefaultDialTimeout || opts.ReadTimeout != DefaultReadTimeout || opts.WriteTimeout != DefaultWriteTimeout {
		t.Fatalf("timeouts = %v, %v, %v", opts.DialTimeout, opts.ReadTimeout, opts.WriteTimeout)
	}
}

func TestNewClientPingFailure(t *testing.T) {
	t.Parallel()
	_, err := NewClient(t.Context(), &Config{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond})
	if err == nil || !contains(err.Error(), "failed to connect") {
		t.Fatalf("NewClient() error = %v", err)
	}
}

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()
	caPEM, certPEM, keyPEM := testCertificate(t)
	tests := []struct {
		name string
		cfg  *TLSConfig
		want string
	}{
		{"nil", nil, ""},
		{"system roots", &TLSConfig{}, ""},
		{"custom CA", &TLSConfig{CACert: caPEM}, ""},
		{"mTLS", &TLSConfig{ClientCert: certPEM, ClientKey: keyPEM}, ""},
		{"invalid CA", &TLSConfig{CACert: []byte("bad")}, "failed to parse CA"},
		{"incomplete mTLS", &TLSConfig{ClientCert: certPEM}, "provided together"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := BuildTLSConfig(tt.cfg)
			if tt.want != "" {
				if err == nil || !contains(err.Error(), tt.want) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.cfg == nil {
				if got != nil {
					t.Fatal("nil config enabled TLS")
				}
			} else if got.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion = %d", got.MinVersion)
			}
		})
	}
}

func TestSentinelDynamicProviderStaysOnDataNodeOptions(t *testing.T) {
	t.Parallel()
	provider := func(context.Context) (string, string, error) { return "user", "token", nil }
	cfg := &Config{SentinelConfig: &SentinelConfig{MasterName: "main", SentinelAddrs: []string{"s:26379"}}, DynamicAuth: &DynamicAuth{
		CredentialsProviderContext: provider, AllowInsecureTransport: true,
	}}
	cfg.applyDefaults()
	client, err := buildSentinelClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	opts := client.(*goredis.Client).Options()
	if opts.CredentialsProviderContext == nil {
		t.Fatal("data-node provider missing")
	}
	if opts.OnConnect != nil {
		t.Fatal("OnConnect would propagate to Sentinel connections")
	}
}

func testCertificate(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, certPEM, keyPEM
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
