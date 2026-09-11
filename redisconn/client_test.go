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
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	miniredisserver "github.com/alicebob/miniredis/v2/server"
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
		{"negative pool size", &Config{Addr: testAddr, PoolSize: -1}, "pool size must not be negative"},
		{"negative max active connections", &Config{Addr: testAddr, MaxActiveConns: -1}, "max active connections must not be negative"},
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
		{"pool size larger than max active connections", &Config{Addr: testAddr, PoolSize: 8, MaxActiveConns: 4}, ""},
		{"max active connections larger than pool size", &Config{Addr: testAddr, PoolSize: 4, MaxActiveConns: 8}, ""},
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

func TestBuildClientsPropagatePoolOptions(t *testing.T) {
	t.Parallel()

	const (
		poolSize       = 3
		maxActiveConns = 7
	)

	t.Run("standalone options", func(t *testing.T) {
		cfg := &Config{Addr: testAddr, PoolSize: poolSize, MaxActiveConns: maxActiveConns}
		cfg.applyDefaults()
		client, err := buildStandaloneClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		opts := client.(*goredis.Client).Options()
		if opts.PoolSize != poolSize || opts.MaxActiveConns != maxActiveConns {
			t.Fatalf("pool options = (%d, %d), want (%d, %d)",
				opts.PoolSize, opts.MaxActiveConns, poolSize, maxActiveConns)
		}
	})

	t.Run("cluster options", func(t *testing.T) {
		cfg := &Config{Addr: testAddr, ClusterMode: true, PoolSize: poolSize, MaxActiveConns: maxActiveConns}
		cfg.applyDefaults()
		client, err := buildClusterClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		opts := client.(*goredis.ClusterClient).Options()
		if opts.PoolSize != poolSize || opts.MaxActiveConns != maxActiveConns {
			t.Fatalf("pool options = (%d, %d), want (%d, %d)",
				opts.PoolSize, opts.MaxActiveConns, poolSize, maxActiveConns)
		}
	})

	t.Run("failover options", func(t *testing.T) {
		cfg := &Config{
			SentinelConfig: &SentinelConfig{MasterName: "main", SentinelAddrs: []string{"s:26379"}},
			PoolSize:       poolSize,
			MaxActiveConns: maxActiveConns,
		}
		cfg.applyDefaults()
		opts, err := buildSentinelOptions(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if opts.PoolSize != poolSize || opts.MaxActiveConns != maxActiveConns {
			t.Fatalf("pool options = (%d, %d), want (%d, %d)",
				opts.PoolSize, opts.MaxActiveConns, poolSize, maxActiveConns)
		}
	})
}

func TestBuildClientsPreserveGoRedisPoolDefaults(t *testing.T) {
	t.Parallel()

	t.Run("standalone", func(t *testing.T) {
		cfg := &Config{Addr: testAddr}
		cfg.applyDefaults()
		client, err := buildStandaloneClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		opts := client.(*goredis.Client).Options()
		if opts.PoolSize != 10*runtime.GOMAXPROCS(0) || opts.MaxActiveConns != 0 {
			t.Fatalf("pool defaults = (%d, %d)", opts.PoolSize, opts.MaxActiveConns)
		}
	})

	t.Run("cluster", func(t *testing.T) {
		cfg := &Config{Addr: testAddr, ClusterMode: true}
		cfg.applyDefaults()
		client, err := buildClusterClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		opts := client.(*goredis.ClusterClient).Options()
		if opts.PoolSize != 5*runtime.GOMAXPROCS(0) || opts.MaxActiveConns != 0 {
			t.Fatalf("pool defaults = (%d, %d)", opts.PoolSize, opts.MaxActiveConns)
		}
	})

	t.Run("sentinel", func(t *testing.T) {
		cfg := &Config{SentinelConfig: &SentinelConfig{MasterName: "main", SentinelAddrs: []string{"s:26379"}}}
		cfg.applyDefaults()
		client, err := buildSentinelClient(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })

		opts := client.(*goredis.Client).Options()
		if opts.PoolSize != 10*runtime.GOMAXPROCS(0) || opts.MaxActiveConns != 0 {
			t.Fatalf("pool defaults = (%d, %d)", opts.PoolSize, opts.MaxActiveConns)
		}
	})
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
			} else {
				if got.MinVersion != tls.VersionTLS12 {
					t.Fatalf("MinVersion = %d", got.MinVersion)
				}
				if tt.name == "system roots" && got.RootCAs != nil {
					t.Fatal("RootCAs is non-nil; nil is required for standard-library system root discovery")
				}
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

func TestNewClientTLSCustomCAAndMutualTLS(t *testing.T) {
	t.Parallel()
	material := newTestTLSMaterial(t)
	srv, err := miniredis.RunTLS(&tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{material.serverCertificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: material.caPool,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	client, err := NewClient(t.Context(), &Config{Addr: srv.Addr(), TLS: &TLSConfig{
		CACert: material.caPEM, ClientCert: material.clientCertPEM, ClientKey: material.clientKeyPEM,
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Set(t.Context(), "tls-key", "tls-value", 0).Err(); err != nil {
		t.Fatal(err)
	}
}

func TestNewClientConfiguredLifetimeOverridesDynamicDefault(t *testing.T) {
	t.Parallel()
	srv := miniredis.RunT(t)
	client, err := NewClient(t.Context(), &Config{
		Addr: srv.Addr(), ConnMaxLifetime: 3 * time.Minute,
		DynamicAuth: &DynamicAuth{
			CredentialsProviderContext: func(context.Context) (string, string, error) { return "", "", nil },
			ConnMaxLifetime:            12 * time.Minute, AllowInsecureTransport: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if got := client.(*goredis.Client).Options().ConnMaxLifetime; got != 3*time.Minute {
		t.Fatalf("ConnMaxLifetime = %v, want 3m", got)
	}
}

func TestNewClientPingFailureClosesCandidate(t *testing.T) {
	t.Parallel()
	srv := miniredis.RunT(t)
	disconnected := make(chan struct{}, 1)
	srv.Server().SetPreHook(func(peer *miniredisserver.Peer, command string, _ ...string) bool {
		if !strings.EqualFold(command, "ping") {
			return false
		}
		peer.OnDisconnect(func() { disconnected <- struct{}{} })
		peer.WriteError("ping rejected")
		return true
	})

	_, err := NewClient(t.Context(), &Config{Addr: srv.Addr()})
	if err == nil || !contains(err.Error(), "failed to connect") {
		t.Fatalf("NewClient() error = %v", err)
	}
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("candidate connection was not closed after failed PING")
	}
}

func TestBuildClusterAndSentinelTLSOptions(t *testing.T) {
	t.Parallel()
	clusterMaterial := newTestTLSMaterial(t)
	clusterCfg := &Config{Addr: testAddr, ClusterMode: true, TLS: &TLSConfig{
		CACert: clusterMaterial.caPEM, ClientCert: clusterMaterial.clientCertPEM, ClientKey: clusterMaterial.clientKeyPEM,
	}}
	clusterCfg.applyDefaults()
	cluster, err := buildClusterClient(clusterCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cluster.Close() })
	clusterOpts := cluster.(*goredis.ClusterClient).Options()
	if clusterOpts.TLSConfig == nil || len(clusterOpts.TLSConfig.Certificates) != 1 || clusterOpts.TLSConfig.RootCAs == nil {
		t.Fatal("cluster TLS CA and client certificate were not installed")
	}

	masterMaterial := newTestTLSMaterial(t)
	sentinelMaterial := newTestTLSMaterial(t)
	masterAddr, masterDone := startTLSServer(t, masterMaterial.serverCertificate)
	sentinelAddr, sentinelDone := startTLSServer(t, sentinelMaterial.serverCertificate)
	sentinelCfg := &Config{
		SentinelConfig: &SentinelConfig{MasterName: "main", SentinelAddrs: []string{sentinelAddr}},
		TLS:            &TLSConfig{CACert: masterMaterial.caPEM}, SentinelTLS: &TLSConfig{CACert: sentinelMaterial.caPEM},
	}
	sentinelCfg.applyDefaults()
	sentinelOpts, err := buildSentinelOptions(sentinelCfg)
	if err != nil {
		t.Fatal(err)
	}
	dial := sentinelOpts.Dialer
	if dial == nil {
		t.Fatal("sentinel FailoverOptions did not install the separately scoped TLS dialer")
	}
	addresses := []struct {
		name string
		addr string
	}{
		{name: "data node", addr: masterAddr},
		{name: "sentinel", addr: sentinelAddr},
	}
	for _, endpoint := range addresses {
		conn, dialErr := dial(t.Context(), "tcp", endpoint.addr)
		if dialErr != nil {
			t.Fatalf("dial %s with configured FailoverOptions dialer: %v", endpoint.name, dialErr)
		}
		_ = conn.Close()
	}
	if err := <-masterDone; err != nil {
		t.Fatalf("master TLS handshake: %v", err)
	}
	if err := <-sentinelDone; err != nil {
		t.Fatalf("sentinel TLS handshake: %v", err)
	}
}

func startTLSServer(t *testing.T, certificate tls.Certificate) (string, <-chan error) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer conn.Close()
		done <- conn.(*tls.Conn).Handshake()
	}()
	return listener.Addr().String(), done
}

type testTLSMaterial struct {
	caPEM             []byte
	caPool            *x509.CertPool
	serverCertificate tls.Certificate
	clientCertPEM     []byte
	clientKeyPEM      []byte
}

func newTestTLSMaterial(t *testing.T) testTLSMaterial {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to build test CA pool")
	}
	makeCertificate := func(serial int64, usages []x509.ExtKeyUsage, ips []net.IP) (tls.Certificate, []byte, []byte) {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		der, certErr := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test endpoint"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: usages, IPAddresses: ips,
		}, ca, &key.PublicKey, caKey)
		if certErr != nil {
			t.Fatal(certErr)
		}
		keyDER, marshalErr := x509.MarshalECPrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		pair, pairErr := tls.X509KeyPair(certPEM, keyPEM)
		if pairErr != nil {
			t.Fatal(pairErr)
		}
		return pair, certPEM, keyPEM
	}
	server, _, _ := makeCertificate(11, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	_, clientPEM, clientKeyPEM := makeCertificate(12, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	return testTLSMaterial{caPEM: caPEM, caPool: caPool, serverCertificate: server, clientCertPEM: clientPEM, clientKeyPEM: clientKeyPEM}
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
