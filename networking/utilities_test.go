// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/stacklok/toolhive-core/env/mocks"
)

// Shared test literals. Pulled out as constants (rather than repeated string
// literals) purely to satisfy goconst across this package's test files.
const (
	testNotAURL              = "not-a-url"
	testHTTPExampleCom       = "http://example.com"
	testHTTPSEmptyHost       = "https://"
	testExampleComHost       = "example.com"
	testLoopbackV4WithPort   = "127.0.0.1:8080"
	testLoopbackV6WithPort   = "[::1]:8080"
	testPublicIPv4           = "8.8.8.8"
	testHTTPLocalhost8080    = "http://localhost:8080"
	testIdpExampleHost       = "idp.example.com"
	testAuthTokenEmptyErrMsg = "auth token file is empty"
	testMCPStartURL          = "https://mcp.example.com/start"
	testNameValidHTTPSURL    = "valid HTTPS URL"
	testNameMissingHost      = "missing host"
	testNameUnsupportedURL   = "unsupported scheme"
	testNameInvalidURLFormat = "invalid URL format"
)

func TestTargetIsPrivate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "private IPv4 literal", url: "https://10.0.0.5/path", want: true},
		{name: "link-local IMDS literal", url: "http://169.254.169.254/latest", want: true},
		{name: "loopback IPv4 literal", url: "http://127.0.0.1:8080", want: true},
		{name: "localhost hostname", url: "http://localhost:9000", want: true},
		{name: "public IPv4 literal", url: "https://8.8.8.8", want: false},
		{name: "unparsable", url: "://nope", want: false},
		{name: "empty host", url: "/just/a/path", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, TargetIsPrivate(context.Background(), tt.url))
		})
	}
}

func TestIsURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid URLs
		{
			name:     "valid https url",
			input:    "https://example.com",
			expected: true,
		},
		{
			name:     "valid http url",
			input:    testHTTPExampleCom,
			expected: true,
		},
		{
			name:     "valid https url with path",
			input:    "https://example.com/path",
			expected: true,
		},
		{
			name:     "valid https url with query params",
			input:    "https://example.com/path?param=value",
			expected: true,
		},
		{
			name:     "valid https url with fragment",
			input:    "https://example.com/path#fragment",
			expected: true,
		},
		{
			name:     "valid https url with port",
			input:    "https://example.com:8080",
			expected: true,
		},
		{
			name:     "valid https url with user info",
			input:    "https://user:pass@example.com",
			expected: true,
		},

		// Invalid URLs
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "invalid URL",
			input:    testNotAURL,
			expected: false,
		},
		{
			name:     testNameUnsupportedURL,
			input:    "ftp://example.com",
			expected: false,
		},
		{
			name:     "missing scheme",
			input:    testExampleComHost,
			expected: false,
		},
		{
			name:     testNameMissingHost,
			input:    testHTTPSEmptyHost,
			expected: false,
		},
		{
			name:     "missing host with path",
			input:    "https:///path",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsURL(tt.input)
			assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		// Valid localhost hosts
		{
			name:     "localhost without port",
			input:    hostLocalhost,
			expected: true,
		},
		{
			name:     "localhost with port",
			input:    "localhost:8080",
			expected: true,
		},
		{
			name:     "localhost with large port",
			input:    "localhost:65535",
			expected: true,
		},
		{
			name:     "127.0.0.1 without port",
			input:    hostLoopbackV4,
			expected: true,
		},
		{
			name:     "127.0.0.1 with port",
			input:    testLoopbackV4WithPort,
			expected: true,
		},
		{
			name:     "127.0.0.1 with large port",
			input:    "127.0.0.1:65535",
			expected: true,
		},
		{
			name:     "127.0.0.2 without port",
			input:    "127.0.0.2",
			expected: true,
		},
		{
			name:     "127.0.0.2 with port",
			input:    "127.0.0.2:8080",
			expected: true,
		},
		{
			name:     "IPv6 localhost without port",
			input:    hostLoopbackV6,
			expected: true,
		},
		{
			name:     "bare IPv6 localhost",
			input:    "::1",
			expected: true,
		},
		{
			name:     "IPv6 localhost with port",
			input:    testLoopbackV6WithPort,
			expected: true,
		},
		{
			name:     "IPv6 localhost with large port",
			input:    "[::1]:65535",
			expected: true,
		},

		// Invalid localhost hosts
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "random hostname",
			input:    testExampleComHost,
			expected: false,
		},
		{
			name:     "random hostname with port",
			input:    "example.com:8080",
			expected: false,
		},
		{
			name:     "public IP without port",
			input:    testPublicIPv4,
			expected: false,
		},
		{
			name:     "public IP with port",
			input:    "8.8.8.8:8080",
			expected: false,
		},
		{
			name:     "private IP without port",
			input:    "192.168.1.1",
			expected: false,
		},
		{
			name:     "private IP with port",
			input:    "192.168.1.1:8080",
			expected: false,
		},
		{
			name:     "IPv6 public address",
			input:    "[2001:db8::1]",
			expected: false,
		},
		{
			name:     "IPv6 public address with port",
			input:    "[2001:db8::1]:8080",
			expected: false,
		},
		{
			name:     "localhost with invalid port",
			input:    "localhost:99999",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "127.0.0.1 with invalid port",
			input:    "127.0.0.1:99999",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "IPv6 localhost with invalid port",
			input:    "[::1]:99999",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "localhost with non-numeric port",
			input:    "localhost:abc",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "127.0.0.1 with non-numeric port",
			input:    "127.0.0.1:abc",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "IPv6 localhost with non-numeric port",
			input:    "[::1]:abc",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "localhost with empty port",
			input:    "localhost:",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "127.0.0.1 with empty port",
			input:    "127.0.0.1:",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "IPv6 localhost with empty port",
			input:    "[::1]:",
			expected: true, // Still matches the prefix check
		},
		{
			name:     "case insensitive localhost",
			input:    "LOCALHOST",
			expected: true,
		},
		{
			name:     "case insensitive localhost with port",
			input:    "LOCALHOST:8080",
			expected: true,
		},
		{
			name:     "mixed case localhost",
			input:    "LocalHost",
			expected: true,
		},
		{
			name:     "localhost with spaces",
			input:    "localhost ",
			expected: false,
		},
		{
			name:     "localhost with leading space",
			input:    " localhost",
			expected: false,
		},
		{
			name:     "127.0.0.1 with spaces",
			input:    "127.0.0.1 ",
			expected: false,
		},
		{
			name:     "127.0.0.1 with leading space",
			input:    " 127.0.0.1",
			expected: false,
		},
		{
			name:     "IPv6 localhost with spaces",
			input:    "[::1] ",
			expected: false,
		},
		{
			name:     "IPv6 localhost with leading space",
			input:    " [::1]",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := IsLocalhost(tt.input)
			assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"CGN 100.64.0.1", "100.64.0.1", true},
		{"CGN 100.127.255.255", "100.127.255.255", true},
		{"documentation TEST-NET-1", "192.0.2.1", true},
		{"documentation TEST-NET-2", "198.51.100.1", true},
		{"documentation TEST-NET-3", "203.0.113.1", true},
		{"public IPv4", testPublicIPv4, false},
		{"public IPv6", "2001:db8::1", false},
		{"global IPv6 outside blocked ranges", "2606:4700:4700::1111", false},

		// Teredo (RFC 4380) obfuscates the client IPv4, so the whole prefix is blocked.
		{"Teredo example", "2001:0000:4136:e378:8000:63bf:3fff:fdd2", true},
		{"another Teredo address", "2001:0:1:2:3:4:5:6", true},

		// 6to4 (RFC 3056): classify bytes 2 through 5 as the embedded IPv4.
		{"6to4 -> IMDS link-local", "2002:a9fe:a9fe::", true},
		{"6to4 -> RFC1918 10.x", "2002:0a00:0001::", true},
		{"6to4 -> loopback", "2002:7f00:0001::", true},
		{"6to4 -> public", "2002:0808:0808::", false},

		// Unspecified / "this host" / reserved ranges (defense-in-depth).
		{"unspecified IPv4", "0.0.0.0", true},
		{"unspecified IPv6", "::", true},
		{`RFC1122 "this host" 0.x`, "0.1.2.3", true},
		{"Class E reserved", "240.0.0.1", true},
		{"limited broadcast", "255.255.255.255", true},

		// NAT64 (RFC 6052 / RFC 8215): classified by the embedded IPv4.
		// IPv4-mapped form is still caught by the link-local check, not NAT64.
		{"IPv4-mapped link-local", "::ffff:169.254.169.254", true},
		// Well-known prefix 64:ff9b::/96 embedding a private/link-local IPv4.
		{"NAT64 well-known -> IMDS link-local", "64:ff9b::a9fe:a9fe", true},
		{"NAT64 well-known -> loopback", "64:ff9b::7f00:1", true},
		{"NAT64 well-known -> RFC1918 10.x", "64:ff9b::a00:1", true},
		{"NAT64 well-known -> RFC1918 192.168.x", "64:ff9b::c0a8:1", true},
		// Well-known prefix embedding a genuinely public IPv4 must stay allowed.
		{"NAT64 well-known -> public", "64:ff9b::8.8.8.8", false},
		// Local-use /96 sub-prefix is decoded the same way.
		{"NAT64 local-use /96 -> IMDS", "64:ff9b:1::a9fe:a9fe", true},
		{"NAT64 local-use /96 -> public", "64:ff9b:1::8.8.8.8", false},
		// Remainder of the local-use /48 uses a non-/96 embedding that cannot be
		// decoded, so it is blocked wholesale even when the low 32 bits look
		// public (would otherwise be a false-negative SSRF bypass).
		{"NAT64 local-use non-/96 blocked", "64:ff9b:1:1::8.8.8.8", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip, "failed to parse test IP %s", tt.ip)
			assert.Equal(t, tt.want, IsPrivateIP(ip))
		})
	}
}

func TestAddressReferencesPrivateIp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		address     string
		expectError bool
	}{
		// Public IP addresses (should not error)
		{
			name:        "public IP with port",
			address:     "8.8.8.8:80",
			expectError: false,
		},
		{
			name:        "public IP with different port",
			address:     "1.1.1.1:443",
			expectError: false,
		},

		// Private IP addresses (should error)
		{
			name:        "localhost IP with port",
			address:     testLoopbackV4WithPort,
			expectError: true,
		},
		{
			name:        "RFC1918 10.x.x.x with port",
			address:     "10.0.0.1:80",
			expectError: true,
		},
		{
			name:        "RFC1918 172.16.x.x with port",
			address:     "172.16.0.1:80",
			expectError: true,
		},
		{
			name:        "RFC1918 192.168.x.x with port",
			address:     "192.168.1.1:80",
			expectError: true,
		},
		{
			name:        "link-local 169.254.x.x with port",
			address:     "169.254.1.1:80",
			expectError: true,
		},
		{
			name:        "IPv6 loopback with port",
			address:     testLoopbackV6WithPort,
			expectError: true,
		},
		{
			name:        "IPv6 link-local with port",
			address:     "[fe80::1]:80",
			expectError: true,
		},
		{
			name:        "IPv6 unique local with port",
			address:     "[fc00::1]:80",
			expectError: true,
		},
		{
			name:        "NAT64 well-known to IMDS with port",
			address:     "[64:ff9b::a9fe:a9fe]:443",
			expectError: true,
		},
		{
			name:        "NAT64 local-use to IMDS with port",
			address:     "[64:ff9b:1::a9fe:a9fe]:443",
			expectError: true,
		},
		{
			name:        "NAT64 to public IPv4 with port",
			address:     "[64:ff9b::8.8.8.8]:443",
			expectError: false,
		},
		{
			name:        "6to4 to public IPv4 with port",
			address:     "[2002:0808:0808::]:443",
			expectError: false,
		},
		{
			name:        "Teredo with port",
			address:     "[2001:0000:4136:e378:8000:63bf:3fff:fdd2]:443",
			expectError: true,
		},
		{
			name:        "6to4 to IMDS link-local with port",
			address:     "[2002:a9fe:a9fe::]:443",
			expectError: true,
		},
		{
			name:        "6to4 to RFC1918 with port",
			address:     "[2002:0a00:0001::]:443",
			expectError: true,
		},
		{
			name:        "6to4 to loopback with port",
			address:     "[2002:7f00:0001::]:443",
			expectError: true,
		},
		{
			name:        "unspecified IPv4 with port",
			address:     "0.0.0.0:80",
			expectError: true,
		},
		{
			name:        "unspecified IPv6 with port",
			address:     "[::]:80",
			expectError: true,
		},

		// Invalid addresses (should error due to parsing)
		{
			name:        "invalid address format",
			address:     "invalid-address",
			expectError: true,
		},
		{
			name:        "unparsable host fails closed",
			address:     "not-an-ip:80",
			expectError: true,
		},
		{
			name:        "missing port",
			address:     testPublicIPv4,
			expectError: true,
		},
		{
			name:        "empty address",
			address:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := AddressReferencesPrivateIp(tt.address)
			if tt.expectError {
				assert.Error(t, err, "Expected error for address: %s", tt.address)
			} else {
				assert.NoError(t, err, "Expected no error for address: %s", tt.address)
			}
		})
	}
}

func TestValidateEndpointURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		endpoint       string
		skipValidation bool
		expectError    bool
	}{
		// Valid HTTPS URLs (should not error)
		{
			name:        testNameValidHTTPSURL,
			endpoint:    "https://example.com",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with path",
			endpoint:    "https://example.com/api/v1",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with port",
			endpoint:    "https://example.com:8443",
			expectError: false,
		},

		// Localhost URLs with HTTP (should not error)
		{
			name:        "localhost HTTP URL",
			endpoint:    testHTTPLocalhost8080,
			expectError: false,
		},
		{
			name:        "127.0.0.1 HTTP URL",
			endpoint:    "http://127.0.0.1:8080",
			expectError: false,
		},
		{
			name:        "IPv6 localhost HTTP URL",
			endpoint:    "http://[::1]:8080",
			expectError: false,
		},

		// Non-localhost HTTP URLs (should error)
		{
			name:        "HTTP URL for non-localhost",
			endpoint:    testHTTPExampleCom,
			expectError: true,
		},
		{
			name:        "HTTP URL with public IP",
			endpoint:    "http://8.8.8.8:80",
			expectError: true,
		},

		// Invalid URLs (should error)
		{
			name:        testNameInvalidURLFormat,
			endpoint:    testNotAURL,
			expectError: true,
		},
		{
			name:        "empty URL",
			endpoint:    "",
			expectError: true,
		},
		{
			name:        testNameUnsupportedURL,
			endpoint:    "ftp://example.com",
			expectError: true,
		},

		// Skip validation cases (should not error)
		{
			name:           "HTTP URL with validation skipped",
			endpoint:       testHTTPExampleCom,
			skipValidation: true,
			expectError:    false,
		},
		{
			name:           "invalid URL with validation skipped",
			endpoint:       testNotAURL,
			skipValidation: true,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateEndpointURLWithSkip(tt.endpoint, tt.skipValidation)
			if tt.expectError {
				assert.Error(t, err, "Expected error for endpoint: %s", tt.endpoint)
			} else {
				assert.NoError(t, err, "Expected no error for endpoint: %s", tt.endpoint)
			}
		})
	}
}

// TestValidateEndpointURLWithReader pins that the Reader-accepting sibling of
// ValidateEndpointURL reads INSECURE_DISABLE_URL_VALIDATION through the
// injected env.Reader rather than the process environment, so the test can
// run with t.Parallel instead of t.Setenv.
func TestValidateEndpointURLWithReader(t *testing.T) {
	t.Parallel()

	t.Run("reader reports true: validation skipped", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockReader := mocks.NewMockReader(ctrl)
		mockReader.EXPECT().Getenv("INSECURE_DISABLE_URL_VALIDATION").Return("true")

		err := ValidateEndpointURLWithReader(testNotAURL, mockReader)
		assert.NoError(t, err)
	})

	t.Run("reader reports false: validation enforced", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockReader := mocks.NewMockReader(ctrl)
		mockReader.EXPECT().Getenv("INSECURE_DISABLE_URL_VALIDATION").Return("")

		err := ValidateEndpointURLWithReader(testHTTPExampleCom, mockReader)
		assert.Error(t, err)
	})
}

// TestValidateEndpointURL_DefaultOSReader pins that ValidateEndpointURL still
// reads INSECURE_DISABLE_URL_VALIDATION from the process environment by
// default. Kept as its own non-parallel top-level test because t.Setenv
// panics if any ancestor test has called t.Parallel.
func TestValidateEndpointURL_DefaultOSReader(t *testing.T) {
	t.Setenv("INSECURE_DISABLE_URL_VALIDATION", "true")

	err := ValidateEndpointURL(testNotAURL)
	assert.NoError(t, err)
}

// TestValidateEndpointURLWithInsecureAndReader mirrors
// TestValidateEndpointURLWithReader for the insecureAllowHTTP variant.
func TestValidateEndpointURLWithInsecureAndReader(t *testing.T) {
	t.Parallel()

	t.Run("insecureAllowHTTP true skips validation regardless of the reader", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockReader := mocks.NewMockReader(ctrl)
		mockReader.EXPECT().Getenv("INSECURE_DISABLE_URL_VALIDATION").Return("")

		err := ValidateEndpointURLWithInsecureAndReader(testHTTPExampleCom, true, mockReader)
		assert.NoError(t, err)
	})

	t.Run("reader reports true: validation skipped", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		mockReader := mocks.NewMockReader(ctrl)
		mockReader.EXPECT().Getenv("INSECURE_DISABLE_URL_VALIDATION").Return("true")

		err := ValidateEndpointURLWithInsecureAndReader(testNotAURL, false, mockReader)
		assert.NoError(t, err)
	})
}

// TestValidateEndpointURLWithInsecure_DefaultOSReader mirrors
// TestValidateEndpointURL_DefaultOSReader for the insecureAllowHTTP variant.
func TestValidateEndpointURLWithInsecure_DefaultOSReader(t *testing.T) {
	t.Setenv("INSECURE_DISABLE_URL_VALIDATION", "true")

	err := ValidateEndpointURLWithInsecure(testNotAURL, false)
	assert.NoError(t, err)
}

func TestValidateHTTPSURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        testNameValidHTTPSURL,
			url:         "https://llm.example.com",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with path",
			url:         "https://llm.example.com/api/v1",
			expectError: false,
		},
		{
			name:        "valid HTTPS URL with port",
			url:         "https://llm.example.com:8443",
			expectError: false,
		},
		{
			name:        "HTTP rejected even for localhost",
			url:         testHTTPLocalhost8080,
			expectError: true,
		},
		{
			name:        "HTTP rejected for remote host",
			url:         "http://llm.example.com",
			expectError: true,
		},
		{
			name:        testNameMissingHost,
			url:         testHTTPSEmptyHost,
			expectError: true,
		},
		{
			name:        testNameUnsupportedURL,
			url:         "ftp://llm.example.com",
			expectError: true,
		},
		{
			name:        testNameInvalidURLFormat,
			url:         testNotAURL,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateHTTPSURL(tt.url)
			if tt.expectError {
				assert.Error(t, err, "Expected error for URL: %s", tt.url)
			} else {
				assert.NoError(t, err, "Expected no error for URL: %s", tt.url)
			}
		})
	}
}

func TestValidateIssuerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "valid HTTPS issuer",
			url:         "https://auth.example.com",
			expectError: false,
		},
		{
			name:        "valid HTTPS issuer with path",
			url:         "https://auth.example.com/realms/myrealm",
			expectError: false,
		},
		{
			name:        "localhost HTTP allowed for development",
			url:         testHTTPLocalhost8080,
			expectError: false,
		},
		{
			name:        "127.0.0.1 HTTP allowed for development",
			url:         "http://127.0.0.1:9000",
			expectError: false,
		},
		{
			name:        "HTTP rejected for remote host",
			url:         "http://auth.example.com",
			expectError: true,
		},
		{
			name:        testNameMissingHost,
			url:         testHTTPSEmptyHost,
			expectError: true,
		},
		{
			name:        testNameInvalidURLFormat,
			url:         testNotAURL,
			expectError: true,
		},
		{
			name:        testNameUnsupportedURL,
			url:         "ftp://auth.example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateIssuerURL(tt.url)
			if tt.expectError {
				assert.Error(t, err, "Expected error for URL: %s", tt.url)
			} else {
				assert.NoError(t, err, "Expected no error for URL: %s", tt.url)
			}
		})
	}
}

func TestValidateLoopbackAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"127.0.0.1:14000", false},
		{"[::1]:14000", false},
		{"0.0.0.0:14000", true},
		{"192.168.1.1:14000", true},
		{"10.0.0.1:14000", true},
		{"notanaddr", true},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()
			err := ValidateLoopbackAddress(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{"localhost bare", hostLocalhost, true},
		{"localhost mixed case", "LocalHost", true},
		{"localhost with port", "localhost:8080", true},
		{"IPv4 loopback bare", hostLoopbackV4, true},
		{"IPv4 loopback with port", testLoopbackV4WithPort, true},
		{"IPv6 loopback bracketed", hostLoopbackV6, true},
		{"IPv6 loopback with port", testLoopbackV6WithPort, true},
		{"public hostname", testExampleComHost, false},
		{"public IP", testPublicIPv4, false},
		{"private IP is not loopback", "192.168.1.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsLoopbackHost(tt.host))
		})
	}
}
