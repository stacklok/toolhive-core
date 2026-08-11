// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/stacklok/toolhive-core/env"
)

// TargetIsPrivate reports whether the host in rawURL refers to — or resolves to —
// a private, loopback, or link-local address. It is used to detect when an
// operator has deliberately pointed ToolHive at an internal target, so that
// discovery fetches derived from untrusted server input may also be allowed to
// reach internal addresses for that deployment.
//
// IP literals and "localhost" are classified without DNS. Hostnames are resolved
// and reported private if ANY resolved address is private. Unparsable input or
// resolution failure returns false (treat as public — the SSRF guard then stays
// engaged, failing secure).
func TargetIsPrivate(ctx context.Context, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if IsLocalhost(host) {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return IsPrivateIP(ip)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if IsPrivateIP(a.IP) {
			return true
		}
	}
	return false
}

// ErrPrivateIPAddress is returned when the provided URL redirects to a
// private IP address, which is not allowed.
var ErrPrivateIPAddress = errors.New("the provided URL redirects to a private IP address, which is not allowed")

// nat64Prefixes are the NAT64 translation prefixes whose embedded IPv4 address
// lives in the low 32 bits (RFC 6052 §2.2 "/96" embedding). An address inside
// one of these is routed to that IPv4 by a NAT64 gateway, so its true
// reachability is determined by the embedded IPv4, not by the (global-unicast)
// IPv6 form.
//   - 64:ff9b::/96   well-known prefix (RFC 6052), always a /96
//   - 64:ff9b:1::/96 the /96 sub-prefix of the RFC 8215 local-use 64:ff9b:1::/48
//
// The rest of the local-use 64:ff9b:1::/48 uses a shorter NAT64 prefix, where
// the embedded IPv4 is NOT in the low 32 bits and cannot be located from the
// address alone. Decoding the low 32 bits there could read attacker-chosen
// suffix bytes and misclassify an internal target as public, so that remainder
// is blocked wholesale via privateIPBlocks to avoid a false-negative bypass.
var nat64Prefixes []*net.IPNet

// sixToFourPrefix identifies 6to4 addresses, whose embedded IPv4 address
// occupies bytes 2 through 5 of the IPv6 address (RFC 3056 §2).
var sixToFourPrefix *net.IPNet

// embeddedIPv4 returns the IPv4 address embedded in a NAT64 or 6to4 address,
// or nil otherwise.
func embeddedIPv4(ip net.IP) net.IP {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return nil
	}
	for _, block := range nat64Prefixes {
		if block.Contains(ip) {
			return net.IPv4(v6[12], v6[13], v6[14], v6[15])
		}
	}
	if sixToFourPrefix.Contains(ip) {
		return net.IPv4(v6[2], v6[3], v6[4], v6[5])
	}
	return nil
}

func init() {
	for _, cidr := range []string{
		"0.0.0.0/8",       // RFC1122 "this host" (incl. 0.0.0.0 unspecified)
		"127.0.0.0/8",     // IPv4 loopback
		"10.0.0.0/8",      // RFC1918
		"172.16.0.0/12",   // RFC1918
		"192.168.0.0/16",  // RFC1918
		"169.254.0.0/16",  // RFC3927 link-local
		"2001::/32",       // RFC4380 Teredo (embedded client IPv4 is obfuscated)
		"::1/128",         // IPv6 loopback
		"fe80::/10",       // IPv6 link-local
		"fc00::/7",        // IPv6 unique local addr
		"100.64.0.0/10",   // RFC6598 shared address space (CGN)
		"192.0.2.0/24",    // RFC5737 documentation (TEST-NET-1)
		"198.51.100.0/24", // RFC5737 documentation (TEST-NET-2)
		"203.0.113.0/24",  // RFC5737 documentation (TEST-NET-3)
		"224.0.0.0/4",     // IPv4 multicast
		"240.0.0.0/4",     // RFC1112 reserved (Class E), incl. 255.255.255.255 broadcast
		"ff00::/8",        // IPv6 multicast
		// NAT64 local-use range (RFC 8215). The 64:ff9b:1::/96 subset is decoded
		// to its embedded IPv4 below; this catch-all blocks the remaining
		// non-/96 embeddings, which cannot be decoded from the address alone.
		"64:ff9b:1::/48",
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %w", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}
	for _, cidr := range []string{
		"64:ff9b::/96",   // NAT64 well-known prefix, /96 embedding (RFC 6052)
		"64:ff9b:1::/96", // /96 sub-prefix of the local-use range (RFC 8215)
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %w", cidr, err))
		}
		nat64Prefixes = append(nat64Prefixes, block)
	}
	_, block, err := net.ParseCIDR("2002::/16")
	if err != nil {
		panic(fmt.Errorf("parse error on 6to4 prefix: %w", err))
	}
	sixToFourPrefix = block
}

// IsPrivateIP reports whether ip is a private, loopback, link-local,
// unspecified, or otherwise reserved/non-public address.
//
// NAT64- and 6to4-translated addresses are evaluated by the IPv4 address they
// embed. A translated address whose embedded IPv4 is private or link-local is
// treated as private, because it reaches that internal IPv4 through its
// translator. NAT64 addresses embed the IPv4 in their low 32 bits; 6to4
// addresses embed it in bytes 2 through 5. Teredo addresses are blocked
// wholesale because their embedded client IPv4 is obfuscated and cannot be
// safely derived from the IPv6 literal.
func IsPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := embeddedIPv4(ip); v4 != nil {
		return IsPrivateIP(v4)
	}
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// AddressReferencesPrivateIp returns an error if the address references a private IP address
func AddressReferencesPrivateIp(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	// Check for a private IP address or loopback
	ip := net.ParseIP(host)
	if ip == nil {
		// Fail closed: an unparsable host must not be treated as safe.
		return fmt.Errorf("could not parse IP from address %q", address)
	}
	if IsPrivateIP(ip) {
		return ErrPrivateIPAddress
	}

	return nil
}

// ValidateEndpointURL validates that an endpoint URL is secure. It reads
// INSECURE_DISABLE_URL_VALIDATION from the process environment; use
// ValidateEndpointURLWithReader to inject a different env.Reader (e.g. in tests).
func ValidateEndpointURL(endpoint string) error {
	return ValidateEndpointURLWithReader(endpoint, &env.OSReader{})
}

// ValidateEndpointURLWithReader validates that an endpoint URL is secure,
// reading INSECURE_DISABLE_URL_VALIDATION via reader instead of the process
// environment directly.
func ValidateEndpointURLWithReader(endpoint string, reader env.Reader) error {
	skipValidation := strings.EqualFold(reader.Getenv("INSECURE_DISABLE_URL_VALIDATION"), "true")
	return validateEndpointURLWithSkip(endpoint, skipValidation)
}

// ValidateEndpointURLWithInsecure validates that an endpoint URL is secure, allowing HTTP if insecureAllowHTTP is true.
// WARNING: This is insecure and should NEVER be used in production. It reads
// INSECURE_DISABLE_URL_VALIDATION from the process environment; use
// ValidateEndpointURLWithInsecureAndReader to inject a different env.Reader.
func ValidateEndpointURLWithInsecure(endpoint string, insecureAllowHTTP bool) error {
	return ValidateEndpointURLWithInsecureAndReader(endpoint, insecureAllowHTTP, &env.OSReader{})
}

// ValidateEndpointURLWithInsecureAndReader validates that an endpoint URL is
// secure, allowing HTTP if insecureAllowHTTP is true, reading
// INSECURE_DISABLE_URL_VALIDATION via reader instead of the process
// environment directly.
// WARNING: insecureAllowHTTP is insecure and should NEVER be used in production.
func ValidateEndpointURLWithInsecureAndReader(endpoint string, insecureAllowHTTP bool, reader env.Reader) error {
	skipValidation := strings.EqualFold(reader.Getenv("INSECURE_DISABLE_URL_VALIDATION"), "true")
	return validateEndpointURLWithSkip(endpoint, skipValidation || insecureAllowHTTP)
}

// validateEndpointURLWithSkip validates that an endpoint URL is secure, with an option to skip validation
func validateEndpointURLWithSkip(endpoint string, skipValidation bool) error {
	if skipValidation {
		return nil // Skip validation
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Ensure HTTPS for security (except localhost for development)
	if u.Scheme != HttpsScheme && !IsLocalhost(u.Host) {
		return fmt.Errorf("endpoint must use HTTPS: %s", endpoint)
	}

	return nil
}

// ValidateHTTPSURL checks that rawURL is a valid URL using the https scheme.
// Unlike ValidateEndpointURL, no localhost exception is made — HTTPS is always
// required (suitable for gateway URLs and other production endpoints).
func ValidateHTTPSURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL must include a host: %s", rawURL)
	}
	if parsed.Scheme != HttpsScheme {
		return fmt.Errorf("must use HTTPS, got scheme %q", parsed.Scheme)
	}
	return nil
}

// ValidateIssuerURL validates that an OIDC issuer URL is well-formed and uses
// HTTPS. HTTP is permitted only for localhost (development). Per OIDC Core
// Section 3.1.2.1 and RFC 8414 Section 2, the issuer MUST use the "https"
// scheme.
func ValidateIssuerURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid issuer URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return fmt.Errorf("issuer URL must include a host: %s", rawURL)
	}
	if u.Scheme != HttpsScheme && !IsLocalhost(u.Host) {
		return fmt.Errorf("issuer URL must use HTTPS (except localhost for development): %s", rawURL)
	}
	return nil
}

// ValidateLoopbackAddress returns an error if addr (a host:port string) does
// not contain a literal loopback IP address. Both IPv4 (127.x.x.x) and IPv6
// (::1) loopback addresses are accepted. Hostnames (including "localhost") are
// not resolved and will be rejected.
func ValidateLoopbackAddress(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q must be a loopback interface (127.x.x.x or ::1)", addr)
	}
	return nil
}

// hostLocalhost, hostLoopbackV4, and hostLoopbackV6 are the bare (no-port)
// loopback host forms recognised by IsLocalhost and IsLoopbackHost.
const (
	hostLocalhost  = "localhost"
	hostLoopbackV4 = "127.0.0.1"
	hostLoopbackV6 = "[::1]"
)

// IsLocalhost checks whether a host is localhost or a literal loopback address.
// It accepts plain-host and host:port forms without resolving hostnames.
func IsLocalhost(host string) bool {
	return IsLoopbackHost(host)
}

// IsLoopbackHost reports whether the Host header value refers to a loopback
// address. It is intended for DNS-rebinding guards on loopback-only listeners.
// It accepts the hostname "localhost" (case-insensitive), any 127.x.x.x
// address, and the IPv6 loopback ::1. Both plain-host and host:port forms are
// accepted. Hostnames other than "localhost" are NOT resolved.
func IsLoopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		// No port present — treat the whole value as the host.
		h = host
		// Strip brackets from bare IPv6 literals like "[::1]".
		if len(h) > 2 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
	}
	if strings.EqualFold(h, hostLocalhost) {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// IsURL checks if the input is a valid HTTP or HTTPS URL
func IsURL(input string) bool {
	parsedURL, err := url.Parse(input)
	if err != nil {
		return false
	}
	// Must have HTTP or HTTPS scheme and a valid host
	return (parsedURL.Scheme == HttpScheme || parsedURL.Scheme == HttpsScheme) &&
		parsedURL.Host != "" &&
		parsedURL.Host != "//"
}
