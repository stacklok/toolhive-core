// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// maxParallelBuilds bounds how many validators NewTrustSet builds at once.
	maxParallelBuilds = 16
	// maxTrustIDLength bounds Trust.ID, which reaches logs and errors.
	maxTrustIDLength = 256
	// maxQuoted bounds how many bytes of an attacker-supplied value reach an
	// error message.
	maxQuoted = 64
)

// Trust is one issuer a TrustSet accepts tokens from.
type Trust struct {
	// ID names the trust in errors. Required and unique within the set.
	ID string
	// Config verifies the issuer's tokens exactly as a Validator built from it
	// would: keys, algorithms, leeway and acceptance policy. Config.Issuer is
	// required; it is the value the token's `iss` must equal.
	Config Config
	// NotAfter, when set, is when the data the trust was built from goes
	// stale. From then on its tokens fail with CodeUnavailable and
	// ReasonTrustStale; they never fall through to another trust.
	NotAfter time.Time
	// Tag is returned unchanged in Principal.Trust, so a caller can attach its
	// own identifiers or policy to the trust that verified a token.
	Tag any
}

// TrustError reports a trust NewTrustSet did not install, and why.
type TrustError struct {
	ID  string
	Err error
}

func (e *TrustError) Error() string { return fmt.Sprintf("authn: trust %q: %v", e.ID, e.Err) }

// Unwrap returns the cause.
func (e *TrustError) Unwrap() error { return e.Err }

// TrustSet verifies tokens from several issuers. It routes a token to the
// trust whose Config.Issuer equals the token's `iss`, then verifies and
// accepts it with that trust's Config alone. There is no fallthrough to
// another trust.
//
// A TrustSet is immutable. To change the trusts, build a new set and swap it
// in (for example with atomic.Pointer), then Close the old one. Verify is
// safe for concurrent use.
type TrustSet struct {
	clock  func() time.Time
	routes map[string]*trustEntry
	cancel context.CancelFunc
	closed atomic.Bool
	once   sync.Once
}

type trustEntry struct {
	ref      TrustRef
	v        *Validator
	notAfter time.Time
}

// SetOption configures a TrustSet.
type SetOption func(*setConfig)

type setConfig struct {
	clock        func() time.Time
	reserved     map[string]bool
	providerOnly bool
}

// WithClock sets the clock Verify reads once per token. The default is
// time.Now.
func WithClock(clock func() time.Time) SetOption {
	return func(c *setConfig) { c.clock = clock }
}

// WithReservedIssuers refuses every trust whose Config.Issuer, with trailing
// slashes removed, equals one of issuers with trailing slashes removed. The
// comparison is otherwise exact. Calls accumulate. A set fed from external
// data uses it with the issuers of another set, so that a trust cannot take
// over one of them, for example https://idp as https://idp/.
func WithReservedIssuers(issuers ...string) SetOption {
	return func(c *setConfig) {
		if c.reserved == nil {
			c.reserved = map[string]bool{}
		}
		for _, iss := range issuers {
			c.reserved[strings.TrimRight(iss, "/")] = true
		}
	}
}

// WithProviderOnly refuses every trust whose Config.ProviderOnly is false. A
// set whose keys are fetched elsewhere uses it to guarantee that no trust in
// it does discovery or a JWKS fetch.
func WithProviderOnly() SetOption {
	return func(c *setConfig) { c.providerOnly = true }
}

// NewTrustSet validates the trusts, builds a validator for each valid one and
// returns a set holding every trust that built. Each trust that did not is
// reported in the returned errors, in input order; a caller that needs all of
// them treats any error as fatal. A trust that failed to build is absent from
// the set, so its tokens get ReasonUnknownIssuer from Verify, not
// CodeUnavailable. A caller that must not fall through to another verifier
// when a trust is missing treats the returned errors as fatal.
//
// A trust is refused when its ID is empty, too long or has control
// characters; when its Config is invalid or has no Issuer; when
// WithReservedIssuers reserves its issuer or WithProviderOnly requires a
// ProviderOnly Config it lacks; and when its ID, or its issuer with trailing
// slashes removed, is shared with another trust that was not refused for one
// of these reasons. A shared ID or issuer refuses every trust that shares it,
// since there is no rule for which one is meant, so an invalid trust never
// keeps a valid one of the same issuer out.
//
// Routing and the shared-issuer check are byte-exact apart from trailing
// slashes: there is no case or default-port normalisation. Because every copy
// of a shared issuer is refused, a feed that lets one party register a
// colliding issuer lets that party deny service to another trust. Such a feed
// must reject collisions when trusts are registered.
//
// ctx bounds construction, including discovery and the first JWKS fetch,
// which run in parallel. The validators' background JWKS refresh lives until
// Close. A set whose trusts are all ProviderOnly holds no goroutines and needs
// no Close.
func NewTrustSet(ctx context.Context, trusts []Trust, opts ...SetOption) (*TrustSet, []TrustError) {
	sc := setConfig{clock: time.Now}
	for _, o := range opts {
		o(&sc)
	}
	// The lifetime context does not derive from ctx: ctx bounds construction
	// only, and a set built per poll must not register a child on a
	// long-lived caller context each time.
	lifetime, cancel := context.WithCancel(context.Background())
	s := &TrustSet{clock: sc.clock, routes: map[string]*trustEntry{}, cancel: cancel}

	errs := make([]error, len(trusts))
	cfgs := make([]Config, len(trusts))
	for i, t := range trusts {
		cfgs[i], errs[i] = validateTrust(t)
		if errs[i] == nil {
			errs[i] = sc.refuse(t)
		}
	}
	refuseShared(trusts, errs, "ID", func(t Trust) string { return t.ID })
	refuseShared(trusts, errs, "issuer", func(t Trust) string { return strings.TrimRight(t.Config.Issuer, "/") })

	built := make([]*Validator, len(trusts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxParallelBuilds)
	for i := range trusts {
		if errs[i] != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			built[i], errs[i] = newValidator(lifetime, ctx, cfgs[i])
		}()
	}
	wg.Wait()

	var report []TrustError
	for i, t := range trusts {
		if errs[i] != nil {
			report = append(report, TrustError{ID: t.ID, Err: errs[i]})
			continue
		}
		s.routes[t.Config.Issuer] = &trustEntry{
			ref:      TrustRef{ID: t.ID, Issuer: t.Config.Issuer, Tag: t.Tag},
			v:        built[i],
			notAfter: t.NotAfter,
		}
	}
	return s, report
}

// refuse applies the set's own rules to a trust that passed validateTrust.
func (c *setConfig) refuse(t Trust) error {
	if c.reserved[strings.TrimRight(t.Config.Issuer, "/")] {
		return fmt.Errorf("authn: issuer %s is reserved", quoteUntrusted(t.Config.Issuer))
	}
	if c.providerOnly && !t.Config.ProviderOnly {
		return fmt.Errorf("authn: issuer %s: the set accepts only ProviderOnly trusts", quoteUntrusted(t.Config.Issuer))
	}
	return nil
}

// validateTrust checks one trust without I/O and returns its validated Config.
func validateTrust(t Trust) (Config, error) {
	switch {
	case t.ID == "":
		return Config{}, errors.New("authn: trust ID must not be empty")
	case len(t.ID) > maxTrustIDLength:
		return Config{}, fmt.Errorf("authn: trust ID is %d bytes, over the %d byte limit", len(t.ID), maxTrustIDLength)
	case strings.IndexFunc(t.ID, unicode.IsControl) >= 0:
		return Config{}, errors.New("authn: trust ID must not contain control characters")
	case t.Config.Issuer == "":
		return Config{}, errors.New("authn: trust config needs an issuer")
	}
	return ValidateConfig(t.Config)
}

// refuseShared sets an error on every still-valid trust whose key is shared
// with another still-valid trust.
func refuseShared(trusts []Trust, errs []error, what string, key func(Trust) string) {
	count := map[string]int{}
	for i, t := range trusts {
		if errs[i] == nil {
			count[key(t)]++
		}
	}
	for i, t := range trusts {
		if errs[i] == nil && count[key(t)] > 1 {
			errs[i] = fmt.Errorf("authn: %s %s is used by more than one trust", what, quoteUntrusted(key(t)))
		}
	}
}

// Close stops the background JWKS refresh of every validator in the set. It
// does not wait for Verify calls already running; one that loses the race
// fails with CodeUnavailable, as does every Verify afterwards. It is
// idempotent.
func (s *TrustSet) Close() {
	s.once.Do(func() {
		s.closed.Store(true)
		s.cancel()
	})
}

// Verify verifies a bare JWT (no "Bearer " prefix; see ParseBearer) and returns
// the Principal, with Principal.Trust naming the trust that verified it. Every
// error is an *Error.
//
// A token that is not a JWT is CodeInvalidToken with ReasonMalformed, so
// PossiblyOpaque works. A JWT whose `iss` no trust routes is ReasonUnknownIssuer
// and no key is tried, so a caller can safely pass it to another verifier. A
// trust past its NotAfter is CodeUnavailable with ReasonTrustStale. Otherwise
// the result is what the trust's Validator would return. One clock reading
// serves every temporal check.
func (s *TrustSet) Verify(ctx context.Context, raw string) (Principal, error) {
	if s.closed.Load() {
		return Principal{}, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
			err: errors.New("trust set is closed")}
	}
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return Principal{}, err
	}
	e, ok := s.routes[iss]
	if !ok {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonUnknownIssuer,
			err: fmt.Errorf("no trust for issuer %s", quoteUntrusted(iss))}
	}
	now := s.clock()
	if !e.notAfter.IsZero() && !now.Before(e.notAfter) {
		return Principal{}, &Error{Code: CodeUnavailable, Reason: ReasonTrustStale,
			err: fmt.Errorf("trust %q is past its NotAfter %s", e.ref.ID, e.notAfter.UTC().Format(time.RFC3339))}
	}
	p, err := e.v.validateAt(ctx, raw, now)
	if err != nil {
		return Principal{}, err
	}
	p.Trust = e.ref
	return p, nil
}

// unverifiedIssuer applies the structural checks every token gets and reads the
// `iss` claim from the unverified payload, as a string only. The value is not
// trusted: it only picks the trust whose validator then verifies the token,
// including that the verified `iss` equals the trust's issuer. A missing or
// non-string `iss` returns "", which no trust routes.
func unverifiedIssuer(token string) (string, error) {
	malformed := func(err error) error {
		return &Error{Code: CodeInvalidToken, Reason: ReasonMalformed, err: err}
	}
	if token == "" {
		return "", malformed(errors.New("empty token"))
	}
	if len(token) > maxTokenLength {
		return "", malformed(fmt.Errorf("token length %d exceeds %d byte limit", len(token), maxTokenLength))
	}
	if _, err := unverifiedAlg(token); err != nil {
		return "", malformed(err)
	}
	// unverifiedAlg has checked that there are three segments.
	raw, err := jwt.NewParser(jwt.WithStrictDecoding()).DecodeSegment(strings.Split(token, ".")[1])
	if err != nil {
		return "", malformed(fmt.Errorf("failed to decode payload segment: %w", err))
	}
	// A map keeps the match on "iss" exact: decoding into a struct would also
	// match "ISS" and let it override "iss".
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", malformed(fmt.Errorf("failed to parse payload JSON: %w", err))
	}
	var iss string
	if json.Unmarshal(claims["iss"], &iss) != nil {
		return "", nil
	}
	return iss, nil
}

// quoteUntrusted renders an attacker-supplied value for an error message:
// truncated to maxQuoted bytes and quoted, so control characters and line
// breaks cannot forge log lines.
func quoteUntrusted(s string) string {
	if len(s) <= maxQuoted {
		return strconv.Quote(s)
	}
	cut := maxQuoted
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strconv.Quote(s[:cut]) + "...(truncated)"
}
