// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stacklok/toolhive-core/jose"
)

const (
	headerTyp = "typ"
	claimCNF  = "cnf"
)

// defaultDeniedTypes are `typ` values of JWTs that are not access tokens but
// can share an access token's issuer, subject and key.
var defaultDeniedTypes = []string{
	jose.JWTTypeIDJAG,
	jose.JWTTypeLogout,
	jose.JWTTypeSecEvent,
	jose.JWTTypeDPoP,
	jose.JWTTypeTokenIntrospection,
}

// typePolicy decides which `typ` header values a token may carry. Matching
// uses jose.IsJOSEType.
type typePolicy struct {
	// allow, when non-empty, restricts `typ` to these types and overrides the
	// default deny list.
	allow []string
}

// acceptPolicy is the policy applied to claims and header after verify has
// authenticated them.
type acceptPolicy struct {
	audiences        []string
	allowAnyAudience bool
	types            typePolicy
	allowCNF         bool
	maxRemaining     time.Duration
	checks           []Check
	// profile and trustID label Check failures in the error detail.
	profile, trustID string
}

func newAcceptPolicy(cfg Config) acceptPolicy {
	return acceptPolicy{
		audiences:        cfg.Audiences,
		allowAnyAudience: cfg.AllowAnyAudience,
		types:            typePolicy{allow: cfg.AcceptedTokenTypes},
		allowCNF:         cfg.AllowCNF,
		maxRemaining:     cfg.MaxRemainingLifetime,
		checks:           cfg.Checks,
	}
}

// validateTypeEntries rejects an entry that could never match a token: empty,
// only `application/`, or padded with whitespace (IsJOSEType does not trim).
func validateTypeEntries(field string, entries []string) error {
	for i, e := range entries {
		if e != strings.TrimSpace(e) {
			return fmt.Errorf("authn: %s[%d] must not have leading or trailing whitespace", field, i)
		}
		if e == "" || strings.EqualFold(e, "application/") {
			return fmt.Errorf("authn: %s[%d] must not be empty or only %q", field, i, "application/")
		}
	}
	return nil
}

// accept applies p to claims and header that verify has authenticated:
// audience, then `typ`, then `cnf`, then the remaining lifetime, then the Checks.
func accept(p *acceptPolicy, claims jwt.MapClaims, header map[string]any, now time.Time) error {
	if !p.allowAnyAudience {
		if err := checkAudience(claims["aud"], p.audiences); err != nil {
			return err
		}
	}
	if err := p.types.check(header); err != nil {
		return err
	}
	if _, has := claims[claimCNF]; has && !p.allowCNF {
		return &Error{Code: CodeInvalidToken, Reason: ReasonTokenKind,
			err: errors.New("token carries a cnf claim")}
	}
	if exp, _ := claims.GetExpirationTime(); p.maxRemaining > 0 && exp != nil && exp.Sub(now) > p.maxRemaining {
		return &Error{Code: CodeInvalidToken, Reason: ReasonLifetime,
			err: fmt.Errorf("token has %s left, more than the maximum %s", exp.Sub(now), p.maxRemaining)}
	}
	return p.runChecks(claims, now)
}

// checkAudience accepts a string or a non-empty array of non-empty strings, and
// requires one value to be byte-equal to a configured audience.
func checkAudience(raw any, want []string) error {
	var values []string
	switch a := raw.(type) {
	case string:
		values = []string{a}
	case []any:
		for _, e := range a {
			s, ok := e.(string)
			if !ok {
				return audienceErr(errors.New("aud array holds a non-string value"))
			}
			values = append(values, s)
		}
	default:
		return audienceErr(fmt.Errorf("aud claim is missing or has unsupported type %T", raw))
	}
	if len(values) == 0 || slices.Contains(values, "") {
		return audienceErr(errors.New("aud claim is empty or holds an empty value"))
	}
	if !slices.ContainsFunc(values, func(v string) bool { return slices.Contains(want, v) }) {
		return audienceErr(errors.New("aud claim does not match a configured audience"))
	}
	return nil
}

func audienceErr(err error) error {
	return &Error{Code: CodeInvalidToken, Reason: ReasonAudience, err: err}
}

// check applies the policy to a verified JOSE header. A non-string `typ` is
// refused; a denied `typ` is refused unless allow lists it; with allow set, any
// other or absent `typ` is refused.
func (tp typePolicy) check(header map[string]any) error {
	raw, present := header[headerTyp]
	typ, isString := raw.(string)
	if present && !isString {
		return &Error{Code: CodeInvalidToken, Reason: ReasonTokenType,
			err: fmt.Errorf("typ header has unsupported type %T", raw)}
	}
	allowed := matchesType(typ, tp.allow)
	if !allowed && matchesType(typ, defaultDeniedTypes) {
		return &Error{Code: CodeInvalidToken, Reason: ReasonTokenKind,
			err: fmt.Errorf("token typ %q is a denied token kind", typ)}
	}
	if len(tp.allow) > 0 && !allowed {
		return &Error{Code: CodeInvalidToken, Reason: ReasonTokenType,
			err: errors.New("token typ is absent or not accepted")}
	}
	return nil
}

func matchesType(typ string, types []string) bool {
	return slices.ContainsFunc(types, func(t string) bool { return jose.IsJOSEType(typ, t) })
}
