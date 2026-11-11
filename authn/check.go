// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"fmt"
	"time"
)

// Check is a rule over verified claims. It runs after every built-in check, so
// it can only add restrictions; it must not do I/O. It returns nil to accept
// the token. Any error or panic rejects it with CodeInvalidToken and
// ReasonCheck; the returned error is never exposed or wrapped.
//
// Each check receives its own deep copy of the claims, and the instant the
// validator used for every temporal check of this token.
type Check interface {
	Check(claims map[string]any, now time.Time) error
}

// CheckFunc adapts a function to the Check interface.
type CheckFunc func(claims map[string]any, now time.Time) error

// Check calls f.
func (f CheckFunc) Check(claims map[string]any, now time.Time) error {
	return f(claims, now)
}

// RejectIDTokens refuses a token that carries an `at_hash` or `c_hash` claim,
// which only OpenID Connect ID tokens carry. It is weak on its own: an ID token
// from the authorization code flow may carry neither.
var RejectIDTokens Check = CheckFunc(func(claims map[string]any, _ time.Time) error {
	for _, name := range []string{"at_hash", "c_hash"} {
		if _, present := claims[name]; present {
			return fmt.Errorf("token carries the ID token claim %q", name)
		}
	}
	return nil
})

// runChecks runs the checks in order, each on its own copy of claims. The
// detail is fixed text naming the check index, profile and trust ID.
func (p *acceptPolicy) runChecks(claims map[string]any, now time.Time) error {
	for i, c := range p.checks {
		if failure := runCheck(c, deepCopy(claims).(map[string]any), now); failure != "" {
			return &Error{Code: CodeInvalidToken, Reason: ReasonCheck,
				err: fmt.Errorf("check %d %s (profile %q, trust %q)", i, failure, p.profile, p.trustID)}
		}
	}
	return nil
}

// runCheck returns "rejected the token", "panicked", or "" when c passed.
func runCheck(c Check, claims map[string]any, now time.Time) (failure string) {
	defer func() {
		if recover() != nil {
			failure = "panicked"
		}
	}()
	if c.Check(claims, now) != nil {
		return "rejected the token"
	}
	return ""
}

// deepCopy copies a decoded JSON value so the result shares no memory with it.
func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = deepCopy(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = deepCopy(e)
		}
		return out
	}
	return v
}
