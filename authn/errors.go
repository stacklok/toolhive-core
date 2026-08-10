// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"errors"
	"fmt"
)

// Code is the OAuth2 error code, safe to send to a client.
//
// It corresponds to the "error" parameter defined in RFC 6750 Section 3.1 and
// carries the coarse response semantics (the HTTP status is implied by the
// value).
type Code string

const (
	// CodeInvalidRequest is the OAuth2 "invalid_request" code (HTTP 400).
	CodeInvalidRequest Code = "invalid_request" // 400
	// CodeInvalidToken is the OAuth2 "invalid_token" code (HTTP 401).
	CodeInvalidToken Code = "invalid_token" // 401
	// CodeUnavailable indicates key material could not be reached and maps to
	// HTTP 503. It is distinct from an invalid token: the verifier could not
	// make a determination because its inputs (e.g. the JWKS endpoint) were
	// unreachable.
	//
	// Unlike CodeInvalidRequest and CodeInvalidToken, CodeUnavailable is NOT a
	// registered RFC 6750 §3.1 error value (that section defines exactly
	// invalid_request, invalid_token, insufficient_scope). It is an internal
	// discriminator: map it to a plain HTTP 503 and do not emit it as an
	// OAuth2 error= parameter.
	CodeUnavailable Code = "unavailable" // 503 — key material unreachable
)

// Reason is a finer-grained, client-safe failure cause.
//
// Reason refines a Code without leaking sensitive detail. Both Code and Reason
// are safe to transmit to a client; the human-readable detail in Error is not.
type Reason string

const (
	// ReasonMissingHeader indicates no Authorization header (or no Bearer
	// scheme) was present in the request.
	ReasonMissingHeader Reason = "missing_header"
	// ReasonMalformed indicates the token could not be parsed as a
	// structurally valid JWT. From Validate, this pairs with CodeInvalidToken
	// and means the token may be an opaque token worth validating via RFC
	// 7662 introspection — use PossiblyOpaque to ask that, rather than
	// comparing Code and Reason by hand; the Reason taxonomy may grow.
	//
	// That opaque-token meaning applies ONLY to Validate. ParseBearer also
	// returns ReasonMalformed, but with Code == CodeInvalidRequest (400): a
	// malformed Authorization header is a broken request, not a
	// possibly-opaque token. PossiblyOpaque already accounts for this split.
	ReasonMalformed Reason = "malformed"
	// ReasonUnsupportedAlg indicates the "alg" header is missing, none, or
	// not in the configured allow-list.
	ReasonUnsupportedAlg Reason = "unsupported_alg"
	// ReasonCriticalHeader indicates a "crit" header listed a header the
	// verifier does not understand or a protected header was malformed.
	ReasonCriticalHeader Reason = "critical_header"
	// ReasonUnknownKID indicates the "kid" in the token header does not
	// match any currently known key.
	ReasonUnknownKID Reason = "unknown_kid"
	// ReasonSignature indicates the signature did not verify against the
	// selected key.
	ReasonSignature Reason = "signature"
	// ReasonExpired indicates the "exp" claim has passed.
	ReasonExpired Reason = "expired"
	// ReasonExpirationMissing indicates the "exp" claim is absent. It is
	// distinct from ReasonExpired (whose contract is "exp has passed"): the
	// parser is configured with WithExpirationRequired, so a missing exp is
	// a missing-claim failure, not a lifetime-expired one.
	ReasonExpirationMissing Reason = "expiration_missing"
	// ReasonNotYetValid indicates the "nbf" claim is in the future.
	ReasonNotYetValid Reason = "not_yet_valid"
	// ReasonIssuedInFuture indicates the "iat" claim is in the future
	// beyond the configured clock skew.
	ReasonIssuedInFuture Reason = "issued_in_future"
	// ReasonLifetime indicates the token's total lifetime (exp - iat)
	// exceeds the configured maximum.
	ReasonLifetime Reason = "lifetime"
	// ReasonIssuer indicates the "iss" claim is missing or not in the
	// trusted set.
	ReasonIssuer Reason = "issuer"
	// ReasonAudience indicates the "aud" claim is missing, has the wrong
	// type, or none of its values match a configured audience.
	ReasonAudience Reason = "audience"
	// ReasonMissingClaim indicates a required claim is absent but could not
	// be identified as iss/aud/exp (e.g. a future required claim added by a
	// custom parser option). It is deliberately NOT ReasonMalformed so it
	// does not trigger the introspection fallback.
	ReasonMissingClaim Reason = "missing_claim"
	// ReasonSubject indicates the "sub" claim is missing or rejected by
	// policy.
	ReasonSubject Reason = "subject"
	// ReasonKeysUnavailable indicates the key material source (e.g. JWKS
	// endpoint) could not be fetched; paired with CodeUnavailable.
	ReasonKeysUnavailable Reason = "keys_unavailable"
	// ReasonInvalidClaims indicates the token parsed as a structurally valid
	// JWT but its claim set was rejected by golang-jwt for a reason this
	// package does not otherwise enumerate (e.g. a claim with the wrong JSON
	// type, such as a numeric iss). It is deliberately NOT ReasonMalformed:
	// that pair is the load-bearing introspection-fallback trigger (see
	// Error), and a token that parsed as a JWT is not an opaque token worth
	// introspecting, no matter which claim check subsequently failed it.
	ReasonInvalidClaims Reason = "invalid_claims"
)

// Error is the only error type Validate and ParseBearer return.
//
// Log-vs-wire split:
//
// Code and Reason are both client-safe, but not equally wire-safe.
// CodeInvalidRequest and CodeInvalidToken are registered RFC 6750 §3.1 error
// values and may be surfaced on the wire verbatim (e.g. in the
// WWW-Authenticate / error response body). CodeUnavailable is not registered
// and must map to a plain HTTP 503 instead (see its doc comment). Error() is
// NOT safe to send to a client — it includes wrapped detail that can carry
// key ids, JWKS URLs, issuer-mismatch specifics, and underlying transport
// errors. Log Error(); send Code/Reason.
//
// As a special case, a Validate failure with Code == CodeInvalidToken &&
// Reason == ReasonMalformed means the token could not be parsed as a JWT at
// all, and so may be an opaque token worth validating via RFC 7662
// introspection — ToolHive layers that introspection above Validate. Use
// PossiblyOpaque to ask this rather than comparing Code and Reason by hand:
// it is the stable API, and the Reason taxonomy may grow. The contract is
// specific to Validate: ParseBearer reports a malformed header as
// CodeInvalidRequest + ReasonMalformed (400, broken request), which
// PossiblyOpaque correctly reports as false.
type Error struct {
	// Code is the coarse, client-safe OAuth2 error code.
	Code Code
	// Reason is the finer-grained, client-safe failure cause.
	Reason Reason
	// err is the unexported wrapped detail; never sent to a client.
	err error
}

// Error returns a human-readable message that combines the Reason with the
// wrapped detail. The output is intended for server-side logs and is NOT safe
// to send to a client; it may contain key ids, JWKS URLs, or issuer-mismatch
// specifics. It is always distinct from string(Reason) when err is non-nil and
// carries the wrapped detail via fmt's %v.
func (e *Error) Error() string {
	if e == nil {
		return "authn: <nil>"
	}
	if e.err != nil {
		return fmt.Sprintf("authn: %s: %v", e.Reason, e.err)
	}
	return fmt.Sprintf("authn: %s", e.Reason)
}

// Unwrap returns the wrapped detail error (may be nil). This enables
// errors.Is and errors.As to traverse the wrapped chain. A nil Unwrap result
// simply terminates the chain for that branch.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// PossiblyOpaque reports whether err indicates the token could not be parsed as a
// JWT at all, and so may be an opaque token worth validating via RFC 7662
// introspection.
//
// It is true only for a Validate failure (Code == CodeInvalidToken) with
// Reason == ReasonMalformed; ParseBearer's CodeInvalidRequest failures are a
// broken request, not a possibly-opaque token, and report false. A nil err
// also reports false.
//
// Verified parity note: a token that is three base64url segments whose header
// decodes to JSON without an "alg" member yields ReasonUnsupportedAlg, not
// ReasonMalformed, so PossiblyOpaque reports false for it. That matches
// ToolHive's existing behavior: ToolHive keys its fallback on
// jwt.ErrTokenMalformed, while golang-jwt reports a missing alg as
// jwt.ErrTokenUnverifiable. Neither implementation introspects that shape.
func PossiblyOpaque(err error) bool {
	var authnErr *Error
	if !errors.As(err, &authnErr) {
		return false
	}
	return authnErr.Code == CodeInvalidToken && authnErr.Reason == ReasonMalformed
}
