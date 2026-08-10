// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	// maxKeyCandidates bounds how many verification keys a single token may
	// attempt (a kid-less token against a large JWKS otherwise turns into a
	// DoS amplifier: every request tries every key). Excess candidates are
	// truncated, never an error.
	maxKeyCandidates = 8

	// refreshFloor is the minimum interval between unknown-kid recovery
	// refreshes. A second concurrent caller blocks on refreshMu, then sees a
	// fresh lastRefresh and skips the network fetch.
	refreshFloor = time.Second

	// negativeCacheTTL is how long a "this kid is not in the JWKS" negative
	// entry suppresses a recovery refresh for that kid.
	negativeCacheTTL = 30 * time.Second

	// negativeCacheMaxEntries bounds the negative cache in ENTRY COUNT, not
	// only TTL: TTL alone does not stop an attacker spraying distinct random
	// kids. On overflow the oldest entry is evicted.
	negativeCacheMaxEntries = 128
)

// allowedAlgs is the hardcoded signature-algorithm allowlist. `none` and all
// HMAC algs are excluded (RFC 8725 §3.1/§3.2 — HMAC with a public JWKS is the
// algorithm-confusion attack). Excluding EdDSA (Ed25519/Ed448) is a policy
// choice, not a spec requirement: none of the current consumers have an
// EdDSA-issuing IdP, and widening later is purely additive.
var allowedAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// Principal is the verified identity carried by a token. It never carries
// the serialized token or any other credential.
type Principal struct {
	// Issuer is the verified `iss` claim.
	Issuer string
	// Subject is the verified `sub` claim, guaranteed non-empty.
	Subject string
	// Name is the `name` claim, may be empty.
	Name string
	// Claims is the full verified claim set. It is the raw credential (the
	// serialized token) that is deliberately absent, never claim data. Claims
	// beyond iss/sub/name — e.g. the `email` claim ToolHive's claimsToIdentity
	// uses for its display-name fallback, or an IdP-specific claim like Okta's
	// `tsid` — are read here by consumers; they are intentionally NOT
	// first-class fields, since the struct carries only what every resource
	// server needs.
	Claims map[string]any
}

// ParseBearer extracts the token from an Authorization header value. The
// scheme match is CASE-INSENSITIVE per RFC 7235 §2.1 (this fixes ToolHive's
// case-sensitive match at pkg/auth/utils.go:45-47).
//
// The missing-vs-malformed split lets callers distinguish "no credentials"
// (a bare WWW-Authenticate challenge, RFC 6750 §3.1) from "broken
// credentials" (error="invalid_request", 400): an empty value yields
// ReasonMissingHeader; anything else malformed — not exactly `Bearer
// <token>`, extra whitespace segments, an empty token part, or a token
// longer than maxTokenLength — yields ReasonMalformed.
//
// All ParseBearer failures use Code CodeInvalidRequest (400), including
// ReasonMalformed. The ReasonMalformed value here is a malformed *header*, not
// a possibly-opaque token, so unlike Validate's CodeInvalidToken +
// ReasonMalformed it must NOT feed ToolHive's introspection fallback (see
// errors.go).
//
// NO error returned here contains any byte of the header value. Error() is
// documented as log-safe, and a malformed header routinely still carries a live
// credential — "Bearer <token> junk", or a token sent with no scheme at all
// would put a replayable token into the logs (RFC 6750 §5 names token
// disclosure as a primary threat). Errors therefore report only the structural
// category and, where useful, a length.
func ParseBearer(headerValue string) (string, error) {
	if headerValue == "" {
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMissingHeader,
			err: errors.New("no Authorization header")}
	}
	// RFC 7235 credentials are `auth-scheme 1*SP token68`: one or more spaces
	// separate the scheme from the credential, and token68 itself has no
	// internal whitespace. Cut at the first space, then trim any additional
	// separator spaces (1*SP, not exactly one).
	scheme, rest, found := strings.Cut(headerValue, " ")
	if !found || scheme == "" {
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed,
			err: errors.New("expected 'Bearer <token>': no scheme/credential separator")}
	}
	if !strings.EqualFold(scheme, "Bearer") {
		// The scheme is not echoed either: on a header with no separator the
		// whole credential can land in this position.
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed,
			err: errors.New("unsupported auth scheme: expected Bearer")}
	}
	token := strings.TrimLeft(rest, " ")
	if token == "" {
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed,
			err: errors.New("expected 'Bearer <token>': empty credential")}
	}
	// token68 forbids internal whitespace, so anything left after trimming the
	// separator means the header is not a single bearer credential.
	if strings.ContainsAny(token, " \t") {
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed,
			err: errors.New("credential contains whitespace")}
	}
	if len(token) > maxTokenLength {
		return "", &Error{Code: CodeInvalidRequest, Reason: ReasonMalformed,
			err: fmt.Errorf("token length %d exceeds %d byte limit", len(token), maxTokenLength)}
	}
	return token, nil
}

// Validate verifies a bare JWT (no "Bearer " prefix — callers use
// ParseBearer for that) against the validator's issuer/audience policy and
// JWKS key material, returning the verified Principal.
//
// Every failure is a *Error. The verification order is fixed so that nothing
// touching key material runs before the algorithm gate (RFC 8725 §3.1) and
// nothing expensive runs before the cheap structural rejects.
func (v *Validator) Validate(ctx context.Context, token string) (Principal, error) {
	// A closed validator cannot reach key material, so say so plainly rather
	// than letting the caller discover it as a context error from deeper down.
	if v.closed() {
		return Principal{}, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
			err: errors.New("validator is closed")}
	}
	if token == "" {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonMalformed,
			err: errors.New("empty token")}
	}
	if len(token) > maxTokenLength {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonMalformed,
			err: fmt.Errorf("token length %d exceeds %d byte limit", len(token), maxTokenLength)}
	}

	// Alg gate: read the UNVERIFIED header's alg and reject anything off the
	// allowlist BEFORE any key material is touched (RFC 8725 §3.1). This is a
	// structural check so mapParseError never has to guess at a message; the
	// result is only used for the gate, never trusted — golang-jwt re-parses
	// and enforces the same allowlist on the verified path below.
	alg, malformedErr := unverifiedAlg(token)
	if malformedErr != nil {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonMalformed, err: malformedErr}
	}
	if !slices.Contains(allowedAlgs, alg) {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonUnsupportedAlg,
			err: fmt.Errorf("alg %q is not in the allow-list", alg)}
	}

	// The same allowlist is enforced again by the parser (WithValidMethods) so
	// the verified path cannot be bypassed by a header that disagrees with
	// itself, and so the gate cannot be forgotten by a second key path.
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedAlgs),
		// Strict base64url, no padding (RFC 7515 §2); padding-allowed decode
		// is the WithPaddingAllowed escape hatch and is NOT enabled.
		jwt.WithStrictDecoding(),
		// exp is required and validated against now+leeway; golang-jwt does
		// not require exp by default, hence the explicit option.
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.cfg.Leeway),
		// iat, when present, must not be in the future beyond leeway.
		jwt.WithIssuedAt(),
	}
	// The iss and aud options are added only when configured. golang-jwt treats
	// an empty expected issuer/audience set as "do not check" anyway, but
	// appending conditionally keeps the disabled case explicit here rather than
	// depending on that library behavior. Config.validate has already ensured
	// an empty Audiences was a deliberate AllowAnyAudience choice and that an
	// empty Issuer came with an explicit JWKSURL.
	if v.cfg.Issuer != "" {
		// iss is compared byte-exact (OIDC Core §3.1.3.2); NO TrimSpace.
		opts = append(opts, jwt.WithIssuer(v.cfg.Issuer))
	}
	if len(v.cfg.Audiences) > 0 {
		// aud any-match against the configured set (bare string or array on
		// the wire).
		opts = append(opts, jwt.WithAudience(v.cfg.Audiences...))
	}
	parser := jwt.NewParser(opts...)

	claims := jwt.MapClaims{}
	// kidSeen records whether the unverified header carried a kid, so the
	// "no candidate keys" error below can distinguish ReasonUnknownKID (kid
	// present, not found) from ReasonSignature (kid absent, nothing matched).
	var kidSeen bool
	_, err := parser.ParseWithClaims(token, claims, func(tok *jwt.Token) (any, error) {
		// RFC 7515 §4.1.11: we understand NO crit extensions, so any token
		// whose header carries a `crit` member must be rejected. golang-jwt
		// v5 does not inspect crit, so this is hand-written.
		if _, hasCrit := tok.Header["crit"]; hasCrit {
			return nil, &Error{Code: CodeInvalidToken, Reason: ReasonCriticalHeader,
				err: fmt.Errorf("token header carries unsupported crit member: %v", tok.Header["crit"])}
		}
		var kid string
		if k, ok := tok.Header["kid"].(string); ok {
			kid = k
		}
		kidSeen = kid != ""
		return v.verificationKeys(ctx, kid, tok.Method.Alg())
	})
	if err != nil {
		return Principal{}, mapParseError(err, kidSeen)
	}

	// Post-verification hand checks. These read the VERIFIED claims map only.
	if err := v.checkLifetime(claims); err != nil {
		return Principal{}, err
	}
	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return Principal{}, &Error{Code: CodeInvalidToken, Reason: ReasonSubject,
			err: errors.New("missing or empty sub claim")}
	}

	// Issuer comes from the VERIFIED claim rather than from Config: when
	// Config.Issuer is set the parser has already proven they are byte-equal,
	// and when it is empty (JWKSURL-only, iss verification disabled) the claim
	// is the only thing that reports who actually issued the token.
	return Principal{
		Issuer:  stringClaim(claims, "iss"),
		Subject: sub,
		Name:    stringClaim(claims, "name"),
		Claims:  claims,
	}, nil
}

// unverifiedAlg extracts the alg from a token's UNVERIFIED header, used only
// for the pre-keyfunc alg gate. The result is never trusted for verification.
//
// The header segment is decoded directly rather than via ParseUnverified
// because ParseUnverified itself rejects a token whose header carries no alg
// ("signing method (alg) is unspecified"), which would mislabel a missing alg
// as ReasonMalformed. Returning "" for a missing alg lets the allowlist check
// in Validate map it to ReasonUnsupportedAlg, matching the errors.go contract
// (missing/none/off-list alg is unsupported_alg). A non-nil error here means
// the token is not a structurally valid 3-segment JWT — wrong segment count,
// bad base64url, or non-JSON header — which Validate maps to ReasonMalformed.
func unverifiedAlg(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token contains an invalid number of segments: %d", len(parts))
	}
	hdr, err := jwt.NewParser().DecodeSegment(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode header segment: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &header); err != nil {
		return "", fmt.Errorf("failed to parse header JSON: %w", err)
	}
	return header.Alg, nil
}

// mapParseError converts a golang-jwt error into the package's *Error. A
// keyfunc *Error (crit/unknown-kid/keys-unavailable) is checked first so it
// is not shadowed by the generic sentinel mapping. The alg gate runs before
// the parser, so ErrTokenSignatureInvalid here is always a genuine signature
// failure, never an alg rejection.
func mapParseError(err error, kidSeen bool) error {
	var authnErr *Error
	if errors.As(err, &authnErr) {
		return authnErr
	}
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return &Error{Code: CodeInvalidToken, Reason: ReasonMalformed, err: err}
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return &Error{Code: CodeInvalidToken, Reason: ReasonSignature, err: err}
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		// The keyfunc returned an empty candidate set. With a kid present the
		// filtered set is only empty when the kid matched nothing, which the
		// unknown-kid path already recorded; reaching here means the kid was
		// absent and no key matched.
		if kidSeen {
			return &Error{Code: CodeInvalidToken, Reason: ReasonUnknownKID, err: err}
		}
		return &Error{Code: CodeInvalidToken, Reason: ReasonSignature, err: err}
	case errors.Is(err, jwt.ErrTokenExpired):
		return &Error{Code: CodeInvalidToken, Reason: ReasonExpired, err: err}
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return &Error{Code: CodeInvalidToken, Reason: ReasonNotYetValid, err: err}
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return &Error{Code: CodeInvalidToken, Reason: ReasonIssuedInFuture, err: err}
	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		// golang-jwt raises ErrTokenRequiredClaimMissing (NOT
		// ErrTokenInvalidIssuer/ErrTokenInvalidAudience) when a required
		// claim is absent OR has the wrong type — e.g. a non-string/array
		// aud surfaces as "aud claim is required". The wrapped message names
		// the claim, which we match to map to a per-claim reason. None of
		// these may be ReasonMalformed: that pair is the load-bearing
		// introspection-fallback trigger (errors.go), and a signed JWT
		// missing iss/aud/exp is a claim-policy failure, not an opaque token
		// worth introspecting.
		msg := err.Error()
		switch {
		case strings.Contains(msg, "iss claim is required"):
			return &Error{Code: CodeInvalidToken, Reason: ReasonIssuer, err: err}
		case strings.Contains(msg, "aud claim is required"):
			return &Error{Code: CodeInvalidToken, Reason: ReasonAudience, err: err}
		case strings.Contains(msg, "exp claim is required"):
			return &Error{Code: CodeInvalidToken, Reason: ReasonExpirationMissing, err: err}
		default:
			return &Error{Code: CodeInvalidToken, Reason: ReasonMissingClaim, err: err}
		}
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return &Error{Code: CodeInvalidToken, Reason: ReasonIssuer, err: err}
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return &Error{Code: CodeInvalidToken, Reason: ReasonAudience, err: err}
	default:
		// By the time mapParseError runs, unverifiedAlg (see Validate) has
		// already rejected any structurally-invalid non-JWT BEFORE the parser
		// ran, and jwt.ErrTokenMalformed (the only genuine "may be an opaque
		// token" signal) has its own case above. So anything reaching here
		// parsed as a JWT and merely failed some claim check this switch does
		// not name — e.g. jwt.ErrInvalidType from a wrong-typed claim such as
		// a numeric iss. That must not be ReasonMalformed: doing so would
		// silently route every unenumerated golang-jwt error into ToolHive's
		// introspection fallback.
		return &Error{Code: CodeInvalidToken, Reason: ReasonInvalidClaims, err: err}
	}
}

// checkLifetime rejects tokens whose exp-iat span exceeds the configured
// MaxTokenLifetime, when both claims are present. A token without iat skips
// the check entirely (many IdPs omit it).
func (v *Validator) checkLifetime(claims jwt.MapClaims) error {
	// Zero means the caller opted out of a lifetime bound (the default).
	if v.cfg.MaxTokenLifetime == 0 {
		return nil
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil
	}
	iat, ok := issuedAt(claims)
	if !ok {
		return nil
	}
	if exp.Sub(iat) > v.cfg.MaxTokenLifetime {
		return &Error{Code: CodeInvalidToken, Reason: ReasonLifetime,
			err: fmt.Errorf("token lifetime %s exceeds maximum %s",
				exp.Sub(iat), v.cfg.MaxTokenLifetime)}
	}
	return nil
}

// issuedAt reads the iat claim, reporting whether it was PRESENT rather than
// whether it was non-zero.
//
// jwt.MapClaims.GetIssuedAt cannot distinguish the two: it returns a nil
// NumericDate for a numeric zero, so `iat: 0` — a perfectly valid NumericDate
// meaning the Unix epoch — reads as absent and silently skips the lifetime
// check, no matter how distant exp is. Inspecting the raw claim closes that
// bypass.
//
// A non-numeric iat cannot reach here: the parser runs WithIssuedAt, which
// rejects a wrong-typed claim before verification completes. The type switch is
// a backstop, and an unrecognized type is reported as absent (the pre-existing
// behavior) rather than guessed at.
func issuedAt(claims jwt.MapClaims) (time.Time, bool) {
	raw, present := claims["iat"]
	if !present {
		return time.Time{}, false
	}
	switch n := raw.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case int:
		return time.Unix(int64(n), 0), true
	case json.Number:
		secs, err := n.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(secs, 0), true
	default:
		return time.Time{}, false
	}
}

// stringClaim extracts a string claim, tolerating a missing or non-string
// value (returns "").
func stringClaim(claims jwt.MapClaims, name string) string {
	if s, ok := claims[name].(string); ok {
		return s
	}
	return ""
}

// verificationKeys implements the keyfunc: it resolves candidate verification
// keys for a token carrying the given (possibly empty) kid and algorithm.
//
// A configured KeyProvider is consulted FIRST and short-circuits on a hit,
// matching the order ToolHive's validator uses. That ordering is what makes the
// embedded-issuer topology work: the local keys resolve without any HTTP, so a
// JWKS endpoint that is not yet listening (or not routable) never blocks
// validation. On a provider miss the JWKS path below still runs, so a validator
// with both sources configured can verify tokens from either.
func (v *Validator) verificationKeys(ctx context.Context, kid, alg string) (any, error) {
	// Bind every cache operation to the validator's lifetime as well as the
	// request. The jwx cache's controller goroutines stop when v.ctx is
	// canceled, so a Lookup issued with only the request context after Close
	// sends on a channel with no remaining receiver and blocks forever — a
	// graceful-shutdown hang for any request still in flight.
	ctx, cancel := v.withLifetime(ctx)
	defer cancel()

	if v.cfg.KeyProvider != nil {
		local, err := v.keysFromProvider(ctx, kid, alg)
		if err != nil {
			return nil, err
		}
		if len(local) > 0 {
			set := jwt.VerificationKeySet{Keys: make([]jwt.VerificationKey, 0, len(local))}
			for _, k := range local {
				set.Keys = append(set.Keys, k)
			}
			return set, nil
		}
		// Provider miss. When there is no JWKS to fall back to (an embedded
		// issuer with no reachable endpoint), report the kid as unknown rather
		// than falling through to a cache that was never populated.
		if v.jwksCache == nil {
			return nil, &Error{Code: CodeInvalidToken, Reason: ReasonUnknownKID,
				err: fmt.Errorf("kid %q not offered by the key provider and no JWKS is configured", kid)}
		}
	}

	set, err := v.jwksCache.Lookup(ctx, v.jwksURL)
	if err != nil {
		// "Registered but first fetch pending" is reported distinctly; any
		// other lookup failure also means key material is unreachable.
		if errors.Is(err, httprc.ErrNotReady()) {
			return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
				err: fmt.Errorf("JWKS fetch pending for %s: %w", v.jwksURL, err)}
		}
		return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
			err: fmt.Errorf("JWKS unavailable for %s: %w", v.jwksURL, err)}
	}

	keys := candidateKeys(set, kid, alg)
	if len(keys) == 0 && kid != "" {
		// H1 unknown-kid recovery: one serialized refresh, then re-resolve.
		// The negative cache suppresses a refresh for a kid we have already
		// failed within the TTL.
		if v.knownBadKID(kid) {
			return nil, &Error{Code: CodeInvalidToken, Reason: ReasonUnknownKID,
				err: fmt.Errorf("kid %q not in JWKS (negative cache)", kid)}
		}
		// refreshOnce reports whether a fetch was actually attempted. When
		// it skipped the fetch (inside refreshFloor), refreshed is false and
		// the kid must NOT be negative-cached below: no fetch happened, so
		// the kid may have been rotated in since the last refresh and simply
		// not yet visible. Negative-caching here would blackhole a
		// legitimately rotated kid for negativeCacheTTL.
		refreshed, refreshErr := v.refreshOnce()
		if refreshErr != nil {
			return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
				err: fmt.Errorf("JWKS refresh for unknown kid %q failed: %w", kid, refreshErr)}
		}
		set, err = v.jwksCache.Lookup(ctx, v.jwksURL)
		if err != nil {
			return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
				err: fmt.Errorf("JWKS unavailable for %s after refresh: %w", v.jwksURL, err)}
		}
		keys = candidateKeys(set, kid, alg)
		if len(keys) == 0 {
			// Only record the kid as bad when a fetch actually happened. If
			// refreshOnce skipped the fetch (inside refreshFloor), proceed to
			// the unknown-kid error WITHOUT recording, so a later Validate
			// past the floor can still recover a rotated key.
			if refreshed {
				v.recordBadKID(kid)
			}
			return nil, &Error{Code: CodeInvalidToken, Reason: ReasonUnknownKID,
				err: fmt.Errorf("kid %q not in JWKS", kid)}
		}
	}

	return exportCandidates(keys, alg)
}

// candidateKeys filters the JWKS set down to the keys eligible to verify a
// token with the given kid/alg, bounded to maxKeyCandidates.
func candidateKeys(set jwk.Set, kid, alg string) []jwk.Key {
	var out []jwk.Key
	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		// kid filter: with a kid, only matching keys; without, every key.
		if kid != "" {
			keyID, hasID := key.KeyID()
			if !hasID || keyID != kid {
				continue
			}
		}
		if !keyEligible(key, alg) {
			continue
		}
		out = append(out, key)
	}
	if len(out) > maxKeyCandidates {
		out = out[:maxKeyCandidates]
	}
	return out
}

// keyEligible applies the candidate filters: use/key_ops/alg eligibility plus
// the kty-vs-alg backstop.
func keyEligible(key jwk.Key, alg string) bool {
	// use: "enc" is excluded; an absent use passes (use is optional in
	// RFC 7517 §4.2).
	if use, hasUse := key.KeyUsage(); hasUse && use == string(jwk.ForEncryption) {
		return false
	}
	// key_ops, when present, must contain "verify" (RFC 7517 §4.3).
	if ops, hasOps := key.KeyOps(); hasOps {
		verify := false
		for _, op := range ops {
			if op == jwk.KeyOpVerify {
				verify = true
				break
			}
		}
		if !verify {
			return false
		}
	}
	// A JWK that declares alg must match the token's alg (RFC 8725 §3.9).
	if keyAlg, hasAlg := key.Algorithm(); hasAlg && keyAlg.String() != alg {
		return false
	}
	// Key-type backstop for JWKs that omit alg: the kty (and for EC the
	// curve) must be consistent with the token's alg. Without this an EC key
	// can be handed to an RS256 verify path.
	return keyTypeMatchesAlg(key, alg)
}

// keyTypeMatchesAlg enforces kty/curve consistency with the token alg.
func keyTypeMatchesAlg(key jwk.Key, alg string) bool {
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		return key.KeyType().String() == "RSA"
	case strings.HasPrefix(alg, "ES"):
		if key.KeyType().String() != "EC" {
			return false
		}
		var raw ecdsa.PublicKey
		if err := jwk.Export(key, &raw); err != nil {
			return false
		}
		return curveMatchesAlg(raw.Curve.Params().Name, alg)
	default:
		// Unreachable via Validate: the alg gate rejects any alg off the
		// allowlist (RS/PS/ES only) before a keyfunc runs.
		return false
	}
}

// curveMatchesAlg maps the ES* alg to its required NIST curve. It is only
// called with ES* algs (keyTypeMatchesAlg dispatches on the alg prefix), so
// the default branch is defensive, not reachable from Validate.
func curveMatchesAlg(curveName, alg string) bool {
	switch alg {
	case "ES256":
		return curveName == "P-256"
	case "ES384":
		return curveName == "P-384"
	case "ES512":
		return curveName == "P-521"
	default:
		return false
	}
}

// exportCandidates converts eligible JWKs to raw crypto keys for golang-jwt,
// returning a VerificationKeySet so golang-jwt iterates the candidates.
func exportCandidates(keys []jwk.Key, alg string) (any, error) {
	set := jwt.VerificationKeySet{Keys: make([]jwt.VerificationKey, 0, len(keys))}
	for _, key := range keys {
		raw, err := exportKey(key, alg)
		if err != nil {
			return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
				err: fmt.Errorf("failed to export JWK to crypto key: %w", err)}
		}
		set.Keys = append(set.Keys, raw)
	}
	return set, nil
}

// exportKey converts a single JWK to the *rsa.PublicKey or *ecdsa.PublicKey
// appropriate for the token alg.
func exportKey(key jwk.Key, alg string) (any, error) {
	switch {
	case strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS"):
		var raw rsa.PublicKey
		if err := jwk.Export(key, &raw); err != nil {
			return nil, err
		}
		return &raw, nil
	case strings.HasPrefix(alg, "ES"):
		var raw ecdsa.PublicKey
		if err := jwk.Export(key, &raw); err != nil {
			return nil, err
		}
		return &raw, nil
	default:
		// Unreachable via Validate: the alg gate admits only RS/PS/ES algs.
		return nil, fmt.Errorf("unsupported alg %q", alg)
	}
}

// refreshOnce triggers at most one JWKS refresh within refreshFloor,
// serialized by refreshMu: a second concurrent caller blocks, then sees a
// fresh lastRefresh and skips the network fetch. This is the unknown-kid
// recovery path (H1), deliberately implemented as mutex+timestamp rather than
// pulling in golang.org/x/sync/singleflight.
//
// It reports whether a fetch was actually attempted (refreshed): within
// refreshFloor the fetch is skipped and refreshed is false, so a caller can
// avoid negative-caching a kid when no fetch actually happened (the kid may
// have been rotated in but not yet visible because the floor suppressed the
// fetch).
//
// The refresh runs on a context derived from the validator's lifetime context
// (v.ctx) with a bounded timeout, NOT the per-request context: the refresh
// outlives the request that triggered it, and a client disconnect mid-refresh
// must not cancel a shared JWKS fetch.
func (v *Validator) refreshOnce() (bool, error) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	if time.Since(v.lastRefresh) < refreshFloor {
		return false, nil
	}
	// The refresh outlives the request that triggered it: derive from the
	// validator's lifetime context, not the per-request ctx.
	refreshCtx, cancel := context.WithTimeout(v.ctx, defaultHTTPTimeout)
	defer cancel()
	_, err := v.jwksCache.Refresh(refreshCtx, v.jwksURL)
	v.lastRefresh = time.Now()
	return true, err
}

// knownBadKID reports whether kid is in the negative cache (within TTL).
func (v *Validator) knownBadKID(kid string) bool {
	v.negativeMu.Lock()
	defer v.negativeMu.Unlock()
	expiry, ok := v.negativeKids[kid]
	return ok && time.Now().Before(expiry)
}

// recordBadKID records kid in the negative cache with a TTL, evicting the
// oldest entry when the cache is full (bounded in entry count, not only TTL).
func (v *Validator) recordBadKID(kid string) {
	v.negativeMu.Lock()
	defer v.negativeMu.Unlock()
	if v.negativeKids == nil {
		v.negativeKids = make(map[string]time.Time)
	}
	if len(v.negativeKids) >= negativeCacheMaxEntries {
		// Evict the oldest entry. The map is small (128) so a linear scan is
		// fine; this path is only hit under a kid-spraying attack.
		var oldestKid string
		var oldestExpiry time.Time
		for k, expiry := range v.negativeKids {
			if oldestKid == "" || expiry.Before(oldestExpiry) {
				oldestKid = k
				oldestExpiry = expiry
			}
		}
		delete(v.negativeKids, oldestKid)
	}
	v.negativeKids[kid] = time.Now().Add(negativeCacheTTL)
}
