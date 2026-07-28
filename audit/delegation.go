// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"reflect"
)

// DefaultMaxDelegationDepth is the default cap on how many delegation hops
// [ParseDelegationChain] retains. It is a parse ceiling, not a minting cap:
// RFC 8693 sets no limit on chain length, so this bounds the size of the
// retained chain and of the emitted audit record on attacker-influenceable
// input. It does not bound parsing work — the caller has already decoded the
// claim. Callers should pass their own minting-side cap as maxDepth when they
// have one; the default is intentionally larger than any known consumer's
// minting cap, so that for consumers passing their (smaller) mint cap,
// Truncated=true is a genuine signal that a token came from outside their own
// issuance path.
const DefaultMaxDelegationDepth = 16

// hopClaimIss, hopClaimSub, and hopClaimAct are the RFC 8693 claim keys
// recognized on a delegation hop. All other keys are treated as extra
// (in-memory-only) claims.
const (
	hopClaimIss = "iss"
	hopClaimSub = "sub"
	hopClaimAct = "act"
)

// MalformedReason is a low-cardinality label describing the first
// RFC 8693 conformance violation encountered while parsing an `act` claim.
// It is deliberately an enum rather than free text so that it is safe to use
// as a metric or alerting dimension.
type MalformedReason string

// Malformed reasons reported by [ParseDelegationChain]. The first violation
// encountered wins; subsequent violations do not overwrite it.
const (
	// MalformedReasonActNotObject: the top-level act claim value was not a
	// JSON object (e.g. a string, number, bool, or array).
	MalformedReasonActNotObject MalformedReason = "act_not_object"
	// MalformedReasonNestedActNotObject: a nested act member inside a
	// delegation hop was not a JSON object.
	MalformedReasonNestedActNotObject MalformedReason = "nested_act_not_object"
	// MalformedReasonIssNotString: a hop carried an iss claim that was not a
	// JSON string. The raw value is retained in that hop's in-memory extra
	// claims under "iss".
	MalformedReasonIssNotString MalformedReason = "iss_not_string"
	// MalformedReasonSubNotString: a hop carried a sub claim that was not a
	// JSON string. The raw value is retained in that hop's in-memory extra
	// claims under "sub".
	MalformedReasonSubNotString MalformedReason = "sub_not_string"
)

// DelegatedActor represents a single hop in an RFC 8693 delegation chain.
//
// Per-hop identity is the issuer (iss) and subject (sub) pair only: per
// OpenID Connect Core §5.7 the (iss, sub) combination is the only stable,
// unique actor identifier, and RFC 8693 §6 calls for data minimization. Any
// other claims present on a hop are retained in the in-memory-only extra map
// (never serialized or logged) to avoid leaking Personally Identifiable
// Information.
type DelegatedActor struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub,omitempty"`
	extra   map[string]any
}

// Extra returns a shallow copy of the hop's extra (non-standard) claims.
// Mutating the returned map (adding, deleting, or replacing top-level keys)
// does not affect the hop's internal state. However, mutating a nested map
// or slice value may share underlying data with the hop's copy. It returns
// nil when the hop has no extra claims.
//
// The extra claims are deliberately excluded from JSON and slog output as a
// PII guard, and may contain sensitive or internal claims (session
// identifiers, emails, roles). Callers MUST NOT serialize or log the returned
// map; doing so reintroduces the leak this design prevents.
func (a DelegatedActor) Extra() map[string]any {
	if len(a.extra) == 0 {
		return nil
	}
	out := make(map[string]any, len(a.extra))
	for k, v := range a.extra {
		out[k] = v
	}
	return out
}

// DelegationChain holds a flattened, ordered RFC 8693 delegation chain.
//
// The chain is ordered OUTERMOST-FIRST: Chain[0] is the current actor — the
// party that presented the token — and the last entry is the least recent
// (original) actor. The party on whose behalf they acted is NOT part of the
// chain: per RFC 8693 it is the token's top-level sub, carried by the event's
// own Subjects map; the chain never repeats it. Per RFC 8693 §4.1, only the
// top-level event claims and Chain[0] may drive access-control decisions;
// prior hops are informational only and exist for audit.
//
// Ordering rationale — do not assume, and do not "fix": current-actor-first
// matches the read order of RFC 8693's nested act structure, and it keeps
// Chain[0] STABLE UNDER TRUNCATION — truncation drops inner (early) hops, so
// the one hop that may inform decisions is always at index 0, complete chain
// or not. Beware that append-style flat formats elsewhere (Envoy XFCC,
// GCP delegates[]) run the OPPOSITE direction (original-first); consumers
// correlating across systems must map explicitly rather than by position
// intuition.
//
// Truncated, Omitted, and Malformed intentionally have no omitempty tag:
// an incomplete or non-conformant chain is never silently indistinguishable
// from a complete, well-formed one. When Truncated is true, Omitted reports
// how many inner hops were dropped to satisfy the maxDepth cap; the outermost
// hops are always preserved (the current actor is never dropped). When
// Malformed is true, MalformedReason carries the first conformance violation
// encountered, and Chain holds the hops that parsed successfully before it.
type DelegationChain struct {
	Chain           []DelegatedActor `json:"chain"`
	Truncated       bool             `json:"truncated"`
	Omitted         int              `json:"omitted"`
	Malformed       bool             `json:"malformed"`
	MalformedReason MalformedReason  `json:"malformedReason,omitempty"`
}

// IsEmpty reports whether the chain is nil or contains no hops. Note that a
// chain with no hops may still carry audit-relevant state (Malformed); use
// [DelegationChain.IsZero] to decide whether a chain is worth recording.
func (c *DelegationChain) IsEmpty() bool {
	return c == nil || len(c.Chain) == 0
}

// IsZero reports whether the chain carries no information at all: no hops,
// no truncation, and no malformation. A zero chain is omitted from JSON and
// log output; a non-zero chain — including a hopless but malformed one — is
// always recorded.
func (c *DelegationChain) IsZero() bool {
	return c == nil || (len(c.Chain) == 0 && !c.Truncated && !c.Malformed)
}

// flagMalformed marks the chain malformed with the given reason. The first
// reason encountered wins so that the recorded reason points at the outermost
// (most actionable) violation.
func (c *DelegationChain) flagMalformed(reason MalformedReason) {
	c.Malformed = true
	if c.MalformedReason == "" {
		c.MalformedReason = reason
	}
}

// ParseDelegationChain parses a raw RFC 8693 `act` claim into a flattened,
// outermost-first [DelegationChain].
//
// The input is expected to be the decoded JSON value of the `act` claim
// (i.e. a map[string]any, or any named map type with string keys such as
// jwt.MapClaims). The parser walks nested `act` claims iteratively, bounded
// by maxDepth, so pathologically deep input cannot cause a stack overflow.
//
// ParseDelegationChain never fails: it is an audit-side parser, and an audit
// record must be producible for exactly the tokens that violate expectations
// (an unreadable delegation assertion is forensically distinct from "no
// delegation"). Non-conformant input is recorded on the returned chain via
// Malformed/MalformedReason rather than dropped or returned as an error.
// Enforcement belongs on the issuance path, not here.
//
// Parsing semantics:
//   - maxDepth <= 0 uses [DefaultMaxDelegationDepth].
//   - A nil input yields a zero chain (no hops, not malformed): a JSON null
//     or absent act claim asserts no delegation.
//   - A non-object input (string, number, bool, array) yields no hops and
//     Malformed=true with [MalformedReasonActNotObject].
//   - A map with no iss/sub/act yields one hop with empty Subject/Issuer
//     (sub is conventional, not RFC-mandatory; parsing is tolerant).
//   - A string sub sets that hop's Subject; a string iss sets Issuer. A
//     non-string sub or iss leaves the field empty, flags the chain malformed,
//     and retains the raw value in the hop's in-memory extra claims — the
//     record shows that an identifier was present but unusable.
//   - A nested `act` map is recursed: the outer map is Chain[0], its act is
//     Chain[1], and so on. The result is naturally outermost-first.
//   - A nested `act` that is present but not a map (JSON null excepted, which
//     ends the chain) keeps the hops parsed so far and flags the chain
//     malformed with [MalformedReasonNestedActNotObject].
//   - When the depth equals maxDepth exactly, the full chain is returned with
//     Truncated=false and Omitted=0.
//   - When the depth exceeds maxDepth, the OUTERMOST maxDepth hops are kept
//     (the current actor is preserved), Truncated=true, and Omitted counts
//     the dropped inner hops. A malformed node past the cap flags Malformed
//     but is not counted as an omitted hop.
//   - Unknown extra keys on a hop are stored in that hop's in-memory-only
//     extra map (see [DelegatedActor.Extra]) and are never serialized.
func ParseDelegationChain(raw any, maxDepth int) *DelegationChain {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDelegationDepth
	}

	chain := &DelegationChain{Chain: []DelegatedActor{}}
	if raw == nil {
		return chain
	}

	current, ok := asStringMap(raw)
	if !ok {
		chain.flagMalformed(MalformedReasonActNotObject)
		return chain
	}

	for depth := 0; ; depth++ {
		if depth >= maxDepth {
			// We have hit the cap. The remaining inner hops (current and any
			// nested act beneath it) are counted and dropped, preserving only
			// the outermost maxDepth hops already collected.
			chain.Truncated = true
			omitted, malformed := countRemainingHops(current)
			chain.Omitted += omitted
			if malformed {
				chain.flagMalformed(MalformedReasonNestedActNotObject)
			}
			return chain
		}

		hop := DelegatedActor{extra: extraClaims(current)}
		if rawIss, present := current[hopClaimIss]; present {
			if iss, isString := rawIss.(string); isString {
				hop.Issuer = iss
			} else {
				chain.flagMalformed(MalformedReasonIssNotString)
			}
		}
		if rawSub, present := current[hopClaimSub]; present {
			if sub, isString := rawSub.(string); isString {
				hop.Subject = sub
			} else {
				chain.flagMalformed(MalformedReasonSubNotString)
			}
		}
		chain.Chain = append(chain.Chain, hop)

		next, hasAct := current[hopClaimAct]
		if !hasAct || next == nil {
			// No further nesting (an explicit JSON null ends the chain like
			// an absent act); the chain is complete.
			return chain
		}

		nextMap, ok := asStringMap(next)
		if !ok {
			// A nested act present but not an object: keep what parsed and
			// record the violation.
			chain.flagMalformed(MalformedReasonNestedActNotObject)
			return chain
		}
		current = nextMap
	}
}

// countRemainingHops counts how many hops follow the current node (inclusive
// of current) down the nested `act` chain. These are the hops dropped due to
// exceeding maxDepth. The second return reports whether the walk ended on a
// non-object act value. The walk is iterative (not recursive), so it cannot
// stack-overflow; it terminates because decoded JSON is a tree and cannot
// contain reference cycles.
func countRemainingHops(node map[string]any) (int, bool) {
	count := 0
	current := node
	for {
		count++
		next, hasAct := current[hopClaimAct]
		if !hasAct || next == nil {
			return count, false
		}
		nm, ok := asStringMap(next)
		if !ok {
			// A non-object act past the cap is a violation, not a hop.
			return count, true
		}
		current = nm
	}
}

// extraClaims returns a shallow copy of the non-standard keys on a hop map:
// every key except act, and except iss/sub when they hold their conventional
// string type. A non-string iss/sub is retained here so the raw value stays
// inspectable in memory after the typed field is left empty. The result is
// nil when there are no extra claims.
func extraClaims(hop map[string]any) map[string]any {
	var extra map[string]any
	for k, v := range hop {
		switch k {
		case hopClaimAct:
			continue
		case hopClaimIss, hopClaimSub:
			if _, isString := v.(string); isString {
				continue
			}
		}
		if extra == nil {
			extra = make(map[string]any)
		}
		extra[k] = v
	}
	return extra
}

// asStringMap converts a decoded JSON object into a map[string]any. The fast
// path is a direct type assertion; the reflective fallback accepts named map
// types with string keys (e.g. jwt.MapClaims) so that programmatically built
// claim structures are not silently misread as non-objects.
func asStringMap(v any) (map[string]any, bool) {
	if m, ok := v.(map[string]any); ok {
		return m, true
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.Kind() != reflect.Map || rv.Type().Key().Kind() != reflect.String {
		return nil, false
	}
	out := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		out[iter.Key().String()] = iter.Value().Interface()
	}
	return out, true
}
