// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DefaultMaxDelegationDepth is the default defensive cap on delegation-chain
// parsing. It bounds recursion on attacker-influenceable input: RFC 8693 sets
// no limit on chain length, so a maliciously crafted token could otherwise
// force unbounded recursion. Callers may pass a stricter maxDepth to
// [ParseDelegationChain] to match a minting-side cap. The default is
// intentionally larger than any known consumer's minting cap.
const DefaultMaxDelegationDepth = 16

// ErrNotJSONObject is returned by [ParseDelegationChain] when the top-level
// act claim value is not a JSON object (e.g. a string, number, bool, or array).
var ErrNotJSONObject = errors.New("top-level act claim is not a JSON object")

// ErrNestedActNotObject is returned by [ParseDelegationChain] when a nested
// act member inside a delegation hop is not a JSON object.
var ErrNestedActNotObject = errors.New("nested act claim is not a JSON object")

// hopClaimIss, hopClaimSub, and hopClaimAct are the RFC 8693 claim keys
// recognized on a delegation hop. All other keys are treated as extra
// (in-memory-only) claims.
const (
	hopClaimIss = "iss"
	hopClaimSub = "sub"
	hopClaimAct = "act"
)

// DelegatedActor represents a single hop in an RFC 8693 delegation chain.
//
// Per-hop identity is the issuer (iss) and subject (sub) pair only, as
// specified by RFC 8693 §6. Any other claims present on a hop are retained
// in the in-memory-only extra map (never serialized or logged) to avoid
// leaking Personally Identifiable Information.
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
// The chain is ordered OUTERMOST-FIRST: Chain[0] is the current actor (the
// immediate subject of the event), and the last entry is the least recent
// (original) actor. Only the top-level event claims and Chain[0] should
// drive access-control decisions; prior hops are informational only.
//
// Truncated and Omitted intentionally have no omitempty tag: truncation is
// never silent. When Truncated is true, Omitted reports how many inner hops
// were dropped to satisfy the maxDepth cap. The outermost hops are always
// preserved (the current actor is never dropped); only inner hops are
// omitted.
type DelegationChain struct {
	Chain     []DelegatedActor `json:"chain"`
	Truncated bool             `json:"truncated"`
	Omitted   int              `json:"omitted"`
}

// IsEmpty reports whether the chain is nil or contains no hops.
func (c *DelegationChain) IsEmpty() bool {
	return c == nil || len(c.Chain) == 0
}

// ParseDelegationChain parses a raw RFC 8693 `act` claim into a flattened,
// outermost-first [DelegationChain].
//
// The input is expected to be a JSON object (map) decoded via
// [encoding/json.Unmarshal] into an `any` value (i.e. map[string]any). The
// parser walks nested `act` claims iteratively, bounded by maxDepth, so
// pathologically deep input cannot cause a stack overflow.
//
// Parsing semantics:
//   - maxDepth <= 0 uses [DefaultMaxDelegationDepth].
//   - A nil input yields a non-nil empty chain (&DelegationChain{}), no error.
//   - A non-map scalar (string, float64, bool, []any) returns nil and an error
//     whose message names the unexpected kind.
//   - A map with no iss/sub/act yields one hop with empty Subject/Issuer
//     (sub is conventional, not RFC-mandatory; parsing is tolerant).
//   - A map with sub sets that hop's Subject; iss sets Issuer.
//   - A nested `act` map is recursed: the outer map is Chain[0], its act is
//     Chain[1], and so on. The result is naturally outermost-first.
//   - When the depth equals maxDepth exactly, the full chain is returned with
//     Truncated=false and Omitted=0.
//   - When the depth exceeds maxDepth, the OUTERMOST maxDepth hops are kept
//     (the current actor is preserved), Truncated=true, and Omitted counts
//     the dropped inner hops. This is truncation, not an error.
//   - An `act` claim present but not a map (e.g. "act":"x") returns nil and
//     an error.
//   - Unknown extra keys on a hop are stored in that hop's in-memory-only
//     extra map (see [DelegatedActor.Extra]).
func ParseDelegationChain(raw any, maxDepth int) (*DelegationChain, error) {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDelegationDepth
	}

	if raw == nil {
		return &DelegationChain{}, nil
	}

	// A non-map scalar input is invalid; the top-level act claim must be a
	// JSON object. Reject by naming the unexpected kind.
	switch raw.(type) {
	case map[string]any:
		// ok, proceed
	case string, float64, bool, []any, json.Number:
		return nil, fmt.Errorf("%w: expected JSON object, got %T", ErrNotJSONObject, raw)
	default:
		return nil, fmt.Errorf("%w: expected JSON object, got %T", ErrNotJSONObject, raw)
	}

	chain := &DelegationChain{}
	current := raw
	depth := 0

	for current != nil {
		if depth >= maxDepth {
			// We have hit the cap. The remaining inner hops (current and any
			// nested act beneath it) must be counted and dropped, preserving
			// only the outermost maxDepth hops already collected.
			chain.Truncated = true
			chain.Omitted += countRemainingHops(current)
			return chain, nil
		}

		hopMap, ok := current.(map[string]any)
		if !ok {
			// An `act` claim present but not a map is a hard error.
			return nil, fmt.Errorf("%w: act claim must be a JSON object", ErrNestedActNotObject)
		}

		hop := DelegatedActor{extra: extraClaims(hopMap)}
		if iss, ok := hopMap[hopClaimIss].(string); ok {
			hop.Issuer = iss
		}
		if sub, ok := hopMap[hopClaimSub].(string); ok {
			hop.Subject = sub
		}
		chain.Chain = append(chain.Chain, hop)
		depth++

		next, hasAct := hopMap[hopClaimAct]
		if !hasAct {
			// No further nesting; the chain is complete.
			return chain, nil
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: act claim must be a JSON object", ErrNestedActNotObject)
		}
		current = nextMap
	}

	return chain, nil
}

// countRemainingHops counts how many hops would follow the current node
// (inclusive of current) down the nested `act` chain. These are the hops
// dropped due to exceeding maxDepth. The walk is iterative (not recursive),
// so it cannot stack-overflow; it terminates because decoded JSON is a tree
// and cannot contain reference cycles.
func countRemainingHops(node any) int {
	count := 0
	current := node
	for current != nil {
		m, ok := current.(map[string]any)
		if !ok {
			// Non-map act was already validated during the main walk; treat a
			// malformed node as a single dropped hop and stop.
			count++
			break
		}
		count++
		next, hasAct := m[hopClaimAct]
		if !hasAct {
			break
		}
		nm, ok := next.(map[string]any)
		if !ok {
			count++
			break
		}
		current = nm
	}
	return count
}

// extraClaims returns a shallow copy of the non-standard keys on a hop map
// (i.e. every key except iss, sub, and act). The result is nil when there are
// no extra claims.
func extraClaims(hop map[string]any) map[string]any {
	var extra map[string]any
	for k, v := range hop {
		if k == hopClaimIss || k == hopClaimSub || k == hopClaimAct {
			continue
		}
		if extra == nil {
			extra = make(map[string]any)
		}
		extra[k] = v
	}
	return extra
}
