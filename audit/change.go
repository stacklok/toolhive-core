// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import "encoding/json"

type changeKind int

const (
	changeKindValue changeKind = iota
	changeKindSecret
	changeKindMembers
)

// Change records one field that a write changed. The [EventBuilder] writes
// the changes passed with [WithChanges] to metadata.extra.changes.
//
// Build a Change with [FieldChange], [SecretFieldChange] or [MembersChange].
// A secret field has no slot for a value, so a call site cannot record a
// secret value by mistake.
type Change struct {
	kind    changeKind
	field   string
	before  string
	after   string
	added   []string
	removed []string
}

// FieldChange records a field whose value went from before to after. Both
// values are written, so the trail shows each value a field has held.
func FieldChange(field, before, after string) Change {
	return Change{kind: changeKindValue, field: field, before: before, after: after}
}

// SecretFieldChange records that a secret-bearing field changed, by name
// only. It takes no value, so neither the old nor the new secret can reach
// the audit trail.
func SecretFieldChange(field string) Change {
	return Change{kind: changeKindSecret, field: field}
}

// MembersChange records a membership change: the ids of the members added to
// and removed from field. The slices are copied.
func MembersChange(field string, added, removed []string) Change {
	return Change{
		kind:    changeKindMembers,
		field:   field,
		added:   append([]string(nil), added...),
		removed: append([]string(nil), removed...),
	}
}

// changeJSON is the encoded form of a [Change].
type changeJSON struct {
	Field   string    `json:"field"`
	Before  *string   `json:"before,omitempty"`
	After   *string   `json:"after,omitempty"`
	Secret  bool      `json:"secret,omitempty"`
	Added   *[]string `json:"added,omitempty"`
	Removed *[]string `json:"removed,omitempty"`
}

// MarshalJSON encodes a value change as {"field","before","after"}, a secret
// change as {"field","secret":true}, and a membership change as
// {"field","added","removed"}.
func (c Change) MarshalJSON() ([]byte, error) {
	out := changeJSON{Field: c.field}
	switch c.kind {
	case changeKindValue:
		out.Before, out.After = &c.before, &c.after
	case changeKindSecret:
		out.Secret = true
	case changeKindMembers:
		added, removed := nonNil(c.added), nonNil(c.removed)
		out.Added, out.Removed = &added, &removed
	}
	return json.Marshal(out)
}

// String renders the change without its values, so formatting a Change with
// fmt never prints a field value.
func (c Change) String() string {
	return "audit.Change{field:" + c.field + "}"
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
