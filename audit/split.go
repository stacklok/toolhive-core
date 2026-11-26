// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// measureTime is the record time used to measure a line. slog renders the
// record time with the local offset, so a time with a non-zero offset and
// sub-second digits gives the longest rendering.
var measureTime = time.Date(2000, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", -(9*3600+30*60)))

// partPlaceholder stands in for part and parts while events are measured,
// before the number of parts is known. It is at least as wide as any real
// value.
const partPlaceholder = 9999999

// lineSize returns the size of the line the audit handler middleware writes
// for e, trailing newline included, measured with the middleware's own
// renderer.
func lineSize(e *AuditEvent) int {
	r := slog.NewRecord(measureTime, LevelAudit, auditEventMessage, 0)
	r.AddAttrs(e.logAttrs()...)
	line, err := renderAuditLine(context.Background(), r)
	if err != nil {
		return math.MaxInt
	}
	return len(line)
}

type itemKind int

const (
	itemChange itemKind = iota
	itemAdded
	itemRemoved
	itemHop
)

// item is one list entry that can move to a continuation event: a whole
// change, one member id of a membership change, or one delegation hop.
type item struct {
	kind itemKind
	// change is the index of the change in the caller's list.
	change int
	// ch is the change, for itemChange.
	ch Change
	// id is the member id, for itemAdded and itemRemoved.
	id string
	// hop is the delegation hop, for itemHop.
	hop DelegatedActor
	// records lists the cuts made to this item.
	records []truncation
}

// plan holds everything needed to build the events for one NewEvent call.
type plan struct {
	eventType string
	outcome   string
	component string
	loggedAt  time.Time
	source    EventSource
	subjects  map[string]string
	reason    string
	requestID string

	targetType string
	targetID   string
	// common lists the cuts to values every event repeats.
	common []truncation

	// First-event-only values.
	cause      string
	extra      map[string]any
	targetName string
	payload    json.RawMessage
	first      []truncation

	// chain carries the delegation chain's flags; its hops are items.
	chain        *DelegationChain
	changeFields []string
	items        []item
}

func (b *EventBuilder) newPlan(
	ctx context.Context,
	actor Actor,
	eventType string,
	target Target,
	outcome string,
	in *eventInput,
) *plan {
	p := &plan{
		eventType:  eventType,
		outcome:    outcome,
		component:  b.component,
		loggedAt:   time.Now().UTC(),
		source:     b.source,
		reason:     in.reason,
		targetType: target.Type,
		targetName: target.Name,
		cause:      in.cause,
		payload:    in.payload,
	}
	if in.source != nil {
		p.source = *in.source
	}
	p.requestID, _ = RequestIDFromContext(ctx)
	p.subjects, p.common = b.subjects(ctx, actor)
	p.targetID = capValue("target.id", target.ID, &p.common)
	p.source.Value = capValue("source.value", p.source.Value, &p.common)
	var sourceRecords []truncation
	p.source.Extra, sourceRecords = boundedExtra("source.extra", nil, p.source.Extra)
	p.common = append(p.common, sourceRecords...)
	sortTruncations(p.common)
	p.extra, p.first = boundedExtra("metadata.extra", reservedExtraKeys, in.extra)
	sortTruncations(p.first)

	p.changeFields = make([]string, len(in.changes))
	for i, c := range in.changes {
		// A field name is capped like an actor string. Its record travels
		// with the change, or with the first member id of a membership
		// change.
		var records []truncation
		c.field = capValue("changes.field", c.field, &records)
		p.changeFields[i] = c.field
		if c.kind != changeKindMembers || len(c.added)+len(c.removed) == 0 {
			p.items = append(p.items, item{kind: itemChange, change: i, ch: c, records: records})
			continue
		}
		for _, id := range c.added {
			p.items = append(p.items, item{kind: itemAdded, change: i, id: id, records: records})
			records = nil
		}
		for _, id := range c.removed {
			p.items = append(p.items, item{kind: itemRemoved, change: i, id: id, records: records})
			records = nil
		}
	}
	if !in.chain.IsZero() {
		p.chain = &DelegationChain{
			Truncated:       in.chain.Truncated,
			Omitted:         in.chain.Omitted,
			Malformed:       in.chain.Malformed,
			MalformedReason: in.chain.MalformedReason,
		}
		for i, hop := range in.chain.Chain {
			it := item{kind: itemHop, hop: hop}
			field := "delegation.chain[" + strconv.Itoa(i) + "]."
			it.hop.Issuer = capValue(field+"iss", hop.Issuer, &it.records)
			it.hop.Subject = capValue(field+"sub", hop.Subject, &it.records)
			p.items = append(p.items, it)
		}
	}
	return p
}

// event assembles one event. first selects the first event, which alone
// carries the component extra, the payload and the target name. parts is 0
// when the call returns a single event.
func (p *plan) event(auditID, cause string, first bool, items []item, part, parts int) *AuditEvent {
	subjects := make(map[string]string, len(p.subjects))
	for k, v := range p.subjects {
		subjects[k] = v
	}
	target := map[string]string{TargetKeyType: p.targetType, TargetKeyID: p.targetID}

	extra := p.baseExtra(first, cause, part, parts)
	records := append([]truncation(nil), p.common...)
	if first {
		if p.targetName != "" {
			target[TargetKeyName] = p.targetName
		}
		records = append(records, p.first...)
	}

	changes, hops := p.lists(items)
	if len(changes) > 0 {
		extra[MetadataExtraKeyChanges] = changes
	}
	for _, it := range items {
		records = append(records, it.records...)
	}
	if len(records) > 0 {
		extra[MetadataExtraKeyTruncated] = records
	}

	e := &AuditEvent{
		Metadata:  EventMetadata{AuditID: auditID, Extra: extra},
		Type:      p.eventType,
		LoggedAt:  p.loggedAt,
		Source:    p.source,
		Outcome:   p.outcome,
		Subjects:  subjects,
		Component: p.component,
		Target:    target,
	}
	if first && p.payload != nil {
		payload := p.payload
		e.Data = &payload
	}
	if p.chain != nil && (first || len(hops) > 0) {
		chain := *p.chain
		chain.Chain = hops
		e.WithDelegationChain(&chain)
	}
	return e
}

// baseExtra returns the metadata.extra keys of one event, before its lists
// and truncation records are added.
func (p *plan) baseExtra(first bool, cause string, part, parts int) map[string]any {
	extra := make(map[string]any)
	if first {
		for k, v := range p.extra {
			extra[k] = v
		}
	}
	extra[MetadataExtraKeySchemaVersion] = SchemaVersion
	if p.reason != "" {
		extra[MetadataExtraKeyReason] = p.reason
	}
	if p.requestID != "" {
		extra[MetadataExtraKeyRequestID] = p.requestID
	}
	if cause != "" {
		extra[MetadataExtraKeyCause] = cause
	}
	if parts > 0 {
		extra[MetadataExtraKeyPart] = part
		extra[MetadataExtraKeyParts] = parts
	}
	return extra
}

// lists rebuilds the change list and delegation hops from items, keeping
// their order and grouping member ids under their membership change.
func (p *plan) lists(items []item) ([]Change, []DelegatedActor) {
	var changes []Change
	var hops []DelegatedActor
	members := make(map[int]int)
	for _, it := range items {
		switch it.kind {
		case itemChange:
			changes = append(changes, it.ch)
		case itemAdded, itemRemoved:
			pos, ok := members[it.change]
			if !ok {
				changes = append(changes, Change{kind: changeKindMembers, field: p.changeFields[it.change]})
				pos = len(changes) - 1
				members[it.change] = pos
			}
			if it.kind == itemAdded {
				changes[pos].added = append(changes[pos].added, it.id)
			} else {
				changes[pos].removed = append(changes[pos].removed, it.id)
			}
		case itemHop:
			hops = append(hops, it.hop)
		}
	}
	return changes, hops
}

// build returns the events for the plan: one event when everything fits in
// targetLineBytes, and otherwise the first event and its continuations.
func (p *plan) build() []*AuditEvent {
	firstID := uuid.New().String()
	single := func() *AuditEvent { return p.event(firstID, p.cause, true, p.items, 0, 0) }

	if e := single(); lineSize(e) <= targetLineBytes {
		return []*AuditEvent{e}
	}

	// The event is too large. First make the first event fit without any
	// list entries, by cutting the payload and then the target name. Lists
	// are split, never cut, so they are left out of this measurement.
	placeholder := 0
	if len(p.items) > 0 {
		placeholder = partPlaceholder
	}
	p.fitHead(firstID, placeholder)
	if e := single(); len(p.items) == 0 || lineSize(e) <= targetLineBytes {
		return []*AuditEvent{e}
	}
	groups, ok := p.pack(firstID)
	switch {
	case !ok:
		// The fields every event repeats leave no room for some entry, so
		// no split brings every line under the limit. Splitting would only
		// repeat those fields once per entry: return one event, best effort.
		return []*AuditEvent{single()}
	case len(groups) == 1:
		return []*AuditEvent{p.event(firstID, p.cause, true, groups[0], 0, 0)}
	}
	events := make([]*AuditEvent, len(groups))
	for i, g := range groups {
		if i == 0 {
			events[i] = p.event(firstID, p.cause, true, g, 1, len(groups))
			continue
		}
		events[i] = p.event(uuid.New().String(), firstID, false, g, i+1, len(groups))
	}
	return events
}

// fitHead cuts the payload, then the target name, until the first event
// without list entries fits in targetLineBytes. It cuts nothing when even
// an empty payload and target name would not fit, since the overflow then
// comes from fields the builder never cuts.
func (p *plan) fitHead(firstID string, placeholder int) {
	size := func() int {
		return lineSize(p.event(firstID, p.cause, true, nil, placeholder, placeholder))
	}
	s := size()
	if s <= targetLineBytes {
		return
	}
	payload, name := p.payload, p.targetName
	if payload != nil {
		p.payload = jsonString("")
	}
	p.targetName = ""
	floor := size()
	p.payload, p.targetName = payload, name
	if floor > targetLineBytes {
		return
	}

	if p.payload != nil {
		full := string(p.payload)
		p.first = append(p.first, newTruncation("data", full, false))
		s = cutUntilFits(full, s, size, func(v string) { p.payload = jsonString(v) })
	}
	if s > targetLineBytes && p.targetName != "" {
		p.first = append(p.first, newTruncation("target.name", p.targetName, false))
		cutUntilFits(p.targetName, s, size, func(v string) { p.targetName = v })
	}
}

// cutUntilFits cuts value at rune boundaries, by the overflow measured in
// encoded bytes, until size reports a fit or nothing is left. set stores
// each cut. It returns the final size.
func cutUntilFits(value string, s int, size func() int, set func(string)) int {
	for {
		value = capEncoded(value, encodedLen(value)-(s-targetLineBytes))
		set(value)
		s = size()
		if s <= targetLineBytes || value == "" {
			return s
		}
	}
}

// jsonString returns s encoded as a JSON string.
func jsonString(s string) json.RawMessage {
	enc, _ := json.Marshal(s) // a string always encodes
	return enc
}

// runeEncodedLen returns an upper bound on the bytes a rune takes inside a
// JSON string.
func runeEncodedLen(r rune, size int) int {
	switch {
	case r == utf8.RuneError && size == 1:
		return 6 // invalid byte, rendered as \ufffd
	case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t':
		return 2
	case r < 0x20, r == '<', r == '>', r == '&', r == '\u2028', r == '\u2029':
		return 6
	default:
		return size
	}
}

// encodedLen returns an upper bound on the bytes s takes inside a JSON string.
func encodedLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		n += runeEncodedLen(r, size)
		i += size
	}
	return n
}

// capEncoded returns the longest prefix of s, cut at a rune boundary, whose
// JSON string encoding takes at most n bytes.
func capEncoded(s string, n int) string {
	used := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		used += runeEncodedLen(r, size)
		if used > n {
			return s[:i]
		}
		i += size
	}
	return s
}

// packState tracks what the event being filled already holds, so the size
// an item adds can be estimated without rendering the event.
type packState struct {
	items      []item
	size       int
	hasChanges bool
	hasHops    bool
	members    map[int]bool
}

// wrapperSlack covers the key, brackets and separators a list adds to an
// event the first time it appears there.
const wrapperSlack = 64

// estimate returns an upper bound on the bytes it adds to the event.
func (s *packState) estimate(p *plan, it item) int {
	n := 0
	switch it.kind {
	case itemChange:
		n = jsonLen(it.ch) + 1
		if !s.hasChanges {
			n += wrapperSlack
		}
	case itemAdded, itemRemoved:
		n = jsonLen(it.id) + 1
		if !s.members[it.change] {
			n += jsonLen(Change{kind: changeKindMembers, field: p.changeFields[it.change]}) + 1
			if !s.hasChanges {
				n += wrapperSlack
			}
		}
	case itemHop:
		n = jsonLen(it.hop) + 1
		if !s.hasHops {
			n += jsonLen(p.chain) + wrapperSlack
		}
	}
	for _, r := range it.records {
		n += jsonLen(r) + 1
	}
	return n + wrapperSlack/2
}

// tryAdd adds it to the event when it fits, using the estimate when that
// suffices and rendering the event otherwise.
func (s *packState) tryAdd(p *plan, it item, measure func([]item) int) bool {
	est := s.estimate(p, it)
	if s.size+est <= targetLineBytes {
		s.add(it, est)
		return true
	}
	trial := append(append([]item(nil), s.items...), it)
	if m := measure(trial); m <= targetLineBytes {
		s.add(it, est)
		s.size = m
		return true
	}
	return false
}

func (s *packState) add(it item, estimate int) {
	s.items = append(s.items, it)
	s.size += estimate
	switch it.kind {
	case itemChange:
		s.hasChanges = true
	case itemAdded, itemRemoved:
		s.hasChanges = true
		s.members[it.change] = true
	case itemHop:
		s.hasHops = true
	}
}

func jsonLen(v any) int {
	enc, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(enc)
}

// pack distributes the list entries over the first event and as many
// continuation events as needed, each within targetLineBytes. An entry that
// does not fit in an empty event has its values over maxFieldValueBytes cut.
// pack reports false when an entry does not fit even then in an empty
// continuation, because the fields every event repeats leave no room.
func (p *plan) pack(firstID string) ([][]item, bool) {
	var groups [][]item
	first := true
	measure := func(items []item) int {
		if first {
			return lineSize(p.event(firstID, p.cause, true, items, partPlaceholder, partPlaceholder))
		}
		return lineSize(p.event(firstID, firstID, false, items, partPlaceholder, partPlaceholder))
	}
	newState := func() *packState {
		return &packState{size: measure(nil), members: make(map[int]bool)}
	}
	state := newState()

	for i := 0; i < len(p.items); i++ {
		it := p.items[i]
		if state.tryAdd(p, it, measure) {
			continue
		}
		if len(state.items) == 0 {
			if state.tryAdd(p, p.cutItem(it), measure) {
				continue
			}
			if !first {
				return nil, false
			}
		}
		groups = append(groups, state.items)
		first = false
		state = newState()
		i-- // place the entry in the new continuation
	}
	return append(groups, state.items), true
}

// cutItem cuts each value of a list entry whose JSON encoding is over
// maxFieldValueBytes to that size. Shorter values, secret changes and
// delegation hops are never cut.
func (p *plan) cutItem(it item) item {
	it.records = append([]truncation(nil), it.records...)
	switch it.kind {
	case itemChange:
		if it.ch.kind != changeKindValue {
			return it
		}
		field := "changes." + it.ch.field + "."
		it.ch.before = capFieldValue(field+"before", it.ch.before, &it.records)
		it.ch.after = capFieldValue(field+"after", it.ch.after, &it.records)
	case itemAdded:
		it.id = capFieldValue("changes."+p.changeFields[it.change]+".added", it.id, &it.records)
	case itemRemoved:
		it.id = capFieldValue("changes."+p.changeFields[it.change]+".removed", it.id, &it.records)
	case itemHop:
		// Hop strings are already capped at MaxActorStringBytes.
	}
	return it
}

// capFieldValue cuts value to an encoding of at most maxFieldValueBytes,
// appending a truncation record for field when it was cut.
func capFieldValue(field, value string, records *[]truncation) string {
	cut := capEncoded(value, maxFieldValueBytes)
	if len(cut) < len(value) {
		*records = append(*records, newTruncation(field, value, false))
	}
	return cut
}

func sortTruncations(records []truncation) {
	slices.SortFunc(records, func(a, b truncation) int { return strings.Compare(a.Field, b.Field) })
}
