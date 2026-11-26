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
	sortTruncations(p.common)
	p.extra, p.first = componentExtra(in.extra)
	sortTruncations(p.first)

	p.changeFields = make([]string, len(in.changes))
	for i, c := range in.changes {
		p.changeFields[i] = c.field
		if c.kind != changeKindMembers || len(c.added)+len(c.removed) == 0 {
			p.items = append(p.items, item{kind: itemChange, change: i, ch: c})
			continue
		}
		for _, id := range c.added {
			p.items = append(p.items, item{kind: itemAdded, change: i, id: id})
		}
		for _, id := range c.removed {
			p.items = append(p.items, item{kind: itemRemoved, change: i, id: id})
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
	// When fields the builder never cuts already overflow an empty
	// continuation, splitting cannot bring any line under the limit and would
	// only repeat the oversized fields once per list entry. Return the single
	// event, best effort.
	if lineSize(p.event(firstID, firstID, false, nil, partPlaceholder, partPlaceholder)) > targetLineBytes {
		return []*AuditEvent{single()}
	}

	groups := p.pack(firstID)
	if len(groups) == 1 {
		return []*AuditEvent{single()}
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
// without list entries fits in targetLineBytes.
func (p *plan) fitHead(firstID string, placeholder int) {
	size := func() int {
		return lineSize(p.event(firstID, p.cause, true, nil, placeholder, placeholder))
	}
	s := size()
	if s > targetLineBytes && p.payload != nil {
		full := string(p.payload)
		p.first = append(p.first, newTruncation("data", full, false))
		cut := full
		for s > targetLineBytes && cut != "" {
			cut = capString(cut, len(cut)-(s-targetLineBytes))
			p.payload = jsonString(cut)
			s = size()
		}
		p.payload = jsonString(cut)
	}
	if s > targetLineBytes && p.targetName != "" {
		full := p.targetName
		p.first = append(p.first, newTruncation("target.name", full, false))
		for s > targetLineBytes && p.targetName != "" {
			p.targetName = capString(p.targetName, len(p.targetName)-(s-targetLineBytes))
			s = size()
		}
	}
}

// jsonString returns s encoded as a JSON string.
func jsonString(s string) json.RawMessage {
	enc, _ := json.Marshal(s) // a string always encodes
	return enc
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
// continuation events as needed, each within targetLineBytes. An entry
// that does not fit in an empty continuation is cut.
func (p *plan) pack(firstID string) [][]item {
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
		est := state.estimate(p, it)
		if state.size+est <= targetLineBytes {
			state.add(it, est)
			continue
		}
		trial := append(append([]item(nil), state.items...), it)
		if s := measure(trial); s <= targetLineBytes {
			state.add(it, est)
			state.size = s
			continue
		}
		if len(state.items) == 0 && !first {
			// Alone in an empty continuation and still too large.
			it = p.cutItem(it, func(it item) int { return measure([]item{it}) })
			state.add(it, 0)
			state.size = measure(state.items)
			continue
		}
		groups = append(groups, state.items)
		first = false
		state = newState()
		i-- // place the entry in the new continuation
	}
	return append(groups, state.items)
}

// cutItem cuts a list entry that does not fit in an event on its own. Each
// value over maxFieldValueBytes is cut to that size first; values are then
// cut further until the entry fits, or until there is nothing left to cut.
func (p *plan) cutItem(it item, size func(item) int) item {
	switch it.kind {
	case itemChange:
		if it.ch.kind != changeKindValue {
			return it
		}
		field := "changes." + it.ch.field + "."
		before := cutValue{field: field + "before", full: it.ch.before, cur: it.ch.before}
		after := cutValue{field: field + "after", full: it.ch.after, cur: it.ch.after}
		apply := func() {
			it.ch.before, it.ch.after = before.cur, after.cur
			it.records = append(before.record(), after.record()...)
		}
		before.cut(maxFieldValueBytes)
		after.cut(maxFieldValueBytes)
		apply()
		for s := size(it); s > targetLineBytes && (before.cur != "" || after.cur != ""); s = size(it) {
			longer := &before
			if len(after.cur) > len(before.cur) {
				longer = &after
			}
			longer.cut(len(longer.cur) - (s - targetLineBytes))
			apply()
		}
	case itemAdded, itemRemoved:
		field := "changes." + p.changeFields[it.change] + ".added"
		if it.kind == itemRemoved {
			field = "changes." + p.changeFields[it.change] + ".removed"
		}
		id := cutValue{field: field, full: it.id, cur: it.id}
		id.cut(maxFieldValueBytes)
		it.id, it.records = id.cur, id.record()
		for s := size(it); s > targetLineBytes && id.cur != ""; s = size(it) {
			id.cut(len(id.cur) - (s - targetLineBytes))
			it.id, it.records = id.cur, id.record()
		}
	case itemHop:
		// Hop strings are already capped at MaxActorStringBytes.
	}
	return it
}

// cutValue tracks one value being cut and its truncation record.
type cutValue struct {
	field string
	full  string
	cur   string
}

func (c *cutValue) cut(n int) {
	c.cur = capString(c.cur, n)
}

func (c *cutValue) record() []truncation {
	if len(c.cur) == len(c.full) {
		return nil
	}
	return []truncation{newTruncation(c.field, c.full, false)}
}

func sortTruncations(records []truncation) {
	slices.SortFunc(records, func(a, b truncation) int { return strings.Compare(a.Field, b.Field) })
}
