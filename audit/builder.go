// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// SchemaVersion is the value of metadata.extra.schema_version on every event
// the [EventBuilder] builds. It increases only on a breaking change to the
// keys the builder writes.
const SchemaVersion = 1

// TargetKeyID is the key for the target's stable id in the target map.
const TargetKeyID = "id"

// Keys the [EventBuilder] writes to metadata.extra. A component key passed
// with [WithExtra] that uses one of these names is dropped.
const (
	// MetadataExtraKeySchemaVersion holds [SchemaVersion].
	MetadataExtraKeySchemaVersion = "schema_version"
	// MetadataExtraKeyReason holds the bounded reason token set with [WithReason].
	MetadataExtraKeyReason = "reason"
	// MetadataExtraKeyRequestID holds the request id from [ContextWithRequestID].
	MetadataExtraKeyRequestID = "request_id"
	// MetadataExtraKeyCause holds the audit id of the event that caused this
	// one: the caller's [WithCause] on a first event, or the first event's
	// audit id on a continuation event.
	MetadataExtraKeyCause = "cause"
	// MetadataExtraKeyChanges holds the [Change] list set with [WithChanges].
	MetadataExtraKeyChanges = "changes"
	// MetadataExtraKeyTruncated lists each value the builder cut or dropped,
	// with its field name, original length and SHA-256 digest.
	MetadataExtraKeyTruncated = "truncated"
	// MetadataExtraKeyPart is the 1-based position of an event among the
	// events one [EventBuilder.NewEvent] call returned, when it returned more
	// than one.
	MetadataExtraKeyPart = "part"
	// MetadataExtraKeyParts is the number of events one
	// [EventBuilder.NewEvent] call returned, when it returned more than one.
	MetadataExtraKeyParts = "parts"
	// MetadataExtraKeySuppressed holds the number of refusals a refusal
	// summary event stands for. The builder never sets it; it is reserved so
	// a component key cannot claim it.
	MetadataExtraKeySuppressed = "suppressed"
)

// reservedExtraKeys are the metadata.extra keys a component cannot set.
var reservedExtraKeys = map[string]struct{}{
	MetadataExtraKeySchemaVersion: {},
	MetadataExtraKeyReason:        {},
	MetadataExtraKeyRequestID:     {},
	MetadataExtraKeyCause:         {},
	MetadataExtraKeyChanges:       {},
	MetadataExtraKeyTruncated:     {},
	MetadataExtraKeyPart:          {},
	MetadataExtraKeyParts:         {},
	MetadataExtraKeySuppressed:    {},
}

const (
	// MaxLineBytes is the largest audit line, trailing newline included, that
	// the [EventBuilder] produces. Container runtimes split longer stdout
	// lines into partial records, which breaks the event for a collector that
	// does not join them again.
	MaxLineBytes = 16384

	// MaxActorStringBytes caps each actor string, each subject enricher value
	// and each component metadata.extra value. Actor strings come from token
	// claims with no length limit.
	MaxActorStringBytes = 256

	// MaxReasonBytes caps the reason token.
	MaxReasonBytes = 64

	// maxExtraKeys caps the keys a subject enricher or a component adds.
	maxExtraKeys = 16

	// maxExtraKeyBytes caps the length of a key a subject enricher or a
	// component adds. A longer key is dropped.
	maxExtraKeyBytes = 64

	// Byte budgets for the keys and values each source adds. Together with
	// the caps above they keep the fields every event repeats well under
	// targetLineBytes, so list entries always have room. Keys past a budget,
	// in sorted order, are dropped.
	enricherBudgetBytes    = 2048
	sourceExtraBudgetBytes = 512
	componentBudgetBytes   = 2048

	// maxFieldValueBytes is the size above which a single change value or
	// member id is cut when it does not fit in an event on its own.
	maxFieldValueBytes = 4096

	// targetLineBytes is the size the builder packs events to. It leaves
	// headroom under MaxLineBytes for the record time and level, which are
	// only known when the event is logged.
	targetLineBytes = 16000
)

// EventErrorsMetricName is the name of the counter [EventBuilder.NewEvent]
// increments each time it refuses to build an event. Its one attribute,
// "reason", is one of no_actor, invalid_outcome, invalid_reason and
// anonymous_invalid_outcome. Every increment is a defect in the calling code.
const EventErrorsMetricName = "stacklok.audit.event.errors"

// Values of the "reason" attribute on the [EventErrorsMetricName] counter.
const (
	eventErrorNoActor                 = "no_actor"
	eventErrorInvalidOutcome          = "invalid_outcome"
	eventErrorInvalidReason           = "invalid_reason"
	eventErrorAnonymousInvalidOutcome = "anonymous_invalid_outcome"
)

// Errors returned by [EventBuilder.NewEvent]. Each is also counted on the
// [EventErrorsMetricName] counter.
var (
	// ErrNoActor means the context carries no valid [Actor]. Every audited
	// request must have one; set it with [ContextWithActor].
	ErrNoActor = errors.New("audit: no actor in context")
	// ErrInvalidOutcome means the outcome is not one of [OutcomeSuccess],
	// [OutcomeFailure], [OutcomeError] and [OutcomeDenied].
	ErrInvalidOutcome = errors.New("audit: outcome is not success, failure, error or denied")
	// ErrInvalidReason means the reason is not a lower snake case token of at
	// most [MaxReasonBytes] bytes.
	ErrInvalidReason = errors.New("audit: reason is not a bounded lower snake case token")
	// ErrAnonymousOutcome means an anonymous actor was given an outcome
	// other than [OutcomeDenied] or [OutcomeError].
	ErrAnonymousOutcome = errors.New("audit: anonymous actor outcome must be denied or error")
)

var reasonPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// IsValidOutcome reports whether outcome is in the closed outcome set.
func IsValidOutcome(outcome string) bool {
	switch outcome {
	case OutcomeSuccess, OutcomeFailure, OutcomeError, OutcomeDenied:
		return true
	default:
		return false
	}
}

// IsValidReason reports whether reason is a lower snake case token of at
// most [MaxReasonBytes] bytes, such as "not_found".
func IsValidReason(reason string) bool {
	return len(reason) <= MaxReasonBytes && reasonPattern.MatchString(reason)
}

// SubjectEnricher returns extra subjects keys for an event, derived from the
// request context. It can never set or override an actor key: any key it
// returns that the builder writes from the [Actor] is dropped, whether or not
// the actor sets it.
type SubjectEnricher func(ctx context.Context) map[string]string

// Target names the resource an event acted on.
type Target struct {
	// Type is the kind of resource, such as "widget".
	Type string
	// ID is the resource's stable id. An id longer than
	// [MaxActorStringBytes] is cut and recorded in metadata.extra.truncated.
	ID string
	// Name is the resource's name, when it has one. It is omitted when empty.
	Name string
}

// BuilderOption configures [NewEventBuilder].
type BuilderOption func(*builderConfig)

type builderConfig struct {
	enricher      SubjectEnricher
	meterProvider metric.MeterProvider
	sourceName    string
}

// WithSubjectEnricher sets a [SubjectEnricher] that adds component keys to
// every event's subjects.
func WithSubjectEnricher(enricher SubjectEnricher) BuilderOption {
	return func(c *builderConfig) { c.enricher = enricher }
}

// WithBuilderMeterProvider sets the meter provider used for the
// [EventErrorsMetricName] counter. The default is the global provider
// returned by [otel.GetMeterProvider]. A nil provider keeps the default.
func WithBuilderMeterProvider(mp metric.MeterProvider) BuilderOption {
	return func(c *builderConfig) {
		if mp != nil {
			c.meterProvider = mp
		}
	}
}

// WithSourceName sets the value of the default event source, whose type is
// [SourceTypeLocal]. The default is the host name, which in a Kubernetes pod
// is the pod name.
func WithSourceName(name string) BuilderOption {
	return func(c *builderConfig) { c.sourceName = name }
}

// EventBuilder builds audit events that carry the actor from the request
// context and stay within [MaxLineBytes] per line. Create one per component
// with [NewEventBuilder]; it is safe for concurrent use.
type EventBuilder struct {
	component string
	enricher  SubjectEnricher
	source    EventSource
	errors    metric.Int64Counter
}

// NewEventBuilder returns an [EventBuilder] for component, the name of the
// emitting service, such as "example-service".
func NewEventBuilder(component string, opts ...BuilderOption) *EventBuilder {
	cfg := builderConfig{}
	if host, err := os.Hostname(); err == nil {
		cfg.sourceName = host
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.meterProvider == nil {
		cfg.meterProvider = otel.GetMeterProvider()
	}
	counter, err := cfg.meterProvider.Meter(meterName).Int64Counter(
		EventErrorsMetricName,
		metric.WithDescription("Number of audit events the event builder refused to build."),
		metric.WithUnit("{event}"),
	)
	if err != nil {
		// See newAuditSink: never let a metrics problem block auditing.
		counter, _ = noop.NewMeterProvider().Meter(meterName).Int64Counter(EventErrorsMetricName)
	}
	return &EventBuilder{
		component: component,
		enricher:  cfg.enricher,
		source:    EventSource{Type: SourceTypeLocal, Value: cfg.sourceName},
		errors:    counter,
	}
}

// EventOption sets an optional input of [EventBuilder.NewEvent].
type EventOption func(*eventInput)

type eventInput struct {
	reason  string
	changes []Change
	cause   string
	chain   *DelegationChain
	payload json.RawMessage
	source  *EventSource
	extra   map[string]any
}

// WithReason sets metadata.extra.reason, a bounded lower snake case token
// that details the outcome, such as "conflict" or "not_found". It is never
// free text, an error message, or a value the caller controls.
func WithReason(reason string) EventOption {
	return func(in *eventInput) { in.reason = reason }
}

// WithChanges records the fields the action changed, in metadata.extra.changes.
// Repeated calls append.
func WithChanges(changes ...Change) EventOption {
	return func(in *eventInput) { in.changes = append(in.changes, changes...) }
}

// WithCause sets metadata.extra.cause to the audit id of the event that
// caused this one, such as the deletion that cascaded to this resource.
func WithCause(auditID string) EventOption {
	return func(in *eventInput) { in.cause = auditID }
}

// WithDelegation attaches the actor's RFC 8693 delegation chain. A chain too
// long for one event is split across continuation events.
func WithDelegation(chain *DelegationChain) EventOption {
	return func(in *eventInput) { in.chain = chain }
}

// WithPayload attaches a captured request or response payload as the event's
// data. Record a payload only when the operator has turned payload capture
// on. It is the first value cut when an event is too large, and is then
// replaced by a JSON string holding its leading bytes.
func WithPayload(payload json.RawMessage) EventOption {
	return func(in *eventInput) { in.payload = payload }
}

// WithSource overrides the default source, which is [SourceTypeLocal] with
// the builder's source name. A component that records a client network
// address should use the connection's remote address only, never a
// forwarding header a client can set.
func WithSource(source EventSource) EventOption {
	return func(in *eventInput) {
		in.source = &source
	}
}

// WithExtra adds component keys to metadata.extra. At most 16 are kept, in
// sorted key order and within a 2 KiB budget; each key is at most 64 bytes
// and each value is capped at [MaxActorStringBytes]. A key
// the builder writes itself, such as "reason" or "request_id", is dropped.
// Repeated calls merge.
func WithExtra(extra map[string]any) EventOption {
	return func(in *eventInput) {
		if in.extra == nil {
			in.extra = make(map[string]any, len(extra))
		}
		for k, v := range extra {
			in.extra[k] = v
		}
	}
}

// NewEvent builds the audit event for an action, with the actor taken from
// ctx. It returns one event, or, when the event's lists do not fit in one
// line of [MaxLineBytes], the first event followed by continuation events.
// Log each returned event with [AuditEvent.LogTo] at [LevelAudit].
//
// It returns an error and no event, and increments the
// [EventErrorsMetricName] counter, when ctx has no actor ([ErrNoActor]), the
// outcome is not in the closed set ([ErrInvalidOutcome]), the reason is not a
// bounded token ([ErrInvalidReason]), or an anonymous actor has an outcome
// other than denied or error ([ErrAnonymousOutcome]).
func (b *EventBuilder) NewEvent(
	ctx context.Context,
	eventType string,
	target Target,
	outcome string,
	opts ...EventOption,
) ([]*AuditEvent, error) {
	in := eventInput{}
	for _, opt := range opts {
		opt(&in)
	}

	actor, ok := ActorFromContext(ctx)
	switch {
	case !ok:
		return nil, b.refuse(ctx, eventErrorNoActor, ErrNoActor)
	case !IsValidOutcome(outcome):
		return nil, b.refuse(ctx, eventErrorInvalidOutcome, ErrInvalidOutcome)
	case in.reason != "" && !IsValidReason(in.reason):
		return nil, b.refuse(ctx, eventErrorInvalidReason, ErrInvalidReason)
	case actor.kind == PrincipalKindAnonymous && outcome != OutcomeDenied && outcome != OutcomeError:
		return nil, b.refuse(ctx, eventErrorAnonymousInvalidOutcome, ErrAnonymousOutcome)
	}

	p := b.newPlan(ctx, actor, eventType, target, outcome, &in)
	return p.build(), nil
}

func (b *EventBuilder) refuse(ctx context.Context, reason string, err error) error {
	b.errors.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", reason)))
	return err
}

// truncation records one value the builder cut or dropped.
//
// A summary record, which stands for keys dropped past the first
// maxDropRecords of one source, has the source as its field, the number of
// keys it stands for in Count, and the length and digest of their sorted
// names joined by newlines.
type truncation struct {
	Field   string `json:"field"`
	Length  int    `json:"length"`
	SHA256  string `json:"sha256"`
	Dropped bool   `json:"dropped,omitempty"`
	Count   int    `json:"count,omitempty"`
}

// maxDropRecords caps the individual records for keys dropped from one
// source, so the records cannot grow the event without bound.
const maxDropRecords = 4

// dropRecorder records the keys dropped from one source: the first
// maxDropRecords individually, then one summary record for the rest.
type dropRecorder struct {
	prefix  string
	records *[]truncation
	n       int
	rest    []string
}

func (d *dropRecorder) drop(key, value string) {
	if d.n < maxDropRecords {
		*d.records = append(*d.records, newTruncation(d.prefix+"."+capString(key, maxExtraKeyBytes), value, true))
		d.n++
		return
	}
	d.rest = append(d.rest, key)
}

// flush adds the summary record, if any keys are left over. Keys are
// dropped in sorted order, so the summary is deterministic.
func (d *dropRecorder) flush() {
	if len(d.rest) == 0 {
		return
	}
	summary := newTruncation(d.prefix, strings.Join(d.rest, "\n"), true)
	summary.Count = len(d.rest)
	*d.records = append(*d.records, summary)
}

func newTruncation(field, full string, dropped bool) truncation {
	sum := sha256.Sum256([]byte(full))
	return truncation{
		Field:   capString(field, MaxActorStringBytes),
		Length:  len(full),
		SHA256:  hex.EncodeToString(sum[:]),
		Dropped: dropped,
	}
}

// capString returns s cut to at most n bytes at a UTF-8 rune boundary.
func capString(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// capValue returns value capped at MaxActorStringBytes, appending a
// truncation record for field when it was cut.
func capValue(field, value string, records *[]truncation) string {
	cut := capString(value, MaxActorStringBytes)
	if len(cut) < len(value) {
		*records = append(*records, newTruncation(field, value, false))
	}
	return cut
}

// subjects returns the event's subjects: the actor's keys, each capped, then
// the enricher's non-actor keys, bounded in number and each capped.
func (b *EventBuilder) subjects(ctx context.Context, actor Actor) (map[string]string, []truncation) {
	var records []truncation
	out := make(map[string]string)
	for k, v := range actor.subjects() {
		out[k] = capValue("subjects."+k, v, &records)
	}
	if b.enricher != nil {
		enriched := b.enricher(ctx)
		values := make(map[string]any, len(enriched))
		for k, v := range enriched {
			values[k] = v
		}
		kept, enricherRecords := boundedExtra("subjects", contractSubjectKeys, enricherBudgetBytes, values)
		for k, v := range kept {
			out[k] = v.(string) // string in, string out
		}
		records = append(records, enricherRecords...)
	}
	return out, records
}

// boundedExtra bounds a map of keys written under prefix, such as
// metadata.extra. Reserved keys are dropped silently. Keys are then taken in
// sorted order: a key longer than maxExtraKeyBytes, a value that cannot be
// encoded, a key past the first maxExtraKeys, or a key whose bytes would take
// the source past budget is dropped. Each kept value is capped at
// MaxActorStringBytes.
func boundedExtra(
	prefix string, reserved map[string]struct{}, budget int, extra map[string]any,
) (map[string]any, []truncation) {
	var records []truncation
	keys := make([]string, 0, len(extra))
	for k := range extra {
		if _, isReserved := reserved[k]; !isReserved && k != "" {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sort.Strings(keys)
	out := make(map[string]any, min(len(keys), maxExtraKeys))
	drops := dropRecorder{prefix: prefix, records: &records}
	used := 0
	for _, k := range keys {
		v := extra[k]
		enc, encodable := encodeExtraValue(v)
		if len(out) >= maxExtraKeys || len(k) > maxExtraKeyBytes || !encodable {
			drops.drop(k, enc)
			continue
		}
		value, cost, cut := boundValue(v, enc)
		if used+len(k)+cost > budget {
			drops.drop(k, enc)
			continue
		}
		used += len(k) + cost
		out[k] = value
		if cut {
			records = append(records, newTruncation(prefix+"."+k, enc, false))
		}
	}
	drops.flush()
	return out, records
}

// boundValue returns v capped at MaxActorStringBytes, the bytes it takes,
// and whether it was cut. enc is v's encoding from encodeExtraValue. A
// composite value whose encoding fits is kept as is; one that does not is
// replaced by its cut encoding.
func boundValue(v any, enc string) (any, int, bool) {
	switch tv := v.(type) {
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v, len(enc), false
	case string:
		cut := capString(tv, MaxActorStringBytes)
		return cut, len(cut), len(cut) < len(tv)
	default:
		if len(enc) <= MaxActorStringBytes {
			return v, len(enc), false
		}
		cut := capString(enc, MaxActorStringBytes)
		return cut, len(cut), true
	}
}

// encodeExtraValue returns v itself when it is a string and its JSON
// encoding otherwise. It reports false when v cannot be encoded.
func encodeExtraValue(v any) (string, bool) {
	if s, ok := v.(string); ok {
		return s, true
	}
	enc, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(enc), true
}
