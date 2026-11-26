// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import "context"

// PrincipalKind classifies the actor of an audit event. It is written to the
// event's subjects under [SubjectKeyPrincipalKind].
type PrincipalKind string

// The principal kinds. Each has its own [Actor] constructor.
const (
	// PrincipalKindUser is a human caller authenticated by a token issuer.
	PrincipalKindUser PrincipalKind = "user"
	// PrincipalKindServiceAccount is a non-human caller with its own identity.
	PrincipalKindServiceAccount PrincipalKind = "service_account"
	// PrincipalKindSCIMIssuer is a SCIM provisioning client authenticated by a
	// static bearer token.
	PrincipalKindSCIMIssuer PrincipalKind = "scim_issuer"
	// PrincipalKindSystem is work that no caller started, such as a
	// boot-time job. Its user id is the fixed name of the runnable.
	PrincipalKindSystem PrincipalKind = "system"
	// PrincipalKindAnonymous marks an authentication refusal: there is no
	// verified caller, so the event has no user id.
	PrincipalKindAnonymous PrincipalKind = "anonymous"
)

// Subject keys that, with [SubjectKeyUser], [SubjectKeyUserID],
// [SubjectKeyClientName] and [SubjectKeyClientVersion], make up the actor in
// an event's subjects. The event builder writes them only from the [Actor];
// a [SubjectEnricher] can never set them.
const (
	// SubjectKeyPrincipalKind is the key for the actor's [PrincipalKind].
	SubjectKeyPrincipalKind = "principal_kind"
	// SubjectKeyIssuer is the key for the verified token issuer, or the SCIM
	// issuer id.
	SubjectKeyIssuer = "issuer"
	// SubjectKeyClientID is the key for the OAuth client the token was issued to.
	SubjectKeyClientID = "client_id"
	// SubjectKeyTokenFingerprint is the key for a keyed fingerprint of a static
	// bearer token. Never the token itself.
	SubjectKeyTokenFingerprint = "token_fingerprint"
)

// contractSubjectKeys are the subject keys the event builder writes from the
// [Actor]. A subject enricher can never set one of them.
var contractSubjectKeys = map[string]struct{}{
	SubjectKeyUserID:           {},
	SubjectKeyPrincipalKind:    {},
	SubjectKeyUser:             {},
	SubjectKeyIssuer:           {},
	SubjectKeyClientID:         {},
	SubjectKeyClientName:       {},
	SubjectKeyClientVersion:    {},
	SubjectKeyTokenFingerprint: {},
}

// Actor is the verified caller of an audited action. The authentication
// middleware that verifies a caller stores one Actor in the request context
// with [ContextWithActor], and the [EventBuilder] writes every actor key of
// the event's subjects from it, so call sites never pass the actor.
//
// Build an Actor with the constructor for its principal kind. The zero Actor
// is not valid and is treated as no actor.
type Actor struct {
	kind             PrincipalKind
	userID           string
	issuer           string
	displayName      string
	clientID         string
	clientName       string
	clientVersion    string
	tokenFingerprint string
}

// ActorOption sets an optional field of an [Actor].
type ActorOption func(*Actor)

// WithActorIssuer sets the verified token issuer. The user and SCIM issuer
// constructors already set it.
func WithActorIssuer(issuer string) ActorOption {
	return func(a *Actor) { a.issuer = issuer }
}

// WithDisplayName sets a display name for the actor. It is informational
// and must never be used to match an actor; use the user id for that.
func WithDisplayName(name string) ActorOption {
	return func(a *Actor) { a.displayName = name }
}

// WithClientID sets the OAuth client the caller's token was issued to.
func WithClientID(clientID string) ActorOption {
	return func(a *Actor) { a.clientID = clientID }
}

// WithClientInfo sets the name and version of the client software the caller
// used, such as an MCP client.
func WithClientInfo(name, version string) ActorOption {
	return func(a *Actor) {
		a.clientName = name
		a.clientVersion = version
	}
}

// WithTokenFingerprint sets a keyed fingerprint (for example HMAC-SHA-256
// under a key the service holds) of the static bearer token the caller
// presented. Pass a fingerprint, never the token: an unkeyed hash of a weak
// token can be reversed offline by anyone who can read the audit trail.
func WithTokenFingerprint(fingerprint string) ActorOption {
	return func(a *Actor) { a.tokenFingerprint = fingerprint }
}

func newActor(kind PrincipalKind, userID string, opts []ActorOption) Actor {
	a := Actor{kind: kind, userID: userID}
	for _, opt := range opts {
		opt(&a)
	}
	return a
}

// NewUserActor returns a human actor. userID is the stable principal id the
// issuer assigns to the person, not a mutable attribute such as an email, so
// the audit trail still answers "what did this person do" after a rename.
func NewUserActor(userID, issuer string, opts ...ActorOption) Actor {
	return newActor(PrincipalKindUser, userID, append([]ActorOption{WithActorIssuer(issuer)}, opts...))
}

// NewServiceAccountActor returns a non-human actor identified by its stable id.
func NewServiceAccountActor(id string, opts ...ActorOption) Actor {
	return newActor(PrincipalKindServiceAccount, id, opts)
}

// NewSCIMIssuerActor returns a SCIM provisioning client. The issuer id is both
// its user id and its issuer. tokenFingerprint is a keyed fingerprint of the
// bearer token it presented; see [WithTokenFingerprint].
func NewSCIMIssuerActor(issuerID, tokenFingerprint string, opts ...ActorOption) Actor {
	base := []ActorOption{WithActorIssuer(issuerID), WithTokenFingerprint(tokenFingerprint)}
	return newActor(PrincipalKindSCIMIssuer, issuerID, append(base, opts...))
}

// NewSystemActor returns the actor for work that no caller started, such as a
// boot-time job. runnable is the fixed name of that work, for example
// "jobs.cleanup". Only such work should build a system actor, never a request
// handler.
func NewSystemActor(runnable string, opts ...ActorOption) Actor {
	return newActor(PrincipalKindSystem, runnable, opts)
}

// NewAnonymousActor returns the actor for an authentication refusal, where no
// caller was verified. It has no user id, and an event built for it must have
// the outcome [OutcomeDenied] or, when the service failed before it could
// verify the caller, [OutcomeError]. Only an authentication refusal path
// should build one. The options may still record what the caller presented,
// such as the issuer or a token fingerprint.
func NewAnonymousActor(opts ...ActorOption) Actor {
	return newActor(PrincipalKindAnonymous, "", opts)
}

// Kind returns the actor's principal kind, or "" for the zero Actor.
func (a Actor) Kind() PrincipalKind {
	return a.kind
}

// UserID returns the actor's user id, which is empty for an anonymous actor.
func (a Actor) UserID() string {
	return a.userID
}

// valid reports whether a is a usable actor: a known kind, and a user id for
// every kind except anonymous.
func (a Actor) valid() bool {
	switch a.kind {
	case PrincipalKindAnonymous:
		return true
	case PrincipalKindUser, PrincipalKindServiceAccount, PrincipalKindSCIMIssuer, PrincipalKindSystem:
		return a.userID != ""
	default:
		return false
	}
}

// subjects returns the actor's subject keys, uncapped. Empty optional fields
// are omitted.
func (a Actor) subjects() map[string]string {
	s := map[string]string{SubjectKeyPrincipalKind: string(a.kind)}
	set := func(key, value string) {
		if value != "" {
			s[key] = value
		}
	}
	if a.kind != PrincipalKindAnonymous {
		set(SubjectKeyUserID, a.userID)
	}
	set(SubjectKeyIssuer, a.issuer)
	set(SubjectKeyUser, a.displayName)
	set(SubjectKeyClientID, a.clientID)
	set(SubjectKeyClientName, a.clientName)
	set(SubjectKeyClientVersion, a.clientVersion)
	set(SubjectKeyTokenFingerprint, a.tokenFingerprint)
	return s
}

type actorContextKey struct{}

type requestIDContextKey struct{}

// ContextWithActor returns a copy of ctx that carries actor. The
// authentication middleware calls it once it has verified the caller, and a
// runnable calls it with a [NewSystemActor] before it writes.
func ContextWithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorContextKey{}, actor)
}

// ActorFromContext returns the actor stored by [ContextWithActor]. It reports
// false when ctx carries no actor, or carries one that is not valid (the zero
// Actor, or a non-anonymous actor with no user id).
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorContextKey{}).(Actor)
	if !ok || !a.valid() {
		return Actor{}, false
	}
	return a, true
}

// ContextWithRequestID returns a copy of ctx that carries the request id. The
// component generates the id when the request arrives; it must never reuse an
// id the client sent, because a client can choose it. The [EventBuilder]
// copies it to metadata.extra.request_id.
func ContextWithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

// RequestIDFromContext returns the request id stored by
// [ContextWithRequestID]. It reports false when there is none or it is empty.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(requestIDContextKey{}).(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}
