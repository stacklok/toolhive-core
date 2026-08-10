// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
	"unicode"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/stacklok/toolhive-core/networking"
	httpvalidation "github.com/stacklok/toolhive-core/validation/http"
)

const (
	// defaultLeeway is the clock-skew tolerance applied to exp/nbf/iat when
	// Config.Leeway is zero.
	defaultLeeway = 60 * time.Second
	// maxLeeway is the largest accepted Config.Leeway. A tolerance beyond
	// this stops being "skew" and starts extending token lifetimes.
	maxLeeway = 2 * time.Minute
	// maxAudienceLength bounds a single Config.Audiences entry. Audiences are
	// identifiers, not documents; 1 KiB is far above any real value.
	maxAudienceLength = 1 << 10
	// maxResponseBody caps discovery and JWKS response bodies. jwx reads the
	// body itself (up to ~1GB); 1 MiB is generous for any legitimate JWKS or
	// discovery document.
	maxResponseBody = 1 << 20
	// jwksRefreshInterval is the pinned background refresh cadence for cached
	// JWKS key material. Pinning it prevents the issuer's Cache-Control/Expires
	// headers from controlling how long key material is trusted locally.
	jwksRefreshInterval = 15 * time.Minute
	// maxTokenLength bounds the bearer-token length accepted by Validate and
	// ParseBearer.
	maxTokenLength = 16 << 10

	// defaultHTTPTimeout bounds each discovery/JWKS fetch made by the
	// default HTTP client.
	defaultHTTPTimeout = 15 * time.Second
	// constructionTimeout bounds the per-operation network I/O performed
	// during NewValidator (Step 2 Register fetch, Step 3 discovery) so a
	// caller passing context.Background() cannot hang construction
	// indefinitely. It bounds ONLY those fetches — the JWKS cache itself is
	// bound to the validator's lifetime context, never to this timeout.
	constructionTimeout = 30 * time.Second
)

// schemeHTTPS and schemeHTTP are compared against parsed URL schemes.
// validateHTTPSURI treats these as the only two acceptable schemes — an
// allowlist, not a "not https" exclusion — so an unrelated scheme (ftp, file,
// gopher) is always rejected regardless of InsecureAllowHTTP.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// Config holds the trusted issuer/audience policy and fetch behavior for a
// Validator. A Config is validated eagerly by NewValidator so that a typo is
// a startup failure, not a 401 on every request.
type Config struct {
	// Issuer is the expected iss claim value. When JWKSURL is empty it is
	// also the base for OIDC discovery ({Issuer}/.well-known/openid-configuration).
	// Must be an https URI unless InsecureAllowHTTP is set.
	//
	// At least one of Issuer or JWKSURL is required. Leaving Issuer EMPTY
	// (only legal alongside an explicit JWKSURL) DISABLES iss verification
	// entirely: any issuer that can present a key from the configured JWKS is
	// accepted. Only do this when the JWKS endpoint itself is the trust
	// boundary.
	Issuer string

	// Audiences lists acceptable aud claim values; a token is accepted when
	// ANY of its aud values matches ANY entry here.
	//
	// Each entry is compared byte-exact against the token's aud values and is
	// validated only as a bounded, control-character-free string: RFC 7519
	// §4.1.3 types aud as StringOrURI, so bare identifiers (an OAuth
	// client_id) and opaque GUIDs (Entra ID) are conformant and accepted.
	//
	// Required and non-empty unless AllowAnyAudience is set.
	Audiences []string

	// AllowAnyAudience disables audience verification. It exists so a
	// deployment with no audience policy can be expressed explicitly rather
	// than by leaving Audiences unset, since a silently absent audience check
	// is how confused-deputy bugs reach production: any token the issuer minted
	// for ANY relying party is accepted by this resource server.
	//
	// Setting it together with a non-empty Audiences is an error, so the two
	// cannot silently disagree.
	AllowAnyAudience bool

	// JWKSURL, when set, points directly at the JWKS endpoint and skips OIDC
	// discovery. Optional. Must be an https URI unless InsecureAllowHTTP is
	// set.
	JWKSURL string

	// Leeway is the clock-skew tolerance applied to exp/nbf/iat. Zero uses
	// the default of 60s; negative is an error; values above 2m are an
	// error.
	Leeway time.Duration

	// DisableLeeway expresses zero clock-skew tolerance explicitly, since
	// Leeway==0 otherwise means "use the 60s default" and so cannot itself
	// express "none" (see Leeway). Mirrors the AllowAnyAudience explicit-opt-out
	// style: some deployments (matching ToolHive, which rejects exactly at exp)
	// need no tolerance at all.
	//
	// Setting it together with a non-zero Leeway is an error, so the two cannot
	// silently disagree about which policy applies.
	DisableLeeway bool

	// MaxJWKSStaleness bounds how long cached JWKS key material stays trusted
	// without a confirmed successful fetch. Negative is an error.
	//
	// Zero DISABLES the bound, and is the default. The bound exists because the
	// cache keeps serving its last good key set after every failed refresh, so a
	// key revoked at the IdP stays trusted for as long as the endpoint is
	// unreachable — the trust window equals the outage length.
	//
	// Enabling it trades availability for that bound: once exceeded, validation
	// fails with CodeUnavailable/ReasonKeysStale, so a prolonged IdP outage
	// becomes an authentication outage instead of an invisible one. Pick a value
	// that reflects how long you are willing to honour a revoked key; hours
	// rather than minutes is usually the right order of magnitude.
	//
	// Freshness is self-correcting rather than schedule-based: when the bound is
	// exceeded the validator attempts a refresh before rejecting anything, so a
	// healthy endpoint never trips it regardless of when the background refresh
	// last ran. It applies only to JWKS material — keys from a KeyProvider are
	// resolved in-process and are never considered stale.
	MaxJWKSStaleness time.Duration

	// AcceptedTokenTypes, when non-empty, requires the token's `typ` header to
	// match one of these media types. Comparison is case-insensitive and an
	// `application/` prefix is optional on both sides (RFC 7515 §4.1.9), so
	// "at+jwt" matches a token carrying "application/at+JWT".
	//
	// Empty (the default) accepts any `typ`, including none. It cannot default
	// to requiring RFC 9068's "at+jwt": that is a SHOULD, and many IdPs emit
	// "JWT" or omit the header entirely, so a default would reject conformant
	// tokens.
	//
	// This guards against ID-token substitution — an ID token sharing the
	// issuer, audience, subject and expiry of an access token. Note the AUDIENCE
	// check is the primary defence there, since an ID token's aud is the
	// client_id rather than the resource: this matters most when
	// AllowAnyAudience is set, or when a deployment uses its client_id as the
	// resource audience, because in those cases the audience check cannot tell
	// the two kinds of token apart.
	AcceptedTokenTypes []string

	// MaxTokenLifetime rejects tokens whose exp-iat span exceeds it, when both
	// claims are present. Negative is an error.
	//
	// Zero DISABLES the check, and is the default: a resource server that
	// accepts long-lived tokens today (service-account credentials commonly
	// outlive a day) must not start rejecting them merely by adopting this
	// package. Set it explicitly to opt into a lifetime bound.
	MaxTokenLifetime time.Duration

	// HTTPClient is used for discovery and JWKS fetches. Leave it nil unless you
	// need something the default cannot express: the default is built by
	// toolhive-core's networking package and is secure by default (private-IP
	// dial guard, 15s timeout, redirects refused, 1 MiB body cap).
	//
	// IMPORTANT — a supplied client OPTS OUT of the address-level SSRF guard.
	// That guard lives in the transport's DialContext, which this package cannot
	// retrofit onto a client it did not build; AllowPrivateIP and CACertPath are
	// likewise ignored. Build your client with
	// networking.NewHttpClientBuilder() (or install
	// networking.NewPrivateIPBlockingDialContext yourself) or you will have a
	// weaker configuration than the default.
	//
	// What IS still enforced for a supplied client: the 1 MiB response-body cap
	// (its Transport is wrapped), plus redirect refusal and the 15s timeout when
	// the caller left CheckRedirect / Timeout unset — so a bare &http.Client{}
	// cannot silently drop them. Explicit caller values are preserved.
	//
	// To attach a bearer token to the OUTBOUND JWKS/discovery request (an IdP
	// whose JWKS endpoint is itself gated), supply a client whose Transport
	// injects the Authorization header. That RoundTripper must be the innermost
	// one — this package wraps whatever it is given in its body-capping
	// transport, so set it as your client's Transport and let the wrapping
	// happen around it.
	//
	// If your IdP legitimately redirects its discovery or JWKS endpoint, set
	// JWKSURL to the final target rather than relaxing the redirect policy.
	HTTPClient *http.Client

	// InsecureAllowHTTP permits http:// Issuer and JWKSURL values. It exists
	// for development and test environments only; never set it in
	// production.
	InsecureAllowHTTP bool

	// AllowPrivateIP permits discovery and JWKS fetches to reach private,
	// loopback, and link-local addresses. It defaults to FALSE, which is what
	// blocks a jwks_uri resolving to cloud instance metadata
	// (169.254.169.254) or an in-cluster address.
	//
	// The check runs on the resolved address at dial time, so it also defends
	// against DNS rebinding and re-applies per redirect hop. Set it only for an
	// issuer that legitimately lives on a private network — an in-cluster OIDC
	// provider, or a test server on localhost.
	//
	// It applies ONLY to the default client. A caller-supplied HTTPClient brings
	// its own dial policy; see that field.
	AllowPrivateIP bool

	// CACertPath optionally points at a PEM CA bundle used to verify the
	// discovery and JWKS endpoints, for an issuer fronted by a private CA.
	//
	// It applies ONLY to the default client, for the same reason as
	// AllowPrivateIP.
	CACertPath string

	// AuthTokenFile optionally points at a file containing a bearer token to
	// attach to the OUTBOUND discovery and JWKS requests, for an IdP whose own
	// endpoints are gated behind auth (mirrors ToolHive's
	// --jwks-auth-token-file). The networking package re-reads the file per
	// request, so a rotated token is picked up without restarting the
	// validator.
	//
	// It applies ONLY to the default client, for the same reason as
	// AllowPrivateIP and CACertPath: it is implemented by networking's HTTP
	// client builder, which cannot be retrofitted onto a caller-supplied
	// HTTPClient.
	AuthTokenFile string

	// KeyProvider optionally supplies verification keys in-process, for an
	// embedded issuer. It is consulted BEFORE the JWKS cache on every
	// validation; a miss falls through to JWKS when one is configured.
	//
	// Setting it also relaxes construction, because an embedded issuer's JWKS
	// endpoint is characteristically not reachable at the moment the Validator
	// is built:
	//
	//   - OIDC discovery failure becomes non-fatal.
	//   - The first JWKS fetch is no longer required to succeed; key material
	//     is fetched lazily by the background refresh instead.
	//
	// Until that first fetch lands, a token whose kid the provider does not
	// offer fails with CodeUnavailable/ReasonKeysUnavailable rather than being
	// rejected as invalid — the verifier could not make a determination.
	//
	// With no KeyProvider, construction stays fail-closed: discovery and the
	// first JWKS fetch must both succeed or NewValidator returns an error.
	KeyProvider KeyProvider
}

// Validator verifies inbound JWT bearer tokens against the configured issuer
// and audience policy and the issuer's JWKS key material.
//
// A Validator owns background JWKS refresh goroutines; always call Close when
// it is no longer needed.
type Validator struct {
	// cfg is the validated, default-filled configuration.
	cfg Config
	// httpClient is used for discovery and JWKS fetches. Its Transport is a
	// limitedTransport, so every response body is capped at maxResponseBody.
	httpClient *http.Client

	// ctx owns the background JWKS refresh goroutines started by the jwx
	// cache: it is derived from the ctx passed to NewValidator and is
	// canceled by Close.
	ctx    context.Context
	cancel context.CancelFunc
	// closeOnce makes Close idempotent and safe for concurrent use.
	closeOnce sync.Once

	// jwksCache refreshes the registered JWKS URL in the background and
	// serves key sets to Validate. Read by Validate in Step 4.
	jwksCache *jwk.Cache
	// jwksWhitelist restricts the URLs the cache's httprc client will fetch to
	// the resolved JWKS URL (defense-in-depth on top of the https scheme check).
	jwksWhitelist httprc.MapWhitelist
	// jwksURL is the resolved JWKS endpoint (Config.JWKSURL if set, else the
	// jwks_uri discovered from the issuer metadata).
	jwksURL string

	// refreshMu serializes the unknown-kid recovery refresh so concurrent
	// unknown-kid validations trigger at most one fetch (H1); lastRefresh is
	// the floor timestamp the second caller sees after blocking on the mutex.
	refreshMu   sync.Mutex
	lastRefresh time.Time
	// lastSuccess is when a JWKS fetch last SUCCEEDED, as opposed to
	// lastRefresh, which records when one was last attempted. Only a success
	// proves the cached key set reflects the issuer, so the staleness bound
	// keys off this. Guarded by refreshMu.
	lastSuccess time.Time

	// negativeMu guards negativeKids, the bounded negative cache of kids that
	// resolved to no key after a refresh (suppresses repeat fetches for a kid
	// already failed within negativeCacheTTL).
	negativeMu   sync.Mutex
	negativeKids map[string]time.Time
}

// NewValidator validates cfg and constructs a Validator.
//
// The ctx argument governs the LIFETIME of the validator's background JWKS
// refresh, not just construction: the refresh goroutines stop when ctx is
// canceled or Close is called. Pass an application-lifetime context, not a
// per-request context.
//
// Construction-time network I/O (discovery and the initial JWKS fetch) is
// separately bounded by an internal timeout, so passing context.Background()
// cannot hang NewValidator indefinitely.
//
// Errors returned here are ordinary construction errors, not the *Error type:
// *Error is reserved for Validate/ParseBearer runtime failures.
func NewValidator(ctx context.Context, cfg Config) (*Validator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Config is copied by value, but Audiences and AcceptedTokenTypes would
	// still alias the caller's backing arrays: mutating either slice afterwards
	// would silently rewrite trusted policy, and would race Validate while
	// doing it. Clone both so the validator owns its policy for its whole
	// lifetime.
	cfg.Audiences = slices.Clone(cfg.Audiences)
	cfg.AcceptedTokenTypes = slices.Clone(cfg.AcceptedTokenTypes)

	httpClient, err := newHTTPClient(cfg.HTTPClient, cfg.AllowPrivateIP, cfg.CACertPath, cfg.AuthTokenFile)
	if err != nil {
		return nil, err
	}

	v := &Validator{
		cfg:        cfg,
		httpClient: httpClient,
	}
	// Deriving the lifetime context before any construction I/O guarantees a
	// validator that can fail construction never leaks refresh goroutines:
	// jwk.NewCache starts them, so on failure the fresh cancel runs before
	// the error return below.
	v.ctx, v.cancel = context.WithCancel(ctx)

	// init is handed the LIFETIME context: jwk.NewCache permanently binds the
	// httprc controller/worker refresh goroutines to the context it receives,
	// so the cache must be created with v.ctx (which Close cancels), not a
	// short-lived construction context. Per-operation construction network I/O
	// (Step 2 Register fetch, Step 3 discovery) is bounded separately with
	// constructionTimeout inside init; that bound must NOT reach NewCache.
	if err := v.init(v.ctx); err != nil {
		v.cancel()
		return nil, err
	}

	return v, nil
}

// Close stops the validator's background JWKS refresh by canceling its
// internal context. It is idempotent and safe to call concurrently. It does
// not wait for in-flight fetches to finish.
//
// Validate must not be called after Close; if it is, it fails fast with
// CodeUnavailable rather than blocking. A concurrent Close during an in-flight
// Validate is also safe: cache operations are bound to the validator lifetime,
// so they unblock instead of waiting on a controller that has stopped.
func (v *Validator) Close() {
	v.closeOnce.Do(v.cancel)
}

// withLifetime derives a context that is canceled when EITHER the request
// context or the validator's lifetime context is done.
//
// This is what keeps a request from outliving the machinery it depends on: the
// jwx cache's controller goroutines are bound to v.ctx, so once Close cancels
// it a cache operation carrying only the request context would wait on a
// receiver that no longer exists.
func (v *Validator) withLifetime(ctx context.Context) (context.Context, context.CancelFunc) {
	merged, cancel := context.WithCancel(ctx)
	// AfterFunc fires immediately when v.ctx is already done, so the
	// already-closed case needs no separate branch.
	stop := context.AfterFunc(v.ctx, cancel)
	return merged, func() {
		stop()
		cancel()
	}
}

// closed reports whether the validator's lifetime context has been canceled,
// either by Close or by cancellation of the context passed to NewValidator.
func (v *Validator) closed() bool {
	return v.ctx.Err() != nil
}

// validate checks cfg and fills in defaults, performing no I/O.
func (c *Config) validate() error {
	// At least one of Issuer/JWKSURL is required: the issuer is what discovery
	// resolves the JWKS URL from, so with neither there is no key material to
	// reach. An Issuer-less config is permitted (and skips iss verification) so
	// a static-JWKS deployment can be expressed; see the Config.Issuer docs.
	if c.Issuer == "" && c.JWKSURL == "" {
		return fmt.Errorf("authn: at least one of issuer or jwks_url is required")
	}
	if c.Issuer != "" {
		if err := validateHTTPSURI("issuer", c.Issuer, c.InsecureAllowHTTP); err != nil {
			return err
		}
	}

	if err := c.validateAudiences(); err != nil {
		return err
	}

	if c.JWKSURL != "" {
		if err := validateHTTPSURI("jwks_url", c.JWKSURL, c.InsecureAllowHTTP); err != nil {
			return err
		}
	}

	if err := c.validateLeeway(); err != nil {
		return err
	}

	// Zero means "no lifetime bound"; it is NOT defaulted. A default cap would
	// reject long-lived tokens that a resource server accepts today, so opting
	// in is the caller's decision.
	if c.MaxTokenLifetime < 0 {
		return fmt.Errorf("authn: max token lifetime must not be negative: %s", c.MaxTokenLifetime)
	}
	// Zero disables the staleness bound, for the same reason: enabling it can
	// turn an issuer outage into an authentication outage.
	if c.MaxJWKSStaleness < 0 {
		return fmt.Errorf("authn: max JWKS staleness must not be negative: %s", c.MaxJWKSStaleness)
	}
	for i, tt := range c.AcceptedTokenTypes {
		if normalizeTokenType(tt) == "" {
			return fmt.Errorf("authn: accepted_token_types[%d] must not be empty", i)
		}
	}

	return nil
}

// validateLeeway checks the clock-skew tolerance policy and fills in the
// default when neither Leeway nor DisableLeeway was set.
//
// DisableLeeway and a non-zero Leeway are mutually exclusive for the same
// reason AllowAnyAudience and a populated Audiences are: the two must not be
// left to silently disagree about which policy applies.
func (c *Config) validateLeeway() error {
	switch {
	case c.Leeway < 0:
		return fmt.Errorf("authn: leeway must not be negative: %s", c.Leeway)
	case c.DisableLeeway && c.Leeway != 0:
		return fmt.Errorf("authn: DisableLeeway must not be set together with a non-zero leeway %s", c.Leeway)
	case c.Leeway == 0 && !c.DisableLeeway:
		c.Leeway = defaultLeeway
	case c.Leeway > maxLeeway:
		return fmt.Errorf("authn: leeway %s exceeds maximum %s", c.Leeway, maxLeeway)
	}
	return nil
}

// validateAudiences checks the audience policy: exactly one of a non-empty
// Audiences list or AllowAnyAudience must be chosen, and every entry must be a
// safe bounded string.
//
// An empty audience list disables audience verification entirely, so it is
// gated behind AllowAnyAudience rather than being the accidental result of
// leaving a field unset.
func (c *Config) validateAudiences() error {
	switch {
	case len(c.Audiences) == 0 && !c.AllowAnyAudience:
		return fmt.Errorf("authn: at least one audience is required (set AllowAnyAudience to disable audience verification)")
	case len(c.Audiences) > 0 && c.AllowAnyAudience:
		return fmt.Errorf("authn: AllowAnyAudience must not be set together with %d configured audience(s)", len(c.Audiences))
	}
	for i, aud := range c.Audiences {
		if err := validateAudience(aud); err != nil {
			return fmt.Errorf("authn: audiences[%d]: %w", i, err)
		}
	}
	return nil
}

// validateAudience checks a single Config.Audiences entry.
//
// RFC 7519 §4.1.3 types aud as StringOrURI, so an audience need NOT be a URI:
// bare identifiers (an OAuth client_id) and opaque GUIDs (Entra ID) are
// conformant and common. The check is therefore a bounded-string one — length
// plus injection-safety — not a URI-shape one.
func validateAudience(aud string) error {
	if aud == "" {
		return fmt.Errorf("audience must not be empty")
	}
	if len(aud) > maxAudienceLength {
		return fmt.Errorf("audience length %d exceeds %d byte limit", len(aud), maxAudienceLength)
	}
	// Audiences are compared against token claims and may be echoed into logs
	// or headers by consumers; reject CR/LF and other control characters for
	// the same reason validation/http rejects them in header values.
	for _, r := range aud {
		if r == '\r' || r == '\n' || unicode.IsControl(r) {
			return fmt.Errorf("audience must not contain control characters: %q", aud)
		}
	}
	return nil
}

// validateHTTPSURI checks that raw is an absolute URI with a host and no
// fragment, and that its scheme is https unless insecureAllowHTTP is set.
func validateHTTPSURI(field, raw string, insecureAllowHTTP bool) error {
	if err := httpvalidation.ValidateResourceURI(raw); err != nil {
		return fmt.Errorf("authn: %s: %w", field, err)
	}
	// ValidateResourceURI already parsed raw successfully, so the error here
	// is impossible; it is checked rather than ignored to keep errcheck and
	// future edits honest.
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("authn: %s: %w", field, err)
	}
	// Allowlist, not exclusion: InsecureAllowHTTP widens the accepted set from
	// {https} to {https, http}, it does not turn the check into "anything but
	// https". Without this, ValidateResourceURI's scheme-presence-only check
	// left ftp://, file://, and gopher:// passing through whenever the flag
	// was set.
	switch u.Scheme {
	case schemeHTTPS:
		return nil
	case schemeHTTP:
		if insecureAllowHTTP {
			return nil
		}
	}
	return fmt.Errorf("authn: %s must use https scheme (set InsecureAllowHTTP for dev only): %s", field, raw)
}

// init resolves the JWKS URL, starts the jwx cache, and registers the URL with
// it. The ctx passed here is the validator's LIFETIME context (v.ctx):
// jwk.NewCache permanently binds the httprc controller/worker refresh
// goroutines to it, and Close cancels it.
//
// The JWKS URL is resolved BEFORE the httprc client is created so the
// whitelist can include a discovered jwks_uri. All construction network I/O —
// the discovery fetch and the first JWKS fetch inside Register/Refresh — runs
// under a context derived from ctx with constructionTimeout; that bound must
// NOT reach jwk.NewCache.
func (v *Validator) init(ctx context.Context) error {
	// Resolve the JWKS URL first: either the explicit Config.JWKSURL or the
	// jwks_uri discovered from the issuer's OIDC metadata.
	v.jwksURL = v.cfg.JWKSURL
	if v.jwksURL == "" {
		// Config.validate guarantees a non-empty Issuer whenever JWKSURL is
		// empty, so discovery always has a base to resolve from here.
		//
		// Bound the discovery fetch so an unresponsive issuer cannot hang
		// NewValidator past constructionTimeout.
		discCtx, cancel := context.WithTimeout(ctx, constructionTimeout)
		jwksURI, err := v.discoverWithRetry(discCtx, v.cfg.Issuer)
		cancel()
		switch {
		case err == nil:
			v.jwksURL = jwksURI
		case v.cfg.KeyProvider != nil && !errors.Is(err, errDiscoveryNotTransient):
			// Startup-race tolerance is for TRANSPORT failures: an embedded
			// issuer's discovery endpoint may not be listening yet, and that is
			// exactly the case a KeyProvider exists to ride out. A REJECTED
			// document (issuer mismatch, missing/non-https jwks_uri) is
			// different — the endpoint answered and the answer is wrong, which
			// is a configuration error, not a race. Tolerating it here would
			// silently abandon JWKS forever: jwksCache stays nil and every
			// token the provider does not offer returns unknown_kid with no
			// evidence beyond one construction-time log line. So only a
			// transient failure is swallowed; a rejected document stays fatal.
			return nil
		default:
			return err
		}
	}

	// The httprc client is restricted to fetching only whitelisted URLs: by
	// default httprc.NewClient allows ALL URLs (InsecureWhitelist{}), so we pass
	// a MapWhitelist as defense-in-depth on top of validateHTTPSURI's https
	// scheme check.
	v.jwksWhitelist = httprc.NewMapWhitelist()
	v.jwksWhitelist.Add(v.jwksURL)

	httprcClient := httprc.NewClient(
		httprc.WithHTTPClient(v.httpClient),
		httprc.WithWhitelist(v.jwksWhitelist),
	)
	// NewCache starts the httprc client (and its refresh goroutines) bound
	// to ctx; canceling v.ctx via Close stops them. Until a URL is registered
	// the cache is running but idle.
	cache, err := jwk.NewCache(ctx, httprcClient)
	if err != nil {
		return fmt.Errorf("authn: failed to start JWKS cache: %w", err)
	}
	v.jwksCache = cache

	// The first fetch is construction I/O only; bound it so an unresponsive
	// JWKS endpoint cannot hang NewValidator past constructionTimeout.
	fetchCtx, cancel := context.WithTimeout(ctx, constructionTimeout)
	defer cancel()

	// WithConstantInterval pins the refresh cadence: the issuer's
	// Cache-Control/Expires headers do not control how long key material is
	// trusted locally. WithHTTPClient injects our body-capped,
	// redirect-refusing client at the resource level. WithWaitReady(false) is
	// deliberate: httprc's async Add path retries the first fetch until the
	// context deadline, which would turn every unreachable-JWKS construction
	// error into a constructionTimeout wait; the synchronous Refresh below
	// surfaces the real error immediately instead.
	if err := v.jwksCache.Register(fetchCtx, v.jwksURL,
		jwk.WithHTTPClient(v.httpClient),
		jwk.WithConstantInterval(jwksRefreshInterval),
		jwk.WithWaitReady(false),
	); err != nil {
		return fmt.Errorf("authn: failed to register JWKS URL %s: %w", v.jwksURL, err)
	}

	// Attempt the first fetch regardless of whether a KeyProvider is set; only
	// whether a FAILURE is fatal differs.
	refreshErr := func() error {
		if _, err := v.jwksCache.Refresh(fetchCtx, v.jwksURL); err != nil {
			return fmt.Errorf("authn: failed to fetch JWKS from %s: %w", v.jwksURL, err)
		}
		if _, err := v.jwksCache.Lookup(fetchCtx, v.jwksURL); err != nil {
			return fmt.Errorf("authn: JWKS from %s unavailable after fetch: %w", v.jwksURL, err)
		}
		return nil
	}()

	// A successful construction fetch is the first freshness proof, regardless
	// of whether a KeyProvider is set: staleness() has to reflect it, or
	// MaxJWKSStaleness's self-correcting refresh (see its docs) never fires and
	// a validator constructed with a provider starts life reporting an
	// infinite staleness that only an actual JWKS refresh clears. This must run
	// BEFORE the KeyProvider early return below.
	if refreshErr == nil {
		v.refreshMu.Lock()
		v.lastSuccess = time.Now()
		v.refreshMu.Unlock()
	}

	// With a KeyProvider the first fetch is attempted but NOT required: an
	// embedded issuer typically mounts its JWKS route on the very listener that
	// has not started yet, so the fetch here can connection-refuse. Tolerating
	// that failure is what lets construction proceed; the registration stays in
	// place so the background refresh picks the keys up once the endpoint is
	// live, and until then the provider answers.
	//
	// Attempting it (rather than skipping it) matters: when the JWKS IS
	// reachable, a provider miss must fall through to populated key material
	// immediately rather than reporting httprc.ErrNotReady on the first request.
	if v.cfg.KeyProvider != nil {
		return nil
	}

	// Fail closed: with no provider the first fetch must complete during
	// construction, so an unreachable or unparseable JWKS endpoint is a
	// NewValidator error, never a validator with no key material. Refresh forces
	// the fetch synchronously and returns the underlying error (unlike waiting
	// on readiness, which would only report context deadline after background
	// retries).
	return refreshErr
}

// errRedirectRefused is returned by the redirect-refusal CheckRedirect policy
// installed below. http.ErrUseLastResponse is NOT an error condition — it
// tells the http.Client to hand the 3xx response back to the caller — so using
// it here made a refused redirect surface as a confusing downstream failure
// (discovery reporting "returned status 302", JWKS a parse error) with no
// mention of a redirect anywhere. Returning a real error fails the request
// instead, which is the point: this package requires jwks_uri/Issuer to be
// the endpoint itself, not something it redirects to.
type errRedirectRefused struct {
	target string
}

func (e *errRedirectRefused) Error() string {
	return fmt.Sprintf("authn: refused to follow redirect to %s (configure the final target directly)", e.target)
}

// refuseRedirects is the http.Client.CheckRedirect policy installed by
// newHTTPClient for both the default and a supplied client.
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return &errRedirectRefused{target: req.URL.String()}
}

// newHTTPClient returns base when non-nil, else a secure-by-default client
// built by the networking package. In both cases the transport is wrapped so
// response bodies are capped at maxResponseBody.
//
// The DEFAULT client carries networking's address-level SSRF guard: a
// net.Dialer.Control hook that refuses private, loopback, and link-local
// addresses AFTER DNS resolution, so a jwks_uri resolving to cloud instance
// metadata (169.254.169.254) or an in-cluster address is not fetched. That guard
// is why the default path must not be the weak one — the https scheme check and
// redirect refusal alone do not classify the address a name resolves to.
//
// authTokenFile, when non-empty, attaches a bearer token (re-read from the
// file on each request by networking) to outbound discovery/JWKS requests,
// for an IdP whose own endpoints are gated. networking.Build() installs
// SameHostRedirectPolicy whenever a token file is set, so the token is not
// replayed to a different host — but the CheckRedirect override just below
// replaces it with authn's stricter refuse-all anyway, so the two compose
// correctly rather than conflicting: whichever runs, redirects are refused.
//
// For a SUPPLIED client, a nil CheckRedirect is replaced with the
// redirect-refusing policy and a zero Timeout with defaultHTTPTimeout, so a
// bare &http.Client{} cannot silently drop the redirect refusal or the fetch
// bound. Explicit caller values for either field are preserved. The dial guard
// and AuthTokenFile CANNOT be retrofitted onto a supplied client's transport,
// though: see the Config.HTTPClient docs.
func newHTTPClient(base *http.Client, allowPrivateIP bool, caCertPath, authTokenFile string) (*http.Client, error) {
	if base == nil {
		built, err := networking.NewHttpClientBuilder().
			WithPrivateIPs(allowPrivateIP).
			WithCABundle(caCertPath).
			WithTokenFromFile(authTokenFile).
			WithInsecureAllowHTTP(true). // scheme policy is enforced by validateHTTPSURI
			WithTimeout(defaultHTTPTimeout).
			Build()
		if err != nil {
			return nil, fmt.Errorf("authn: failed to build HTTP client: %w", err)
		}
		// authn is stricter than networking's own redirect tolerance: refuse
		// redirects outright, since a jwks_uri that 302s elsewhere should be
		// configured as its final target instead.
		built.CheckRedirect = refuseRedirects
		base = built
	}
	// A zero-value client has a nil Transport and would use
	// http.DefaultTransport; wrap that instead so the cap always applies.
	rt := base.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	capped := *base
	capped.Transport = limitedTransport{base: rt}
	// Enforce the redirect-refusal and timeout for a supplied client that
	// left them unset, preserving an explicit caller policy.
	if capped.CheckRedirect == nil {
		capped.CheckRedirect = refuseRedirects
	}
	if capped.Timeout == 0 {
		capped.Timeout = defaultHTTPTimeout
	}
	return &capped, nil
}

// limitedTransport caps response bodies at maxResponseBody. The cap lives at
// the transport (rather than in each caller) because jwx reads the response
// body itself and would otherwise accept up to ~1GB.
type limitedTransport struct {
	base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp != nil && resp.Body != nil {
		resp.Body = &limitedBody{body: resp.Body}
	}
	return resp, nil
}

// limitedBody is a response body that fails the read with a terminal error once
// more than maxResponseBody bytes would be delivered. It never silently
// truncates: a caller that exceeds the cap gets an explicit "exceeds limit"
// error rather than a misleading downstream JSON parse failure (matching the
// explicit-limit style of validation/http). A body of exactly maxResponseBody
// bytes is delivered in full with a clean io.EOF; one byte more is an error.
// Any legitimate JWKS or discovery document is far below the cap.
type limitedBody struct {
	body io.ReadCloser
	read int
	// eof records that the underlying body returned io.EOF, so a body of
	// exactly maxResponseBody bytes terminates cleanly instead of erroring.
	eof bool
}

// Read implements io.Reader. It delivers at most the remaining budget. When the
// budget is exactly consumed it reads one extra byte from the underlying body
// to distinguish "exactly at the cap, then EOF" (clean) from "more data than
// the cap" (terminal error).
func (b *limitedBody) Read(p []byte) (int, error) {
	if b.read >= maxResponseBody {
		if b.eof {
			return 0, io.EOF
		}
		// Budget exhausted; determine whether the body actually has more data.
		// A zero-length Read is legal but some readers return (0, nil), so read
		// a single byte to get a definitive answer.
		var one [1]byte
		n, err := b.body.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("authn: response body exceeds %d byte limit", maxResponseBody)
		}
		if err == io.EOF {
			b.eof = true
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		// (0, nil): nothing available right now; report progress and let the
		// caller retry — the budget is still fully consumed.
		return 0, nil
	}
	if remaining := maxResponseBody - b.read; len(p) > remaining {
		p = p[:remaining]
	}
	n, err := b.body.Read(p)
	b.read += n
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

// Close implements io.Closer.
func (b *limitedBody) Close() error {
	return b.body.Close()
}
