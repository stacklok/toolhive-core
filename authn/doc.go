// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package authn validates INBOUND JWT bearer tokens at a resource server.
//
// It performs NO OAuth flows and issues nothing: there is no token endpoint,
// no authorization-code exchange, and no signing of tokens. The package only
// verifies the bearer tokens that clients present.
//
// Validate, Verify and ParseBearer return failures as *Error. An *Error has a
// Code and a Reason that are safe to send to a client. Its Error method also
// returns detail for your logs. Do not send that detail to a client.
// NewValidator and NewTrustSet report construction problems as ordinary errors.
//
// # Overview
//
// A Validator checks tokens from one issuer. Build it with NewValidator from a
// Config. Call ParseBearer on the Authorization header, then call
// Validator.Validate on the token. Validate returns a Principal.
//
// A TrustSet checks tokens from several issuers. It holds one Trust for each
// issuer. Build it with NewTrustSet. Call TrustSet.Verify on the token.
// Verify returns a Principal whose Trust field names the trust that verified
// the token.
//
// ValidateConfig checks a Config and does no network I/O. Use it to reject a
// bad Config at startup when you build the Validator later.
//
// # Defaults
//
// These defaults differ from a verifier that you write by hand.
//
//   - The token must have exp, and sub must not be empty.
//   - The iss claim must equal Config.Issuer byte for byte.
//   - Config needs Audiences. To skip the audience check, set
//     AllowAnyAudience. An empty Audiences list alone is an error.
//   - Only RS, PS and ES algorithms are accepted (256, 384 and 512). The
//     algorithm none and the HMAC algorithms are refused. Config.Algs can
//     narrow the list.
//   - RSA keys under 2048 bits are refused. A token with a crit header is
//     refused.
//   - The clock-skew tolerance is 60 seconds. The maximum is 2 minutes.
//   - A token with a cnf claim is refused. Set AllowCNF to accept it.
//   - A token whose typ is an ID-JAG, logout, security event, DPoP or token
//     introspection type is refused with ReasonTokenKind.
//   - The default HTTP client refuses private addresses and redirects. It
//     stops after 15 seconds and reads at most 1 MiB. A client that you
//     supply in Config.HTTPClient does not get the private-address check.
//   - Construction fails if discovery or the first JWKS fetch fails. With a
//     KeyProvider, a failed fetch is not fatal. With ProviderOnly, nothing is
//     fetched.
//   - MaxTokenLifetime and MaxJWKSStaleness are off. Turn them on if you need
//     them. MaxJWKSStaleness turns an issuer outage into CodeUnavailable.
//
// # What the caller must still do
//
// A valid token is not yet an allowed request. You must still do these things.
//
//   - Check scopes. Call Principal.RequireScopes. It checks only the scope
//     claim, or scp when scope is absent. It does not read roles. A token
//     with no scopes fails every RequireScopes call that names a scope.
//   - Choose your own identity claim. Principal.Subject is the sub claim. It
//     is unique only within one issuer, and some issuers need another claim.
//   - Qualify every claim by Principal.Trust. A claim such as email or groups
//     means something only for the issuer that signed it. Never compare a
//     claim from one trust with a claim from another.
//   - Read Principal.Claims as JSON types. A number is a float64. An array is
//     a []any. An object is a map[string]any.
//   - Map errors to responses. Use Code.HTTPStatus. CodeUnavailable is not an
//     OAuth2 error value: return a plain 503. Use PossiblyOpaque to find a
//     token that may be opaque and need introspection.
//   - Add rules with Config.Checks when the built-in rules are not enough.
//
// # Several issuers
//
// TrustSet.Verify reads iss from the token before it checks the signature. It
// uses iss only to choose a trust. The match is exact. Then it verifies the
// token with the Config of that trust alone. It never tries another trust. If
// no trust has that issuer, the error is ReasonUnknownIssuer, and no key is
// tried. You can then pass the token to another verifier.
//
// Each Trust needs an ID that is unique in the set and a Config.Issuer that
// is unique in the set. Two trusts that differ only by a trailing slash in the
// issuer are both refused. Trust.Tag comes back unchanged in Principal.Trust.
//
// A TrustSet cannot change. To change the trusts, build a new set, swap it in
// with an atomic.Pointer, and call Close on the old set. NewTrustSet returns
// the set and a []TrustError. The set holds every trust that built. A trust
// that failed to build is not in the set, and its tokens fail with
// ReasonUnknownIssuer.
//
// Set Trust.NotAfter to the time when the data of a trust goes stale. After
// that time, its tokens fail with CodeUnavailable and ReasonTrustStale.
//
// A set whose trusts are all ProviderOnly makes no network requests and holds
// no goroutines. It needs no Close.
//
// The next example uses two sets. The first holds the human identity
// providers. It is built once at startup, and a TrustError is fatal. The
// second holds issuers from a directory service. It is rebuilt on a timer.
// WithProviderOnly makes sure that no trust in it fetches keys. WithReservedIssuers
// makes sure that it cannot take over an issuer of the first set.
//
//	humans, errs := authn.NewTrustSet(ctx, humanTrusts)
//	if len(errs) > 0 {
//		log.Fatal(errs[0])
//	}
//
//	var machines atomic.Pointer[authn.TrustSet]
//	rebuild := func() {
//		next, errs := authn.NewTrustSet(ctx, trustsFromDirectory(),
//			authn.WithProviderOnly(),
//			authn.WithReservedIssuers(humanIssuers...))
//		for _, e := range errs {
//			log.Print(e)
//		}
//		if old := machines.Swap(next); old != nil {
//			old.Close()
//		}
//	}
//	rebuild() // before the server accepts requests, then on a timer
//
//	verify := func(ctx context.Context, token string) (authn.Principal, error) {
//		p, err := humans.Verify(ctx, token)
//		var ae *authn.Error
//		if errors.As(err, &ae) && ae.Reason == authn.ReasonUnknownIssuer {
//			return machines.Load().Verify(ctx, token)
//		}
//		return p, err
//	}
//
// # Identity providers
//
// Config.Issuer must be the exact iss value of the tokens. For that reason
// NewValidator and NewTrustSet refuse an issuer with a template placeholder
// such as {tenantid}, which no token carries. The Entra multi-tenant
// issuers common, organizations and consumers are not refused, but no token
// carries them either. Configure one issuer, and so one trust, for each
// tenant.
//
// Microsoft Entra:
//
//   - Set Config.JWKSURL. The v1 issuer is https://sts.windows.net/{tenant}/,
//     but its keys are on login.microsoftonline.com. Use
//     https://login.microsoftonline.com/{tenant}/discovery/keys for v1 tokens
//     and https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys for
//     v2 tokens.
//   - The aud claim has a different form in v1 and v2 tokens. It can be a
//     client ID (a GUID) or an App ID URI such as api://{id}. List every form
//     that your clients receive in Config.Audiences. Matching is byte-exact.
//   - A delegated token has scp, a space-separated string. An app-only token
//     has roles, an array, and no scp. Principal.Scopes never holds roles.
//     Read roles from Principal.Claims.
//   - The typ header of Entra tokens is JWT. Leave AcceptedTokenTypes empty.
//   - An ID token has the client ID as aud. The strongest guard against an ID
//     token is an API audience that is not the ID of any client, together
//     with RequireScopes for at least one scope. An ID token has no scp.
//   - Roles do not separate ID tokens from access tokens. An ID token can
//     carry roles.
//   - Identify a user by the pair tid and oid from Principal.Claims. Do not
//     use sub alone.
//
// Okta:
//
//   - Use a custom authorization server. The issuer is
//     https://{org}.okta.com/oauth2/{id}. Do not use the org authorization
//     server.
//   - Scopes are in scp, an array. Principal.Scopes reads it.
//   - Do not set AcceptedTokenTypes. Do not rely on typ for Okta tokens.
//   - The cid claim is the ID of the client that asked for the token. Read it
//     from Principal.Claims.
//   - A client-credentials token has no user. Its sub is the client ID.
package authn
