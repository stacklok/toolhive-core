// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

//go:embed tufroots
var embeddedTufRoots embed.FS

var (
	// ErrProvenanceNotFoundOrIncomplete is returned when there's no provenance info (missing .sig or attestation) or
	// has incomplete data
	ErrProvenanceNotFoundOrIncomplete = errors.New("provenance not found or incomplete")

	// ErrProvenanceServerInformationNotSet is returned when the provenance information for a server is not set
	ErrProvenanceServerInformationNotSet = errors.New("provenance server information not set")

	// ErrImageNotSigned is returned when no signatures or attestations are found for the image
	ErrImageNotSigned = errors.New("image is not signed")

	// ErrProvenanceMismatch is returned when the image is signed but no bundle matches the expected provenance
	ErrProvenanceMismatch = errors.New("image provenance does not match")

	// MaxAttestationsBytesLimit is the maximum number of bytes we're willing to read from the attestation endpoint
	// We'll limit this to 10mb for now
	MaxAttestationsBytesLimit int64 = 10 * 1024 * 1024
)

// bundleMaterialFetchError marks an operational failure while downloading
// material named by an already-read manifest. Its Error and Unwrap methods
// preserve the legacy error text and chain; strict retrieval uses the marker
// to distinguish an incomplete read from malformed material that was fully
// downloaded and rejected.
type bundleMaterialFetchError struct {
	err error
}

func (e *bundleMaterialFetchError) Error() string { return e.err.Error() }
func (e *bundleMaterialFetchError) Unwrap() error { return e.err }

func markBundleMaterialFetchError(err error) error {
	return &bundleMaterialFetchError{err: err}
}

func isBundleMaterialFetchError(err error) bool {
	var fetchErr *bundleMaterialFetchError
	return errors.As(err, &fetchErr)
}

// isOperationalFetchError separates an interrupted registry/blob read from
// content that was completely read but could not be parsed or used. Strict
// retrieval must report the former as an incomplete bundle set, while the
// latter is simply rejected verification material.
func isOperationalFetchError(err error) bool {
	if errors.Is(err, ErrBundleSetIncomplete) || isBundleMaterialFetchError(err) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}

func bundleSetIncompletef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBundleSetIncomplete, fmt.Sprintf(format, args...))
}

func bundleSetIncompleteBecause(cause error, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w", ErrBundleSetIncomplete, fmt.Sprintf(format, args...), cause)
}

// registryRequestTarget identifies one registry endpoint whose successful
// response body is security-relevant discovery metadata. Host matching keeps
// an authentication service with a similar path outside the absence and
// response-budget rules.
type registryRequestTarget struct {
	host            string
	path            string
	acceptMediaType string
}

func manifestRequestTarget(ref name.Reference) registryRequestTarget {
	return registryRequestTarget{
		host:            ref.Context().RegistryStr(),
		path:            fmt.Sprintf("/v2/%s/manifests/%s", ref.Context().RepositoryStr(), ref.Identifier()),
		acceptMediaType: string(types.OCIManifestSchema1),
	}
}

func indexManifestRequestTarget(ref name.Reference) registryRequestTarget {
	return registryRequestTarget{
		host:            ref.Context().RegistryStr(),
		path:            fmt.Sprintf("/v2/%s/manifests/%s", ref.Context().RepositoryStr(), ref.Identifier()),
		acceptMediaType: string(types.OCIImageIndex),
	}
}

func referrersRequestTarget(digest name.Digest) registryRequestTarget {
	return registryRequestTarget{
		host:            digest.Context().RegistryStr(),
		path:            fmt.Sprintf("/v2/%s/referrers/%s", digest.Context().RepositoryStr(), digest.DigestStr()),
		acceptMediaType: string(types.OCIImageIndex),
	}
}

func (t registryRequestTarget) matchesGET(req *http.Request) bool {
	return req.Method == http.MethodGet && strings.Contains(req.Header.Get("Accept"), t.acceptMediaType) &&
		t.matches(req)
}

func (t registryRequestTarget) matchesExactGET(req *http.Request) bool {
	return req.Method == http.MethodGet && req.URL != nil && req.URL.Host == t.host && req.URL.Path == t.path &&
		strings.Contains(req.Header.Get("Accept"), t.acceptMediaType)
}

func (t registryRequestTarget) matches(req *http.Request) bool {
	// A manifest response may follow a redirect. net/http links each
	// redirected request to its predecessor through Request.Response, so walk
	// that chain and retain the original registry endpoint's classification.
	for current := req; current != nil; {
		if current.URL != nil && current.URL.Host == t.host && current.URL.Path == t.path {
			return true
		}
		if current.Response == nil {
			break
		}
		current = current.Response.Request
	}
	return false
}

// responseBodyBudget is a shared byte allowance for one strict discovery
// class. It is consumed while response bodies are read, before
// go-containerregistry can buffer them using its larger internal limit.
type responseBodyBudget struct {
	mu        sync.Mutex
	remaining int64
	detail    string
}

func newResponseBodyBudget(limit int64, detail string) *responseBodyBudget {
	return &responseBodyBudget{remaining: limit, detail: detail}
}

// strictResponseTransport applies a responseBodyBudget only to successful
// GETs for the listed registry endpoints. Authentication and registry error
// responses retain go-containerregistry's own bounded handling.
type strictResponseTransport struct {
	inner   http.RoundTripper
	targets []registryRequestTarget
	budget  *responseBodyBudget
}

func newStrictResponseTransport(
	budget *responseBodyBudget,
	targets ...registryRequestTarget,
) *strictResponseTransport {
	return &strictResponseTransport{
		inner:   remote.DefaultTransport,
		targets: targets,
		budget:  budget,
	}
}

func (t *strictResponseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	for _, target := range t.targets {
		if target.matchesGET(req) {
			resp.Body = &budgetedReadCloser{ReadCloser: resp.Body, budget: t.budget}
			break
		}
	}
	return resp, nil
}

type budgetedReadCloser struct {
	io.ReadCloser
	budget *responseBodyBudget
}

func (r *budgetedReadCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if r.budget.remaining <= 0 {
		// Probe one bounded byte beyond the allowance. EOF means the complete
		// body fit exactly; any byte means accepting the response would exceed
		// the strict budget. Never expose the probe byte to the caller.
		var probe [1]byte
		n, err := r.ReadCloser.Read(probe[:])
		if n > 0 {
			overflow := bundleSetIncompletef("%s exceeds the strict retrieval byte limit", r.budget.detail)
			if err != nil {
				return 0, errors.Join(overflow, err)
			}
			return 0, overflow
		}
		return 0, err
	}

	if int64(len(p)) > r.budget.remaining {
		p = p[:r.budget.remaining]
	}
	n, err := r.ReadCloser.Read(p)
	r.budget.remaining -= int64(n)
	return n, err
}

// OCI and Sigstore media type constants used when inspecting referrer manifests.
const (
	MediaTypeOCIEmptyV1JSON            = "application/vnd.oci.empty.v1+json"
	MediaTypeCosignSimpleSigningV1JSON = "application/vnd.dev.cosign.simplesigning.v1+json"
	MediaTypeSigstoreBundleV03JSON     = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

const (
	sigstoreBundleMediaType01 = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	// githubTokenIssuer is the issuer stamped into sigstore certs
	// when authenticating through GitHub tokens
	//nolint: gosec // Not an embedded credential
	githubTokenIssuer = "https://token.actions.githubusercontent.com"
)

func verifierOptions(trustedRoot string) ([]verify.VerifierOption, error) {
	switch trustedRoot {
	case TrustedRootSigstorePublicGoodInstance:
		return []verify.VerifierOption{
			verify.WithSignedCertificateTimestamps(1),
			verify.WithTransparencyLog(1),
			verify.WithObserverTimestamps(1),
		}, nil
	case TrustedRootSigstoreGitHub:
		return []verify.VerifierOption{
			verify.WithObserverTimestamps(1),
		}, nil
	}
	return nil, fmt.Errorf("unknown trusted root: %s", trustedRoot)
}

func getSigstoreOptions(sigstoreTUFRepoURL string) (*tuf.Options, []verify.VerifierOption, error) {
	// Default the sigstoreTUFRepoURL to the sigstore public trusted root repo if not provided
	if sigstoreTUFRepoURL == "" {
		sigstoreTUFRepoURL = TrustedRootSigstorePublicGoodInstance
	}

	// Get the Sigstore TUF client options
	tufOpts, err := getTUFOptions(sigstoreTUFRepoURL)
	if err != nil {
		return nil, nil, err
	}

	// Get the Sigstore verifier options
	opts, err := verifierOptions(sigstoreTUFRepoURL)
	if err != nil {
		return nil, nil, err
	}

	// All good
	return tufOpts, opts, nil
}

func getTUFOptions(sigstoreTUFRepoURL string) (*tuf.Options, error) {
	// Default the TUF options
	tufOpts := tuf.DefaultOptions()
	tufOpts.DisableLocalCache = true

	// Set the repository base URL, fix the scheme if not provided
	tufURL, err := url.Parse(sigstoreTUFRepoURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing sigstore TUF repo URL: %w", err)
	}
	if tufURL.Scheme == "" {
		tufURL.Scheme = "https"
	}
	tufOpts.RepositoryBaseURL = tufURL.String()

	// sigstore-go has a copy of the root.json for the public sigstore instance embedded. Nothing to do.
	if sigstoreTUFRepoURL != TrustedRootSigstorePublicGoodInstance {
		// Look up and set the embedded root.json for the given TUF repository
		rootJson, err := embeddedRootJson(sigstoreTUFRepoURL)
		if err != nil {
			return nil, fmt.Errorf("error getting embedded root.json for %s: %w", sigstoreTUFRepoURL, err)
		}
		tufOpts.Root = rootJson
	}

	// All good
	return tufOpts, nil
}

func embeddedRootJson(tufRootURL string) ([]byte, error) {
	embeddedRootPath := path.Join("tufroots", tufRootURL, rootTUFPath)
	return embeddedTufRoots.ReadFile(embeddedRootPath)
}

// getSigstoreBundles returns the sigstore bundles for an artifact, gathering
// both layouts this package understands: attestation manifests discovered
// through the OCI 1.1 referrers API, and a cosign signature manifest at the
// "sha256-<hex>.sig" tag.
//
// Referrers are queried FIRST, deliberately. A referrer is addressed by the
// artifact's own digest, so a bundle found that way is bound to the artifact
// by construction. The cosign ".sig" tag is a mutable tag, so a bundle found
// there is bound to the artifact only by the check
// bundleFromSigstoreSignedImage performs on the signed payload. Preferring
// the structurally-bound layout keeps an attacker who can write tags from
// choosing which code path runs — defence in depth, not a substitute for
// that check.
//
// Both layouts are gathered rather than short-circuiting on the first hit:
// an artifact may legitimately carry an attestation and a cosign signature
// from different signers, and returning only whichever was found first would
// make verification depend on discovery order.
func getSigstoreBundles(
	ctx context.Context,
	imageRef string,
	keychain authn.Keychain,
) ([]sigstoreBundle, error) {
	referrerBundles, referrerErr := bundleFromAttestation(ctx, imageRef, keychain)
	if referrerErr != nil && !errors.Is(referrerErr, ErrProvenanceNotFoundOrIncomplete) {
		// Something went wrong before we could even ask about provenance
		// (an unparseable reference, an unreachable registry). The cosign
		// path resolves the same reference and would fail the same way.
		return nil, referrerErr
	}

	sigBundles, sigErr := bundleFromSigstoreSignedImage(ctx, imageRef, keychain)
	switch {
	case sigErr == nil:
	case errors.Is(sigErr, ErrProvenanceNotFoundOrIncomplete), errors.Is(sigErr, ErrSignatureArtifactMismatch):
		// Recorded rather than returned: a referrer bundle may still make
		// this artifact verifiable, and the verdict is decided below.
	default:
		if len(referrerBundles) == 0 {
			return nil, sigErr
		}
		slog.Warn("reading the cosign signature manifest failed; continuing with attestation bundles",
			"error", sigErr)
	}

	bundles := append(referrerBundles, sigBundles...)
	if len(bundles) > 0 {
		return bundles, nil
	}
	// Nothing usable. A signature that was found and refused for not
	// covering this artifact is a different verdict from no signature at all
	// and is reported as itself.
	if errors.Is(sigErr, ErrSignatureArtifactMismatch) {
		return nil, sigErr
	}
	return nil, ErrProvenanceNotFoundOrIncomplete
}

// getSigstoreBundlesStrict resolves imageRef once and requires complete,
// bounded retrieval from both supported attachment layouts. It deliberately
// does not reuse getSigstoreBundles: that legacy path preserves permissive
// partial-result behavior for existing callers.
func getSigstoreBundlesStrict(
	ctx context.Context,
	imageRef string,
	keychain authn.Keychain,
) ([]sigstoreBundle, error) {
	target, err := getSignatureReferenceFromOCIImageStrict(ctx, imageRef, keychain)
	if err != nil {
		if isOperationalFetchError(err) {
			return nil, bundleSetIncompleteBecause(err, "resolving artifact reference")
		}
		return nil, err
	}

	referrerBundles, referrerErr := bundleFromAttestationTarget(ctx, target, keychain, true)
	if referrerErr != nil && !errors.Is(referrerErr, ErrProvenanceNotFoundOrIncomplete) {
		return nil, referrerErr
	}

	sigBundles, sigErr := bundleFromSigstoreSignedTarget(ctx, target, keychain, true)
	switch {
	case sigErr == nil:
	case errors.Is(sigErr, ErrProvenanceNotFoundOrIncomplete), errors.Is(sigErr, ErrSignatureArtifactMismatch):
		// Absence and fully assessed, rejected material do not make the set
		// incomplete. A mismatch is returned below only when no referrer
		// bundle remains usable.
	default:
		return nil, sigErr
	}

	bundles := append(referrerBundles, sigBundles...)
	if len(bundles) > 0 {
		return bundles, nil
	}
	if errors.Is(sigErr, ErrSignatureArtifactMismatch) {
		return nil, sigErr
	}
	return nil, ErrProvenanceNotFoundOrIncomplete
}
