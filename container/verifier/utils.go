// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"path"

	"github.com/google/go-containerregistry/pkg/authn"
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
