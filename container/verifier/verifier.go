// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/types/known/structpb"

	registry "github.com/stacklok/toolhive-core/registry/types"
)

const (
	// TrustedRootSigstoreGitHub is the GitHub trusted root repository for sigstore (used for private repos, Enterprise)
	TrustedRootSigstoreGitHub = "tuf-repo.github.com"
	// TrustedRootSigstorePublicGoodInstance is the public trusted root repository for sigstore
	TrustedRootSigstorePublicGoodInstance = "tuf-repo-cdn.sigstore.dev"
	// RootTUFPath is the path to the root.json file inside an embedded TUF repository
	rootTUFPath = "root.json"
)

// Sigstore is the sigstore verifier
type Sigstore struct {
	verifier *verify.Verifier
	keychain authn.Keychain
}

// Result is the result of the verification
type Result struct {
	IsSigned   bool `json:"is_signed"`
	IsVerified bool `json:"is_verified"`
	verify.VerificationResult
}

// New creates a new Sigstore verifier
func New(provenance *registry.Provenance, keychain authn.Keychain) (*Sigstore, error) {
	// Fail the verification early if the server information is not set
	if provenance == nil {
		return nil, ErrProvenanceServerInformationNotSet
	}
	sigstoreTUFRepoURL := provenance.SigstoreURL

	// Default the sigstoreTUFRepoURL to the sigstore public trusted root repo if not provided.
	// Note: Update this if we want to support more sigstore instances
	if sigstoreTUFRepoURL == "" {
		sigstoreTUFRepoURL = TrustedRootSigstorePublicGoodInstance
	}

	// Get the sigstore options for the TUF client and the verifier
	tufOpts, opts, err := getSigstoreOptions(sigstoreTUFRepoURL)
	if err != nil {
		return nil, err
	}

	// Get the trusted material - sigstore's trusted_root.json
	trustedMaterial, err := root.FetchTrustedRootWithOptions(tufOpts)
	if err != nil {
		return nil, err
	}

	sev, err := verify.NewVerifier(trustedMaterial, opts...)
	if err != nil {
		return nil, err
	}

	// return the verifier
	return &Sigstore{
		verifier: sev,
		keychain: keychain,
	}, nil
}

// WithKeychain sets the keychain for authentication
func (s *Sigstore) WithKeychain(keychain authn.Keychain) *Sigstore {
	s.keychain = keychain
	return s
}

// GetVerificationResults returns the verification results for the given image reference
func (s *Sigstore) GetVerificationResults(
	imageRef string,
) ([]*verify.VerificationResult, error) {
	// Construct the bundle(s) for the image reference. The exported
	// signature predates context plumbing, so the fetch is not cancellable
	// from here; RetrieveBundles is the context-aware entry point.
	bundles, err := getSigstoreBundles(context.Background(), imageRef, s.keychain)
	if err != nil && !errors.Is(err, ErrProvenanceNotFoundOrIncomplete) {
		// We got some other unexpected error prior to querying for the signature/attestation
		return nil, err
	}
	//nolint:gosec // G706: bundle count derived from external registry data
	slog.Debug("sigstore bundles constructed", "count", len(bundles))

	// If we didn't manage to construct any valid bundles, it probably means that the image is not signed.
	if len(bundles) == 0 || errors.Is(err, ErrProvenanceNotFoundOrIncomplete) {
		return []*verify.VerificationResult{}, nil
	}

	// Construct the verification result for each bundle we managed to generate.
	return getVerifiedResults(s.verifier, bundles), nil
}

// getVerifiedResults verifies the artifact using the bundles against the configured sigstore instance
// and returns the extracted metadata that we need for ingestion
func getVerifiedResults(
	sev *verify.Verifier,
	bundles []sigstoreBundle,
) []*verify.VerificationResult {
	var results []*verify.VerificationResult

	// Verify each bundle we've constructed
	for _, b := range bundles {
		// Create a new verification result. At this point, we managed to extract a bundle, so lets verify it.
		verificationResult, err := sev.Verify(b.bundle, verify.NewPolicy(
			verify.WithArtifactDigest(b.digestAlgo, b.digestBytes),
			verify.WithoutIdentitiesUnsafe(),
		))
		if err != nil {
			slog.Info("bundle verification failed", "error", err)
			continue
		}
		// We've successfully verified and extracted the artifact provenance information
		results = append(results, verificationResult)
	}
	// Return the results
	return results
}

// VerifyServer verifies the server information for the given image reference
func (s *Sigstore) VerifyServer(imageRef string, provenance *registry.Provenance) error {
	// Get the verification results for the image reference
	results, err := s.GetVerificationResults(imageRef)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		return ErrImageNotSigned
	}

	// Return nil if any result matches the provenance
	for _, res := range results {
		if isVerificationResultMatchingServerProvenance(res, provenance) {
			return nil
		}
	}
	return ErrProvenanceMismatch
}

func isVerificationResultMatchingServerProvenance(r *verify.VerificationResult, p *registry.Provenance) bool {
	if r == nil || p == nil || r.Signature == nil || r.Signature.Certificate == nil {
		return false
	}

	// Compare the base properties of the verification result and the server provenance
	if !compareBaseProperties(r, p) {
		return false
	}

	return compareAttestation(r, p)
}

// compareAttestation compares the attestation constraint declared in the
// server provenance against the in-toto statement carried by the verification
// result. Following the same per-field convention as compareBaseProperties, an
// unset expectation means "do not constrain that dimension" rather than "skip
// the check".
func compareAttestation(r *verify.VerificationResult, p *registry.Provenance) bool {
	// A nil attestation places no constraint on the artifact.
	if p.Attestation == nil {
		return true
	}

	// The provenance asks for an attestation, so the artifact has to carry
	// one. Treating a missing statement as a match would skip the constraint
	// exactly when it matters.
	if r.Statement == nil {
		return false
	}

	if p.Attestation.PredicateType != "" && p.Attestation.PredicateType != r.Statement.PredicateType {
		return false
	}

	if p.Attestation.Predicate != nil {
		if r.Statement.Predicate == nil {
			return false
		}
		// Round both sides through structpb before comparing. The expected
		// predicate is decoded registry data whose Go types depend on the
		// serialisation format - encoding/json yields float64 for every
		// number where yaml.v3 yields int - while the statement carries a
		// *structpb.Struct. Comparing the raw values would make verification
		// depend on how the registry entry happened to be decoded.
		expected, err := normalizeAttestationPredicate(p.Attestation.Predicate)
		if err != nil {
			// An expected predicate we cannot normalise is one we cannot
			// confirm, so treat it as a mismatch rather than a pass.
			slog.Error("cannot normalize expected attestation predicate", "error", err)
			return false
		}
		if !reflect.DeepEqual(expected, r.Statement.Predicate.AsMap()) {
			return false
		}
	}

	return true
}

// normalizeAttestationPredicate renders an expected predicate from the registry
// into the same shape structpb produces for a statement predicate, so that
// semantically equal predicates compare equal regardless of whether they were
// decoded from JSON or YAML. An in-toto predicate is always an object, so an
// expectation that is not a map cannot match one.
func normalizeAttestationPredicate(predicate any) (map[string]any, error) {
	fields, ok := predicate.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected predicate is %T, want an object", predicate)
	}
	s, err := structpb.NewStruct(fields)
	if err != nil {
		return nil, fmt.Errorf("expected predicate is not representable as a struct: %w", err)
	}
	return s.AsMap(), nil
}

// compareBaseProperties compares the base properties of the verification result and the server provenance
func compareBaseProperties(r *verify.VerificationResult, p *registry.Provenance) bool {
	// Extract the signer identity from the certificate
	siIdentity, err := signerIdentityFromCertificate(r.Signature.Certificate)
	if err != nil {
		slog.Error("error parsing signer identity")
	}
	// Compare repository name and reference, signer identity, runner environment, and cert issuer
	if p.RepositoryURI != "" {
		// If the repository URI is set, we need to compare it with the verification result
		if p.RepositoryURI != r.Signature.Certificate.SourceRepositoryURI {
			return false
		}
	}
	if p.RepositoryRef != "" {
		// If the repository reference is set, we need to compare it with the verification result
		if p.RepositoryRef != r.Signature.Certificate.SourceRepositoryRef {
			return false
		}
	}
	if p.RunnerEnvironment != "" {
		// If the runner environment is set, we need to compare it with the verification result
		if p.RunnerEnvironment != r.Signature.Certificate.RunnerEnvironment {
			return false
		}
	}
	if p.CertIssuer != "" {
		// If the certificate issuer is set, we need to compare it with the verification result
		if p.CertIssuer != r.Signature.Certificate.Issuer {
			return false
		}
	}
	if p.SignerIdentity != "" {
		// If the signer identity is set, we need to compare it with the verification result
		if p.SignerIdentity != siIdentity {
			return false
		}
	}
	return true
}

// signerIdentityFromCertificate returns the signer identity. When the identity
// is a URI (from the BuildSignerURI extension or the cert SAN), we return only
// the URI path component. We split it this way to ensure we can make rules
// more generalizable (applicable to the same path regardless of the repo for example).
func signerIdentityFromCertificate(c *certificate.Summary) (string, error) {
	var builderURL string

	if c.SubjectAlternativeName == "" {
		return "", fmt.Errorf("certificate has no signer identity in SAN (is it a fulcio cert?)")
	}

	switch {
	case c.SubjectAlternativeName != "":
		builderURL = c.SubjectAlternativeName
	default:
		// Return the SAN in the cert as a last resort. This handles the case when
		// we don't have a signer identity but also when the SAN is an email
		// when a user authenticated using an OIDC provider or a SPIFFE ID.
		// Any other SAN types are returned verbatim
		return c.SubjectAlternativeName, nil
	}

	// Any signer identity not issued by github actions is returned verbatim
	if c.Issuer != githubTokenIssuer {
		return builderURL, nil
	}

	// When handling a cert issued through GitHub actions tokens, break the identity
	// into its components. The verifier captures the git reference and the
	// the repository URI.
	if c.SourceRepositoryURI == "" {
		return "", fmt.Errorf(
			"certificate extension dont have a SourceRepositoryURI set (oid 1.3.6.1.4.1.57264.1.5)",
		)
	}

	builderURL, _, _ = strings.Cut(builderURL, "@")
	builderURL = strings.TrimPrefix(builderURL, c.SourceRepositoryURI)

	return builderURL, nil
}
