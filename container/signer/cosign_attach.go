// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	mediaTypeCosignSimpleSigningV1JSON = "application/vnd.dev.cosign.simplesigning.v1+json"
	annotationCosignSignature          = "dev.cosignproject.cosign/signature"
	// annotationCosignCertificate and annotationCosignBundle are the
	// additional annotations a keyless (Fulcio) signature carries, on top of
	// annotationCosignSignature. They MUST match exactly what
	// container/verifier/sigstore.go reads on the retrieval side: that
	// package classifies a layer as key-signed whenever
	// annotationCosignCertificate is absent, so a keyless layer missing it
	// would silently be misclassified.
	annotationCosignCertificate = "dev.sigstore.cosign/certificate"
	annotationCosignBundle      = "dev.sigstore.cosign/bundle"
)

// cosignSimpleSigning is the payload cosign signs: it embeds the artifact's
// manifest digest, binding the signature to the exact artifact content.
type cosignSimpleSigning struct {
	Critical cosignCritical `json:"critical"`
}

type cosignCritical struct {
	Identity cosignIdentity `json:"identity"`
	Image    cosignImage    `json:"image"`
	Type     string         `json:"type"`
}

type cosignIdentity struct {
	DockerReference string `json:"docker-reference"`
}

type cosignImage struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

// SimpleSigningPayload builds the canonical simple-signing payload for the
// artifact at ref pinned to digestStr. This payload — not the manifest
// digest — is what gets signed, per the cosign convention: a verifier
// recovers the payload from the signature manifest's layer, checks the
// signature over it, and reads the bound manifest digest out of it.
// Exported because offline re-verification of a stored key-signed bundle
// must reconstruct exactly these bytes to check the signature's binding.
func SimpleSigningPayload(imageRef, digestStr string) ([]byte, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}
	d, err := parseManifestDigest(digestStr)
	if err != nil {
		return nil, err
	}
	payload := cosignSimpleSigning{
		Critical: cosignCritical{
			Identity: cosignIdentity{DockerReference: ref.Context().Name()},
			Image:    cosignImage{DockerManifestDigest: d.String()},
			Type:     "cosign container image signature",
		},
	}
	return json.Marshal(payload)
}

// parseManifestDigest validates and normalizes an artifact manifest digest
// string, defaulting a bare hex value to sha256.
func parseManifestDigest(digestStr string) (digest.Digest, error) {
	digestStr = strings.TrimSpace(digestStr)
	if digestStr == "" {
		return "", fmt.Errorf("digest is required for signing")
	}
	if !strings.Contains(digestStr, ":") {
		digestStr = "sha256:" + digestStr
	}
	d, err := digest.Parse(digestStr)
	if err != nil {
		return "", fmt.Errorf("parsing digest: %w", err)
	}
	return d, nil
}

// attachCosignSignature writes the cosign signature manifest for the
// artifact: an OCI image at the "sha256-<hex>.sig" tag whose single layer is
// the simple-signing payload, carrying the signature in the layer's
// annotations. This is the classic cosign layout, chosen deliberately for
// interop — "cosign verify --key" and any Sigstore-aware registry tooling
// can discover and verify it.
//
// pb is the Sigstore bundle produced for payload, in the exact shape
// [sign.Bundle] returns: its message signature is what gets attached, and
// its verification material determines the layout. A bundle whose
// verification material carries a certificate (the keyless/Fulcio flow) also
// gets the certificate and transparency-log annotations
// container/verifier/sigstore.go reads back; a bundle carrying only a public
// key hint (the plain key-pair flow) attaches just the signature, as before.
// pub is the public key used for the key-signed dedupe check below — it is
// separate from pb because the key-signed bundle itself carries no key
// material, only a hint.
func attachCosignSignature(
	ctx context.Context,
	keychain authn.Keychain,
	imageRef, digestStr string,
	payload []byte,
	pb *protobundle.Bundle,
	pub crypto.PublicKey,
) error {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return fmt.Errorf("parsing image reference: %w", err)
	}
	d, err := parseManifestDigest(digestStr)
	if err != nil {
		return err
	}

	msgSig := pb.GetMessageSignature()
	if msgSig == nil || len(msgSig.GetSignature()) == 0 {
		return errors.New("bundle carries no message signature to attach")
	}
	cert, err := certMaterialFromBundle(pb)
	if err != nil {
		return err
	}

	h, err := v1.NewHash(d.String())
	if err != nil {
		return fmt.Errorf("parsing digest hash: %w", err)
	}
	sigTag := ref.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	remoteOpts := []remote.Option{remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx)}

	// An artifact can carry signatures from several signers, so the new
	// layer is appended to whatever is already at the .sig tag rather than
	// replacing it. Building from empty.Image unconditionally would delete
	// every existing signature — including other people's trust material —
	// on the next push. This mirrors cosign's own append behaviour.
	base, err := existingSignatureImage(sigTag, remoteOpts)
	if err != nil {
		return err
	}

	already, err := alreadySigned(base, payload, pub, cert)
	if err != nil {
		return err
	}
	if already {
		// Re-signing with the same key/identity is a no-op; pushing
		// repeatedly must not grow the manifest without bound.
		return nil
	}
	annotations, err := signatureAnnotations(msgSig.GetSignature(), cert)
	if err != nil {
		return err
	}

	layer := static.NewLayer(payload, mediaTypeCosignSimpleSigningV1JSON)
	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       layer,
		Annotations: annotations,
		MediaType:   mediaTypeCosignSimpleSigningV1JSON,
	})
	if err != nil {
		return fmt.Errorf("building signature manifest: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	if err := remote.Write(sigTag, img, remoteOpts...); err != nil {
		return fmt.Errorf("pushing signature manifest: %w", err)
	}
	return nil
}

// alreadySigned reports whether base already carries a signature layer
// equivalent to the one about to be attached, dispatching to the dedupe
// check that matches the signature's layout: identity comparison for a
// certificate-bearing (keyless) signature, key comparison otherwise. See
// signedByIdentity and signedByKey for why these must be different checks.
func alreadySigned(base v1.Image, payload []byte, pub crypto.PublicKey, cert *certMaterial) (bool, error) {
	if cert != nil {
		return signedByIdentity(base, payload, cert.summary)
	}
	return signedByKey(base, payload, pub)
}

// signatureAnnotations builds the layer annotations for an attached
// signature: always the signature itself, plus the certificate and
// (when present) transparency-log annotations for a keyless signature.
func signatureAnnotations(signatureBytes []byte, cert *certMaterial) (map[string]string, error) {
	annotations := map[string]string{
		annotationCosignSignature: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	if cert == nil {
		return annotations, nil
	}
	annotations[annotationCosignCertificate] = certificateAnnotation(cert.certDER)
	bundleAnnotation, err := rekorBundleAnnotation(cert.tlogEntry)
	if err != nil {
		return nil, err
	}
	if bundleAnnotation != "" {
		annotations[annotationCosignBundle] = bundleAnnotation
	}
	return annotations, nil
}

// existingSignatureImage fetches the signature manifest already at tag, or
// an empty image when none exists yet. Only a genuine "absent" answer from
// the registry is treated as empty — any other failure is returned, because
// silently starting from empty would discard existing signatures.
func existingSignatureImage(tag name.Tag, remoteOpts []remote.Option) (v1.Image, error) {
	img, err := remote.Image(tag, remoteOpts...)
	if err == nil {
		return img, nil
	}
	if isAbsentFromRegistry(err) {
		return empty.Image, nil
	}
	return nil, fmt.Errorf("reading existing signature manifest: %w", err)
}

// isAbsentFromRegistry reports whether err means "this tag does not exist"
// as opposed to a transport, auth, or server failure.
func isAbsentFromRegistry(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	if terr.StatusCode == http.StatusNotFound {
		return true
	}
	for _, diag := range terr.Errors {
		if diag.Code == transport.ManifestUnknownErrorCode || diag.Code == transport.NameUnknownErrorCode {
			return true
		}
	}
	return false
}

// signedByKey reports whether img already carries a signature over payload
// that verifies with pub — i.e. whether this key has already signed this
// artifact. This is the same question cosign's dupe detector asks, and the
// only reliable one: ECDSA signatures are randomised, so two signatures
// from one key never match byte-for-byte.
func signedByKey(img v1.Image, payload []byte, pub crypto.PublicKey) (bool, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return false, fmt.Errorf("reading signature manifest layers: %w", err)
	}
	if len(manifest.Layers) == 0 {
		return false, nil
	}
	sigVerifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("loading verifier for duplicate detection: %w", err)
	}
	for _, l := range manifest.Layers {
		encoded := l.Annotations[annotationCosignSignature]
		if encoded == "" {
			continue
		}
		raw, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			// A layer we cannot decode is not one of ours; leave it alone
			// rather than failing the whole push over someone else's
			// malformed annotation.
			continue
		}
		if sigVerifier.VerifySignature(bytes.NewReader(raw), bytes.NewReader(payload)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// signedByIdentity reports whether img already carries a certificate-bearing
// signature layer from the same signer identity as summary that ALSO
// cryptographically verifies against payload — i.e. whether this keyless
// signer has already produced a valid signature over this exact artifact.
// Identity match alone is not enough to dedupe on: a layer whose signature
// does not verify against its own certificate is not "already signed",
// merely damaged, and treating it as equivalent would let a corrupted or
// mismatched existing layer permanently block a legitimate re-sign from
// ever attaching a valid signature. This is the keyless counterpart to
// signedByKey: comparing certificate bytes, or the signature itself, would
// never dedupe, because keyless signing mints a fresh ephemeral keypair and
// certificate on every run. Identity — certificate SAN plus OIDC issuer —
// is what stays stable across runs, and is also what a verifier's trust
// policy binds to (see container/verifier's identityPolicyOption), so it is
// the right notion of "already signed by this signer", checked alongside —
// never instead of — the cryptographic check.
func signedByIdentity(img v1.Image, payload []byte, summary fulciocert.Summary) (bool, error) {
	manifest, err := img.Manifest()
	if err != nil {
		return false, fmt.Errorf("reading signature manifest layers: %w", err)
	}
	for _, l := range manifest.Layers {
		pemCert := l.Annotations[annotationCosignCertificate]
		if pemCert == "" {
			continue
		}
		existing, err := parseLeafCertificate([]byte(pemCert))
		if err != nil {
			// A layer we cannot parse is not one of ours; leave it alone
			// rather than failing the whole push over someone else's
			// malformed annotation.
			continue
		}
		existingSummary, err := fulciocert.SummarizeCertificate(existing)
		if err != nil {
			continue
		}
		if existingSummary.SubjectAlternativeName != summary.SubjectAlternativeName ||
			existingSummary.Issuer != summary.Issuer {
			continue
		}
		if verifies, _ := certLayerVerifies(l, existing, payload); verifies {
			return true, nil
		}
		// Same identity, but this layer's signature does not verify against
		// its own certificate and payload — it is corrupt or stale, not a
		// prior valid signing. Fall through rather than dedupe on it, so a
		// new, valid signature still gets appended.
	}
	return false, nil
}

// certLayerVerifies reports whether layer's attached signature annotation
// cryptographically verifies against cert's public key and payload. A
// decode or verifier-construction failure is reported as "does not verify"
// rather than propagated: the annotation is registry-supplied data, and the
// caller's fallback (treat as not-yet-signed, append a new layer) is
// already the correct response to a layer that fails to check out.
func certLayerVerifies(layer v1.Descriptor, cert *x509.Certificate, payload []byte) (bool, error) {
	encoded := layer.Annotations[annotationCosignSignature]
	if encoded == "" {
		return false, errors.New("layer carries a certificate but no signature annotation")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false, fmt.Errorf("decoding signature annotation: %w", err)
	}
	sigVerifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("loading verifier for existing certificate: %w", err)
	}
	return sigVerifier.VerifySignature(bytes.NewReader(raw), bytes.NewReader(payload)) == nil, nil
}

// certMaterial is the certificate and transparency-log evidence for a
// keyless (Fulcio) signature, extracted from the Sigstore bundle passed to
// attachCosignSignature.
type certMaterial struct {
	// certDER is the leaf signing certificate, DER-encoded.
	certDER []byte
	// summary is the signer identity (SAN + OIDC issuer) the certificate
	// carries, used by signedByIdentity for dedupe.
	summary fulciocert.Summary
	// tlogEntry is the Rekor transparency-log entry covering the signature,
	// when the bundle carries one.
	tlogEntry *protorekor.TransparencyLogEntry
}

// certMaterialFromBundle extracts the leaf certificate and transparency-log
// entry from pb's verification material, structurally mirroring
// container/verifier/bundles.go's Bundle.HasCertificate: a bundle whose
// verification material carries neither a certificate nor a certificate
// chain is the key-signed layout, and certMaterialFromBundle reports that by
// returning a nil *certMaterial (not an error) — attachCosignSignature falls
// back to the key-signed dedupe and annotation path in that case. Only a
// certificate that IS present but fails to parse is an error: a bundle
// claiming to be keyless with unusable certificate material must not be
// silently treated as key-signed.
func certMaterialFromBundle(pb *protobundle.Bundle) (*certMaterial, error) {
	vm := pb.GetVerificationMaterial()
	var certDER []byte
	switch {
	case vm.GetCertificate() != nil:
		certDER = vm.GetCertificate().GetRawBytes()
	case vm.GetX509CertificateChain() != nil && len(vm.GetX509CertificateChain().GetCertificates()) > 0:
		// The verifier's read side only ever reconstructs a single
		// certificate from the "dev.sigstore.cosign/certificate"
		// annotation (see getVerificationMaterialX509CertificateChain), so
		// only the leaf is written here too — intermediates are not
		// carried through this layout today.
		certDER = vm.GetX509CertificateChain().GetCertificates()[0].GetRawBytes()
	default:
		return nil, nil
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing signing certificate: %w", err)
	}
	summary, err := fulciocert.SummarizeCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("summarizing signing certificate identity: %w", err)
	}

	var tlogEntry *protorekor.TransparencyLogEntry
	if entries := vm.GetTlogEntries(); len(entries) > 0 {
		tlogEntry = entries[0]
	}
	return &certMaterial{certDER: certDER, summary: summary, tlogEntry: tlogEntry}, nil
}

// parseLeafCertificate decodes a single PEM-encoded certificate block, the
// shape written by certificateAnnotation and read by
// container/verifier/sigstore.go's getVerificationMaterialX509CertificateChain.
func parseLeafCertificate(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// certificateAnnotation PEM-encodes certDER for the
// "dev.sigstore.cosign/certificate" annotation, matching exactly what
// container/verifier/sigstore.go's getVerificationMaterialX509CertificateChain
// decodes back.
func certificateAnnotation(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

// rekorBundleAnnotation renders entry into the JSON shape
// container/verifier/sigstore.go's getVerificationMaterialTlogEntries reads
// back from the "dev.sigstore.cosign/bundle" annotation — cosign's classic
// RekorBundle layout: a base64 SignedEntryTimestamp alongside a Payload
// carrying the hex log ID, integrated time, log index, and base64
// canonicalized entry body. entry may be nil — a bundle can be keyless
// without a transparency-log entry (e.g. signing against a private,
// non-transparency-logged Fulcio deployment) — in which case the empty
// string is returned and no annotation is written.
//
// This layout has no field for a Rekor v2 style inclusion proof (a Merkle
// proof against a signed checkpoint) — only the v1 inclusion promise (a
// signed entry timestamp) fits. An entry with no promise would otherwise
// silently produce an annotation with an empty SignedEntryTimestamp, which
// container/verifier's reconstructed bundle fails to validate far away from
// this call site; failing here instead keeps the error at the point the bad
// data was produced. Target-only-Rekor-v1 is a deliberate current scope
// limit, not an oversight — see the keyless design notes.
func rekorBundleAnnotation(entry *protorekor.TransparencyLogEntry) (string, error) {
	if entry == nil {
		return "", nil
	}
	set := entry.GetInclusionPromise().GetSignedEntryTimestamp()
	if len(set) == 0 {
		return "", errors.New(
			"transparency-log entry carries no inclusion promise (SignedEntryTimestamp): " +
				"the cosign bundle annotation cannot represent a proof-only (Rekor v2) entry")
	}
	bun := struct {
		SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
		Payload              struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		} `json:"Payload"`
	}{
		SignedEntryTimestamp: base64.StdEncoding.EncodeToString(set),
	}
	bun.Payload.Body = base64.StdEncoding.EncodeToString(entry.GetCanonicalizedBody())
	bun.Payload.IntegratedTime = entry.GetIntegratedTime()
	bun.Payload.LogIndex = entry.GetLogIndex()
	bun.Payload.LogID = hex.EncodeToString(entry.GetLogId().GetKeyId())

	raw, err := json.Marshal(bun)
	if err != nil {
		return "", fmt.Errorf("encoding rekor bundle annotation: %w", err)
	}
	return string(raw), nil
}
