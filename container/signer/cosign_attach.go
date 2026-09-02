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
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/stacklok/toolhive-core/container/verifier"
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
// Exported so callers can reproduce and inspect the exact bytes a signature
// covers; re-verifying a stored [Result.Bundle] does not need it, since the
// stored form carries the payload itself.
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
			// The verifier refuses a payload carrying any other type, so
			// this must stay the value it checks for.
			Type: verifier.CosignSignatureType,
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
//
// The returned bool reports whether a new layer was actually appended:
// false means the artifact was already signed by this identity/key and
// attachCosignSignature was a no-op. This matters to the caller — pb's
// signature is randomised per call, so when nothing was appended, pb does
// NOT represent what is now on the registry; only the pre-existing layer
// does. See SignOCI's use of this to decide what to return as Result.Bundle.
func attachCosignSignature(
	ctx context.Context,
	keychain authn.Keychain,
	imageRef, digestStr string,
	payload []byte,
	pb *protobundle.Bundle,
	pub crypto.PublicKey,
	tm root.TrustedMaterial,
) (bool, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, fmt.Errorf("parsing image reference: %w", err)
	}
	d, err := parseManifestDigest(digestStr)
	if err != nil {
		return false, err
	}

	msgSig := pb.GetMessageSignature()
	if msgSig == nil || len(msgSig.GetSignature()) == 0 {
		return false, errors.New("bundle carries no message signature to attach")
	}
	cert, err := certMaterialFromBundle(pb)
	if err != nil {
		return false, err
	}

	h, err := v1.NewHash(d.String())
	if err != nil {
		return false, fmt.Errorf("parsing digest hash: %w", err)
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
		return false, err
	}

	already, err := alreadySigned(ctx, keychain, imageRef, digestStr, base, payload, pub, cert, tm)
	if err != nil {
		return false, err
	}
	if already {
		// Re-signing with the same key/identity is a no-op; pushing
		// repeatedly must not grow the manifest without bound.
		return false, nil
	}
	annotations, err := signatureAnnotations(msgSig.GetSignature(), cert)
	if err != nil {
		return false, err
	}

	layer := static.NewLayer(payload, mediaTypeCosignSimpleSigningV1JSON)
	img, err := mutate.Append(base, mutate.Addendum{
		Layer:       layer,
		Annotations: annotations,
		MediaType:   mediaTypeCosignSimpleSigningV1JSON,
	})
	if err != nil {
		return false, fmt.Errorf("building signature manifest: %w", err)
	}
	img = mutate.MediaType(img, types.OCIManifestSchema1)

	if err := remote.Write(sigTag, img, remoteOpts...); err != nil {
		return false, fmt.Errorf("pushing signature manifest: %w", err)
	}
	return true, nil
}

// alreadySigned reports whether the artifact already carries a signature
// layer equivalent to the one about to be attached, dispatching to the
// dedupe check that matches the signature's layout: a chain-verified
// identity check for a certificate-bearing (keyless) signature, key
// comparison against base's raw layers otherwise. See keylessAlreadySigned
// and signedByKey for why these must be different checks.
func alreadySigned(
	ctx context.Context, keychain authn.Keychain, imageRef, digestStr string,
	base v1.Image, payload []byte, pub crypto.PublicKey, cert *certMaterial, tm root.TrustedMaterial,
) (bool, error) {
	if cert != nil {
		return keylessAlreadySigned(ctx, keychain, imageRef, digestStr, payload, cert, tm)
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

// keylessAlreadySigned reports whether the artifact at imageRef/digestStr
// already carries a genuinely trusted keyless signature from cert's
// identity over payload. See keylessLayerTrusted for why identity match
// alone (certificate SAN plus OIDC issuer — the keyless counterpart to
// signedByKey's public-key comparison, since keyless signing mints a fresh
// ephemeral keypair and certificate on every run) is NOT enough to dedupe
// on: unlike signedByKey's pub, which the caller supplies as ground truth,
// the SAN and issuer extensions are attacker-visible fields inside the
// certificate itself, so a self-signed certificate can claim any identity —
// this must additionally chain-verify.
//
// This re-reads the registry through verifier.RetrieveBundles rather than
// scanning the existing signature manifest's raw layers directly (as the
// key-signed path does): only RetrieveBundles' reconstruction carries the
// certificate and transparency-log material coreverifier.VerifyBundle
// needs, and rebuilding that here would duplicate container/verifier's own
// read side. A failure here — including "nothing attached yet" — is
// treated as not-yet-signed rather than propagated: at worst this appends a
// redundant layer, which append-never-replace already makes safe, and that
// is a better failure mode than blocking a legitimate sign over a
// transient read problem.
func keylessAlreadySigned(
	ctx context.Context, keychain authn.Keychain, imageRef, digestStr string,
	payload []byte, cert *certMaterial, tm root.TrustedMaterial,
) (bool, error) {
	full := imageRef
	if !strings.Contains(imageRef, "@") {
		full = imageRef + "@" + digestStr
	}
	bundles, err := verifier.RetrieveBundles(ctx, full, keychain)
	if err != nil {
		return false, nil //nolint:nilerr // see doc comment: a read failure here means "append", not "fail the sign"
	}
	opts, err := verifier.DefaultVerifierOptions()
	if err != nil {
		return false, nil //nolint:nilerr // embedded verifier options; failure here is not expected in practice
	}
	for _, b := range bundles {
		if b.HasCertificate() && keylessLayerTrusted(b, tm, opts, payload, cert.summary) {
			return true, nil
		}
	}
	return false, nil
}

// keylessLayerTrusted reports whether bundle b is a genuine, chain-verified
// Fulcio/Rekor signature from summary's identity over payload — not merely
// a certificate carrying a matching SAN/issuer extension. Both fields are
// public, unauthenticated data embedded in the certificate: anyone with
// registry write access can mint a self-signed certificate carrying a
// victim's SAN and OIDC-issuer extension, sign the known simple-signing
// payload with the matching (self-generated) key, and push it as a
// signature layer. A check that only confirms internal self-consistency
// (the signature verifies against ITS OWN certificate's key) would accept
// that forgery as "already signed by this identity" and silently skip
// attaching the real, Fulcio-backed signature — a signing-pipeline bypass,
// not a forged verification (a real consumer's install/verify step still
// rejects the self-signed certificate on chain-of-trust), but a bypass
// nonetheless. This instead runs the exact chain-of-trust and
// transparency-log verification a real consumer's install/verify step
// applies — container/verifier's embedded trust root and
// DefaultVerifierOptions — so only a genuinely Fulcio-issued, Rekor-logged
// certificate can dedupe.
//
// The payload check runs before the (comparatively expensive) chain
// verification: a chain-valid signature over some OTHER payload from this
// same identity says nothing about whether THIS payload has already been
// signed, and checking it first also avoids wasted verification work.
// Comparing payload bytes — rather than the bundle's artifact digest, which
// every signature on this artifact shares — is what makes it a check about
// this signature at all.
func keylessLayerTrusted(
	b verifier.Bundle, tm root.TrustedMaterial, opts []verify.VerifierOption, payload []byte, summary fulciocert.Summary,
) bool {
	if !bytes.Equal(b.SimpleSigningPayload, payload) {
		return false
	}
	vr, err := verifier.VerifyBundle(b, tm, nil, opts...)
	if err != nil || vr.Signature == nil || vr.Signature.Certificate == nil {
		return false
	}
	return vr.Signature.Certificate.SubjectAlternativeName == summary.SubjectAlternativeName &&
		vr.Signature.Certificate.Issuer == summary.Issuer
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
