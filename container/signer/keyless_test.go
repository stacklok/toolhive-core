// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/swag/conv"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctx509util "github.com/google/certificate-transparency-go/x509util"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	// Blank import registers the Rekor entry type the fake log unmarshals
	// and canonicalizes.
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekorutil "github.com/sigstore/rekor/pkg/util"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/container/verifier"
)

// Identity fixtures for the keyless tests: the OIDC claims the fake Fulcio
// stamps into the certificates it issues.
const (
	testKeylessSAN    = "signer@example.com"
	testKeylessIssuer = "https://oidc.example.com"
)

// testSigstore is a complete Sigstore deployment running in-process: a Fulcio
// certificate authority (root + intermediate), a Certificate Transparency log,
// and a Rekor v1 transparency log, exposed over httptest servers speaking the
// real HTTP APIs sigstore-go's sign.Fulcio and sign.Rekor clients drive.
//
// It exists because these are unit tests: they must never reach the public-good
// or staging Sigstore instances. Mocking sigstore-go's own client interfaces
// instead would leave the part most likely to break — that SignOCI wires the
// ephemeral key, identity token, and endpoint URLs into real requests — untested.
// So the fakes are servers, not stubs, and the material they produce is
// cryptographically genuine: certificates chain to the test root, carry a real
// embedded SCT, and Rekor entries carry a real SignedEntryTimestamp. That is
// what lets the same object serve as the verification trust root
// (testSigstore implements root.TrustedMaterial), so a bundle this deployment
// signs is verified end to end under the project's real policy rather than
// merely inspected.
type testSigstore struct {
	rootCert         *x509.Certificate
	intermediateCert *x509.Certificate
	intermediateKey  *ecdsa.PrivateKey
	ctlogKey         *ecdsa.PrivateKey
	rekorKey         *ecdsa.PrivateKey

	fulcioURL string
	rekorURL  string

	// serial hands out unique certificate serial numbers, so signing the same
	// artifact twice yields distinguishable certificates as real Fulcio does.
	serial atomic.Int64
	// logIndex hands out increasing Rekor log indices.
	logIndex atomic.Int64
}

var _ root.TrustedMaterial = (*testSigstore)(nil)

// newTestSigstore mints the deployment's keys and starts its Fulcio and Rekor
// servers, registering cleanup on t.
func newTestSigstore(t *testing.T) *testSigstore {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "toolhive-test-sigstore-root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootCert := createTestCertificate(t, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)

	// Fulcio issues from an intermediate, and the SCT verification path needs
	// the leaf's issuer in the chain, so the test CA mirrors that shape rather
	// than signing leaves directly off the root.
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intermediateTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "toolhive-test-fulcio-intermediate"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateCert := createTestCertificate(t, intermediateTmpl, rootCert, &intermediateKey.PublicKey, rootKey)

	ctlogKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rekorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	s := &testSigstore{
		rootCert:         rootCert,
		intermediateCert: intermediateCert,
		intermediateKey:  intermediateKey,
		ctlogKey:         ctlogKey,
		rekorKey:         rekorKey,
	}

	fulcioMux := http.NewServeMux()
	fulcioMux.HandleFunc("POST /api/v2/signingCert", s.handleSigningCert)
	fulcio := httptest.NewServer(fulcioMux)
	t.Cleanup(fulcio.Close)
	s.fulcioURL = fulcio.URL

	rekorMux := http.NewServeMux()
	rekorMux.HandleFunc("POST /api/v1/log/entries", s.handleCreateLogEntry)
	rekor := httptest.NewServer(rekorMux)
	t.Cleanup(rekor.Close)
	s.rekorURL = rekor.URL

	return s
}

func createTestCertificate(
	t *testing.T, tmpl, parent *x509.Certificate, pub any, parentKey crypto.Signer,
) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// identityToken builds a syntactically valid, unsigned OIDC ID token carrying
// the fixture identity. Nothing verifies its signature: real Fulcio does that,
// and sigstore-go only base64-decodes the claims to recover the subject it
// proves possession of. An unsigned token is therefore the honest fixture —
// signing it would imply a check that does not happen here.
func identityToken(t *testing.T, subject string) string {
	t.Helper()
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	header := enc(map[string]string{"alg": "none", "typ": "JWT"})
	claims := enc(map[string]any{
		"iss":            testKeylessIssuer,
		"sub":            subject,
		"email":          subject,
		"email_verified": true,
		"aud":            "sigstore",
		"exp":            time.Now().Add(time.Hour).Unix(),
	})
	return header + "." + claims + ".unsigned"
}

// claimsFromToken recovers the subject and issuer from an ID token's claims,
// standing in for the verification real Fulcio performs against the issuer.
func claimsFromToken(token string) (subject, issuer string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("identity token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decoding identity token claims: %w", err)
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", "", fmt.Errorf("parsing identity token claims: %w", err)
	}
	subject = claims.Email
	if subject == "" {
		subject = claims.Subject
	}
	if subject == "" || claims.Issuer == "" {
		return "", "", fmt.Errorf("identity token carries no subject or issuer")
	}
	return subject, claims.Issuer, nil
}

// fulcioSigningCertRequest is Fulcio's v2 signing-certificate request body, as
// sign.Fulcio serializes it.
type fulcioSigningCertRequest struct {
	PublicKeyRequest struct {
		PublicKey struct {
			Algorithm string `json:"algorithm"`
			Content   string `json:"content"`
		} `json:"publicKey"`
		ProofOfPossession string `json:"proofOfPossession"`
	} `json:"publicKeyRequest"`
}

// handleSigningCert implements Fulcio's POST /api/v2/signingCert: it
// authenticates the bearer identity token, checks the caller's proof of
// possession of the submitted public key, and returns a certificate chain whose
// leaf binds that key to the token's identity.
//
// The proof-of-possession check is the point of doing this over HTTP at all: it
// only passes if SignOCI signed the token's subject with the very key it asked
// to have certified, which is exactly the wiring a stub could not exercise.
func (s *testSigstore) handleSigningCert(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		http.Error(w, "missing bearer identity token", http.StatusUnauthorized)
		return
	}
	subject, issuer, err := claimsFromToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var req fulcioSigningCertRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "malformed signing certificate request", http.StatusBadRequest)
		return
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(req.PublicKeyRequest.PublicKey.Content))
	if err != nil {
		http.Error(w, "unparseable public key", http.StatusBadRequest)
		return
	}
	pop, err := base64.StdEncoding.DecodeString(req.PublicKeyRequest.ProofOfPossession)
	if err != nil {
		http.Error(w, "unparseable proof of possession", http.StatusBadRequest)
		return
	}
	popVerifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		http.Error(w, "unusable public key", http.StatusBadRequest)
		return
	}
	if err := popVerifier.VerifySignature(bytes.NewReader(pop), bytes.NewReader([]byte(subject))); err != nil {
		http.Error(w, "proof of possession does not verify", http.StatusBadRequest)
		return
	}

	leafDER, err := s.issueLeafCertificate(pub, subject, issuer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	chain := make([]string, 0, 3)
	for _, der := range [][]byte{leafDER, s.intermediateCert.Raw, s.rootCert.Raw} {
		chain = append(chain, certificateAnnotation(der))
	}
	// Fulcio's v2 signingCert returns 200, not 201, and sign.Fulcio treats
	// anything else as a failure.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"signedCertificateEmbeddedSct": map[string]any{
			"chain": map[string]any{"certificates": chain},
		},
	})
}

// issueLeafCertificate issues a Fulcio-shaped code-signing certificate for pub:
// the subject in a SAN, the OIDC issuer in the Fulcio issuer extension, and a
// Certificate Transparency SCT embedded in the certificate.
//
// The certificate is created twice on purpose. An embedded SCT signs the
// PRE-certificate's TBS — the certificate as it would be without the SCT
// extension — so the pre-certificate has to exist before the SCT can be
// computed, and the final certificate is then reissued from the same template
// with the SCT appended. A verifier reverses this by stripping the SCT
// extension back off, which recovers byte-identical TBS bytes only because
// nothing else about the template changed between the two issuances.
func (s *testSigstore) issueLeafCertificate(pub crypto.PublicKey, subject, issuer string) ([]byte, error) {
	issuerExt, err := asn1.Marshal(issuer)
	if err != nil {
		return nil, fmt.Errorf("encoding OIDC issuer extension: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(s.serial.Add(1)),
		EmailAddresses: []string{subject},
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{
			{Id: fulciocert.OIDIssuerV2, Value: issuerExt},
		},
	}

	precertDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.intermediateCert, pub, s.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("issuing pre-certificate: %w", err)
	}
	precert, err := x509.ParseCertificate(precertDER)
	if err != nil {
		return nil, fmt.Errorf("parsing pre-certificate: %w", err)
	}

	sctExt, err := s.signedCertificateTimestampExtension(precert)
	if err != nil {
		return nil, err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, *sctExt)

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, s.intermediateCert, pub, s.intermediateKey)
	if err != nil {
		return nil, fmt.Errorf("issuing signing certificate: %w", err)
	}
	return leafDER, nil
}

// signedCertificateTimestampExtension logs precert to the test CT log and
// returns the SCT list extension to embed in the final certificate, in the
// RFC 6962 §3.3 encoding sigstore-go's SCT verification parses back.
func (s *testSigstore) signedCertificateTimestampExtension(precert *x509.Certificate) (*pkix.Extension, error) {
	logID, err := testLogID(s.ctlogKey.Public())
	if err != nil {
		return nil, err
	}
	timestamp := uint64(time.Now().UnixMilli()) //nolint:gosec // test timestamp, always positive
	sct := ct.SignedCertificateTimestamp{
		SCTVersion: ct.V1,
		LogID:      ct.LogID{KeyID: logID},
		Timestamp:  timestamp,
	}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{
		Leaf: ct.MerkleTreeLeaf{
			Version:  ct.V1,
			LeafType: ct.TimestampedEntryLeafType,
			TimestampedEntry: &ct.TimestampedEntry{
				Timestamp: timestamp,
				EntryType: ct.PrecertLogEntryType,
				PrecertEntry: &ct.PreCert{
					IssuerKeyHash:  sha256.Sum256(s.intermediateCert.RawSubjectPublicKeyInfo),
					TBSCertificate: precert.RawTBSCertificate,
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("serializing SCT signature input: %w", err)
	}
	digest := sha256.Sum256(input)
	sig, err := s.ctlogKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing SCT: %w", err)
	}
	sct.Signature = ct.DigitallySigned{
		Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA},
		Signature: sig,
	}

	sctList, err := ctx509util.MarshalSCTsIntoSCTList([]*ct.SignedCertificateTimestamp{&sct})
	if err != nil {
		return nil, fmt.Errorf("marshaling SCT list: %w", err)
	}
	raw, err := cttls.Marshal(*sctList)
	if err != nil {
		return nil, fmt.Errorf("encoding SCT list: %w", err)
	}
	// The extension value is the TLS-encoded SCT list wrapped in an ASN.1
	// OCTET STRING, per RFC 6962 §3.3.
	wrapped, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("wrapping SCT list: %w", err)
	}
	return &pkix.Extension{Id: asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT), Value: wrapped}, nil
}

// handleCreateLogEntry implements Rekor v1's POST /api/v1/log/entries. The
// proposed entry is unmarshaled with Rekor's own type registry — which
// cryptographically validates the submitted signature against the entry's
// public key and artifact hash, exactly as the real log does — then
// canonicalized, signed into a SignedEntryTimestamp, and returned.
func (s *testSigstore) handleCreateLogEntry(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "unreadable proposed entry", http.StatusBadRequest)
		return
	}
	proposed, err := models.UnmarshalProposedEntry(bytes.NewReader(body), runtime.JSONConsumer())
	if err != nil {
		http.Error(w, "malformed proposed entry", http.StatusBadRequest)
		return
	}
	entryImpl, err := types.UnmarshalEntry(proposed)
	if err != nil {
		http.Error(w, "invalid proposed entry: "+err.Error(), http.StatusBadRequest)
		return
	}
	canonical, err := entryImpl.Canonicalize(r.Context())
	if err != nil {
		http.Error(w, "uncanonicalizable entry", http.StatusInternalServerError)
		return
	}

	entry, err := s.logEntry(r.Context(), canonical)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// The client reads the created entry out of the payload map by the ETag
	// header, so the two must agree on the entry's UUID.
	uuid := hex.EncodeToString(entry.leafHash)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", uuid)
	w.Header().Set("Location", "/api/v1/log/entries/"+uuid)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(models.LogEntry{uuid: entry.anon})
}

// testLogEntry is a Rekor log entry the fake log has just integrated.
type testLogEntry struct {
	anon     models.LogEntryAnon
	leafHash []byte
}

// logEntry integrates a canonicalized entry body into the fake log: it signs
// the entry timestamp (the inclusion promise the cosign bundle annotation
// carries) and a single-leaf checkpoint (the inclusion proof).
func (s *testSigstore) logEntry(ctx context.Context, canonical []byte) (*testLogEntry, error) {
	signer, err := signature.LoadECDSASignerVerifier(s.rekorKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading rekor signer: %w", err)
	}
	logID, err := testLogID(s.rekorKey.Public())
	if err != nil {
		return nil, err
	}
	logIDHex := hex.EncodeToString(logID[:])
	integratedTime := time.Now().Unix()
	logIndex := s.logIndex.Add(1)
	encodedBody := base64.StdEncoding.EncodeToString(canonical)

	// The SignedEntryTimestamp covers the canonicalized JCS form of the
	// {body, integratedTime, logIndex, logID} payload — the shape
	// sigstore-go's tlog.VerifySET reconstructs and checks.
	payload, err := json.Marshal(tlog.RekorPayload{
		Body:           encodedBody,
		IntegratedTime: integratedTime,
		LogIndex:       logIndex,
		LogID:          logIDHex,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling rekor payload: %w", err)
	}
	canonicalPayload, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing rekor payload: %w", err)
	}
	set, err := signer.SignMessage(bytes.NewReader(canonicalPayload))
	if err != nil {
		return nil, fmt.Errorf("signing entry timestamp: %w", err)
	}

	// A one-leaf Merkle tree: the RFC 6962 leaf hash is also the root hash,
	// and the inclusion proof needs no sibling hashes.
	leafHash := sha256.Sum256(append([]byte{0x00}, canonical...))
	checkpoint, err := rekorutil.CreateAndSignCheckpoint(ctx, testRekorHostname, testRekorTreeID, 1, leafHash[:], signer)
	if err != nil {
		return nil, fmt.Errorf("signing checkpoint: %w", err)
	}
	rootHashHex := hex.EncodeToString(leafHash[:])

	return &testLogEntry{
		leafHash: leafHash[:],
		anon: models.LogEntryAnon{
			Body:           encodedBody,
			IntegratedTime: &integratedTime,
			LogID:          &logIDHex,
			LogIndex:       &logIndex,
			Verification: &models.LogEntryAnonVerification{
				SignedEntryTimestamp: set,
				InclusionProof: &models.InclusionProof{
					LogIndex:   conv.Pointer(int64(0)),
					TreeSize:   conv.Pointer(int64(1)),
					RootHash:   &rootHashHex,
					Hashes:     []string{},
					Checkpoint: conv.Pointer(string(checkpoint)),
				},
			},
		},
	}, nil
}

// testRekorHostname and testRekorTreeID form the checkpoint origin
// ("<hostname> - <treeID>"). The trailing numeric tree ID is load-bearing:
// sigstore-go tells a Rekor v1 signed tree head from a v2 checkpoint by that
// suffix, and a v1 entry misread as v2 fails inclusion verification.
const (
	testRekorHostname = "rekor.localhost"
	testRekorTreeID   = int64(1)
)

// testLogID is a transparency log's ID: the SHA-256 of its PKIX-encoded public
// key. It keys both the trusted root's log maps and the SCT's LogID field.
func testLogID(pub crypto.PublicKey) ([sha256.Size]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("marshaling log public key: %w", err)
	}
	return sha256.Sum256(der), nil
}

// TimestampingAuthorities returns none: this deployment has no RFC 3161
// timestamp authority, so signature time comes from the Rekor entry's
// integrated time — the same observer-timestamp source a public-good cosign
// keyless signature relies on.
func (*testSigstore) TimestampingAuthorities() []root.TimestampingAuthority {
	return nil
}

func (s *testSigstore) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{&root.FulcioCertificateAuthority{
		Root:                s.rootCert,
		Intermediates:       []*x509.Certificate{s.intermediateCert},
		ValidityPeriodStart: s.rootCert.NotBefore,
		ValidityPeriodEnd:   s.rootCert.NotAfter,
		URI:                 s.fulcioURL,
	}}
}

func (s *testSigstore) RekorLogs() map[string]*root.TransparencyLog {
	return s.transparencyLog(s.rekorKey.Public(), s.rekorURL)
}

func (s *testSigstore) CTLogs() map[string]*root.TransparencyLog {
	return s.transparencyLog(s.ctlogKey.Public(), s.fulcioURL)
}

func (*testSigstore) transparencyLog(pub crypto.PublicKey, baseURL string) map[string]*root.TransparencyLog {
	logID, err := testLogID(pub)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	return map[string]*root.TransparencyLog{
		hex.EncodeToString(logID[:]): {
			BaseURL:             baseURL,
			ID:                  logID[:],
			ValidityPeriodStart: now.Add(-time.Hour),
			ValidityPeriodEnd:   now.Add(time.Hour),
			HashFunc:            crypto.SHA256,
			PublicKey:           pub,
			SignatureHashFunc:   crypto.SHA256,
		},
	}
}

// PublicKeyVerifier returns an error: this deployment issues certificates, so
// nothing signed against it should be verified as a bare long-lived key.
func (*testSigstore) PublicKeyVerifier(hint string) (root.TimeConstrainedVerifier, error) {
	return nil, fmt.Errorf("test sigstore has no long-lived public keys (hint %q)", hint)
}

// signKeylessArtifact pushes an artifact to an in-process registry and signs it
// keylessly against s, returning the artifact reference and the signing result.
func signKeylessArtifact(t *testing.T, s *testSigstore) (ref, digestStr string, res *Result) {
	t.Helper()
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	ref, digestStr = pushTestArtifact(t, host)
	res, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{
		IdentityToken: identityToken(t, testKeylessSAN),
		FulcioURL:     s.fulcioURL,
		RekorURL:      s.rekorURL,
	})
	require.NoError(t, err, "keyless signing against the test Fulcio and Rekor must succeed")
	return ref, digestStr, res
}

// TestSignOCIKeylessRoundTrip is the contract for the keyless flow: signing
// with an identity token produces a certificate-bearing signature that
// container/verifier discovers from the registry and classifies as keyless.
// Before this existed, SignOCI hard-failed without a key, so the
// certificate-bearing attach path C1 added had no producer.
func TestSignOCIKeylessRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestSigstore(t)

	ref, digestStr, res := signKeylessArtifact(t, s)
	require.NotEmpty(t, res.Bundle)
	require.NotEmpty(t, res.PayloadDigest)

	// The returned bundle carries Fulcio and Rekor material, not a key hint.
	bundles, err := verifier.RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err, "the attached keyless signature must be retrievable")
	require.Len(t, bundles, 1)
	assert.True(t, bundles[0].HasCertificate(),
		"a keyless signature must round-trip through the registry as certificate-bearing")

	// The bundle signs the simple-signing payload digest, which is what the
	// attached layer's own digest is — the cosign convention.
	expectedDigest, err := PayloadDigest(ref, digestStr)
	require.NoError(t, err)
	assert.Equal(t, expectedDigest, res.PayloadDigest)
	assert.Equal(t, strings.TrimPrefix(expectedDigest, "sha256:"), bundles[0].DigestHex)
}

// TestSignOCIKeylessBundleVerifies is the test that matters: a bundle this
// package signs keylessly must satisfy the project's own keyless verification
// policy — DefaultVerifierOptions, i.e. an embedded SCT, a transparency-log
// entry, and an observer timestamp — against the deployment that issued it,
// with the signer identity bound into the policy. Anything less would prove
// only that the annotations parse, not that the signature is trustworthy.
func TestSignOCIKeylessBundleVerifies(t *testing.T) {
	t.Parallel()
	s := newTestSigstore(t)

	ref, _, _ := signKeylessArtifact(t, s)

	bundles, err := verifier.RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	opts, err := verifier.DefaultVerifierOptions()
	require.NoError(t, err)

	// Trust on first use: the chain of trust is verified, and the identity is
	// read back out of the result.
	result, err := verifier.VerifyBundle(bundles[0], s, nil, opts...)
	require.NoError(t, err, "a keyless bundle must verify under the default policy")

	identity, err := verifier.IdentityFromResult(result)
	require.NoError(t, err)
	assert.Equal(t, testKeylessSAN, identity.SignerIdentity)
	assert.Equal(t, testKeylessIssuer, identity.CertIssuer)

	// Pinning that identity must still verify, and a different one must not.
	_, err = verifier.VerifyBundle(bundles[0], s, &identity, opts...)
	require.NoError(t, err, "the recorded identity must re-verify")

	_, err = verifier.VerifyBundle(bundles[0], s, &verifier.Identity{
		SignerIdentity: "someone-else@example.com",
		CertIssuer:     testKeylessIssuer,
	}, opts...)
	require.ErrorIs(t, err, verifier.ErrVerificationFailed,
		"a bundle must not verify against an identity that did not sign it")
}

// TestSignOCIKeylessRejectedByUnrelatedTrustRoot guards against the test above
// passing for the wrong reason: the bundle must verify because the deployment
// that issued its certificate is trusted, not because the policy is lax. A
// second, independent deployment must reject it.
func TestSignOCIKeylessRejectedByUnrelatedTrustRoot(t *testing.T) {
	t.Parallel()
	s := newTestSigstore(t)
	other := newTestSigstore(t)

	ref, _, _ := signKeylessArtifact(t, s)
	bundles, err := verifier.RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	opts, err := verifier.DefaultVerifierOptions()
	require.NoError(t, err)
	_, err = verifier.VerifyBundle(bundles[0], other, nil, opts...)
	require.ErrorIs(t, err, verifier.ErrVerificationFailed,
		"a bundle must not verify against a trust root that did not issue its certificate")
}

// TestSignOCIKeylessAttachesCertificateAndTlogAnnotations pins the annotations
// the keyless path writes. container/verifier classifies a layer as key-signed
// whenever the certificate annotation is absent, and cannot establish signature
// time without the transparency-log annotation, so both are load-bearing rather
// than informational.
func TestSignOCIKeylessAttachesCertificateAndTlogAnnotations(t *testing.T) {
	t.Parallel()
	s := newTestSigstore(t)

	ref, digestStr, _ := signKeylessArtifact(t, s)

	layers := sigLayers(t, ref, digestStr)
	require.Len(t, layers, 1)
	assert.NotEmpty(t, layers[0].Annotations[annotationCosignSignature])

	pemCert := layers[0].Annotations[annotationCosignCertificate]
	require.NotEmpty(t, pemCert, "the keyless path must attach the certificate annotation")
	cert, err := parseLeafCertificate([]byte(pemCert))
	require.NoError(t, err)
	summary, err := fulciocert.SummarizeCertificate(cert)
	require.NoError(t, err)
	assert.Equal(t, testKeylessSAN, summary.SubjectAlternativeName)
	assert.Equal(t, testKeylessIssuer, summary.Issuer)

	require.NotEmpty(t, layers[0].Annotations[annotationCosignBundle],
		"a Rekor entry is mandatory for the keyless flow, so its annotation must be written")
}

// TestSignOCIKeylessReSignAppendsForNewIdentity exercises the dedupe path with
// real Fulcio-issued certificates: keyless signing mints a fresh key and
// certificate every run, so re-signing as the same identity must dedupe on
// identity rather than on key or certificate bytes, while a different identity
// must append.
func TestSignOCIKeylessReSignAppendsForNewIdentity(t *testing.T) {
	t.Parallel()
	s := newTestSigstore(t)

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")
	ref, digestStr := pushTestArtifact(t, host)

	signAs := func(subject string) {
		t.Helper()
		_, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{
			IdentityToken: identityToken(t, subject),
			FulcioURL:     s.fulcioURL,
			RekorURL:      s.rekorURL,
		})
		require.NoError(t, err)
	}

	signAs(testKeylessSAN)
	require.Len(t, sigLayers(t, ref, digestStr), 1)

	signAs(testKeylessSAN)
	assert.Len(t, sigLayers(t, ref, digestStr), 1,
		"re-signing as the same identity must not append a second layer")

	signAs("other@example.com")
	assert.Len(t, sigLayers(t, ref, digestStr), 2,
		"a different signer identity must append its own layer")
}

// TestSignOCIKeylessSurfacesFulcioFailure proves a rejected identity token
// fails signing rather than silently falling back to some other layout.
func TestSignOCIKeylessSurfacesFulcioFailure(t *testing.T) {
	t.Parallel()

	fulcio := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid identity token", http.StatusUnauthorized)
	}))
	t.Cleanup(fulcio.Close)

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	ref, digestStr := pushTestArtifact(t, strings.TrimPrefix(reg.URL, "http://"))

	_, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{
		IdentityToken: identityToken(t, testKeylessSAN),
		FulcioURL:     fulcio.URL,
		// Unreachable, and must stay unreached: Fulcio fails first.
		RekorURL: "http://127.0.0.1:1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "building sigstore bundle")
}

// TestSignOCIRejectsAmbiguousSigningMethod documents the precedence choice:
// supplying both a key and an identity token is a caller error, not a
// preference to be resolved silently.
func TestSignOCIRejectsAmbiguousSigningMethod(t *testing.T) {
	t.Parallel()
	keyPath, _ := writeTestKey(t)

	_, err := NewDefault(nil).SignOCI(t.Context(), testRef, "sha256:"+strings.Repeat("ab", 32), Options{
		Key:           keyPath,
		IdentityToken: identityToken(t, testKeylessSAN),
	})
	require.ErrorIs(t, err, ErrAmbiguousSigningMethod)
}

// TestErrKeyRequiredNamesBothSigningMethods keeps the "nothing provided" error
// actionable: it must point at both ways to sign, or a caller reading it will
// conclude a private key is the only option.
func TestErrKeyRequiredNamesBothSigningMethods(t *testing.T) {
	t.Parallel()

	_, err := NewDefault(nil).SignOCI(t.Context(), testRef, "sha256:abc", Options{})
	require.ErrorIs(t, err, ErrKeyRequired)
	assert.Contains(t, err.Error(), "Key")
	assert.Contains(t, err.Error(), "IdentityToken")
}

// TestKeylessBundleOptionsDefaultToPublicGood pins where URL defaulting
// happens: at signing time, so a zero-valued Options targets the public-good
// deployment and a caller-supplied URL is used verbatim.
func TestKeylessBundleOptionsDefaultToPublicGood(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "https://fulcio.sigstore.dev", DefaultFulcioURL)
	assert.Equal(t, "https://rekor.sigstore.dev", DefaultRekorURL)

	opts := keylessBundleOptions(t.Context(), Options{IdentityToken: "token"})
	require.NotNil(t, opts.CertificateProvider, "keyless signing must go through Fulcio")
	require.Len(t, opts.TransparencyLogs, 1,
		"keyless signing must submit to exactly one transparency log")
	require.NotNil(t, opts.CertificateProviderOptions)
	assert.Equal(t, "token", opts.CertificateProviderOptions.IDToken)
	assert.Nil(t, opts.TrustedRoot,
		"signing must not verify against a trusted root it cannot scope to the target deployment")
}
