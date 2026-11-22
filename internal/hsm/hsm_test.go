package hsm_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/hsm"
)

func newModule(t *testing.T) *hsm.Module {
	t.Helper()
	v, err := hsm.NewVendor()
	if err != nil {
		t.Fatalf("NewVendor: %v", err)
	}
	m, err := hsm.Manufacture(v, "node-1")
	if err != nil {
		t.Fatalf("Manufacture: %v", err)
	}
	return m
}

// certifyStandInAK installs a self-signed stand-in AK certificate on m. The
// Module API exposes no AK public key, so the test derives it from the CSR
// returned by CreateAK and signs the cert itself. This exercises the Quote
// path (which only needs a non-nil, non-key-carrying akCert) without reaching
// into module internals.
func certifyStandInAK(t *testing.T, m *hsm.Module, csrPEM string) *x509.Certificate {
	t.Helper()
	csr, err := certutil.ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	akPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("AK CSR public key is not ECDSA")
	}
	// A disposable issuer stands in for the platform root that authd would use.
	// The cert's subject key is the AK's, so it matches what Quote signs with;
	// the issuer signature is irrelevant to the check under test.
	issuer, err := certutil.NewSelfSignedRoot("stand-in-platform-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	akDer, err := certutil.NewCertSignedBy(issuer.Cert, issuer.Key, akPub, certutil.IssueOptions{
		CN:   "AK/node-1",
		TTL:  time.Hour,
		Role: certutil.RoleAK,
	})
	if err != nil {
		t.Fatalf("NewCertSignedBy: %v", err)
	}
	akCert, err := x509.ParseCertificate(akDer)
	if err != nil {
		t.Fatal(err)
	}
	akPEM := certutil.EncodeCertPEM(akCert.Raw)
	if err := m.BindAKCert(akPEM, []string{certutil.EncodeCertPEM(issuer.Cert.Raw)}); err != nil {
		t.Fatalf("BindAKCert: %v", err)
	}
	return akCert
}

func TestManufactureAndCSRs(t *testing.T) {
	m := newModule(t)

	ekPEM, ekRoots := m.EKChainPEM()
	if _, err := certutil.ParseCertPEM(ekPEM); err != nil {
		t.Fatalf("EK cert PEM: %v", err)
	}
	if len(ekRoots) == 0 {
		t.Fatal("EKChainPEM returned no roots")
	}
	if m.EKFingerprint() == "" {
		t.Fatal("EKFingerprint is empty")
	}

	akCSRPEM, err := m.CreateAK("node-1")
	if err != nil {
		t.Fatalf("CreateAK: %v", err)
	}
	if _, err := certutil.ParseCSR(akCSRPEM); err != nil {
		t.Fatalf("AK CSR: %v", err)
	}

	tlsCSR, caCSR, err := m.NodeCSRs("node-1")
	if err != nil {
		t.Fatalf("NodeCSRs: %v", err)
	}
	for name, csr := range map[string]string{"tls": tlsCSR, "ca": caCSR} {
		if _, err := certutil.ParseCSR(csr); err != nil {
			t.Fatalf("%s CSR: %v", name, err)
		}
	}
}

// TestQuoteFailsBeforeAKExists covers the uncertified state reachable through
// the public API: a module that has not called CreateAK has no AK at all, so
// Quote must fail. (CreateAK itself installs an EK-signed AK certificate, so
// after that call Quote already has a cert to return -- see
// TestCreateAKSelfCertifiesBelow.)
func TestQuoteFailsBeforeAKExists(t *testing.T) {
	m := newModule(t)
	_, _, _, err := m.Quote(hsm.AttestStatement{Nonce: "n", Node: "node-1", IssuedAt: 1})
	if err == nil {
		t.Fatal("Quote succeeded with no attestation key")
	}
}

// TestCreateAKSelfCertifiesBelow documents production behavior: CreateAK signs
// the AK certificate with the EK inside the module, so Quote works even before
// authd's BindAKCert is called. A caller wanting "must be certified by authd
// first" cannot get that from this API.
func TestCreateAKSelfCertifiesBelow(t *testing.T) {
	m := newModule(t)
	if _, err := m.CreateAK("node-1"); err != nil {
		t.Fatalf("CreateAK: %v", err)
	}
	if sig, certPEM, _, err := m.Quote(hsm.AttestStatement{Nonce: "n", Node: "node-1", IssuedAt: 1}); err != nil {
		t.Fatalf("Quote after CreateAK (EK self-certified): %v", err)
	} else if sig == "" || certPEM == "" {
		t.Fatal("Quote returned empty material")
	}
}

func TestQuoteVerifiesWithAKCert(t *testing.T) {
	m := newModule(t)
	csrPEM, err := m.CreateAK("node-1")
	if err != nil {
		t.Fatalf("CreateAK: %v", err)
	}
	akCert := certifyStandInAK(t, m, csrPEM)

	stmt := hsm.AttestStatement{
		Nonce:     "nonce-123",
		Node:      "node-1",
		TLSKey:    "aa",
		NodeCAKey: "bb",
		IssuedAt:  time.Now().Unix(),
	}
	sigHex, akCertPEM, _, err := m.Quote(stmt)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if sigHex == "" {
		t.Fatal("Quote returned an empty signature")
	}

	// The returned cert's key must match the cert we bound.
	returned, err := certutil.ParseCertPEM(akCertPEM)
	if err != nil {
		t.Fatalf("parse returned AK cert: %v", err)
	}
	if !returned.Equal(akCert) {
		t.Fatal("Quote returned a different AK certificate")
	}

	pub, ok := returned.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("AK public key is not ECDSA")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	}
	sum := sha256.Sum256(stmt.Canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatal("Quote signature does not verify over AttestStatement.Canonical()")
	}

	// A tampered statement must not verify.
	tampered := stmt
	tampered.Nonce = "other"
	sum = sha256.Sum256(tampered.Canonical())
	if ecdsa.VerifyASN1(pub, sum[:], sig) {
		t.Fatal("signature verified over a tampered statement")
	}
}

func TestPubHashFromCSRMatchesPubHash(t *testing.T) {
	m := newModule(t)
	tlsCSR, _, err := m.NodeCSRs("node-1")
	if err != nil {
		t.Fatalf("NodeCSRs: %v", err)
	}
	tlsHash, _, err := m.NodeKeyHashes()
	if err != nil {
		t.Fatalf("NodeKeyHashes: %v", err)
	}
	fromCSR, err := hsm.PubHashFromCSR(tlsCSR)
	if err != nil {
		t.Fatalf("PubHashFromCSR: %v", err)
	}
	if fromCSR != tlsHash {
		t.Fatalf("PubHashFromCSR = %q, want NodeKeyHashes tls hash %q", fromCSR, tlsHash)
	}

	csr, err := certutil.ParseCSR(tlsCSR)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := hsm.PubHash(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if direct != fromCSR {
		t.Fatalf("PubHash = %q, PubHashFromCSR = %q", direct, fromCSR)
	}
}
