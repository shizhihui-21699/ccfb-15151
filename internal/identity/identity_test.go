package identity_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/identity"
)

// fixture builds a throwaway root -> node CA -> leaf hierarchy and returns
// everything a Creds needs plus the trust inputs for VerifySelf.
type fixture struct {
	root    *certutil.Authority
	ca      *certutil.Authority
	key     certutil.IssueOptions
	chainPB []string
	roots   *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root, err := certutil.NewSelfSignedRoot("test-root", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedRoot: %v", err)
	}
	ca, err := root.NewIntermediate("node-1-ca", 12*time.Hour, &certutil.Scope{Node: "node-1", MaxTTLSec: 3600})
	if err != nil {
		t.Fatalf("NewIntermediate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	return &fixture{
		root:    root,
		ca:      ca,
		chainPB: []string{certutil.EncodeCertPEM(ca.Cert.Raw)},
		roots:   roots,
	}
}

func (f *fixture) leaf(t *testing.T, ttl time.Duration) (string, *certutil.Meta) {
	t.Helper()
	key, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{
		Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1",
		Mode: certutil.ModeDegraded,
	}
	der, err := f.ca.SignCert(&key.PublicKey, certutil.IssueOptions{
		CN:     "svc1",
		URISAN: "spiffe://" + certutil.MeshDomain + "/ns/ns1/svc/svc1/node/node-1/inst/inst-1",
		TTL:    ttl,
		Role:   certutil.RoleWorkload,
		Meta:   meta,
	})
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	return certutil.EncodeCertPEM(der), meta
}

func TestNewAndSetKey(t *testing.T) {
	f := newFixture(t)
	key, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1", Mode: certutil.ModeDegraded}
	der, err := f.ca.SignCert(&key.PublicKey, certutil.IssueOptions{
		CN: "svc1", TTL: time.Minute, Role: certutil.RoleWorkload, Meta: meta,
	})
	if err != nil {
		t.Fatal(err)
	}

	creds, err := identity.New(certutil.EncodeCertPEM(der), f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := creds.SetKey(key); err != nil {
		t.Fatalf("SetKey with matching key: %v", err)
	}
}

// publicKeyer wraps a key and exposes Public() any; verifyKeyMatch compares the
// public key only for values satisfying that exact interface.
type publicKeyer struct{ key *ecdsa.PrivateKey }

func (p publicKeyer) Public() any { return &p.key.PublicKey }

func TestSetKeyMismatchedKeyErrors(t *testing.T) {
	f := newFixture(t)
	leafKey, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1", Mode: certutil.ModeDegraded}
	der, err := f.ca.SignCert(&leafKey.PublicKey, certutil.IssueOptions{
		CN: "svc1", TTL: time.Minute, Role: certutil.RoleWorkload, Meta: meta,
	})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := identity.New(certutil.EncodeCertPEM(der), f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Correct key, but surfaced through the Public() any interface.
	if err := creds.SetKey(publicKeyer{leafKey}); err != nil {
		t.Fatalf("SetKey with matching public-keyer: %v", err)
	}
	// A different key must be rejected.
	other, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.SetKey(publicKeyer{other}); err == nil {
		t.Fatal("SetKey accepted a mismatched public-keyer")
	}
}

// A mismatched plain *ecdsa.PrivateKey must be rejected at SetKey, not at the
// first handshake.
func TestSetKeyMismatchedECDSAKey(t *testing.T) {
	f := newFixture(t)
	leafKey, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1", Mode: certutil.ModeDegraded}
	der, err := f.ca.SignCert(&leafKey.PublicKey, certutil.IssueOptions{
		CN: "svc1", TTL: time.Minute, Role: certutil.RoleWorkload, Meta: meta,
	})
	if err != nil {
		t.Fatal(err)
	}
	creds, err := identity.New(certutil.EncodeCertPEM(der), f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	other, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.SetKey(other); err == nil {
		t.Fatal("SetKey accepted a mismatched *ecdsa.PrivateKey")
	}
}

func TestRenewAtIsTwoThirdsThroughLifetime(t *testing.T) {
	f := newFixture(t)
	const ttl = 90 * time.Second
	leafPEM, meta := f.leaf(t, ttl)

	creds, err := identity.New(leafPEM, f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf, err := certutil.ParseCertPEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	// renewAt is 2/3 through the certificate's own validity window, leaving
	// one third of it before NotAfter.
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	want := leaf.NotAfter.Add(-lifetime / 3)
	if got := creds.RenewAt(); !got.Equal(want) {
		t.Fatalf("RenewAt = %v, want %v", got, want)
	}
	if remaining := creds.ExpiresAt().Sub(creds.RenewAt()); remaining != lifetime/3 {
		t.Fatalf("time left after RenewAt = %v, want %v", remaining, lifetime/3)
	}
}

func TestRotateKeepsOldLeaf(t *testing.T) {
	f := newFixture(t)
	key, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1", Mode: certutil.ModeDegraded}
	issue := func(ttl time.Duration) string {
		der, err := f.ca.SignCert(&key.PublicKey, certutil.IssueOptions{
			CN: "svc1", TTL: ttl, Role: certutil.RoleWorkload, Meta: meta,
		})
		if err != nil {
			t.Fatalf("SignCert: %v", err)
		}
		return certutil.EncodeCertPEM(der)
	}

	creds, err := identity.New(issue(time.Minute), f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := creds.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	oldSerial := creds.Serial()
	oldCert, err := creds.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	if err := creds.Rotate(issue(2*time.Minute), f.chainPB, meta, time.Time{}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	newSerial := creds.Serial()
	if newSerial == oldSerial {
		t.Fatal("Rotate did not change the serial")
	}
	if creds.Generation() != 1 {
		t.Fatalf("Generation = %d, want 1", creds.Generation())
	}
	// The old tls.Certificate handle must still be usable (long-lived conns).
	if oldCert == nil || oldCert.Leaf == nil || oldCert.Leaf.SerialNumber.Text(16) != oldSerial {
		t.Fatal("old leaf no longer available after rotation")
	}
	newCert, err := creds.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after rotate: %v", err)
	}
	if newCert.Leaf.SerialNumber.Text(16) != newSerial {
		t.Fatal("GetCertificate did not return the rotated leaf")
	}
}

func TestVerifySelfRejectsRevoked(t *testing.T) {
	f := newFixture(t)
	key, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1", Mode: certutil.ModeDegraded}
	der, err := f.ca.SignCert(&key.PublicKey, certutil.IssueOptions{
		CN: "svc1", TTL: time.Minute, Role: certutil.RoleWorkload, Meta: meta,
	})
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := certutil.EncodeCertPEM(der)

	creds, err := identity.New(leafPEM, f.chainPB, meta, time.Time{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := creds.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	now := time.Now()
	if err := creds.VerifySelf(f.roots, nil, now); err != nil {
		t.Fatalf("VerifySelf (no revocation): %v", err)
	}

	leaf, err := certutil.ParseCertPEM(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	rev := &certutil.RevocationList{
		Version: 1,
		Entries: []certutil.Revocation{{Serial: leaf.SerialNumber.Text(16), Reason: "test"}},
	}
	if err := creds.VerifySelf(f.roots, rev, now); err == nil {
		t.Fatal("VerifySelf accepted a revoked certificate")
	}
}
