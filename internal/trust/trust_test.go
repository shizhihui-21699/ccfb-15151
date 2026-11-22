package trust

import (
	"crypto/x509"
	"testing"
	"time"

	"meshid/internal/certutil"
)

// buildTenant creates a root and a signed bundle naming it, the way authd
// publishes on first boot.
func buildTenant(t *testing.T) (*certutil.Authority, *certutil.SignedBundle) {
	t.Helper()
	root, err := certutil.NewSelfSignedRoot("trust-test-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rootPEM := certutil.EncodeCertPEM(root.Cert.Raw)
	b, err := certutil.SignBundle(root.Key, root.ID, rootPEM, certutil.Bundle{
		Version:   3,
		Roots:     []string{rootPEM},
		UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, b
}

func TestBundleVerifiesAgainstPinnedRoot(t *testing.T) {
	root, b := buildTenant(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	if err := VerifyBundle(b, pool); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
}

func TestBundleSignedByOtherRootRejected(t *testing.T) {
	_, b := buildTenant(t)
	other, err := certutil.NewSelfSignedRoot("attacker-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(other.Cert)
	if err := VerifyBundle(b, pool); err == nil {
		t.Fatal("bundle signed by an unpinned root was accepted")
	}
}

// A bundle cannot bootstrap trust in itself: replacing its roots with an
// attacker root and re-signing still fails when the verifier pins the real
// root, which is the property nodes rely on after first boot.
func TestSwappedRootBundleRejected(t *testing.T) {
	root, _ := buildTenant(t)
	pinned := x509.NewCertPool()
	pinned.AddCert(root.Cert)

	attacker, err := certutil.NewSelfSignedRoot("attacker-root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	attackerPEM := certutil.EncodeCertPEM(attacker.Cert.Raw)
	forged, err := certutil.SignBundle(attacker.Key, attacker.ID, attackerPEM, certutil.Bundle{
		Version: 999, Roots: []string{attackerPEM}, UpdatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundle(forged, pinned); err == nil {
		t.Fatal("attacker bundle replaced the pinned trust root")
	}
}

func TestTamperedBundleRejected(t *testing.T) {
	root, b := buildTenant(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	b.Version++ // change a signed field
	if err := VerifyBundle(b, pool); err == nil {
		t.Fatal("tampered bundle accepted")
	}
}

func TestRevocationSnapshotAndBundleCoexist(t *testing.T) {
	_, b := buildTenant(t)
	st := NewStore()
	if err := st.SetBundle(b); err != nil {
		t.Fatal(err)
	}
	st.SetRevocations(&certutil.RevocationList{
		Version: 7,
		Entries: []certutil.Revocation{{Node: "node-9", Reason: "compromised"}},
	})
	snap := st.Load()
	if snap.BundleVersion != 3 || snap.Revocations == nil || snap.Revocations.Version != 7 {
		t.Fatalf("unexpected snapshot: bundle=%d rev=%v", snap.BundleVersion, snap.Revocations)
	}
	if len(snap.Revocations.Entries) != 1 || snap.Revocations.Entries[0].Node != "node-9" {
		t.Fatalf("revocation entry lost: %+v", snap.Revocations.Entries)
	}
	// Replacing the bundle must not drop the revocation list.
	if err := st.SetBundle(b); err != nil {
		t.Fatal(err)
	}
	if st.Load().Revocations == nil {
		t.Fatal("bundle replacement dropped revocations")
	}
}

func TestPolicySignatureChecked(t *testing.T) {
	root, _ := buildTenant(t)
	rootPEM := certutil.EncodeCertPEM(root.Cert.Raw)
	pol, err := certutil.SignPolicy(root.Key, root.ID, rootPEM, certutil.Policy{
		Version: 1, DefaultMaxTTLSec: 60,
		Grants: []certutil.ServiceGrant{{Namespace: "a", Service: "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	if err := VerifyPolicy(pol, pool); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	pol.Policy.Grants[0].Service = "evil"
	if err := VerifyPolicy(pol, pool); err == nil {
		t.Fatal("tampered policy accepted")
	}
}
