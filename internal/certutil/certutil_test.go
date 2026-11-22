package certutil_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"meshid/internal/certutil"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := certutil.NewKey()
	if err != nil {
		t.Fatalf("NewKey: %v", err)
	}
	return k
}

func mustRoot(t *testing.T) *certutil.Authority {
	t.Helper()
	a, err := certutil.NewSelfSignedRoot("test-root", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedRoot: %v", err)
	}
	return a
}

func mustIssue(t *testing.T, ca *certutil.Authority, key *ecdsa.PrivateKey, o certutil.IssueOptions) *x509.Certificate {
	t.Helper()
	der, err := ca.SignCert(&key.PublicKey, o)
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

func workloadOptions(node, svc string) certutil.IssueOptions {
	return certutil.IssueOptions{
		CN:     svc,
		URISAN: "spiffe://" + certutil.MeshDomain + "/ns/ns1/svc/" + svc + "/node/" + node + "/inst/i1",
		TTL:    5 * time.Minute,
		Role:   certutil.RoleWorkload,
		Meta: &certutil.Meta{
			Namespace: "ns1",
			Service:   svc,
			Node:      node,
			Instance:  "i1",
			Mode:      certutil.ModeDegraded,
		},
	}
}

func TestCheckNodeScope(t *testing.T) {
	root := mustRoot(t)
	scoped, err := root.NewIntermediate("node-2-ca", time.Hour, &certutil.Scope{Node: "node-2", MaxTTLSec: 3600})
	if err != nil {
		t.Fatalf("NewIntermediate: %v", err)
	}

	// A CA scoped to node-2 must not mint a leaf for node-1.
	wrongNode := mustIssue(t, scoped, mustKey(t), workloadOptions("node-1", "svc1"))
	err = certutil.CheckNodeScope([]*x509.Certificate{wrongNode, scoped.Cert})
	if !errors.Is(err, certutil.ErrScopeViolation) {
		t.Fatalf("leaf for node-1 under node-2 CA: got %v, want ErrScopeViolation", err)
	}

	// The matching node passes.
	rightNode := mustIssue(t, scoped, mustKey(t), workloadOptions("node-2", "svc1"))
	if err := certutil.CheckNodeScope([]*x509.Certificate{rightNode, scoped.Cert}); err != nil {
		t.Fatalf("leaf for node-2 under node-2 CA: %v", err)
	}

	// A degraded leaf under an unscoped CA is also a violation.
	unscoped, err := root.NewIntermediate("online-ca", time.Hour, nil)
	if err != nil {
		t.Fatalf("NewIntermediate: %v", err)
	}
	degraded := mustIssue(t, unscoped, mustKey(t), workloadOptions("node-1", "svc1"))
	if degraded == nil {
		t.Fatal("nil leaf")
	}
	err = certutil.CheckNodeScope([]*x509.Certificate{degraded, unscoped.Cert})
	if !errors.Is(err, certutil.ErrScopeViolation) {
		t.Fatalf("degraded leaf under unscoped CA: got %v, want ErrScopeViolation", err)
	}
}

func TestRevocationMatching(t *testing.T) {
	root := mustRoot(t)
	leaf := mustIssue(t, root, mustKey(t), workloadOptions("node-1", "svc1"))
	serial := leaf.SerialNumber.Text(16)

	cases := []struct {
		name    string
		entries []certutil.Revocation
		want    bool
	}{
		{"serial", []certutil.Revocation{{Serial: serial, Reason: "serial"}}, true},
		{"serial case-insensitive", []certutil.Revocation{{Serial: strings.ToUpper(serial), Reason: "serial"}}, true},
		{"different serial", []certutil.Revocation{{Serial: "deadbeef"}}, false},
		{"node", []certutil.Revocation{{Node: "node-1", Reason: "node"}}, true},
		{"other node", []certutil.Revocation{{Node: "node-2"}}, false},
		{"node+service", []certutil.Revocation{{Node: "node-1", Service: "svc1", Reason: "svc"}}, true},
		{"node+other service", []certutil.Revocation{{Node: "node-1", Service: "svc2"}}, false},
		{"node+service+instance", []certutil.Revocation{{Node: "node-1", Service: "svc1", Instance: "i1", Reason: "inst"}}, true},
		{"node+service+other instance", []certutil.Revocation{{Node: "node-1", Service: "svc1", Instance: "i2"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := certutil.RevocationList{Version: 1, Entries: tc.entries}
			got, why := list.Revoked(leaf)
			if got != tc.want {
				t.Fatalf("Revoked = %v (%q), want %v", got, why, tc.want)
			}
			if got && why == "" {
				t.Fatal("revoked without a reason")
			}
		})
	}
}

func TestSignedBundleVerification(t *testing.T) {
	root := mustRoot(t)
	pub := &root.Key.PublicKey
	b := certutil.Bundle{
		Version:   7,
		Roots:     []string{certutil.EncodeCertPEM(root.Cert.Raw)},
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}

	sb, err := certutil.SignBundle(root.Key, root.ID, "", b)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	if err := sb.Verify(pub); err != nil {
		t.Fatalf("Verify fresh bundle: %v", err)
	}

	// Changing any signed field must invalidate the signature.
	flippedRoots := *sb
	flippedRoots.Roots = append([]string{}, sb.Roots...)
	flippedRoots.Roots[0] = certutil.EncodeCertPEM(mustRoot(t).Cert.Raw)
	if err := flippedRoots.Verify(pub); err == nil {
		t.Fatal("bundle with replaced roots verified")
	}

	flippedVersion := *sb
	flippedVersion.Version++
	if err := flippedVersion.Verify(pub); err == nil {
		t.Fatal("bundle with bumped version verified")
	}

	if err := sb.Verify(&mustKey(t).PublicKey); err == nil {
		t.Fatal("bundle verified under the wrong public key")
	}
}

// TestLifetimeIgnoresBackdate verifies the lifetime semantics around the
// clock-skew backdate. Two properties matter:
//
//  1. NotAfter is measured from "now", not from the backdated NotBefore, so
//     absolute expiry is not pushed out.
//  2. The validity window NotAfter-NotBefore should equal the requested TTL
//     exactly, because CheckNodeScope compares that window against a node CA's
//     MaxTTLSec.
//
// A backdated NotBefore must not lengthen the validity window: the window is
// exactly TTL, and the whole window is merely shifted earlier for clock-skew
// tolerance. CheckNodeScope relies on this.
func TestLifetimeIgnoresBackdate(t *testing.T) {
	const ttl = 10 * time.Minute
	root := mustRoot(t)
	before := time.Now()
	leaf := mustIssue(t, root, mustKey(t), certutil.IssueOptions{
		CN:  "ttl-test",
		TTL: ttl,
	})
	after := time.Now()

	if !leaf.NotBefore.Before(before) {
		t.Fatalf("NotBefore %v is not backdated relative to %v", leaf.NotBefore, before)
	}
	// Absolute expiry is still bounded by now+TTL. X.509 stores seconds only,
	// so allow a second of truncation on either side.
	lo, hi := before.Add(ttl).Add(-time.Second), after.Add(ttl).Add(time.Second)
	if leaf.NotAfter.Before(lo) || leaf.NotAfter.After(hi) {
		t.Fatalf("NotAfter = %v, want about now+%v", leaf.NotAfter, ttl)
	}

	// The *window* may be TTL+skew because NotBefore is backdated; the usable
	// lifetime from issuance must still be exactly TTL.
	if got := leaf.NotAfter.Sub(before); got < ttl-time.Second || got > ttl+time.Second {
		t.Fatalf("usable lifetime = %v, want about %v", got, ttl)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got > ttl+certutil.MaxSkew {
		t.Fatalf("window = %v exceeds TTL+skew (%v)", got, ttl+certutil.MaxSkew)
	}
}
