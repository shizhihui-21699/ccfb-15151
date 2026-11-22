package mesh_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/mesh"
)

// staticTrust is a minimal in-memory mesh.TrustSource for tests.
type staticTrust struct {
	roots   []string
	inter   []string
	rev     *mesh.RevocationSnapshot
	version int
}

func (s staticTrust) RootsAndIntermediates() ([]string, []string) { return s.roots, s.inter }
func (s staticTrust) Revocations() *mesh.RevocationSnapshot       { return s.rev }
func (s staticTrust) BundleVersion() int                          { return s.version }

type hierarchy struct {
	root *certutil.Authority
	ca   *certutil.Authority
	key  *ecdsa.PrivateKey
}

func newHierarchy(t *testing.T) *hierarchy {
	t.Helper()
	root, err := certutil.NewSelfSignedRoot("root", 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSelfSignedRoot: %v", err)
	}
	ca, err := root.NewIntermediate("node-1-ca", 12*time.Hour, &certutil.Scope{Node: "node-1", MaxTTLSec: 3600})
	if err != nil {
		t.Fatalf("NewIntermediate: %v", err)
	}
	key, err := certutil.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return &hierarchy{root: root, ca: ca, key: key}
}

func (h *hierarchy) trust() staticTrust {
	return staticTrust{
		roots: []string{certutil.EncodeCertPEM(h.root.Cert.Raw)},
		inter: []string{certutil.EncodeCertPEM(h.ca.Cert.Raw)},
	}
}

func (h *hierarchy) leaf(t *testing.T, o certutil.IssueOptions) *x509.Certificate {
	t.Helper()
	der, err := h.ca.SignCert(&h.key.PublicKey, o)
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return c
}

func workloadLeafOptions() certutil.IssueOptions {
	return certutil.IssueOptions{
		CN:     "svc1",
		URISAN: "spiffe://" + certutil.MeshDomain + "/ns/ns1/svc/svc1/node/node-1/inst/inst-1",
		TTL:    5 * time.Minute,
		EKU:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		Role:   certutil.RoleWorkload,
		Meta: &certutil.Meta{
			Namespace: "ns1", Service: "svc1", Node: "node-1", Instance: "inst-1",
			Mode: certutil.ModeDegraded, BinarySHA256: "abc",
		},
	}
}

func TestVerifyCertsAcceptsValidLeaf(t *testing.T) {
	h := newHierarchy(t)
	leaf := h.leaf(t, workloadLeafOptions())

	v := mesh.NewVerifier(mesh.VerifierConfig{Trust: h.trust(), Expect: mesh.ExpectClient})
	id, err := v.VerifyCerts([]*x509.Certificate{leaf}, "")
	if err != nil {
		t.Fatalf("VerifyCerts: %v", err)
	}
	if id.Namespace != "ns1" || id.Service != "svc1" || id.Node != "node-1" || id.Instance != "inst-1" {
		t.Fatalf("extracted identity = %+v", id)
	}
	if id.Mode != certutil.ModeDegraded {
		t.Fatalf("Mode = %q, want degraded", id.Mode)
	}
	if id.Role != certutil.RoleWorkload {
		t.Fatalf("Role = %q, want workload", id.Role)
	}
	if id.Chain[0] != leaf || len(id.Chain) < 3 {
		t.Fatalf("Chain length = %d, want leaf + intermediate + root", len(id.Chain))
	}
}

func TestVerifyCertsRejectsExpiredLeaf(t *testing.T) {
	h := newHierarchy(t)
	o := workloadLeafOptions()
	// Issue a leaf that expired an hour ago, with a matching backdated start.
	o.TTL = -1 * time.Hour
	leaf := h.leaf(t, o)

	v := mesh.NewVerifier(mesh.VerifierConfig{Trust: h.trust()})
	if _, err := v.VerifyCerts([]*x509.Certificate{leaf}, ""); err == nil {
		t.Fatal("VerifyCerts accepted an expired leaf")
	}
}

func TestVerifyCertsRejectsRevokedLeaf(t *testing.T) {
	h := newHierarchy(t)
	leaf := h.leaf(t, workloadLeafOptions())

	tr := h.trust()
	tr.rev = &mesh.RevocationSnapshot{
		Version: 3,
		Entries: []mesh.RevocationEntry{{Node: "node-1", Reason: "compromised"}},
	}
	v := mesh.NewVerifier(mesh.VerifierConfig{Trust: tr})
	if _, err := v.VerifyCerts([]*x509.Certificate{leaf}, ""); err == nil {
		t.Fatal("VerifyCerts accepted a revoked leaf")
	}
}

func TestRequireRoleRejectsNodeAgent(t *testing.T) {
	h := newHierarchy(t)
	o := workloadLeafOptions()
	o.Role = certutil.RoleNodeAgent
	leaf := h.leaf(t, o)

	v := mesh.NewVerifier(mesh.VerifierConfig{
		Trust:       h.trust(),
		Expect:      mesh.ExpectClient,
		RequireRole: certutil.RoleWorkload,
	})
	_, err := v.VerifyCerts([]*x509.Certificate{leaf}, "")
	if err == nil {
		t.Fatal("workload verifier accepted a node-agent certificate")
	}
}

func TestExpectClientVsServerEKU(t *testing.T) {
	h := newHierarchy(t)

	clientLeaf := h.leaf(t, func() certutil.IssueOptions {
		o := workloadLeafOptions()
		o.EKU = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		return o
	}())
	serverLeaf := h.leaf(t, func() certutil.IssueOptions {
		o := workloadLeafOptions()
		o.EKU = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		return o
	}())

	clientV := mesh.NewVerifier(mesh.VerifierConfig{Trust: h.trust(), Expect: mesh.ExpectClient})
	if _, err := clientV.VerifyCerts([]*x509.Certificate{clientLeaf}, ""); err != nil {
		t.Fatalf("ExpectClient rejected a client-auth leaf: %v", err)
	}
	if _, err := clientV.VerifyCerts([]*x509.Certificate{serverLeaf}, ""); err == nil {
		t.Fatal("ExpectClient accepted a server-auth-only leaf")
	}

	serverV := mesh.NewVerifier(mesh.VerifierConfig{Trust: h.trust(), Expect: mesh.ExpectServer})
	if _, err := serverV.VerifyCerts([]*x509.Certificate{serverLeaf}, ""); err != nil {
		t.Fatalf("ExpectServer rejected a server-auth leaf: %v", err)
	}
	if _, err := serverV.VerifyCerts([]*x509.Certificate{clientLeaf}, ""); err == nil {
		t.Fatal("ExpectServer accepted a client-auth-only leaf")
	}
}
