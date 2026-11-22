package authd

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/procinfo"
)

// attestedKeys are the public-key hashes proven by the AK quote.
type attestedKeys struct {
	TLSKey        string
	NodeCAKey     string
	EKFingerprint string
	AKKeyID       string
}

// verifyAttestation performs the complete node-identity proof:
//
//  1. the EK certificate chains to a platform vendor root — the machine is a
//     genuine machine and the EK is its fused identity;
//  2. the AK certificate was signed by that EK — the AK lives in the same
//     hardware module;
//  3. the AK signed our fresh, single-use nonce together with the TLS and
//     node-CA public keys from the CSRs — the presenter owns the AK and the
//     keys, and this is not a replayed transcript from another enrollment.
//
// The nonce is consumed atomically before any of this, so a recorded exchange
// cannot be replayed, and the key binding means it cannot be re-targeted at a
// different TLS key even if it could.
func (s *Server) verifyAttestation(req *api.EnrollRequest) (*attestedKeys, string, error) {
	at := req.Attestation
	if at.Nonce == "" || at.Sig == "" {
		return nil, api.CodeAttestationFail, errors.New("incomplete attestation")
	}
	ch, err := s.st.ConsumeChallenge(at.Nonce)
	if err != nil {
		return nil, api.CodeAttestationFail, fmt.Errorf("unknown, used or expired challenge: %w", err)
	}
	if ch.Node != "" && ch.Node != req.Node {
		return nil, api.CodeAttestationFail, errors.New("challenge was issued for a different node")
	}

	ek, err := certutil.ParseCertPEM(at.EKCertPEM)
	if err != nil {
		return nil, api.CodeAttestationFail, fmt.Errorf("EK certificate: %w", err)
	}
	if role, ok := certutil.RoleOf(ek); !ok || role != certutil.RoleEK {
		return nil, api.CodeAttestationFail, errors.New("EK certificate has the wrong role")
	}
	vendor := s.cfg.VendorRoots
	if vendor == nil {
		return nil, api.CodeUnavailable, errors.New("no platform roots configured")
	}
	for _, p := range at.EKChainPEM {
		vendor = vendor.Clone()
		vendor.AppendCertsFromPEM([]byte(p))
	}
	if _, err := ek.Verify(x509.VerifyOptions{
		Roots: vendor, CurrentTime: s.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, api.CodeAttestationFail, fmt.Errorf("EK does not chain to a platform root: %w", err)
	}

	ak, err := certutil.ParseCertPEM(at.AKCertPEM)
	if err != nil {
		return nil, api.CodeAttestationFail, fmt.Errorf("AK certificate: %w", err)
	}
	inter := x509.NewCertPool()
	for _, p := range at.AKChainPEM {
		if !inter.AppendCertsFromPEM([]byte(p)) {
			return nil, api.CodeAttestationFail, errors.New("malformed AK chain")
		}
	}
	akChains, err := ak.Verify(x509.VerifyOptions{
		Roots: vendor, Intermediates: inter, CurrentTime: s.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, api.CodeAttestationFail, fmt.Errorf("AK does not chain to platform root: %w", err)
	}
	// The AK must be *this* EK's child: a direct issuer check, not merely
	// "both chain to the vendor". Otherwise any machine's AK would do.
	if len(akChains[0]) < 2 || !akChains[0][1].Equal(ek) {
		return nil, api.CodeAttestationFail, errors.New("AK was not certified by the presented EK")
	}

	stmt := at.Statement
	if stmt.Nonce != ch.Nonce || stmt.Node != req.Node {
		return nil, api.CodeAttestationFail, errors.New("quote is not bound to this nonce and node")
	}
	// Bound the age of the statement so a valid nonce cannot be paired with
	// a long-stale statement.
	if d := s.now().Sub(time.Unix(stmt.IssuedAt, 0)).Abs(); d > 2*time.Minute {
		return nil, api.CodeAttestationFail, fmt.Errorf("attestation statement is %s old", d)
	}
	if err := verifyQuoteSignature(ak, stmt, at.Sig); err != nil {
		return nil, api.CodeAttestationFail, err
	}
	tlsHash, err := hsm.PubHashFromCSR(req.TLSKeyCSRPEM)
	if err != nil {
		return nil, api.CodeBadRequest, err
	}
	caHash, err := hsm.PubHashFromCSR(req.NodeCAKeyCSRPEM)
	if err != nil {
		return nil, api.CodeBadRequest, err
	}
	if tlsHash != stmt.TLSKey || caHash != stmt.NodeCAKey {
		return nil, api.CodeAttestationFail, errors.New("CSR keys differ from the keys the AK attested")
	}

	// Inventory check: the node name must be registered against this exact
	// EK fingerprint. Attestation alone proves "some genuine machine"; it
	// cannot prove "the machine we racked as node-7". Without this an
	// attacker with any valid machine could enroll under a stolen name.
	rec, err := s.st.NodeRecordFor(req.Node)
	if err != nil {
		return nil, api.CodeUnauthorized, fmt.Errorf("node %q is not registered for enrollment", req.Node)
	}
	if rec.EKFingerprint != certutil.FingerprintCert(ek) {
		return nil, api.CodeAttestationFail, fmt.Errorf("EK does not match the registered hardware for %q", req.Node)
	}

	ekPub, _ := ek.PublicKey.(*ecdsa.PublicKey)
	akPub, _ := ak.PublicKey.(*ecdsa.PublicKey)
	if ekPub == nil || akPub == nil {
		return nil, api.CodeAttestationFail, errors.New("non-ECDSA platform keys")
	}
	s.audit(map[string]any{"kind": "attest", "node": req.Node, "outcome": "verified",
		"ek": certutil.FingerprintCert(ek), "ak": certutil.KeyID(akPub)})
	return &attestedKeys{
		TLSKey: tlsHash, NodeCAKey: caHash,
		EKFingerprint: certutil.FingerprintCert(ek),
		AKKeyID:       certutil.KeyID(akPub),
	}, "", nil
}

func verifyQuoteSignature(ak *x509.Certificate, stmt hsm.AttestStatement, sigHex string) error {
	sig, err := decodeHex(sigHex)
	if err != nil {
		return errors.New("bad quote signature encoding")
	}
	pub, ok := ak.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("AK key is not ECDSA")
	}
	sum := sha256.Sum256(stmt.Canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("quote signature does not verify under the AK")
	}
	return nil
}

// checkGrant enforces central policy against process facts.
func checkGrant(g certutil.ServiceGrant, f procinfo.Facts) error {
	if g.RequireUID != nil && *g.RequireUID != f.UID {
		return fmt.Errorf("uid %d does not match required %d", f.UID, *g.RequireUID)
	}
	if g.BinarySHA256 != "" && g.BinarySHA256 != f.BinarySHA {
		return fmt.Errorf("binary hash does not match policy for %s/%s", g.Namespace, g.Service)
	}
	if f.BinarySHA == "" {
		return errors.New("process facts carry no binary hash")
	}
	return nil
}

func (s *Server) leafTTL(g certutil.ServiceGrant, pol *certutil.Policy) time.Duration {
	ttl := s.cfg.LeafTTL
	if pol.DefaultMaxTTLSec > 0 && ttl > time.Duration(pol.DefaultMaxTTLSec)*time.Second {
		ttl = time.Duration(pol.DefaultMaxTTLSec) * time.Second
	}
	if g.MaxTTLSec > 0 && ttl > time.Duration(g.MaxTTLSec)*time.Second {
		ttl = time.Duration(g.MaxTTLSec) * time.Second
	}
	return ttl
}

type issuedCert struct {
	leaf       *x509.Certificate
	chain      []*x509.Certificate
	meta       certutil.Meta
	scope      certutil.Scope
	renewAfter time.Time
}

// issueNodeAgent issues the agent's TLS certificate.
func (s *Server) issueNodeAgent(ca *certutil.Authority, node string, csr *x509.CertificateRequest) (*issuedCert, error) {
	if ca == nil {
		return nil, errors.New("no node issuing CA")
	}
	meta := certutil.Meta{
		Node: node, Instance: "agent", Mode: certutil.ModeOnline,
		Issuer: s.cfg.ReplicaID, PolicyVersion: s.policyVersion(),
	}
	der, err := certutil.NewCertSignedByCA(ca.Cert, ca.Key, csr.PublicKey, certutil.IssueOptions{
		CN:        "node-agent/" + node,
		URISAN:    fmt.Sprintf("spiffe://%s/node/%s/agent", certutil.MeshDomain, node),
		EKU:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		TTL:       s.cfg.NodeAgentTTL,
		Meta:      &meta,
		Role:      certutil.RoleNodeAgent,
		NotBefore: s.now().Add(-10 * time.Second),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuedCert{
		leaf: leaf, chain: []*x509.Certificate{ca.Cert}, meta: meta,
		renewAfter: leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3),
	}, nil
}

// issueNodeIntermediate issues a node-scoped intermediate CA. The scope is the
// crux of the blast-radius argument: this key, even if stolen, can mint only
// short-lived identities for one node.
func (s *Server) issueNodeIntermediate(ca *certutil.Authority, node string, csr *x509.CertificateRequest) (*issuedCert, error) {
	scope := certutil.Scope{Node: node, MaxTTLSec: int64(s.cfg.LeafTTL.Seconds())}
	der, err := certutil.NewCertSignedByCA(ca.Cert, ca.Key, csr.PublicKey, certutil.IssueOptions{
		CN:        "node-ca/" + node,
		URISAN:    fmt.Sprintf("spiffe://%s/ca/node/%s", certutil.MeshDomain, node),
		IsCA:      true,
		PathLen:   0,
		TTL:       s.cfg.NodeCATTL,
		Role:      certutil.RoleNodeAgent,
		Scope:     &scope,
		NotBefore: s.now().Add(-10 * time.Second),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	meta := certutil.Meta{Node: node, Instance: "node-ca", Mode: certutil.ModeOnline, Issuer: s.cfg.ReplicaID}
	return &issuedCert{leaf: leaf, chain: []*x509.Certificate{ca.Cert}, meta: meta, scope: scope}, nil
}

func (s *Server) policyVersion() int {
	p, err := s.st.Policy()
	if err != nil {
		return 0
	}
	return p.Policy.Version
}

func pems(certs []*x509.Certificate) []string {
	var out []string
	for _, c := range certs {
		out = append(out, certutil.EncodeCertPEM(c.Raw))
	}
	return out
}
