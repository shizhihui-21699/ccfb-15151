// Package trust holds the immutable, point-in-time view of everything a peer
// needs in order to authenticate a certificate: roots, intermediates and the
// revocation list, plus verification of the signed control-plane documents.
//
// Snapshots are replaced wholesale, never mutated, so a request that grabbed
// one sees a consistent world even while the control plane is updating.
package trust

import (
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/mesh"
)

// Snapshot is one consistent view of the trust state.
type Snapshot struct {
	RootsPEM         []string
	IntermediatesPEM []string
	Roots            *x509.CertPool
	Revocations      *mesh.RevocationSnapshot
	BundleVersion    int
	RevocationAt     time.Time
}

// Store is an atomically replaceable Snapshot.
type Store struct{ v atomic.Pointer[Snapshot] }

func NewStore() *Store {
	s := &Store{}
	s.v.Store(&Snapshot{Roots: x509.NewCertPool()})
	return s
}

// Load returns the current snapshot.
func (s *Store) Load() *Snapshot { return s.v.Load() }

// SetBundle installs a trust bundle, replacing roots and intermediates.
func (s *Store) SetBundle(b *certutil.SignedBundle) error {
	roots := x509.NewCertPool()
	for _, p := range b.Roots {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			return errors.New("trust: malformed root certificate")
		}
	}
	cur := s.Load()
	next := &Snapshot{
		RootsPEM:         b.Roots,
		IntermediatesPEM: b.Intermediates,
		Roots:            roots,
		Revocations:      cur.Revocations,
		BundleVersion:    b.Version,
		RevocationAt:     cur.RevocationAt,
	}
	s.v.Store(next)
	return nil
}

// SetRevocations installs a revocation list. Entries are copied so the caller
// can reuse its slice.
func (s *Store) SetRevocations(l *certutil.RevocationList) {
	cur := s.Load()
	snap := &mesh.RevocationSnapshot{Version: l.Version}
	for _, e := range l.Entries {
		snap.Entries = append(snap.Entries, mesh.RevocationEntry{
			Serial: e.Serial, Node: e.Node, Service: e.Service,
			Instance: e.Instance, Reason: e.Reason,
		})
	}
	next := &Snapshot{
		RootsPEM:         cur.RootsPEM,
		IntermediatesPEM: cur.IntermediatesPEM,
		Roots:            cur.Roots,
		Revocations:      snap,
		BundleVersion:    cur.BundleVersion,
		RevocationAt:     time.Now(),
	}
	s.v.Store(next)
}

// TrustSource adapts the Store to mesh.TrustSource.
func (s *Store) TrustSource() mesh.TrustSource { return source{s} }

type source struct{ s *Store }

func (s source) RootsAndIntermediates() ([]string, []string) {
	snap := s.s.Load()
	return snap.RootsPEM, snap.IntermediatesPEM
}

func (s source) Revocations() *mesh.RevocationSnapshot { return s.s.Load().Revocations }

func (s source) BundleVersion() int { return s.s.Load().BundleVersion }

// Bootstrap trust model
//
// A node cannot learn its roots from an unauthenticated download, so the
// bootstrap root is pinned in the node's image (exactly like the CA bundle
// baked into a container or an operating system). Everything after that is
// signed by a key that chains to a pinned root, which supports root rotation:
// the new root arrives inside a bundle signed by the old one, and the pinned
// pool keeps the old root until every node has rolled over.

// VerifyBundle checks a signed bundle. Its signer must chain to a root in
// pinned. bundle.CanonicalBundle() is what was signed.
func VerifyBundle(b *certutil.SignedBundle, pinned *x509.CertPool) error {
	pub, err := verifySigner(b.SignerCertPEM, pinned)
	if err != nil {
		return err
	}
	return certutil.VerifyCanonical(pub, certutil.DomainBundle, b.CanonicalBundle(), b.Signature)
}

// VerifyPolicy checks a signed policy against the current trust pool.
func VerifyPolicy(p *certutil.SignedPolicy, pool *x509.CertPool) error {
	pub, err := verifySigner(p.SignerCertPEM, pool)
	if err != nil {
		return err
	}
	return certutil.VerifyCanonical(pub, certutil.DomainPolicy, p.CanonicalPolicy(), p.Signature)
}

// VerifyRevocations checks a signed revocation list against the trust pool.
func VerifyRevocations(r *certutil.SignedRevocationList, pool *x509.CertPool) error {
	pub, err := verifySigner(r.SignerCertPEM, pool)
	if err != nil {
		return err
	}
	return certutil.VerifyCanonical(pub, certutil.DomainRevocation, r.CanonicalRevocations(), r.Signature)
}

// verifySigner validates the signer certificate chain and returns its public
// key. The caller verifies the signature with that key, so a bad chain and a
// bad signature produce distinct errors.
func verifySigner(certPEM string, pool *x509.CertPool) (*ecdsa.PublicKey, error) {
	if certPEM == "" {
		return nil, errors.New("trust: document has no signer certificate")
	}
	c, err := certutil.ParseCertPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("trust: signer certificate: %w", err)
	}
	if _, err := c.Verify(x509.VerifyOptions{
		Roots: pool, CurrentTime: time.Now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("trust: signer not trusted: %w", err)
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("trust: signer key is not ECDSA")
	}
	return pub, nil
}
