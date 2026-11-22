// Package identity is the client side of the design: it holds a process's
// short-lived certificate, renews it before expiry without ever interrupting
// in-flight work, and hands out a TLS configuration that always uses the
// current certificate.
//
// The renewal loop deliberately keeps the previous certificate usable until
// its own expiry: new handshakes prefer the newest leaf, but a connection
// established with the old leaf is not torn down. This is what makes
// rotation invisible to callers.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"meshid/internal/certutil"
)

// Creds is a rotating workload certificate.
type Creds struct {
	mu sync.RWMutex

	cert      *tls.Certificate
	meta      *certutil.Meta
	expiresAt time.Time
	renewAt   time.Time

	// previous is kept so long-lived connections are not disturbed and so a
	// renewal racing a handshake still has a valid leaf to offer.
	previous *tls.Certificate

	gen atomic.Uint64

	// OnChange is called after a successful swap (for logging/metrics).
	OnChange func(oldSerial, newSerial string, expiresAt time.Time)
}

// New builds Creds from a leaf and its chain. renewAt is the point at which
// the holder should ask for a new leaf; the issuer computes it as 2/3 of the
// remaining lifetime.
func New(leafPEM string, chainPEM []string, meta *certutil.Meta, renewAt time.Time) (*Creds, error) {
	leaf, err := certutil.ParseCertPEM(leafPEM)
	if err != nil {
		return nil, err
	}
	chain, err := certutil.ParseCertsPEM(chainPEM)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{
		PrivateKey:  nil, // installed by SetKey
		Leaf:        leaf,
		Certificate: [][]byte{leaf.Raw},
	}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	if renewAt.IsZero() {
		renewAt = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	}
	c := &Creds{cert: tc, meta: meta, expiresAt: leaf.NotAfter, renewAt: renewAt}
	return c, nil
}

// SetKey installs the private key. It must match the leaf; a mismatch is
// rejected here rather than surfacing later as an inexplicable handshake
// failure.
func (c *Creds) SetKey(key any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert.Leaf == nil {
		return errors.New("identity: no leaf")
	}
	if err := checkKeyMatch(key, c.cert.Leaf); err != nil {
		return err
	}
	c.cert.PrivateKey = key
	return nil
}

// checkKeyMatch compares the private key's public half with the leaf's. It
// accepts any crypto.Signer (which covers *ecdsa.PrivateKey and the HSM-backed
// signer used by the node agent).
func checkKeyMatch(key any, leaf *x509.Certificate) error {
	var pub crypto.PublicKey
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case crypto.Signer:
		pub = k.Public()
	case interface{ Public() any }:
		// Covers test doubles and wrappers that expose the key the Go
		// 1.18-style way rather than through crypto.Signer.
		pub = k.Public()
	default:
		return errors.New("identity: unsupported private key type")
	}
	der1, err1 := x509.MarshalPKIXPublicKey(pub)
	der2, err2 := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err1 != nil || err2 != nil {
		return errors.New("identity: cannot compare keys")
	}
	if string(der1) != string(der2) {
		return errors.New("identity: private key does not match certificate")
	}
	return nil
}

// Rotate swaps in a new leaf. The old one is retained for connections that
// already negotiated it.
func (c *Creds) Rotate(leafPEM string, chainPEM []string, meta *certutil.Meta, renewAt time.Time) error {
	leaf, err := certutil.ParseCertPEM(leafPEM)
	if err != nil {
		return err
	}
	chain, err := certutil.ParseCertsPEM(chainPEM)
	if err != nil {
		return err
	}
	c.mu.Lock()
	old := c.cert
	if old == nil || old.PrivateKey == nil {
		c.mu.Unlock()
		return errors.New("identity: no current key to rotate")
	}
	if err := checkKeyMatch(old.PrivateKey, leaf); err != nil {
		c.mu.Unlock()
		return fmt.Errorf("identity: rotated leaf does not match retained key: %w", err)
	}
	cert := &tls.Certificate{
		PrivateKey:  old.PrivateKey, // same key across rotations
		Leaf:        leaf,
		Certificate: [][]byte{leaf.Raw},
	}
	for _, cc := range chain {
		cert.Certificate = append(cert.Certificate, cc.Raw)
	}
	c.previous = old
	c.cert = cert
	c.meta = meta
	c.expiresAt = leaf.NotAfter
	if renewAt.IsZero() {
		renewAt = leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3)
	}
	c.renewAt = renewAt
	gen := c.gen.Add(1)
	onChange := c.OnChange
	c.mu.Unlock()
	if onChange != nil {
		onChange(old.Leaf.SerialNumber.Text(16), leaf.SerialNumber.Text(16), leaf.NotAfter)
	}
	_ = gen
	return nil
}

// Meta returns the identity metadata of the current leaf.
func (c *Creds) Meta() *certutil.Meta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.meta
}

// ExpiresAt and RenewAt report the current schedule.
func (c *Creds) ExpiresAt() time.Time { c.mu.RLock(); defer c.mu.RUnlock(); return c.expiresAt }
func (c *Creds) RenewAt() time.Time   { c.mu.RLock(); defer c.mu.RUnlock(); return c.renewAt }

// Generation increments on each rotation.
func (c *Creds) Generation() uint64 { return c.gen.Load() }

// Serial returns the current leaf serial in hex.
func (c *Creds) Serial() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert.Leaf == nil {
		return ""
	}
	return c.cert.Leaf.SerialNumber.Text(16)
}

// Certificate returns the current tls.Certificate.
func (c *Creds) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil {
		return nil, errors.New("identity: no certificate")
	}
	return c.cert, nil
}

// GetClientCertificate returns the current tls.Certificate.
func (c *Creds) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil {
		return nil, errors.New("identity: no certificate")
	}
	return c.cert, nil
}

// PrivateKeyPEM returns the holder's key in PKCS#8 PEM, or "" when the key is
// not exportable (for example when it lives in an HSM). Simulation workers use
// this to hand credentials to a child process; production code should not.
func (c *Creds) PrivateKeyPEM() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cert == nil || c.cert.PrivateKey == nil {
		return "", errors.New("identity: no private key")
	}
	switch k := c.cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		return certutil.EncodeKeyPEM(k)
	case interface {
		Export() (*ecdsa.PrivateKey, bool)
	}:
		if ek, ok := k.Export(); ok {
			return certutil.EncodeKeyPEM(ek)
		}
	}
	return "", errors.New("identity: private key is not exportable")
}

// ChainPEM returns the current leaf and chain as PEM.
func (c *Creds) ChainPEM() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []string
	for _, der := range c.cert.Certificate {
		out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	}
	return out
}

// VerifySelf checks the current certificate chains to roots and is not
// revoked, which is a cheap way to catch a bad rotation before using it.
func (c *Creds) VerifySelf(roots *x509.CertPool, rev *certutil.RevocationList, now time.Time) error {
	c.mu.RLock()
	cert := c.cert
	c.mu.RUnlock()
	if cert == nil || cert.Leaf == nil {
		return errors.New("identity: no certificate")
	}
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		cc, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		inter.AddCert(cc)
	}
	chains, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("identity: self-verify: %w", err)
	}
	if err := certutil.CheckNodeScope(chains[0]); err != nil {
		return err
	}
	if rev != nil {
		if ok, why := rev.Revoked(cert.Leaf); ok {
			return fmt.Errorf("identity: revoked: %s", why)
		}
	}
	return nil
}
