// Package hsm is a simulated TPM 2.0 / HSM used to make the trust boundaries
// of the design executable rather than aspirational.
//
//   - Private keys are generated inside the module and are never exported.
//     Callers hand in a digest and get back a signature; there is no export
//     API. Compromising the node-agent process therefore does not hand an
//     attacker the node's long-lived identity keys.
//   - The endorsement key (EK) is "fused" at manufacture and certified by a
//     platform vendor root, exactly like a TPM EK credential.
//   - The attestation key (AK) is created under the EK and certified by it
//     (TPM2_Create with the EK as parent, then TPM2_Certify).
//   - Quotes bind a fresh server nonce to the node's TLS and CA public keys,
//     so an enrollment transcript cannot be replayed against another key.
//
// Honest limits of the simulation: there are no PCR measurements, no sealed
// storage bound to boot measurements, and "manufacture" happens in the test
// process rather than on a die. The property that *is* modelled faithfully is
// the one the design relies on: holding a node's runtime secrets is not the
// same as holding its hardware identity, and only the module can use the
// latter.
package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"meshid/internal/certutil"
)

// Module is one simulated TPM.
type Module struct {
	mu sync.Mutex

	ekKey  *ecdsa.PrivateKey
	EKPub  *ecdsa.PublicKey
	EKCert *x509.Certificate
	EKRoot *x509.Certificate

	akKey   *ecdsa.PrivateKey
	akCSR   *x509.CertificateRequest
	akCert  *x509.Certificate
	akChain []*x509.Certificate

	nodeKey   *ecdsa.PrivateKey // TLS identity for the node agent
	nodeCAKey *ecdsa.PrivateKey // node intermediate CA

	sealed map[string][]byte
}

// Vendor is the platform vendor trust anchor that certifies EKs.
type Vendor struct {
	Root *certutil.Authority
}

func NewVendor() (*Vendor, error) {
	a, err := certutil.NewSelfSignedRoot("meshid-sim-platform-root", 20*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return &Vendor{Root: a}, nil
}

// Manufacture creates a module with a freshly fused EK and its vendor-
// certified EK certificate. Only the returned Module holds the EK private key.
func Manufacture(v *Vendor, node string) (*Module, error) {
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := v.Root.SignCert(&ekKey.PublicKey, certutil.IssueOptions{
		CN:       "EK/" + node,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		TTL:      20 * 365 * 24 * time.Hour,
		Role:     certutil.RoleEK,
		IsCA:     true,
		PathLen:  0,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return nil, err
	}
	ekCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Module{
		ekKey:  ekKey,
		EKPub:  &ekKey.PublicKey,
		EKCert: ekCert,
		EKRoot: v.Root.Cert,
		sealed: map[string][]byte{},
	}, nil
}

// EKChainPEM returns the EK certificate and vendor root for enrollment.
func (m *Module) EKChainPEM() (string, []string) {
	return certutil.EncodeCertPEM(m.EKCert.Raw), []string{certutil.EncodeCertPEM(m.EKRoot.Raw)}
}

// EKFingerprint identifies the physical module.
func (m *Module) EKFingerprint() string { return certutil.FingerprintCert(m.EKCert) }

// CreateAK generates an AK inside the module and returns its CSR. In a TPM
// this is TPM2_Create under the EK primary seed; the certificate request is
// what authd will certify.
func (m *Module) CreateAK(node string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.akKey != nil {
		return certutil.EncodeCSRPEM(m.akCSR.Raw), nil
	}
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	// TPM2_Certify: the EK signs a certificate for the AK public key. The
	// AK certificate chain is AK <- EK <- vendor root; authd verifies it
	// without ever being able to mint an EK for an arbitrary machine.
	akDer, err := certutil.NewCertSignedBy(m.EKCert, m.ekKey, &ak.PublicKey, certutil.IssueOptions{
		CN:       "AK/" + node,
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		TTL:      20 * 365 * 24 * time.Hour,
		Role:     certutil.RoleAK,
		DNSNames: []string{node},
	})
	if err != nil {
		return "", err
	}
	akCert, err := x509.ParseCertificate(akDer)
	if err != nil {
		return "", err
	}
	m.akKey = ak
	m.akCert = akCert
	m.akChain = []*x509.Certificate{akCert, m.EKCert, m.EKRoot}
	csrPEM, err := certutil.NewCSR(ak, "AK/"+node)
	if err != nil {
		return "", err
	}
	csr, err := certutil.ParseCSR(csrPEM)
	if err != nil {
		return "", err
	}
	m.akCSR = csr
	return csrPEM, nil
}

// BindAKCert installs the AK certificate and chain returned by authd.
func (m *Module) BindAKCert(certPEM string, chainPEM []string) error {
	c, err := certutil.ParseCertPEM(certPEM)
	if err != nil {
		return err
	}
	chain, err := certutil.ParseCertsPEM(chainPEM)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.akCert = c
	m.akChain = append([]*x509.Certificate{c}, chain...)
	return nil
}

// AKCertPEM returns the AK certificate and the rest of its chain.
func (m *Module) AKCertPEM() (string, []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.akCert == nil {
		return "", nil
	}
	var chain []string
	for _, c := range m.akChain[1:] {
		chain = append(chain, certutil.EncodeCertPEM(c.Raw))
	}
	return certutil.EncodeCertPEM(m.akCert.Raw), chain
}

// AttestStatement is the exact byte string the AK signs.
type AttestStatement struct {
	Nonce     string `json:"nonce"`
	Node      string `json:"node"`
	TLSKey    string `json:"tls_key"`     // hex SHA-256 of PKIX TLS public key
	NodeCAKey string `json:"node_ca_key"` // hex SHA-256 of PKIX CA public key
	IssuedAt  int64  `json:"issued_at"`
}

func (s AttestStatement) Canonical() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%d", s.Nonce, s.Node, s.TLSKey, s.NodeCAKey, s.IssuedAt))
}

func PubHash(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// PubHashFromCSR returns the same hash for the key inside a PEM CSR, so the
// server can compare "the key the AK attested" with "the key I am asked to
// certify" without trusting any field in the request.
func PubHashFromCSR(csrPEM string) (string, error) {
	c, err := certutil.ParseCSR(csrPEM)
	if err != nil {
		return "", err
	}
	return PubHash(c.PublicKey)
}

// NodeCSRs creates (if needed) the node TLS key and node intermediate key
// inside the module and returns their certificate requests. Private keys stay
// inside.
func (m *Module) NodeCSRs(node string) (tlsCSR, caCSR string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodeKey == nil {
		if m.nodeKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return "", "", err
		}
	}
	if m.nodeCAKey == nil {
		if m.nodeCAKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return "", "", err
		}
	}
	if tlsCSR, err = certutil.NewCSR(m.nodeKey, "node-agent/"+node); err != nil {
		return "", "", err
	}
	if caCSR, err = certutil.NewCSR(m.nodeCAKey, "node-ca/"+node); err != nil {
		return "", "", err
	}
	return tlsCSR, caCSR, nil
}

// NodeKeyHashes returns the public key hashes bound into attestation.
func (m *Module) NodeKeyHashes() (tlsHash, caHash string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodeKey == nil || m.nodeCAKey == nil {
		return "", "", errors.New("hsm: node keys not created")
	}
	if tlsHash, err = PubHash(&m.nodeKey.PublicKey); err != nil {
		return "", "", err
	}
	caHash, err = PubHash(&m.nodeCAKey.PublicKey)
	return
}

// Quote signs stmt with the AK and returns the signature plus the AK chain.
func (m *Module) Quote(stmt AttestStatement) (sigHex, akCertPEM string, akChain []string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.akKey == nil {
		return "", "", nil, errors.New("hsm: no attestation key; call CreateAK first")
	}
	if m.akCert == nil {
		return "", "", nil, errors.New("hsm: AK not certified")
	}
	sum := sha256.Sum256(stmt.Canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, m.akKey, sum[:])
	if err != nil {
		return "", "", nil, err
	}
	for _, c := range m.akChain[1:] {
		akChain = append(akChain, certutil.EncodeCertPEM(c.Raw))
	}
	return hex.EncodeToString(sig), certutil.EncodeCertPEM(m.akCert.Raw), akChain, nil
}

// Signer is the crypto.Signer view of a private key held by the module.
type Signer struct{ key *ecdsa.PrivateKey }

func (s Signer) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// NodeTLSSigner and NodeCASigner give out signing capability without the key.
func (m *Module) NodeTLSSigner() (crypto.Signer, error) { return m.signer(&m.nodeKey) }
func (m *Module) NodeCASigner() (crypto.Signer, error)  { return m.signer(&m.nodeCAKey) }

func (m *Module) signer(k **ecdsa.PrivateKey) (crypto.Signer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if *k == nil {
		return nil, errors.New("hsm: key not created")
	}
	return Signer{key: *k}, nil
}

// Seal stores bytes inside the module under name.
func (m *Module) Seal(name string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealed[name] = append([]byte(nil), data...)
}

// Unseal retrieves sealed bytes, or nil.
func (m *Module) Unseal(name string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.sealed[name]...)
}

// ExportNodeCAKey is a simulation-only backdoor used to model a root-level
// attacker who reads the node agent's memory. A real TPM has no such call,
// which is exactly why the simulation needs to make it explicit here rather
// than pretend the attack is impossible.
func (m *Module) ExportNodeCAKey() (*ecdsa.PrivateKey, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.nodeCAKey == nil {
		return nil, false
	}
	return m.nodeCAKey, true
}
