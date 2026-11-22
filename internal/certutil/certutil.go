// Package certutil holds the X.509 primitives of the mesh: private material,
// certificate authorities, the mesh identity extensions, trust bundles and
// signed revocation lists.
//
// Certificate shape
//
//	root CA (offline, 10y)
//	  ├── authd intermediate (one per authd replica, 30d)      -> online leaf certs
//	  ├── node intermediate  (one per node, 7d, node-scoped)   -> degraded leaf certs
//	  └── node agent TLS cert (per node, 7d)
//
//	platform/vendor root (offline, 10y)
//	  └── node endorsement key cert (per node, TTL of hardware)
//	        └── node attestation key cert (signed by the EK inside the TPM)
//
// Leaves carry a URI SAN identifying the workload:
//
//	spiffe://meshid.local/ns/<namespace>/svc/<service>/node/<node>/inst/<instance>
//
// plus a private, non-critical extension with the structured metadata
// (binary hash, uid, pid, issuance mode, ...) used by peers for authorization.
package certutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// MeshDomain is the trust domain used in URI SANs.
const MeshDomain = "meshid.local"

// MaxSkew is the clock-skew allowance applied to NotBefore at issuance.
const MaxSkew = 10 * time.Second

// Private enterprise OID arc used by this project. It is a placeholder; a
// real deployment must allocate an arc it owns (or use the SPIFFE ID
// extension with the SPIFFE X.509-SVID spec).
var (
	OIDMeshMeta  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 1}
	OIDMeshScope = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 2}
	OIDMeshRole  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1, 3}
)

// Roles recorded in the role extension.
const (
	RoleNodeAgent = "node-agent"
	RoleWorkload  = "workload"
	RoleEK        = "tpm-ek"
	RoleAK        = "tpm-ak"
)

// Issuance modes carried by leaves.
const (
	ModeOnline   = "online"   // issued by authd after central policy check
	ModeDegraded = "degraded" // issued by a node agent while authd is unreachable
)

var (
	ErrScopeViolation   = errors.New("certutil: certificate outside issuer scope")
	ErrNotMeshCert      = errors.New("certutil: not a mesh certificate")
	ErrRevoked          = errors.New("certutil: certificate revoked")
	ErrUntrustedIssuer  = errors.New("certutil: untrusted issuer")
	ErrMetadataMismatch = errors.New("certutil: mesh metadata mismatch")
)

// Meta is the structured identity attached to workload certificates.
type Meta struct {
	Namespace      string `json:"ns"`
	Service        string `json:"svc"`
	Node           string `json:"node"`
	Instance       string `json:"inst"`
	Mode           string `json:"mode"`
	Issuer         string `json:"issuer"`
	UID            uint32 `json:"uid"`
	PID            int    `json:"pid"`
	ProcessStart   int64  `json:"proc_start"`
	BinaryPath     string `json:"bin_path"`
	BinarySHA256   string `json:"bin_sha256"`
	PolicyVersion  int    `json:"policy_version"`
	AttestationAge int64  `json:"attested_at"`
}

// Scope is embedded in a node intermediate and limits what it may issue.
// Peers check every degraded leaf against the scope of the intermediate that
// signed it, so a compromised node cannot mint identities for another node.
type Scope struct {
	Node      string `json:"node"`
	MaxTTLSec int64  `json:"max_ttl_sec"`
}

// Authority is a CA certificate with its private key.
type Authority struct {
	ID   string
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func randSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func EncodeCertPEM(der []byte) string { return string(pemBlock("CERTIFICATE", der)) }

func EncodeKeyPEM(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pemBlock("PRIVATE KEY", der)), nil
}

func ParseKeyPEM(s string) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("certutil: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certutil: not an ECDSA key")
	}
	return ek, nil
}

func ParseCertPEM(s string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil, errors.New("certutil: no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func ParseCertsPEM(certs []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range certs {
		rest := []byte(p)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// KeyID returns a stable short identifier for a public key.
func KeyID(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// FingerprintCert is the plain-SHA256 certificate fingerprint.
func FingerprintCert(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func spiffe(node string) string { return "spiffe://" + MeshDomain + "/node/" + node }

// NewSelfSignedRoot builds a root CA. In production the private key is kept
// offline (HSM / air-gapped machine) and only used at provisioning time.
func NewSelfSignedRoot(name string, ttl time.Duration) (*Authority, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"meshid"}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(ttl),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		MaxPathLen:            2,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{ID: name, Cert: c, Key: key}, nil
}

// IssueOptions describes a certificate to create.
type IssueOptions struct {
	CN        string
	URISAN    string
	DNSNames  []string
	IPs       []net.IP
	EKU       []x509.ExtKeyUsage
	IsCA      bool
	PathLen   int
	TTL       time.Duration
	NotBefore time.Time
	KeyUsage  x509.KeyUsage
	Scope     *Scope
	Meta      *Meta
	Role      string
	// Extra holds additional raw extensions (used for EKs/AKs).
	Extra []pkix.Extension
}

func marshalExt(oid asn1.ObjectIdentifier, v any) (pkix.Extension, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: oid, Value: b}, nil
}

func buildTemplate(pub any, o IssueOptions) (*x509.Certificate, error) {
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	// The certificate lives exactly TTL from now. NotBefore is backdated by a
	// bounded skew allowance so a verifier whose clock lags slightly still
	// accepts it; that backdate lengthens the *window* but not the usable
	// lifetime. Peer checks allow MaxSkew backdate on top of the scope TTL.
	skew := MaxSkew
	if o.TTL > 0 && o.TTL/4 < skew {
		skew = o.TTL / 4
	}
	nb := o.NotBefore
	if nb.IsZero() {
		nb = now.Add(-skew)
	}
	if o.CN == "" {
		o.CN = "meshid"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: o.CN, Organization: []string{"meshid"}},
		NotBefore:             nb,
		NotAfter:              now.Add(o.TTL),
		IsCA:                  o.IsCA,
		BasicConstraintsValid: true,
		MaxPathLen:            o.PathLen,
		KeyUsage:              o.KeyUsage,
		ExtKeyUsage:           o.EKU,
		DNSNames:              o.DNSNames,
		IPAddresses:           o.IPs,
	}
	if o.IsCA {
		if tmpl.KeyUsage == 0 {
			tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		}
	}
	if o.URISAN != "" {
		u, err := url.Parse(o.URISAN)
		if err != nil {
			return nil, err
		}
		tmpl.URIs = []*url.URL{u}
	}
	if o.Role != "" {
		e, err := marshalExt(OIDMeshRole, o.Role)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, e)
	}
	if o.Scope != nil && o.Scope.Node != "" {
		e, err := marshalExt(OIDMeshScope, o.Scope)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, e)
	}
	if o.Meta != nil {
		e, err := marshalExt(OIDMeshMeta, o.Meta)
		if err != nil {
			return nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, e)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, o.Extra...)
	_ = pub
	return tmpl, nil
}

// Template builds the certificate template described by o.
func (o IssueOptions) Template() (*x509.Certificate, error) { return buildTemplate(nil, o) }

// CreateCert signs tmpl for pub with an arbitrary signer and issuer
// certificate. signer may be a crypto.Signer backed by an HSM, so the issuer
// key never has to leave it.
func CreateCert(issuer *x509.Certificate, signer crypto.Signer, pub any, tmpl *x509.Certificate) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, signer)
}

// IssueWithSigner is CreateCert for the common case: build a template from
// options and sign it.
func IssueWithSigner(issuer *x509.Certificate, signer crypto.Signer, pub any, o IssueOptions) ([]byte, error) {
	tmpl, err := buildTemplate(pub, o)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, signer)
}

// SignCert creates a certificate for pub, signed by the authority.
func (a *Authority) SignCert(pub any, o IssueOptions) ([]byte, error) {
	tmpl, err := buildTemplate(pub, o)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, tmpl, a.Cert, pub, a.Key)
}

// NewIntermediate creates and signs a subordinate CA.
func (a *Authority) NewIntermediate(id string, ttl time.Duration, scope *Scope) (*Authority, error) {
	key, err := NewKey()
	if err != nil {
		return nil, err
	}
	der, err := a.SignCert(&key.PublicKey, IssueOptions{
		CN:      id,
		IsCA:    true,
		PathLen: 0,
		TTL:     ttl,
		Scope:   scope,
		Role:    "intermediate",
		URISAN:  "spiffe://" + MeshDomain + "/ca/" + id,
	})
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{ID: id, Cert: c, Key: key}, nil
}

// NewSelfSignedKeyCert creates a self-signed certificate for key (used only by
// tests and by EK bootstrap in the simulated TPM).
func NewSelfSignedKeyCert(key *ecdsa.PrivateKey, o IssueOptions) ([]byte, *x509.Certificate, error) {
	tmpl, err := buildTemplate(&key.PublicKey, o)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return der, c, err
}

// NewCertSignedByCA issues a certificate for pub signed by a CA whose key is
// held by a crypto.Signer (an HSM). The issuer certificate is ca.
func NewCertSignedByCA(ca *x509.Certificate, signer crypto.Signer, pub any, o IssueOptions) ([]byte, error) {
	tmpl, err := buildTemplate(pub, o)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca, pub, signer)
}

// NewCertSignedBy issues a certificate for pub signed by an arbitrary issuer
// certificate and key. Used for TPM-style EK->AK binding, where the EK
// certifies the AK but is not a general-purpose CA.
func NewCertSignedBy(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, pub any, o IssueOptions) ([]byte, error) {
	tmpl, err := buildTemplate(pub, o)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificate(rand.Reader, tmpl, issuer, pub, issuerKey)
}

// SignCSR signs a certificate request with the mesh identity fields.
func (a *Authority) SignCSR(csr *x509.CertificateRequest, o IssueOptions) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certutil: bad CSR signature: %w", err)
	}
	return a.SignCert(csr.PublicKey, o)
}

// ParseCSR parses a PEM encoded PKCS#10 request.
func ParseCSR(pemStr string) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode([]byte(pemStr))
	if blk == nil {
		return nil, errors.New("certutil: no CSR PEM block")
	}
	return x509.ParseCertificateRequest(blk.Bytes)
}

func EncodeCSRPEM(der []byte) string { return string(pemBlock("CERTIFICATE REQUEST", der)) }

// NewCSR builds a CSR for key.
func NewCSR(key *ecdsa.PrivateKey, cn string) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		return "", err
	}
	return EncodeCSRPEM(der), nil
}

// Extension returns the value of the extension with oid, if present.
func Extension(c *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.Id.Equal(oid) {
			return e.Value, true
		}
	}
	return nil, false
}

// MetaOf extracts and decodes the mesh metadata extension.
func MetaOf(c *x509.Certificate) (*Meta, error) {
	v, ok := Extension(c, OIDMeshMeta)
	if !ok {
		return nil, ErrNotMeshCert
	}
	var m Meta
	if err := json.Unmarshal(v, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ScopeOf extracts the scope extension of an intermediate.
func ScopeOf(c *x509.Certificate) (*Scope, error) {
	v, ok := Extension(c, OIDMeshScope)
	if !ok {
		return nil, ErrNotMeshCert
	}
	var s Scope
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// RoleOf extracts the role extension.
func RoleOf(c *x509.Certificate) (string, bool) {
	v, ok := Extension(c, OIDMeshRole)
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", false
	}
	return s, true
}

// ServiceIDOf returns a stable identifier for a workload certificate.
func ServiceIDOf(c *x509.Certificate) (string, bool) {
	if len(c.URIs) == 0 {
		return "", false
	}
	return c.URIs[0].String(), true
}

// RootPool builds a pool from PEM certificates.
func RootPool(pems []string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	certs, err := ParseCertsPEM(pems)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

// VerifyChain verifies leaf against roots, using the presented intermediates.
// It returns the full verified chain.
func VerifyChain(leaf *x509.Certificate, presented []*x509.Certificate, roots *x509.CertPool, now time.Time, dnsName string) ([]*x509.Certificate, error) {
	inter := x509.NewCertPool()
	for _, c := range presented {
		if c != leaf {
			inter.AddCert(c)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		DNSName:       dnsName,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedIssuer, err)
	}
	return chains[0], nil
}

// CheckNodeScope enforces that a degraded leaf was issued by an intermediate
// scoped to the same node, within the intermediate's max TTL.
func CheckNodeScope(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return fmt.Errorf("%w: no issuer in chain", ErrScopeViolation)
	}
	leaf, issuer := chain[0], chain[1]
	m, err := MetaOf(leaf)
	if err != nil {
		return err
	}
	sc, err := ScopeOf(issuer)
	if err != nil {
		if m.Mode == ModeDegraded {
			return fmt.Errorf("%w: degraded leaf issued by unscoped CA", ErrScopeViolation)
		}
		return nil
	}
	if m.Node != sc.Node {
		return fmt.Errorf("%w: leaf for node %q issued by CA scoped to %q", ErrScopeViolation, m.Node, sc.Node)
	}
	if m.Mode == ModeDegraded {
		// The window may be MaxSkew longer than the issued lifetime because
		// NotBefore is backdated; anything beyond that is a real violation.
		limit := time.Duration(sc.MaxTTLSec)*time.Second + MaxSkew
		if sc.MaxTTLSec > 0 && leaf.NotAfter.Sub(leaf.NotBefore) > limit {
			return fmt.Errorf("%w: leaf TTL exceeds node CA scope", ErrScopeViolation)
		}
	}
	return nil
}

// Revocation records one revoked credential. Exactly one of Serial, Node
// (with optional Service/Instance) is set. Node-level revocation cuts off a
// compromised host along with every credential it ever held.
type Revocation struct {
	Serial   string    `json:"serial,omitempty"`
	Node     string    `json:"node,omitempty"`
	Service  string    `json:"svc,omitempty"`
	Instance string    `json:"inst,omitempty"`
	Reason   string    `json:"reason"`
	At       time.Time `json:"at"`
	// Leaf is true when the entry revokes a specific instance, false when it
	// revokes every credential under Node/Service/Instance.
}

// RevocationList is served by authd and enforced by peers and node agents.
type RevocationList struct {
	Version  int          `json:"version"`
	IssuedAt time.Time    `json:"issued_at"`
	Entries  []Revocation `json:"entries"`
}

// Canonical encodes the signed portion deterministically.
func (l *RevocationList) Canonical() []byte {
	cp := struct {
		Version  int          `json:"version"`
		IssuedAt time.Time    `json:"issued_at"`
		Entries  []Revocation `json:"entries"`
	}{l.Version, l.IssuedAt, l.Entries}
	b, _ := json.Marshal(cp)
	return b
}

// Revoked reports whether the leaf matches any revocation entry, and why.
func (l *RevocationList) Revoked(leaf *x509.Certificate) (bool, string) {
	m, err := MetaOf(leaf)
	if err != nil {
		return false, ""
	}
	serial := leaf.SerialNumber.Text(16)
	for _, e := range l.Entries {
		switch {
		case e.Serial != "" && strings.EqualFold(e.Serial, serial):
			return true, e.Reason
		case e.Node != "" && e.Node == m.Node && e.Service == "" && e.Instance == "":
			return true, e.Reason
		case e.Node == m.Node && e.Service == m.Service && e.Instance == "":
			return true, e.Reason
		case e.Node == m.Node && e.Service == m.Service && e.Instance == m.Instance:
			return true, e.Reason
		}
	}
	return false, ""
}

// Bundle is the set of trust anchors a peer needs. It is small and public.
type Bundle struct {
	Version       int       `json:"version"`
	Roots         []string  `json:"roots_pem"`
	Intermediates []string  `json:"intermediates_pem"`
	VendorRoots   []string  `json:"vendor_roots_pem,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (b *Bundle) RootPool() (*x509.CertPool, error) { return RootPool(b.Roots) }

func (b *Bundle) AllRootsPool() (*x509.CertPool, error) {
	return RootPool(append(append([]string{}, b.Roots...), b.VendorRoots...))
}

// SignCanonical signs SHA-256 over a domain-separated canonical encoding.
// Callers pass a deterministic JSON encoding of the object without its
// Signature field.
func SignCanonical(key *ecdsa.PrivateKey, domain string, canonical []byte) (string, error) {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig), nil
}

// VerifyCanonical verifies a signature produced by SignCanonical.
func VerifyCanonical(pub *ecdsa.PublicKey, domain string, canonical []byte, sigHex string) error {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("certutil: bad signature encoding")
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(canonical)
	if !ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
		return errors.New("certutil: signature verification failed")
	}
	return nil
}

// SignedBundle is a trust bundle with a root signature. Peers cache it and
// keep using it when authd is unreachable; the signature lets a node agent
// accept a bundle fetched through an untrusted path.
type SignedBundle struct {
	Version       int       `json:"version"`
	Roots         []string  `json:"roots_pem"`
	Intermediates []string  `json:"intermediates_pem,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
	SignerID      string    `json:"signer_id"`
	SignerCertPEM string    `json:"signer_cert_pem,omitempty"`
	Signature     string    `json:"signature"`
}

// CanonicalBundle is the signed portion.
func (b *SignedBundle) CanonicalBundle() []byte {
	cp := struct {
		Version int       `json:"version"`
		Roots   []string  `json:"roots_pem"`
		Inter   []string  `json:"intermediates_pem,omitempty"`
		Updated time.Time `json:"updated_at"`
	}{b.Version, b.Roots, b.Intermediates, b.UpdatedAt}
	out, _ := json.Marshal(cp)
	return out
}

func (b *SignedBundle) Bundle() Bundle {
	return Bundle{Version: b.Version, Roots: b.Roots, Intermediates: b.Intermediates, UpdatedAt: b.UpdatedAt}
}

// ServiceGrant is one rule in the central authorization policy.
type ServiceGrant struct {
	Namespace string `json:"ns"`
	Service   string `json:"svc"`
	// RequireUID pins the Unix UID the workload must run as, when non-zero.
	RequireUID *uint32 `json:"require_uid,omitempty"`
	// BinarySHA256, when set, pins the exact executable hash. This is the
	// core defense against a different binary on a compromised host asking
	// for this service's identity.
	BinarySHA256 string `json:"binary_sha256,omitempty"`
	// MaxTTLSec caps the lifetime of issued leaves for this service.
	MaxTTLSec int64 `json:"max_ttl_sec,omitempty"`
	// Nodes, when non-empty, restricts which nodes may run this service.
	// This is how a compromised host cannot ask for a neighbour's identity.
	Nodes []string `json:"nodes,omitempty"`
	// AllowDegraded lets node agents keep issuing this service while authd is
	// unreachable. Off by default: fail closed for sensitive services.
	AllowDegraded bool `json:"allow_degraded,omitempty"`
}

// Policy is the signed authorization document served by authd.
type Policy struct {
	Version int            `json:"version"`
	Grants  []ServiceGrant `json:"grants"`
	// DefaultMaxTTLSec applies when a grant does not specify a cap.
	DefaultMaxTTLSec int64     `json:"default_max_ttl_sec"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// SignedPolicy is Policy with a root signature.
type SignedPolicy struct {
	Policy        Policy `json:"policy"`
	SignerID      string `json:"signer_id"`
	SignerCertPEM string `json:"signer_cert_pem,omitempty"`
	Signature     string `json:"signature"`
}

// CanonicalPolicy is the signed portion.
func (p *SignedPolicy) CanonicalPolicy() []byte {
	out, _ := json.Marshal(p.Policy)
	return out
}

// FindGrant returns the most specific grant for ns/svc.
func (p *Policy) FindGrant(ns, svc string) (ServiceGrant, bool) {
	for _, g := range p.Grants {
		if g.Namespace == ns && g.Service == svc {
			return g, true
		}
	}
	return ServiceGrant{}, false
}

// SignedRevocationList wraps the revocation list for transport.
type SignedRevocationList struct {
	List          RevocationList `json:"list"`
	SignerID      string         `json:"signer_id"`
	SignerCertPEM string         `json:"signer_cert_pem,omitempty"`
	Signature     string         `json:"signature"`
}

// CanonicalRevocations is the signed portion of a revocation response.
func (r *SignedRevocationList) CanonicalRevocations() []byte { return r.List.Canonical() }

// Envelopes over bundles, policies and revocations. Each has a stable
// canonical form and is signed by the root key (or a dedicated signing key
// with an offline root). Domain separation prevents cross-protocol reuse.
const (
	DomainBundle     = "meshid/bundle/v1"
	DomainPolicy     = "meshid/policy/v1"
	DomainRevocation = "meshid/revocations/v1"
	DomainAttest     = "meshid/attestation/v1"
)

// SignBundle signs a bundle with key.
func SignBundle(key *ecdsa.PrivateKey, signerID, signerCertPEM string, b Bundle) (*SignedBundle, error) {
	sb := &SignedBundle{
		Version: b.Version, Roots: b.Roots, Intermediates: b.Intermediates,
		UpdatedAt: b.UpdatedAt, SignerID: signerID, SignerCertPEM: signerCertPEM,
	}
	sig, err := SignCanonical(key, DomainBundle, sb.CanonicalBundle())
	if err != nil {
		return nil, err
	}
	sb.Signature = sig
	return sb, nil
}

// Verify checks a signed bundle against a root public key.
func (b *SignedBundle) Verify(pub *ecdsa.PublicKey) error {
	return VerifyCanonical(pub, DomainBundle, b.CanonicalBundle(), b.Signature)
}

// SignPolicy signs a policy with key.
func SignPolicy(key *ecdsa.PrivateKey, signerID, signerCertPEM string, p Policy) (*SignedPolicy, error) {
	sp := &SignedPolicy{Policy: p, SignerID: signerID, SignerCertPEM: signerCertPEM}
	sig, err := SignCanonical(key, DomainPolicy, sp.CanonicalPolicy())
	if err != nil {
		return nil, err
	}
	sp.Signature = sig
	return sp, nil
}

// Verify checks a signed policy against a root public key.
func (p *SignedPolicy) Verify(pub *ecdsa.PublicKey) error {
	return VerifyCanonical(pub, DomainPolicy, p.CanonicalPolicy(), p.Signature)
}

// SignRevocations signs a revocation list with key.
func SignRevocations(key *ecdsa.PrivateKey, signerID, signerCertPEM string, l RevocationList) (*SignedRevocationList, error) {
	sr := &SignedRevocationList{List: l, SignerID: signerID, SignerCertPEM: signerCertPEM}
	sig, err := SignCanonical(key, DomainRevocation, sr.CanonicalRevocations())
	if err != nil {
		return nil, err
	}
	sr.Signature = sig
	return sr, nil
}

// Verify checks a signed revocation list against a root public key.
func (r *SignedRevocationList) Verify(pub *ecdsa.PublicKey) error {
	return VerifyCanonical(pub, DomainRevocation, r.CanonicalRevocations(), r.Signature)
}

// HashBytes is a small convenience used by policy fixtures and tests.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
