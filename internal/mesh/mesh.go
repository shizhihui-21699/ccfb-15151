// Package mesh is the server-side integration library. A service that wants
// to authenticate callers with short-lived certificates uses:
//
//	srv, err := mesh.NewServer(mesh.ServerConfig{
//	    Creds: creds,             // rotating credential source
//	    Authorize: policy.Check,  // what may this peer do
//	})
//	http.ServeTLS(ln, handler, "", "") // TLS comes from creds
//
// The TLS configuration is stable for the life of the process; the
// certificates behind it are swapped underneath, so rotation never closes a
// listener and never drops a connection. A client certificate is accepted as
// soon as it chains to a trusted root; which *service* it identifies and what
// it may do is a separate authorization decision made per request from the
// verified peer identity.
package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"meshid/internal/certutil"
	"sync/atomic"
	"time"
)

// Identity is the verified identity of the peer on a connection.
type Identity struct {
	// SPIFFE URI from the leaf SAN, e.g. spiffe://meshid.local/ns/x/svc/y/...
	URI string
	// Namespace, Service, Node, Instance are parsed from URI and metadata.
	Namespace string
	Service   string
	Node      string
	Instance  string
	// Mode is "online" or "degraded".
	Mode string
	// Serial is the leaf serial, useful in audit logs.
	Serial string
	// NotAfter is when the presented certificate expires. Callers should
	// treat connections whose certificate expired mid-flight as no longer
	// authenticated (see Guard).
	NotAfter time.Time
	// Chain is the verified chain, leaf first.
	Chain []*x509.Certificate
	// IssuedBy records the authd replica or node agent that signed the leaf.
	IssuedBy string
	// BinarySHA256 is the build identity the issuer attested.
	BinarySHA256 string
	// RevocationVersion is the revocation list version in force when the
	// handshake was authorized.
	RevocationVersion int
	// Role is the certificate role: workload, node-agent, or empty.
	Role string
}

type ctxKey struct{}

// FromContext returns the peer identity attached to a request, if any.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok
}

// ContextWithIdentity is used by tests and middleware.
func ContextWithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// VerifierConfig configures peer verification.
type VerifierConfig struct {
	// Trust provides the current roots, intermediates and revocation list.
	Trust TrustSource
	// Now can be overridden in tests.
	Now func() time.Time
	// MaxClockSkew tolerated when checking validity windows.
	MaxClockSkew time.Duration
	// RequireMode, when non-empty, rejects other issuance modes.
	RequireMode string
	// Expect selects which extended key usage is required.
	Expect Expect
	// RequireRole, when non-empty, rejects certificates of other roles.
	// Workload endpoints set "workload" so a node agent certificate cannot
	// be used to call a service.
	RequireRole string
}

// Expect says whether the peer is a client or a server.
type Expect int

const (
	ExpectAny Expect = iota
	ExpectClient
	ExpectServer
)

// TrustSource is implemented by the credential source and by static test
// bundles. Implementations must be safe for concurrent use and must return
// snapshots that are internally consistent.
type TrustSource interface {
	// RootsAndIntermediates returns PEM trust anchors.
	RootsAndIntermediates() (roots []string, intermediates []string)
	// Revocations returns the currently known revocation list, or nil.
	Revocations() *RevocationSnapshot
	// BundleVersion increments when trust anchors change.
	BundleVersion() int
}

// RevocationSnapshot is an immutable view of the revocation list.
type RevocationSnapshot struct {
	Version int
	Entries []RevocationEntry
}

// RevocationEntry mirrors certutil.Revocation for the library's public API.
type RevocationEntry struct {
	Serial   string
	Node     string
	Service  string
	Instance string
	Reason   string
}

// Matches reports whether the entry revokes the given identity.
func (e RevocationEntry) Matches(id *Identity) bool {
	switch {
	case e.Serial != "":
		return e.Serial == id.Serial
	case e.Node != "" && e.Node != id.Node:
		return false
	case e.Service != "" && e.Service != id.Service:
		return false
	case e.Instance != "" && e.Instance != id.Instance:
		return false
	}
	return e.Node != "" || e.Service != "" || e.Instance != ""
}

// Verifier verifies client certificates at handshake time.
type Verifier struct {
	cfg VerifierConfig
}

func NewVerifier(cfg VerifierConfig) *Verifier {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 30 * time.Second
	}
	return &Verifier{cfg: cfg}
}

// VerifyConnection is installed as tls.Config.VerifyConnection, so it runs for
// every handshake with the peer's raw certificates, including when
// InsecureSkipVerify is used to do custom verification.
func (v *Verifier) VerifyConnection(state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("mesh: peer presented no certificate")
	}
	id, err := v.VerifyCerts(state.PeerCertificates, state.ServerName)
	if err != nil {
		return err
	}
	id.RevocationVersion = v.revocationVersion()
	return nil
}

func (v *Verifier) revocationVersion() int {
	if r := v.cfg.Trust.Revocations(); r != nil {
		return r.Version
	}
	return 0
}

// VerifyCerts performs the full verification chain and returns the identity.
// It is exported so tests and the attacker simulation can use exactly the
// same code path as production.
func (v *Verifier) VerifyCerts(peerCerts []*x509.Certificate, dnsName string) (*Identity, error) {
	now := v.cfg.Now()
	leaf := peerCerts[0]

	rootsPEM, interPEM := v.cfg.Trust.RootsAndIntermediates()
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, p := range rootsPEM {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			return nil, errors.New("mesh: bad root PEM")
		}
	}
	inter := x509.NewCertPool()
	for _, p := range interPEM {
		inter.AppendCertsFromPEM([]byte(p))
	}
	for _, c := range peerCerts[1:] {
		inter.AddCert(c)
	}

	// We do our own time and revocation checks; verify at the current time
	// with a small skew allowance so a slightly fast client clock is not a
	// hard failure. Revocation below uses the real clock.
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	switch v.cfg.Expect {
	case ExpectClient:
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case ExpectServer:
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     usages,
	})
	if err != nil {
		return nil, fmt.Errorf("mesh: verify chain: %w", err)
	}
	chain := chains[0]

	id := &Identity{
		URI:      leaf.URIs[0].String(),
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: leaf.NotAfter,
		Chain:    chain,
		IssuedBy: chain[1].Subject.CommonName,
	}
	if m, err := metaOf(leaf); err == nil {
		id.Namespace, id.Service, id.Node, id.Instance = m.Namespace, m.Service, m.Node, m.Instance
		id.Mode = m.Mode
		id.BinarySHA256 = m.BinarySHA256
	} else {
		return nil, fmt.Errorf("mesh: peer certificate has no mesh identity")
	}
	if v.cfg.RequireMode != "" && id.Mode != v.cfg.RequireMode {
		return nil, fmt.Errorf("mesh: issuance mode %q not allowed", id.Mode)
	}
	if role, _ := certutil.RoleOf(leaf); true {
		id.Role = role
	}
	if v.cfg.RequireRole != "" && id.Role != v.cfg.RequireRole {
		return nil, fmt.Errorf("mesh: certificate role %q not allowed here", id.Role)
	}
	if err := v.checkScope(chain); err != nil {
		return nil, err
	}
	if rev := v.cfg.Trust.Revocations(); rev != nil {
		for _, e := range rev.Entries {
			if e.Matches(id) {
				return nil, fmt.Errorf("mesh: peer %s revoked: %s", id.URI, e.Reason)
			}
		}
	}
	return id, nil
}

// checkScope enforces that a degraded leaf came from a CA scoped to its node.
func (v *Verifier) checkScope(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return errors.New("mesh: no issuer in chain")
	}
	m, err := metaOf(chain[0])
	if err != nil {
		return err
	}
	sc, ok := scopeOf(chain[1])
	if !ok {
		if m.Mode == "degraded" {
			return errors.New("mesh: degraded certificate issued by unscoped CA")
		}
		return nil
	}
	if m.Node != sc.Node {
		return fmt.Errorf("mesh: certificate for node %q issued by CA scoped to %q", m.Node, sc.Node)
	}
	return nil
}

// Guard returns middleware that enforces two things the TLS handshake cannot:
//
//  1. The peer's certificate has not been revoked since the connection was
//     opened. TLS only checks at handshake time, and connections are long
//     lived. This is what makes revocation take effect in seconds rather
//     than at the next handshake.
//  2. The caller is authorized for the request path. The handler is given the
//     identity so it can make finer decisions.
func Guard(trust TrustSource, next func(http.ResponseWriter, *http.Request, *Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := r.TLS
		if st == nil || len(st.PeerCertificates) == 0 {
			http.Error(w, "mesh: client certificate required", http.StatusUnauthorized)
			return
		}
		id, err := NewVerifier(VerifierConfig{
			Trust: trust, Expect: ExpectClient, RequireRole: certutil.RoleWorkload,
		}).VerifyCerts(st.PeerCertificates, "")
		if err != nil {
			http.Error(w, "mesh: "+err.Error(), http.StatusForbidden)
			return
		}
		next(w, r.WithContext(ContextWithIdentity(r.Context(), id)), id)
	})
}

func metaOf(c *x509.Certificate) (*meta, error) {
	raw, ok := certExtension(c, oidMeta)
	if !ok {
		return nil, errors.New("no mesh metadata")
	}
	var m meta
	if err := jsonUnmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func scopeOf(c *x509.Certificate) (*scope, bool) {
	raw, ok := certExtension(c, oidScope)
	if !ok {
		return nil, false
	}
	var s scope
	if err := jsonUnmarshal(raw, &s); err != nil {
		return nil, false
	}
	return &s, true
}

// RotatingSource is a TLS certificate source whose material can be replaced
// at runtime. It implements tls.Config.GetCertificate / GetClientCertificate,
// so a swap affects only new handshakes; established connections keep
// working with the certificate they negotiated.
type RotatingSource struct {
	mu     sync.RWMutex
	cur    *tls.Certificate
	getter CertificateGetter // when set, the source delegates
	gen    atomic.Uint64
}

func NewRotatingSource(cert *tls.Certificate) *RotatingSource {
	r := &RotatingSource{}
	r.Set(cert)
	return r
}

// Set installs new material. It is atomic with respect to handshakes.
func (r *RotatingSource) Set(cert *tls.Certificate) {
	r.mu.Lock()
	r.cur = cert
	r.mu.Unlock()
	r.gen.Add(1)
}

// Get returns the current certificate.
func (r *RotatingSource) Get() (*tls.Certificate, uint64, bool) {
	r.mu.RLock()
	getter := r.getter
	cur := r.cur
	r.mu.RUnlock()
	if getter != nil {
		c, err := getter.GetCertificate(nil)
		if err != nil || c == nil {
			return nil, 0, false
		}
		return c, r.gen.Load(), true
	}
	if cur == nil {
		return nil, 0, false
	}
	return cur, r.gen.Load(), true
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *RotatingSource) GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	getter := r.getter
	cur := r.cur
	r.mu.RUnlock()
	if getter != nil {
		return getter.GetCertificate(hi)
	}
	if cur == nil {
		return nil, errors.New("mesh: no certificate available")
	}
	return cur, nil
}

// GetClientCertificate implements tls.Config.GetClientCertificate.
func (r *RotatingSource) GetClientCertificate(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	getter := r.getter
	cur := r.cur
	r.mu.RUnlock()
	if getter != nil {
		return getter.GetClientCertificate(cri)
	}
	if cur == nil {
		return nil, errors.New("mesh: no certificate available")
	}
	return cur, nil
}

// ServerConfig is the integration point for a service's TLS listener.
type ServerConfig struct {
	Verifier *Verifier
	// Certs is the server's own certificate source. It rotates like any
	// other mesh identity.
	Certs CertificateGetter
	// MinVersion defaults to TLS 1.3.
	MinVersion uint16
}

// TLSConfig builds the tls.Config for a listener. The returned value is
// stable; rotation happens through GetCertificate and VerifyConnection.
func (c ServerConfig) TLSConfig() *tls.Config {
	mv := c.MinVersion
	if mv == 0 {
		mv = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion: mv,
		// Verification of the peer is delegated to VerifyConnection so we
		// can express scope and revocation rules the stdlib does not.
		ClientAuth:     tls.RequireAnyClientCert,
		GetCertificate: c.Certs.GetCertificate,
		VerifyConnection: func(state tls.ConnectionState) error {
			return c.Verifier.VerifyConnection(state)
		},
	}
}

// DialConfig builds the client-side tls.Config for calling another service.
// The caller's certificate rotates; the server is verified against the same
// trust store, so a peer is authenticated in both directions.
func DialConfig(certs CertificateGetter, verifier *Verifier, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		ServerName:           serverName,
		GetClientCertificate: certs.GetClientCertificate,
		// Manual verification in VerifyConnection gives us control of
		// revocation and scope checks on the server certificate too.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifier.VerifyConnection(state)
		},
	}
}

// ListenTLS wraps a listener with the mesh TLS config.
func ListenTLS(ln net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(ln, cfg)
}
