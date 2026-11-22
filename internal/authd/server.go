// Package authd is the identity signing service. It is deliberately small and
// stateless: every replica loads the same signed documents from the store and
// holds only a short-lived intermediate under a root whose key is offline.
//
// Responsibilities:
//
//   - verify node attestation (TPM EK -> AK -> quote) and issue node agent
//     certificates plus node-scoped intermediates;
//   - issue workload certificates on request from an authenticated node agent,
//     re-checking central policy against the kernel facts the agent reports;
//   - serve the trust bundle, policy and revocation list, all signed so peers
//     can keep using cached copies while authd is down;
//   - maintain the revocation list and the audit log.
//
// What it does *not* hold: the root private key, workload private keys, or any
// per-node secret. Compromising one replica yields a 30-day intermediate that
// is itself revocable, which is why the intermediate is short-lived and why
// peers enforce revocation on every connection.
package authd

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/mesh"
	"meshid/internal/store"
	"meshid/internal/trust"
)

// Config configures one authd replica.
type Config struct {
	ReplicaID  string
	Addr       string
	Logger     *slog.Logger
	AdminToken string
	Now        func() time.Time
	Store      *store.Store

	// Root is the offline root authority. In production only the public
	// half reaches authd; the private half signs bundles/policies offline
	// and authd holds a pre-signed set. The simulation keeps it so a single
	// process can bootstrap.
	Root *certutil.Authority

	// VendorRoots are the platform roots trusted for EK certificates.
	VendorRoots *x509.CertPool

	// IntermediateTTL is the lifetime of this replica's issuing CA.
	IntermediateTTL time.Duration
	// LeafTTL is the default workload certificate lifetime.
	LeafTTL time.Duration
	// NodeAgentTTL is the lifetime of a node agent's TLS certificate.
	NodeAgentTTL time.Duration
	// NodeCATTL is the lifetime of a node-scoped intermediate.
	NodeCATTL time.Duration

	// AuthdCert is this replica's TLS server certificate (a mesh identity
	// issued by the root, served on the mesh listener).
	AuthdCertPEM  string
	AuthdKeyPEM   string
	AuthdChainPEM []string

	// Admin listener (plain HTTP on loopback) for simulation control.
	AdminAddr string
}

// Server is one authd replica.
type Server struct {
	cfg Config
	log *slog.Logger
	st  *store.Store
	now func() time.Time

	mu sync.RWMutex
	// intermediate is this replica's issuing CA for workload leaves.
	intermediate *certutil.Authority
	nodeCA       *certutil.Authority // issues node agent certs and node CAs

	trust *trust.Store

	srv      *http.Server
	adminSrv *http.Server
	ln       net.Listener
	adminLn  net.Listener

	started time.Time
}

// New builds a replica. It loads or creates its issuing intermediate.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IntermediateTTL == 0 {
		cfg.IntermediateTTL = 30 * 24 * time.Hour
	}
	if cfg.LeafTTL == 0 {
		cfg.LeafTTL = 10 * time.Minute
	}
	if cfg.NodeAgentTTL == 0 {
		cfg.NodeAgentTTL = time.Hour
	}
	if cfg.NodeCATTL == 0 {
		cfg.NodeCATTL = 6 * time.Hour
	}
	s := &Server{
		cfg:     cfg,
		log:     cfg.Logger.With("component", "authd", "replica", cfg.ReplicaID),
		st:      cfg.Store,
		now:     cfg.Now,
		trust:   trust.NewStore(),
		started: cfg.Now(),
	}
	if err := s.bootstrap(); err != nil {
		return nil, err
	}
	return s, nil
}

// bootstrap loads the signed documents, creating them on first run, and makes
// sure this replica has a live intermediate.
func (s *Server) bootstrap() error {
	if err := s.ensureDocuments(); err != nil {
		return err
	}
	b, err := s.st.Bundle()
	if err != nil {
		return err
	}
	if err := s.trust.SetBundle(b); err != nil {
		return err
	}
	r, err := s.st.Revocations()
	if err == nil {
		s.trust.SetRevocations(&r.List)
	}
	return s.ensureIntermediate()
}

// ensureDocuments creates the initial bundle, policy and revocation list if
// the store is empty. The bundle declares the root; the policy starts empty
// (deny by default) and is replaced by the operator.
func (s *Server) ensureDocuments() error {
	if _, err := s.st.Bundle(); err == nil {
		return nil
	}
	if s.cfg.Root == nil {
		return errors.New("authd: store empty and no root provided")
	}
	rootPEM := certutil.EncodeCertPEM(s.cfg.Root.Cert.Raw)
	bundle := certutil.Bundle{
		Version:   1,
		Roots:     []string{rootPEM},
		UpdatedAt: s.now().UTC(),
	}
	sb, err := certutil.SignBundle(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, bundle)
	if err != nil {
		return err
	}
	if err := s.st.PutBundle(sb); err != nil {
		return err
	}
	pol := certutil.Policy{Version: 1, DefaultMaxTTLSec: int64(s.cfg.LeafTTL.Seconds()), UpdatedAt: s.now().UTC()}
	sp, err := certutil.SignPolicy(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, pol)
	if err != nil {
		return err
	}
	if err := s.st.PutPolicy(sp); err != nil {
		return err
	}
	rl := certutil.RevocationList{Version: 1, IssuedAt: s.now().UTC()}
	sr, err := certutil.SignRevocations(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, rl)
	if err != nil {
		return err
	}
	return s.st.PutRevocations(sr)
}

// ensureIntermediate creates this replica's issuing CAs, or reloads them from
// the store if they are still valid. Intermediates are per replica so the
// blast radius of a replica compromise ends with that replica.
func (s *Server) ensureIntermediate() error {
	key := "authd-" + s.cfg.ReplicaID
	if der, k, ok := s.loadIntermediate(key); ok {
		inter, err := x509.ParseCertificate(der)
		if err == nil && s.now().Add(2*time.Hour).Before(inter.NotAfter) {
			nodeCA, nerr := s.loadOrCreateNodeCA()
			if nerr != nil {
				return nerr
			}
			s.mu.Lock()
			s.intermediate = &certutil.Authority{ID: key, Cert: inter, Key: k}
			s.nodeCA = nodeCA
			s.mu.Unlock()
			return s.publishIntermediates()
		}
	}
	inter, err := s.cfg.Root.NewIntermediate(key, s.cfg.IntermediateTTL, nil)
	if err != nil {
		return err
	}
	// A node-agent issuing CA is separate so its scope can be tightened and
	// revoked independently from workload issuance.
	nodeCA, err := s.loadOrCreateNodeCA()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.intermediate = inter
	s.nodeCA = nodeCA
	s.mu.Unlock()
	s.saveIntermediate(key, inter)
	s.log.Info("issuing intermediate ready", "id", key, "expires", inter.Cert.NotAfter)
	return s.publishIntermediates()
}

func (s *Server) loadOrCreateNodeCA() (*certutil.Authority, error) {
	key := "node-issuing"
	if der, k, ok := s.loadIntermediate(key); ok {
		c, err := x509.ParseCertificate(der)
		if err == nil && s.now().Add(48*time.Hour).Before(c.NotAfter) {
			return &certutil.Authority{ID: key, Cert: c, Key: k}, nil
		}
	}
	return s.cfg.Root.NewIntermediate(key, 30*24*time.Hour, nil)
}

func (s *Server) loadIntermediate(id string) ([]byte, *ecdsa.PrivateKey, bool) {
	b, err := s.st.Bundle()
	_ = b
	certPEM, err := s.st.LoadDoc("intermediate-" + id + ".crt")
	if err != nil {
		return nil, nil, false
	}
	keyPEM, err := s.st.LoadDoc("intermediate-" + id + ".key")
	if err != nil {
		return nil, nil, false
	}
	c, err := certutil.ParseCertPEM(string(certPEM))
	if err != nil {
		return nil, nil, false
	}
	k, err := certutil.ParseKeyPEM(string(keyPEM))
	if err != nil {
		return nil, nil, false
	}
	return c.Raw, k, true
}

func (s *Server) saveIntermediate(id string, a *certutil.Authority) {
	kPEM, err := certutil.EncodeKeyPEM(a.Key)
	if err != nil {
		s.log.Error("cannot encode intermediate key", "err", err)
		return
	}
	_ = s.st.SaveDoc("intermediate-"+id+".crt", []byte(certutil.EncodeCertPEM(a.Cert.Raw)), 0o600)
	_ = s.st.SaveDoc("intermediate-"+id+".key", []byte(kPEM), 0o600)
}

// publishIntermediates refreshes the signed bundle's intermediate list so
// peers can build chains for the leaves this replica issues.
func (s *Server) publishIntermediates() error {
	s.mu.RLock()
	var pems []string
	if s.intermediate != nil {
		pems = append(pems, certutil.EncodeCertPEM(s.intermediate.Cert.Raw))
	}
	if s.nodeCA != nil {
		pems = append(pems, certutil.EncodeCertPEM(s.nodeCA.Cert.Raw))
	}
	s.mu.RUnlock()

	cur, err := s.st.Bundle()
	if err != nil {
		return err
	}
	if equalStringSets(cur.Intermediates, pems) {
		return nil
	}
	rootPEM := certutil.EncodeCertPEM(s.cfg.Root.Cert.Raw)
	b := certutil.Bundle{
		Version:       cur.Version + 1,
		Roots:         cur.Roots,
		Intermediates: pems,
		UpdatedAt:     s.now().UTC(),
	}
	sb, err := certutil.SignBundle(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, b)
	if err != nil {
		return err
	}
	if err := s.st.PutBundle(sb); err != nil {
		return err
	}
	return s.trust.SetBundle(sb)
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		if m[x] == 0 {
			return false
		}
		m[x]--
	}
	return true
}

// Listen binds the mesh listener. The server certificate is a mesh identity,
// verified by agents against the same trust store they use for everything
// else.
func (s *Server) Listen() error {
	certPEM := s.cfg.AuthdCertPEM
	for _, c := range s.cfg.AuthdChainPEM {
		certPEM += c
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(s.cfg.AuthdKeyPEM))
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		// The challenge and enrollment endpoints must accept callers that
		// have no certificate yet, so the handshake only requests one. Every
		// endpoint that does anything sensitive re-verifies the peer per
		// request (see authenticateRole), which is also what makes revocation
		// effective between handshakes.
		ClientAuth: tls.RequestClientCert,
	}
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.ln = tls.NewListener(ln, tlsCfg)
	s.srv = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second}
	if s.cfg.AdminAddr != "" {
		aln, err := net.Listen("tcp", s.cfg.AdminAddr)
		if err != nil {
			return err
		}
		s.adminLn = aln
		s.adminSrv = &http.Server{Handler: s.adminRoutes(), ReadHeaderTimeout: 5 * time.Second}
	}
	return nil
}

// Serve blocks serving both listeners until Shutdown.
func (s *Server) Serve() error {
	errCh := make(chan error, 2)
	go func() { errCh <- s.srv.Serve(s.ln) }()
	if s.adminSrv != nil {
		go func() { errCh <- s.adminSrv.Serve(s.adminLn) }()
	}
	err := <-errCh
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Addr returns the bound mesh address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// AdminAddr returns the bound admin address.
func (s *Server) AdminAddr() string {
	if s.adminLn == nil {
		return ""
	}
	return s.adminLn.Addr().String()
}

// Shutdown stops serving.
func (s *Server) Shutdown() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.adminSrv != nil {
		s.adminSrv.Close()
	}
}

// TrustSource exposes the replica's trust view (used by tests).
func (s *Server) TrustSource() mesh.TrustSource { return s.trust.TrustSource() }
