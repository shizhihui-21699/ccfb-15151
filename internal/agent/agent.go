// Package agent implements the node agent: the privileged per-machine
// component that attests the machine to authd, rotates the node's own
// certificates, and decides which local processes get which service identity.
//
// # Trust split
//
// The node agent holds a node-scoped intermediate CA. That CA may issue
// certificates for exactly one node (its own), for at most a short TTL, and
// only for services the signed policy marks AllowDegraded. This is what lets
// the mesh keep issuing identities through an authd outage without letting a
// compromised host mint identities for anyone else.
//
// # Attestation
//
// The only secret on the machine is inside the simulated TPM. Enrollment
// proves the machine is a genuine machine with a vendor-certified endorsement
// key, and that the party asking owns that EK's child AK. It deliberately does
// not prove good behaviour afterwards; that is what policy, the short TTL and
// revocation are for.
package agent

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/identity"
	"meshid/internal/mesh"
	"meshid/internal/procinfo"
	"meshid/internal/trust"
)

// Config configures a node agent.
type Config struct {
	AgentID  string
	NodeName string
	// AuthdURLs are the control-plane replicas, tried in order with
	// short failure cooldowns. AuthdURL is used when this is empty.
	AuthdURLs []string
	AuthdURL  string
	DataDir   string
	SocketDir string
	Logger    *slog.Logger

	// LeafTTL is the lifetime of workload certificates.
	LeafTTL time.Duration
	// AgentCertTTL is the lifetime of the agent's own TLS certificate.
	AgentCertTTL time.Duration
	// AuthdCARoots are the roots trusted for the authd server certificate.
	AuthdCARoots []string
	// AuthdServerName is the name authd presents.
	AuthdServerName string

	TPM *hsm.Module

	Now func() time.Time

	// RevocationRefresh is how often the revocation list is pulled.
	RevocationRefresh time.Duration
	// ControlRefresh is how often bundle and policy are pulled.
	ControlRefresh time.Duration

	// AdminToken guards local admin endpoints.
	AdminToken string
}

// Agent is a running node agent.
type Agent struct {
	cfg  Config
	log  *slog.Logger
	tpm  *hsm.Module
	now  func() time.Time
	stop chan struct{}
	wg   sync.WaitGroup

	mu     sync.RWMutex
	ts     *trust.Store
	bundle *certutil.SignedBundle
	policy *certutil.SignedPolicy

	agentCreds   *identity.Creds
	nodeCACert   *x509.Certificate
	nodeCAChain  []*x509.Certificate
	nodeCASigner crypto.Signer
	nodeScope    certutil.Scope

	downUntil   map[string]time.Time
	nextReplica atomic.Int32

	enrolled     atomic.Bool
	authdOK      atomic.Bool
	lastSeen     atomic.Int64 // unix nanos
	lastIssueErr atomic.Value
}

// New builds an agent. Call Run.
func New(cfg Config) *Agent {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.LeafTTL == 0 {
		cfg.LeafTTL = 10 * time.Minute
	}
	if cfg.AgentCertTTL == 0 {
		cfg.AgentCertTTL = time.Hour
	}
	if cfg.RevocationRefresh == 0 {
		cfg.RevocationRefresh = 10 * time.Second
	}
	if cfg.ControlRefresh == 0 {
		cfg.ControlRefresh = 30 * time.Second
	}
	return &Agent{
		cfg:  cfg,
		log:  cfg.Logger.With("component", "agent", "node", cfg.NodeName),
		tpm:  cfg.TPM,
		now:  cfg.Now,
		stop: make(chan struct{}),
		ts:   trust.NewStore(),
	}
}

// Run enrolls, serves the identity socket, and runs renewal until Close.
func (a *Agent) Run() error {
	if err := a.Enroll(); err != nil {
		return err
	}
	ln, err := a.listen()
	if err != nil {
		return err
	}
	ln = PeerFactsListener(ln)
	srv := &http.Server{
		Handler:           a.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ConnContext:       ConnContextForFacts(),
	}
	a.wg.Add(1)
	go func() { defer a.wg.Done(); _ = srv.Serve(ln) }()

	a.wg.Add(1)
	go a.renewLoop()
	a.wg.Add(1)
	go a.controlLoop()

	a.log.Info("agent ready", "socket", a.SocketPath())
	<-a.stop
	_ = srv.Close()
	a.wg.Wait()
	return nil
}

// Close stops the agent.
func (a *Agent) Close() { close(a.stop) }

// SocketPath is the workload-facing Unix socket.
func (a *Agent) SocketPath() string { return filepath.Join(a.cfg.SocketDir, "agent.sock") }

// SocketAddr is the address a workload dials.
func (a *Agent) SocketAddr() string { return a.SocketPath() }

func (a *Agent) listen() (net.Listener, error) {
	if err := os.MkdirAll(a.cfg.SocketDir, 0o755); err != nil {
		return nil, err
	}
	p := a.SocketPath()
	_ = os.Remove(p)
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, err
	}
	// World-connectable; every request is still gated on verified kernel
	// facts about the peer, so the mode is not the authorization boundary.
	if err := os.Chmod(p, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Enroll runs the challenge -> attest -> enroll exchange.
func (a *Agent) Enroll() error {
	if _, err := a.tpm.CreateAK(a.cfg.NodeName); err != nil {
		return err
	}
	tlsCSR, caCSR, err := a.tpm.NodeCSRs(a.cfg.NodeName)
	if err != nil {
		return err
	}
	var ch api.ChallengeResponse
	if err := a.postJSON(api.PathChallenge, map[string]string{"node": a.cfg.NodeName}, &ch); err != nil {
		return fmt.Errorf("agent: challenge: %w", err)
	}
	tlsHash, caHash, err := a.tpm.NodeKeyHashes()
	if err != nil {
		return err
	}
	stmt := hsm.AttestStatement{
		Nonce: ch.Nonce, Node: a.cfg.NodeName,
		TLSKey: tlsHash, NodeCAKey: caHash, IssuedAt: a.now().Unix(),
	}
	sig, akCertPEM, akChain, err := a.tpm.Quote(stmt)
	if err != nil {
		return fmt.Errorf("agent: quote: %w", err)
	}
	ekCertPEM, ekChain := a.tpm.EKChainPEM()
	req := api.EnrollRequest{
		Node:            a.cfg.NodeName,
		TLSKeyCSRPEM:    tlsCSR,
		NodeCAKeyCSRPEM: caCSR,
		Attestation: api.Attestation{
			EKCertPEM: ekCertPEM, EKChainPEM: ekChain,
			AKCertPEM: akCertPEM, AKChainPEM: akChain,
			Nonce: ch.Nonce, Statement: stmt, Sig: sig,
		},
	}
	var resp api.EnrollResponse
	if err := a.postJSON(api.PathEnroll, req, &resp); err != nil {
		return fmt.Errorf("agent: enroll: %w", err)
	}
	if resp.Node != a.cfg.NodeName {
		return errors.New("agent: authd enrolled a different node")
	}
	if err := a.install(&resp); err != nil {
		return err
	}
	a.enrolled.Store(true)
	a.authdOK.Store(true)
	a.lastSeen.Store(a.now().UnixNano())
	a.log.Info("enrolled", "authd", resp.Bundle.SignerID,
		"bundle_version", resp.Bundle.Version)
	return nil
}

func (a *Agent) install(resp *api.EnrollResponse) error {
	nodeCA, err := certutil.ParseCertPEM(resp.NodeCACertPEM)
	if err != nil {
		return fmt.Errorf("agent: node CA: %w", err)
	}
	scope, err := certutil.ScopeOf(nodeCA)
	if err != nil {
		return fmt.Errorf("agent: node CA scope: %w", err)
	}
	if scope.Node != a.cfg.NodeName {
		return errors.New("agent: node CA scoped to a different node")
	}
	caSigner, err := a.tpm.NodeCASigner()
	if err != nil {
		return err
	}
	if !keysEqual(caSigner.Public(), nodeCA.PublicKey) {
		return errors.New("agent: node CA does not match TPM key")
	}
	agentSigner, err := a.tpm.NodeTLSSigner()
	if err != nil {
		return err
	}
	agentCert, err := certutil.ParseCertPEM(resp.AgentCertPEM)
	if err != nil {
		return err
	}
	if !keysEqual(agentSigner.Public(), agentCert.PublicKey) {
		return errors.New("agent: agent certificate does not match TPM key")
	}
	chain, err := certutil.ParseCertsPEM(resp.NodeCAChainPEM)
	if err != nil {
		return err
	}
	creds, err := identity.New(resp.AgentCertPEM, resp.AgentChainPEM, &resp.AgentMeta, resp.AgentRenewAfter)
	if err != nil {
		return err
	}
	if err := creds.SetKey(agentSigner); err != nil {
		return err
	}
	// The bundle must be signed by a root it names; the pinned root is the
	// one this agent already trusts from a previous enrollment, or the one
	// compiled into its image at first boot.
	if err := a.acceptBundle(&resp.Bundle); err != nil {
		return err
	}
	if err := a.acceptPolicy(&resp.Policy); err != nil {
		return err
	}
	a.ts.SetRevocations(&resp.Revocations.List)
	if resp.AKCertPEM != "" {
		if err := a.tpm.BindAKCert(resp.AKCertPEM, resp.AKChainPEM); err != nil {
			return err
		}
	}
	a.mu.Lock()
	a.agentCreds = creds
	a.nodeCACert = nodeCA
	a.nodeCAChain = chain
	a.nodeCASigner = caSigner
	a.nodeScope = *scope
	a.mu.Unlock()
	return nil
}

func keysEqual(a, b crypto.PublicKey) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	return err1 == nil && err2 == nil && string(da) == string(db)
}

// acceptBundle verifies and installs a signed bundle.
func (a *Agent) acceptBundle(b *certutil.SignedBundle) error {
	if b == nil {
		return nil
	}
	pinned := a.pinnedPool()
	if pinned == nil {
		// First enrollment: the bundle is the bootstrap. Its roots must
		// verify the signer and the signature.
		pool := x509.NewCertPool()
		for _, p := range b.Roots {
			if !pool.AppendCertsFromPEM([]byte(p)) {
				return errors.New("agent: malformed root in bundle")
			}
		}
		pinned = pool
	}
	if err := trust.VerifyBundle(b, pinned); err != nil {
		return err
	}
	a.mu.Lock()
	a.bundle = b
	a.mu.Unlock()
	return a.ts.SetBundle(b)
}

func (a *Agent) pinnedPool() *x509.CertPool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.bundle == nil {
		return nil
	}
	pool := x509.NewCertPool()
	for _, p := range a.bundle.Roots {
		pool.AppendCertsFromPEM([]byte(p))
	}
	return pool
}

func (a *Agent) rootPool() *x509.CertPool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	pool := x509.NewCertPool()
	if a.bundle != nil {
		for _, p := range a.bundle.Roots {
			pool.AppendCertsFromPEM([]byte(p))
		}
	}
	return pool
}

func (a *Agent) acceptPolicy(p *certutil.SignedPolicy) error {
	if p == nil {
		return nil
	}
	pool := a.rootPool()
	if err := trust.VerifyPolicy(p, pool); err != nil {
		return err
	}
	a.mu.Lock()
	a.policy = p
	a.mu.Unlock()
	return nil
}

func (a *Agent) policySnapshot() *certutil.Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.policy == nil {
		return nil
	}
	return &a.policy.Policy
}

// Trust returns a mesh.TrustSource over the cached documents.
func (a *Agent) Trust() mesh.TrustSource { return a.ts.TrustSource() }

// Credentials returns the agent's rotating TLS credentials.
func (a *Agent) Credentials() *identity.Creds {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.agentCreds
}

// ---- renewal and control-plane refresh ---------------------------------

func (a *Agent) renewLoop() {
	defer a.wg.Done()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
		}
		creds := a.Credentials()
		if creds == nil {
			continue
		}
		if a.now().Before(creds.RenewAt()) {
			continue
		}
		if err := a.renewAgentCert(); err != nil {
			a.log.Warn("agent certificate renewal failed", "err", err)
			a.authdOK.Store(false)
			continue
		}
		a.authdOK.Store(true)
		a.lastSeen.Store(a.now().UnixNano())
	}
}

// renewAgentCert re-issues the agent's TLS leaf. The CSR is rebuilt from the
// TPM-held key, so renewal never moves a private key.
func (a *Agent) renewAgentCert() error {
	csr, _, err := a.tpm.NodeCSRs(a.cfg.NodeName)
	if err != nil {
		return err
	}
	req := api.RenewAgentRequest{Node: a.cfg.NodeName, CSRPEM: csr}
	var resp api.EnrollResponse
	if err := a.postJSON(api.PathRenewAgent, req, &resp); err != nil {
		return err
	}
	a.mu.Lock()
	creds := a.agentCreds
	a.mu.Unlock()
	if creds == nil {
		return errors.New("agent: not enrolled")
	}
	return creds.Rotate(resp.AgentCertPEM, resp.AgentChainPEM, &resp.AgentMeta, resp.AgentRenewAfter)
}

func (a *Agent) controlLoop() {
	defer a.wg.Done()
	rt := time.NewTicker(a.cfg.RevocationRefresh)
	defer rt.Stop()
	ct := time.NewTicker(a.cfg.ControlRefresh)
	defer ct.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-rt.C:
			if err := a.refreshRevocations(); err != nil {
				a.log.Warn("revocation refresh failed; keeping cached list", "err", err)
			}
		case <-ct.C:
			if err := a.refreshControl(); err != nil {
				a.log.Warn("control refresh failed; keeping cached documents", "err", err)
			}
		}
	}
}

func (a *Agent) refreshRevocations() error {
	var r certutil.SignedRevocationList
	if err := a.getJSON(api.PathRevocations, &r); err != nil {
		return err
	}
	pool := a.rootPool()
	if len(pool.Subjects()) > 0 { //nolint:staticcheck // Subjects is the only size accessor
		if err := trust.VerifyRevocations(&r, pool); err != nil {
			return err
		}
	}
	a.ts.SetRevocations(&r.List)
	a.authdOK.Store(true)
	a.lastSeen.Store(a.now().UnixNano())
	return nil
}

func (a *Agent) refreshControl() error {
	var b certutil.SignedBundle
	if err := a.getJSON(api.PathBundle, &b); err == nil {
		if err := a.acceptBundle(&b); err != nil {
			a.log.Warn("rejected bundle", "err", err)
		}
	}
	var p certutil.SignedPolicy
	if err := a.getJSON(api.PathPolicy, &p); err == nil {
		if err := a.acceptPolicy(&p); err != nil {
			a.log.Warn("rejected policy", "err", err)
		}
	}
	return nil
}

// ---- issuing identities for local processes ----------------------------

// nodeRevoked reports whether this node appears in the cached revocation list
// at node granularity. A revoked node mints nothing, online or degraded.
func (a *Agent) nodeRevoked() bool {
	rev := a.ts.Load().Revocations
	if rev == nil {
		return false
	}
	for _, e := range rev.Entries {
		if e.Node == a.cfg.NodeName && e.Service == "" && e.Instance == "" && e.Serial == "" {
			return true
		}
	}
	return false
}

// IssueForLocalProcess verifies observed kernel facts against the policy and
// either has authd sign a certificate or, if authd is unreachable and policy
// permits, signs a short-lived degraded certificate with the node CA.
func (a *Agent) IssueForLocalProcess(ns, svc, csrPEM string, f *procinfo.Facts) (*api.WorkloadResponse, error) {
	if f == nil {
		return nil, errors.New("agent: no process facts")
	}
	// A revoked node must not mint anything, not even degraded identities.
	// The revocation list is cached, so this check works while authd is
	// unreachable — which is exactly when degraded issuance happens.
	if a.nodeRevoked() {
		return nil, errors.New("agent: node is revoked")
	}
	pol := a.policySnapshot()
	if pol == nil {
		return nil, errors.New("agent: no policy")
	}
	grant, ok := pol.FindGrant(ns, svc)
	if !ok {
		return nil, fmt.Errorf("agent: service %s/%s not in policy", ns, svc)
	}
	if err := checkFacts(grant, a.cfg.NodeName, f); err != nil {
		return nil, err
	}
	csr, err := certutil.ParseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	// Online path: ask authd. If it fails and policy allows degraded
	// issuance, fall back to the node CA.
	resp, err := a.issueOnline(ns, svc, csrPEM, f)
	if err == nil {
		a.authdOK.Store(true)
		a.lastSeen.Store(a.now().UnixNano())
		return resp, nil
	}
	a.authdOK.Store(false)
	// Only *unavailability* may trigger degraded issuance. An explicit
	// refusal from authd means central policy said no — for instance the
	// grant was withdrawn, or the node was revoked — and falling back would
	// let this node's stale cached policy override the control plane.
	if !isUnavailable(err) {
		return nil, fmt.Errorf("agent: authd refused issuance: %w", err)
	}
	if !grant.AllowDegraded {
		return nil, fmt.Errorf("agent: authd unavailable and degraded issuance not allowed for %s/%s: %w", ns, svc, err)
	}
	a.log.Warn("issuing degraded certificate", "svc", ns+"/"+svc, "err", err)
	return a.issueDegraded(grant, ns, svc, csr, f)
}

// isUnavailable reports whether err means "authd could not be reached or could
// not serve", as opposed to "authd declined". Only the former may lead to
// degraded issuance.
func isUnavailable(err error) bool {
	var e *api.ErrorResponse
	if errors.As(err, &e) {
		switch e.Code {
		case api.CodeUnavailable:
			return true
		default:
			return false
		}
	}
	return true
}

func checkFacts(g certutil.ServiceGrant, node string, f *procinfo.Facts) error {
	if g.RequireUID != nil && *g.RequireUID != f.UID {
		return fmt.Errorf("agent: process uid %d does not match required %d", f.UID, *g.RequireUID)
	}
	if g.BinarySHA256 != "" && g.BinarySHA256 != f.BinarySHA {
		return fmt.Errorf("agent: binary hash %s does not match policy", f.BinarySHA)
	}
	if len(g.Nodes) > 0 {
		found := false
		for _, n := range g.Nodes {
			if n == node {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("agent: service %s/%s not permitted on node %s", g.Namespace, g.Service, node)
		}
	}
	return nil
}

func (a *Agent) ttlFor(g certutil.ServiceGrant, pol *certutil.Policy) time.Duration {
	ttl := a.cfg.LeafTTL
	if pol.DefaultMaxTTLSec > 0 && ttl > time.Duration(pol.DefaultMaxTTLSec)*time.Second {
		ttl = time.Duration(pol.DefaultMaxTTLSec) * time.Second
	}
	if g.MaxTTLSec > 0 && ttl > time.Duration(g.MaxTTLSec)*time.Second {
		ttl = time.Duration(g.MaxTTLSec) * time.Second
	}
	return ttl
}

func (a *Agent) issueOnline(ns, svc, csrPEM string, f *procinfo.Facts) (*api.WorkloadResponse, error) {
	req := api.IssueRequest{
		Node: a.cfg.NodeName, Namespace: ns, Service: svc,
		Instance: f.InstanceName(), CSRPEM: csrPEM, Facts: *f,
	}
	var resp api.IssueResponse
	if err := a.postJSON(api.PathIssue, req, &resp); err != nil {
		return nil, err
	}
	a.ts.SetRevocations(&resp.Revocations.List)
	if resp.Bundle.Version > 0 {
		if err := a.acceptBundle(&resp.Bundle); err != nil {
			a.log.Warn("rejected bundle in issue response", "err", err)
		}
	}
	return &api.WorkloadResponse{
		CertPEM: resp.CertPEM, ChainPEM: resp.ChainPEM, Meta: resp.Meta,
		ExpiresAt: resp.ExpiresAt, RenewAfter: resp.RenewAfter,
		Mode: resp.Mode, Bundle: resp.Bundle, Revocations: resp.Revocations,
		AgentNode: a.cfg.NodeName,
	}, nil
}

// issueDegraded signs with the node CA. It is deliberately conservative:
// same node only, short TTL, explicit mode marker so peers can apply stricter
// authorization to degraded identities.
func (a *Agent) issueDegraded(g certutil.ServiceGrant, ns, svc string, csr *x509.CertificateRequest, f *procinfo.Facts) (*api.WorkloadResponse, error) {
	a.mu.RLock()
	caCert, chain, signer, scope := a.nodeCACert, a.nodeCAChain, a.nodeCASigner, a.nodeScope
	a.mu.RUnlock()
	if caCert == nil || signer == nil {
		return nil, errors.New("agent: no node CA available")
	}
	if a.now().After(caCert.NotAfter) {
		return nil, errors.New("agent: node CA expired; cannot issue degraded certificates")
	}
	ttl := a.ttlFor(g, a.policySnapshot())
	if scope.MaxTTLSec > 0 && ttl > time.Duration(scope.MaxTTLSec)*time.Second {
		ttl = time.Duration(scope.MaxTTLSec) * time.Second
	}
	inst := fmt.Sprintf("%s-%d-%x", a.cfg.NodeName, f.PID, time.Now().UnixNano())
	meta := &certutil.Meta{
		Namespace: ns, Service: svc, Node: a.cfg.NodeName, Instance: inst,
		Mode: certutil.ModeDegraded, Issuer: a.cfg.AgentID,
		UID: f.UID, PID: f.PID, ProcessStart: f.StartTime.Unix(), BinaryPath: f.Exe,
		BinarySHA256: f.BinarySHA, PolicyVersion: a.policyVersion(),
		AttestationAge: 0,
	}
	opts := certutil.IssueOptions{
		CN:     svc + "." + a.cfg.NodeName,
		URISAN: fmt.Sprintf("spiffe://%s/ns/%s/svc/%s/node/%s/inst/%s", certutil.MeshDomain, ns, svc, a.cfg.NodeName, inst),
		EKU:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		TTL:    ttl, Meta: meta, Role: certutil.RoleWorkload,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	notBefore := a.now().Add(-5 * time.Second)
	opts.NotBefore = notBefore
	der, err := certutil.NewCertSignedByCA(caCert, signer, csr.PublicKey, opts)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	// The peer needs the complete chain: the node CA that signed this leaf
	// plus the CAs that signed the node CA.
	chainPEM := []string{certutil.EncodeCertPEM(caCert.Raw)}
	for _, c := range chain {
		chainPEM = append(chainPEM, certutil.EncodeCertPEM(c.Raw))
	}
	a.mu.RLock()
	bundle := a.bundle
	a.mu.RUnlock()
	var sb certutil.SignedBundle
	if bundle != nil {
		sb = *bundle
	}
	var rev certutil.SignedRevocationList
	if r := a.ts.Load().Revocations; r != nil {
		rev.List = certutil.RevocationList{Version: r.Version}
	}
	return &api.WorkloadResponse{
		CertPEM: certutil.EncodeCertPEM(leaf.Raw), ChainPEM: chainPEM, Meta: *meta,
		ExpiresAt:  leaf.NotAfter,
		RenewAfter: leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3),
		Mode:       certutil.ModeDegraded, Bundle: sb, Revocations: rev,
		AgentNode: a.cfg.NodeName,
	}, nil
}

func (a *Agent) policyVersion() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.policy == nil {
		return 0
	}
	return a.policy.Policy.Version
}

// ---- HTTP surface -------------------------------------------------------

func (a *Agent) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.AgentPathIdentity, a.handleIdentity)
	mux.HandleFunc(api.AgentPathHealth, a.handleHealth)
	if a.cfg.AdminToken != "" {
		mux.HandleFunc("/admin/refresh", a.requireAdmin(a.handleAdminRefresh))
	}
	return mux
}

func (a *Agent) handleHealth(w http.ResponseWriter, r *http.Request) {
	serial := ""
	if c := a.Credentials(); c != nil {
		serial = c.Serial()
	}
	writeJSON(w, 200, map[string]any{
		"node": a.cfg.NodeName, "enrolled": a.enrolled.Load(),
		"authd_ok":        a.authdOK.Load(),
		"last_authd_seen": time.Unix(0, a.lastSeen.Load()).UTC(),
		"agent_serial":    serial,
		"node_ca":         a.cfg.NodeName,
	})
}

func (a *Agent) handleAdminRefresh(w http.ResponseWriter, r *http.Request) {
	if err := a.refreshControl(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := a.refreshRevocations(); err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *Agent) requireAdmin(h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Admin-Token") != a.cfg.AdminToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

// RefreshNow pulls policy and revocations immediately. Used by tests and by a
// control-plane event stream to cut propagation latency.
func (a *Agent) RefreshNow() {
	if err := a.refreshControl(); err != nil {
		a.log.Warn("control refresh failed", "err", err)
	}
	if err := a.refreshRevocations(); err != nil {
		a.log.Warn("revocation refresh failed", "err", err)
	}
}

// NodeCADebug exposes the node's intermediate certificate for tests that model
// a stolen node CA. The key is only obtainable through the TPM's simulation
// backdoor, mirroring "attacker reads agent memory".
func (a *Agent) NodeCADebug() *x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodeCACert
}

// NodeCAChainDebug returns the node intermediate chain for tests that model a
// stolen node CA presenting a complete chain.
func (a *Agent) NodeCAChainDebug() []*x509.Certificate {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.nodeCAChain
}
