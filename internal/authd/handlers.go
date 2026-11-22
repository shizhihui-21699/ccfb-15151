package authd

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/mesh"
	"meshid/internal/store"
)

const maxBody = 1 << 20

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.PathChallenge, s.handleChallenge)
	mux.HandleFunc(api.PathEnroll, s.handleEnroll)
	mux.HandleFunc(api.PathIssue, s.handleIssue)
	mux.HandleFunc(api.PathRenewAgent, s.handleRenewAgent)
	mux.HandleFunc(api.PathBundle, s.handleBundle)
	mux.HandleFunc(api.PathPolicy, s.handlePolicy)
	mux.HandleFunc(api.PathRevocations, s.handleRevocations)
	mux.HandleFunc(api.PathHealth, s.handleHealth)
	return mux
}

func (s *Server) adminRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.PathRevoke, s.handleRevoke)
	mux.HandleFunc(api.PathAuditTail, s.handleAuditTail)
	mux.HandleFunc("/admin/policy", s.handlePutPolicy)
	mux.HandleFunc("/admin/health", s.handleHealth)
	return mux
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	var body struct {
		Node string `json:"node"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	nonce, exp, err := s.st.NewChallenge(body.Node, s.cfg.ReplicaID)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	writeJSON(w, 200, api.ChallengeResponse{Nonce: nonce, ExpiresAt: exp, AuthdID: s.cfg.ReplicaID})
}

// handleEnroll verifies node attestation and issues the node's long-lived
// bootstrap material: an agent certificate, a node-scoped intermediate, and
// signed trust documents.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	var req api.EnrollRequest
	if !s.decode(w, r, &req) {
		return
	}
	facts, code, err := s.verifyAttestation(&req)
	if err != nil {
		s.audit(map[string]any{"kind": "enroll", "node": req.Node, "outcome": "denied", "detail": err.Error()})
		s.fail(w, code, err.Error(), 403)
		return
	}

	tlsCSR, err := certutil.ParseCSR(req.TLSKeyCSRPEM)
	if err != nil {
		s.fail(w, api.CodeBadRequest, "bad TLS CSR: "+err.Error(), 400)
		return
	}
	caCSR, err := certutil.ParseCSR(req.NodeCAKeyCSRPEM)
	if err != nil {
		s.fail(w, api.CodeBadRequest, "bad node CA CSR: "+err.Error(), 400)
		return
	}
	// The CSR keys must be exactly the keys the quote is bound to.

	s.mu.RLock()
	nodeCA := s.nodeCA
	s.mu.RUnlock()
	if nodeCA == nil {
		s.fail(w, api.CodeUnavailable, "no node issuing CA", 503)
		return
	}

	agent, err := s.issueNodeAgent(nodeCA, req.Node, tlsCSR)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	nodeIntermediate, err := s.issueNodeIntermediate(nodeCA, req.Node, caCSR)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	bundle, err := s.st.Bundle()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	policy, err := s.st.Policy()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	revs, err := s.signedRevocations()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	resp := api.EnrollResponse{
		Node:            req.Node,
		AgentCertPEM:    certutil.EncodeCertPEM(agent.leaf.Raw),
		AgentChainPEM:   pems(agent.chain),
		NodeCACertPEM:   certutil.EncodeCertPEM(nodeIntermediate.leaf.Raw),
		NodeCAChainPEM:  pems(nodeIntermediate.chain),
		AgentMeta:       agent.meta,
		AgentRenewAfter: agent.renewAfter,
		NodeScope:       agent.scope,
		Bundle:          *bundle,
		Policy:          *policy,
		Revocations:     *revs,
		AKCertPEM:       req.Attestation.AKCertPEM,
		AKChainPEM:      req.Attestation.AKChainPEM,
	}
	s.audit(map[string]any{
		"kind": "enroll", "node": req.Node, "outcome": "issued",
		"ek": facts.EKFingerprint, "ak": facts.AKKeyID,
		"agent_serial": agent.leaf.SerialNumber.Text(16),
	})
	writeJSON(w, 200, resp)
}

// handleIssue signs a workload certificate for a local process. The caller is
// an authenticated node agent; the node identity comes from its certificate.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	// Only a node agent may ask for workload identities. A workload's own
	// certificate is for calling peers, never for minting identities.
	caller, ok := s.authenticateRole(w, r, certutil.RoleNodeAgent)
	if !ok {
		return
	}
	if caller.Mode == certutil.ModeDegraded {
		s.fail(w, api.CodeUnauthorized, "degraded identities may not request online issuance", 403)
		return
	}
	var req api.IssueRequest
	if !s.decode(w, r, &req) {
		return
	}
	// The node is whatever the agent's certificate says, never the body.
	if req.Node != caller.Node {
		s.fail(w, api.CodeUnauthorized, fmt.Sprintf("agent for node %q may not request for node %q", caller.Node, req.Node), 403)
		return
	}
	csr, err := certutil.ParseCSR(req.CSRPEM)
	if err != nil {
		s.fail(w, api.CodeBadRequest, "bad CSR: "+err.Error(), 400)
		return
	}
	pol, err := s.st.Policy()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	grant, ok := pol.Policy.FindGrant(req.Namespace, req.Service)
	if !ok {
		s.denyIssue(w, req, "service not in policy")
		return
	}
	if err := checkGrant(grant, req.Facts); err != nil {
		s.denyIssue(w, req, err.Error())
		return
	}
	if len(grant.Nodes) > 0 && !contains(grant.Nodes, caller.Node) {
		s.denyIssue(w, req, "service not permitted on node "+caller.Node)
		return
	}
	ttl := s.leafTTL(grant, &pol.Policy)
	inst := req.Instance
	if inst == "" {
		inst = fmt.Sprintf("p%d", req.Facts.PID)
	}
	meta := certutil.Meta{
		Namespace: req.Namespace, Service: req.Service, Node: caller.Node,
		Instance: inst, Mode: certutil.ModeOnline, Issuer: s.cfg.ReplicaID,
		UID: req.Facts.UID, PID: req.Facts.PID, ProcessStart: req.Facts.StartTime.Unix(),
		BinaryPath: req.Facts.Exe, BinarySHA256: req.Facts.BinarySHA,
		PolicyVersion: pol.Policy.Version,
	}
	s.mu.RLock()
	inter := s.intermediate
	s.mu.RUnlock()
	if inter == nil {
		s.fail(w, api.CodeUnavailable, "no issuing CA", 503)
		return
	}
	opts := certutil.IssueOptions{
		CN:     req.Service + "." + caller.Node,
		URISAN: fmt.Sprintf("spiffe://%s/ns/%s/svc/%s/node/%s/inst/%s", certutil.MeshDomain, req.Namespace, req.Service, caller.Node, inst),
		EKU:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		TTL:    ttl, Meta: &meta, Role: certutil.RoleWorkload,
		NotBefore: s.now().Add(-10 * time.Second),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}
	der, err := certutil.NewCertSignedByCA(inter.Cert, inter.Key, csr.PublicKey, opts)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	bundle, _ := s.st.Bundle()
	revs, _ := s.signedRevocations()
	resp := api.IssueResponse{
		CertPEM:  certutil.EncodeCertPEM(leaf.Raw),
		ChainPEM: pems([]*x509.Certificate{inter.Cert}),
		Meta:     meta,
		// Renew at 2/3 of the usable lifetime, measured from the leaf's
		// own validity, not from the backdated NotBefore.
		ExpiresAt:  leaf.NotAfter,
		RenewAfter: leaf.NotAfter.Add(-leaf.NotAfter.Sub(leaf.NotBefore) / 3),
		Mode:       certutil.ModeOnline,
	}
	if bundle != nil {
		resp.Bundle = *bundle
	}
	if revs != nil {
		resp.Revocations = *revs
	}
	s.audit(map[string]any{
		"kind": "issue", "node": caller.Node, "svc": req.Namespace + "/" + req.Service,
		"inst": inst, "pid": req.Facts.PID, "uid": req.Facts.UID,
		"bin": req.Facts.BinarySHA, "serial": leaf.SerialNumber.Text(16),
		"ttl": ttl.String(), "outcome": "issued",
	})
	writeJSON(w, 200, resp)
}

// handleRenewAgent re-issues the agent's own certificate. Authenticated by the
// current agent certificate; the CSR must be for the same node.
func (s *Server) handleRenewAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	caller, ok := s.authenticateRole(w, r, certutil.RoleNodeAgent)
	if !ok {
		return
	}
	var req api.RenewAgentRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Node != caller.Node {
		s.fail(w, api.CodeUnauthorized, "node mismatch", 403)
		return
	}
	csr, err := certutil.ParseCSR(req.CSRPEM)
	if err != nil {
		s.fail(w, api.CodeBadRequest, "bad CSR: "+err.Error(), 400)
		return
	}
	s.mu.RLock()
	nodeCA := s.nodeCA
	s.mu.RUnlock()
	agent, err := s.issueNodeAgent(nodeCA, caller.Node, csr)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	bundle, _ := s.st.Bundle()
	policy, _ := s.st.Policy()
	revs, _ := s.signedRevocations()
	resp := api.EnrollResponse{
		Node: req.Node, AgentCertPEM: certutil.EncodeCertPEM(agent.leaf.Raw),
		AgentChainPEM: pems(agent.chain), AgentMeta: agent.meta,
		AgentRenewAfter: agent.renewAfter,
	}
	if bundle != nil {
		resp.Bundle = *bundle
	}
	if policy != nil {
		resp.Policy = *policy
	}
	if revs != nil {
		resp.Revocations = *revs
	}
	s.audit(map[string]any{"kind": "renew-agent", "node": caller.Node, "outcome": "issued",
		"serial": agent.leaf.SerialNumber.Text(16)})
	writeJSON(w, 200, resp)
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.st.Bundle()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 503)
		return
	}
	writeJSON(w, 200, b)
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.st.Policy()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 503)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) handleRevocations(w http.ResponseWriter, r *http.Request) {
	rev, err := s.signedRevocations()
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 503)
		return
	}
	writeJSON(w, 200, rev)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	b, _ := s.st.Bundle()
	p, _ := s.st.Policy()
	rev, _ := s.st.Revocations()
	h := api.HealthResponse{AuthdID: s.cfg.ReplicaID, Uptime: time.Since(s.started).String(), Time: s.now()}
	if b != nil {
		h.BundleVersion = b.Version
	}
	if p != nil {
		h.PolicyVersion = p.Policy.Version
	}
	if rev != nil {
		h.RevVersion = rev.List.Version
	}
	writeJSON(w, 200, h)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	if !s.adminAuth(w, r) {
		return
	}
	var req api.RevokeRequest
	if !s.decode(w, r, &req) {
		return
	}
	if req.Serial == "" && req.Node == "" {
		s.fail(w, api.CodeBadRequest, "serial or node is required", 400)
		return
	}
	rev := certutil.Revocation{
		Serial: req.Serial, Node: req.Node, Service: req.Service,
		Instance: req.Instance, Reason: req.Reason,
	}
	rootPEM := certutil.EncodeCertPEM(s.cfg.Root.Cert.Raw)
	signed, err := s.st.Revoke(rev, func(l certutil.RevocationList) (*certutil.SignedRevocationList, error) {
		return certutil.SignRevocations(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, l)
	})
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	s.trust.SetRevocations(&signed.List)
	s.audit(map[string]any{"kind": "revoke", "node": req.Node, "svc": req.Service,
		"inst": req.Instance, "serial": req.Serial, "reason": req.Reason,
		"version": signed.List.Version, "outcome": "applied"})
	writeJSON(w, 200, signed)
}

func (s *Server) handleAuditTail(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuth(w, r) {
		return
	}
	n := 100
	if v := r.URL.Query().Get("n"); v != "" {
		fmt.Sscanf(v, "%d", &n)
	}
	lines, err := s.st.AuditTail(n)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/jsonl")
	for _, l := range lines {
		io.WriteString(w, l+"\n")
	}
}

func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.fail(w, api.CodeBadRequest, "method not allowed", 405)
		return
	}
	if !s.adminAuth(w, r) {
		return
	}
	var pol certutil.Policy
	if !s.decode(w, r, &pol) {
		return
	}
	cur, err := s.st.Policy()
	if err == nil {
		pol.Version = cur.Policy.Version + 1
	}
	if pol.Version == 0 {
		pol.Version = 1
	}
	if pol.DefaultMaxTTLSec == 0 {
		pol.DefaultMaxTTLSec = int64(s.cfg.LeafTTL.Seconds())
	}
	pol.UpdatedAt = s.now().UTC()
	rootPEM := certutil.EncodeCertPEM(s.cfg.Root.Cert.Raw)
	sp, err := certutil.SignPolicy(s.cfg.Root.Key, s.cfg.Root.ID, rootPEM, pol)
	if err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	if err := s.st.PutPolicy(sp); err != nil {
		s.fail(w, api.CodeUnavailable, err.Error(), 500)
		return
	}
	s.audit(map[string]any{"kind": "policy", "version": pol.Version, "grants": len(pol.Grants), "outcome": "updated"})
	writeJSON(w, 200, sp)
}

func (s *Server) signedRevocations() (*certutil.SignedRevocationList, error) {
	r, err := s.st.Revocations()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return r, nil
}

func (s *Server) adminAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		s.fail(w, api.CodeUnauthorized, "admin disabled", 403)
		return false
	}
	if r.Header.Get("X-Admin-Token") != s.cfg.AdminToken {
		s.fail(w, api.CodeUnauthorized, "unauthorized", 401)
		return false
	}
	return true
}

func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v); err != nil {
		s.fail(w, api.CodeBadRequest, "bad JSON: "+err.Error(), 400)
		return false
	}
	return true
}

func (s *Server) fail(w http.ResponseWriter, code, msg string, status int) {
	writeJSON(w, status, api.ErrorResponse{Code: code, Message: msg})
}

func (s *Server) denyIssue(w http.ResponseWriter, req api.IssueRequest, msg string) {
	s.audit(map[string]any{"kind": "issue", "node": req.Node,
		"svc": req.Namespace + "/" + req.Service, "pid": req.Facts.PID,
		"bin": req.Facts.BinarySHA, "outcome": "denied", "detail": msg})
	s.fail(w, api.CodePolicyDenied, msg, 403)
}

func (s *Server) audit(ev map[string]any) {
	ev["at"] = s.now().UTC()
	ev["replica"] = s.cfg.ReplicaID
	if err := s.st.Audit(ev); err != nil {
		s.log.Warn("audit write failed", "err", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// authenticate verifies the caller's client certificate against the mesh
// trust store and returns its identity.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*mesh.Identity, bool) {
	return s.authenticateRole(w, r, "")
}

// authenticateRole is authenticate plus a role requirement. The issuance and
// renewal endpoints must only be reachable with a *node agent* certificate:
// a workload certificate is a client identity, not an issuer, and must never
// be able to request another service's identity.
func (s *Server) authenticateRole(w http.ResponseWriter, r *http.Request, role string) (*mesh.Identity, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.fail(w, api.CodeUnauthorized, "client certificate required", 401)
		return nil, false
	}
	v := mesh.NewVerifier(mesh.VerifierConfig{
		Trust: s.trust.TrustSource(), Expect: mesh.ExpectClient, RequireRole: role,
	})
	id, err := v.VerifyCerts(r.TLS.PeerCertificates, "")
	if err != nil {
		s.audit(map[string]any{"kind": "auth", "required_role": role, "outcome": "denied", "detail": err.Error()})
		s.fail(w, api.CodeUnauthorized, err.Error(), 403)
		return nil, false
	}
	return id, true
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if strings.EqualFold(y, x) {
			return true
		}
	}
	return false
}

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
