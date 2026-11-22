// Package api defines the JSON wire format spoken between nodes, authd and
// workloads. All certificate material is PEM; all signatures are lowercase
// hex over SHA-256 of the canonical JSON payload.
package api

import (
	"time"

	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/procinfo"
)

// HTTP paths. authd serves all of them on one TLS listener; the endpoints
// that consume a node certificate require an authenticated peer.
const (
	PathChallenge   = "/v1/challenge"
	PathEnroll      = "/v1/enroll"
	PathIssue       = "/v1/issue"
	PathBundle      = "/v1/bundle"
	PathPolicy      = "/v1/policy"
	PathRevocations = "/v1/revocations"
	PathRevoke      = "/admin/revoke"
	PathRenewAgent  = "/v1/renew-agent"
	PathHealth      = "/v1/health"
	PathAuditTail   = "/admin/audit/tail"
)

// Agent-side paths (Unix socket).
const (
	AgentPathIdentity = "/v1/identity"
	AgentPathHealth   = "/v1/health"
)

// Error codes carried in ErrorResponse.Code.
const (
	CodeBadRequest      = "bad_request"
	CodeUnauthorized    = "unauthorized"
	CodeAttestationFail = "attestation_failed"
	CodePolicyDenied    = "policy_denied"
	CodeRevoked         = "revoked"
	CodeUnavailable     = "unavailable"
	CodeConflict        = "conflict"
)

// ErrorResponse is returned for every non-2xx response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *ErrorResponse) Error() string { return e.Code + ": " + e.Message }

// ChallengeResponse starts an enrollment. Nonces are single-use and expire.
type ChallengeResponse struct {
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
	AuthdID   string    `json:"authd_id"`
}

// Attestation is a TPM-style quote: the AK signs a statement that binds a
// fresh nonce to the node's TLS public key, so a replayed enrollment cannot
// be transplanted onto another key.
type Attestation struct {
	EKCertPEM  string   `json:"ek_cert_pem"`
	EKChainPEM []string `json:"ek_chain_pem,omitempty"`
	AKCertPEM  string   `json:"ak_cert_pem"`
	AKChainPEM []string `json:"ak_chain_pem,omitempty"`
	Nonce      string   `json:"nonce"`
	// Statement is exactly what the AK signed. Splitting it into fields
	// lets the server rebuild the canonical byte string independently.
	Statement hsm.AttestStatement `json:"statement"`
	Sig       string              `json:"sig"`
}

// EnrollRequest asks authd to certify a node. Both private keys live inside
// the node's TPM; only public keys and the attestation travel.
type EnrollRequest struct {
	Node            string      `json:"node"`
	TLSKeyCSRPEM    string      `json:"tls_key_csr_pem"`
	NodeCAKeyCSRPEM string      `json:"node_ca_key_csr_pem"`
	Attestation     Attestation `json:"attestation"`
}

// EnrollResponse carries everything a node needs to operate offline.
type EnrollResponse struct {
	Node            string                        `json:"node"`
	AgentCertPEM    string                        `json:"agent_cert_pem"`
	AgentChainPEM   []string                      `json:"agent_chain_pem"`
	NodeCACertPEM   string                        `json:"node_ca_cert_pem"`
	NodeCAChainPEM  []string                      `json:"node_ca_chain_pem"`
	AgentMeta       certutil.Meta                 `json:"agent_meta"`
	AgentRenewAfter time.Time                     `json:"agent_renew_after"`
	NodeScope       certutil.Scope                `json:"node_scope"`
	Bundle          certutil.SignedBundle         `json:"bundle"`
	Policy          certutil.SignedPolicy         `json:"policy"`
	Revocations     certutil.SignedRevocationList `json:"revocations"`
	AKCertPEM       string                        `json:"ak_cert_pem,omitempty"`
	AKChainPEM      []string                      `json:"ak_chain_pem,omitempty"`
}

// RenewAgentRequest re-issues the agent's own TLS certificate. It is
// authenticated by the agent's current certificate.
type RenewAgentRequest struct {
	Node   string `json:"node"`
	CSRPEM string `json:"csr_pem"`
}

// IssueRequest is sent by a node agent on behalf of a local process. Facts
// are the kernel-observed facts; authd checks them against central policy.
type IssueRequest struct {
	Node      string         `json:"node"`
	Namespace string         `json:"ns"`
	Service   string         `json:"svc"`
	Instance  string         `json:"inst"`
	CSRPEM    string         `json:"csr_pem"`
	Facts     procinfo.Facts `json:"facts"`
	// AgentSerial identifies the authenticated mTLS peer for audit. authd
	// takes the node identity from the connection, never from this field.
	AgentSerial int64 `json:"agent_serial"`
}

// IssueResponse is a freshly signed workload leaf.
type IssueResponse struct {
	CertPEM     string                        `json:"cert_pem"`
	ChainPEM    []string                      `json:"chain_pem"`
	Meta        certutil.Meta                 `json:"meta"`
	ExpiresAt   time.Time                     `json:"expires_at"`
	RenewAfter  time.Time                     `json:"renew_after"`
	Mode        string                        `json:"mode"`
	Revocations certutil.SignedRevocationList `json:"revocations"`
	Bundle      certutil.SignedBundle         `json:"bundle"`
}

// HealthResponse reports replica health and loaded versions.
type HealthResponse struct {
	AuthdID       string    `json:"authd_id"`
	Uptime        string    `json:"uptime"`
	BundleVersion int       `json:"bundle_version"`
	PolicyVersion int       `json:"policy_version"`
	RevVersion    int       `json:"rev_version"`
	Time          time.Time `json:"time"`
}

// RevokeRequest is the simulation control-plane operation. It is guarded by
// an admin token and rate limited; in production this lives behind a separate
// authenticated break-glass service.
type RevokeRequest struct {
	Node     string `json:"node,omitempty"`
	Service  string `json:"svc,omitempty"`
	Instance string `json:"inst,omitempty"`
	Serial   string `json:"serial,omitempty"`
	Reason   string `json:"reason"`
}

// WorkloadRequest is what a local process sends to the node agent.
type WorkloadRequest struct {
	Namespace string `json:"ns"`
	Service   string `json:"svc"`
	CSRPEM    string `json:"csr_pem"`
}

// WorkloadResponse is what the node agent returns.
type WorkloadResponse struct {
	CertPEM     string                        `json:"cert_pem"`
	ChainPEM    []string                      `json:"chain_pem"`
	Meta        certutil.Meta                 `json:"meta"`
	ExpiresAt   time.Time                     `json:"expires_at"`
	RenewAfter  time.Time                     `json:"renew_after"`
	Mode        string                        `json:"mode"`
	Bundle      certutil.SignedBundle         `json:"bundle"`
	Revocations certutil.SignedRevocationList `json:"revocations"`
	AgentNode   string                        `json:"agent_node"`
}

// AuditEvent is one line of the tamper-evident application log (JSONL).
type AuditEvent struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Node     string    `json:"node,omitempty"`
	Service  string    `json:"svc,omitempty"`
	Instance string    `json:"inst,omitempty"`
	Mode     string    `json:"mode,omitempty"`
	Remote   string    `json:"remote,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Outcome  string    `json:"outcome"`
}
