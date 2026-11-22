package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/procinfo"
)

type factsKey struct{}

// handleIdentity is the workload-facing endpoint. It answers one question:
// "which process is connected, and may it have a certificate for the service
// it asked for?"
//
// Nothing in the request body is trusted for identity. The service name is a
// claim checked against kernel facts about the peer and the signed policy. A
// process that asks for a service it is not the pinned binary for is refused
// no matter what it says about itself.
func (a *Agent) handleIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	captured, ok := r.Context().Value(factsKey{}).(*procinfo.Facts)
	if !ok {
		writeError(w, http.StatusForbidden, api.CodeAttestationFail, "agent: connection has no verified peer")
		return
	}
	var req api.WorkloadRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, api.CodeBadRequest, err.Error())
		return
	}
	if req.Namespace == "" || req.Service == "" || req.CSRPEM == "" {
		writeError(w, http.StatusBadRequest, api.CodeBadRequest, "ns, svc and csr_pem are required")
		return
	}

	// Re-read the process now and require it to be the same instance that
	// was accepted: same PID, same start time, same executable hash. This
	// closes the window where a process exits and its PID is reused by
	// something else between accept and issuance.
	live, err := procinfo.ProcessFacts(captured.PID)
	if err != nil || live.StableID() != captured.StableID() {
		writeError(w, http.StatusForbidden, api.CodeAttestationFail, "agent: peer process changed during issuance")
		return
	}
	facts := captured

	resp, err := a.IssueForLocalProcess(req.Namespace, req.Service, req.CSRPEM, facts)
	if err != nil {
		code := api.CodePolicyDenied
		var e *api.ErrorResponse
		if errors.As(err, &e) {
			code = e.Code
		}
		writeError(w, http.StatusForbidden, code, err.Error())
		a.log.Info("identity denied", "pid", facts.PID, "uid", facts.UID,
			"exe", facts.Exe, "svc", req.Namespace+"/"+req.Service, "err", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
	a.log.Info("identity issued", "pid", facts.PID, "uid", facts.UID,
		"svc", req.Namespace+"/"+req.Service, "mode", resp.Mode,
		"serial", serialOf(resp.CertPEM))
}

func serialOf(certPEM string) string {
	c, err := certutil.ParseCertPEM(certPEM)
	if err != nil {
		return ""
	}
	return c.SerialNumber.Text(16)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, api.ErrorResponse{Code: code, Message: msg})
}

// PeerFactsListener wraps a Unix listener so each accepted connection carries
// the verified facts of its peer, read once at accept time.
//
// Accept-time capture is deliberate. By the time the handler runs the peer may
// have exited or execed, and either would change what the kernel reports.
// Facts are pinned to the connection and re-validated against the live process
// before a certificate is signed.
func PeerFactsListener(ln net.Listener) net.Listener { return &factsListener{Listener: ln} }

type factsListener struct{ net.Listener }

func (l *factsListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			continue
		}
		f, err := procinfo.PeerFacts(uc)
		if err != nil {
			// Peer gone or unreadable: drop it. Never serve a connection
			// whose peer identity could not be established.
			c.Close()
			continue
		}
		return &factsConn{UnixConn: uc, facts: f}, nil
	}
}

type factsConn struct {
	*net.UnixConn
	facts *procinfo.Facts
}

// ConnContextForFacts returns a http.Server.ConnContext that attaches the
// facts pinned at accept time.
func ConnContextForFacts() func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, c net.Conn) context.Context {
		if fc, ok := c.(*factsConn); ok {
			return context.WithValue(ctx, factsKey{}, fc.facts)
		}
		return ctx
	}
}
