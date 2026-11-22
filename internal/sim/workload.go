package sim

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/identity"
	"meshid/internal/mesh"
)

// RequestIdentity asks a node agent for a certificate. The call rides a real
// Unix socket so the agent's kernel-fact verification runs for real: the peer
// PID read by the agent is this process.
//
// The service name passed here is a *claim*. The agent decides whether it is
// true by looking at this process.
func RequestIdentity(ctx context.Context, sock, ns, svc string) (*identity.Creds, *api.WorkloadResponse, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := certutil.NewCSR(key, svc)
	if err != nil {
		return nil, nil, err
	}
	body, err := json.Marshal(api.WorkloadRequest{Namespace: ns, Service: svc, CSRPEM: csr})
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent"+api.AgentPathIdentity, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Code != "" {
			return nil, nil, &e
		}
		return nil, nil, fmt.Errorf("agent: %s: %s", resp.Status, data)
	}
	var wr api.WorkloadResponse
	if err := json.Unmarshal(data, &wr); err != nil {
		return nil, nil, err
	}
	creds, err := identity.New(wr.CertPEM, wr.ChainPEM, &wr.Meta, wr.RenewAfter)
	if err != nil {
		return nil, nil, err
	}
	if err := creds.SetKey(key); err != nil {
		return nil, nil, err
	}
	return creds, &wr, nil
}

// Workload is a running simulated service: it has credentials, serves mTLS on
// a loopback port, and can call other services.
type Workload struct {
	Name    string
	Meta    certutil.Meta
	Trust   mesh.TrustSource
	CertPEM string
	Chain   []string

	mu    sync.RWMutex
	creds *identity.Creds

	ln  net.Listener
	srv *http.Server
	url string
}

// Credentials returns the current credential set.
func (w *Workload) Credentials() *identity.Creds {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.creds
}

// SetCredentials swaps in a rotated credential set. Calls in flight keep using
// the pointer they already fetched; new handshakes use the new one.
func (w *Workload) SetCredentials(c *identity.Creds) {
	w.mu.Lock()
	w.creds = c
	w.mu.Unlock()
}

// Serve starts an mTLS listener that returns its own identity on "/whoami".
func (w *Workload) Serve() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	verifier := mesh.NewVerifier(mesh.VerifierConfig{Trust: w.Trust, Expect: mesh.ExpectClient})
	cfg := mesh.ServerConfig{
		Verifier: verifier,
		Certs:    w.Credentials(),
	}.TLSConfig()
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(rw http.ResponseWriter, r *http.Request) {
		id, ok := mesh.FromContext(r.Context())
		if !ok {
			http.Error(rw, "no peer", 401)
			return
		}
		json.NewEncoder(rw).Encode(map[string]string{
			"caller": id.URI, "svc": id.Service, "node": id.Node,
			"mode": id.Mode, "serial": id.Serial,
		})
	})
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, r *http.Request) { io.WriteString(rw, "ok") })
	handler := mesh.Guard(w.Trust, func(rw http.ResponseWriter, r *http.Request, id *mesh.Identity) {
		mux.ServeHTTP(rw, r)
	})
	w.ln = tls.NewListener(ln, cfg)
	w.srv = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	w.url = "https://" + ln.Addr().String()
	go w.srv.Serve(w.ln)
	return nil
}

// URL is the https endpoint of the workload, empty before Serve.
func (w *Workload) URL() string { return w.url }

// Close stops the listener.
func (w *Workload) Close() {
	if w.srv != nil {
		w.srv.Close()
	}
}

// Client builds an mTLS client that presents this workload's certificate and
// verifies the server with the same rules.
func (w *Workload) Client() *http.Client {
	verifier := mesh.NewVerifier(mesh.VerifierConfig{Trust: w.Trust, Expect: mesh.ExpectServer})
	// Resolve the credential source once; it is itself a live view, so
	// rotation after this point still takes effect.
	cfg := mesh.DialConfig(w.Credentials(), verifier, "")
	// The simulated servers listen on 127.0.0.1 with a URI SAN, not a DNS
	// name, so ServerName stays empty and verification is by chain.
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			ForceAttemptHTTP2: false,
			MaxIdleConns:      4,
			IdleConnTimeout:   30 * time.Second,
		},
	}
}

// Call performs one authenticated request and returns the caller identity the
// peer reported.
func (w *Workload) Call(ctx context.Context, target, path string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := w.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return nil, &HTTPError{Status: resp.StatusCode, Body: string(data)}
	}
	var out map[string]string
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// HTTPError preserves status for assertions.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("http %d: %s", e.Status, e.Body) }

// WriteWorkload writes an executable stand-in for a service binary so tests
// can pin an exact binary hash in policy. The returned path is a copy of the
// test binary (so it is a real executable) with a marker appended, which
// changes the hash without changing behaviour.
func WriteWorkload(dir, name, marker string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	src, err := os.ReadFile(self)
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, append(src, []byte("\n--marker:"+marker+"--\n")...), 0o755); err != nil {
		return "", err
	}
	return p, nil
}

// ExecError marks a failure to run a chosen executable.
type ExecError struct{ Err error }

func (e *ExecError) Error() string { return "sim: cannot exec chosen binary: " + e.Err.Error() }
func (e *ExecError) Unwrap() error { return e.Err }

var errEmptyExe = errors.New("sim: empty executable")

// WorkloadFromJSON rebuilds a Workload from the credentials JSON written by a
// worker process. The private key is re-created by the caller; this helper only
// reconstructs the public material, so tests drive the private key explicitly
// through RequestIdentity.
func WorkloadFromJSON(t interface{ Fatalf(string, ...any) }, b []byte) *Workload {
	var raw struct {
		Cert       string        `json:"cert"`
		Chain      []string      `json:"chain"`
		Meta       certutil.Meta `json:"meta"`
		Key        string        `json:"key"`
		RenewAfter time.Time     `json:"renew_after"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("creds json: %v", err)
	}
	creds, err := identity.New(raw.Cert, raw.Chain, &raw.Meta, raw.RenewAfter)
	if err != nil {
		t.Fatalf("creds: %v", err)
	}
	if raw.Key != "" {
		k, err := certutil.ParseKeyPEM(raw.Key)
		if err != nil {
			t.Fatalf("creds key: %v", err)
		}
		if err := creds.SetKey(k); err != nil {
			t.Fatalf("creds SetKey: %v", err)
		}
	}
	return &Workload{Name: raw.Meta.Service, creds: creds, Meta: raw.Meta, CertPEM: raw.Cert, Chain: raw.Chain}
}

// RequestIdentityWithTrust is RequestIdentity for callers that already hold
// their key (so renewal can reuse the same key) and that need the trust
// material the agent returns. It also rebuilds a TrustSource from the response
// so a standalone process can verify peers without calling back to the agent.
func RequestIdentityWithTrust(ctx context.Context, sock, ns, svc, csrPEM string, key *ecdsa.PrivateKey) (*identity.Creds, *api.WorkloadResponse, mesh.TrustSource, error) {
	body, err := json.Marshal(api.WorkloadRequest{Namespace: ns, Service: svc, CSRPEM: csrPEM})
	if err != nil {
		return nil, nil, nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent"+api.AgentPathIdentity, bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Code != "" {
			return nil, nil, nil, &e
		}
		return nil, nil, nil, fmt.Errorf("agent: %s: %s", resp.Status, data)
	}
	var wr api.WorkloadResponse
	if err := json.Unmarshal(data, &wr); err != nil {
		return nil, nil, nil, err
	}
	creds, err := identity.New(wr.CertPEM, wr.ChainPEM, &wr.Meta, wr.RenewAfter)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := creds.SetKey(key); err != nil {
		return nil, nil, nil, err
	}
	return creds, &wr, StaticTrustFrom(&wr), nil
}

// StaticTrustFrom builds a TrustSource from the documents returned with a
// credential response. This is the "cached signed documents" path: a process
// that has them can verify peers without any control-plane call.
func StaticTrustFrom(wr *api.WorkloadResponse) mesh.TrustSource {
	ts := &staticTrust{}
	ts.set(wr)
	return ts
}

type staticTrust struct {
	roots []string
	inter []string
	revs  *mesh.RevocationSnapshot
	ver   int
	mu    sync.RWMutex
}

func (s *staticTrust) set(wr *api.WorkloadResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(wr.Bundle.Roots) > 0 {
		s.roots = wr.Bundle.Roots
		s.inter = wr.Bundle.Intermediates
		s.ver = wr.Bundle.Version
	}
	rev := &mesh.RevocationSnapshot{Version: wr.Revocations.List.Version}
	for _, e := range wr.Revocations.List.Entries {
		rev.Entries = append(rev.Entries, mesh.RevocationEntry{
			Serial: e.Serial, Node: e.Node, Service: e.Service,
			Instance: e.Instance, Reason: e.Reason,
		})
	}
	s.revs = rev
}

func (s *staticTrust) RootsAndIntermediates() ([]string, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roots, s.inter
}

func (s *staticTrust) Revocations() *mesh.RevocationSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revs
}

func (s *staticTrust) BundleVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ver
}

// Refresh replaces the cached documents from a fresh credential response.
func (s *staticTrust) Refresh(wr *api.WorkloadResponse) { s.set(wr) }
