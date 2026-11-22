package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"meshid/internal/api"
	"meshid/internal/mesh"
)

// httpClient returns a client for talking to authd. Once the agent has
// credentials it presents them; before enrollment it only needs the authd
// server certificate to verify, so it uses AuthdCA and no client cert.
func (a *Agent) httpClient() (*http.Client, error) {
	cfg, err := a.clientTLS()
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second},
	}, nil
}

func (a *Agent) clientTLS() (*tls.Config, error) {
	roots := x509.NewCertPool()
	for _, p := range a.cfg.AuthdCARoots {
		if !roots.AppendCertsFromPEM([]byte(p)) {
			return nil, errors.New("agent: malformed authd CA PEM")
		}
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: a.cfg.AuthdServerName,
	}
	if creds := a.Credentials(); creds != nil {
		// After enrollment, the authd server certificate is verified
		// against the mesh trust store, so even authd must present a
		// certificate issued under the mesh root.
		cfg.GetClientCertificate = creds.GetClientCertificate
		cfg.InsecureSkipVerify = true
		verifier := mesh.NewVerifier(mesh.VerifierConfig{
			Trust:  a.ts.TrustSource(),
			Expect: mesh.ExpectServer,
		})
		cfg.VerifyConnection = func(st tls.ConnectionState) error {
			return verifier.VerifyConnection(st)
		}
	} else {
		// Before enrollment there is nothing to verify against but the
		// pinned authd CA from the node image.
		cfg.RootCAs = roots
	}
	return cfg, nil
}

// authdBase picks the replica to talk to. Replicas are equivalent, so a
// failed one is skipped and retried only after the others have been tried;
// this is what makes a rolling authd restart invisible.
func (a *Agent) authdBase() string {
	urls := a.cfg.AuthdURLs
	if len(urls) == 0 {
		return a.cfg.AuthdURL
	}
	start := int(a.nextReplica.Load())
	for i := 0; i < len(urls); i++ {
		idx := (start + i) % len(urls)
		if a.replicaDown(idx, urls[idx]) {
			continue
		}
		a.nextReplica.Store(int32(idx))
		return urls[idx]
	}
	return urls[start%len(urls)]
}

// replicaDown remembers recent failures with a short cooldown.
func (a *Agent) replicaDown(idx int, url string) bool {
	a.mu.RLock()
	until, ok := a.downUntil[url]
	a.mu.RUnlock()
	return ok && time.Now().Before(until)
}

func (a *Agent) markReplica(idx int, url string, down bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.downUntil == nil {
		a.downUntil = map[string]time.Time{}
	}
	if down {
		a.downUntil[url] = time.Now().Add(2 * time.Second)
		return
	}
	delete(a.downUntil, url)
}

func (a *Agent) postJSON(path string, in, out any) error {
	return a.doJSON(http.MethodPost, path, in, out)
}

func (a *Agent) getJSON(path string, out any) error {
	return a.doJSON(http.MethodGet, path, nil, out)
}

func (a *Agent) doJSON(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	hc, err := a.httpClient()
	if err != nil {
		return err
	}
	base := a.authdBase()
	idx := 0
	if urls := a.cfg.AuthdURLs; len(urls) > 0 {
		for i, u := range urls {
			if u == base {
				idx = i
			}
		}
	}
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		a.markReplica(idx, base, true)
		return fmt.Errorf("%s: %w", base, err)
	}
	a.markReplica(idx, base, false)
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Code != "" {
			return &e
		}
		return fmt.Errorf("authd: %s: %s", resp.Status, truncate(string(data), 200))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
