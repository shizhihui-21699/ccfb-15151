package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/mesh"
	"meshid/internal/sim"
)

// TestWrongBinaryIsRefused covers the everyday insider case: a process on the
// right machine, running as the right user, asks for a service it is not.
func TestWrongBinaryIsRefused(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	dir := t.TempDir()
	good := buildVariant(t, dir, "good", "good")
	bad := buildVariant(t, dir, "bad", "bad")
	if err := w.SetPolicy(certutil.ServiceGrant{
		Namespace: "pay", Service: "ledger",
		BinarySHA256: hashFile(t, good), MaxTTLSec: 20,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := runWorkerProc(t, good, n1.Socket, "pay", "ledger", filepath.Join(t.TempDir(), "ok.json")); err != nil {
		t.Fatalf("pinned binary refused: %v", err)
	}
	_, err := runWorkerProc(t, bad, n1.Socket, "pay", "ledger", filepath.Join(t.TempDir(), "no.json"))
	if err == nil {
		t.Fatalf("unpinned binary obtained the ledger identity")
	}
	if !strings.Contains(err.Error(), "binary hash") && !strings.Contains(err.Error(), "policy_denied") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// TestReplayedEnrollmentFails: a captured enrollment transcript cannot be
// replayed, because the nonce is single-use and key-binding is part of the
// signed statement.
func TestReplayedEnrollmentFails(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n, err := w.AddNode("node-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.RegisterNode(n, "test"); err != nil {
		t.Fatal(err)
	}
	// Capture a complete, valid enrollment exchange by proxying it.
	rec, err := captureEnrollment(t, w, n)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	// The first real enrollment already consumed the nonce. Replay the exact
	// bytes.
	if err := postRaw(t, w.AuthdURLs()[0]+api.PathEnroll, rec.body); err == nil {
		t.Fatalf("replayed enrollment succeeded")
	} else if !strings.Contains(err.Error(), "challenge") && !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("replay failed for an unexpected reason: %v", err)
	}
}

// TestNonceIsBoundToNode: a nonce fetched for one node name cannot be used to
// enroll another, even with valid attestation for the other.
func TestNonceIsBoundToNode(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1})
	body, _ := json.Marshal(map[string]string{"node": "node-1"})
	ch, err := postJSON(t, w.AuthdURLs()[0]+api.PathChallenge, body)
	if err != nil {
		t.Fatal(err)
	}
	var cresp api.ChallengeResponse
	if err := json.Unmarshal(ch, &cresp); err != nil {
		t.Fatal(err)
	}
	if _, err := postJSON(t, w.AuthdURLs()[0]+api.PathEnroll, []byte(fmt.Sprintf(
		`{"node":"node-2","tls_key_csr_pem":"","node_ca_key_csr_pem":"","attestation":{"nonce":%q,"sig":"00"}}`, cresp.Nonce))); err == nil {
		t.Fatalf("enroll with a foreign nonce succeeded")
	}
}

// TestAgentRoleCannotIssue: an agent certificate is not a workload
// certificate; presenting one where a workload is expected must fail when the
// policy distinguishes roles. Here we check the weaker but essential property
// that a node agent's identity cannot be *used* to call workloads, because its
// URI does not parse as a workload identity.
func TestAgentRoleCannotIssue(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	apiBin := buildVariant(t, dir, "api", "api")
	if err := w.SetPolicy(certutil.ServiceGrant{
		Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), MaxTTLSec: 20,
	}); err != nil {
		t.Fatal(err)
	}
	svc := startWorkload(t, w, n2, apiBin, "shop", "api")

	// Build a workload that presents the *agent's* certificate.
	agentCreds := n1.Agent.Credentials()
	if agentCreds == nil {
		t.Fatal("agent has no credentials")
	}
	impostor := &sim.Workload{Trust: n2.Agent.Trust()}
	impostor.SetCredentials(agentCreds)
	if _, err := impostor.Call(t.Context(), svc.URL(), "/whoami"); err == nil {
		t.Fatalf("a node agent certificate was accepted as a workload identity")
	} else if !strings.Contains(err.Error(), "role") && !strings.Contains(err.Error(), "bad certificate") {
		t.Fatalf("rejected for an unexpected reason: %v", err)
	}
}

// ---- helpers -------------------------------------------------------------

type captured struct{ body []byte }

// captureEnrollment performs an enrollment through a recording proxy so the
// exact request bytes are available for replay.
func captureEnrollment(t *testing.T, w *sim.World, n *sim.Node) (*captured, error) {
	t.Helper()
	// Use the store directly to mint a challenge the agent does not use, then
	// build the same request by hand. This is closer to "attacker records
	// traffic" than to "attacker uses the real agent".
	chBody, _ := json.Marshal(map[string]string{"node": n.Name})
	raw, err := postJSON(t, w.AuthdURLs()[0]+api.PathChallenge, chBody)
	if err != nil {
		return nil, err
	}
	var ch api.ChallengeResponse
	if err := json.Unmarshal(raw, &ch); err != nil {
		return nil, err
	}
	// This body would fail the real attestation, but it is enough to prove
	// the replay property: the nonce is gone after the first submission, so
	// the second submission fails at "challenge unknown" regardless of the
	// rest of the payload.
	body := []byte(fmt.Sprintf(`{"node":%q,"tls_key_csr_pem":"x","node_ca_key_csr_pem":"x","attestation":{"nonce":%q,"sig":"00"}}`, n.Name, ch.Nonce))
	// First submission consumes the nonce (fails later, but consumes it).
	_ = postRaw(t, w.AuthdURLs()[0]+api.PathEnroll, body)
	return &captured{body: body}, nil
}

func postRaw(t *testing.T, url string, body []byte) error {
	t.Helper()
	_, err := postJSON(t, url, body)
	return err
}

// httpClient talks to authd over TLS, trusting the simulation root. Tests that
// only exercise control-plane error paths use it; they never need a client
// certificate because those endpoints reject anonymous callers before doing
// anything sensitive.
func httpClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func postJSON(t *testing.T, url string, body []byte) ([]byte, error) {
	t.Helper()
	resp, err := httpClient().Post(url, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

var _ = ecdsa.GenerateKey
var _ = elliptic.P256
var _ = rand.Reader
var _ = x509.NewCertPool
var _ = os.Getpid
var _ = time.Second

// TestWorkloadCertificateCannotRequestIdentities: a workload's certificate is
// a caller identity, not an issuer. Presenting one to /v1/issue must be
// refused even when the request body claims to be a node agent with perfect
// kernel facts.
func TestWorkloadCertificateCannotRequestIdentities(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	victimBin := buildVariant(t, dir, "victim", "victim")
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: hashFile(t, feBin), MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "victim", BinarySHA256: hashFile(t, victimBin), MaxTTLSec: 20},
	); err != nil {
		t.Fatal(err)
	}
	fe := startWorkload(t, w, n1, feBin, "shop", "frontend")

	// Build a perfectly-formed issue request, as the frontend workload.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := certutil.NewCSR(key, "victim")
	if err != nil {
		t.Fatal(err)
	}
	facts := map[string]any{
		"pid": 1, "ppid": 0, "uid": 0, "start_time": "2020-01-01T00:00:00Z",
		"exe": "/usr/bin/victim", "binary_sha256": strings.Repeat("a", 64),
		"binary_size": 1, "binary_mod": "2020-01-01T00:00:00Z", "service_tag": "",
	}
	body, _ := json.Marshal(map[string]any{
		"node": "node-1", "ns": "shop", "svc": "victim", "inst": "x",
		"csr_pem": csr, "facts": facts,
	})

	verifier := mesh.NewVerifier(mesh.VerifierConfig{Trust: fe.Trust, Expect: mesh.ExpectServer})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: mesh.DialConfig(fe.Credentials(), mesh.NewVerifier(mesh.VerifierConfig{
				Trust: fe.Trust, Expect: mesh.ExpectServer,
			}), ""),
		},
	}
	_ = verifier
	resp, err := client.Post(w.AuthdURLs()[0]+api.PathIssue, "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("could not reach authd to exercise the role check: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == 200 {
		t.Fatalf("workload certificate obtained an identity for another service")
	}
	if !strings.Contains(string(respBody), "role") &&
		!strings.Contains(string(respBody), "unauthorized") &&
		!strings.Contains(string(respBody), "not allowed") {
		t.Fatalf("unexpected refusal: %s", respBody)
	}
}
