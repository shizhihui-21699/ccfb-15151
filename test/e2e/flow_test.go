package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/sim"
)

// TestAttestationGrantsIdentity is the core happy path:
//   - a machine enrolls with no pre-shared secret, only its TPM;
//   - a local process asks the node agent for an identity;
//   - the agent verifies the process by kernel facts and the policy pins the
//     process's exact binary;
//   - authd signs a short-lived certificate;
//   - a workload on another machine accepts that certificate over mTLS.
func TestAttestationGrantsIdentity(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")

	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "frontend-v1")
	apiBin := buildVariant(t, dir, "api", "api-v1")

	feHash, apiHash := hashFile(t, feBin), hashFile(t, apiBin)
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: feHash, MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: apiHash, MaxTTLSec: 20},
	); err != nil {
		t.Fatalf("policy: %v", err)
	}

	frontend := startWorkload(t, w, n1, feBin, "shop", "frontend")
	apiSvc := startWorkload(t, w, n2, apiBin, "shop", "api")

	// The API accepts the frontend's certificate and reports what it saw.
	got, err := frontend.Call(t.Context(), apiSvc.URL(), "/whoami")
	if err != nil {
		t.Fatalf("frontend -> api: %v", err)
	}
	if got["svc"] != "frontend" || got["node"] != "node-1" {
		t.Fatalf("api saw wrong caller: %+v", got)
	}
	if !strings.Contains(got["caller"], "/ns/shop/svc/frontend/node/node-1/") {
		t.Fatalf("unexpected caller URI %q", got["caller"])
	}
	if got["mode"] != certutil.ModeOnline {
		t.Fatalf("expected online mode, got %q", got["mode"])
	}

	// The listener on the API still works with a previously negotiated
	// connection after the frontend rotates: rotation must not break calls.
	before := frontend.Credentials().Serial()
	rotateWorkload(t, w, n1, frontend, feBin, "shop", "frontend")
	if frontend.Credentials().Serial() == before {
		t.Fatalf("frontend serial did not change on rotation")
	}
	if got, err := frontend.Call(t.Context(), apiSvc.URL(), "/whoami"); err != nil {
		t.Fatalf("call after rotation: %v", err)
	} else if got["serial"] == before {
		t.Fatalf("call after rotation used the old certificate")
	}
}

func rotateWorkload(t *testing.T, w *sim.World, n *sim.Node, wl *sim.Workload, exe, ns, svc string) {
	t.Helper()
	// A workload's "renewal" is the same request as initial issuance: the
	// process is already authenticated to the agent by PID and binary.
	out := filepath.Join(t.TempDir(), "creds.json")
	if _, err := runWorkerProc(t, exe, n.Socket, ns, svc, out); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	creds := loadWorkload(t, out)
	wl.SetCredentials(creds.Credentials())
}

// startWorkload runs a worker process for the given binary, which obtains a
// certificate from that node's agent, and wraps the certificate as a running
// mTLS service.
func startWorkload(t *testing.T, w *sim.World, n *sim.Node, exe, ns, svc string) *sim.Workload {
	t.Helper()
	out := filepath.Join(t.TempDir(), "creds-"+svc+".json")
	res, err := runWorkerProc(t, exe, n.Socket, ns, svc, out)
	if err != nil {
		t.Fatalf("request identity for %s: %v", svc, err)
	}
	_ = res
	wl := loadWorkload(t, out)
	wl.Trust = n.Agent.Trust()
	if err := wl.Serve(); err != nil {
		t.Fatalf("serve %s: %v", svc, err)
	}
	t.Cleanup(wl.Close)
	return wl
}

func loadWorkload(t *testing.T, path string) *sim.Workload {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read creds: %v", err)
	}
	return sim.WorkloadFromJSON(t, b)
}

var (
	_ = context.Background
	_ = ecdsa.GenerateKey
	_ = elliptic.P256
	_ = rand.Reader
	_ = errors.New
	_ = sync.Once{}
)
