package e2e

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/sim"
)

// TestSustainedTrafficThroughRotationAndOutage is the load-shaped test: many
// calls while certificates rotate and while authd is down. It answers "does
// the mesh stay usable" rather than "does one call work".
func TestSustainedTrafficThroughRotationAndOutage(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 2, LeafTTL: 6 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	apiBin := buildVariant(t, dir, "api", "api")
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: hashFile(t, feBin), MaxTTLSec: 6, AllowDegraded: true},
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), MaxTTLSec: 6, AllowDegraded: true},
	); err != nil {
		t.Fatal(err)
	}
	fe := startWorkload(t, w, n1, feBin, "shop", "frontend")
	apiSvc := startWorkload(t, w, n2, apiBin, "shop", "api")

	var ok, fail atomic.Int64
	var errMu sync.Mutex
	errCounts := map[string]int{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One client per goroutine: a real service reuses its
			// connections, and a per-call Transport would distort the test
			// (and leak sockets).
			client := fe.Client()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, _ := http.NewRequest(http.MethodGet, apiSvc.URL()+"/whoami", nil)
				resp, err := client.Do(req)
				if err != nil {
					fail.Add(1)
					errMu.Lock()
					errCounts[classifyErr(err)]++
					errMu.Unlock()
				} else {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					ok.Add(1)
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
	}

	// Rotate the caller several times, then take authd away entirely and
	// rotate again, which exercises degraded issuance under live traffic.
	for i := 0; i < 2; i++ {
		out := t.TempDir() + "/r.json"
		if _, err := runWorkerProc(t, feBin, n1.Socket, "shop", "frontend", out); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		fe.SetCredentials(loadWorkload(t, out).Credentials())
		time.Sleep(200 * time.Millisecond)
	}
	before := ok.Load()
	w.StopAllAuthd()
	time.Sleep(150 * time.Millisecond)
	for i := 0; i < 2; i++ {
		out := t.TempDir() + "/d.json"
		if _, err := runWorkerProc(t, feBin, n1.Socket, "shop", "frontend", out); err != nil {
			t.Fatalf("degraded rotation %d: %v", i, err)
		}
		fe.SetCredentials(loadWorkload(t, out).Credentials())
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("ok=%d fail=%d (after outage start ok=%d)", ok.Load(), fail.Load(), ok.Load()-before)
	if ok.Load() < 100 {
		t.Fatalf("too few successful calls (%d); mesh did not stay up", ok.Load())
	}
	// Degraded issuance is allowed for these services, so a handful of
	// failures during the swap is acceptable but a collapse is not.
	if fail.Load() > ok.Load()/10 {
		t.Fatalf("failure rate too high: %d failures out of %d", fail.Load(), ok.Load()+fail.Load())
	}
	if ok.Load()-before < 50 {
		errMu.Lock()
		t.Logf("error classes: %v", errCounts)
		errMu.Unlock()
		t.Fatalf("traffic did not continue during the outage (%d calls)", ok.Load()-before)
	}
	errMu.Lock()
	if len(errCounts) > 0 {
		t.Logf("error classes: %v", errCounts)
	}
	errMu.Unlock()
}

// classifyErr buckets errors so a failing run says what actually broke.
func classifyErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "certificate has expired"):
		return "expired"
	case strings.Contains(s, "revoked"):
		return "revoked"
	case strings.Contains(s, "bad certificate"):
		return "tls-bad-cert"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "connection reset"), strings.Contains(s, "EOF"):
		return "reset"
	case strings.Contains(s, "deadline"):
		return "timeout"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// TestPolicyWithdrawalBeatsStaleCache: once the control plane withdraws a
// grant, a node with a stale cached policy must not use degraded issuance to
// keep minting that identity. An explicit refusal from authd must never fall
// back to the node's own CA.
func TestPolicyWithdrawalBeatsStaleCache(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	dir := t.TempDir()
	bin := buildVariant(t, dir, "svc", "svc")
	grant := certutil.ServiceGrant{
		Namespace: "shop", Service: "svc", BinarySHA256: hashFile(t, bin),
		AllowDegraded: true, MaxTTLSec: 20,
	}
	if err := w.SetPolicy(grant); err != nil {
		t.Fatal(err)
	}
	// First issuance works and the agent caches the policy.
	if _, err := runWorkerProc(t, bin, n1.Socket, "shop", "svc", t.TempDir()+"/a.json"); err != nil {
		t.Fatalf("initial issuance: %v", err)
	}
	// Withdraw the grant centrally.
	if err := w.SetPolicy(); err != nil {
		t.Fatal(err)
	}
	// The agent's policy cache is stale (it still contains the grant), but
	// authd now refuses. Degraded mode must not kick in.
	if _, err := runWorkerProc(t, bin, n1.Socket, "shop", "svc", t.TempDir()+"/b.json"); err == nil {
		t.Fatalf("withdrawn service still got an identity via degraded fallback")
	}
}
