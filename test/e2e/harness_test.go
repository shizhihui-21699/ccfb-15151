// Package e2e drives the whole system as real processes: a real node agent
// per simulated machine, real Unix-socket credential requests, real mTLS
// between workloads, and a real authd over TLS.
//
// Why re-exec: the node agent decides a caller's identity from the kernel's
// view of the peer (its executable path and hash, its UID, its start time).
// A goroutine inside the test binary cannot pretend to be a different binary,
// so every workload that needs a distinct build identity runs as a child
// process — which is also exactly how a real deployment looks.
package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/sim"
)

// The child-process protocol. The parent test starts a copy of the test
// binary with -worker=<role>, passing the node socket and policy details in
// the environment. The child performs one action and prints one JSON line.
const (
	envWorker    = "MESHID_WORKER"
	envSocket    = "MESHID_SOCKET"
	envService   = "MESHID_SERVICE"
	envNamespace = "MESHID_NAMESPACE"
	envOut       = "MESHID_OUT"
)

func TestMain(m *testing.M) {
	role := os.Getenv(envWorker)
	if role != "" {
		if err := runWorker(role); err != nil {
			fmt.Fprintln(os.Stderr, "worker error:", err)
			os.Exit(3)
		}
		os.Exit(0)
	}
	flag.Parse()
	os.Exit(m.Run())
}

type workerResult struct {
	OK    bool              `json:"ok"`
	Error string            `json:"error,omitempty"`
	Meta  map[string]string `json:"meta,omitempty"`
}

func runWorker(role string) error {
	sock := os.Getenv(envSocket)
	ns := os.Getenv(envNamespace)
	svc := os.Getenv(envService)
	out := os.Getenv(envOut)
	res := workerResult{}
	creds, resp, err := sim.RequestIdentity(context.Background(), sock, ns, svc)
	if err != nil {
		res.Error = err.Error()
		res.OK = false
	} else {
		res.OK = true
		res.Meta = map[string]string{
			"serial": creds.Serial(), "mode": resp.Mode,
			"node": resp.Meta.Node, "svc": resp.Meta.Service,
			"uri": fmt.Sprintf("%+v", resp.Meta.Namespace),
		}
		// Keep the credentials where the parent can build a workload from
		// them, so the mTLS test uses the real leaf.
		if out != "" {
			keyPEM, kerr := creds.PrivateKeyPEM()
			if kerr != nil {
				res.OK = false
				res.Error = kerr.Error()
				writeResult(res)
				return nil
			}
			b, _ := json.Marshal(map[string]any{
				"cert": resp.CertPEM, "chain": resp.ChainPEM, "meta": resp.Meta,
				"renew_after": resp.RenewAfter, "key": keyPEM,
			})
			if err := os.WriteFile(out, b, 0o600); err != nil {
				res.OK = false
				res.Error = err.Error()
			}
		}
	}
	writeResult(res)
	return nil
}

func writeResult(res workerResult) {
	b, _ := json.Marshal(res)
	fmt.Println(string(b))
}

// ---- parent-side helpers -------------------------------------------------

// buildVariant produces a copy of the test binary at dir/name whose content
// differs from every other variant, so its SHA-256 is a distinct build
// identity. Appending bytes after the Mach-O image is harmless: the loader
// ignores trailing data.
func buildVariant(t *testing.T, dir, name, marker string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read self: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, append(src, []byte("\nMESHID-BUILD-"+marker+"\n")...), 0o755); err != nil {
		t.Fatalf("write variant: %v", err)
	}
	return p
}

// hashFile returns the hash the agent will compute.
func hashFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	return hashHex(b)
}

func hashHex(b []byte) string { return certutil.HashBytes(b) }

// runWorkerProc runs a variant binary in worker mode and returns its result.
func runWorkerProc(t *testing.T, exe, sock, ns, svc, outPath string) (workerResult, error) {
	t.Helper()
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		envWorker+"=issue",
		envSocket+"="+sock,
		envNamespace+"="+ns,
		envService+"="+svc,
		envOut+"="+outPath,
	)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return workerResult{}, fmt.Errorf("worker process: %w", err)
	}
	line := strings.TrimSpace(string(out))
	if i := strings.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	var res workerResult
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		return workerResult{}, fmt.Errorf("worker output %q: %w", line, err)
	}
	if !res.OK {
		return res, fmt.Errorf("worker refused: %s", res.Error)
	}
	return res, nil
}

var (
	_ = flag.Parse
	_ = io.Discard
	_ = http.Get
	_ = time.Second
)
