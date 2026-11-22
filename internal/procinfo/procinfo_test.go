//go:build darwin

package procinfo_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/procinfo"
)

func TestProcessFactsSelf(t *testing.T) {
	pid := os.Getpid()
	f, err := procinfo.ProcessFacts(pid)
	if err != nil {
		t.Fatalf("ProcessFacts(%d): %v", pid, err)
	}
	if f.PID != pid {
		t.Fatalf("PID = %d, want %d", f.PID, pid)
	}
	if f.PPID <= 0 {
		t.Fatalf("PPID = %d, want a real parent", f.PPID)
	}
	if f.UID != uint32(os.Getuid()) {
		t.Fatalf("UID = %d, want %d", f.UID, os.Getuid())
	}
	if f.Exe == "" {
		t.Fatal("Exe is empty")
	}
	if len(f.BinarySHA) != 64 {
		t.Fatalf("BinarySHA = %q, want 64 hex chars", f.BinarySHA)
	}
	if _, err := hex.DecodeString(f.BinarySHA); err != nil {
		t.Fatalf("BinarySHA is not hex: %v", err)
	}
	if f.StartTime.IsZero() {
		t.Fatal("StartTime is zero")
	}
	if f.StartTime.After(time.Now().Add(time.Minute)) {
		t.Fatalf("StartTime %v is in the future", f.StartTime)
	}
}

func TestStableIdentity(t *testing.T) {
	f1, err := procinfo.ProcessFacts(os.Getpid())
	if err != nil {
		t.Fatalf("first ProcessFacts: %v", err)
	}
	f2, err := procinfo.ProcessFacts(os.Getpid())
	if err != nil {
		t.Fatalf("second ProcessFacts: %v", err)
	}
	if f1.StableID() != f2.StableID() {
		t.Fatalf("StableID changed between calls: %q != %q", f1.StableID(), f2.StableID())
	}
	if f1.InstanceName() != f2.InstanceName() {
		t.Fatalf("InstanceName changed between calls: %q != %q", f1.InstanceName(), f2.InstanceName())
	}
	if f1.InstanceName() == "" {
		t.Fatal("InstanceName is empty")
	}
}

func TestHashFileMatchesHashBytes(t *testing.T) {
	content := []byte("mesh identity binary fixture\n")
	path := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sha, size, _, err := procinfo.HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if want := certutil.HashBytes(content); sha != want {
		t.Fatalf("HashFile = %q, want %q", sha, want)
	}
	if size != int64(len(content)) {
		t.Fatalf("size = %d, want %d", size, len(content))
	}
}

// TestHashFileCachedInvalidation verifies the cache key includes size/mtime:
// replacing the file with different contents must not return the old hash.
func TestHashFileCachedInvalidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bin")
	first := []byte("aaaa")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	h1, err := procinfo.HashFileCached(path)
	if err != nil {
		t.Fatalf("first HashFileCached: %v", err)
	}
	// Warm cache hit returns the same value.
	if again, err := procinfo.HashFileCached(path); err != nil || again != h1 {
		t.Fatalf("cached read = %q, %v; want %q", again, err, h1)
	}

	second := []byte("bbbbbbbb") // different size forces a different cache key
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	h2, err := procinfo.HashFileCached(path)
	if err != nil {
		t.Fatalf("second HashFileCached: %v", err)
	}
	if h2 == h1 {
		t.Fatal("HashFileCached returned a stale hash after the file was replaced")
	}
	if want := certutil.HashBytes(second); h2 != want {
		t.Fatalf("HashFileCached = %q, want %q", h2, want)
	}
}
