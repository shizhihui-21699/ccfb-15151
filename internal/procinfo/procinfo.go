// Package procinfo answers, for a process that just connected over a Unix
// domain socket: which PID is on the other end, who owns it, which executable
// it is running, and since when. The node agent uses these kernel-supplied
// facts — never anything the client says about itself — to decide what
// service identity a local process is allowed to receive.
//
// Platform support: Linux (/proc + SO_PEERCRED) and macOS (LOCAL_PEERPID +
// sysctl/ps). Other platforms fail closed. Production would use
// proc_pidpath(3) / SCM_CREDENTIALS where available; see README for what each
// platform can and cannot prove.
package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// ErrUnsupported is returned on platforms where peer facts cannot be read.
var ErrUnsupported = errors.New("procinfo: unsupported platform")

// Facts is the verified description of one process instance.
type Facts struct {
	PID        int       `json:"pid"`
	PPID       int       `json:"ppid"`
	UID        uint32    `json:"uid"`
	StartTime  time.Time `json:"start_time"`
	Exe        string    `json:"exe"`
	Argv       []string  `json:"argv,omitempty"`
	BinarySHA  string    `json:"binary_sha256"`
	BinarySize int64     `json:"binary_size"`
	BinaryMod  time.Time `json:"binary_mod"`
	// ServiceTag optionally carries an OS-provided label (systemd unit,
	// Kubernetes pod UID, launchd label). Empty when unavailable.
	ServiceTag string `json:"service_tag,omitempty"`
}

// StableID identifies this precise process instance. PID alone is not enough:
// PIDs are reused. Comparing StableID before and after issuance rejects
// exec-replacement and PID-reuse races.
func (f *Facts) StableID() string {
	return fmt.Sprintf("%d/%d/%d/%s", f.PID, f.StartTime.UnixNano(), f.UID, f.BinarySHA)
}

// PeerPID returns the PID of the process on the other end of a connected Unix
// socket, as reported by the kernel.
func PeerPID(conn *net.UnixConn) (int, error) { return peerPID(conn) }

// PeerFacts resolves the remote PID and reads its facts. The socket must be a
// connected AF_UNIX stream or seqpacket socket.
func PeerFacts(conn *net.UnixConn) (*Facts, error) {
	pid, err := peerPID(conn)
	if err != nil {
		return nil, err
	}
	return ProcessFacts(pid)
}

var hashCache = struct {
	sync.Mutex
	m map[string]cachedHash
}{m: map[string]cachedHash{}}

type cachedHash struct {
	sha  string
	size int64
	mod  time.Time
}

// HashFile hashes the executable behind path. It re-stats after reading so a
// file swapped mid-read is rejected rather than silently measured.
func HashFile(path string) (sha string, size int64, mod time.Time, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return "", 0, time.Time{}, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, time.Time{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return "", 0, time.Time{}, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", 0, time.Time{}, errors.New("procinfo: executable changed while hashing")
	}
	return hex.EncodeToString(h.Sum(nil)), after.Size(), after.ModTime(), nil
}

// HashFileCached is HashFile with a small cache keyed by identity and mtime,
// which keeps the issuance path cheap when many processes of the same service
// start at once.
func HashFileCached(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano())
	hashCache.Lock()
	c, ok := hashCache.m[key]
	hashCache.Unlock()
	if ok {
		return c.sha, nil
	}
	sha, _, _, err := HashFile(path)
	if err != nil {
		return "", err
	}
	hashCache.Lock()
	if len(hashCache.m) > 4096 {
		hashCache.m = map[string]cachedHash{}
	}
	hashCache.m[key] = cachedHash{sha: sha, size: st.Size(), mod: st.ModTime()}
	hashCache.Unlock()
	return sha, nil
}

// InstanceName is a stable, human-legible instance identifier derived only
// from facts the agent verified. It is used in the certificate URI so two
// instances of one service on one node are distinguishable.
func (f *Facts) InstanceName() string {
	sum := sha256.Sum256([]byte(f.StableID()))
	return fmt.Sprintf("p%d-%s", f.PID, hex.EncodeToString(sum[:4]))
}

// HashHex is a helper for policy fixtures and tests.
func HashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
