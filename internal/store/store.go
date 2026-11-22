// Package store is the small persistent control-plane state that authd
// replicas share: the trust bundle, the authorization policy, the revocation
// list, enrollment challenges and the audit log.
//
// In production this would be etcd/Raft or a Postgres bootstrap; the point of
// the interface is that authd replicas are stateless and any replica can serve
// any request, so losing replicas is not losing the system. The file-backed
// implementation here is for the simulation and for single-box deployments;
// it uses flock so several replica processes can share one directory.
package store

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"meshid/internal/certutil"
)

// Store provides versioned, signed control-plane documents.
type Store struct {
	Dir string

	mu sync.Mutex // in-process serialization; flock covers cross-process
}

// New opens (creating if needed) a store at dir.
func New(dir string) (*Store, error) {
	for _, sub := range []string{"", "challenges", "issues"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// withLock runs fn while holding an exclusive lock shared by all processes.
func (s *Store) withLock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.path(".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, b, mode)
}

// ErrNotFound is returned when a document has not been written yet.
var ErrNotFound = errors.New("store: not found")

// ---- bundle / policy / revocations -------------------------------------

func (s *Store) Bundle() (*certutil.SignedBundle, error) {
	var b certutil.SignedBundle
	if err := readJSON(s.path("bundle.json"), &b); err != nil {
		return nil, wrapNotFound(err)
	}
	return &b, nil
}

func (s *Store) PutBundle(b *certutil.SignedBundle) error {
	return s.withLock(func() error { return writeJSON(s.path("bundle.json"), b, 0o644) })
}

func (s *Store) Policy() (*certutil.SignedPolicy, error) {
	var p certutil.SignedPolicy
	if err := readJSON(s.path("policy.json"), &p); err != nil {
		return nil, wrapNotFound(err)
	}
	return &p, nil
}

func (s *Store) PutPolicy(p *certutil.SignedPolicy) error {
	return s.withLock(func() error { return writeJSON(s.path("policy.json"), p, 0o644) })
}

func (s *Store) Revocations() (*certutil.SignedRevocationList, error) {
	var r certutil.SignedRevocationList
	if err := readJSON(s.path("revocations.json"), &r); err != nil {
		return nil, wrapNotFound(err)
	}
	return &r, nil
}

func (s *Store) PutRevocations(r *certutil.SignedRevocationList) error {
	return s.withLock(func() error { return writeJSON(s.path("revocations.json"), r, 0o644) })
}

func wrapNotFound(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// ---- revocation ---------------------------------------------------------

// Revoke adds an entry and increments the revocation list version. The
// callback signs the new list so the store never holds signing keys.
func (s *Store) Revoke(rev certutil.Revocation, sign func(certutil.RevocationList) (*certutil.SignedRevocationList, error)) (*certutil.SignedRevocationList, error) {
	var out *certutil.SignedRevocationList
	err := s.withLock(func() error {
		cur := certutil.RevocationList{Version: 0}
		var existing certutil.SignedRevocationList
		if err := readJSON(s.path("revocations.json"), &existing); err == nil {
			cur = existing.List
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, e := range cur.Entries {
			if e.Serial == rev.Serial && e.Node == rev.Node && e.Service == rev.Service && e.Instance == rev.Instance {
				cur.IssuedAt = time.Now().UTC()
				signed, err := sign(cur)
				if err != nil {
					return err
				}
				out = signed
				return writeJSON(s.path("revocations.json"), signed, 0o644)
			}
		}
		rev.At = time.Now().UTC()
		cur.Entries = append(cur.Entries, rev)
		cur.Version++
		cur.IssuedAt = time.Now().UTC()
		signed, err := sign(cur)
		if err != nil {
			return err
		}
		out = signed
		return writeJSON(s.path("revocations.json"), signed, 0o644)
	})
	return out, err
}

// ---- enrollment challenges ---------------------------------------------

type challengeFile struct {
	Nonce     string    `json:"nonce"`
	Node      string    `json:"node,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedBy  string    `json:"issued_by"`
}

const challengeTTL = 60 * time.Second

// NewChallenge records a fresh nonce and returns it.
func (s *Store) NewChallenge(node, authdID string) (string, time.Time, error) {
	nonce, err := randomHex(24)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(challengeTTL).UTC()
	cf := challengeFile{Nonce: nonce, Node: node, ExpiresAt: exp, IssuedBy: authdID}
	if err := writeJSON(s.path(filepath.Join("challenges", nonce+".json")), cf, 0o600); err != nil {
		return "", time.Time{}, err
	}
	s.sweepChallenges()
	return nonce, exp, nil
}

// ConsumeChallenge atomically deletes the nonce and returns its record.
// One nonce is good for exactly one enrollment, on exactly one replica.
func (s *Store) ConsumeChallenge(nonce string) (*challengeFile, error) {
	if !validHex(nonce, 48) {
		return nil, errors.New("store: malformed nonce")
	}
	p := s.path(filepath.Join("challenges", nonce+".json"))
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, ErrNotFound
	}
	if err := os.Remove(p); err != nil {
		// Lost the race: another replica consumed it.
		return nil, ErrNotFound
	}
	var cf challengeFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, err
	}
	if time.Now().After(cf.ExpiresAt) {
		return nil, errors.New("store: challenge expired")
	}
	return &cf, nil
}

func (s *Store) sweepChallenges() {
	ents, err := os.ReadDir(s.path("challenges"))
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		var cf challengeFile
		if err := readJSON(s.path(filepath.Join("challenges", e.Name())), &cf); err != nil {
			continue
		}
		if now.After(cf.ExpiresAt) {
			os.Remove(s.path(filepath.Join("challenges", e.Name())))
		}
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ---- audit --------------------------------------------------------------

// Audit appends one event as a JSON line. Writes are O_APPEND and atomic for
// lines under PIPE_BUF, which is the standard way to keep a shared log intact.
func (s *Store) Audit(ev map[string]any) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path("audit.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// AuditTail returns the last n audit lines.
func (s *Store) AuditTail(n int) ([]string, error) {
	b, err := os.ReadFile(s.path("audit.jsonl"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// PutRootPublic writes the root public key used to verify signed documents.
// Node agents receive it at enrollment; authd receives it at bootstrap.
func (s *Store) PutSigningPub(pub *ecdsa.PublicKey) error {
	der, err := x509MarshalPKIX(pub)
	if err != nil {
		return err
	}
	return writeAtomic(s.path("signing.pub"), der, 0o644)
}

func (s *Store) SigningPub() (*ecdsa.PublicKey, error) {
	der, err := os.ReadFile(s.path("signing.pub"))
	if err != nil {
		return nil, wrapNotFound(err)
	}
	return x509ParsePKIX(der)
}

// LoadDoc reads a named document from the store directory.
func (s *Store) LoadDoc(name string) ([]byte, error) { return os.ReadFile(s.path(name)) }

// SaveDoc writes a named document atomically.
func (s *Store) SaveDoc(name string, data []byte, mode os.FileMode) error {
	return s.withLock(func() error { return writeAtomic(s.path(name), data, mode) })
}

// ---- enrollment inventory ----------------------------------------------

// NodeRecord authorizes a node name to enroll with one specific hardware
// identity. Provisioning writes this when a machine is racked (in production:
// from the TPM vendor's EK registry or a manufacturing database). Without it,
// anyone who can reach authd could enroll *any* name on their own hardware,
// which would defeat the whole point.
type NodeRecord struct {
	Node          string    `json:"node"`
	EKFingerprint string    `json:"ek_fingerprint"`
	RegisteredAt  time.Time `json:"registered_at"`
	RegisteredBy  string    `json:"registered_by,omitempty"`
	// Note explains why the record exists (rack, replacement, ...).
	Note string `json:"note,omitempty"`
}

func (s *Store) nodes() (map[string]NodeRecord, error) {
	m := map[string]NodeRecord{}
	err := readJSON(s.path("nodes.json"), &m)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	return m, err
}

// RegisterNode binds a node name to an EK fingerprint.
func (s *Store) RegisterNode(r NodeRecord) error {
	if r.Node == "" || r.EKFingerprint == "" {
		return errors.New("store: node and ek fingerprint required")
	}
	r.RegisteredAt = time.Now().UTC()
	return s.withLock(func() error {
		m, err := s.nodes()
		if err != nil {
			return err
		}
		m[r.Node] = r
		return writeJSON(s.path("nodes.json"), m, 0o644)
	})
}

// NodeRecordFor returns the inventory record for a node.
func (s *Store) NodeRecordFor(node string) (NodeRecord, error) {
	m, err := s.nodes()
	if err != nil {
		return NodeRecord{}, err
	}
	r, ok := m[node]
	if !ok {
		return NodeRecord{}, ErrNotFound
	}
	return r, nil
}

// Nodes returns the whole inventory.
func (s *Store) Nodes() ([]NodeRecord, error) {
	m, err := s.nodes()
	if err != nil {
		return nil, err
	}
	out := make([]NodeRecord, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out, nil
}

// RemoveNode deletes an inventory record (decommissioning).
func (s *Store) RemoveNode(node string) error {
	return s.withLock(func() error {
		m, err := s.nodes()
		if err != nil {
			return err
		}
		delete(m, node)
		return writeJSON(s.path("nodes.json"), m, 0o644)
	})
}
