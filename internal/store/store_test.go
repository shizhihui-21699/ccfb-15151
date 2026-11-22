package store_test

import (
	"errors"
	"testing"

	"meshid/internal/certutil"
	"meshid/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

func TestNewCreatesLayout(t *testing.T) {
	s := newStore(t)
	if s.Dir == "" {
		t.Fatal("Store.Dir is empty")
	}
}

func TestChallengeConsumeOnce(t *testing.T) {
	s := newStore(t)
	nonce, exp, err := s.NewChallenge("node-1", "authd-1")
	if err != nil {
		t.Fatalf("NewChallenge: %v", err)
	}
	if len(nonce) != 48 {
		t.Fatalf("nonce length = %d, want 48", len(nonce))
	}
	if exp.IsZero() {
		t.Fatal("challenge expiry is zero")
	}

	rec, err := s.ConsumeChallenge(nonce)
	if err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}
	if rec.Nonce != nonce || rec.Node != "node-1" || rec.IssuedBy != "authd-1" {
		t.Fatalf("consumed record = %+v", rec)
	}

	// A nonce is single-use.
	if _, err := s.ConsumeChallenge(nonce); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second ConsumeChallenge = %v, want ErrNotFound", err)
	}
}

func TestConsumeChallengeRejectsMalformed(t *testing.T) {
	s := newStore(t)
	for _, nonce := range []string{"", "short", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"} {
		if _, err := s.ConsumeChallenge(nonce); err == nil {
			t.Fatalf("ConsumeChallenge(%q) succeeded", nonce)
		}
	}
}

func TestNodeInventoryRoundTrip(t *testing.T) {
	s := newStore(t)
	rec := store.NodeRecord{
		Node:          "node-1",
		EKFingerprint: "abcdef",
		RegisteredBy:  "provisioner",
		Note:          "rack 4",
	}
	if err := s.RegisterNode(rec); err != nil {
		t.Fatalf("RegisterNode: %v", err)
	}
	got, err := s.NodeRecordFor("node-1")
	if err != nil {
		t.Fatalf("NodeRecordFor: %v", err)
	}
	if got.Node != "node-1" || got.EKFingerprint != "abcdef" || got.RegisteredBy != "provisioner" {
		t.Fatalf("NodeRecordFor = %+v", got)
	}
	if got.RegisteredAt.IsZero() {
		t.Fatal("RegisteredAt not set")
	}

	if _, err := s.NodeRecordFor("nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("NodeRecordFor(unknown) = %v, want ErrNotFound", err)
	}

	if err := s.RegisterNode(store.NodeRecord{Node: "x"}); err == nil {
		t.Fatal("RegisterNode accepted a record without an EK fingerprint")
	}
}

// signRevocation is a stand-in signer that records what the store handed it.
func signRevocation(l certutil.RevocationList) (*certutil.SignedRevocationList, error) {
	return &certutil.SignedRevocationList{List: l, SignerID: "test", Signature: "sig"}, nil
}

func TestRevokeVersionAndDedup(t *testing.T) {
	s := newStore(t)
	rev := certutil.Revocation{Serial: "abc123", Reason: "key compromise"}

	signed, err := s.Revoke(rev, signRevocation)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if signed.List.Version != 1 {
		t.Fatalf("version = %d, want 1", signed.List.Version)
	}
	if len(signed.List.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(signed.List.Entries))
	}

	// Repeating the same revocation must not add a duplicate entry, even
	// though the list is re-signed.
	signed, err = s.Revoke(rev, signRevocation)
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if len(signed.List.Entries) != 1 {
		t.Fatalf("after duplicate revoke entries = %d, want 1", len(signed.List.Entries))
	}

	// A distinct revocation adds exactly one entry and bumps the version.
	signed, err = s.Revoke(certutil.Revocation{Node: "node-1", Reason: "host down"}, signRevocation)
	if err != nil {
		t.Fatalf("third Revoke: %v", err)
	}
	if signed.List.Version != 2 {
		t.Fatalf("version = %d, want 2", signed.List.Version)
	}
	if len(signed.List.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(signed.List.Entries))
	}

	// The persisted document matches what was returned.
	stored, err := s.Revocations()
	if err != nil {
		t.Fatalf("Revocations: %v", err)
	}
	if stored.List.Version != 2 || len(stored.List.Entries) != 2 {
		t.Fatalf("stored list = %+v", stored.List)
	}
}

func TestAuditTail(t *testing.T) {
	s := newStore(t)
	for _, ev := range []map[string]any{
		{"event": "start", "n": 1},
		{"event": "issue", "n": 2},
		{"event": "stop", "n": 3},
	} {
		if err := s.Audit(ev); err != nil {
			t.Fatalf("Audit: %v", err)
		}
	}
	tail, err := s.AuditTail(2)
	if err != nil {
		t.Fatalf("AuditTail: %v", err)
	}
	if len(tail) != 2 {
		t.Fatalf("AuditTail(2) returned %d lines", len(tail))
	}
	if !contains(tail[0], `"n":2`) || !contains(tail[1], `"n":3`) {
		t.Fatalf("AuditTail order = %v", tail)
	}

	all, err := s.AuditTail(10)
	if err != nil {
		t.Fatalf("AuditTail(10): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("AuditTail(10) returned %d lines, want 3", len(all))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
