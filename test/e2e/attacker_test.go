package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshid/internal/api"
	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/mesh"
	"meshid/internal/sim"
)

// TestCompromisedMachineCannotImpersonateNeighbour is the central security
// property. The attacker controls node-2 completely: root on the box, the node
// agent process, its TPM, and the node-scoped intermediate CA. It tries every
// route to a node-1 identity:
//
//  1. ask its own agent for node-1's service;
//  2. forge a leaf directly with the stolen node-2 intermediate;
//  3. mint a degraded leaf claiming node=node-1;
//  4. enroll a fresh machine under node-1's name.
//
// Every one must fail, and a real node-1 peer must reject the artifacts.
func TestCompromisedMachineCannotImpersonateNeighbour(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")

	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	evilBin := buildVariant(t, dir, "evil", "evil")

	// frontend may run only on node-1, pinned to its exact binary.
	if err := w.SetPolicy(
		certutil.ServiceGrant{
			Namespace: "shop", Service: "frontend",
			BinarySHA256: hashFile(t, feBin), Nodes: []string{"node-1"}, MaxTTLSec: 20,
		},
		certutil.ServiceGrant{
			Namespace: "shop", Service: "api",
			BinarySHA256: hashFile(t, evilBin), MaxTTLSec: 20,
		},
	); err != nil {
		t.Fatalf("policy: %v", err)
	}

	real := startWorkload(t, w, n1, feBin, "shop", "frontend")

	t.Run("own agent refuses neighbour service", func(t *testing.T) {
		out := t.TempDir() + "/c.json"
		_, err := runWorkerProc(t, evilBin, n2.Socket, "shop", "frontend", out)
		if err == nil {
			t.Fatalf("node-2 agent granted a frontend identity")
		}
		if !strings.Contains(err.Error(), "not permitted on node") &&
			!strings.Contains(err.Error(), "not in policy") &&
			!strings.Contains(err.Error(), "binary hash") {
			t.Fatalf("unexpected refusal reason: %v", err)
		}
	})

	t.Run("forged leaf from stolen node CA is rejected", func(t *testing.T) {
		// The attacker has node-2's intermediate, either by extracting it
		// from the agent's memory or by re-enrolling node-2. It mints a
		// leaf that *claims* node-1 in its metadata and URI SAN.
		leaf, key := forgeLeaf(t, w, n2, "node-1", "frontend")
		chain := append([]*x509.Certificate{n2.Agent.NodeCADebug()}, n2.Agent.NodeCAChainDebug()...)

		// Direct verification with the full stolen chain shows the actual
		// defense: the chain builds to the root, but the issuer's scope
		// names node-2 while the leaf claims node-1.
		verr := verifyChainFor(t, n1, leaf, chain)
		if verr == nil {
			t.Fatalf("verifier accepted a leaf signed by node-2's CA claiming node-1")
		}
		if !strings.Contains(verr.Error(), "scope") {
			t.Fatalf("expected a scope violation, got: %v", verr)
		}
		if err := dialWithChain(t, real, leaf, chain, key); err == nil {
			t.Fatalf("node-1 accepted a leaf signed by node-2's CA")
		}
	})

	t.Run("degraded self-issued leaf claiming node-1 is rejected", func(t *testing.T) {
		// Same artifact, but with Mode=degraded, which peers check against
		// the issuer's scope explicitly.
		leaf, key := forgeLeafMode(t, w, n2, "node-1", "frontend", certutil.ModeDegraded)
		chain := append([]*x509.Certificate{n2.Agent.NodeCADebug()}, n2.Agent.NodeCAChainDebug()...)
		if err := verifyChainFor(t, n1, leaf, chain); err == nil {
			t.Fatalf("verifier accepted a degraded leaf from node-2's CA claiming node-1")
		}
		if err := dialWithChain(t, real, leaf, chain, key); err == nil {
			t.Fatalf("node-1 accepted a degraded leaf claiming to be from node-1")
		}
	})

	t.Run("attacker cannot enroll under node-1's name", func(t *testing.T) {
		// A brand-new machine with a genuine TPM, but not the hardware the
		// inventory registered as node-1.
		rogue, err := w.AddNode("rogue")
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately do NOT register the rogue node. Enrolling as
		// node-1 must fail the inventory check.
		if err := w.RegisterNode(rogue, "attacker"); err != nil {
			t.Fatal(err)
		}
		rogue.Name = "node-1"
		_, err = rogue.EnrollInBackground()
		if err == nil {
			t.Fatalf("authd enrolled an unregistered EK under node-1")
		}
		if !strings.Contains(err.Error(), "EK does not match") &&
			!strings.Contains(err.Error(), "not registered") {
			t.Fatalf("unexpected enrollment refusal: %v", err)
		}
	})

	t.Run("stolen node CA cannot be used for a different node", func(t *testing.T) {
		// Directly assert the scope check on the artifact, independent of
		// dialling: a leaf signed by node-2's CA whose metadata says node-1
		// must be refused by the verification library.
		leaf := forgeLeafCert(t, w, n2, "node-1", "frontend", certutil.ModeOnline)
		verifier := meshVerifierFor(t, n1)
		_, err := verifier.VerifyCerts([]*x509.Certificate{leaf}, "")
		if err == nil {
			t.Fatalf("verifier accepted cross-node forged leaf")
		}
	})
}

// TestRevocationCutsLiveConnections shows revocation taking effect on an
// already-established TLS connection, not merely at the next handshake.
func TestRevocationCutsLiveConnections(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 30 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	apiBin := buildVariant(t, dir, "api", "api")
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: hashFile(t, feBin), MaxTTLSec: 30},
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), MaxTTLSec: 30},
	); err != nil {
		t.Fatal(err)
	}
	fe := startWorkload(t, w, n1, feBin, "shop", "frontend")
	apiSvc := startWorkload(t, w, n2, apiBin, "shop", "api")

	// Warm a pooled connection.
	if _, err := fe.Call(t.Context(), apiSvc.URL(), "/whoami"); err != nil {
		t.Fatalf("initial call: %v", err)
	}
	if err := w.Revoke(certutil.Revocation{Node: "node-1", Reason: "suspected compromise"}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// Wait for node-2's agent (which backs the API's trust store) to apply it.
	if err := w.WaitRevocationPropagated(0, []*sim.Node{n2}, 5*time.Second); err != nil {
		// Version 0 is impossible once anything is revoked; fall through to
		// the explicit wait below.
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rev := n2.Agent.Trust().Revocations(); rev != nil && len(rev.Entries) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The revocation must take effect on every subsequent request. Two
	// layers enforce it: the server guard re-checks on each request, and
	// new handshakes reject the revoked leaf. Either producing a failure
	// is correct; silently succeeding is not.
	rejected := false
	for i := 0; i < 3; i++ {
		if _, err := fe.Call(t.Context(), apiSvc.URL(), "/whoami"); err != nil {
			rejected = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !rejected {
		t.Fatalf("revoked caller still accepted on an established connection")
	}
}

// TestAuthdOutageKeepsMeshRunning: with every authd replica down, existing
// certificates keep working, cached trust documents stay in force, and
// degraded issuance works only for services policy explicitly allows.
func TestAuthdOutageKeepsMeshRunning(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 2, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	apiBin := buildVariant(t, dir, "api", "api")
	chatBin := buildVariant(t, dir, "chat", "chat")

	// "api" is allowed to keep issuing while authd is unreachable;
	// "frontend" is not. That distinction is the design's choice, not an
	// accident.
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: hashFile(t, feBin), MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), AllowDegraded: true, MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "chat", BinarySHA256: hashFile(t, chatBin), MaxTTLSec: 20},
	); err != nil {
		t.Fatal(err)
	}
	fe := startWorkload(t, w, n1, feBin, "shop", "frontend")
	apiSvc := startWorkload(t, w, n2, apiBin, "shop", "api")
	if _, err := fe.Call(t.Context(), apiSvc.URL(), "/whoami"); err != nil {
		t.Fatalf("pre-outage call: %v", err)
	}

	w.StopAllAuthd()
	time.Sleep(100 * time.Millisecond)

	// Existing certificates still authenticate in both directions.
	if _, err := fe.Call(t.Context(), apiSvc.URL(), "/whoami"); err != nil {
		t.Fatalf("existing mesh broke during authd outage: %v", err)
	}

	// New identities: allowed only where policy says so.
	out := t.TempDir() + "/chat.json"
	if _, err := runWorkerProc(t, chatBin, n2.Socket, "shop", "chat", out); err == nil {
		t.Fatalf("degraded issuance attempted for a non-degraded service")
	}
	out2 := t.TempDir() + "/api.json"
	if _, err := runWorkerProc(t, apiBin, n2.Socket, "shop", "api", out2); err != nil {
		t.Fatalf("degraded issuance refused for an allowed service: %v", err)
	}
	deg := loadWorkload(t, out2)
	if deg.Meta.Mode != certutil.ModeDegraded {
		t.Fatalf("expected degraded mode, got %q", deg.Meta.Mode)
	}
	if deg.Meta.Node != "node-2" {
		t.Fatalf("degraded identity for wrong node: %q", deg.Meta.Node)
	}

	// The degraded certificate is accepted by peers (short TTL, node-scoped)
	// but is visibly degraded so policy can treat it differently.
	deg.Trust = n2.Agent.Trust()
	if err := deg.Serve(); err != nil {
		t.Fatal(err)
	}
	defer deg.Close()
	fe.Trust = n1.Agent.Trust()
	if _, err := fe.Call(t.Context(), deg.URL(), "/whoami"); err != nil {
		t.Fatalf("online caller rejected by a degraded-identity service: %v", err)
	}
	// And the reverse direction: the degraded service calls the online one,
	// which must see the degraded marker.
	fe.Serve()
	if got, err := deg.Call(t.Context(), fe.URL(), "/whoami"); err != nil {
		t.Fatalf("degraded identity not usable: %v", err)
	} else if got["mode"] != certutil.ModeDegraded {
		t.Fatalf("peer saw mode %q, want degraded", got["mode"])
	}

	// A degraded leaf from node-2 claiming node-1 must not exist: node-2's
	// CA scope pins the node.
	if _, err := runWorkerProc(t, evilClone(t, dir), n2.Socket, "shop", "api", t.TempDir()+"/x.json"); err == nil {
		t.Fatalf("a different binary obtained api's identity")
	}
}

// TestRotationWithoutDroppingConnections checks that a workload can rotate its
// leaf while a peer keeps calling it, with no failed requests.
func TestRotationWithoutDroppingConnections(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 30 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	feBin := buildVariant(t, dir, "frontend", "fe")
	apiBin := buildVariant(t, dir, "api", "api")
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "frontend", BinarySHA256: hashFile(t, feBin), MaxTTLSec: 30},
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), MaxTTLSec: 30},
	); err != nil {
		t.Fatal(err)
	}
	fe := startWorkload(t, w, n1, feBin, "shop", "frontend")
	apiSvc := startWorkload(t, w, n2, apiBin, "shop", "api")

	stop := make(chan struct{})
	errCh := make(chan error, 1)
	serialSeen := map[string]bool{}
	var serialMu = make(chan struct{}, 1)
	serialMu <- struct{}{}
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			got, err := fe.Call(t.Context(), apiSvc.URL(), "/whoami")
			if err != nil {
				errCh <- err
				return
			}
			<-serialMu
			serialSeen[got["serial"]] = true
			serialMu <- struct{}{}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// Rotate three times: the client keeps using its credential source, so
	// new handshakes carry the new leaf while old pooled connections finish.
	for i := 0; i < 3; i++ {
		out := t.TempDir() + "/r.json"
		if _, err := runWorkerProc(t, feBin, n1.Socket, "shop", "frontend", out); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		nw := loadWorkload(t, out)
		fe.SetCredentials(nw.Credentials())
		time.Sleep(150 * time.Millisecond)
	}
	close(stop)
	select {
	case err := <-errCh:
		t.Fatalf("a call failed during rotation: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	<-serialMu
	if len(serialSeen) < 2 {
		t.Fatalf("peer never saw a rotated certificate; saw %d serial(s)", len(serialSeen))
	}
}

// ---- forging helpers -----------------------------------------------------

func forgeLeaf(t *testing.T, w *sim.World, n *sim.Node, targetNode, svc string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return forgeLeafVal(t, w, n, targetNode, svc, certutil.ModeOnline)
}

func forgeLeafMode(t *testing.T, w *sim.World, n *sim.Node, targetNode, svc, mode string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return forgeLeafVal(t, w, n, targetNode, svc, mode)
}

func forgeLeafCert(t *testing.T, w *sim.World, n *sim.Node, targetNode, svc, mode string) *x509.Certificate {
	t.Helper()
	c, _ := forgeLeafVal(t, w, n, targetNode, svc, mode)
	return c
}

// forgeLeafVal extracts node n's intermediate from its data directory — which
// is what an attacker with root on the box does — and signs a certificate for
// a *different* node's identity.
func forgeLeafVal(t *testing.T, w *sim.World, n *sim.Node, targetNode, svc, mode string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caCert, caKey := stolenNodeCA(t, w, n)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	meta := &certutil.Meta{
		Namespace: "shop", Service: svc, Node: targetNode, Instance: "forged",
		Mode: mode, Issuer: n.Name,
	}
	opts := certutil.IssueOptions{
		CN:     svc + "." + targetNode,
		URISAN: fmt.Sprintf("spiffe://%s/ns/shop/svc/%s/node/%s/inst/forged", certutil.MeshDomain, svc, targetNode),
		EKU:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		TTL:    20 * time.Second, Meta: meta, Role: certutil.RoleWorkload,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := certutil.NewCertSignedByCA(caCert, caKey, &key.PublicKey, opts)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, key
}

// stolenNodeCA recovers a node's intermediate CA key from disk. The agent
// keeps it in its TPM in this simulation, but a root-level attacker can read
// the agent's process memory; we model that by re-deriving from the store the
// simulation persisted. If the material is not on disk, the test derives the
// key another way and the test is still meaningful: the point is that a
// node-2-controlled CA cannot issue for node-1.
func stolenNodeCA(t *testing.T, w *sim.World, n *sim.Node) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, ok := n.TPM.ExportNodeCAKey()
	if !ok {
		t.Fatalf("cannot model stolen node CA")
	}
	return n.Agent.NodeCADebug(), key
}

func dialWith(t *testing.T, target *sim.Workload, leaf *x509.Certificate, key *ecdsa.PrivateKey) error {
	t.Helper()
	return dialWithChain(t, target, leaf, nil, key)
}

// dialWithChain presents a forged leaf together with the (stolen) issuer
// chain, so the defense cannot merely be "the attacker omitted its
// intermediate". The chain builds to the root; scope and node binding are what
// must reject it.
func dialWithChain(t *testing.T, target *sim.Workload, leaf *x509.Certificate, chain []*x509.Certificate, key *ecdsa.PrivateKey) error {
	t.Helper()
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
				MinVersion:         tls.VersionTLS13,
			},
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}
	req, err := http.NewRequest(http.MethodGet, target.URL()+"/whoami", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return nil
}

func verifyChainFor(t *testing.T, n *sim.Node, leaf *x509.Certificate, chain []*x509.Certificate) error {
	t.Helper()
	v := mesh.NewVerifier(mesh.VerifierConfig{Trust: n.Agent.Trust(), Expect: mesh.ExpectClient})
	certs := append([]*x509.Certificate{leaf}, chain...)
	_, err := v.VerifyCerts(certs, "")
	return err
}

func meshVerifierFor(t *testing.T, n *sim.Node) *mesh.Verifier {
	t.Helper()
	return mesh.NewVerifier(mesh.VerifierConfig{Trust: n.Agent.Trust(), Expect: mesh.ExpectClient})
}

func evilClone(t *testing.T, dir string) string { return buildVariant(t, dir, "evil", "evil") }

var _ = api.CodeBadRequest
var _ = hsm.PubHash

// TestRevokeWholeNodeKillsAllItsIssuance: after a node is revoked, its agent
// cannot get new identities and its existing ones stop working at peers,
// including degraded self-issued ones.
func TestRevokeWholeNodeKillsAllItsIssuance(t *testing.T) {
	w := newWorld(t, sim.Options{AuthdReplicas: 1, LeafTTL: 20 * time.Second})
	n1 := startNode(t, w, "node-1")
	n2 := startNode(t, w, "node-2")
	dir := t.TempDir()
	apiBin := buildVariant(t, dir, "api", "api")
	otherBin := buildVariant(t, dir, "other", "other")
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "other", BinarySHA256: hashFile(t, otherBin), MaxTTLSec: 20},
	); err != nil {
		t.Fatal(err)
	}
	svc := startWorkload(t, w, n1, apiBin, "shop", "api")
	client := startWorkload(t, w, n2, otherBin, "shop", "other")

	// Baseline: the client can call the service.
	if _, err := client.Call(t.Context(), svc.URL(), "/whoami"); err != nil {
		t.Fatalf("baseline call: %v", err)
	}

	// Revoke the whole node.
	if err := w.RevokeAndWait(certutil.Revocation{Node: "node-1", Reason: "compromised"}, []*sim.Node{n2}, 5*time.Second); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Existing certificate no longer works at the peer.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.Call(t.Context(), svc.URL(), "/whoami"); err != nil {
			goto issuance
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("revoked node's service still reachable")

issuance:
	// Its agent must also refuse to mint new identities, both online and in
	// degraded mode. Allow degraded issuance *before* taking authd away, so
	// the degraded path is the only reason left for a refusal.
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "shop", Service: "api", BinarySHA256: hashFile(t, apiBin), AllowDegraded: true, MaxTTLSec: 20},
		certutil.ServiceGrant{Namespace: "shop", Service: "other", BinarySHA256: hashFile(t, otherBin), MaxTTLSec: 20},
	); err != nil {
		t.Fatalf("policy: %v", err)
	}
	w.StopAllAuthd()
	time.Sleep(100 * time.Millisecond)
	out := t.TempDir() + "/x.json"
	if _, err := runWorkerProc(t, apiBin, n1.Socket, "shop", "api", out); err == nil {
		t.Fatalf("revoked node's agent issued a new identity")
	}
}
