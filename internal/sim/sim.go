// Package sim builds a complete, in-process mesh: an offline root, a platform
// vendor, one or more authd replicas, and any number of "machines", each with
// its own simulated TPM, node agent and workload socket.
//
// It is the test environment for the design questions that a unit test cannot
// answer: can a node enroll without any pre-shared secret, does an attacker
// who owns one machine get any other machine's identity, does the mesh keep
// working through an authd outage, and does revocation take effect on live
// connections.
package sim

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"meshid/internal/agent"
	"meshid/internal/api"
	"meshid/internal/authd"
	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/store"
)

// World is one simulated deployment.
type World struct {
	Root       *certutil.Authority
	Vendor     *hsm.Vendor
	Dir        string
	Logger     *slog.Logger
	AdminToken string
	Now        func() time.Time

	mu     sync.Mutex
	authds []*authd.Server
	nodes  map[string]*Node
	st     *store.Store
}

// Options tunes the simulated deployment.
type Options struct {
	Dir        string
	Logger     *slog.Logger
	AdminToken string
	RootTTL    time.Duration
	// AuthdReplicas is how many authd instances to run (each with its own
	// issuing intermediate, sharing one store).
	AuthdReplicas int
	// LeafTTL is the workload certificate lifetime.
	LeafTTL time.Duration
	// NodeCATTL is the node intermediate lifetime.
	NodeCATTL time.Duration
}

// New builds a world, starts the requested authd replicas and returns it.
func New(opts Options) (*World, error) {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}
	if opts.Dir == "" {
		d, err := os.MkdirTemp("", "meshid-sim-")
		if err != nil {
			return nil, err
		}
		opts.Dir = d
	}
	if opts.AdminToken == "" {
		opts.AdminToken = "sim-admin"
	}
	if opts.RootTTL == 0 {
		opts.RootTTL = 24 * time.Hour
	}
	if opts.AuthdReplicas == 0 {
		opts.AuthdReplicas = 1
	}
	if opts.LeafTTL == 0 {
		opts.LeafTTL = 15 * time.Second
	}
	if opts.NodeCATTL == 0 {
		opts.NodeCATTL = 5 * time.Minute
	}
	root, err := certutil.NewSelfSignedRoot("meshid-root", opts.RootTTL)
	if err != nil {
		return nil, err
	}
	vendor, err := hsm.NewVendor()
	if err != nil {
		return nil, err
	}
	w := &World{
		Root: root, Vendor: vendor, Dir: opts.Dir,
		Logger: opts.Logger, AdminToken: opts.AdminToken,
		Now: time.Now, nodes: map[string]*Node{},
	}
	vendorPool := x509.NewCertPool()
	vendorPool.AddCert(vendor.Root.Cert)

	st, err := store.New(filepath.Join(opts.Dir, "control"))
	if err != nil {
		return nil, err
	}
	w.st = st
	for i := 0; i < opts.AuthdReplicas; i++ {
		id := fmt.Sprintf("authd-%d", i+1)
		certPEM, keyPEM, chainPEM, err := w.issueAuthdCert(id)
		if err != nil {
			return nil, err
		}
		srv, err := authd.New(authd.Config{
			ReplicaID:     id,
			Addr:          "127.0.0.1:0",
			AdminAddr:     "127.0.0.1:0",
			Logger:        opts.Logger,
			AdminToken:    opts.AdminToken,
			Store:         st,
			Root:          root,
			VendorRoots:   vendorPool,
			LeafTTL:       opts.LeafTTL,
			NodeCATTL:     opts.NodeCATTL,
			AuthdCertPEM:  certPEM,
			AuthdKeyPEM:   keyPEM,
			AuthdChainPEM: chainPEM,
		})
		if err != nil {
			return nil, err
		}
		if err := srv.Listen(); err != nil {
			return nil, err
		}
		go srv.Serve()
		w.authds = append(w.authds, srv)
	}
	return w, nil
}

// issueAuthdCert creates a mesh server certificate for an authd replica. Its
// private key is generated here and handed to the replica; authd holds no
// long-lived secret beyond this short-lived TLS key.
func (w *World) issueAuthdCert(id string) (certPEM, keyPEM string, chain []string, err error) {
	key, err := certutil.NewKey()
	if err != nil {
		return "", "", nil, err
	}
	meta := &certutil.Meta{
		Node: "authd", Service: id, Instance: id,
		Mode: certutil.ModeOnline, Issuer: id,
	}
	o := certutil.IssueOptions{
		CN:       id,
		URISAN:   "spiffe://" + certutil.MeshDomain + "/ns/meshid/svc/authd/node/authd/inst/" + id,
		DNSNames: []string{"localhost", "authd.meshid.local", "127.0.0.1"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		TTL:      24 * time.Hour, Meta: meta, Role: certutil.RoleWorkload,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := w.Root.SignCert(&key.PublicKey, o)
	if err != nil {
		return "", "", nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", nil, err
	}
	keyPEM, err = certutil.EncodeKeyPEM(key)
	if err != nil {
		return "", "", nil, err
	}
	return certutil.EncodeCertPEM(leaf.Raw), keyPEM,
		[]string{certutil.EncodeCertPEM(w.Root.Cert.Raw)}, nil
}

func (w *World) store() (*store.Store, error) {
	if w.st == nil {
		return nil, errors.New("sim: no store")
	}
	return w.st, nil
}

// AuthdAddrs returns the mesh addresses of all replicas.
func (w *World) AuthdAddrs() []string {
	var out []string
	for _, s := range w.authds {
		out = append(out, s.Addr())
	}
	return out
}

// AuthdURLs returns the https URLs of all replicas.
func (w *World) AuthdURLs() []string {
	var out []string
	for _, s := range w.authds {
		out = append(out, "https://"+s.Addr())
	}
	return out
}

// AdminURL is the admin listener of replica 1.
func (w *World) AdminURL() string { return "http://" + w.authds[0].AdminAddr() }

// RootPEM is the trust anchor PEM that nodes pin in their image.
func (w *World) RootPEM() string { return certutil.EncodeCertPEM(w.Root.Cert.Raw) }

// VendorRootPEM is the platform root that certifies EKs.
func (w *World) VendorRootPEM() string { return certutil.EncodeCertPEM(w.Vendor.Root.Cert.Raw) }

// StopReplica shuts down replica i, simulating a crash or a partition.
func (w *World) StopReplica(i int) {
	if i < 0 || i >= len(w.authds) {
		return
	}
	w.authds[i].Shutdown()
}

// StopAllAuthd shuts down every replica.
func (w *World) StopAllAuthd() {
	for _, s := range w.authds {
		s.Shutdown()
	}
}

// Node is one simulated machine.
type Node struct {
	Name    string
	World   *World
	TPM     *hsm.Module
	Agent   *agent.Agent
	DataDir string
	Socket  string
}

// AddNode manufactures a TPM for a new machine and returns it unenrolled.
func (w *World) AddNode(name string) (*Node, error) {
	dir := filepath.Join(w.Dir, "nodes", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	mod, err := hsm.OpenOrManufacture(w.Vendor, filepath.Join(dir, "tpm"), name)
	if err != nil {
		return nil, err
	}
	// Unix socket paths are limited to ~104 bytes on macOS, and t.TempDir
	// paths are easily longer. Sockets therefore live in a short private
	// directory under the system temp dir, keyed by node name.
	sock, err := os.MkdirTemp("", "msk-")
	if err != nil {
		return nil, err
	}
	n := &Node{Name: name, World: w, TPM: mod, DataDir: dir,
		Socket: filepath.Join(sock, "agent.sock")}
	w.mu.Lock()
	w.nodes[name] = n
	w.mu.Unlock()
	return n, nil
}

// EnrollAndRun starts the node agent and enrolls it against the first reachable
// authd replica.
func (n *Node) EnrollAndRun() error {
	rootPEM := n.World.RootPEM()
	a := agent.New(agent.Config{
		AgentID:   n.Name,
		NodeName:  n.Name,
		AuthdURLs: n.World.AuthdURLs(),
		// All replicas are equivalent; the agent retries others only on
		// failure, which is enough for the simulation.
		DataDir:           n.DataDir,
		SocketDir:         filepath.Dir(n.Socket),
		Logger:            n.World.Logger,
		TPM:               n.TPM,
		AuthdCARoots:      []string{rootPEM},
		AuthdServerName:   "localhost",
		LeafTTL:           15 * time.Second,
		AgentCertTTL:      20 * time.Second,
		RevocationRefresh: 300 * time.Millisecond,
		ControlRefresh:    500 * time.Millisecond,
		AdminToken:        n.World.AdminToken,
	})
	n.Agent = a
	return a.Run()
}

// RunAgentAsync starts the agent in the background after enrollment.
func (n *Node) EnrollInBackground() (chan error, error) {
	done := make(chan error, 1)
	go func() { done <- n.EnrollAndRun() }()
	// Wait for the socket to appear, failing fast if the agent exits.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			if err == nil {
				err = errors.New("sim: agent exited before serving")
			}
			return done, err
		default:
		}
		if _, err := os.Stat(n.Socket); err == nil {
			return done, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return done, errors.New("sim: agent socket did not appear")
}

// Close stops the node agent.
func (n *Node) Close() {
	if n.Agent != nil {
		n.Agent.Close()
	}
}

// PolicyGrant is a convenience alias.
type PolicyGrant = certutil.ServiceGrant

// SetPolicy installs a signed policy on the control plane.
func (w *World) SetPolicy(grants ...certutil.ServiceGrant) error {
	admin := w.AdminURL()
	pol := certutil.Policy{
		Grants:           grants,
		DefaultMaxTTLSec: 15,
	}
	body, err := jsonMarshal(pol)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, admin+"/admin/policy", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Token", w.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("sim: set policy: %s", resp.Status)
	}
	// Nudge every running agent so tests do not race the poll interval.
	w.forceControlRefresh()
	return nil
}

// forceControlRefresh asks all running agents to pull policy and
// revocations now. In production this is a watch/event stream; the simulation
// uses the agents' admin endpoint so tests are deterministic.
func (w *World) forceControlRefresh() {
	w.mu.Lock()
	var nodes []*Node
	for _, n := range w.nodes {
		nodes = append(nodes, n)
	}
	w.mu.Unlock()
	var wg sync.WaitGroup
	for _, n := range nodes {
		if n.Agent == nil {
			continue
		}
		wg.Add(1)
		go func(n *Node) {
			defer wg.Done()
			n.Agent.RefreshNow()
		}(n)
	}
	wg.Wait()
}

// Revoke requests revocation of a node, service or serial.
func (w *World) Revoke(r certutil.Revocation) error {
	body, err := jsonMarshal(api.RevokeRequest{
		Node: r.Node, Service: r.Service, Instance: r.Instance,
		Serial: r.Serial, Reason: r.Reason,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.AdminURL()+api.PathRevoke, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Admin-Token", w.AdminToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("sim: revoke: %s", resp.Status)
	}
	return nil
}

// WaitRevocationPropagated blocks until every given agent has observed a
// revocation list version at least v.
func (w *World) WaitRevocationPropagated(v int, nodes []*Node, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, n := range nodes {
			if n.Agent == nil || n.Agent.Trust() == nil {
				ok = false
				break
			}
			revs := n.Agent.Trust().Revocations()
			if revs == nil || revs.Version < v {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("sim: revocation did not propagate in time")
}

// TLSForAgent builds a listener's tls.Config using a node agent's own
// rotating credentials, exactly as an integration would.
func (n *Node) ServerTLS() (*tls.Config, error) {
	a := n.Agent
	return (&meshServerConfig{trust: a.Trust(), creds: a.Credentials()}).config()
}

// RegisterNode authorizes a machine name against its TPM's EK, the way
// provisioning does before a machine is racked.
func (w *World) RegisterNode(n *Node, note string) error {
	st, err := w.store()
	if err != nil {
		return err
	}
	return st.RegisterNode(store.NodeRecord{
		Node: n.Name, EKFingerprint: n.TPM.EKFingerprint(),
		RegisteredBy: "sim", Note: note,
	})
}

// RevokeAndWait revokes and waits until the given agents have applied it.
func (w *World) RevokeAndWait(r certutil.Revocation, nodes []*Node, timeout time.Duration) error {
	if err := w.Revoke(r); err != nil {
		return err
	}
	w.forceControlRefresh()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ok := true
		for _, n := range nodes {
			if n.Agent == nil {
				continue
			}
			revs := n.Agent.Trust().Revocations()
			if revs == nil {
				ok = false
				break
			}
			hit := false
			for _, e := range revs.Entries {
				if (r.Serial != "" && e.Serial == r.Serial) ||
					(r.Node != "" && e.Node == r.Node && e.Service == r.Service && e.Instance == r.Instance) {
					hit = true
				}
			}
			if !hit {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("sim: revocation did not reach all agents")
}
