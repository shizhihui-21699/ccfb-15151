// Package deploy materializes a whole deployment on disk so the command-line
// binaries can run as separate processes, the way they would in production.
//
// Layout:
//
//	<dir>/
//	  offline/root.key           root private key (would be offline/HSM)
//	  offline/root.crt
//	  platform/vendor.crt        platform vendor root
//	  control/                   authd store: bundle, policy, revocations, inventory
//	  authd/<id>.json            replica config (listeners, certs, store)
//	  authd/<id>.key|crt         replica TLS identity
//	  nodes/<node>/tpm/          simulated TPM state for that machine
//	  nodes/<node>/agent.json    node agent config
package deploy

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"meshid/internal/authd"
	"meshid/internal/certutil"
	"meshid/internal/hsm"
	"meshid/internal/store"
)

// AuthdConfig is the on-disk config for one authd replica.
type AuthdConfig struct {
	ReplicaID    string   `json:"replica_id"`
	Listen       string   `json:"listen"`
	AdminListen  string   `json:"admin_listen"`
	AdminToken   string   `json:"admin_token"`
	StoreDir     string   `json:"store_dir"`
	RootCertPath string   `json:"root_cert_path"`
	RootKeyPath  string   `json:"root_key_path"`
	VendorRoots  []string `json:"vendor_roots_pem"`
	TLSCertPath  string   `json:"tls_cert_path"`
	TLSKeyPath   string   `json:"tls_key_path"`
	TLSChainPath string   `json:"tls_chain_path"`
	LeafTTL      string   `json:"leaf_ttl"`
	NodeCATTL    string   `json:"node_ca_ttl"`
	NodeAgentTTL string   `json:"node_agent_ttl"`
}

// NodeConfig is the on-disk config for one node agent.
type NodeConfig struct {
	Node       string   `json:"node"`
	AuthdURLs  []string `json:"authd_urls"`
	DataDir    string   `json:"data_dir"`
	SocketDir  string   `json:"socket_dir"`
	TPMDir     string   `json:"tpm_dir"`
	RootPEM    string   `json:"root_pem"`
	VendorPEM  string   `json:"vendor_pem"`
	ServerName string   `json:"server_name"`
	AdminToken string   `json:"admin_token"`
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Init creates (or opens) a deployment directory and returns the offline root.
// It is idempotent: an existing root and store are reused so replicas can be
// added without re-keying the world.
func Init(dir string, replicas int, adminToken string) (*certutil.Authority, error) {
	if replicas <= 0 {
		replicas = 1
	}
	for _, sub := range []string{"offline", "platform", "control", "authd"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	root, err := loadOrCreateRoot(filepath.Join(dir, "offline"))
	if err != nil {
		return nil, err
	}
	vendor, err := loadOrCreateVendor(filepath.Join(dir, "platform"))
	if err != nil {
		return nil, err
	}
	if _, err := store.New(filepath.Join(dir, "control")); err != nil {
		return nil, err
	}
	vendorPEM := certutil.EncodeCertPEM(vendor.Cert.Raw)
	for i := 1; i <= replicas; i++ {
		id := fmt.Sprintf("authd-%d", i)
		cfgPath := filepath.Join(dir, "authd", id+".json")
		if _, err := os.Stat(cfgPath); err == nil {
			continue
		}
		certPEM, keyPEM, chainPEM, err := replicaCert(root, id)
		if err != nil {
			return nil, err
		}
		certPath := filepath.Join(dir, "authd", id+".crt")
		keyPath := filepath.Join(dir, "authd", id+".key")
		chainPath := filepath.Join(dir, "authd", id+".chain")
		if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(chainPath, []byte(chainPEM), 0o600); err != nil {
			return nil, err
		}
		cfg := AuthdConfig{
			ReplicaID: id, Listen: "127.0.0.1:0", AdminListen: "127.0.0.1:0",
			AdminToken: adminToken, StoreDir: filepath.Join(dir, "control"),
			RootCertPath: filepath.Join(dir, "offline", "root.crt"),
			RootKeyPath:  filepath.Join(dir, "offline", "root.key"),
			VendorRoots:  []string{vendorPEM},
			TLSCertPath:  certPath, TLSKeyPath: keyPath, TLSChainPath: chainPath,
			LeafTTL: "30s", NodeCATTL: "10m", NodeAgentTTL: "2m",
		}
		if err := writeJSON(cfgPath, cfg); err != nil {
			return nil, err
		}
	}
	return root, nil
}

func loadOrCreateRoot(dir string) (*certutil.Authority, error) {
	certPath := filepath.Join(dir, "root.crt")
	keyPath := filepath.Join(dir, "root.key")
	if b, err := os.ReadFile(certPath); err == nil {
		c, err := certutil.ParseCertPEM(string(b))
		if err != nil {
			return nil, err
		}
		kb, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		k, err := certutil.ParseKeyPEM(string(kb))
		if err != nil {
			return nil, err
		}
		return &certutil.Authority{ID: "meshid-root", Cert: c, Key: k}, nil
	}
	a, err := certutil.NewSelfSignedRoot("meshid-root", 10*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	kp, err := certutil.EncodeKeyPEM(a.Key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(kp), 0o600); err != nil {
		return nil, err
	}
	return a, os.WriteFile(certPath, []byte(certutil.EncodeCertPEM(a.Cert.Raw)), 0o644)
}

// loadOrCreateVendor returns the platform vendor root, persisting both its
// certificate and — because this simulation manufactures TPMs on the same
// machine — its key. In production only the certificate would be distributed;
// the key stays with the platform vendor, which signs EK certificates at
// manufacture time.
func loadOrCreateVendor(dir string) (*certutil.Authority, error) {
	certPath := filepath.Join(dir, "vendor.crt")
	keyPath := filepath.Join(dir, "vendor.key")
	if b, err := os.ReadFile(certPath); err == nil {
		c, err := certutil.ParseCertPEM(string(b))
		if err != nil {
			return nil, err
		}
		if kb, err := os.ReadFile(keyPath); err == nil {
			k, err := certutil.ParseKeyPEM(string(kb))
			if err != nil {
				return nil, err
			}
			return &certutil.Authority{ID: "meshid-sim-platform-root", Cert: c, Key: k}, nil
		}
		return nil, fmt.Errorf("deploy: vendor key missing for %s (cannot manufacture EKs)", certPath)
	}
	a, err := certutil.NewSelfSignedRoot("meshid-sim-platform-root", 20*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	kp, err := certutil.EncodeKeyPEM(a.Key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(kp), 0o600); err != nil {
		return nil, err
	}
	return a, os.WriteFile(certPath, []byte(certutil.EncodeCertPEM(a.Cert.Raw)), 0o644)
}

// VendorKeyPath is where the platform vendor key lives in the simulation.
func VendorKeyPath(dir string) string { return filepath.Join(dir, "platform", "vendor.key") }

func replicaCert(root *certutil.Authority, id string) (certPEM, keyPEM, chainPEM string, err error) {
	key, err := certutil.NewKey()
	if err != nil {
		return "", "", "", err
	}
	meta := &certutil.Meta{Node: "authd", Service: id, Instance: id, Mode: certutil.ModeOnline, Issuer: id}
	der, err := root.SignCert(&key.PublicKey, certutil.IssueOptions{
		CN: id, URISAN: "spiffe://" + certutil.MeshDomain + "/ns/meshid/svc/authd/node/authd/inst/" + id,
		DNSNames: []string{"localhost", id},
		IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		EKU:      []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		TTL:      30 * 24 * time.Hour, Meta: meta, Role: certutil.RoleWorkload,
		KeyUsage: x509.KeyUsageDigitalSignature,
	})
	if err != nil {
		return "", "", "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", "", err
	}
	keyPEM, err = certutil.EncodeKeyPEM(key)
	if err != nil {
		return "", "", "", err
	}
	return certutil.EncodeCertPEM(leaf.Raw), keyPEM, certutil.EncodeCertPEM(root.Cert.Raw), nil
}

// AddNode creates (or opens) a machine's TPM and writes its agent config.
func AddNode(dir, node string, authdURLs []string, adminToken string) (*NodeConfig, error) {
	tpmDir := filepath.Join(dir, "nodes", node, "tpm")
	if err := os.MkdirAll(tpmDir, 0o700); err != nil {
		return nil, err
	}
	vendor, err := loadOrCreateVendor(filepath.Join(dir, "platform"))
	if err != nil {
		return nil, err
	}
	// Only the EK public material is needed here; the module itself is
	// opened by the agent process. We still open it once so the EK exists
	// and can be registered in the inventory.
	v := &hsm.Vendor{Root: vendor}
	mod, err := hsm.OpenOrManufacture(v, tpmDir, node)
	if err != nil {
		return nil, err
	}
	rootPEMBytes, err := os.ReadFile(filepath.Join(dir, "offline", "root.crt"))
	if err != nil {
		return nil, err
	}
	vendorPEM := certutil.EncodeCertPEM(vendor.Cert.Raw)
	st, err := store.New(filepath.Join(dir, "control"))
	if err != nil {
		return nil, err
	}
	if err := st.RegisterNode(store.NodeRecord{
		Node: node, EKFingerprint: mod.EKFingerprint(), RegisteredBy: "deploy",
	}); err != nil {
		return nil, err
	}
	cfg := &NodeConfig{
		Node: node, AuthdURLs: authdURLs,
		DataDir:    filepath.Join(dir, "nodes", node, "data"),
		SocketDir:  filepath.Join(dir, "nodes", node, "run"),
		TPMDir:     tpmDir,
		RootPEM:    string(rootPEMBytes),
		VendorPEM:  vendorPEM,
		ServerName: "localhost",
		AdminToken: adminToken,
	}
	// Unix socket path length limit: keep the socket dir short and put it
	// beside the deployment when the deployment dir is long.
	if len(filepath.Join(cfg.SocketDir, "agent.sock")) > 100 {
		sock, err := os.MkdirTemp("", "msk-")
		if err != nil {
			return nil, err
		}
		cfg.SocketDir = sock
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(dir, "nodes", node, "agent.json"), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadAuthd reads a replica config and builds the authd server.
func LoadAuthd(cfgPath string, logger *slog.Logger, listenOverride, adminOverride string) (*authd.Server, error) {
	var c AuthdConfig
	if err := readJSON(cfgPath, &c); err != nil {
		return nil, err
	}
	rootCert, err := certutil.ParseCertPEM(string(mustRead(c.RootCertPath)))
	if err != nil {
		return nil, err
	}
	rootKey, err := certutil.ParseKeyPEM(string(mustRead(c.RootKeyPath)))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, p := range c.VendorRoots {
		pool.AppendCertsFromPEM([]byte(p))
	}
	st, err := store.New(c.StoreDir)
	if err != nil {
		return nil, err
	}
	leafTTL, err := time.ParseDuration(orDefault(c.LeafTTL, "30s"))
	if err != nil {
		return nil, err
	}
	nodeCATTL, err := time.ParseDuration(orDefault(c.NodeCATTL, "10m"))
	if err != nil {
		return nil, err
	}
	agentTTL, err := time.ParseDuration(orDefault(c.NodeAgentTTL, "2m"))
	if err != nil {
		return nil, err
	}
	cfg := authd.Config{
		ReplicaID: c.ReplicaID, Addr: c.Listen, AdminAddr: c.AdminListen,
		AdminToken: c.AdminToken, Store: st,
		Root:        &certutil.Authority{ID: "meshid-root", Cert: rootCert, Key: rootKey},
		VendorRoots: pool,
		LeafTTL:     leafTTL, NodeCATTL: nodeCATTL, NodeAgentTTL: agentTTL,
		AuthdCertPEM:  string(mustRead(c.TLSCertPath)),
		AuthdKeyPEM:   string(mustRead(c.TLSKeyPath)),
		AuthdChainPEM: []string{string(mustRead(c.TLSChainPath))},
	}
	cfg.Logger = logger
	if listenOverride != "" {
		cfg.Addr = listenOverride
	}
	if adminOverride != "" {
		cfg.AdminAddr = adminOverride
	}
	return authd.New(cfg)
}

func mustRead(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		panic(fmt.Sprintf("deploy: read %s: %v", p, err))
	}
	return b
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ReadNodeConfig loads a node agent config.
func ReadNodeConfig(path string, cfg *NodeConfig) error { return readJSON(path, cfg) }

// VendorRootPEMFor returns the platform root PEM shipped with a node.
func VendorRootPEMFor(cfg NodeConfig) string { return cfg.VendorPEM }

// ErrNotInitialized is returned when a config is missing.
var ErrNotInitialized = errors.New("deploy: not initialized")
