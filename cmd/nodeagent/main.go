// Command nodeagent runs the per-machine agent: it attests the machine to
// authd, rotates the node's certificates and vends short-lived identities to
// local processes over a Unix socket.
//
//	nodeagent -config /var/lib/meshid/nodes/node-1/agent.json
package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"meshid/internal/agent"
	"meshid/internal/certutil"
	"meshid/internal/deploy"
	"meshid/internal/hsm"
)

func main() {
	cfgPath := flag.String("config", "", "path to the node config JSON")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "nodeagent: -config is required")
		os.Exit(2)
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var cfg deploy.NodeConfig
	if err := deploy.ReadNodeConfig(*cfgPath, &cfg); err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}
	vendor := loadVendor(cfg)
	mod, err := hsm.OpenOrManufacture(vendor, cfg.TPMDir, cfg.Node)
	if err != nil {
		logger.Error("open tpm", "err", err)
		os.Exit(1)
	}
	a := agent.New(agent.Config{
		AgentID: cfg.Node, NodeName: cfg.Node,
		AuthdURLs: cfg.AuthdURLs, DataDir: cfg.DataDir, SocketDir: cfg.SocketDir,
		Logger: logger, TPM: mod,
		AuthdCARoots: []string{cfg.RootPEM}, AuthdServerName: cfg.ServerName,
		LeafTTL: 30 * time.Second, AgentCertTTL: 2 * time.Minute,
		RevocationRefresh: 2 * time.Second, ControlRefresh: 3 * time.Second,
		AdminToken: cfg.AdminToken,
	})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		a.Close()
	}()
	if err := a.Run(); err != nil {
		logger.Error("agent", "err", err)
		os.Exit(1)
	}
}

// loadVendor loads the platform vendor root from the node's own image. In
// production this is a compiled-in root; the simulation reads it from the
// deployment directory.
func loadVendor(cfg deploy.NodeConfig) *hsm.Vendor {
	// The vendor root is distributed with the node image; the deploy
	// command writes it next to the node config.
	rootPEM := deploy.VendorRootPEMFor(cfg)
	c, err := certutil.ParseCertPEM(rootPEM)
	if err != nil {
		panic("nodeagent: no platform vendor root available")
	}
	return &hsm.Vendor{Root: &certutil.Authority{ID: "platform", Cert: c}}
}

var _ = x509.NewCertPool
