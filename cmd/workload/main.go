// Command workload is a demo service (and a working integration example). It
// asks the local node agent for its identity, serves mTLS, and can call peers.
//
//	workload -socket /run/meshid/agent.sock -ns shop -svc frontend -listen :8080
//	workload -socket ... -call https://127.0.0.1:8081
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/identity"
	"meshid/internal/mesh"
	"meshid/internal/sim"
)

func main() {
	sock := flag.String("socket", "/run/meshid/agent.sock", "node agent Unix socket")
	ns := flag.String("ns", "", "namespace")
	svc := flag.String("svc", "", "service name")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address for mTLS")
	call := flag.String("call", "", "instead of serving, call this https URL and exit")
	peer := flag.String("peer-roots", "", "PEM file with extra roots (unused; trust comes from the agent)")
	flag.Parse()
	_ = peer
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *ns == "" || *svc == "" {
		fmt.Fprintln(os.Stderr, "workload: -ns and -svc are required")
		os.Exit(2)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("keygen", "err", err)
		os.Exit(1)
	}
	csr, err := certutil.NewCSR(key, *svc)
	if err != nil {
		logger.Error("csr", "err", err)
		os.Exit(1)
	}
	ctx := context.Background()
	creds, resp, trust, err := sim.RequestIdentityWithTrust(ctx, *sock, *ns, *svc, csr, key)
	if err != nil {
		logger.Error("identity", "err", err)
		os.Exit(1)
	}
	logger.Info("identity acquired", "svc", *ns+"/"+*svc, "node", resp.Meta.Node,
		"mode", resp.Mode, "expires", creds.ExpiresAt())

	// Keep the credential fresh: renew at 2/3 of lifetime, never before.
	// Renewal reuses the same private key, so the certificate can be swapped
	// underneath live connections.
	go renewLoop(ctx, creds, key, *sock, *ns, *svc, logger)

	if *call != "" {
		w := &sim.Workload{Trust: trust}
		w.SetCredentials(creds)
		got, err := w.Call(ctx, *call, "/whoami")
		if err != nil {
			logger.Error("call", "err", err)
			os.Exit(1)
		}
		b, _ := json.MarshalIndent(got, "", "  ")
		fmt.Println(string(b))
		return
	}

	verifier := mesh.NewVerifier(mesh.VerifierConfig{
		Trust: trust, Expect: mesh.ExpectClient, RequireRole: certutil.RoleWorkload,
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		id, ok := mesh.FromContext(r.Context())
		if !ok {
			http.Error(w, "no peer identity", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"caller": id.URI, "svc": id.Service, "node": id.Node,
			"mode": id.Mode, "serial": id.Serial, "role": id.Role,
		})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	handler := mesh.Guard(trust, func(w http.ResponseWriter, r *http.Request, _ *mesh.Identity) {
		mux.ServeHTTP(w, r)
	})
	cfg := mesh.ServerConfig{Verifier: verifier, Certs: creds}.TLSConfig()
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen", "err", err)
		os.Exit(1)
	}
	logger.Info("serving", "addr", ln.Addr().String())
	srv := &http.Server{Handler: handler, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ServeTLS(ln, "", ""); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func renewLoop(ctx context.Context, creds *identity.Creds, key *ecdsa.PrivateKey, sock, ns, svc string, logger *slog.Logger) {
	for {
		d := time.Until(creds.RenewAt())
		if d < time.Second {
			d = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
		}
		csr, err := certutil.NewCSR(key, svc)
		if err != nil {
			logger.Warn("renew csr", "err", err)
			continue
		}
		// Re-issue with the *same* key and swap the leaf in place, so
		// established connections keep working and new handshakes carry
		// the fresh certificate.
		_, resp, _, err := sim.RequestIdentityWithTrust(ctx, sock, ns, svc, csr, key)
		if err != nil {
			logger.Warn("renew failed; continuing with current certificate", "err", err)
			continue
		}
		if err := creds.Rotate(resp.CertPEM, resp.ChainPEM, &resp.Meta, resp.RenewAfter); err != nil {
			logger.Warn("rotate failed", "err", err)
			continue
		}
		logger.Info("renewed", "expires", creds.ExpiresAt(), "mode", resp.Mode)
	}
}

var _ = x509.NewCertPool
