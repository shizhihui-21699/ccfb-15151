// Command hsmd is a stub for the hardware boundary. In this simulation the TPM
// is an in-process package (internal/hsm); a production deployment runs the
// same API over a local socket or uses the platform TPM 2.0 device directly.
//
//	hsmd -dir /var/lib/meshid/nodes/node-1/tpm -node node-1
//
// It prints the module's public identity so operators can verify what is on
// disk before trusting it.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"meshid/internal/certutil"
	"meshid/internal/hsm"
)

func main() {
	dir := flag.String("dir", "", "TPM state directory")
	node := flag.String("node", "", "node name")
	vendorPath := flag.String("vendor-root", "", "PEM file with the platform vendor root")
	flag.Parse()
	if *dir == "" || *node == "" {
		fmt.Fprintln(os.Stderr, "hsmd: -dir and -node are required")
		os.Exit(2)
	}
	var vendor *hsm.Vendor
	if *vendorPath != "" {
		b, err := os.ReadFile(*vendorPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "hsmd:", err)
			os.Exit(1)
		}
		c, err := certutil.ParseCertPEM(string(b))
		if err != nil {
			fmt.Fprintln(os.Stderr, "hsmd:", err)
			os.Exit(1)
		}
		vendor = &hsm.Vendor{Root: &certutil.Authority{ID: "platform", Cert: c}}
	} else {
		v, err := hsm.NewVendor()
		if err != nil {
			fmt.Fprintln(os.Stderr, "hsmd:", err)
			os.Exit(1)
		}
		vendor = v
	}
	mod, err := hsm.OpenOrManufacture(vendor, *dir, *node)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsmd:", err)
		os.Exit(1)
	}
	ekPEM, ekChain := mod.EKChainPEM()
	c, _ := certutil.ParseCertPEM(ekPEM)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("tpm ready",
		"node", *node,
		"ek_fingerprint", mod.EKFingerprint(),
		"ek_not_after", c.NotAfter,
		"ek_chain_len", len(ekChain),
	)
}
