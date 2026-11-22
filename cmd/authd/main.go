// Command authd runs one identity signing replica.
//
//	authd -config /var/lib/meshid/authd/authd-1.json
//
// The replica is stateless apart from its short-lived issuing intermediate; any
// number of replicas can run against the same store.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"meshid/internal/deploy"
)

func main() {
	cfgPath := flag.String("config", "", "path to the replica config JSON")
	listen := flag.String("listen", "", "override mesh listen address")
	admin := flag.String("admin-listen", "", "override admin listen address")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "authd: -config is required")
		os.Exit(2)
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	srv, err := deploy.LoadAuthd(*cfgPath, logger, *listen, *admin)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}
	if err := srv.Listen(); err != nil {
		logger.Error("listen", "err", err)
		os.Exit(1)
	}
	logger.Info("authd listening", "mesh", srv.Addr(), "admin", srv.AdminAddr())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		srv.Shutdown()
	}()
	if err := srv.Serve(); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}
