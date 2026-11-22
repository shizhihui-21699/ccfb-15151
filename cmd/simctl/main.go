// Command simctl drives the simulated multi-machine environment from a
// terminal: bring a world up, run attack scenarios, and print what happened.
//
//	simctl up      -dir /tmp/w -nodes 3 -authd 2
//	simctl attack  -dir /tmp/w
//	simctl outage  -dir /tmp/w
//	simctl down    -dir /tmp/w
//
// The same scenarios run as Go tests (see test/e2e); this command exists so a
// person can watch them happen against real processes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "/tmp/meshid-sim", "deployment directory")
	nodes := fs.Int("nodes", 3, "number of machines")
	replicas := fs.Int("authd", 2, "number of authd replicas")
	fs.Parse(os.Args[2:])

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	switch cmd {
	case "up":
		if err := up(*dir, *nodes, *replicas, logger); err != nil {
			fatal(err)
		}
	case "down":
		if err := down(*dir); err != nil {
			fatal(err)
		}
	case "attack":
		if err := attack(*dir, logger); err != nil {
			fatal(err)
		}
	case "outage":
		if err := outage(*dir, logger); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: simctl <up|down|attack|outage> -dir DIR [-nodes N] [-authd N]`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "simctl:", err)
	os.Exit(1)
}

// up creates a world in-process (so the CLI can start it in one command) and
// then reports how to reach it. The processes are children of simctl; use
// "simctl up" as a long-running command.
func up(dir string, nodes, replicas int, logger *slog.Logger) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	w, err := sim.New(sim.Options{
		Dir: dir, Logger: logger, AuthdReplicas: replicas,
		AdminToken: "sim-admin", LeafTTL: 30 * time.Second, NodeCATTL: 10 * time.Minute,
	})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AUTHD\tURL")
	for i, u := range w.AuthdURLs() {
		fmt.Fprintf(tw, "authd-%d\t%s\n", i+1, u)
	}
	fmt.Fprintf(tw, "admin\t%s\n", w.AdminURL())
	tw.Flush()

	names := make([]string, 0, nodes)
	for i := 1; i <= nodes; i++ {
		name := fmt.Sprintf("node-%d", i)
		n, err := w.AddNode(name)
		if err != nil {
			return err
		}
		if err := w.RegisterNode(n, "simctl up"); err != nil {
			return err
		}
		if _, err := n.EnrollInBackground(); err != nil {
			return fmt.Errorf("enroll %s: %w", name, err)
		}
		names = append(names, name)
		fmt.Printf("node %s enrolled, socket %s\n", name, n.Socket)
	}
	// A demo policy: one service that may run anywhere, one pinned to node-1.
	if err := w.SetPolicy(
		certutil.ServiceGrant{Namespace: "demo", Service: "echo", AllowDegraded: true, MaxTTLSec: 30},
		certutil.ServiceGrant{Namespace: "demo", Service: "frontend", Nodes: []string{"node-1"}, MaxTTLSec: 30},
	); err != nil {
		return err
	}
	fmt.Printf("\nworld up: %d machines, %d authd replicas\n", len(names), replicas)
	fmt.Println("press Ctrl-C to stop")
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	w.StopAllAuthd()
	return nil
}

func down(dir string) error {
	// Stop any authd/nodeagent processes recorded under dir.
	for _, pat := range []string{"authd", "nodeagent"} {
		cmd := exec.Command("pkill", "-f", filepath.Join(dir, pat))
		_ = cmd.Run()
	}
	return os.RemoveAll(dir)
}

// attack runs the impersonation scenario and prints a verdict per attempt.
func attack(dir string, logger *slog.Logger) error {
	// Attack scenarios need the full simulation object, which lives in the
	// test harness. For the CLI we run the Go test that performs them, which
	// is the same code path.
	fmt.Println("running attack scenarios (test/e2e)...")
	cmd := exec.Command("go", "test", "./test/e2e", "-run", "TestCompromisedMachineCannotImpersonateNeighbour", "-count=1", "-v")
	cmd.Dir = moduleRoot()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func outage(dir string, logger *slog.Logger) error {
	fmt.Println("running authd-outage scenarios (test/e2e)...")
	cmd := exec.Command("go", "test", "./test/e2e", "-run", "TestAuthdOutageKeepsMeshRunning", "-count=1", "-v")
	cmd.Dir = moduleRoot()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func moduleRoot() string {
	wd, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "."
		}
		wd = parent
	}
}

var _ = context.Background
var _ = strings.TrimSpace
