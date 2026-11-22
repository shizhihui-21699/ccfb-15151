package e2e

import (
	"testing"
	"time"

	"meshid/internal/sim"
)

// newWorld builds a simulated deployment and registers its cleanup.
func newWorld(t *testing.T, opts sim.Options) *sim.World {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = t.TempDir()
	}
	w, err := sim.New(opts)
	if err != nil {
		t.Fatalf("sim.New: %v", err)
	}
	t.Cleanup(w.StopAllAuthd)
	return w
}

// startNode manufactures a machine, registers it in the inventory (the
// provisioning step that binds a node name to its hardware), and enrolls it.
func startNode(t *testing.T, w *sim.World, name string) *sim.Node {
	t.Helper()
	n, err := w.AddNode(name)
	if err != nil {
		t.Fatalf("AddNode(%s): %v", name, err)
	}
	if err := w.RegisterNode(n, "test"); err != nil {
		t.Fatalf("RegisterNode(%s): %v", name, err)
	}
	done, err := n.EnrollInBackground()
	if err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	t.Cleanup(func() {
		n.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	return n
}
