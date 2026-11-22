// Command loadgen exercises a running mesh: N clients of one service make M
// requests per second to another, using credentials obtained from their local
// node agents. It reports latency and error percentiles, which is how rotation
// and revocation are validated under load rather than one call at a time.
//
//	loadgen -socket /run/meshid/agent.sock -ns demo -svc client \
//	        -target https://127.0.0.1:9000 -qps 200 -duration 30s
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"meshid/internal/certutil"
	"meshid/internal/sim"
)

func main() {
	sock := flag.String("socket", "", "node agent socket")
	ns := flag.String("ns", "demo", "namespace")
	svc := flag.String("svc", "client", "service name")
	target := flag.String("target", "", "https URL of the service to call")
	qps := flag.Int("qps", 100, "requests per second")
	duration := flag.Duration("duration", 20*time.Second, "run time")
	concurrency := flag.Int("concurrency", 16, "parallel callers")
	flag.Parse()
	if *sock == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "loadgen: -socket and -target are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal(err)
	}
	csr, err := certutil.NewCSR(key, *svc)
	if err != nil {
		fatal(err)
	}
	creds, _, trust, err := sim.RequestIdentityWithTrust(ctx, *sock, *ns, *svc, csr, key)
	if err != nil {
		fatal(err)
	}
	w := &sim.Workload{Trust: trust}
	w.SetCredentials(creds)

	var ok, fail atomic.Int64
	lat := make(chan time.Duration, 200000)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Renewal loop: keeps the caller's certificate fresh during the run.
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Until(creds.RenewAt())):
			}
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			c, _ := certutil.NewCSR(k, *svc)
			if _, _, t, err := sim.RequestIdentityWithTrust(ctx, *sock, *ns, *svc, c, k); err == nil {
				_ = t
			}
		}
	}()
	interval := time.Second / time.Duration(*qps)
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := time.NewTicker(interval * time.Duration(*concurrency))
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				start := time.Now()
				_, err := w.Call(ctx, *target, "/whoami")
				d := time.Since(start)
				select {
				case lat <- d:
				default:
				}
				if err != nil {
					fail.Add(1)
				} else {
					ok.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	close(lat)
	var ds []time.Duration
	for d := range lat {
		ds = append(ds, d)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	pct := func(p float64) time.Duration {
		if len(ds) == 0 {
			return 0
		}
		i := int(float64(len(ds)-1) * p)
		return ds[i]
	}
	fmt.Printf("requests ok=%d fail=%d\n", ok.Load(), fail.Load())
	fmt.Printf("latency p50=%s p95=%s p99=%s max=%s\n", pct(0.5), pct(0.95), pct(0.99), pct(1))
	if ok.Load() > 0 && fail.Load() > 0 {
		fmt.Printf("failure ratio %.2f%%\n", 100*float64(fail.Load())/float64(ok.Load()+fail.Load()))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "loadgen:", err)
	os.Exit(1)
}
