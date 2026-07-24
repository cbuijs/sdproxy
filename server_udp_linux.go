// File: server_udp_linux.go
// Version: 1.4.0
// Last Updated: 11-May-2026 08:37 CEST
// Description: Linux-only SO_REUSEPORT UDP listener pool.
// Changes:
//   1.4.0 - [LOGGING] Bound port multiplexing allocations organically to `logSystem`.
//   1.3.0 - [PERF/SECURITY] Implemented dynamically scaling UDP ring-buffers 
//           (`SO_RCVBUF`, `SO_SNDBUF`) bounded natively to the configured 
//           system `memory_limit_mb`. Severely neutralizes embedded router 
//           Out-Of-Memory (OOM) killer crashes instigated by 8MB unswappable allocations.

//go:build linux

package main

import (
	"context"
	"log"
	"net"
	"syscall"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func startUDPServers(addrs []string, workers int) {
    if len(addrs) == 0 {
        return
    }
    if workers <= 0 {
        workers = 10
    }
    for _, addr := range addrs {
        addr := addr
        for i := 0; i < workers; i++ {
            workerID := i
            go func() {
                if err := runReusePortWorker(addr, workerID, workers); err != nil {
                    log.Fatalf("[FATAL] UDP SO_REUSEPORT worker %d on %s: %v", workerID, addr, err)
                }
            }()
        }
        if logSystem {
            log.Printf("[LISTEN] UDP on %s (%d SO_REUSEPORT workers)", addr, workers)
        }
    }
}

func runReusePortWorker(addr string, _ int, workers int) error {
    conn, err := newReusePortConn(addr, workers)
    if err != nil {
        return err
    }
    srv := &dns.Server{
        PacketConn: conn,
        Net:        "udp",
        Handler:    dns.HandlerFunc(handleUDPDirect),
    }
    return srv.ActivateAndServe()
}

func handleUDPDirect(w dns.ResponseWriter, r *dns.Msg) {
    var ip string
    if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
        ip = addr.IP.String()
    }
    ProcessDNS(w, r, ip, "UDP", "", "")
}

func newReusePortConn(addr string, workers int) (net.PacketConn, error) {
    lc := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            var setSockOptErr error
            err := c.Control(func(fd uintptr) {
                if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
                    setSockOptErr = err
                    return
                }
                if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
                    setSockOptErr = err
                    return
                }

                // [SECURITY/FIX] The per-tier size below is a TOTAL budget for the
                // whole SO_REUSEPORT worker pool on this address, not a per-socket
                // size. The previous version applied the full tier size to every
                // worker's socket independently, so the default 10-worker pool could
                // consume up to 160MB of kernel buffers on the top tier, or ~40MB
                // (nearly a third of budget) on a memory_limit_mb: 128 router — the
                // exact class this code says it protects. Dividing by workers keeps
                // total kernel-buffer usage proportional to the configured ceiling
                // regardless of worker count.
                totalBudget := 8 * 1024 * 1024 // 8MB total default (unbounded or >=1024MB host)
                switch {
                case cfg.Server.MemoryLimitMB > 0 && cfg.Server.MemoryLimitMB < 128:
                    totalBudget = 1024 * 1024
                case cfg.Server.MemoryLimitMB >= 128 && cfg.Server.MemoryLimitMB < 512:
                    totalBudget = 2 * 1024 * 1024
                case cfg.Server.MemoryLimitMB >= 512 && cfg.Server.MemoryLimitMB < 1024:
                    totalBudget = 4 * 1024 * 1024
                }

                w := workers
                if w <= 0 {
                    w = 1
                }
                bufferSize := totalBudget / w
                const minBufferSize = 64 * 1024 // floor — below this, kernel buffering stops helping under burst load
                if bufferSize < minBufferSize {
                    bufferSize = minBufferSize
                }

                _ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, bufferSize)
                _ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, bufferSize)
            })
            if err != nil {
                return err
            }
            return setSockOptErr
        },
    }
    return lc.ListenPacket(context.Background(), "udp", addr)
}

