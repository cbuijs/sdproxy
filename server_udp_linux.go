// File: server_udp_linux.go
// Version: 1.3.0
// Last Updated: 03-May-2026 03:20 EDT
// Description: Linux-only SO_REUSEPORT UDP listener pool.
// Changes:
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
				if err := runReusePortWorker(addr, workerID); err != nil {
					log.Fatalf("[FATAL] UDP SO_REUSEPORT worker %d on %s: %v", workerID, addr, err)
				}
			}()
		}
		log.Printf("[LISTEN] UDP on %s (%d SO_REUSEPORT workers)", addr, workers)
	}
}

func runReusePortWorker(addr string, _ int) error {
	conn, err := newReusePortConn(addr)
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

func newReusePortConn(addr string) (net.PacketConn, error) {
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
				
				// [PERF/SECURITY] Dynamically scale socket buffers based on memory limit
				// Prevents OOM on embedded 64MB-128MB routers by replacing flat 8MB allocations natively.
				bufferSize := 1024 * 1024 // 1MB Safe Default Minimum
				if cfg.Server.MemoryLimitMB >= 128 {
					bufferSize = 2 * 1024 * 1024
				}
				if cfg.Server.MemoryLimitMB >= 512 {
					bufferSize = 4 * 1024 * 1024
				}
				if cfg.Server.MemoryLimitMB >= 1024 {
					bufferSize = 8 * 1024 * 1024
				}
				if cfg.Server.MemoryLimitMB == 0 {
					// Unbounded memory limit, safely assume massive host capability
					bufferSize = 8 * 1024 * 1024
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

