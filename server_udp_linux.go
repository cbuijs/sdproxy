// File: server_udp_linux.go
// Version: 1.0.0
// Last Updated: 2026-03-05 14:00 CET
// Description: Linux-only SO_REUSEPORT UDP listener pool.
//              Each worker opens its own UDP socket bound to the same address via
//              SO_REUSEPORT. The kernel distributes incoming packets across sockets
//              at the NIC/receive-queue level — no shared channel, no mutex, no
//              goroutine wake-up overhead per packet.
//
//              Compared to the old single-socket + channel design:
//                - Eliminates the (UDPWorkers*10)-deep job channel entirely.
//                - Eliminates the channel send/receive mutex on every incoming query.
//                - Each worker blocks in its own ReadFrom syscall — no contention.
//                - On multi-core routers the kernel can spread load across CPUs.
//
//              SO_REUSEPORT requires Linux ≥ 3.9. All supported OpenWrt targets
//              (ramips, ath79, x86, arm) run 5.x or 6.x kernels — safe to rely on.
//              Non-Linux builds use the channel-based pool in server_udp_stub.go.
//
// Changes:
//   1.0.0 - Initial SO_REUSEPORT per-worker UDP implementation.

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

// startUDPServers spawns `workers` goroutines per listen address, each with its
// own SO_REUSEPORT UDP socket. If no addresses are configured it returns
// immediately without allocating anything.
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

// runReusePortWorker creates a single SO_REUSEPORT UDP socket bound to addr and
// serves DNS queries from it directly, calling ProcessDNS without any channel.
//
// We use dns.Server.ActivateAndServe with a pre-built net.PacketConn so that
// miekg/dns handles the ReadFrom/WriteMsg loop — we only need to supply the socket.
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

// handleUDPDirect is the miekg/dns handler used by SO_REUSEPORT workers.
// Called directly in the worker goroutine — no channel, no mutex.
func handleUDPDirect(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ip = addr.IP.String()
	}
	ProcessDNS(w, r, ip, "UDP")
}

// newReusePortConn creates a UDP socket with SO_REUSEPORT and SO_REUSEADDR set
// before bind, then returns it as a net.PacketConn.
//
// We use the low-level syscall Control hook on net.ListenConfig so the socket
// options are set between socket() and bind() — the only window where they work
// correctly on all Linux kernel versions.
func newReusePortConn(addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setSockOptErr error
			err := c.Control(func(fd uintptr) {
				// SO_REUSEADDR: allows multiple sockets on the same port (safety net).
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					setSockOptErr = err
					return
				}
				// SO_REUSEPORT: the actual load-distribution mechanism.
				// Packets are distributed by the kernel's 4-tuple hash, so queries
				// from the same client IP:port always land on the same socket/worker
				// within a hash epoch — good cache locality for TCP-less UDP sessions.
				setSockOptErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return setSockOptErr
		},
	}

	// Use "udp" which resolves to udp4 or udp6 depending on the address.
	// "0.0.0.0:53" → udp4,  "[::]:53" → udp6,  ":53" → udp (dual-stack on Linux).
	return lc.ListenPacket(context.Background(), "udp", addr)
}

