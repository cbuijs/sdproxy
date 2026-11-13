// File: server_udp_stub.go
// Version: 1.4.0
// Last Updated: 15-Oct-2026 18:55 CEST
// Description: Non-Linux fallback UDP listener pool using a shared channel.
// Changes:
//   1.4.0 - [SECURITY/FIX] Wrapped non-Linux UDP listeners in `superviseListener`
//           and tied server teardown to `shutdownCh` so transient socket errors
//           do not call `log.Fatalf` at runtime.
//   1.3.0 - [SECURITY/FIX] Same fail-open source-address extraction repaired in
//           server_udp_linux.go 1.5.0: the worker asserted job.w.RemoteAddr()
//           to *net.UDPAddr and left the IP empty on failure. Switched to the
//           shared remoteIPFromAddr() helper (server.go 1.36.0) so both build
//           variants derive the peer address identically. The "net" import is
//           dropped with it — the type assertion was this file's only consumer.
//   1.2.0 - [LOGGING] Attached binding events smoothly into `logSystem`.

//go:build !linux

package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

type udpJob struct {
	w dns.ResponseWriter
	r *dns.Msg
}

var udpQueue chan udpJob

func startUDPServers(addrs []string, workers int) {
	if len(addrs) == 0 {
		return
	}
	if workers <= 0 {
		workers = 10
	}

	udpQueue = make(chan udpJob, workers*10)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case job, ok := <-udpQueue:
					if !ok {
						return
					}
					// [SECURITY 1.3.0] Type-agnostic extraction — see header.
					ip := remoteIPFromAddr(job.w.RemoteAddr())
					ProcessDNS(job.w, job.r, ip, "UDP", "", "")
				case <-shutdownCh:
					return
				}
			}
		}()
	}

	if logSystem {
		log.Printf("[LISTEN] UDP Worker Pool: %d goroutines (channel-based, non-Linux)", workers)
	}

	for _, addr := range addrs {
		addr := addr
		go superviseListener("UDP", addr, func(attempt int) error {
			server := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(handleUDP)}
			if logSystem {
				log.Printf("[LISTEN] UDP on %s", addr)
			}

			served := make(chan struct{})
			defer close(served)
			go func() {
				select {
				case <-shutdownCh:
					_ = server.Shutdown()
				case <-served:
				}
			}()

			err := server.ListenAndServe()
			if err != nil && attempt == 0 {
				log.Fatalf("[FATAL] UDP failed on %s: %v", addr, err)
			}
			if err != nil {
				return fmt.Errorf("rebind: %w", err)
			}
			return nil
		})
	}
}

func handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	case <-shutdownCh:
	default:
	}
}

