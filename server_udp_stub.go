/*
File:    server_udp_stub.go
Version: 1.5.0
Last Updated: 24-Nov-2026 12:56 CET

Description:
  Non-Linux fallback UDP listener pool using a shared channel.

Changes:
  1.5.0 - [FIX] Incremented `thr.droppedQueries` when `udpQueue` is full in
          `handleUDP` so queue-saturation drops on non-Linux builds are recorded
          in throttle diagnostics and persistent telemetry.
  1.4.0 - [SECURITY/FIX] Wrapped non-Linux UDP listeners in `superviseListener`
          and tied server teardown to `shutdownCh`.
  1.3.0 - [SECURITY/FIX] Switched peer address extraction to `remoteIPFromAddr`.
  1.2.0 - [LOGGING] Attached binding events to `logSystem`.
*/

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
		thr.droppedQueries.Add(1)
	}
}
