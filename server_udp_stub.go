// File: server_udp_stub.go
// Version: 1.0.0
// Last Updated: 2026-03-05 14:00 CET
// Description: Non-Linux fallback UDP listener pool using a shared channel.
//              Functionally identical to the original server.go UDP pool from
//              v1.15.0–v1.17.0. Used on macOS (dev builds), BSDs, etc.
//              On Linux, server_udp_linux.go replaces this with SO_REUSEPORT.
//
// Changes:
//   1.0.0 - Extracted from server.go v1.17.0 into its own build-tag-gated file.

//go:build !linux

package main

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

type udpJob struct {
	w dns.ResponseWriter
	r *dns.Msg
}

// udpQueue is the shared job channel for the non-Linux worker pool.
// Nil when no listen_udp addresses are configured — handleUDP's select default
// branch makes a nil channel safe (drops the query rather than blocking/panicking).
var udpQueue chan udpJob

// startUDPServers starts the channel-based UDP worker pool and one dns.Server
// per configured address. Workers dequeue jobs and call ProcessDNS directly.
func startUDPServers(addrs []string, workers int) {
	if len(addrs) == 0 {
		return
	}
	if workers <= 0 {
		workers = 10
	}

	// Allocate the shared job channel and start workers.
	udpQueue = make(chan udpJob, workers*10)
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case job, ok := <-udpQueue:
					if !ok {
						return
					}
					var ip string
					if addr, ok := job.w.RemoteAddr().(*net.UDPAddr); ok {
						ip = addr.IP.String()
					}
					ProcessDNS(job.w, job.r, ip, "UDP")
				case <-shutdownCh:
					return
				}
			}
		}()
	}
	log.Printf("[LISTEN] UDP Worker Pool: %d goroutines (channel-based, non-Linux)", workers)

	// Start one dns.Server per listen address. Each server reads from its UDP
	// socket and enqueues jobs onto the shared channel for the worker pool.
	for _, addr := range addrs {
		addr := addr
		go func() {
			server := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(handleUDP)}
			log.Printf("[LISTEN] UDP on %s", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Fatalf("[FATAL] UDP failed on %s: %v", addr, err)
			}
		}()
	}
}

// handleUDP enqueues an incoming UDP query onto the shared worker pool channel.
// udpQueue is nil when no listen_udp addresses are configured — the default
// branch drops the query safely without blocking.
func handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	case <-shutdownCh:
	default:
	}
}

