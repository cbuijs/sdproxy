// File: server_udp_stub.go
// Version: 1.1.0
// Last Updated: 2026-04-10 10:52 CET
// Description: Non-Linux fallback UDP listener pool using a shared channel.

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
					var ip string
					if addr, ok := job.w.RemoteAddr().(*net.UDPAddr); ok {
						ip = addr.IP.String()
					}
					ProcessDNS(job.w, job.r, ip, "UDP", "", "")
				case <-shutdownCh:
					return
				}
			}
		}()
	}
	log.Printf("[LISTEN] UDP Worker Pool: %d goroutines (channel-based, non-Linux)", workers)

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

func handleUDP(w dns.ResponseWriter, r *dns.Msg) {
	select {
	case udpQueue <- udpJob{w: w, r: r}:
	case <-shutdownCh:
	default:
	}
}

