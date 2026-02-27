//go:build linux

/*
File: arp.go
Version: 1.10.0
Last Updated: 2026-02-27 20:41 CET
Description: Linux-only ARP/NDP table poller using the 'ip neigh' command.
             Continuously resolves local network IPs to MAC addresses in the background
             so routing lookups on the hot path (process.go) are instant O(1) hash maps.
*/

package main

import (
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	// arpMap stores IP -> MAC mappings
	arpMap sync.Map
)

func InitARP() {
	go func() {
		pollARP() // Initial immediate run
		
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pollARP()
		}
	}()
}

func LookupMAC(ipStr string) string {
	if mac, ok := arpMap.Load(ipStr); ok {
		return mac.(string)
	}
	return ""
}

func pollARP() {
	out, err := exec.Command("ip", "neigh").Output()
	if err != nil {
		log.Printf("[ARP] Warning: Failed to execute 'ip neigh': %v", err)
		return
	}

	lines := strings.Split(string(out), "\n")
	found := 0

	for _, line := range lines {
		fields := strings.Fields(line)
		
		if len(fields) < 5 {
			continue
		}

		ip := fields[0]
		mac := ""

		for i, field := range fields {
			if field == "lladdr" && i+1 < len(fields) {
				mac = fields[i+1]
				break
			}
		}

		if mac != "" {
			parsedMAC, err := net.ParseMAC(mac)
			if err == nil {
				arpMap.Store(ip, parsedMAC.String())
				found++
			}
		}
	}
}

