//go:build linux

/*
File: arp.go
Version: 1.11.0
Last Updated: 2026-03-01 14:00 CET
Description: Linux-only ARP table reader for IP->MAC resolution.
             Reads /proc/net/arp directly — no subprocess, no iproute2 dependency,
             works on OpenWrt, DD-WRT, and any Linux-based router.
             Full fresh-map rebuild per cycle auto-evicts stale entries.

Changes:
  1.11.0 - [PERF] Replaced exec.Command("ip neigh") with direct /proc/net/arp read.
           Eliminates fork+exec overhead every 30s — critical on MIPS/ARM routers.
           [PERF] Switched sync.Map to RWMutex + plain map with full rebuild per poll.
           sync.Map is optimised for append-once workloads; a full periodic rewrite
           (our pattern) has lower overhead with a plain map under RWMutex.
           [FIX]  Full rebuild automatically evicts entries for devices that left
           the network — Store-only approaches accumulate stale data indefinitely.
  1.10.0 - Initial version using exec.Command("ip neigh") and sync.Map.
*/

package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	arpMu   sync.RWMutex
	arpData = make(map[string]string, 64) // IP -> normalized MAC
)

func InitARP() {
	go func() {
		pollARP() // Immediate first run so routing works before the first tick

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pollARP()
		}
	}()
}

// LookupMAC returns the normalized MAC for an IP, or "" if unknown.
func LookupMAC(ipStr string) string {
	arpMu.RLock()
	mac := arpData[ipStr]
	arpMu.RUnlock()
	return mac
}

// pollARP reads /proc/net/arp and rebuilds the IP->MAC table from scratch.
//
// /proc/net/arp format (kernel-maintained, always present on Linux):
//   IP address       HW type  Flags  HW address         Mask  Device
//   192.168.1.42     0x1      0x2    aa:bb:cc:dd:ee:ff  *     br-lan
//
// Flags: 0x0 = incomplete (kernel still resolving), 0x2 = valid, 0x4 = permanent.
// Incomplete entries have HW address "00:00:00:00:00:00" — skip them.
func pollARP() {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		log.Printf("[ARP] Warning: cannot read /proc/net/arp: %v", err)
		return
	}
	defer file.Close()

	fresh := make(map[string]string, 64)
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip the header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip  := fields[0]
		mac := fields[3]

		// Skip incomplete ARP entries (kernel hasn't resolved them yet)
		if mac == "00:00:00:00:00:00" {
			continue
		}

		// Normalize MAC so it matches the format used in dnsmasq leases
		if parsedMAC, err := net.ParseMAC(mac); err == nil {
			fresh[ip] = parsedMAC.String()
		}
	}

	// Atomic swap — readers block for one RLock/RUnlock cycle at most
	arpMu.Lock()
	arpData = fresh
	arpMu.Unlock()
}

