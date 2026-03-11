//go:build linux

/*
File: arp.go
Version: 1.12.0
Last Updated: 2026-03-03 18:00 CET
Description: Linux-only ARP table reader for IP->MAC resolution.
             Reads /proc/net/arp directly — no subprocess, no iproute2 dependency.
             Full fresh-map rebuild per cycle auto-evicts stale entries.

Changes:
  1.12.0 - [PERF] Replaced sync.RWMutex + plain map with atomic.Pointer to an
           immutable map. LookupMAC is called on every single DNS query — it was
           the second-hottest lock (after identMu, now also eliminated). With
           atomic.Pointer, readers pay one atomic load (~1 CPU instruction on
           ARM64/x86) instead of an RLock/RUnlock pair. The writer (pollARP)
           already rebuilt the map from scratch every 30s, so the atomic swap
           pattern is a drop-in replacement with zero semantic change.
  1.11.0 - [PERF] Replaced exec.Command("ip neigh") with direct /proc/net/arp read.
           [PERF] Switched sync.Map to RWMutex + plain map with full rebuild.
           [FIX]  Full rebuild automatically evicts stale entries.
  1.10.0 - Initial version using exec.Command("ip neigh") and sync.Map.
*/

package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// arpSnap holds the current IP->MAC table as an atomically-swapped immutable map.
// Readers: (*arpSnap.Load())[ip] — zero locks, zero contention.
// Writer:  arpSnap.Store(&fresh) — called only from the pollARP goroutine.
var arpSnap atomic.Pointer[map[string]string]

func init() {
	m := make(map[string]string, 64)
	arpSnap.Store(&m)
}

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
// Single atomic pointer load — zero locks, called on every query.
func LookupMAC(ipStr string) string {
	return (*arpSnap.Load())[ipStr]
}

// pollARP reads /proc/net/arp and rebuilds the IP->MAC table from scratch.
//
// /proc/net/arp format (kernel-maintained, always present on Linux):
//   IP address       HW type  Flags  HW address         Mask  Device
//   192.168.1.42     0x1      0x2    aa:bb:cc:dd:ee:ff  *     br-lan
//
// Flags: 0x0 = incomplete, 0x2 = valid, 0x4 = permanent.
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

		if mac == "00:00:00:00:00:00" {
			continue
		}

		if parsedMAC, err := net.ParseMAC(mac); err == nil {
			fresh[ip] = parsedMAC.String()
		}
	}

	// Atomic swap — readers see old map until this store completes,
	// then instantly see the new one. No partial state possible.
	arpSnap.Store(&fresh)
}

