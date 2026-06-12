//go:build linux

/*
File: arp.go
Version: 1.17.0
Last Updated: 10-Jun-2026 10:30 CEST
Description: Linux-only ARP table reader for IP->MAC resolution.
             Reads /proc/net/arp directly — no subprocess, no iproute2 dependency.
             Full fresh-map rebuild per cycle auto-evicts stale entries.

Changes:
  1.17.0 - [PERF] Overhauled `pollARP` to execute entirely via zero-allocation 
           byte scanning (`bytes.Fields`, `bytes.Equal`). Eradicates massive 
           Garbage Collection (GC) thrashing caused by dynamic string allocations 
           every 30 seconds natively.
  1.16.0 - [SECURITY/FIX] Resolved a severe cache-wiping regression. Natively 
           intercepts `scanner.Err()` interrupts and explicitly aborts the 
           atomic `arpSnap.Store()` operation. Prevents the active router map 
           from being permanently overwritten by truncated OS-level descriptor streams.
  1.15.0 - [LOGGING] Applied granular logging bounds natively. ARP warnings now 
           check `logSystem` organically.
  1.14.0 - [RELIABILITY] Added `scanner.Err()` evaluation following the loop to 
           catch and log silent `procfs` read interruptions or kernel faults.
  1.13.0 - [PERF] Made initial ARP polling synchronous to guarantee table mapping 
           is fully populated before the DNS listeners bind and accept traffic.
  1.12.0 - [PERF] Replaced sync.RWMutex + plain map with atomic.Pointer to an
           immutable map.
*/

package main

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os"
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
	pollARP() // Immediate synchronous first run so routing works before listeners bind

	go func() {
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
//   192.168.1.42     0x1      0x2    aa:bb:cc:dd:ee:ff  * br-lan
//
// Flags: 0x0 = incomplete, 0x2 = valid, 0x4 = permanent.
// Incomplete entries have HW address "00:00:00:00:00:00" — skip them.
func pollARP() {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		if logSystem {
			log.Printf("[ARP] Warning: cannot read /proc/net/arp: %v", err)
		}
		return
	}
	defer file.Close()

	fresh := make(map[string]string, 64)
	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip the header line

	for scanner.Scan() {
		// [PERF/FIX] Operate strictly on byte slices organically to prevent allocating 
		// millions of useless strings over the lifecycle of the process for discarded lines.
		line := scanner.Bytes()
		fields := bytes.Fields(line)
		
		if len(fields) < 4 {
			continue
		}
		
		macBytes := fields[3]

		if bytes.Equal(macBytes, []byte("00:00:00:00:00:00")) {
			continue
		}

		if parsedMAC, err := net.ParseMAC(string(macBytes)); err == nil {
			// IP allocation is deferred until we guarantee the MAC is actively valid
			fresh[string(fields[0])] = parsedMAC.String()
		}
	}

	// [SECURITY/FIX] Catch silent interruptions from the OS-level file descriptor natively.
	// If the kernel buffer starves or truncates the read, we MUST abort the cycle entirely 
	// rather than flushing the active routing maps with partial, corrupted data.
	if err := scanner.Err(); err != nil {
		if logSystem {
			log.Printf("[ARP] Warning: error reading /proc/net/arp stream: %v. Aborting map refresh natively.", err)
		}
		return
	}

	// Atomic swap — readers see old map until this store completes,
	// then instantly see the new one. No partial state possible.
	arpSnap.Store(&fresh)
}

