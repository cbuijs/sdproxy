// File: arp_stub.go
// Version: 1.1.0
// Last Updated: 08-Jul-2026 09:25 CEST
// Description: No-op stubs for InitARP and LookupMAC on non-Linux platforms.
//              arp.go uses /proc/net/arp which is Linux-only. On other platforms
//              (macOS for dev builds, BSDs, etc.) ARP resolution is simply skipped —
//              identity fallback via IP->name from /etc/hosts still works fine.
//
// Changes:
//   1.1.0 - [FIX] Exported `arpSnap` dummy pointer to prevent compilation failures 
//           within `webui_api.go` when evaluating network identities on non-Linux OSs.
//   1.0.0 - Initial stub to satisfy the compiler when arp.go is excluded by build tags.

//go:build !linux

package main

import "sync/atomic"

// arpSnap holds a dummy IP->MAC table to satisfy the compiler on non-Linux 
// platforms when the Web UI attempts to harvest known physical identities natively.
var arpSnap atomic.Pointer[map[string]string]

func init() {
	m := make(map[string]string)
	arpSnap.Store(&m)
}

// InitARP is a no-op on non-Linux platforms.
// MAC-based routing and {client-name} resolution via MAC are unavailable,
// but IP-based identity (hosts files, leases) and all upstream routing still work.
func InitARP() {}

// LookupMAC always returns "" on non-Linux platforms.
// process.go gracefully falls through to IP-based identity resolution when MAC is empty.
func LookupMAC(_ string) string { return "" }

