// File: arp_stub.go
// Version: 1.0.0
// Last Updated: 2026-03-01 15:00 CET
// Description: No-op stubs for InitARP and LookupMAC on non-Linux platforms.
//              arp.go uses /proc/net/arp which is Linux-only. On other platforms
//              (macOS for dev builds, BSDs, etc.) ARP resolution is simply skipped —
//              identity fallback via IP->name from /etc/hosts still works fine.
//
// Changes:
//   1.0.0 - Initial stub to satisfy the compiler when arp.go is excluded by build tags.

//go:build !linux

package main

// InitARP is a no-op on non-Linux platforms.
// MAC-based routing and {client-name} resolution via MAC are unavailable,
// but IP-based identity (hosts files, leases) and all upstream routing still work.
func InitARP() {}

// LookupMAC always returns "" on non-Linux platforms.
// process.go gracefully falls through to IP-based identity resolution when MAC is empty.
func LookupMAC(_ string) string { return "" }

