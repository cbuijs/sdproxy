/*
File: identity.go
Version: 1.13.1
Last Updated: 2026-02-27 21:30 CET
Description: Parses standard /etc/hosts and dnsmasq lease files periodically 
             to extract human-readable hostnames for {client-name} substitution.
             TRUNCATES domain names to only cache the short hostname (e.g., host.lan -> host).
*/

package main

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// Thread-safe map for dynamic names extracted from files
	ipNameMap  sync.Map
	macNameMap sync.Map
)

func InitIdentity() {
	if len(cfg.Identity.HostsFiles) == 0 && len(cfg.Identity.DnsmasqLeases) == 0 {
		return
	}

	go func() {
		pollIdentity() // Initial run
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			pollIdentity()
		}
	}()
}

func LookupNameByIP(ip string) (string, bool) {
	if val, ok := ipNameMap.Load(ip); ok {
		return val.(string), true
	}
	return "", false
}

func LookupNameByMAC(mac string) (string, bool) {
	if val, ok := macNameMap.Load(mac); ok {
		return val.(string), true
	}
	return "", false
}

func pollIdentity() {
	for _, path := range cfg.Identity.HostsFiles {
		parseHostsFile(path)
	}
	for _, path := range cfg.Identity.DnsmasqLeases {
		parseLeasesFile(path)
	}
}

// parseHostsFile reads a standard /etc/hosts file format (IP Hostname Aliases...)
func parseHostsFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			ip := fields[0]
			rawName := fields[1]
			
			// Extract short hostname (strip domain)
			shortName := strings.Split(rawName, ".")[0]
			
			ipNameMap.Store(ip, shortName)
		}
	}
}

// parseLeasesFile reads a standard dnsmasq leases file format
// Format: ExpiryTime MAC_Address IP_Address Hostname Client_ID
func parseLeasesFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		
		if len(fields) >= 4 {
			macStr := fields[1]
			ipStr := fields[2]
			rawName := fields[3]

			if rawName != "*" && rawName != "" {
				// Extract short hostname (strip domain)
				shortName := strings.Split(rawName, ".")[0]

				ipNameMap.Store(ipStr, shortName)

				// Normalize MAC for reliable lookup mapping
				if parsedMAC, err := net.ParseMAC(macStr); err == nil {
					macNameMap.Store(parsedMAC.String(), shortName)
				}
			}
		}
	}
}

