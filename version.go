/*
File:    version.go
Version: v1.269.0
Updated: 07-May-2026 13:23 CEST

Description:
  Global version, build time, and build number constants for sdproxy.
  These variables can be overridden at link time using the Go linker flags:
  e.g., -ldflags "-X main.BuildVersion=v1.269.0 -X 'main.BuildTime=...'"

Changes:
  1.269.0 - [FIX] Resolved build compilation errors caused by duplicate method 
            declarations (`exchangeHTTP`). Accurately routed the payload truncation 
            and HTTP GET URI fixes natively into their correct structural 
            file (`upstream_net.go`).
  1.268.0 - [SECURITY/FIX] Remediated a severe False-Positive Payload Truncation regression 
            in the outbound HTTP exchange network layer. 64KB responses are now correctly 
            absorbed natively without triggering memory boundary alerts.
          - [FIX] Hardened DoH GET query construction to cleanly evaluate existing URI parameters 
            before appending encoded payloads.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	// It is used in boot logs and the Web UI dashboards.
	BuildVersion string = "v1.269.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "07-May-2026 13:23 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "324"
)

