/*
File:    version.go
Version: 1.454.0
Last Updated: 17-Aug-2026 19:06 CEST
Description:
  Global version, build time, and build number constants for sdproxy.

Changes:
  1.454.0 - [SECURITY/FIX] Eradicated a critical Initialization Deadlock natively.
            Moved `InitThrottle()` prior to executing `initUpstreams()` and bootstrap
            parsing operations within `main.go`. Previously, the adaptive admission 
            throttler initialized its atomic `upstreamLimit` to `0` until late in the 
            boot cycle. This forced `AcquireUpstream()` to instantly reject and 
            strangle all DNS-over-HTTPS (DoH), DoH3, and DDR (Discovery of Designated 
            Resolvers) bootstrap queries, permanently degrading encrypted transport 
            initialization at startup.
  1.453.0 - [SECURITY/FIX] Swept and eradicated Blind Map Eviction vulnerabilities 
            across all dynamically bounded arrays natively (Exfiltration, Search Domain 
            Leak Prevention, Parental Tracking, and Last-Seen telemetries).
            Replaced randomized iteration deletion with Power-of-N-Choices sampled 
            eviction. This neutralizes algorithmic attack vectors where attackers 
            could purposefully induce OOM HashDoS ceilings to seamlessly launder 
            penalty strikes or scrub tracked residential clients from existence.
  1.452.0 - [PERF] Eradicated `sync.Map` boxing allocations across Rate Limiting 
            and Exfiltration hot paths. Replaced the generic lock-free sync maps 
            with dedicated 256-shard `sync.RWMutex` arrays. Completely eliminates 
            the 24-byte `netip.Addr` heap allocations required for struct-to-interface 
            conversion, massively reducing Garbage Collection (GC) bottlenecks during 
            severe volumetric DDoS traffic.
*/

package main

var (
	// BuildVersion represents the current release/build version of sdproxy.
	BuildVersion string = "v1.454.0"

	// BuildTime records the date and time the binary was compiled.
	BuildTime string = "17-Aug-2026 19:06 CEST"

	// BuildNumber is an internal sequential build tracker or CI pipeline number.
	BuildNumber string = "513"
)

