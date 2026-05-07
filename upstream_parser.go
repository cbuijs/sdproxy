/*
File:    upstream_parser.go
Version: 2.41.0
Updated: 04-May-2026 22:02 CEST

Description:
  Configuration parsing, initialization, and client allocation for sdproxy upstreams.
  Extracted from upstream.go to cleanly separate boot-time instantiation from 
  the hot-path routing execution pipeline.

Changes:
  2.41.0 - [SECURITY/FIX] Addressed an HTTP/3 (QUIC) stream rejection anomaly (H3 error 0x5) 
           by proactively stripping redundant default ports (`:443`) from DoH/DoH3 target URLs. 
           This correctly aligns the `:authority` pseudo-header with RFC 9114 specifications, 
           preventing strict upstreams from severing the connection natively.
  2.40.0 - [FIX] Liberated DoH and DoH3 HTTP clients from rigid hardcoded timeouts 
           (`Timeout: 5 * time.Second`). Client execution deadlines are now 
           strictly and robustly governed natively by the overarching `context.Context` 
           injected via `ExchangeContext`, which accurately honors the user-configured 
           `upstream_timeout_ms` boundary without artificially severing the connection.
  2.39.0 - [SECURITY/FIX] Resolved a structural routing defect in `stripMethodModifier`. 
           The function erroneously utilized `strings.HasPrefix` instead of `strings.HasSuffix` 
           when evaluating `+get` and `+post` parameters. This physically broke all DNS-over-HTTPS 
           `GET` integrations natively since the evaluated string always commenced with the `doh://` schema.
  2.38.0 - [FIX] Hardened Encrypted Client Hello (ECH) base64 parsing to natively 
           accept padded standard/URL-encoded payloads, preventing rejection of 
           valid third-party ECH configurations.
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ---------------------------------------------------------------------------
// Initialization & Parsing
// ---------------------------------------------------------------------------

// stripMethodModifier checks whether a DoH/DoH3 URL path (before any # fragment)
// ends with +get or +post (case-insensitive). Returns the stripped URL and whether
// GET was requested. Default (no modifier) → POST (false).
func stripMethodModifier(url string) (stripped string, useGET bool) {
	lower := strings.ToLower(url)
	switch {
	// [SECURITY/FIX] Validate suffix rather than prefix to securely evaluate
	// query directives appended AFTER the schema and FQDN.
	case strings.HasSuffix(lower, "+get"):
		return url[:len(url)-4], true
	case strings.HasSuffix(lower, "+post"):
		return url[:len(url)-5], false
	default:
		return url, false
	}
}

// stripDefaultHTTPSPort removes the redundant :443 port from the host part of an HTTPS URL.
// In HTTP/2 and HTTP/3, sending the default port in the :authority pseudo-header 
// can cause strict servers to reject the request stream natively.
func stripDefaultHTTPSPort(rawURL string) string {
	if !strings.HasPrefix(rawURL, "https://") {
		return rawURL
	}
	pathIdx := strings.IndexByte(rawURL[8:], '/')
	if pathIdx >= 0 {
		hostPart := rawURL[8 : 8+pathIdx]
		if strings.HasSuffix(hostPart, ":443") {
			hostPart = strings.TrimSuffix(hostPart, ":443")
			return "https://" + hostPart + rawURL[8+pathIdx:]
		}
	} else {
		if strings.HasSuffix(rawURL, ":443") {
			return strings.TrimSuffix(rawURL, ":443")
		}
	}
	return rawURL
}

// ParseUpstream parses a raw upstream URL string into an initialised Upstream.
func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts   := strings.Split(raw, "#")
	urlPart := parts[0]
	
	// Extract manual Encrypted Client Hello (ECH) parameters from the URL
	var echBase64 string
	if idx := strings.Index(urlPart, "ech="); idx >= 0 {
		end := strings.IndexAny(urlPart[idx:], "&")
		if end < 0 {
			echBase64 = urlPart[idx+4:]
			urlPart = urlPart[:idx]
		} else {
			echBase64 = urlPart[idx+4 : idx+end]
			urlPart = urlPart[:idx] + urlPart[idx+end+1:]
		}
		urlPart = strings.TrimRight(urlPart, "?&")
	}

	useECH := cfg.Server.UseUpstreamECH
	if useECH == "" {
		useECH = "disable"
	}

	if echBase64 != "" {
		if useECH == "disable" {
			log.Printf("[ECH] Upstream %s: ECH is explicitly disabled globally ('use_upstream_ech: disable'), ignoring manual URL config", urlPart)
		} else {
			// [FIX] Implement multi-encoding checks to seamlessly parse both padded and 
			// unpadded ECH payloads natively, ensuring broad upstream compatibility.
			decoded, err := base64.RawURLEncoding.DecodeString(echBase64)
			if err != nil {
				decoded, err = base64.URLEncoding.DecodeString(echBase64)
				if err != nil {
					decoded, err = base64.StdEncoding.DecodeString(echBase64)
				}
			}
			
			if err == nil {
				u.ECHConfigList = decoded
				log.Printf("[ECH] Upstream %s: Loaded manual ECH config via URL parameter (%d bytes)", urlPart, len(decoded))
			} else {
				log.Printf("[ECH] Upstream %s: WARNING - Invalid manual ECH base64 string: %v", urlPart, err)
			}
		}
	}

	if len(parts) > 1 && parts[1] != "" {
		rawIPs := strings.Split(parts[1], ",")
		// [FEAT] IP Version Support Enforcement for Bootstrap IPs
		if ipVersionSupport == "both" {
			u.BootstrapIPs = rawIPs
		} else {
			for _, rip := range rawIPs {
				if addr, err := netip.ParseAddr(rip); err == nil {
					if ipVersionSupport == "ipv4" && !addr.Is4() { continue }
					if ipVersionSupport == "ipv6" && !addr.Is6() { continue }
					u.BootstrapIPs = append(u.BootstrapIPs, rip)
				}
			}
		}
	}

	u.hasClientNameTemplate = strings.Contains(urlPart, "{client-name}")

	switch {
	case strings.HasPrefix(urlPart, "udp://"):
		u.Proto     = "udp"
		u.RawURL    = strings.TrimPrefix(urlPart, "udp://")
		u.udpClient = &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	case strings.HasPrefix(urlPart, "tcp://"):
		u.Proto       = "tcp"
		u.RawURL      = strings.TrimPrefix(urlPart, "tcp://")
		u.streamConns = make(map[string][]*streamConnEntry)

	case strings.HasPrefix(urlPart, "dot://"), strings.HasPrefix(urlPart, "tls://"):
		u.Proto       = "dot"
		u.RawURL      = strings.TrimPrefix(strings.TrimPrefix(urlPart, "dot://"), "tls://")
		u.baseTLSConf = getHardenedTLSConfig()
		u.baseTLSConf.NextProtos = []string{"dot"}
		u.streamConns = make(map[string][]*streamConnEntry)

	case strings.HasPrefix(urlPart, "doh://"), strings.HasPrefix(urlPart, "https://"):
		u.Proto = "doh"
		urlPart, u.useGET = stripMethodModifier(urlPart)
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh://"), "https://")
		u.RawURL = stripDefaultHTTPSPort(u.RawURL) // [SECURITY/FIX] Normalize :authority
		dialer  := &net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		
		// [PERF/FIX] Removed rigid 5-second `Timeout` definitions across HTTP clients.
		// Execution deadlines are now natively supervised by the dynamic `context.Context` 
		// passed down during active queries, faithfully enforcing `upstream_timeout_ms` 
		// limits without artificial severances.
		u.h2Client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:       getHardenedTLSConfig(),
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				IdleConnTimeout:       5 * time.Second,
				TLSHandshakeTimeout:   3 * time.Second,
				ResponseHeaderTimeout: 3 * time.Second,
				DisableCompression:    true,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
							if err == nil {
								return conn, nil
							}
						}
					}
					return dialer.DialContext(ctx, network, addr)
				},
			},
		}

		if cfg.Server.UpgradeDoH3 {
			u.h3Client = &http.Client{
				Transport: &http3.Transport{
					TLSClientConfig:    getHardenedTLSConfig(),
					DisableCompression: true,
					QUICConfig: &quic.Config{
						HandshakeIdleTimeout: 3 * time.Second,
					},
					Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
						if len(u.BootstrapIPs) > 0 {
							_, port, _ := net.SplitHostPort(addr)
							for _, ip := range u.BootstrapIPs {
								conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, port), tlsCfg, qCfg)
								if err == nil {
									return conn, nil
								}
							}
						}
						return quic.DialAddrEarly(ctx, addr, tlsCfg, qCfg)
					},
				},
			}
		}

	case strings.HasPrefix(urlPart, "doh3://"):
		u.Proto = "doh3"
		urlPart, u.useGET = stripMethodModifier(urlPart)
		u.RawURL = "https://" + strings.TrimPrefix(urlPart, "doh3://")
		u.RawURL = stripDefaultHTTPSPort(u.RawURL) // [SECURITY/FIX] Normalize :authority
		
		// [PERF/FIX] Removed rigid 5-second `Timeout` definitions. 
		// Context natively enforces boundaries based on the unified pipeline thresholds.
		u.h3Client = &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig:    getHardenedTLSConfig(),
				DisableCompression: true,
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 3 * time.Second,
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, port), tlsCfg, qCfg)
							if err == nil {
								return conn, nil
							}
						}
					}
					return quic.DialAddrEarly(ctx, addr, tlsCfg, qCfg)
				},
			},
		}

	case strings.HasPrefix(urlPart, "doq://"):
		u.Proto       = "doq"
		u.RawURL      = strings.TrimPrefix(urlPart, "doq://")
		u.doqConns    = make(map[string]*doqConnEntry)
		u.baseTLSConf = getHardenedTLSConfig()
		u.baseTLSConf.NextProtos = []string{"doq"}

	default:
		return nil, fmt.Errorf("unsupported upstream scheme in %q", raw)
	}

	// Resolve dialHost / dialAddrs for address-based protocols.
	switch u.Proto {
	case "udp", "tcp", "dot", "doq":
		host, port := parseHostPort(u.RawURL, u.Proto)
		if net.ParseIP(host) == nil {
			u.dialHost = host
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if ipVersionSupport == "ipv4" && !addr.Is4() {
				return nil, fmt.Errorf("upstream %s is IPv6 but support_ip_version is 'ipv4'", host)
			}
			if ipVersionSupport == "ipv6" && !addr.Is6() {
				return nil, fmt.Errorf("upstream %s is IPv4 but support_ip_version is 'ipv6'", host)
			}
		}
		u.dialAddrs = []string{net.JoinHostPort(host, port)}
	}

	// Evaluate the core hostname for DNS bootstrapping (IPs and ECH configurations)
	var resolveHost string
	switch u.Proto {
	case "udp", "tcp", "dot", "doq":
		if net.ParseIP(u.dialHost) == nil {
			resolveHost = strings.ReplaceAll(u.dialHost, "{client-name}", "bootstrap")
		}
	case "doh", "doh3":
		rest := strings.TrimPrefix(u.RawURL, "https://")
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			rest = rest[:idx]
		}
		if h, _, err := net.SplitHostPort(rest); err == nil {
			rest = h
		}
		if net.ParseIP(rest) == nil {
			resolveHost = strings.ReplaceAll(rest, "{client-name}", "bootstrap")
		}
	}

	var hintedIPs []string
	var nativeH3 bool

	needsDDR := false
	if (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0 {
		needsDDR = true
	}
	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load() {
		needsDDR = true
	}

	// Bootstrap DDR Params implicitly if not manually defined by the user
	if needsDDR && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		log.Printf("[DDR] Upstream %s: Attempting discovery for ECH, IP hints, and ALPN...", resolveHost)
		if resolveHost != "" && len(globalBootstrapServers) > 0 {
			echConfig, hIPs, h3Supported := bootstrapResolveECH(resolveHost, globalBootstrapServers)
			if len(echConfig) > 0 && len(u.ECHConfigList) == 0 {
				u.ECHConfigList = echConfig
				log.Printf("[DDR] Upstream %s: Extracted ECH config (%d bytes) via native UDP HTTPS record", resolveHost, len(echConfig))
			}
			
			if len(u.BootstrapIPs) == 0 && len(hIPs) > 0 {
				hintedIPs = hIPs
				log.Printf("[DDR] Upstream %s: Discovered %d IP hint(s) via HTTPS/SVCB record: %v", resolveHost, len(hIPs), hIPs)
			}

			if h3Supported {
				nativeH3 = true
			}
		}
	}

	if len(u.BootstrapIPs) > 0 {
		switch u.Proto {
		case "udp", "tcp", "dot", "doq":
			_, port := parseHostPort(u.RawURL, u.Proto)
			u.dialAddrs = make([]string, len(u.BootstrapIPs))
			for i, ip := range u.BootstrapIPs {
				u.dialAddrs[i] = net.JoinHostPort(ip, port)
			}
		}
	} else if resolveHost != "" {
		var ips []string
		
		if len(hintedIPs) > 0 {
			ips = hintedIPs
		} else if len(globalBootstrapServers) > 0 {
			ips = bootstrapResolve(resolveHost, globalBootstrapServers)
		}
		
		if len(ips) > 0 {
			u.BootstrapIPs = ips
			
			if len(hintedIPs) == 0 {
				log.Printf("[INIT] Bootstrap: %s -> %v", resolveHost, ips)
			}
			
			if u.dialHost != "" {
				_, port := parseHostPort(u.RawURL, u.Proto)
				u.dialAddrs = make([]string, len(ips))
				for i, ip := range ips {
					u.dialAddrs[i] = net.JoinHostPort(ip, port)
				}
			}
		} else {
			if u.dialHost != "" && strings.Contains(u.dialHost, "{client-name}") {
				_, port := parseHostPort(u.RawURL, u.Proto)
				u.dialAddrs = []string{net.JoinHostPort(resolveHost, port)}
			}
			log.Printf("[WARN] Bootstrap: could not resolve %s — OS resolver will be used at dial time", resolveHost)
		}
	}

	if needsDDR && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		if resolveHost != "" && (len(u.dialAddrs) > 0 || len(u.BootstrapIPs) > 0) {
			echBytes, h3Supported := fetchDDRParams(u, resolveHost)
			if len(echBytes) > 0 && len(u.ECHConfigList) == 0 {
				u.ECHConfigList = echBytes
				log.Printf("[DDR] Upstream %s: Successfully secured ECH config (%d bytes)", resolveHost, len(echBytes))
			}
			if h3Supported {
				nativeH3 = true
			}
		}
	}

	// Proactive DoH3 Upgrade based on SVCB ALPN discovery
	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && nativeH3 && !u.h3Upgraded.Load() {
		u.h3Upgraded.Store(true)
		log.Printf("[UPGRADE] Upstream %s: Proactively upgraded DoH to DoH3 (QUIC) based on SVCB/HTTPS ALPN discovery natively.", resolveHost)
	}

	// STRICT Mode Check
	if useECH == "strict" && len(u.ECHConfigList) == 0 && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		return nil, fmt.Errorf("upstream %s: strict ECH enforced but no ECH config could be discovered", u.RawURL)
	}

	// Inject the finalized ECH settings into the active Transport payloads
	if len(u.ECHConfigList) > 0 {
		log.Printf("[ECH] Upstream %s: TLS Transport strictly enforcing Encrypted Client Hello (Requires TLS 1.3+)", resolveHost)
		
		if useECH == "try" {
			if u.baseTLSConf != nil {
				u.baseTLSConfNoECH = u.baseTLSConf.Clone()
			}
			if u.h2Client != nil {
				tr := u.h2Client.Transport.(*http.Transport).Clone()
				u.h2ClientNoECH = &http.Client{Transport: tr} // Respect context deadlines securely
			}
			if u.h3Client != nil {
				origTr := u.h3Client.Transport.(*http3.Transport)
				qCfg := *origTr.QUICConfig 
				u.h3ClientNoECH = &http.Client{
					Transport: &http3.Transport{
						TLSClientConfig:    origTr.TLSClientConfig.Clone(),
						DisableCompression: origTr.DisableCompression,
						QUICConfig:         &qCfg,
						Dial:               origTr.Dial,
					},
				}
			}
		}

		if u.baseTLSConf != nil {
			u.baseTLSConf.EncryptedClientHelloConfigList = u.ECHConfigList
			u.baseTLSConf.MinVersion = tls.VersionTLS13
		}
		if u.h2Client != nil {
			if tr, ok := u.h2Client.Transport.(*http.Transport); ok {
				tr.TLSClientConfig.EncryptedClientHelloConfigList = u.ECHConfigList
				tr.TLSClientConfig.MinVersion = tls.VersionTLS13
			}
		}
		if u.h3Client != nil {
			if tr, ok := u.h3Client.Transport.(*http3.Transport); ok {
				tr.TLSClientConfig.EncryptedClientHelloConfigList = u.ECHConfigList
				tr.TLSClientConfig.MinVersion = tls.VersionTLS13
			}
		}
	}

	return u, nil
}

