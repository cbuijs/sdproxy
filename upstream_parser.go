/*
File:    upstream_parser.go
Version: 2.55.0
Last Updated: 10-Nov-2026 11:45 CET

Description:
  Configuration parsing, initialization, and client allocation for sdproxy upstreams.
  Extracted from upstream.go to cleanly separate boot-time instantiation from 
  the hot-path routing execution pipeline.

Changes:
  2.55.0 - [FEAT] Initialized an HTTP/2 fallback client (`h2Client` / `h2ClientNoECH`)
           on `doh3://` upstreams and tracked standard DoH availability (`u.dohAvailable`)
           via SVCB/HTTPS ALPN (`h2` / `http/1.1`) discovery and runtime probes so
           `doh3://` upstreams can downgrade and stick to standard DoH when
           `doh3_fallback_threshold` is reached and DoH is available on the same server.
  2.54.0 - [CRITICAL/FIX] Configured explicit `ReadIdleTimeout: 10 * time.Second`
           and `PingTimeout: 5 * time.Second` on `golang.org/x/net/http2.Transport`
           for all DoH (`h2Client` and `h2ClientNoECH`) transports.
  2.53.0 - [SECURITY/FEAT] Initialized a cryptographically random 64-bit RFC 7873
           `clientCookieHex` and `streamConns` pool on `udp://` upstreams.
  2.52.0 - [FIX] Enabled invalid manual ECH base64 warning in `ParseUpstream` when
           `logSystem` or `logTLS` is active.
  2.51.0 - [SECURITY/FIX] Fixed broken ECH injection on `h3Client` (DoH3 and upgraded DoH).
  2.50.0 - [BUG/FIX] Corrected `quic.EarlyConnection` to `*quic.Conn` for all `http3.Transport.Dial`
           implementations.
  2.49.0 - [BUG/FIX] Corrected parameter usage when instantiating `quic.DialAddrEarly`.
  2.48.0 - [CLEANUP] Abstracted the ECH `base64` fallback decoding sequence natively 
           into `decodeBase64Flex()`.
  2.47.0 - [FEAT] Implemented robust extraction bounds for `?echdomain=`.
  2.46.0 - [SECURITY/FIX] Eradicated a Bootstrap Resolution Bypass vulnerability.
*/

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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
	"golang.org/x/net/http2"
)

// ---------------------------------------------------------------------------
// Initialization & Parsing
// ---------------------------------------------------------------------------

func decodeBase64Flex(s string) ([]byte, error) {
	if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.URLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	if d, err := base64.StdEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func stripMethodModifier(url string) (stripped string, useGET bool) {
	lower := strings.ToLower(url)
	switch {
	case strings.HasSuffix(lower, "+get"):
		return url[:len(url)-4], true
	case strings.HasSuffix(lower, "+post"):
		return url[:len(url)-5], false
	default:
		return url, false
	}
}

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

func configureHTTP2HealthChecks(tr *http.Transport) {
	if tr == nil {
		return
	}
	if h2Tr, err := http2.ConfigureTransports(tr); err == nil && h2Tr != nil {
		h2Tr.ReadIdleTimeout = 10 * time.Second
		h2Tr.PingTimeout = 5 * time.Second
	}
}

func newDoHHTTP2Client(u *Upstream) *http.Client {
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 15 * time.Second,
	}

	h2Tr := &http.Transport{
		TLSClientConfig:       getHardenedTLSConfig(),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       30 * time.Second,
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
	}
	configureHTTP2HealthChecks(h2Tr)
	return &http.Client{Transport: h2Tr}
}

func ParseUpstream(raw string, bootstrapNodes []*Upstream) (*Upstream, error) {
	u := &Upstream{}

	parts := strings.Split(raw, "#")
	urlPart := parts[0]

	var echBase64, echDomain string

	if idx := strings.Index(urlPart, "echdomain="); idx >= 0 {
		end := strings.IndexAny(urlPart[idx:], "&")
		if end < 0 {
			echDomain = urlPart[idx+10:]
			urlPart = urlPart[:idx]
		} else {
			echDomain = urlPart[idx+10 : idx+end]
			urlPart = urlPart[:idx] + urlPart[idx+end+1:]
		}
		urlPart = strings.TrimRight(urlPart, "?&")
	}

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

	u.echDomain = echDomain
	useECH := cfg.Server.UseUpstreamECH
	if useECH == "" {
		useECH = "disable"
	}

	if echBase64 != "" {
		if useECH == "disable" {
			if logTLS {
				log.Printf("[TLS] [ECH] Upstream %s: ECH is explicitly disabled globally ('use_upstream_ech: disable'), ignoring manual URL config", urlPart)
			}
		} else {
			decoded, err := decodeBase64Flex(echBase64)
			if err == nil {
				u.ECHConfigList = decoded
				if logTLS {
					log.Printf("[TLS] [ECH] Upstream %s: Loaded manual ECH config via URL parameter (%d bytes)", urlPart, len(decoded))
				}
			} else if logTLS || logSystem {
				log.Printf("[TLS] [ECH] Upstream %s: WARNING - Invalid manual ECH base64 string: %v", urlPart, err)
			}
		}
	}

	if len(parts) > 1 && parts[1] != "" {
		rawIPs := strings.Split(parts[1], ",")
		for _, rip := range rawIPs {
			rip = strings.TrimSpace(rip)
			if addr, err := netip.ParseAddr(rip); err == nil {
				if ipVersionSupport == "ipv4" && !addr.Is4() {
					continue
				}
				if ipVersionSupport == "ipv6" && !addr.Is6() {
					continue
				}
				u.BootstrapIPs = append(u.BootstrapIPs, rip)
			} else {
				if logSystem {
					log.Printf("[WARN] Invalid bootstrap IP %q ignored for upstream %s", rip, urlPart)
				}
			}
		}
	}

	u.hasClientNameTemplate = strings.Contains(urlPart, "{client-name}")

	switch {
	case strings.HasPrefix(urlPart, "udp://"):
		u.Proto = "udp"
		u.RawURL = strings.TrimPrefix(urlPart, "udp://")
		u.udpClient = &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		u.streamConns = make(map[string][]*streamConnEntry)
		var cookieBytes [8]byte
		_, _ = rand.Read(cookieBytes[:])
		u.clientCookieHex = hex.EncodeToString(cookieBytes[:])

	case strings.HasPrefix(urlPart, "tcp://"):
		u.Proto = "tcp"
		u.RawURL = strings.TrimPrefix(urlPart, "tcp://")
		u.streamConns = make(map[string][]*streamConnEntry)

	case strings.HasPrefix(urlPart, "dot://"), strings.HasPrefix(urlPart, "tls://"):
		u.Proto = "dot"
		u.RawURL = strings.TrimPrefix(strings.TrimPrefix(urlPart, "dot://"), "tls://")
		u.baseTLSConf = getHardenedTLSConfig()
		u.baseTLSConf.NextProtos = []string{"dot"}
		u.streamConns = make(map[string][]*streamConnEntry)

	case strings.HasPrefix(urlPart, "doh://"), strings.HasPrefix(urlPart, "https://"):
		u.Proto = "doh"
		urlPart, u.useGET = stripMethodModifier(urlPart)
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh://"), "https://")
		u.RawURL = stripDefaultHTTPSPort(u.RawURL)
		u.dohAvailable.Store(true)
		u.h2Client = newDoHHTTP2Client(u)

		if cfg.Server.UpgradeDoH3 {
			u.h3Client = &http.Client{
				Transport: &http3.Transport{
					TLSClientConfig:    getHardenedTLSConfig(),
					DisableCompression: true,
					QUICConfig: &quic.Config{
						HandshakeIdleTimeout: 3 * time.Second,
						MaxIdleTimeout:       30 * time.Second,
						KeepAlivePeriod:      15 * time.Second,
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
		u.RawURL = stripDefaultHTTPSPort(u.RawURL)
		u.h2Client = newDoHHTTP2Client(u)

		u.h3Client = &http.Client{
			Transport: &http3.Transport{
				TLSClientConfig:    getHardenedTLSConfig(),
				DisableCompression: true,
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 3 * time.Second,
					MaxIdleTimeout:       30 * time.Second,
					KeepAlivePeriod:      15 * time.Second,
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
		u.Proto = "doq"
		u.RawURL = strings.TrimPrefix(urlPart, "doq://")
		u.doqConns = make(map[string]*doqConnEntry)
		u.baseTLSConf = getHardenedTLSConfig()
		u.baseTLSConf.NextProtos = []string{"doq"}

	default:
		return nil, fmt.Errorf("unsupported upstream scheme in %q", raw)
	}

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
	var nativeH2 bool

	needsDDR := false
	if (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0 {
		needsDDR = true
	}
	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load() {
		needsDDR = true
	}
	if u.Proto == "doh3" && !u.dohAvailable.Load() {
		needsDDR = true
	}

	if needsDDR && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		if logDDR {
			log.Printf("[DDR] Upstream %s: Attempting discovery for ECH, IP hints, and ALPN...", resolveHost)
		}
		if resolveHost != "" && len(bootstrapNodes) > 0 {
			echConfig, hIPs, h3Supported, h2Supported := bootstrapResolveECH(resolveHost, u.echDomain, bootstrapNodes)
			if len(echConfig) > 0 && len(u.ECHConfigList) == 0 && useECH != "disable" {
				u.ECHConfigList = echConfig
				if logDDR {
					log.Printf("[DDR] Upstream %s: Extracted ECH config (%d bytes) via native UDP HTTPS record", resolveHost, len(echConfig))
				}
			}

			if len(u.BootstrapIPs) == 0 && len(hIPs) > 0 {
				hintedIPs = hIPs
				if logDDR {
					log.Printf("[DDR] Upstream %s: Discovered %d IP hint(s) via HTTPS/SVCB record: %v", resolveHost, len(hIPs), hIPs)
				}
			}

			if h3Supported {
				nativeH3 = true
			}
			if h2Supported {
				nativeH2 = true
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
		} else if len(bootstrapNodes) > 0 {
			ips = bootstrapResolve(resolveHost, bootstrapNodes)
		}

		if len(ips) > 0 {
			u.BootstrapIPs = ips

			if len(hintedIPs) == 0 {
				if logSystem {
					log.Printf("[INIT] Bootstrap: %s -> %v", resolveHost, ips)
				}
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
			if logSystem {
				log.Printf("[WARN] Bootstrap: could not resolve %s — OS resolver will be used at dial time", resolveHost)
			}
		}
	}

	needsDirectDDR := false
	if (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0 {
		needsDirectDDR = true
	}
	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !nativeH3 {
		needsDirectDDR = true
	}
	if u.Proto == "doh3" && !nativeH2 {
		needsDirectDDR = true
	}

	if needsDirectDDR && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		if resolveHost != "" && (len(u.dialAddrs) > 0 || len(u.BootstrapIPs) > 0) {
			echBytes, h3Supported, h2Supported := fetchDDRParams(u, resolveHost, u.echDomain)
			if len(echBytes) > 0 && len(u.ECHConfigList) == 0 && useECH != "disable" {
				u.ECHConfigList = echBytes
				if logDDR {
					log.Printf("[DDR] Upstream %s: Successfully secured ECH config (%d bytes)", resolveHost, len(echBytes))
				}
			}
			if h3Supported {
				nativeH3 = true
			}
			if h2Supported {
				nativeH2 = true
			}
		}
	}

	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && nativeH3 && !u.h3Upgraded.Load() {
		u.h3Upgraded.Store(true)
		if logTLS {
			log.Printf("[TLS] [UPGRADE] Upstream %s: Proactively upgraded DoH to DoH3 (QUIC) based on SVCB/HTTPS ALPN discovery natively.", resolveHost)
		}
	}

	if u.Proto == "doh3" && nativeH2 {
		u.dohAvailable.Store(true)
		if logTLS {
			log.Printf("[TLS] [DOWNGRADE] Upstream %s: Verified standard DoH (HTTP/2) availability on same server via SVCB/HTTPS ALPN.", resolveHost)
		}
	}

	if useECH == "strict" && len(u.ECHConfigList) == 0 && (u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq") {
		return nil, fmt.Errorf("upstream %s: strict ECH enforced but no ECH config could be discovered", u.RawURL)
	}

	if len(u.ECHConfigList) > 0 {
		if logTLS {
			log.Printf("[TLS] [ECH] Upstream %s: TLS Transport strictly enforcing Encrypted Client Hello (Requires TLS 1.3+)", resolveHost)
		}

		if useECH == "try" {
			if u.baseTLSConf != nil {
				u.baseTLSConfNoECH = u.baseTLSConf.Clone()
			}
			if u.h2Client != nil {
				tr := u.h2Client.Transport.(*http.Transport).Clone()
				configureHTTP2HealthChecks(tr)
				u.h2ClientNoECH = &http.Client{Transport: tr}
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
