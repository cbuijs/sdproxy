/*
File:    upstream_parser.go
Version: 2.60.0
Last Updated: 24-Nov-2026 14:30 CET

Description:
  Configuration parsing, initialization, and client allocation for sdproxy upstreams.

Changes:
  2.60.0 - [CRITICAL/SECURITY] Prevented `newDoHHTTP2Client` and `newDoHHTTP3Client`
           from falling through to OS DNS resolution when explicit `BootstrapIPs`
           are configured and all bootstrap dials fail, eliminating self-query
           loopback deadlocks, plaintext DNS leaks, and uncancelable
           `net.ResolveUDPAddr` blocks in QUIC.
         - [SECURITY/FIX] Scoped `ech=` and `echdomain=` URL parameter extraction
           strictly to `?`/`&` query tokens (preventing substring collisions such
           as `?tech=`), supported `+get`/`+post` before query parameters, and
           validated manual `ECHConfigList` blobs via `extractECHConfigs`.
  2.59.0 - [SECURITY/FIX] Populated `u.BootstrapIPs` on literal-IP `doh://` and
           `doh3://` upstream URLs and validated IPv4/IPv6 compatibility.
  2.58.0 - [FEAT/FIX] Extracted `newDoHHTTP3Client(u)` and routed HTTP/3 QUIC dials
           through `u.dialQUIC`.
  2.57.0 - [FEAT/FIX] Extended direct-first ECH/ALPN discovery to literal-IP URLs.
  2.56.0 - [FEAT/SECURITY] Reordered ECH/DDR/ALPN discovery in `ParseUpstream`.
  2.55.0 - [FEAT] Initialized an HTTP/2 fallback client on `doh3://` upstreams.
  2.54.0 - [CRITICAL/FIX] Configured `ReadIdleTimeout` and `PingTimeout` on HTTP/2.
  2.53.0 - [SECURITY/FEAT] Initialized random 64-bit RFC 7873 `clientCookieHex`.
  2.52.0 - [FIX] Enabled invalid manual ECH base64 warning when `logSystem` or `logTLS`.
  2.51.0 - [SECURITY/FIX] Fixed ECH injection on `h3Client`.
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
	if qIdx := strings.IndexByte(url, '?'); qIdx >= 0 {
		base, get := stripMethodModifier(url[:qIdx])
		if get || len(base) != qIdx {
			return base + url[qIdx:], get
		}
	}
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
				_, port, err := net.SplitHostPort(addr)
				if err != nil || port == "" {
					port = "443"
				}
				var lastErr error
				for _, ip := range u.BootstrapIPs {
					conn, dErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
					if dErr == nil {
						return conn, nil
					}
					lastErr = dErr
				}
				return nil, fmt.Errorf("doh: all bootstrap IPs failed for %s: %w", addr, lastErr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	configureHTTP2HealthChecks(h2Tr)
	return &http.Client{Transport: h2Tr}
}

func newDoHHTTP3Client(u *Upstream) *http.Client {
	return &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig:    getHardenedTLSConfig(),
			DisableCompression: true,
			QUICConfig: &quic.Config{
				Allow0RTT:            true,
				HandshakeIdleTimeout: 3 * time.Second,
				MaxIdleTimeout:       30 * time.Second,
				KeepAlivePeriod:      15 * time.Second,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
				if len(u.BootstrapIPs) > 0 {
					_, port, err := net.SplitHostPort(addr)
					if err != nil || port == "" {
						port = "443"
					}
					var lastErr error
					for _, ip := range u.BootstrapIPs {
						conn, dErr := u.dialQUIC(ctx, net.JoinHostPort(ip, port), tlsCfg, qCfg)
						if dErr == nil {
							return conn, nil
						}
						lastErr = dErr
					}
					return nil, fmt.Errorf("doh3: all bootstrap IPs failed for %s: %w", addr, lastErr)
				}
				return u.dialQUIC(ctx, addr, tlsCfg, qCfg)
			},
		},
	}
}

func ParseUpstream(raw string, bootstrapNodes []*Upstream) (*Upstream, error) {
	u := &Upstream{}

	parts := strings.SplitN(raw, "#", 2)
	urlPart := parts[0]

	var echBase64, echDomain string
	if qIdx := strings.IndexByte(urlPart, '?'); qIdx >= 0 {
		baseURL := urlPart[:qIdx]
		rawQuery := urlPart[qIdx+1:]
		var keptParams []string
		for _, param := range strings.Split(rawQuery, "&") {
			switch {
			case strings.HasPrefix(param, "echdomain="):
				echDomain = strings.TrimSpace(param[len("echdomain="):])
			case strings.HasPrefix(param, "ech="):
				echBase64 = strings.TrimSpace(param[len("ech="):])
			case param != "":
				keptParams = append(keptParams, param)
			}
		}
		if len(keptParams) > 0 {
			urlPart = baseURL + "?" + strings.Join(keptParams, "&")
		} else {
			urlPart = baseURL
		}
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
			if err == nil && len(decoded) > 0 {
				if cfgs, cfgErr := extractECHConfigs(decoded); cfgErr == nil && len(cfgs) > 0 {
					u.ECHConfigList = decoded
					if logTLS {
						log.Printf("[TLS] [ECH] Upstream %s: Loaded manual ECH config via URL parameter (%d bytes)", urlPart, len(decoded))
					}
				} else {
					if useECH == "strict" {
						return nil, fmt.Errorf("upstream %s: malformed manual ECHConfigList: %v", urlPart, cfgErr)
					}
					if logTLS || logSystem {
						log.Printf("[TLS] [ECH] Upstream %s: WARNING - Malformed manual ECHConfigList ignored: %v", urlPart, cfgErr)
					}
				}
			} else {
				if useECH == "strict" {
					return nil, fmt.Errorf("upstream %s: invalid manual ECH base64 string: %v", urlPart, err)
				}
				if logTLS || logSystem {
					log.Printf("[TLS] [ECH] Upstream %s: WARNING - Invalid manual ECH base64 string: %v", urlPart, err)
				}
			}
		}
	}

	if len(parts) > 1 && parts[1] != "" {
		rawIPs := strings.Split(parts[1], ",")
		for _, rip := range rawIPs {
			rip = strings.TrimSpace(rip)
			if addr, err := netip.ParseAddr(rip); err == nil {
				addr = addr.Unmap()
				if ipVersionSupport == "ipv4" && !addr.Is4() {
					continue
				}
				if ipVersionSupport == "ipv6" && !addr.Is6() {
					continue
				}
				u.BootstrapIPs = append(u.BootstrapIPs, addr.String())
			} else if rip != "" && logSystem {
				log.Printf("[WARN] Invalid bootstrap IP %q ignored for upstream %s", rip, urlPart)
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
			u.h3Client = newDoHHTTP3Client(u)
		}

	case strings.HasPrefix(urlPart, "doh3://"):
		u.Proto = "doh3"
		urlPart, u.useGET = stripMethodModifier(urlPart)
		u.RawURL = "https://" + strings.TrimPrefix(urlPart, "doh3://")
		u.RawURL = stripDefaultHTTPSPort(u.RawURL)
		u.h2Client = newDoHHTTP2Client(u)
		u.h3Client = newDoHHTTP3Client(u)

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
			addr = addr.Unmap()
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
		if u.dialHost != "" && net.ParseIP(u.dialHost) == nil {
			resolveHost = strings.ReplaceAll(u.dialHost, "{client-name}", "bootstrap")
		}
	case "doh", "doh3":
		rest := strings.TrimPrefix(u.RawURL, "https://")
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			rest = rest[:idx]
		}
		if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
			rest = rest[:qIdx]
		}
		if h, _, err := net.SplitHostPort(rest); err == nil {
			rest = h
		} else {
			rest = strings.TrimPrefix(strings.TrimSuffix(rest, "]"), "[")
		}
		if addr, err := netip.ParseAddr(rest); err == nil {
			addr = addr.Unmap()
			if ipVersionSupport == "ipv4" && !addr.Is4() {
				return nil, fmt.Errorf("upstream %s is IPv6 but support_ip_version is 'ipv4'", rest)
			}
			if ipVersionSupport == "ipv6" && !addr.Is6() {
				return nil, fmt.Errorf("upstream %s is IPv4 but support_ip_version is 'ipv6'", rest)
			}
			if len(u.BootstrapIPs) == 0 {
				u.BootstrapIPs = []string{addr.String()}
			}
		} else {
			resolveHost = strings.ReplaceAll(rest, "{client-name}", "bootstrap")
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
	}

	hasDirectIPs := len(u.BootstrapIPs) > 0 || resolveHost == ""
	hasDiscoveryTarget := resolveHost != "" || u.echDomain != ""
	logTarget := resolveHost
	if logTarget == "" {
		logTarget = u.echDomain
	}
	if logTarget == "" {
		logTarget = u.RawURL
	}

	var hintedIPs []string
	var nativeH3 bool
	var nativeH2 bool

	isEncrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	needsECH := (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0
	needsH3 := u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load()
	needsH2 := u.Proto == "doh3" && !u.dohAvailable.Load()

	if hasDirectIPs && isEncrypted && hasDiscoveryTarget && (needsECH || needsH3 || needsH2) {
		if logDDR {
			log.Printf("[DDR] Upstream %s: Direct IP(s) available — probing upstream directly first via %s (no ECH)...", logTarget, u.Proto)
		}
		echBytes, h3Supported, h2Supported := fetchDDRParams(u, resolveHost, u.echDomain)
		if len(echBytes) > 0 && len(u.ECHConfigList) == 0 && useECH != "disable" {
			u.ECHConfigList = echBytes
			if logDDR {
				log.Printf("[DDR] Upstream %s: Successfully secured ECH config (%d bytes) directly from upstream", logTarget, len(echBytes))
			}
		}
		if h3Supported {
			nativeH3 = true
		}
		if h2Supported {
			nativeH2 = true
		}
	}

	stillNeedsECH := (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0
	stillNeedsH3 := u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !nativeH3 && !u.h3Upgraded.Load()
	stillNeedsH2 := u.Proto == "doh3" && !nativeH2 && !u.dohAvailable.Load()

	if isEncrypted && hasDiscoveryTarget && len(bootstrapNodes) > 0 && (!hasDirectIPs || stillNeedsECH || stillNeedsH3 || stillNeedsH2) {
		if logDDR {
			log.Printf("[DDR] Upstream %s: Querying bootstrap servers for ECH, IP hints, and ALPN...", logTarget)
		}
		echConfig, hIPs, h3Supported, h2Supported := bootstrapResolveECH(resolveHost, u.echDomain, bootstrapNodes)
		if len(echConfig) > 0 && len(u.ECHConfigList) == 0 && useECH != "disable" {
			u.ECHConfigList = echConfig
			if logDDR {
				log.Printf("[DDR] Upstream %s: Extracted ECH config (%d bytes) via bootstrap HTTPS record", logTarget, len(echConfig))
			}
		}
		if !hasDirectIPs && len(hIPs) > 0 {
			hintedIPs = hIPs
			if logDDR {
				log.Printf("[DDR] Upstream %s: Discovered %d IP hint(s) via HTTPS/SVCB record: %v", logTarget, len(hIPs), hIPs)
			}
		}
		if h3Supported {
			nativeH3 = true
		}
		if h2Supported {
			nativeH2 = true
		}
	}

	if !hasDirectIPs && resolveHost != "" {
		var ips []string

		if len(hintedIPs) > 0 {
			ips = hintedIPs
		} else if len(bootstrapNodes) > 0 {
			ips = bootstrapResolve(resolveHost, bootstrapNodes)
		}

		if len(ips) > 0 {
			u.BootstrapIPs = ips

			if len(hintedIPs) == 0 && logSystem {
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
			if logSystem {
				log.Printf("[WARN] Bootstrap: could not resolve %s — OS resolver will be used at dial time", resolveHost)
			}
		}
	}

	stillNeedsECH = (useECH == "try" || useECH == "strict") && len(u.ECHConfigList) == 0
	stillNeedsH3 = u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !nativeH3 && !u.h3Upgraded.Load()
	stillNeedsH2 = u.Proto == "doh3" && !nativeH2 && !u.dohAvailable.Load()

	if !hasDirectIPs && isEncrypted && hasDiscoveryTarget && (stillNeedsECH || stillNeedsH3 || stillNeedsH2) && (len(u.dialAddrs) > 0 || len(u.BootstrapIPs) > 0) {
		echBytes, h3Supported, h2Supported := fetchDDRParams(u, resolveHost, u.echDomain)
		if len(echBytes) > 0 && len(u.ECHConfigList) == 0 && useECH != "disable" {
			u.ECHConfigList = echBytes
			if logDDR {
				log.Printf("[DDR] Upstream %s: Successfully secured ECH config (%d bytes)", logTarget, len(echBytes))
			}
		}
		if h3Supported {
			nativeH3 = true
		}
		if h2Supported {
			nativeH2 = true
		}
	}

	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && nativeH3 && !u.h3Upgraded.Load() {
		u.h3Upgraded.Store(true)
		if logTLS {
			log.Printf("[TLS] [UPGRADE] Upstream %s: Proactively upgraded DoH to DoH3 (QUIC) based on SVCB/HTTPS ALPN discovery natively.", logTarget)
		}
	}

	if u.Proto == "doh3" && nativeH2 {
		u.dohAvailable.Store(true)
		if logTLS {
			log.Printf("[TLS] [DOWNGRADE] Upstream %s: Verified standard DoH (HTTP/2) availability on same server via SVCB/HTTPS ALPN.", logTarget)
		}
	}

	if useECH == "strict" && len(u.ECHConfigList) == 0 && isEncrypted {
		return nil, fmt.Errorf("upstream %s: strict ECH enforced but no ECH config could be discovered", u.RawURL)
	}

	if len(u.ECHConfigList) > 0 {
		if logTLS {
			log.Printf("[TLS] [ECH] Upstream %s: TLS Transport strictly enforcing Encrypted Client Hello (Requires TLS 1.3+)", logTarget)
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
