/*
File:    upstream_ddr.go
Version: 2.62.0
Last Updated: 18-Nov-2026 12:30 CET

Description:
  Discovery of Designated Resolvers (DDR), Encrypted Client Hello (ECH), and 
  Application-Layer Protocol Negotiation (ALPN) extraction mechanics. Interrogates 
  upstream resolvers directly to autonomously secure encrypted TLS channels, 
  map topological dependencies, and upgrade transports natively.

  Extracted from upstream.go to isolate network probing and bootstrap capabilities 
  away from the primary structural configurations.

Changes:
  2.62.0 - [SECURITY/FIX] Added CNAME/DNAME chain target awareness to
           `extractSVCBParams` (`validChainNames []string`) across `fetchDDRParams`
           and `bootstrapResolveECH`. When an `HTTPS` query (such as
           `cloudflare-ech.com` -> `CNAME` -> `HTTPS`) resolves through an alias
           chain, RFC 9460 `TargetName` matches any in-bailiwick owner name in
           the alias chain rather than failing strict target comparison against
            only the initial query name.
         - [FIX] Handled portless `u.dialAddrs` entries safely in `fetchDDRParams`.
  2.61.0 - [CRITICAL/FIX] Fixed `fetchWellKnownFallback` so literal-IP upstreams
           with `?echdomain=` (where `expectedHost` is empty) substitute
           `{client-name}` on `l7Host` before invoking `fetchWellKnownFallback`
           and use `u.lockNo0RTT()` / `u.revertUnverifiedNo0RTT()` for race-free
           0-RTT fallback latching.
  2.60.0 - [FEAT/FIX] Routed all QUIC dials in `fetchDDRParams` and
           `fetchWellKnownFallback` through `u.dialQUIC`, and added an automatic
           `no0RTT` retry loop in both functions.
  2.59.0 - [SECURITY/FIX] Added unified `matchSVCBTarget(svcbTarget, expectedHost, isDDR)`
           and `extractSVCBParams` helpers to enforce RFC 9460 `Priority != 0`
           (ServiceMode) and `cfg.Server.HostnameECH` (`strict`, `loose`, `apex`, `any`)
           target validation consistently across `_dns.resolver.arpa` (`SVCB`),
           direct `expectedHost` (`HTTPS`), `echDomain` (`HTTPS`), and
           `bootstrapResolveECH`.
         - [FIX] Fixed `fetchWellKnownFallback` so explicit `doh3://` upstreams
           probe L7 well-known endpoints over HTTP/3 even when `upgrade_doh3` is
           false, and automatically fall back per-target to HTTP/2 when `u.Proto == "doh"`
           or `u.dohAvailable.Load()` is true.
         - [CLEANUP] Removed dead `reqExtraOpt` helper.
  2.58.0 - [FEAT/PERF] Optimized `fetchDDRParams` when `echDomain` is explicitly
           configured.
  2.57.0 - [FEAT/SECURITY] Extended `fetchDDRParams` to also query `expectedHost`
           (`HTTPS`) directly over the upstream's native protocol.
  2.56.0 - [FEAT] Extended `fetchDDRParams` and `bootstrapResolveECH` to detect
           standard DoH (`h2` or `http/1.1` ALPN) support in SVCB/HTTPS records.
  2.55.0 - [SECURITY/FIX] Marked `bootstrapResolveECH` contexts with
           `WithBypassUpstreamThrottle`.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// SVCB / HTTPS Target Validation & Parameter Extraction
// ---------------------------------------------------------------------------

// matchSVCBTarget validates an SVCB/HTTPS TargetName against expectedHost
// (or any valid CNAME/DNAME chain owner name when validChainNames is provided)
// according to `cfg.Server.HostnameECH` ("strict", "loose", "apex", "any").
func matchSVCBTarget(svcbTarget, expectedHost string, isDDR bool, validChainNames []string) bool {
	if expectedHost == "" && len(validChainNames) == 0 {
		return true
	}
	targetFqdn := strings.ToLower(dns.Fqdn(svcbTarget))
	if svcbTarget == "." || svcbTarget == "" {
		targetFqdn = "."
	}

	switch cfg.Server.HostnameECH {
	case "any":
		return true
	case "apex":
		if targetFqdn == "." {
			return true
		}
		targetApex, _ := extractETLDPlusOne(strings.TrimSuffix(targetFqdn, "."))
		if expectedHost != "" {
			expectedFqdn := strings.ToLower(dns.Fqdn(expectedHost))
			if targetFqdn == expectedFqdn {
				return true
			}
			expectedApex, _ := extractETLDPlusOne(strings.TrimSuffix(expectedFqdn, "."))
			if targetApex != "" && targetApex == expectedApex {
				return true
			}
		}
		for _, cn := range validChainNames {
			if targetFqdn == cn {
				return true
			}
			cnApex, _ := extractETLDPlusOne(strings.TrimSuffix(cn, "."))
			if targetApex != "" && targetApex == cnApex {
				return true
			}
		}
		return false
	case "loose":
		if targetFqdn == "." {
			return true
		}
		if expectedHost != "" && targetFqdn == strings.ToLower(dns.Fqdn(expectedHost)) {
			return true
		}
		return isValidBailiwickName(validChainNames, targetFqdn)
	default: // "strict"
		if !isDDR && targetFqdn == "." {
			return true
		}
		if targetFqdn == "." {
			return false
		}
		if expectedHost != "" && targetFqdn == strings.ToLower(dns.Fqdn(expectedHost)) {
			return true
		}
		return !isDDR && isValidBailiwickName(validChainNames, targetFqdn)
	}
}

func extractSVCBParams(rr dns.RR, expectedHost string, isDDR bool, validChainNames []string) (priority uint16, target string, values []dns.SVCBKeyValue, matched bool) {
	if len(validChainNames) > 0 && !isValidBailiwickName(validChainNames, strings.ToLower(dns.Fqdn(rr.Header().Name))) {
		return 0, "", nil, false
	}
	switch r := rr.(type) {
	case *dns.HTTPS:
		if r.Priority == 0 {
			return 0, r.Target, nil, false
		}
		return r.Priority, r.Target, r.Value, matchSVCBTarget(r.Target, expectedHost, isDDR, validChainNames)
	case *dns.SVCB:
		if r.Priority == 0 {
			return 0, r.Target, nil, false
		}
		return r.Priority, r.Target, r.Value, matchSVCBTarget(r.Target, expectedHost, isDDR, validChainNames)
	default:
		return 0, "", nil, false
	}
}

// ---------------------------------------------------------------------------
// SVCB / DDR Upstream Probing
// ---------------------------------------------------------------------------

func readDDRPayload(body io.ReadCloser) (*dns.Msg, error) {
	limitReader := io.LimitReader(body, 65536+1)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("read DDR payload: %w", err)
	}
	if len(bodyBytes) > 65536 {
		return nil, fmt.Errorf("security constraint: DDR payload exceeded 64KB maximum buffer capacity")
	}
	resp := new(dns.Msg)
	return resp, resp.Unpack(bodyBytes)
}

func fetchDDRParams(u *Upstream, expectedHost string, echDomain string) ([]byte, bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(targetURL, "{client-name}", "bootstrap")
		expectedHost = strings.ReplaceAll(expectedHost, "{client-name}", "bootstrap")
	}
	echDomain = strings.ReplaceAll(echDomain, "{client-name}", "bootstrap")

	probeSNI := expectedHost
	if probeSNI == "" && echDomain != "" {
		probeSNI = echDomain
	}

	if logDDR {
		log.Printf("[DDR] Initiating extended bootstrap for upstream %s via %s", probeSNI, u.Proto)
	}

	_, defPort := parseHostPort(u.RawURL, u.Proto)
	var targets []string
	if len(u.dialAddrs) > 0 {
		for _, da := range u.dialAddrs {
			if _, _, err := net.SplitHostPort(da); err == nil {
				targets = append(targets, da)
			} else {
				targets = append(targets, net.JoinHostPort(da, defPort))
			}
		}
	} else if len(u.BootstrapIPs) > 0 {
		for _, ip := range u.BootstrapIPs {
			targets = append(targets, net.JoinHostPort(ip, defPort))
		}
	} else {
		h, port := parseHostPort(u.RawURL, u.Proto)
		if expectedHost != "" {
			h = expectedHost
		}
		targets = []string{net.JoinHostPort(h, port)}
	}

	probeH3Once := func(dialCtx context.Context, dialAddr string, fwdBytes []byte) (*dns.Msg, error) {
		tlsConfH3 := getHardenedTLSConfig()
		tlsConfH3.ServerName = probeSNI
		trH3 := &http3.Transport{
			TLSClientConfig: tlsConfH3,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: 3 * time.Second,
			},
			Dial: func(dCtx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
				return u.dialQUIC(dCtx, dialAddr, tlsCfg, qCfg)
			},
		}
		defer trH3.Close()
		clientH3 := &http.Client{Timeout: 5 * time.Second, Transport: trH3}

		hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(fwdBytes))
		if reqErr != nil {
			return nil, reqErr
		}
		hReq.Header.Set("Content-Type", "application/dns-message")
		hReq.Header.Set("Accept", "application/dns-message")
		hReq.Header.Set("User-Agent", cfg.Server.UserAgent)

		httpResp, err := clientH3.Do(hReq)
		if err != nil {
			return nil, err
		}
		defer httpResp.Body.Close()
		if httpResp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http status %d", httpResp.StatusCode)
		}
		return readDDRPayload(httpResp.Body)
	}

	probeH3With0RTTFallback := func(dialCtx context.Context, dialAddr string, fwdBytes []byte) (*dns.Msg, error) {
		was0RTT := !u.no0RTT.Load() && !u.no0RTTVerified.Load()
		resp, err := probeH3Once(dialCtx, dialAddr, fwdBytes)
		if err != nil && was0RTT && dialCtx.Err() == nil {
			u.no0RTT.Store(true)
			resp, err = probeH3Once(dialCtx, dialAddr, fwdBytes)
			if err == nil {
				u.lockNo0RTT()
				if logTLS || logSystem {
					log.Printf("[TLS] [QUIC] Upstream %s: DDR HTTP/3 probe succeeded after disabling Allow0RTT; keeping 0-RTT disabled.", u.RawURL)
				}
			} else {
				u.revertUnverifiedNo0RTT()
			}
		}
		return resp, err
	}

	probeDoQOnce := func(dialCtx context.Context, dialAddr string, fwdBytes []byte) (*dns.Msg, error) {
		tlsConf := getHardenedTLSConfig()
		tlsConf.ServerName = probeSNI
		tlsConf.NextProtos = []string{"doq"}

		conn, err := u.dialQUIC(dialCtx, dialAddr, tlsConf, &quic.Config{HandshakeIdleTimeout: 3 * time.Second})
		if err != nil {
			return nil, err
		}
		defer conn.CloseWithError(0, "ddr complete")

		stream, err := conn.OpenStreamSync(dialCtx)
		if err != nil {
			return nil, err
		}
		if len(fwdBytes) > 65535 {
			return nil, fmt.Errorf("ddr probe too large for the RFC 9250 length prefix: %d bytes", len(fwdBytes))
		}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(fwdBytes)))
		_, _ = stream.Write(lenBuf)
		_, _ = stream.Write(fwdBytes)
		_ = stream.Close()

		if _, readErr := io.ReadFull(stream, lenBuf); readErr != nil {
			return nil, fmt.Errorf("read length: %v", readErr)
		}
		respLen := binary.BigEndian.Uint16(lenBuf)
		if respLen == 0 {
			return nil, errors.New("zero length response")
		}
		respBuf := make([]byte, respLen)
		if _, rErr := io.ReadFull(stream, respBuf); rErr != nil {
			return nil, fmt.Errorf("read payload: %v", rErr)
		}
		resp := new(dns.Msg)
		if uErr := resp.Unpack(respBuf); uErr != nil {
			return nil, uErr
		}
		return resp, nil
	}

	sendProbe := func(qName string, qType uint16) (*dns.Msg, error) {
		req := new(dns.Msg)
		req.SetQuestion(qName, qType)
		req.RecursionDesired = true

		opt := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		req.Extra = []dns.RR{opt}

		fwd := prepareForwardQuery(req, true, nil, netip.Addr{})

		fwdBytes, packErr := fwd.Pack()
		if packErr != nil {
			if logDDR || logSystem {
				log.Printf("[DDR] WARNING: Failed to pack SVCB/HTTPS query payload: %v", packErr)
			}
			return nil, packErr
		}

		var resp *dns.Msg
		var err error

		for _, dialAddr := range targets {
			err = nil
			resp = nil

			dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)

			switch u.Proto {
			case "dot":
				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = probeSNI
				tlsConf.NextProtos = []string{"dot"}

				var conn *dns.Conn
				conn, err = dns.DialTimeoutWithTLS("tcp-tls", dialAddr, tlsConf, 5*time.Second)
				if err == nil {
					if err = conn.WriteMsg(fwd); err == nil {
						resp, err = conn.ReadMsg()
					}
					conn.Close()
				}
			case "doh":
				if cfg.Server.UpgradeDoH3 {
					resp, err = probeH3With0RTTFallback(dialCtx, dialAddr, fwdBytes)
					if err == nil && resp != nil {
						dialCancel()
						break
					}
				}

				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = probeSNI
				tr := &http.Transport{
					TLSClientConfig:   tlsConf,
					ForceAttemptHTTP2: true,
					DisableKeepAlives: true,
				}

				dialer := &net.Dialer{Timeout: 3 * time.Second}
				tr.DialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(dCtx, network, dialAddr)
				}
				client := &http.Client{Timeout: 5 * time.Second, Transport: tr}

				hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(fwdBytes))
				if reqErr != nil {
					err = reqErr
					tr.CloseIdleConnections()
					dialCancel()
					continue
				}

				hReq.Header.Set("Content-Type", "application/dns-message")
				hReq.Header.Set("Accept", "application/dns-message")
				hReq.Header.Set("User-Agent", cfg.Server.UserAgent)

				var httpResp *http.Response
				httpResp, err = client.Do(hReq)
				if err == nil {
					if httpResp.StatusCode == http.StatusOK {
						resp, err = readDDRPayload(httpResp.Body)
					} else {
						err = fmt.Errorf("http status %d", httpResp.StatusCode)
					}
					httpResp.Body.Close()
				}

				tr.CloseIdleConnections()
			case "doh3":
				resp, err = probeH3With0RTTFallback(dialCtx, dialAddr, fwdBytes)
			case "doq":
				was0RTT := !u.no0RTT.Load() && !u.no0RTTVerified.Load()
				resp, err = probeDoQOnce(dialCtx, dialAddr, fwdBytes)
				if err != nil && was0RTT && dialCtx.Err() == nil {
					u.no0RTT.Store(true)
					resp, err = probeDoQOnce(dialCtx, dialAddr, fwdBytes)
					if err == nil {
						u.lockNo0RTT()
						if logTLS || logSystem {
							log.Printf("[TLS] [QUIC] Upstream %s: DDR DoQ probe succeeded after disabling Allow0RTT; keeping 0-RTT disabled.", u.RawURL)
						}
					} else {
						u.revertUnverifiedNo0RTT()
					}
				}
			}

			dialCancel()

			if err == nil && resp != nil {
				break
			}
		}

		return resp, err
	}

	var extractedECH []byte
	var supportsH3 bool
	var supportsH2 bool

	needsALPN := (u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load()) ||
		(u.Proto == "doh3" && !u.dohAvailable.Load())

	if expectedHost != "" && (echDomain == "" || needsALPN) {
		if logDDR {
			log.Printf("[DDR] Executing _dns.resolver.arpa SVCB query against %s using native protocol %s", expectedHost, u.Proto)
		}
		resp, err := sendProbe("_dns.resolver.arpa.", dns.TypeSVCB)

		if err != nil {
			if logDDR || logSystem {
				log.Printf("[DDR] WARNING: Failed to query upstream %s for DDR parameters via DNS: %v", expectedHost, err)
			}
		} else if resp == nil {
			if logDDR {
				log.Printf("[DDR] Received empty DNS response from upstream %s", expectedHost)
			}
		} else {
			if logDDR {
				log.Printf("[DDR] Received response (RCODE: %s) with %d Answer records from %s", dns.RcodeToString[resp.Rcode], len(resp.Answer), expectedHost)
			}

			expectedHostFqdn := dns.Fqdn(expectedHost)
			var chainBuf [64]string
			validChain, _, _ := walkBailiwickChain(resp.Answer, "_dns.resolver.arpa.", 8, &chainBuf)

			for _, rr := range resp.Answer {
				prio, target, values, isMatch := extractSVCBParams(rr, expectedHost, true, validChain)
				if prio == 0 {
					continue
				}
				if logDDR {
					log.Printf("[DDR] Found SVCB record for Target: %s (Expected: %s)", target, expectedHostFqdn)
				}
				if isMatch {
					for _, v := range values {
						if e, ok := v.(*dns.SVCBECHConfig); ok {
							extractedECH = e.ECH
						}
						if alpn, ok := v.(*dns.SVCBAlpn); ok {
							for _, a := range alpn.Alpn {
								switch a {
								case "h3":
									supportsH3 = true
								case "h2", "http/1.1":
									supportsH2 = true
								}
							}
						}
					}
				} else if logDDR {
					log.Printf("[DDR] Skipping SVCB record: Target mismatch (Target: %s, Expected: %s, Mode: %s)", target, expectedHostFqdn, cfg.Server.HostnameECH)
				}
			}
		}
	}

	if echDomain != "" {
		if logDDR {
			log.Printf("[DDR] Executing explicit ECH discovery query for %s (HTTPS) directly via %s", echDomain, u.Proto)
		}
		echFqdn := dns.Fqdn(echDomain)
		respEch, errEch := sendProbe(echFqdn, dns.TypeHTTPS)
		if errEch == nil && respEch != nil {
			var chainBuf [64]string
			validChain, _, _ := walkBailiwickChain(respEch.Answer, echFqdn, 8, &chainBuf)
			for _, rr := range respEch.Answer {
				prio, _, values, isMatch := extractSVCBParams(rr, echDomain, false, validChain)
				if prio == 0 || !isMatch {
					continue
				}
				for _, v := range values {
					if e, ok := v.(*dns.SVCBECHConfig); ok {
						extractedECH = e.ECH
					}
					if echDomain == expectedHost {
						if alpn, ok := v.(*dns.SVCBAlpn); ok {
							for _, a := range alpn.Alpn {
								switch a {
								case "h3":
									supportsH3 = true
								case "h2", "http/1.1":
									supportsH2 = true
								}
							}
						}
					}
				}
			}
		} else if logDDR || logSystem {
			log.Printf("[DDR] WARNING: Explicit ECH discovery query for %s failed: %v", echDomain, errEch)
		}
	} else if len(extractedECH) == 0 && expectedHost != "" {
		if logDDR {
			log.Printf("[DDR] Executing direct HTTPS record query for %s via %s", expectedHost, u.Proto)
		}
		hostFqdn := dns.Fqdn(expectedHost)
		respHost, errHost := sendProbe(hostFqdn, dns.TypeHTTPS)
		if errHost == nil && respHost != nil {
			var chainBuf [64]string
			validChain, _, _ := walkBailiwickChain(respHost.Answer, hostFqdn, 8, &chainBuf)
			for _, rr := range respHost.Answer {
				prio, _, values, isMatch := extractSVCBParams(rr, expectedHost, false, validChain)
				if prio == 0 || !isMatch {
					continue
				}
				for _, v := range values {
					if e, ok := v.(*dns.SVCBECHConfig); ok {
						extractedECH = e.ECH
					}
					if alpn, ok := v.(*dns.SVCBAlpn); ok {
						for _, a := range alpn.Alpn {
							switch a {
							case "h3":
								supportsH3 = true
							case "h2", "http/1.1":
								supportsH2 = true
							}
						}
					}
				}
			}
		}
	}

	if logDDR {
		if len(extractedECH) > 0 {
			log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) via DNS SVCB/HTTPS for %s", len(extractedECH), probeSNI)
		}
		if supportsH3 {
			log.Printf("[DDR] Successfully discovered HTTP/3 (ALPN: h3) support via DNS SVCB for %s", probeSNI)
		}
		if supportsH2 {
			log.Printf("[DDR] Successfully discovered DoH (ALPN: h2/http/1.1) support via DNS SVCB for %s", probeSNI)
		}
	}

	if len(extractedECH) == 0 && (u.Proto == "doh" || u.Proto == "doh3") {
		l7Host := expectedHost
		if echDomain != "" {
			l7Host = echDomain
		}

		if l7Host != "" {
			if logDDR {
				log.Printf("[DDR] No ECH configuration obtained via DNS SVCB for %s. Attempting Out-of-Band L7 fallback via /.well-known/origin-svcb", l7Host)
			}

			tryH3 := u.Proto == "doh3" || (u.Proto == "doh" && cfg.Server.UpgradeDoH3)
			allowH2Fallback := u.Proto == "doh" || u.dohAvailable.Load() || u.DoH3FallbackThreshold > 0

			wkECH, wkErr := fetchWellKnownFallback(ctx, u, l7Host, targets, tryH3, allowH2Fallback, "/.well-known/origin-svcb", true)
			if wkErr == nil && len(wkECH) > 0 {
				extractedECH = wkECH
				if logDDR {
					log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) for %s via Out-of-Band L7 /.well-known/origin-svcb", len(extractedECH), l7Host)
				}
			} else {
				if logDDR {
					log.Printf("[DDR] L7 fallback via /.well-known/origin-svcb failed for %s: %v. Attempting legacy /.well-known/ech", l7Host, wkErr)
				}

				wkECH, wkErr = fetchWellKnownFallback(ctx, u, l7Host, targets, tryH3, allowH2Fallback, "/.well-known/ech", false)
				if wkErr == nil && len(wkECH) > 0 {
					extractedECH = wkECH
					if logDDR {
						log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) for %s via Out-of-Band L7 /.well-known/ech", len(extractedECH), l7Host)
					}
				} else {
					if logDDR {
						log.Printf("[DDR] L7 fallback via /.well-known/ech failed for %s: %v", l7Host, wkErr)
					}
				}
			}
		}
	}

	if len(extractedECH) > 0 || supportsH3 || supportsH2 {
		return extractedECH, supportsH3, supportsH2
	}

	if logDDR {
		log.Printf("[DDR] No valid ECH/ALPN configurations discovered for upstream %s", probeSNI)
	}
	return nil, false, false
}

// ---------------------------------------------------------------------------
// Native UDP Bootstrapping Constraints
// ---------------------------------------------------------------------------

func bootstrapResolveECH(host, echDomain string, servers []*Upstream) ([]byte, []string, bool, bool) {
	var ech []byte
	var hints []string
	var supportsH3 bool
	var supportsH2 bool
	seenMap := make(map[string]struct{})

	queryHTTPS := func(target string, extractECHOnly bool) {
		fqdn := dns.Fqdn(target)
		m := new(dns.Msg)
		m.SetQuestion(fqdn, dns.TypeHTTPS)
		m.RecursionDesired = true

		opt := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		m.Extra = []dns.RR{opt}

		for _, u := range servers {
			if u == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), 3*time.Second)

			resp, _, err := u.Exchange(ctx, m, "bootstrap", "bootstrap", netip.Addr{})
			cancel()

			if err != nil || resp == nil {
				continue
			}

			var chainBuf [64]string
			validChain, _, _ := walkBailiwickChain(resp.Answer, fqdn, 8, &chainBuf)

			for _, rr := range resp.Answer {
				prio, _, values, isMatch := extractSVCBParams(rr, target, false, validChain)
				if prio == 0 || !isMatch {
					continue
				}

				for _, v := range values {
					if e, ok := v.(*dns.SVCBECHConfig); ok {
						ech = e.ECH
					}
					if !extractECHOnly {
						if alpn, ok := v.(*dns.SVCBAlpn); ok {
							for _, a := range alpn.Alpn {
								switch a {
								case "h3":
									supportsH3 = true
								case "h2", "http/1.1":
									supportsH2 = true
								}
							}
						}
						if v4, ok := v.(*dns.SVCBIPv4Hint); ok {
							if ipVersionSupport == "ipv6" {
								continue
							}
							for _, ip := range v4.Hint {
								ipStr := ip.String()
								if _, dup := seenMap[ipStr]; !dup {
									seenMap[ipStr] = struct{}{}
									hints = append(hints, ipStr)
								}
							}
						}
						if v6, ok := v.(*dns.SVCBIPv6Hint); ok {
							if ipVersionSupport == "ipv4" {
								continue
							}
							for _, ip := range v6.Hint {
								ipStr := ip.String()
								if _, dup := seenMap[ipStr]; !dup {
									seenMap[ipStr] = struct{}{}
									hints = append(hints, ipStr)
								}
							}
						}
					}
				}
			}
			break
		}
	}

	if host != "" {
		queryHTTPS(host, false)
	}

	if echDomain != "" && echDomain != host {
		queryHTTPS(echDomain, true)
	}

	return ech, hints, supportsH3, supportsH2
}

// ---------------------------------------------------------------------------
// Application Layer (L7) Out-of-Band Fallback
// ---------------------------------------------------------------------------

func fetchWellKnownFallback(ctx context.Context, u *Upstream, l7Host string, targets []string, tryH3 bool, allowH2Fallback bool, uriPath string, isJSON bool) ([]byte, error) {
	if l7Host == "" {
		return nil, errors.New("empty L7 discovery host")
	}
	wkURL := "https://" + l7Host + uriPath

	var modes []bool
	if tryH3 {
		modes = append(modes, true)
		if allowH2Fallback {
			modes = append(modes, false)
		}
	} else {
		modes = append(modes, false)
	}

	doL7Attempt := func(dialAddr string, useH3 bool) ([]byte, error) {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dialCancel()

		var client *http.Client
		var trH3 *http3.Transport
		var trH2 *http.Transport

		if useH3 {
			tlsConfH3 := getHardenedTLSConfig()
			tlsConfH3.ServerName = l7Host

			trH3 = &http3.Transport{
				TLSClientConfig: tlsConfH3,
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 3 * time.Second,
				},
				Dial: func(dCtx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
					return u.dialQUIC(dCtx, dialAddr, tlsCfg, qCfg)
				},
			}
			defer trH3.Close()
			client = &http.Client{Timeout: 5 * time.Second, Transport: trH3}
		} else {
			tlsConf := getHardenedTLSConfig()
			tlsConf.ServerName = l7Host

			trH2 = &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: true,
				DisableKeepAlives: true,
			}
			defer trH2.CloseIdleConnections()

			dialer := &net.Dialer{Timeout: 3 * time.Second}
			trH2.DialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(dCtx, network, dialAddr)
			}
			client = &http.Client{Timeout: 5 * time.Second, Transport: trH2}
		}

		req, err := http.NewRequestWithContext(dialCtx, http.MethodGet, wkURL, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", cfg.Server.UserAgent)
		req.Header.Set("Accept", "application/json, application/echconfig-list, application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("http status %d", resp.StatusCode)
		}

		limitReader := io.LimitReader(resp.Body, 65536+1)
		bodyBytes, readErr := io.ReadAll(limitReader)
		if readErr != nil {
			return nil, fmt.Errorf("read L7 fallback body: %w", readErr)
		}
		if limitReader.(*io.LimitedReader).N == 0 {
			return nil, errors.New("security constraint: L7 fallback payload exceeded 64KB maximum buffer capacity")
		}
		if len(bodyBytes) == 0 {
			return nil, errors.New("empty payload returned")
		}

		if isJSON {
			var svcbResp struct {
				Endpoints []struct {
					ECH string `json:"ech"`
				} `json:"endpoints"`
			}
			if err := json.Unmarshal(bodyBytes, &svcbResp); err == nil {
				for _, ep := range svcbResp.Endpoints {
					if ep.ECH != "" {
						echBytes, decErr := decodeBase64Flex(ep.ECH)
						if decErr == nil && len(echBytes) > 0 {
							return echBytes, nil
						}
					}
				}
				return nil, errors.New("no valid ECH config in origin-svcb endpoints")
			}
			return nil, fmt.Errorf("failed to parse origin-svcb JSON: %v", err)
		}

		return bodyBytes, nil
	}

	var lastErr error
	for _, dialAddr := range targets {
		for _, useH3 := range modes {
			was0RTT := useH3 && u != nil && !u.no0RTT.Load() && !u.no0RTTVerified.Load()
			b, err := doL7Attempt(dialAddr, useH3)
			if err == nil && len(b) > 0 {
				return b, nil
			}
			if err != nil && was0RTT && ctx.Err() == nil {
				u.no0RTT.Store(true)
				b, err = doL7Attempt(dialAddr, true)
				if err == nil && len(b) > 0 {
					u.lockNo0RTT()
					if logTLS || logSystem {
						log.Printf("[TLS] [QUIC] Upstream %s: L7 well-known HTTP/3 probe succeeded after disabling Allow0RTT; keeping 0-RTT disabled.", u.RawURL)
					}
					return b, nil
				}
				u.revertUnverifiedNo0RTT()
			}
			lastErr = err
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no responsive targets for L7 discovery")
}
