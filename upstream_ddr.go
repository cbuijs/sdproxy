/*
File:    upstream_ddr.go
Version: 2.52.0
Last Updated: 26-Aug-2026 15:57 CEST

Description:
  Discovery of Designated Resolvers (DDR), Encrypted Client Hello (ECH), and 
  Application-Layer Protocol Negotiation (ALPN) extraction mechanics. Interrogates 
  upstream resolvers directly to autonomously secure encrypted TLS channels, 
  map topological dependencies, and upgrade transports natively.

  Extracted from upstream.go to isolate network probing and bootstrap capabilities 
  away from the primary structural configurations.

Changes:
  2.52.0 - [CLEANUP] Deduplicated redundant Base64 extraction boundaries natively. 
           L7 Out-of-Band (`/.well-known/origin-svcb`) routines now leverage the 
           structurally compliant `decodeBase64Flex` primitive natively from 
           `upstream_parser.go`, obliterating nested permutation loops organically.
  2.51.0 - [SECURITY/FIX] Guarded the DDR DoQ probe's length prefix against
           uint16 wraparound (audit item S-C), completing the sweep begun in
           server.go 1.39.0 (inbound responses) and upstream_net.go 1.31.0
           (outbound queries). All three sites shared one unchecked
           `uint16(len(...))`, which on an oversized payload announces a length
           modulo 65.536 and then writes the full body — desynchronising the
           peer's read offset rather than merely failing.
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
// SVCB / DDR Upstream Probing
// ---------------------------------------------------------------------------

// readDDRPayload cleanly extracts and unpacks the upstream HTTP payload securely natively.
func readDDRPayload(body io.ReadCloser) (*dns.Msg, error) {
	// [SECURITY/FIX] CWE-400 Memory Exhaustion Prevention
	// Prevent malicious upstreams from flooding the router RAM via infinite streams natively
	limitReader := io.LimitReader(body, 65536 + 1)
	bodyBytes, _ := io.ReadAll(limitReader)
	if len(bodyBytes) > 65536 {
		return nil, fmt.Errorf("security constraint: DDR payload exceeded 64KB maximum buffer capacity")
	}
	resp := new(dns.Msg)
	return resp, resp.Unpack(bodyBytes)
}

// fetchDDRParams performs a one-off Discovery of Designated Resolvers (DDR) query
// directly against the upstream using its native encrypted protocol (DoT, DoH, DoQ).
// It requests _dns.resolver.arpa (SVCB) to extract ECH keys and ALPN parameters dynamically.
// If echDomain is explicitly set, it isolates and conducts an additional HTTPS query
// explicitly targeting the specified hostname natively.
func fetchDDRParams(u *Upstream, expectedHost string, echDomain string) ([]byte, bool) {
	// [SECURITY/FIX] Expand global timeout envelope to guarantee all targets have time 
	// to successfully iterate natively before abrupt termination.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if logDDR {
		log.Printf("[DDR] Initiating extended bootstrap for upstream %s via %s", expectedHost, u.Proto)
	}

	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(targetURL, "{client-name}", "bootstrap")
		expectedHost = strings.ReplaceAll(expectedHost, "{client-name}", "bootstrap")
	}

	var targets []string
	if len(u.dialAddrs) > 0 {
		targets = append(targets, u.dialAddrs...)
	} else if len(u.BootstrapIPs) > 0 {
		_, port := parseHostPort(u.RawURL, u.Proto)
		for _, ip := range u.BootstrapIPs {
			targets = append(targets, net.JoinHostPort(ip, port))
		}
	} else {
		_, port := parseHostPort(u.RawURL, u.Proto)
		targets = []string{net.JoinHostPort(expectedHost, port)}
	}

	// [FEAT] Wrap dial and query executions strictly into an independent closure natively.
	// Permits dynamic extraction of both _dns.resolver.arpa and ?echdomain parameters 
	// organically without polluting the transport logic arrays.
	sendProbe := func(qName string, qType uint16) (*dns.Msg, error) {
		req := new(dns.Msg)
		req.SetQuestion(qName, qType)
		req.RecursionDesired = true

		opt := &dns.OPT{
			Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
		}
		opt.SetUDPSize(4096)
		req.Extra = append(req.Extra, opt)

		// Suppress ECS mappings forcefully during external bootstrap probes
		fwd := prepareForwardQuery(req, true, nil, netip.Addr{})

		fwdBytes, packErr := fwd.Pack()
		if packErr != nil {
			if logDDR {
				log.Printf("[DDR] Failed to pack SVCB/HTTPS query payload: %v", packErr)
			}
			return nil, packErr
		}

		var resp *dns.Msg
		var err error

		// Isolate the DDR fetch to completely ephemeral transports.
		// Iterate through all identified target boundaries until successful.
		for _, dialAddr := range targets {
			err = nil
			resp = nil

			// [SECURITY/FIX] Dynamically inject strict boundary contexts per dial 
			// to ensure tarpitted connections do not instantly sever parallel targets.
			dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)

			switch u.Proto {
			case "dot":
				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = expectedHost
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
				// If UpgradeDoH3 is enabled, attempt to run DoH3 (HTTP/3 over QUIC) discovery first.
				// Prevents protocol deadlocks if the upstream server strictly rejects HTTP/2.
				if cfg.Server.UpgradeDoH3 {
					tlsConfH3 := getHardenedTLSConfig()
					tlsConfH3.ServerName = expectedHost
					trH3 := &http3.Transport{
						TLSClientConfig: tlsConfH3,
						QUICConfig: &quic.Config{
							HandshakeIdleTimeout: 3 * time.Second,
						},
						Dial: func(dCtx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
							return quic.DialAddrEarly(dCtx, dialAddr, tlsCfg, qCfg)
						},
					}
					clientH3 := &http.Client{Timeout: 5 * time.Second, Transport: trH3}
					
					hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(fwdBytes))
					if reqErr == nil {
						hReq.Header.Set("Content-Type", "application/dns-message")
						hReq.Header.Set("Accept", "application/dns-message")
						
						var httpResp *http.Response
						httpResp, err = clientH3.Do(hReq)
						if err == nil {
							if httpResp.StatusCode == http.StatusOK {
								resp, err = readDDRPayload(httpResp.Body)
							} else {
								err = fmt.Errorf("http status %d", httpResp.StatusCode)
							}
							httpResp.Body.Close()
						}
					}
					trH3.Close()
					
					if err == nil && resp != nil {
						dialCancel()
						break
					}
				}

				// Fallback to standard HTTP/2 over TCP discovery
				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = expectedHost
				tr := &http.Transport{
					TLSClientConfig:   tlsConf,
					ForceAttemptHTTP2: true,
					// [SECURITY/FIX] Explicitly disable keep-alives since this is a one-shot probe.
					// This natively prevents ephemeral Go network pollers from leaking idle sockets globally.
					DisableKeepAlives: true, 
				}
				
				// [SECURITY/FIX] Definitively sever any lingering background HTTP/2 goroutines 
				// natively. Prevents transport connections from abandoning threads.
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
				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = expectedHost
				tr := &http3.Transport{
					TLSClientConfig: tlsConf,
					QUICConfig: &quic.Config{
						HandshakeIdleTimeout: 3 * time.Second,
					},
					Dial: func(dCtx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
						return quic.DialAddrEarly(dCtx, dialAddr, tlsCfg, qCfg)
					},
				}
				client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
				
				hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(fwdBytes))
				if reqErr != nil {
					err = reqErr
					tr.Close() 
					dialCancel()
					continue
				}
				
				hReq.Header.Set("Content-Type", "application/dns-message")
				hReq.Header.Set("Accept", "application/dns-message")
				
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
				
				tr.Close()
			case "doq":
				tlsConf := getHardenedTLSConfig()
				tlsConf.ServerName = expectedHost
				tlsConf.NextProtos = []string{"doq"}
				
				var conn *quic.Conn
				conn, err = quic.DialAddrEarly(dialCtx, dialAddr, tlsConf, &quic.Config{})
				if err == nil {
					var stream *quic.Stream
					stream, err = conn.OpenStreamSync(dialCtx)
					if err == nil && len(fwdBytes) > 65535 {
						// [SECURITY/FIX 2.51.0] 16-bit length-prefix guard (S-C).
						err = fmt.Errorf("ddr probe too large for the RFC 9250 length prefix: %d bytes", len(fwdBytes))
					} else if err == nil {
						lenBuf := make([]byte, 2)
						binary.BigEndian.PutUint16(lenBuf, uint16(len(fwdBytes)))
						stream.Write(lenBuf)
						stream.Write(fwdBytes)
						stream.Close() // Send FIN to prevent strict QUIC servers from stalling
						
						if _, readErr := io.ReadFull(stream, lenBuf); readErr == nil {
							respLen := binary.BigEndian.Uint16(lenBuf)
							if respLen > 0 {
								respBuf := make([]byte, respLen)
								if _, rErr := io.ReadFull(stream, respBuf); rErr == nil {
									resp = new(dns.Msg)
									err = resp.Unpack(respBuf)
								} else {
									err = fmt.Errorf("read payload: %v", rErr)
								}
							} else {
								err = errors.New("zero length response")
							}
						} else {
							err = fmt.Errorf("read length: %v", readErr)
						}
					}
					conn.CloseWithError(0, "ddr complete")
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

	// 1. Initial DDR Probe (_dns.resolver.arpa) for ALPN bounds and default ECH configurations
	if logDDR {
		log.Printf("[DDR] Executing _dns.resolver.arpa SVCB query against %s using native protocol %s", expectedHost, u.Proto)
	}
	resp, err := sendProbe("_dns.resolver.arpa.", dns.TypeSVCB)

	if err != nil {
		if logDDR {
			log.Printf("[DDR] Failed to query upstream %s for DDR parameters via DNS: %v", expectedHost, err)
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

		// Deep-inspect the answer payload for structural DDR parameters.
		for _, rr := range resp.Answer {
			if svcb, ok := rr.(*dns.SVCB); ok {
				if logDDR {
					log.Printf("[DDR] Found SVCB record for Target: %s (Expected: %s)", svcb.Target, expectedHostFqdn)
				}
				
				// Validate target constraints natively against strict/loose/apex/any mode
				isMatch := false
				targetClean := strings.TrimSuffix(svcb.Target, ".")
				expectedClean := strings.TrimSuffix(expectedHostFqdn, ".")

				switch cfg.Server.HostnameECH {
				case "any":
					// [SECURITY] "any" universally accepts the returned SVCB target, including "."
					// Use with caution as it bypasses strict hostname identity validation.
					isMatch = true
				case "apex":
					// [SECURITY] "apex" validates that both the expected host and the discovered
					// target share the exact same eTLD+1 domain boundary.
					if svcb.Target == "." {
						isMatch = true
					} else {
						targetApex, _ := extractETLDPlusOne(targetClean)
						expectedApex, _ := extractETLDPlusOne(expectedClean)
						if targetApex != "" && targetApex == expectedApex {
							isMatch = true
						}
					}
				case "loose":
					// [SECURITY] "loose" accepts an exact hostname match or the standard "." fallback.
					if svcb.Target == expectedHostFqdn || svcb.Target == "." {
						isMatch = true
					}
				default: // "strict"
					// [SECURITY] "strict" mandates an exact FQDN match. Fallback targets (".") are rejected.
					if svcb.Target == expectedHostFqdn && svcb.Target != "." {
						isMatch = true
					}
				}

				if isMatch {
					for _, v := range svcb.Value {
						if e, ok := v.(*dns.SVCBECHConfig); ok {
							extractedECH = e.ECH
						}
						if alpn, ok := v.(*dns.SVCBAlpn); ok {
							for _, a := range alpn.Alpn {
								if a == "h3" {
									supportsH3 = true
								}
							}
						}
					}
				} else {
					if logDDR {
						log.Printf("[DDR] Skipping SVCB record: Target mismatch (Target: %s, Expected: %s, Mode: %s)", svcb.Target, expectedHostFqdn, cfg.Server.HostnameECH)
					}
				}
			}
		}
	}

	// 2. Explicit ECH Domain Probe natively
	// Triggers seamlessly if administrators designated `?echdomain=` inside the URL.
	if echDomain != "" {
		if logDDR {
			log.Printf("[DDR] Executing explicit ECH discovery query for %s (HTTPS)", echDomain)
		}
		respEch, errEch := sendProbe(dns.Fqdn(echDomain), dns.TypeHTTPS)
		if errEch == nil && respEch != nil {
			for _, rr := range respEch.Answer {
				var values []dns.SVCBKeyValue
				if https, ok := rr.(*dns.HTTPS); ok {
					values = https.Value
				} else if svcb, ok := rr.(*dns.SVCB); ok {
					values = svcb.Value
				}
				for _, v := range values {
					if e, ok := v.(*dns.SVCBECHConfig); ok {
						extractedECH = e.ECH // OVERRIDE the payload extracted previously natively
					}
				}
			}
		} else if logDDR {
			log.Printf("[DDR] Explicit ECH discovery query failed: %v", errEch)
		}
	}

	if logDDR {
		if len(extractedECH) > 0 {
			log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) via DNS SVCB/HTTPS for %s", len(extractedECH), expectedHost)
		}
		if supportsH3 {
			log.Printf("[DDR] Successfully discovered HTTP/3 (ALPN: h3) support via DNS SVCB for %s", expectedHost)
		}
	}

	// [FEAT] Out-of-Band L7 Discovery Fallback
	// If the DNS firewall dropped the _dns.resolver.arpa request or stripped the SVCB payload,
	// we bypass the DNS layer entirely and attempt to fetch the keys natively via standard HTTPS.
	if len(extractedECH) == 0 && (u.Proto == "doh" || u.Proto == "doh3") {
		l7Host := expectedHost
		if echDomain != "" {
			l7Host = echDomain
		}

		if logDDR {
			log.Printf("[DDR] No ECH configuration obtained via DNS SVCB for %s. Attempting Out-of-Band L7 fallback via /.well-known/origin-svcb", l7Host)
		}
		
		// 1. Try draft-ietf-tls-wkech-11 (/.well-known/origin-svcb) natively
		wkECH, wkErr := fetchWellKnownFallback(ctx, l7Host, targets, u.Proto == "doh3", "/.well-known/origin-svcb", true)
		if wkErr == nil && len(wkECH) > 0 {
			extractedECH = wkECH
			if logDDR {
				log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) for %s via Out-of-Band L7 /.well-known/origin-svcb", len(extractedECH), l7Host)
			}
		} else {
			if logDDR {
				log.Printf("[DDR] L7 fallback via /.well-known/origin-svcb failed for %s: %v. Attempting legacy /.well-known/ech", l7Host, wkErr)
			}
			
			// 2. Safely fallback to legacy (/.well-known/ech) binary discovery
			wkECH, wkErr = fetchWellKnownFallback(ctx, l7Host, targets, u.Proto == "doh3", "/.well-known/ech", false)
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

	if len(extractedECH) > 0 || supportsH3 {
		return extractedECH, supportsH3
	}

	if logDDR {
		log.Printf("[DDR] No valid ECH/ALPN configurations discovered for upstream %s", expectedHost)
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Native UDP Bootstrapping Constraints
// ---------------------------------------------------------------------------

// bootstrapResolveECH resolves host against the provided servers specifically 
// interrogating `HTTPS/SVCB` structural records to extract `SVCBECHConfig`.
// Provides auto-bootstrapping capabilities for Encrypted Client Hello structures natively. 
// It also extracts `ipv4hint` and `ipv6hint` to preemptively populate routing tables, 
// and `alpn` parameters to discover proactive DoH3 upgrade paths natively.
func bootstrapResolveECH(host, echDomain string, servers []*Upstream) ([]byte, []string, bool) {
	var ech []byte
	var hints []string
	var supportsH3 bool
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
		m.Extra = append(m.Extra, opt)

		for _, u := range servers {
			// [SECURITY/FIX] Guard against uninitialized pointers natively during parallel discovery loops.
			if u == nil { continue }
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			
			// Explicitly bypass ECS constraints dynamically via null netip.Addr injections for bootstrap probing
			resp, _, err := u.Exchange(ctx, m, "bootstrap", "bootstrap", netip.Addr{})
			cancel()
			
			if err != nil || resp == nil { continue }
			
			for _, rr := range resp.Answer {
				var values []dns.SVCBKeyValue
				
				if https, ok := rr.(*dns.HTTPS); ok {
					values = https.Value
				} else if svcb, ok := rr.(*dns.SVCB); ok {
					values = svcb.Value
				} else {
					continue
				}
				
				for _, v := range values {
					if e, ok := v.(*dns.SVCBECHConfig); ok {
						ech = e.ECH
					}
					if !extractECHOnly {
						if alpn, ok := v.(*dns.SVCBAlpn); ok {
							for _, a := range alpn.Alpn {
								if a == "h3" {
									supportsH3 = true
								}
							}
						}
						if v4, ok := v.(*dns.SVCBIPv4Hint); ok {
							if ipVersionSupport == "ipv6" { continue }
							for _, ip := range v4.Hint {
								ipStr := ip.String()
								if _, dup := seenMap[ipStr]; !dup {
									seenMap[ipStr] = struct{}{}
									hints = append(hints, ipStr)
								}
							}
						}
						if v6, ok := v.(*dns.SVCBIPv6Hint); ok {
							if ipVersionSupport == "ipv4" { continue }
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

	// 1. Initial lookup to populate ALPN bounds and extract generalized defaults organically
	queryHTTPS(host, false)
	
	// 2. Explicit structural override targeting the provided `?echdomain=` payload 
	if echDomain != "" && echDomain != host {
		queryHTTPS(echDomain, true)
	}

	return ech, hints, supportsH3
}

// ---------------------------------------------------------------------------
// Application Layer (L7) Out-of-Band Fallback
// ---------------------------------------------------------------------------

// fetchWellKnownFallback performs an Out-of-Band (Application Layer) retrieval of the
// Encrypted Client Hello configuration payload. It actively bypasses DNS filtering
// by connecting directly to the specified URI (e.g. /.well-known/origin-svcb) natively via HTTPS.
// Accepts an isJSON boolean to parse structured endpoints or legacy raw binary payloads dynamically.
func fetchWellKnownFallback(ctx context.Context, expectedHost string, targets []string, tryH3 bool, uriPath string, isJSON bool) ([]byte, error) {
	wkURL := "https://" + expectedHost + uriPath
	
	var lastErr error
	for _, dialAddr := range targets {
		dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)

		var client *http.Client
		var trH3 *http3.Transport
		var trH2 *http.Transport
		
		if tryH3 && cfg.Server.UpgradeDoH3 {
			tlsConfH3 := getHardenedTLSConfig()
			tlsConfH3.ServerName = expectedHost
			
			trH3 = &http3.Transport{
				TLSClientConfig: tlsConfH3,
				QUICConfig: &quic.Config{
					HandshakeIdleTimeout: 3 * time.Second,
				},
				Dial: func(dCtx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
					return quic.DialAddrEarly(dCtx, dialAddr, tlsCfg, qCfg)
				},
			}
			client = &http.Client{Timeout: 5 * time.Second, Transport: trH3}
		} else {
			tlsConf := getHardenedTLSConfig()
			tlsConf.ServerName = expectedHost
			
			trH2 = &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: true,
				DisableKeepAlives: true,
			}
			
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			trH2.DialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(dCtx, network, dialAddr)
			}
			client = &http.Client{Timeout: 5 * time.Second, Transport: trH2}
		}

		req, err := http.NewRequestWithContext(dialCtx, http.MethodGet, wkURL, nil)
		if err != nil {
			dialCancel()
			if trH3 != nil { trH3.Close() }
			if trH2 != nil { trH2.CloseIdleConnections() }
			lastErr = err
			continue
		}
		
		req.Header.Set("User-Agent", cfg.Server.UserAgent)
		req.Header.Set("Accept", "application/json, application/echconfig-list, application/octet-stream")

		resp, err := client.Do(req)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				// ECH configs are typically very small (~1KB).
				// Bound memory limits tightly to prevent L7 memory exhaustion attacks natively.
				limitReader := io.LimitReader(resp.Body, 65536 + 1)
				bodyBytes, _ := io.ReadAll(limitReader)
				resp.Body.Close()
				dialCancel()
				
				if trH3 != nil { trH3.Close() }
				if trH2 != nil { trH2.CloseIdleConnections() }
				
				// Evaluate Limit exhaustion natively to flag silent truncations
				if limitReader.(*io.LimitedReader).N == 0 {
					lastErr = errors.New("security constraint: L7 fallback payload exceeded 64KB maximum buffer capacity")
					continue
				}
				
				if len(bodyBytes) == 0 {
					lastErr = errors.New("empty payload returned")
					continue
				}

				// Dynamically extract the ECH structure from draft-ietf-tls-wkech JSON array natively.
				if isJSON {
					var svcbResp struct {
						Endpoints []struct {
							ECH string `json:"ech"`
						} `json:"endpoints"`
					}
					if err := json.Unmarshal(bodyBytes, &svcbResp); err == nil {
						for _, ep := range svcbResp.Endpoints {
							if ep.ECH != "" {
								// Base64 specifications often differ across CDN implementations. 
								// Evaluate multiple pad combinations organically to guarantee decode success.
								echBytes, decErr := decodeBase64Flex(ep.ECH)
								if decErr == nil && len(echBytes) > 0 {
									return echBytes, nil
								}
							}
						}
						lastErr = errors.New("no valid ECH config in origin-svcb endpoints")
					} else {
						lastErr = fmt.Errorf("failed to parse origin-svcb JSON: %v", err)
					}
					continue
				}
				
				// Standard binary response
				return bodyBytes, nil
			} else {
				resp.Body.Close()
				lastErr = fmt.Errorf("http status %d", resp.StatusCode)
			}
		} else {
			lastErr = err
		}
		dialCancel()
		if trH3 != nil { trH3.Close() }
		if trH2 != nil { trH2.CloseIdleConnections() }
	}
	
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("no responsive targets for L7 discovery")
}

