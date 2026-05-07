/*
File:    upstream_ddr.go
Version: 2.39.0
Updated: 06-May-2026 10:28 CEST

Description:
  Discovery of Designated Resolvers (DDR), Encrypted Client Hello (ECH), and 
  Application-Layer Protocol Negotiation (ALPN) extraction mechanics. Interrogates 
  upstream resolvers directly to autonomously secure encrypted TLS channels, 
  map topological dependencies, and upgrade transports natively.

  Extracted from upstream.go to isolate network probing and bootstrap capabilities 
  away from the primary structural configurations.

Changes:
  2.39.0 - [SECURITY/FIX] Severely hardened CWE-400 Memory Exhaustion Prevention boundaries.
           `io.LimitReader` allocations processing upstream payload responses during DDR
           discovery now intelligently probe exactly 1 byte past the 64KB threshold limit
           to autonomously detect truncation attempts, preventing infinite datastreams 
           from escaping bounds undetected natively.
  2.38.0 - [SECURITY/FIX] Resolved a severe Memory Exhaustion (CWE-400) vulnerability 
           in the HTTP/2 and HTTP/3 DDR polling engines. `io.ReadAll` is now strictly 
           guarded by a 64KB `io.LimitReader` to prevent malicious upstreams from OOM 
           crashing the router with infinite garbage streams.
         - [SECURITY/FIX] Hardened DoQ QUIC stream consumption natively. Intercepts 
           ignored `io.ReadFull` errors to prevent `Unpack()` from executing against 
           poisoned or incomplete zero-byte payloads.
  2.37.0 - [SECURITY/FIX] Addressed connection leakage vulnerabilities in DDR probing. 
           Ephemeral `http.Client` structures dynamically allocated during `DoH` and 
           `DoH3` SVCB discovery loops previously abandoned their transport bindings, 
           leaving idle sockets marooned globally. `DisableKeepAlives` is now explicitly 
           enforced for DoH payloads, and `quic.Transport.Close()` is natively executed 
           upon loop termination to surgically seal HTTP/3 memory footprints.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ---------------------------------------------------------------------------
// SVCB / DDR Upstream Probing
// ---------------------------------------------------------------------------

// fetchDDRParams performs a one-off Discovery of Designated Resolvers (DDR) query
// directly against the upstream using its native encrypted protocol (DoT, DoH, DoQ).
// It requests _dns.resolver.arpa (SVCB) to extract ECH keys and ALPN parameters dynamically.
// Validates target constraints according to the cfg.Server.HostnameECH strictness setting natively.
func fetchDDRParams(u *Upstream, expectedHost string) ([]byte, bool) {
	// [SECURITY/FIX] Expand global timeout envelope to guarantee all targets have time 
	// to successfully iterate natively before abrupt termination.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log.Printf("[DDR] Initiating extended bootstrap for upstream %s via %s", expectedHost, u.Proto)

	req := new(dns.Msg)
	req.SetQuestion("_dns.resolver.arpa.", dns.TypeSVCB)
	req.RecursionDesired = true

	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: dns.ClassINET},
	}
	opt.SetUDPSize(4096)
	req.Extra = append(req.Extra, opt)

	fwd := prepareForwardQuery(req, true)

	var resp *dns.Msg
	var err error

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

	log.Printf("[DDR] Executing _dns.resolver.arpa SVCB query against %s using native protocol %s", expectedHost, u.Proto)

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
			tlsConf := getHardenedTLSConfig()
			tlsConf.ServerName = expectedHost
			tr := &http.Transport{
				TLSClientConfig:   tlsConf,
				ForceAttemptHTTP2: true,
				// [SECURITY/FIX] Explicitly disable keep-alives since this is a one-shot probe.
				// This natively prevents ephemeral Go network pollers from leaking idle sockets globally.
				DisableKeepAlives: true, 
			}
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			tr.DialContext = func(dCtx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(dCtx, network, dialAddr)
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: tr}
			
			buf, _ := fwd.Pack()
			hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(buf))
			if reqErr != nil {
				err = reqErr
				dialCancel()
				continue
			}
			
			hReq.Header.Set("Content-Type", "application/dns-message")
			hReq.Header.Set("Accept", "application/dns-message")
			
			var httpResp *http.Response
			httpResp, err = client.Do(hReq)
			if err == nil {
				if httpResp.StatusCode == http.StatusOK {
					// [SECURITY/FIX] CWE-400 Memory Exhaustion Prevention
					// Prevent malicious upstreams from flooding the router RAM via infinite streams natively
					limitReader := io.LimitReader(httpResp.Body, 65536 + 1)
					bodyBytes, _ := io.ReadAll(limitReader)
					if len(bodyBytes) > 65536 {
						err = fmt.Errorf("security constraint: DDR payload exceeded 64KB maximum buffer capacity")
					} else {
						resp = new(dns.Msg)
						err = resp.Unpack(bodyBytes)
					}
				} else {
					err = fmt.Errorf("http status %d", httpResp.StatusCode)
				}
				httpResp.Body.Close()
			}
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
			
			buf, _ := fwd.Pack()
			hReq, reqErr := http.NewRequestWithContext(dialCtx, http.MethodPost, targetURL, bytes.NewReader(buf))
			if reqErr != nil {
				err = reqErr
				tr.Close() // [SECURITY/FIX] Clean up HTTP/3 transport
				dialCancel()
				continue
			}
			
			hReq.Header.Set("Content-Type", "application/dns-message")
			hReq.Header.Set("Accept", "application/dns-message")
			
			var httpResp *http.Response
			httpResp, err = client.Do(hReq)
			if err == nil {
				if httpResp.StatusCode == http.StatusOK {
					// [SECURITY/FIX] CWE-400 Memory Exhaustion Prevention
					// Prevent malicious upstreams from flooding the router RAM via infinite streams natively
					limitReader := io.LimitReader(httpResp.Body, 65536 + 1)
					bodyBytes, _ := io.ReadAll(limitReader)
					if len(bodyBytes) > 65536 {
						err = fmt.Errorf("security constraint: DDR payload exceeded 64KB maximum buffer capacity")
					} else {
						resp = new(dns.Msg)
						err = resp.Unpack(bodyBytes)
					}
				} else {
					err = fmt.Errorf("http status %d", httpResp.StatusCode)
				}
				httpResp.Body.Close()
			}
			
			// [SECURITY/FIX] Explicitly terminate underlying QUIC connections 
			// natively bounding UDP socket allocations safely on the hot path.
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
				if err == nil {
					buf, _ := fwd.Pack()
					lenBuf := make([]byte, 2)
					binary.BigEndian.PutUint16(lenBuf, uint16(len(buf)))
					stream.Write(lenBuf)
					stream.Write(buf)
					stream.Close() // Send FIN to prevent strict QUIC servers from stalling
					
					if _, readErr := io.ReadFull(stream, lenBuf); readErr == nil {
						respLen := binary.BigEndian.Uint16(lenBuf)
						if respLen > 0 {
							respBuf := make([]byte, respLen)
							// [SECURITY/FIX] Catch ignored ReadFull payload errors to prevent 
							// unpacking poisoned or incomplete zero-byte arrays natively.
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

		dialCancel() // Terminate inner ephemeral context

		if err == nil && resp != nil {
			break
		}
	}

	if err != nil {
		log.Printf("[DDR] Failed to query upstream %s for DDR parameters: %v", expectedHost, err)
		return nil, false
	}
	if resp == nil {
		log.Printf("[DDR] Received empty response from upstream %s", expectedHost)
		return nil, false
	}

	log.Printf("[DDR] Received response (RCODE: %s) with %d Answer records from %s", dns.RcodeToString[resp.Rcode], len(resp.Answer), expectedHost)

	expectedHostFqdn := dns.Fqdn(expectedHost)

	// Deep-inspect the answer payload for structural DDR parameters.
	for _, rr := range resp.Answer {
		if svcb, ok := rr.(*dns.SVCB); ok {
			log.Printf("[DDR] Found SVCB record for Target: %s (Expected: %s)", svcb.Target, expectedHostFqdn)
			
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
				// target share the exact same eTLD+1 domain boundary (e.g., dns.google and 8.8.8.8.dns.google).
				// Safely permits "." as a valid fallback if the apex matched originally.
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
				var extractedECH []byte
				var supportsH3 bool

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

				if len(extractedECH) > 0 {
					log.Printf("[DDR] Successfully extracted ECH Config payload (%d bytes) for %s", len(extractedECH), expectedHost)
				}
				if supportsH3 {
					log.Printf("[DDR] Successfully discovered HTTP/3 (ALPN: h3) support for %s", expectedHost)
				}
				
				if len(extractedECH) > 0 || supportsH3 {
					return extractedECH, supportsH3
				}
				log.Printf("[DDR] SVCB record matched target, but no useful parameters (ECH/ALPN) were found")
			} else {
				log.Printf("[DDR] Skipping SVCB record: Target mismatch (Target: %s, Expected: %s, Mode: %s)", svcb.Target, expectedHostFqdn, cfg.Server.HostnameECH)
			}
		}
	}

	log.Printf("[DDR] No valid ECH/ALPN configurations discovered for upstream %s", expectedHost)
	return nil, false
}

