/*
File:    ddr.go
Version: 1.11.0
Last Updated: 05-Nov-2026 08:40 CET

Description:
  Discovery of Designated Resolvers (DDR) — RFC 9462 / RFC 9461.
  Intercepts two query shapes and returns synthetic responses without
  forwarding to any upstream:

    1a. _dns.resolver.arpa SVCB — DDR service discovery (RFC 9462).
        Advertises DoH, DoT, and DoQ endpoints via SVCB records with
        IP hints and port parameters. Automatically advertises ECHConfigList
        if configured securely at startup.

    1b. Resolver hostname A / AAAA / HTTPS — RFC 9461.
        Answers address queries for our own resolver hostnames (the ones
        listed under server.ddr.hostnames: or authorized TLS SANs) so clients
        can verify and upgrade to encrypted transport.

  handleDDR is called from ProcessDNS (process.go) after policy checks but
  before identity, cache, and upstream. Returns true when the query was
  handled so ProcessDNS can return immediately.

  localAddrIP and ddrAddrs live here because they exist solely to populate
  the IP hints in DDR responses.

Changes:
  1.11.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with `enforceUDPDefenses` and
           added `IncrReturnCode` telemetry across all DDR responses so UDP
           fragmentation bounds (1232B) and EDNS0 option sanitization are
           strictly enforced on DDR answers.
  1.10.0 - [FEAT] Added `clientIP` and `protoEndpoint` to `handleDDR` and emitted
           concise query/answer logs via `logQuerySimple` when `logSimple` is enabled.
  1.9.0  - [SECURITY/FIX] Added RFC 2308 negative SOA record on DDR NODATA responses
           and prevented emitting a broken `HTTPS` SVCB record with `Port: 0` when
           no DoH listener is configured.
  1.8.0  - [TIER 2] Collapsed the three near-identical DoH/DoT/DoQ SVCB builders
           into one table-driven loop over ddrServices().
  1.7.0  - [REFACTOR] Applied PreserveEDNS0 and RcodeStr to deduplicate telemetry.
  1.6.0  - [LOGGING] Bound DDR intercepts to logDDR rather than logQueries.
*/

package main

import (
	"log"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

// ddrService describes one advertised encrypted endpoint.
type ddrService struct {
	alpn    []string
	port    uint16
	dohPath string // empty for DoT/DoQ
}

// ddrServices returns the enabled endpoints in advertisement order.
func ddrServices() []ddrService {
	var out []ddrService
	if ddrDoHPort > 0 {
		out = append(out, ddrService{
			alpn:    []string{"h2", "h3", "http/1.1"},
			port:    ddrDoHPort,
			dohPath: "/dns-query{?dns}",
		})
	}
	if ddrDoTPort > 0 {
		out = append(out, ddrService{alpn: []string{"dot"}, port: ddrDoTPort})
	}
	if ddrDoQPort > 0 {
		out = append(out, ddrService{alpn: []string{"doq"}, port: ddrDoQPort})
	}
	return out
}

// handleDDR intercepts _dns.resolver.arpa SVCB and resolver-hostname queries
// when DDR is enabled. Returns true when the query was fully handled.
func handleDDR(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP, clientID, protocol, protoEndpoint string) bool {
	if !cfg.Server.DDR.Enabled {
		return false
	}

	// 1a. _dns.resolver.arpa SVCB — service discovery per RFC 9462.
	if qNameTrimmed == "_dns.resolver.arpa" && q.Qtype == dns.TypeSVCB {
		ipv4s, ipv6s := ddrAddrs(w)

		resp := msgPool.Get().(*dns.Msg)
		*resp = dns.Msg{}
		resp.SetReply(r)
		resp.Authoritative = true

		services := ddrServices()
		resp.Answer = make([]dns.RR, 0, len(services))

		target := "."
		if len(ddrHostnamesList) > 0 {
			target = dns.Fqdn(ddrHostnamesList[0])
		}

		for i, svc := range services {
			rec := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: syntheticTTL},
				Priority: uint16(i + 1),
				Target:   target,
			}
			rec.Value = append(rec.Value, &dns.SVCBAlpn{Alpn: svc.alpn})
			rec.Value = append(rec.Value, &dns.SVCBPort{Port: svc.port})
			if svc.dohPath != "" {
				rec.Value = append(rec.Value, &dns.SVCBDoHPath{Template: svc.dohPath})
			}
			if len(ddrECHConfig) > 0 {
				rec.Value = append(rec.Value, &dns.SVCBECHConfig{ECH: ddrECHConfig})
			}
			appendIPHints(rec, ipv4s, ipv6s)
			resp.Answer = append(resp.Answer, rec)
		}

		if len(resp.Answer) == 0 {
			SetNegativeSOA(resp, q.Name, syntheticTTL)
		}

		IncrReturnCode(resp.Rcode, false)
		enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
		w.WriteMsg(resp)
		msgPool.Put(resp)

		if logQueries && logSimple {
			logQuerySimple(protoEndpoint, clientIP, q.Name, "SVCB", "NOERROR", "DDR", false)
		} else if logDDR {
			log.Printf("[DDR] [%s] %s -> _dns.resolver.arpa SVCB | DDR DISCOVERY | NOERROR", protocol, clientID)
		}
		return true
	}

	// 1b. Resolver hostname A / AAAA / HTTPS — RFC 9461.
	if !ddrHostnames[qNameTrimmed] {
		return false
	}

	ipv4s, ipv6s := ddrAddrs(w)
	resp := msgPool.Get().(*dns.Msg)
	*resp = dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = true
	var label string

	switch q.Qtype {
	case dns.TypeA:
		label = "DDR A"
		resp.Answer = make([]dns.RR, 0, len(ipv4s))
		for _, ip := range ipv4s {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
				A:   ip.To4(),
			})
		}

	case dns.TypeAAAA:
		label = "DDR AAAA"
		resp.Answer = make([]dns.RR, 0, len(ipv6s))
		for _, ip := range ipv6s {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
				AAAA: ip.To16(),
			})
		}

	case dns.TypeHTTPS:
		if ddrDoHPort > 0 {
			label = "DDR HTTPS"
			svcb := &dns.HTTPS{SVCB: dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: syntheticTTL},
				Priority: 1,
				Target:   ".",
			}}
			svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3", "http/1.1"}})
			svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: ddrDoHPort})
			svcb.Value = append(svcb.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
			if len(ddrECHConfig) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBECHConfig{ECH: ddrECHConfig})
			}
			appendIPHints(&svcb.SVCB, ipv4s, ipv6s)
			resp.Answer = []dns.RR{svcb}
		} else {
			resp.SetRcode(r, dns.RcodeSuccess)
			label = "DDR NODATA"
		}

	default:
		resp.SetRcode(r, dns.RcodeSuccess)
		label = "DDR NODATA"
	}

	if len(resp.Answer) == 0 {
		SetNegativeSOA(resp, q.Name, syntheticTTL)
	}

	IncrReturnCode(resp.Rcode, false)
	enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
	w.WriteMsg(resp)

	if logQueries && logSimple {
		rcStr := RcodeStr(resp.Rcode)
		if label == "DDR NODATA" || len(resp.Answer) == 0 {
			rcStr = "NOERROR (NODATA)"
		}
		logQuerySimple(protoEndpoint, clientIP, q.Name, qtypeName(q.Qtype), rcStr, "DDR", false)
	} else if logDDR {
		log.Printf("[DDR] [%s] %s -> %s %s | %s | %s",
			protocol, clientID, q.Name, qtypeName(q.Qtype), label, RcodeStr(resp.Rcode))
	}
	msgPool.Put(resp)
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func appendIPHints(svcb *dns.SVCB, ipv4s, ipv6s []net.IP) {
	if len(ipv4s) > 0 {
		svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
	}
	if len(ipv6s) > 0 {
		svcb.Value = append(svcb.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
	}
}

func localAddrIP(w dns.ResponseWriter) net.IP {
	addr := w.LocalAddr()
	if addr == nil {
		return nil
	}
	var ip net.IP
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip = a.IP
	case *net.TCPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			ip = net.ParseIP(addr.String())
		} else {
			ip = net.ParseIP(host)
		}
	}
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	return ip
}

func ddrAddrs(w dns.ResponseWriter) (ipv4s, ipv6s []net.IP) {
	ipv4s = ddrIPv4
	ipv6s = ddrIPv6
	if len(ipv4s) > 0 && len(ipv6s) > 0 {
		return
	}
	local := localAddrIP(w)
	if local == nil {
		return
	}
	if len(ipv4s) == 0 {
		if v4 := local.To4(); v4 != nil {
			ipv4s = []net.IP{v4}
		}
	}
	if len(ipv6s) == 0 {
		if local.To4() == nil {
			ipv6s = []net.IP{local}
		}
	}
	return
}
