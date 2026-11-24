/*
File:    ddr.go
Version: 1.14.0
Last Updated: 24-Nov-2026 12:30 CET

Description:
  Discovery of Designated Resolvers (DDR) — RFC 9462 / RFC 9461.
  Intercepts `_dns.resolver.arpa` SVCB and resolver-hostname A/AAAA/HTTPS
  queries locally without upstream forwarding.

Changes:
  1.14.0 - [SECURITY/FIX] Enforced `ipVersionSupport` (`ipv4` / `ipv6`) in
           `ddrAddrs` and `handleDDR` so disabled address families are never
           synthesized or leaked via SVCB `ipv4hint`/`ipv6hint` or `A`/`AAAA` answers.
  1.13.0 - [FIX] Applied `applyRcodeOnlyWireTTL` to all DDR responses so
           `min_ttl` and `max_ttl` bounds apply consistently.
  1.12.0 - [FEAT] Applied `applyRcodeOnlyWireTTL` on DDR `NODATA` responses.
  1.11.0 - [SECURITY/FIX] Replaced `PreserveEDNS0` with `enforceUDPDefenses` and
           added `IncrReturnCode` telemetry across all DDR responses.
  1.10.0 - [FEAT] Added `clientIP` and `protoEndpoint` to `handleDDR` and emitted
           concise query/answer logs via `logQuerySimple` when `logSimple` is enabled.
  1.9.0  - [SECURITY/FIX] Added RFC 2308 negative SOA record on DDR NODATA responses
           and prevented emitting `HTTPS` SVCB with `Port: 0` when DoH is disabled.
  1.8.0  - [TIER 2] Collapsed DoH/DoT/DoQ SVCB builders into `ddrServices()`.
  1.7.0  - [REFACTOR] Applied `PreserveEDNS0` and `RcodeStr`.
  1.6.0  - [LOGGING] Bound DDR intercepts to `logDDR`.
*/

package main

import (
	"log"
	"net"
	"net/netip"

	"github.com/miekg/dns"
)

type ddrService struct {
	alpn    []string
	port    uint16
	dohPath string
}

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

func handleDDR(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientIP, clientID, protocol, protoEndpoint string) bool {
	if !cfg.Server.DDR.Enabled {
		return false
	}

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
		applyRcodeOnlyWireTTL(resp)

		IncrReturnCode(resp.Rcode, false)
		enforceUDPDefenses(r, resp, protocol, netip.Addr{}, nil)
		w.WriteMsg(resp)
		msgPool.Put(resp)

		if logQueries && logSimple {
			rcStr := "NOERROR"
			if len(services) == 0 {
				rcStr = "NOERROR (NODATA)"
			}
			logQuerySimple(protoEndpoint, clientIP, q.Name, "SVCB", rcStr, "DDR", false)
		} else if logDDR {
			log.Printf("[DDR] [%s] %s -> _dns.resolver.arpa SVCB | DDR DISCOVERY | NOERROR", protocol, clientID)
		}
		return true
	}

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
		if ipVersionSupport != "ipv6" && len(ipv4s) > 0 {
			resp.Answer = make([]dns.RR, 0, len(ipv4s))
			for _, ip := range ipv4s {
				if v4 := ip.To4(); v4 != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
						A:   v4,
					})
				}
			}
		}

	case dns.TypeAAAA:
		label = "DDR AAAA"
		if ipVersionSupport != "ipv4" && len(ipv6s) > 0 {
			resp.Answer = make([]dns.RR, 0, len(ipv6s))
			for _, ip := range ipv6s {
				if ip.To4() == nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
						AAAA: ip.To16(),
					})
				}
			}
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
	applyRcodeOnlyWireTTL(resp)

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
	if ipVersionSupport != "ipv6" {
		ipv4s = ddrIPv4
	}
	if ipVersionSupport != "ipv4" {
		ipv6s = ddrIPv6
	}
	if (ipVersionSupport == "ipv6" || len(ipv4s) > 0) && (ipVersionSupport == "ipv4" || len(ipv6s) > 0) {
		return
	}
	local := localAddrIP(w)
	if local == nil {
		return
	}
	if ipVersionSupport != "ipv6" && len(ipv4s) == 0 {
		if v4 := local.To4(); v4 != nil {
			ipv4s = []net.IP{v4}
		}
	}
	if ipVersionSupport != "ipv4" && len(ipv6s) == 0 {
		if local.To4() == nil {
			ipv6s = []net.IP{local}
		}
	}
	return
}
