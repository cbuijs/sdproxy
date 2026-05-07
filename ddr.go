/*
File:    ddr.go
Version: 1.5.0
Updated: 06-May-2026 11:58 CEST

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
  1.5.0 - [FEAT] Hardened DDR structural execution to natively select and enforce 
          `SVCB` Targets from dynamically populated `ddrHostnamesList` variables, 
          respecting TLS-certified boundaries automatically.
  1.4.0 - [PERF] Wired synthetic response instantiation natively into the zero-allocation 
          `msgPool`. Eradicates severe Garbage Collection (GC) thrashing if the 
          router is flooded with DDR discovery probes.
  1.3.0 - [SECURITY/FIX] Added EDNS0 OPT record preservation to DDR synthetic 
          responses to uphold RFC 6891 capabilities securely.
  1.2.0 - [SECURITY] Added native `ech=` payload injection to `SVCB` and `HTTPS` 
          responses to seamlessly propagate Encrypted Client Hello structures 
          to DDR-aware clients.
  1.1.0 - [LOG] Added explicit DNS Return Code string mapping to DDR logging lines.
*/

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/miekg/dns"
)

// handleDDR intercepts _dns.resolver.arpa SVCB and resolver-hostname queries
// when DDR is enabled. Returns true when the query was fully handled.
// clientID and protocol are used only in log lines.
func handleDDR(w dns.ResponseWriter, r *dns.Msg, q dns.Question, qNameTrimmed, clientID, protocol string) bool {
	if !cfg.Server.DDR.Enabled {
		return false
	}

	// 1a. _dns.resolver.arpa SVCB — service discovery per RFC 9462.
	if qNameTrimmed == "_dns.resolver.arpa" && q.Qtype == dns.TypeSVCB {
		ipv4s, ipv6s := ddrAddrs(w)
		resp         := msgPool.Get().(*dns.Msg)
		*resp         = dns.Msg{} // Zero fields safely
		resp.SetReply(r)
		resp.Authoritative = true
		resp.Answer         = make([]dns.RR, 0, 3) // DoH + DoT + DoQ
		priority           := uint16(1)

		// Natively select the premier verified Target from the combined global lists
		target := "."
		if len(ddrHostnamesList) > 0 {
			target = dns.Fqdn(ddrHostnamesList[0])
		}

		if ddrDoHPort > 0 {
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: syntheticTTL},
				Priority: priority,
				Target:   target,
			}
			priority++
			svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3", "http/1.1"}})
			svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: ddrDoHPort})
			svcb.Value = append(svcb.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
			if len(ddrECHConfig) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBECHConfig{ECH: ddrECHConfig})
			}
			appendIPHints(svcb, ipv4s, ipv6s)
			resp.Answer = append(resp.Answer, svcb)
		}

		if ddrDoTPort > 0 {
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: syntheticTTL},
				Priority: priority,
				Target:   target,
			}
			priority++
			svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: []string{"dot"}})
			svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: ddrDoTPort})
			if len(ddrECHConfig) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBECHConfig{ECH: ddrECHConfig})
			}
			appendIPHints(svcb, ipv4s, ipv6s)
			resp.Answer = append(resp.Answer, svcb)
		}

		if ddrDoQPort > 0 {
			svcb := &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: syntheticTTL},
				Priority: priority,
				Target:   target,
			}
			svcb.Value = append(svcb.Value, &dns.SVCBAlpn{Alpn: []string{"doq"}})
			svcb.Value = append(svcb.Value, &dns.SVCBPort{Port: ddrDoQPort})
			if len(ddrECHConfig) > 0 {
				svcb.Value = append(svcb.Value, &dns.SVCBECHConfig{ECH: ddrECHConfig})
			}
			appendIPHints(svcb, ipv4s, ipv6s)
			resp.Answer = append(resp.Answer, svcb)
		}

		// [FIX] EDNS0 Preservation
		if opt := r.IsEdns0(); opt != nil {
			resp.Extra = append(resp.Extra, dns.Copy(opt))
		}

		w.WriteMsg(resp)
		msgPool.Put(resp)
		if logQueries {
			log.Printf("[DNS] [%s] %s -> _dns.resolver.arpa SVCB | DDR DISCOVERY | NOERROR", protocol, clientID)
		}
		return true
	}

	// 1b. Resolver hostname A / AAAA / HTTPS — RFC 9461.
	if !ddrHostnames[qNameTrimmed] {
		return false
	}

	ipv4s, ipv6s := ddrAddrs(w)
	resp         := msgPool.Get().(*dns.Msg)
	*resp         = dns.Msg{} // Zero fields safely
	resp.SetReply(r)
	resp.Authoritative = true
	var label string

	switch q.Qtype {
	case dns.TypeA:
		label       = "DDR A"
		resp.Answer  = make([]dns.RR, 0, len(ipv4s))
		for _, ip := range ipv4s {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
				A:   ip.To4(),
			})
		}

	case dns.TypeAAAA:
		label       = "DDR AAAA"
		resp.Answer  = make([]dns.RR, 0, len(ipv6s))
		for _, ip := range ipv6s {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
				AAAA: ip.To16(),
			})
		}

	case dns.TypeHTTPS:
		label = "DDR HTTPS"
		svcb  := &dns.HTTPS{SVCB: dns.SVCB{
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
		appendIPHintsHTTPS(&svcb.SVCB, ipv4s, ipv6s)
		resp.Answer = []dns.RR{svcb}
		// Glue A/AAAA records in Extra so clients don't need a second lookup.
		resp.Extra = make([]dns.RR, 0, len(ipv4s)+len(ipv6s))
		for _, ip := range ipv4s {
			resp.Extra = append(resp.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: syntheticTTL},
				A:   ip.To4(),
			})
		}
		for _, ip := range ipv6s {
			resp.Extra = append(resp.Extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: syntheticTTL},
				AAAA: ip.To16(),
			})
		}

	default:
		// Hostname is known but query type is unsupported — NODATA, not NXDOMAIN.
		resp.SetRcode(r, dns.RcodeSuccess)
		label = "DDR NODATA"
	}

	// [FIX] EDNS0 Preservation
	if opt := r.IsEdns0(); opt != nil {
		resp.Extra = append(resp.Extra, dns.Copy(opt))
	}

	w.WriteMsg(resp)
	if logQueries {
		rcodeStr := dns.RcodeToString[resp.Rcode]
		if rcodeStr == "" {
			rcodeStr = fmt.Sprintf("RCODE:%d", resp.Rcode)
		}
		log.Printf("[DNS] [%s] %s -> %s %s | %s | %s", protocol, clientID, q.Name, dns.TypeToString[q.Qtype], label, rcodeStr)
	}
	msgPool.Put(resp)
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// appendIPHints adds SVCBIPv4Hint and SVCBIPv6Hint params to a SVCB record.
// Extracted to avoid copy-paste across the three SVCB RR builds above.
func appendIPHints(svcb *dns.SVCB, ipv4s, ipv6s []net.IP) {
	if len(ipv4s) > 0 {
		svcb.Value = append(svcb.Value, &dns.SVCBIPv4Hint{Hint: ipv4s})
	}
	if len(ipv6s) > 0 {
		svcb.Value = append(svcb.Value, &dns.SVCBIPv6Hint{Hint: ipv6s})
	}
}

// appendIPHintsHTTPS is identical to appendIPHints but takes a *dns.SVCB
// embedded inside dns.HTTPS (same struct, separate pointer receiver).
func appendIPHintsHTTPS(svcb *dns.SVCB, ipv4s, ipv6s []net.IP) {
	appendIPHints(svcb, ipv4s, ipv6s)
}

// localAddrIP extracts the listener's IP from a ResponseWriter's local address.
// Returns nil when the address is unspecified (0.0.0.0 / ::).
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

// ddrAddrs returns the effective IPv4/IPv6 slices for DDR responses.
// Falls back to the local listener interface address when the configured
// slices are empty — handy for single-NIC routers with no explicit config.
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

