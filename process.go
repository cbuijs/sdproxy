/*
File: process.go
Version: 1.12.0
Last Updated: 2026-02-27 21:10 CET
Description: Core logical router. Evaluates client IPs, performs MAC lookups,
             intercepts DDR Discovery queries unconditionally (with port hints), 
             resolves {client-name}, checks the cache, forwards to upstream, 
             and caches the reply.
             FIXED: Logs now output the correctly resolved target URL.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ProcessDNS is the central hub for all incoming queries across all protocols.
func ProcessDNS(w dns.ResponseWriter, r *dns.Msg, clientIP string, protocol string) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	originalID := r.Id

	qNameLower := strings.ToLower(q.Name)
	qNameTrimmed := strings.TrimSuffix(qNameLower, ".")
	
	if q.Qtype == dns.TypeSVCB && qNameTrimmed == "_dns.resolver.arpa" {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Authoritative = true

		if cfg.Server.DDR.Enabled {
			for host := range ddrHostnames {
				target := dns.Fqdn(host)
				
				svcbHTTPS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 1,
					Target:   target,
				}
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBAlpn{Alpn: []string{"h2", "h3"}})
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBPort{Port: 443}) 
				svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBDoHPath{Template: "/dns-query{?dns}"})
				
				if ddrIPv4 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbHTTPS.Value = append(svcbHTTPS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbHTTPS)

				svcbTLS := &dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
					Priority: 2,
					Target:   target,
				}
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBAlpn{Alpn: []string{"dot", "doq"}})
				svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBPort{Port: 853}) 
				
				if ddrIPv4 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ddrIPv4.To4()}})
				}
				if ddrIPv6 != nil {
					svcbTLS.Value = append(svcbTLS.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ddrIPv6.To16()}})
				}
				resp.Answer = append(resp.Answer, svcbTLS)
				
				if ddrIPv4 != nil {
					resp.Extra = append(resp.Extra, &dns.A{
						Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   ddrIPv4.To4(),
					})
				}
				if ddrIPv6 != nil {
					resp.Extra = append(resp.Extra, &dns.AAAA{
						Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
						AAAA: ddrIPv6.To16(),
					})
				}
			}
		}

		w.WriteMsg(resp)
		log.Printf("[DNS] [%s] %s -> %s %s | DDR DISCOVERY (Answered Local)", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
		return
	}

	if cfg.Server.DDR.Enabled && ddrHostnames[qNameTrimmed] {
		handled := false
		resp := new(dns.Msg)
		resp.SetReply(r)

		if q.Qtype == dns.TypeA && ddrIPv4 != nil {
			rr := new(dns.A)
			rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
			rr.A = ddrIPv4.To4()
			resp.Answer = append(resp.Answer, rr)
			handled = true
		} else if q.Qtype == dns.TypeAAAA && ddrIPv6 != nil {
			rr := new(dns.AAAA)
			rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
			rr.AAAA = ddrIPv6.To16()
			resp.Answer = append(resp.Answer, rr)
			handled = true
		}

		if handled {
			w.WriteMsg(resp)
			log.Printf("[DNS] [%s] %s -> %s %s | DDR SPOOF", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype])
			return
		}
	}

	mac := LookupMAC(clientIP)

	routeName := "default"
	clientName := "unknown"

	if mac != "" {
		if routeInfo, exists := macRoutes[mac]; exists {
			if routeInfo.Upstream != "" {
				routeName = routeInfo.Upstream
			}
			if routeInfo.ClientName != "" {
				clientName = routeInfo.ClientName
			} else {
				clientName = strings.ReplaceAll(mac, ":", "-")
			}
		} else {
			clientName = strings.ReplaceAll(mac, ":", "-")
		}
	} else {
		clientName = strings.ReplaceAll(clientIP, ".", "-")
		clientName = strings.ReplaceAll(clientName, ":", "-")
	}

	cacheKey := fmt.Sprintf("%s|%d|%d|%s", q.Name, q.Qtype, q.Qclass, routeName)
	
	if cachedResp := CacheGet(cacheKey); cachedResp != nil {
		cachedResp.Id = originalID 
		w.WriteMsg(cachedResp)
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s | UPSTREAM: CACHE | OK", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeName)
		return
	}

	upstreams, exists := routeUpstreams[routeName]
	if !exists || len(upstreams) == 0 {
		upstreams = routeUpstreams["default"]
	}

	var finalResp *dns.Msg
	var lastErr error
	var upstreamUsed string

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fwdReq := r.Copy()
	fwdReq.Id = dns.Id()

	for _, up := range upstreams {
		// up.Exchange now returns (response, actualTargetUrl, error)
		resp, actualURL, err := up.Exchange(ctx, fwdReq, clientName)
		if err == nil && resp != nil {
			finalResp = resp
			upstreamUsed = actualURL
			break
		}
		lastErr = err
	}

	if finalResp == nil {
		log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s | FAILED: %v", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeName, lastErr)
		dns.HandleFailed(w, r)
		return
	}

	CacheSet(cacheKey, finalResp)

	finalResp.Id = originalID 
	w.WriteMsg(finalResp)

	log.Printf("[DNS] [%s] %s -> %s %s | ROUTE: %s | UPSTREAM: %s | OK", protocol, clientIP, q.Name, dns.TypeToString[q.Qtype], routeName, upstreamUsed)
}

