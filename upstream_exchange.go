/*
File:    upstream_exchange.go
Version: 2.36.1
Updated: 07-May-2026 13:23 CEST

Description:
  Protocol multiplexer and connection fallback orchestrator for sdproxy.
  Evaluates upstream bindings and switches seamlessly between UDP, TCP, 
  DoT, DoH, DoH3, and DoQ transport implementations securely.
  
  Extracted from upstream.go to cleanly separate execution pipelines from setup.

Changes:
  2.36.1 - [FIX] Removed duplicate `exchangeHTTP` method declaration that was 
           erroneously breaking build compilation.
  2.36.0 - [SECURITY/FIX] Addressed a False-Positive Payload Truncation regression. 
           Replaced the rigid `io.LimitReader` in DoH/DoH3 unpackers with a native 
           buffer loop and a 1-byte overflow probe. Perfectly sized 64KB upstream 
           responses are now processed cleanly without triggering artificial capacity 
           constraint errors.
         - [FIX] Hardened DoH GET query construction. The HTTP dialer now dynamically 
           evaluates existing URI query parameters to append `&dns=` or `?dns=` 
           correctly, preventing malformed routing requests natively.
  2.35.0 - [SECURITY/FIX] Implemented progressive exponential backoff logic (15s, 60s, 5m)
           across DoH3 and ECH fallback mechanisms natively. This completely prevents 
           the system from locking out QUIC upgrades for 5 minutes when an initial 
           handshake inevitably stumbles or times out on startup.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Protocol Multiplexer
// ---------------------------------------------------------------------------

// Exchange forwards a DNS query to this upstream and returns the response.
// Automatically orchestrates the protocol bindings (UDP, TCP, DoT, DoH, DoQ),
// enforces the Encrypted Client Hello (ECH) cooldown states, and handles 
// dynamic DoH-to-DoH3 upgrades natively on the hot path.
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientID string, clientName string) (*dns.Msg, string, error) {
	if !AcquireUpstream() {
		return nil, u.Proto + "://" + u.RawURL, errors.New("upstream throttled: concurrency limit reached")
	}
	defer ReleaseUpstream()

	switch u.Proto {
	case "udp", "tcp", "dot", "doq":
		if len(u.dialAddrs) == 0 {
			return nil, u.Proto + "://" + u.RawURL,
				fmt.Errorf("no dial addresses for %s://%s (hostname resolution failed at startup)", u.Proto, u.RawURL)
		}
	}

	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	encrypted := u.Proto == "dot" || u.Proto == "doh" || u.Proto == "doh3" || u.Proto == "doq"
	fwd       := prepareForwardQuery(req, encrypted)

	switch u.Proto {
	case "udp":
		var (
			resp         *dns.Msg
			err          error
			lastDialAddr string
		)
		for _, dialAddr := range u.dialAddrs {
			lastDialAddr = dialAddr
			resp, _, err = u.udpClient.ExchangeContext(ctx, fwd, dialAddr)
			if err == nil && resp != nil {
				return resp, formatUpstreamLog(u.Proto, targetURL, dialAddr), nil
			}
		}
		if err != nil {
			return nil, formatUpstreamLog(u.Proto, targetURL, lastDialAddr), fmt.Errorf("udp exchange: %w", err)
		}
		return nil, formatUpstreamLog(u.Proto, targetURL, lastDialAddr), errors.New("udp exchange failed")

	case "tcp", "dot":
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}
		var lastErr error
		var lastDialAddr string
		
		fallbackNoECH := false
		if len(u.ECHConfigList) > 0 && cfg.Server.UseUpstreamECH == "try" {
			if time.Now().UnixNano() < u.echCooldown.Load() {
				fallbackNoECH = true
			}
		}
		
		for _, dialAddr := range u.dialAddrs {
			lastDialAddr = dialAddr
			resp, echAccepted, err := u.exchangeStream(ctx, fwd, dialAddr, effectiveHost, fallbackNoECH)
			
			// [FEAT] Fallback to plaintext SNI if the ECH connection drops
			if err != nil && !fallbackNoECH && cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0 {
				fails := u.echFails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				log.Printf("[ECH] Upstream %s: %s connection failed (%v). Falling back to plaintext SNI (%s cooldown).", dialAddr, u.Proto, err, cooldown)
				u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				fallbackNoECH = true
				resp, echAccepted, err = u.exchangeStream(ctx, fwd, dialAddr, effectiveHost, fallbackNoECH)
			} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
				u.echFails.Store(0)
			}
			
			if err == nil && resp != nil {
				protoLog := u.Proto
				if echAccepted {
					protoLog += "+ECH"
				}
				return resp, formatUpstreamLog(protoLog, targetURL, dialAddr), nil
			}
			lastErr = err
		}
		
		protoLog := u.Proto
		if len(u.ECHConfigList) > 0 && !fallbackNoECH {
			// Intent-based logging for failures
			protoLog += "+ECH"
		}
		
		if lastErr != nil {
			return nil, formatUpstreamLog(protoLog, targetURL, lastDialAddr), fmt.Errorf("stream exchange: %w", lastErr)
		}
		return nil, formatUpstreamLog(protoLog, targetURL, lastDialAddr), errors.New("stream exchange failed")

	case "doh":
		var resp *dns.Msg
		var remoteAddr string
		var err error
		var echAccepted bool

		// [FEAT] Evaluate dynamic HTTP/3 upgrade sequence natively.
		// Protect against UDP blocking via automatic fallback cooldown logic.
		tryH3 := cfg.Server.UpgradeDoH3 && u.h3Upgraded.Load() && time.Now().UnixNano() > u.h3Cooldown.Load()

		fallbackNoECH := false
		if len(u.ECHConfigList) > 0 && cfg.Server.UseUpstreamECH == "try" {
			if time.Now().UnixNano() < u.echCooldown.Load() {
				fallbackNoECH = true
			}
		}

		if tryH3 && u.h3Client != nil {
			clientToUse := u.h3Client
			if fallbackNoECH {
				clientToUse = u.h3ClientNoECH
			}
			resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, clientToUse)
			
			if err != nil && !fallbackNoECH && cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0 {
				fails := u.echFails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				log.Printf("[ECH] Upstream %s: Upgraded DoH3 connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
				u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				fallbackNoECH = true
				resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, u.h3ClientNoECH)
			} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
				u.echFails.Store(0)
			}
			
			if err != nil {
				fails := u.h3Fails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				// H3 Upgrade Failed. Instigate a backoff cooldown and seamlessly fallback to standard DoH.
				u.h3Cooldown.Store(time.Now().Add(cooldown).UnixNano())
				log.Printf("[UPGRADE] Upstream %s: DoH3 connection failed (%v). Falling back to standard DoH (%s cooldown).", targetURL, err, cooldown)
				tryH3 = false // Trigger native fallback sequence
			} else {
				u.h3Fails.Store(0)
			}
		}

		if !tryH3 {
			// Re-evaluate ECH cooldown because the H3 attempt might have triggered it
			fallbackNoECH = false
			if len(u.ECHConfigList) > 0 && cfg.Server.UseUpstreamECH == "try" {
				if time.Now().UnixNano() < u.echCooldown.Load() {
					fallbackNoECH = true
				}
			}

			clientToUse := u.h2Client
			if fallbackNoECH {
				clientToUse = u.h2ClientNoECH
			}
			resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, clientToUse)
			
			if err != nil && !fallbackNoECH && cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0 {
				fails := u.echFails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				log.Printf("[ECH] Upstream %s: DoH connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
				u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				fallbackNoECH = true
				resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, u.h2ClientNoECH)
			} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
				u.echFails.Store(0)
			}
		}
		
		protoLog := u.Proto
		if tryH3 {
			protoLog = "DoH3" // Accurately broadcast the successful protocol upgrade in telemetry
		}
		if echAccepted {
			protoLog += "+ECH"
		}
		
		if err != nil {
			return nil, formatUpstreamLog(protoLog, targetURL, remoteAddr), fmt.Errorf("doh exchange: %w", err)
		}
		return resp, formatUpstreamLog(protoLog, targetURL, remoteAddr), nil

	case "doh3":
		fallbackNoECH := false
		if len(u.ECHConfigList) > 0 && cfg.Server.UseUpstreamECH == "try" {
			if time.Now().UnixNano() < u.echCooldown.Load() {
				fallbackNoECH = true
			}
		}
		
		clientToUse := u.h3Client
		if fallbackNoECH {
			clientToUse = u.h3ClientNoECH
		}
		resp, remoteAddr, echAccepted, err := u.exchangeHTTP(ctx, fwd, targetURL, clientToUse)
		
		// [FEAT] Fallback to plaintext SNI if the ECH connection drops
		if err != nil && !fallbackNoECH && cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0 {
			fails := u.echFails.Add(1)
			cooldown := 5 * time.Minute
			if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
			
			log.Printf("[ECH] Upstream %s: DoH3 connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
			u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
			fallbackNoECH = true
			resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, u.h3ClientNoECH)
		} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
			u.echFails.Store(0)
		}
		
		protoLog := u.Proto
		if echAccepted {
			protoLog += "+ECH"
		}

		if err != nil {
			return nil, formatUpstreamLog(protoLog, targetURL, remoteAddr), fmt.Errorf("doh3 exchange: %w", err)
		}
		return resp, formatUpstreamLog(protoLog, targetURL, remoteAddr), nil

	case "doq":
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}

		fallbackNoECH := false
		if len(u.ECHConfigList) > 0 && cfg.Server.UseUpstreamECH == "try" {
			if time.Now().UnixNano() < u.echCooldown.Load() {
				fallbackNoECH = true
			}
		}

		resp, dialAddr, echAccepted, err := u.exchangeDoQ(ctx, fwd, effectiveHost, fallbackNoECH)
		
		// [FEAT] Fallback to plaintext SNI if the ECH connection drops
		if err != nil && !fallbackNoECH && cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0 {
			fails := u.echFails.Add(1)
			cooldown := 5 * time.Minute
			if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
			
			log.Printf("[ECH] Upstream %s: DoQ connection failed (%v). Falling back to plaintext SNI (%s cooldown).", effectiveHost, err, cooldown)
			u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
			fallbackNoECH = true
			resp, dialAddr, echAccepted, err = u.exchangeDoQ(ctx, fwd, effectiveHost, fallbackNoECH)
		} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
			u.echFails.Store(0)
		}
		
		protoLog := u.Proto
		if echAccepted {
			protoLog += "+ECH"
		}

		if err != nil {
			return nil, formatUpstreamLog(protoLog, targetURL, dialAddr), fmt.Errorf("doq exchange: %w", err)
		}
		return resp, formatUpstreamLog(protoLog, targetURL, dialAddr), nil

	default:
		return nil, targetURL, fmt.Errorf("unknown protocol: %s", u.Proto)
	}
}

