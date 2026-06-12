/*
File:    upstream_exchange.go
Version: 2.41.0
Updated: 04-Jun-2026 12:55 CEST

Description:
  Protocol multiplexer and connection fallback orchestrator for sdproxy.
  Evaluates upstream bindings and switches seamlessly between UDP, TCP, 
  DoT, DoH, DoH3, and DoQ transport implementations securely.
  
  Extracted from upstream.go to cleanly separate execution pipelines from setup.

Changes:
  2.41.0 - [SECURITY/FIX] Eradicated Context-Death Cascading Dials. Deployed 
           strict `errors.Is(err, context.Canceled)` and `ctx.Err() == nil` 
           bypasses across DoT, DoH, DoH3, and DoQ transport fallback chains natively. 
           Instantly aborts protocol regressions (e.g., ECH to Plaintext, DoH3 to DoH2) 
           if the overarching query deadline has expired, drastically slashing 
           CPU starvation and socket exhaustion during DDoS reflection floods.
  2.40.0 - [SECURITY/FIX] Guarded ECH and DoH3 fallback triggers against context cancellation (`ctx.Err() == nil`).
           Prevents staggered racing and quorum cancellations from falsely registering as protocol failures
           and natively halts the launch of plaintext SNI fallbacks if the parallel pipeline 
           already reached its conclusion organically.
  2.39.0 - [SECURITY/FIX] Guarded ECH and DoH3 fallback triggers against context cancellation (context.Canceled).
           Prevents staggered racing and quorum cancellations from falsely registering as protocol failures,
           saving CPU/IO and maintaining ECH/DoH3 transport stability.
  2.38.0 - [LOGGING] Managed `ECH` fallback and connection `UPGRADE` alerts cleanly 
           by encapsulating them strictly inside the `logTLS` threshold dynamically.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
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
func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
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
	
	// Pass the resolved IP capabilities natively into the structure mapping for explicit ECS evaluations
	fwd := prepareForwardQuery(req, encrypted, u, clientAddr)

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
				// Avoid treating active parallel cancels or client disconnects as real connection errors
				// [SECURITY/FIX] Additionally, verify ctx.Err() == nil to prevent launching dead fallback dials organically.
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					fails := u.echFails.Add(1)
					cooldown := 5 * time.Minute
					if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
					
					if logTLS {
						log.Printf("[TLS] [ECH] Upstream %s: %s connection failed (%v). Falling back to plaintext SNI (%s cooldown).", dialAddr, u.Proto, err, cooldown)
					}
					u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				} else {
					protoLog := u.Proto + "+ECH"
					return nil, formatUpstreamLog(protoLog, targetURL, dialAddr), err
				}
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
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					fails := u.echFails.Add(1)
					cooldown := 5 * time.Minute
					if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
					
					if logTLS {
						log.Printf("[TLS] [ECH] Upstream %s: Upgraded DoH3 connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
					}
					u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				} else {
					return nil, formatUpstreamLog("DoH3+ECH", targetURL, remoteAddr), err
				}
				fallbackNoECH = true
				resp, remoteAddr, echAccepted, err = u.exchangeHTTP(ctx, fwd, targetURL, u.h3ClientNoECH)
			} else if err == nil && len(u.ECHConfigList) > 0 && !fallbackNoECH {
				u.echFails.Store(0)
			}
			
			if err != nil {
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					fails := u.h3Fails.Add(1)
					cooldown := 5 * time.Minute
					if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
					
					u.h3Cooldown.Store(time.Now().Add(cooldown).UnixNano())
					if logTLS {
						log.Printf("[TLS] [UPGRADE] Upstream %s: DoH3 connection failed (%v). Falling back to standard DoH (%s cooldown).", targetURL, err, cooldown)
					}
					tryH3 = false // Trigger native fallback sequence
				} else {
					protoLog := "DoH3"
					if !fallbackNoECH && len(u.ECHConfigList) > 0 { protoLog += "+ECH" }
					return nil, formatUpstreamLog(protoLog, targetURL, remoteAddr), err
				}
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
				if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
					fails := u.echFails.Add(1)
					cooldown := 5 * time.Minute
					if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
					
					if logTLS {
						log.Printf("[TLS] [ECH] Upstream %s: DoH connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
					}
					u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
				} else {
					return nil, formatUpstreamLog("doh+ECH", targetURL, remoteAddr), err
				}
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
			if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				fails := u.echFails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				if logTLS {
					log.Printf("[TLS] [ECH] Upstream %s: DoH3 connection failed (%v). Falling back to plaintext SNI (%s cooldown).", targetURL, err, cooldown)
				}
				u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
			} else {
				return nil, formatUpstreamLog("doh3+ECH", targetURL, remoteAddr), err
			}
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
			if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				fails := u.echFails.Add(1)
				cooldown := 5 * time.Minute
				if fails == 1 { cooldown = 15 * time.Second } else if fails == 2 { cooldown = 60 * time.Second }
				
				if logTLS {
					log.Printf("[TLS] [ECH] Upstream %s: DoQ connection failed (%v). Falling back to plaintext SNI (%s cooldown).", effectiveHost, err, cooldown)
				}
				u.echCooldown.Store(time.Now().Add(cooldown).UnixNano())
			} else {
				return nil, formatUpstreamLog("doq+ECH", targetURL, dialAddr), err
			}
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

