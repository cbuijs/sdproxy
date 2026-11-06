/*
File:    upstream_exchange.go
Version: 3.5.0
Last Updated: 05-Nov-2026 16:36 CET

Description:
  Protocol multiplexer and connection fallback orchestrator for sdproxy.
  Evaluates upstream bindings and switches between UDP, TCP, DoT, DoH, DoH3
  and DoQ transports.

Changes:
  3.5.0 - [CRITICAL/FIX] Honored `IsBypassUpstreamThrottle(ctx)` in `Exchange` so
          internal sub-probes (`for_sale`, `parked`, `backgroundRevalidate`, and
          startup bootstrap/DDR probes) do not contend for or exhaust client-facing
          `AcquireUpstream` slots.
  3.4.0 - [SECURITY/FIX] Cleared stale `u.serverCookieHex` when a `BADCOOKIE`
          response did not supply a fresh server cookie before retrying over UDP,
          and aborted the UDP exchange if the `BADCOOKIE` retry fails or still
          returns `BADCOOKIE`.
  3.3.0 - [SECURITY/FIX] Stripped UDP-only `EDNS0_COOKIE` (`stripEDNS0Cookie`)
          and assigned a fresh TXID before retrying truncated (`TC=1`) UDP
          responses over TCP in `Exchange`.
  3.2.0 - [SECURITY/FEAT] Implemented Recommendations 1, 2, 3, and 4 on UDP
          upstreams in `Exchange`.
  3.1.0 - [FIX] Enabled ECH and DoH3 fallback warning logs in `runWithECHFallback`
          and `Exchange` when `logSystem` or `logTLS` is active.
  3.0.0 - [TIER 3] Unified the four duplicated ECH fallback ladders behind
          runWithECHFallback().
  2.41.0 - [SECURITY/FIX] Context-death guards across all transport fallback
          chains.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// ECH fallback ladder
// ---------------------------------------------------------------------------

type echAttempt func(fallbackNoECH bool) (msg *dns.Msg, addr string, echAccepted bool, err error)

func echBackoff(fails int32) time.Duration {
	switch fails {
	case 1:
		return 15 * time.Second
	case 2:
		return 60 * time.Second
	default:
		return 5 * time.Minute
	}
}

func (u *Upstream) runWithECHFallback(ctx context.Context, label string, fn echAttempt) (*dns.Msg, string, bool, error) {
	tryMode := cfg.Server.UseUpstreamECH == "try" && len(u.ECHConfigList) > 0
	noECH := tryMode && time.Now().UnixNano() < u.echCooldown.Load()

	msg, addr, ech, err := fn(noECH)
	if err == nil {
		if tryMode && !noECH {
			u.echFails.Store(0)
		}
		return msg, addr, ech, nil
	}

	if !tryMode || noECH {
		return msg, addr, ech, err
	}
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return msg, addr, ech, err
	}

	cd := echBackoff(u.echFails.Add(1))
	u.echCooldown.Store(time.Now().Add(cd).UnixNano())
	if logTLS || logSystem {
		log.Printf("[TLS] [ECH] WARNING: Upstream %s: %s connection failed (%v). Falling back to plaintext SNI (%s cooldown).",
			u.RawURL, label, err, cd)
	}
	return fn(true)
}

func (u *Upstream) pickHTTPClient(h3, noECH bool) *http.Client {
	if h3 {
		if noECH && u.h3ClientNoECH != nil {
			return u.h3ClientNoECH
		}
		return u.h3Client
	}
	if noECH && u.h2ClientNoECH != nil {
		return u.h2ClientNoECH
	}
	return u.h2Client
}

func (u *Upstream) protoLabel(base string, echAccepted bool) string {
	if echAccepted {
		return base + "+ECH"
	}
	if len(u.ECHConfigList) > 0 && time.Now().UnixNano() >= u.echCooldown.Load() {
		return base + "+ECH"
	}
	return base
}

// ---------------------------------------------------------------------------
// Protocol Multiplexer
// ---------------------------------------------------------------------------

func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientID string, clientName string, clientAddr netip.Addr) (*dns.Msg, string, error) {
	if !IsBypassUpstreamThrottle(ctx) {
		if !AcquireUpstream() {
			return nil, u.Proto + "://" + u.RawURL, errors.New("upstream throttled: concurrency limit reached")
		}
		defer ReleaseUpstream()
	}

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
				prevCookie, _ := u.serverCookieHex.Load().(string)
				if valErr := u.validateUpstreamResponse(fwd, resp, true, u.DNS0x20, true); valErr != nil {
					err = valErr
					resp = nil
					continue
				}

				// RFC 7873 §5.2.3: If server returned BADCOOKIE and supplied a fresh
				// Server Cookie (learned inside validateUpstreamResponse), retry once.
				if u.DNSCookies && resp.Rcode == dns.RcodeBadCookie {
					curCookie, _ := u.serverCookieHex.Load().(string)
					if curCookie == prevCookie {
						u.serverCookieHex.Store("")
					}
					fwdRetry := prepareForwardQuery(req, false, u, clientAddr)
					respRetry, _, retryErr := u.udpClient.ExchangeContext(ctx, fwdRetry, dialAddr)
					if retryErr != nil || respRetry == nil {
						err = fmt.Errorf("badcookie retry failed: %v", retryErr)
						resp = nil
						continue
					}
					if valErr := u.validateUpstreamResponse(fwdRetry, respRetry, true, u.DNS0x20, true); valErr != nil {
						err = valErr
						resp = nil
						continue
					}
					if respRetry.Rcode == dns.RcodeBadCookie {
						err = errors.New("upstream returned persistent BADCOOKIE")
						resp = nil
						continue
					}
					resp = respRetry
					fwd = fwdRetry
				}

				// Recommendation 4: Automatic TCP fallback when UDP response is truncated (TC=1).
				if resp != nil && resp.Truncated {
					tcpFwd := prepareForwardQuery(req, false, u, clientAddr)
					stripEDNS0Cookie(tcpFwd)
					tcpResp, _, tcpErr := u.exchangeStream(ctx, tcpFwd, dialAddr, "", false)
					if tcpErr == nil && tcpResp != nil {
						return tcpResp, formatUpstreamLog("tcp", targetURL, dialAddr), nil
					}
				}

				if resp != nil {
					return resp, formatUpstreamLog(u.Proto, targetURL, dialAddr), nil
				}
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

		var lastAddr string
		attempt := func(noECH bool) (*dns.Msg, string, bool, error) {
			var lastErr error
			for _, dialAddr := range u.dialAddrs {
				lastAddr = dialAddr
				resp, ech, err := u.exchangeStream(ctx, fwd, dialAddr, effectiveHost, noECH)
				if err == nil && resp != nil {
					return resp, dialAddr, ech, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = errors.New("stream exchange failed")
			}
			return nil, lastAddr, false, lastErr
		}

		resp, addr, ech, err := u.runWithECHFallback(ctx, u.Proto, attempt)
		label := u.protoLabel(u.Proto, ech)
		if err != nil {
			return nil, formatUpstreamLog(label, targetURL, addr), fmt.Errorf("stream exchange: %w", err)
		}
		return resp, formatUpstreamLog(label, targetURL, addr), nil

	case "doh":
		tryH3 := cfg.Server.UpgradeDoH3 &&
			u.h3Upgraded.Load() &&
			time.Now().UnixNano() > u.h3Cooldown.Load() &&
			u.h3Client != nil

		var (
			resp   *dns.Msg
			remote string
			ech    bool
			err    error
		)

		if tryH3 {
			resp, remote, ech, err = u.runWithECHFallback(ctx, "DoH3", func(noECH bool) (*dns.Msg, string, bool, error) {
				return u.exchangeHTTP(ctx, fwd, targetURL, u.pickHTTPClient(true, noECH))
			})
			if err != nil {
				if errors.Is(err, context.Canceled) || ctx.Err() != nil {
					return nil, formatUpstreamLog(u.protoLabel("DoH3", ech), targetURL, remote), err
				}
				cd := echBackoff(u.h3Fails.Add(1))
				u.h3Cooldown.Store(time.Now().Add(cd).UnixNano())
				if logTLS || logSystem {
					log.Printf("[TLS] [UPGRADE] WARNING: Upstream %s: DoH3 connection failed (%v). Falling back to standard DoH (%s cooldown).",
						targetURL, err, cd)
				}
				tryH3 = false
			} else {
				u.h3Fails.Store(0)
			}
		}

		if !tryH3 {
			resp, remote, ech, err = u.runWithECHFallback(ctx, "DoH", func(noECH bool) (*dns.Msg, string, bool, error) {
				return u.exchangeHTTP(ctx, fwd, targetURL, u.pickHTTPClient(false, noECH))
			})
		}

		base := u.Proto
		if tryH3 {
			base = "DoH3"
		}
		label := u.protoLabel(base, ech)
		if err != nil {
			return nil, formatUpstreamLog(label, targetURL, remote), fmt.Errorf("doh exchange: %w", err)
		}
		return resp, formatUpstreamLog(label, targetURL, remote), nil

	case "doh3":
		resp, remote, ech, err := u.runWithECHFallback(ctx, "DoH3", func(noECH bool) (*dns.Msg, string, bool, error) {
			return u.exchangeHTTP(ctx, fwd, targetURL, u.pickHTTPClient(true, noECH))
		})
		label := u.protoLabel(u.Proto, ech)
		if err != nil {
			return nil, formatUpstreamLog(label, targetURL, remote), fmt.Errorf("doh3 exchange: %w", err)
		}
		return resp, formatUpstreamLog(label, targetURL, remote), nil

	case "doq":
		effectiveHost := u.dialHost
		if u.hasClientNameTemplate {
			effectiveHost = strings.ReplaceAll(u.dialHost, "{client-name}", clientName)
		}

		resp, dialAddr, ech, err := u.runWithECHFallback(ctx, "DoQ", func(noECH bool) (*dns.Msg, string, bool, error) {
			return u.exchangeDoQ(ctx, fwd, effectiveHost, noECH)
		})
		label := u.protoLabel(u.Proto, ech)
		if err != nil {
			return nil, formatUpstreamLog(label, targetURL, dialAddr), fmt.Errorf("doq exchange: %w", err)
		}
		return resp, formatUpstreamLog(label, targetURL, dialAddr), nil

	default:
		return nil, targetURL, fmt.Errorf("unknown protocol: %s", u.Proto)
	}
}
