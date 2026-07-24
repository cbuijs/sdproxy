/*
File:    upstream_exchange.go
Version: 3.0.0
Updated: 22-Jul-2026 21:40 CEST

Description:
  Protocol multiplexer and connection fallback orchestrator for sdproxy.
  Evaluates upstream bindings and switches between UDP, TCP, DoT, DoH, DoH3
  and DoQ transports.

  ECH ("try" mode) fallback and the DoH3 downgrade path are handled by
  runWithECHFallback() and echBackoff(); the four transports no longer carry
  their own copies of that ladder.

Changes:
  3.0.0 - [TIER 3] Unified the four duplicated ECH fallback ladders behind
          runWithECHFallback(). Backoff schedule extracted to echBackoff() and
          reused for the DoH3 downgrade. Client selection moved to
          pickHTTPClient().
          BEHAVIOUR CHANGE (TCP/DoT): ECH is now retried across ALL dial
          addresses before downgrading to plaintext SNI. Previously the first
          failing address forced the remaining addresses onto plaintext.
  2.41.0 - [SECURITY/FIX] Context-death guards across all transport fallback
          chains: an expired parent context aborts the ladder instead of
          cascading a dead retry.
  2.40.0 - [SECURITY/FIX] ECH/DoH3 fallback triggers guarded against
          context.Canceled so staggered-race losses aren't logged as failures.
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

// echAttempt performs one exchange attempt against this upstream.
// fallbackNoECH selects the plaintext-SNI transport variant.
type echAttempt func(fallbackNoECH bool) (msg *dns.Msg, addr string, echAccepted bool, err error)

// echBackoff returns the cooldown for the n-th consecutive failure.
// Short at first so a transient blip barely costs anything, then long enough
// that a genuinely ECH-hostile network isn't probed on every query.
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

// runWithECHFallback wraps an exchange in the "try"-mode ECH ladder:
//
//   1. Honour an active cooldown by going straight to plaintext SNI.
//   2. On success with ECH active, reset the failure counter.
//   3. On a genuine failure, latch a backoff and retry once without ECH.
//
// [SECURITY] A cancelled parent context means a lost staggered race or a
// disconnected client — never an ECH failure. Latching a cooldown on those
// would let ordinary racing traffic disable ECH for the whole upstream.
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

	// Already plaintext, or ECH isn't in "try" mode — nothing to fall back to.
	if !tryMode || noECH {
		return msg, addr, ech, err
	}
	if errors.Is(err, context.Canceled) || ctx.Err() != nil {
		return msg, addr, ech, err
	}

	cd := echBackoff(u.echFails.Add(1))
	u.echCooldown.Store(time.Now().Add(cd).UnixNano())
	if logTLS {
		log.Printf("[TLS] [ECH] Upstream %s: %s connection failed (%v). Falling back to plaintext SNI (%s cooldown).",
			u.RawURL, label, err, cd)
	}
	return fn(true)
}

// pickHTTPClient selects the HTTP client for the requested protocol and ECH
// state. The NoECH variants are only built when use_upstream_ech is "try", so
// fall back to the primary client when they're absent.
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

// protoLabel appends the +ECH marker for telemetry. echAccepted reflects the
// negotiated result; intended reflects that ECH was configured and not on
// cooldown, so failures still show what was attempted.
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

// Exchange forwards a DNS query to this upstream and returns the response.
// Orchestrates protocol bindings (UDP, TCP, DoT, DoH, DoQ), the ECH cooldown
// state, and dynamic DoH-to-DoH3 upgrades on the hot path.
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
				// A cancelled context is a race loss, not a QUIC-path problem —
				// don't latch a downgrade cooldown on it.
				if errors.Is(err, context.Canceled) || ctx.Err() != nil {
					return nil, formatUpstreamLog(u.protoLabel("DoH3", ech), targetURL, remote), err
				}
				cd := echBackoff(u.h3Fails.Add(1))
				u.h3Cooldown.Store(time.Now().Add(cd).UnixNano())
				if logTLS {
					log.Printf("[TLS] [UPGRADE] Upstream %s: DoH3 connection failed (%v). Falling back to standard DoH (%s cooldown).",
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
			base = "DoH3" // report the upgrade that actually served the query
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

