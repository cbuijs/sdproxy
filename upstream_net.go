/*
File:    upstream_net.go
Version: 1.46.0
Last Updated: 24-Nov-2026 14:30 CET

Description:
  TCP, DoT, HTTP, and QUIC stream network dialers and protocol implementations.

Changes:
  1.46.0 - [PERF/CONCURRENCY] Replaced per-query cancellation goroutines and
           channels in `exchangeStream` and `exchangeHTTP` with zero-goroutine
           `context.AfterFunc` hooks, and registered a `context.AfterFunc` stream
           aborter in `doqStreamExchange` so canceled loser DoQ streams abort
           immediately instead of blocking up to `streamTimeout` (5s).
  1.45.0 - [SECURITY/FIX] Used `u.lockNo0RTT()` and `u.revertUnverifiedNo0RTT()`
           in `exchangeHTTP` and `exchangeDoQ`.
  1.44.0 - [FEAT/FIX] Implemented sticky `Allow0RTT` disabling (`u.no0RTT`) in
           `exchangeHTTP` and `exchangeDoQ`.
  1.43.0 - [FEAT] Guarded dynamic `Alt-Svc: h3=` auto-upgrade in `exchangeHTTP`
           with `!u.dohSticky.Load()`.
  1.42.0 - [CRITICAL/FIX] Replaced `closer.Close()` with `CloseIdleConnections()`
           on `client.Transport` inside `exchangeHTTP` retry path.
  1.41.0 - [SECURITY/FIX] Closed idle HTTP/3 QUIC connections on retry.
  1.40.0 - [CRITICAL/FIX] Eliminated stalls in `exchangeHTTP` and `exchangeDoQ`.
  1.39.0 - [SECURITY/FIX] Enforced `u.validateUpstreamResponse` across all stream
           and encrypted transports.
  1.38.0 - [FIX/CLEANUP] Added `conn == nil` defensive check in `doqStreamExchange`.
  1.37.0 - [SECURITY/FIX] Added zero-progress read guard (`maxZeroReads = 64`).
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	maxIdleStreamConns = 10
	httpAttemptTimeout = 5 * time.Second
)

func (u *Upstream) takeStreamConn(addr string) *dns.Conn {
	var expiredConns []*dns.Conn

	u.streamMu.Lock()
	conns := u.streamConns[addr]
	var entry *streamConnEntry

	for len(conns) > 0 {
		entry = conns[len(conns)-1]
		conns[len(conns)-1] = nil
		conns = conns[:len(conns)-1]

		if time.Since(entry.idleAt) > streamIdleMax {
			expiredConns = append(expiredConns, entry.conn)
			entry = nil
			continue
		}
		break
	}

	if len(conns) == 0 {
		delete(u.streamConns, addr)
	} else {
		u.streamConns[addr] = conns
	}
	u.streamMu.Unlock()

	for _, c := range expiredConns {
		c.Close()
	}

	if entry == nil {
		return nil
	}
	return entry.conn
}

func (u *Upstream) putStreamConn(addr string, conn *dns.Conn) {
	u.streamMu.Lock()
	conns := u.streamConns[addr]

	if len(conns) >= maxIdleStreamConns {
		u.streamMu.Unlock()
		conn.Close()
		return
	}

	u.streamConns[addr] = append(conns, &streamConnEntry{conn: conn, idleAt: time.Now()})
	u.streamMu.Unlock()
}

func (u *Upstream) dialStream(ctx context.Context, addr, tlsHost string, fallbackNoECH bool) (*dns.Conn, error) {
	dialTimeout := streamTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < dialTimeout {
			dialTimeout = rem
		}
	}
	netDialer := &net.Dialer{Timeout: dialTimeout}

	if u.Proto == "dot" {
		var tlsConf *tls.Config
		if fallbackNoECH && u.baseTLSConfNoECH != nil {
			tlsConf = u.baseTLSConfNoECH.Clone()
		} else if u.baseTLSConf != nil {
			tlsConf = u.baseTLSConf.Clone()
		} else {
			tlsConf = getHardenedTLSConfig()
			tlsConf.NextProtos = []string{"dot"}
		}

		if tlsHost != "" {
			tlsConf.ServerName = tlsHost
		}
		tlsDialer := &tls.Dialer{
			NetDialer: netDialer,
			Config:    tlsConf,
		}
		c, err := tlsDialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dot dial: %w", err)
		}
		return &dns.Conn{Conn: c}, nil
	}

	c, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	return &dns.Conn{Conn: c}, nil
}

func (u *Upstream) exchangeStream(ctx context.Context, req *dns.Msg, dialAddr, tlsHost string, fallbackNoECH bool) (*dns.Msg, bool, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	} else if maxDL := time.Now().Add(streamTimeout); deadline.After(maxDL) {
		deadline = maxDL
	}

	poolKey := dialAddr
	if fallbackNoECH {
		poolKey += "_noech"
	}

	check0x20 := u.DNS0x20 && u.Proto != "dot"

	executeExchange := func(conn *dns.Conn) (*dns.Msg, bool, error) {
		var connClosed atomic.Bool
		closeOnce := func() {
			if connClosed.CompareAndSwap(false, true) {
				_ = conn.Close()
			}
		}
		stopCancel := context.AfterFunc(ctx, closeOnce)

		conn.SetDeadline(deadline)

		if err := conn.WriteMsg(req); err != nil {
			stopCancel()
			closeOnce()
			return nil, false, fmt.Errorf("write msg: %w", err)
		}

		resp, err := conn.ReadMsg()

		if err != nil || resp == nil {
			stopCancel()
			closeOnce()
			if err == nil {
				err = errors.New("empty response")
			} else {
				err = fmt.Errorf("read msg: %w", err)
			}
			return nil, false, err
		}

		if valErr := u.validateUpstreamResponse(req, resp, true, check0x20, false); valErr != nil {
			stopCancel()
			closeOnce()
			return nil, false, valErr
		}

		var echAccepted bool
		if tlsConn, ok := conn.Conn.(*tls.Conn); ok {
			echAccepted = tlsConn.ConnectionState().ECHAccepted
		}

		// Return to pool only if AfterFunc was stopped before firing and ctx is still live.
		if stopCancel() && ctx.Err() == nil && connClosed.CompareAndSwap(false, true) {
			u.putStreamConn(poolKey, conn)
		} else {
			closeOnce()
		}

		return resp, echAccepted, nil
	}

	if conn := u.takeStreamConn(poolKey); conn != nil {
		resp, ech, err := executeExchange(conn)
		if err == nil {
			return resp, ech, nil
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
	}

	conn, err := u.dialStream(ctx, dialAddr, tlsHost, fallbackNoECH)
	if err != nil {
		return nil, false, err
	}

	return executeExchange(conn)
}

// ---------------------------------------------------------------------------
// HTTP (DoH / DoH3)
// ---------------------------------------------------------------------------

func isRetryableHTTPError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	errMsg := err.Error()
	return strings.Contains(errMsg, "H3 error") ||
		strings.Contains(errMsg, "http3:") ||
		strings.Contains(errMsg, "EOF") ||
		strings.Contains(errMsg, "connection reset") ||
		strings.Contains(errMsg, "server closed") ||
		strings.Contains(errMsg, "PROTOCOL_ERROR") ||
		strings.Contains(errMsg, "FRAME_ERROR") ||
		strings.Contains(errMsg, "NO_ERROR") ||
		strings.Contains(errMsg, "CANCELLED") ||
		strings.Contains(errMsg, "Application error") ||
		strings.Contains(errMsg, "Transport error") ||
		strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "Client.Timeout") ||
		strings.Contains(errMsg, "0-RTT") ||
		strings.Contains(errMsg, "early data")
}

func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, string, bool, error) {
	bufPtr := largeBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*bufPtr)[:0])
	if err != nil {
		largeBufPool.Put(bufPtr)
		return nil, "", false, fmt.Errorf("pack buffer: %w", err)
	}
	defer largeBufPool.Put(bufPtr)

	var remoteAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Conn != nil {
				remoteAddr = connInfo.Conn.RemoteAddr().String()
			}
		},
	}

	var separator string
	var encoded string
	if u.useGET {
		encoded = base64.RawURLEncoding.EncodeToString(packed)
		separator = "?"
		if strings.Contains(targetURL, "?") {
			separator = "&"
		}
	}

	doSingleAttempt := func() (*dns.Msg, bool, error) {
		attemptTimeout := httpAttemptTimeout
		if dl, ok := ctx.Deadline(); ok {
			if rem := time.Until(dl); rem > 0 && rem < attemptTimeout {
				attemptTimeout = rem
			}
		}
		reqCtx, reqCancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), attemptTimeout)
		defer reqCancel()

		var hReq *http.Request
		var reqErr error
		if u.useGET {
			hReq, reqErr = http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL+separator+"dns="+encoded, nil)
		} else {
			hReq, reqErr = http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader(packed))
		}
		if reqErr != nil {
			return nil, false, fmt.Errorf("new http request: %w", reqErr)
		}

		if !u.useGET {
			hReq.Header.Set("Content-Type", "application/dns-message")
		}
		hReq.Header.Set("Accept", "application/dns-message")
		hReq.Header.Set("User-Agent", cfg.Server.UserAgent)

		resp, doErr := client.Do(hReq)
		if doErr != nil {
			return nil, false, doErr
		}

		var bodyClosed atomic.Bool
		closeBody := func() {
			if bodyClosed.CompareAndSwap(false, true) {
				_ = resp.Body.Close()
			}
		}
		stopBodyCancel := context.AfterFunc(reqCtx, closeBody)
		defer func() {
			stopBodyCancel()
			closeBody()
		}()

		var echAccepted bool
		if resp.TLS != nil {
			echAccepted = resp.TLS.ECHAccepted
		}

		if resp.StatusCode != http.StatusOK {
			return nil, echAccepted, fmt.Errorf("bad status code: %d", resp.StatusCode)
		}

		if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.dohSticky.Load() && !u.h3Upgraded.Load() {
			if strings.Contains(resp.Header.Get("Alt-Svc"), "h3=") {
				u.h3Upgraded.Store(true)
			}
		}

		rBufPtr := largeBufPool.Get().(*[]byte)
		rBuf := *rBufPtr

		n := 0
		const maxZeroReads = 64
		zeroReads := 0

		for {
			c, readErr := resp.Body.Read(rBuf[n:])
			n += c
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				largeBufPool.Put(rBufPtr)
				return nil, echAccepted, fmt.Errorf("read body: %w", readErr)
			}
			if c == 0 {
				zeroReads++
				if zeroReads > maxZeroReads {
					largeBufPool.Put(rBufPtr)
					return nil, echAccepted, errors.New("response body stalled")
				}
			} else {
				zeroReads = 0
			}
			if n == len(rBuf) {
				var dummy [1]byte
				if extra, _ := resp.Body.Read(dummy[:]); extra > 0 {
					largeBufPool.Put(rBufPtr)
					return nil, echAccepted, errors.New("security constraint: response payload exceeded maximum buffer capacity")
				}
				break
			}
		}

		tightBuf := make([]byte, n)
		copy(tightBuf, rBuf[:n])
		largeBufPool.Put(rBufPtr)

		dnsResp := new(dns.Msg)
		if err := dnsResp.Unpack(tightBuf); err != nil {
			return nil, echAccepted, fmt.Errorf("unpack response: %w", err)
		}
		if valErr := u.validateUpstreamResponse(req, dnsResp, false, false, false); valErr != nil {
			return nil, echAccepted, valErr
		}
		return dnsResp, echAccepted, nil
	}

	_, isH3 := client.Transport.(*http3.Transport)
	was0RTT := isH3 && !u.no0RTT.Load() && !u.no0RTTVerified.Load()

	dnsResp, echAccepted, err := doSingleAttempt()
	if err == nil {
		return dnsResp, remoteAddr, echAccepted, nil
	}

	if ctx.Err() == nil && isRetryableHTTPError(err) {
		firstErr := err
		if was0RTT {
			u.no0RTT.Store(true)
		}
		client.CloseIdleConnections()
		dnsResp, echAccepted, err = doSingleAttempt()
		if err == nil {
			if was0RTT {
				u.lockNo0RTT()
				if logTLS || logSystem {
					log.Printf("[TLS] [QUIC] Upstream %s: HTTP/3 succeeded after disabling Allow0RTT (previous error: %v); keeping 0-RTT disabled for this upstream.",
						targetURL, firstErr)
				}
			}
			return dnsResp, remoteAddr, echAccepted, nil
		}
		if was0RTT {
			u.revertUnverifiedNo0RTT()
		}
	}

	return nil, remoteAddr, echAccepted, fmt.Errorf("http request: %w", err)
}

// ---------------------------------------------------------------------------
// QUIC (DoQ)
// ---------------------------------------------------------------------------

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, host string, fallbackNoECH bool) (*dns.Msg, string, bool, error) {
	key := host
	if fallbackNoECH {
		key += "_noech"
	}

	dialWithSF := func(sfKey string) (*doqConnEntry, error) {
		resCh := u.doqDialGroup.DoChan(sfKey, func() (any, error) {
			if entry := u.getDoQConn(key); entry != nil {
				return entry, nil
			}
			dialCtx, dialCancel := context.WithTimeout(context.Background(), streamTimeout)
			defer dialCancel()

			newConn, dialAddr, err := u.dialDoQ(dialCtx, host, u.dialAddrs, fallbackNoECH)
			if err != nil {
				return nil, err
			}

			entry := &doqConnEntry{conn: newConn, dialAddr: dialAddr, idleAt: time.Now()}
			u.doqMu.Lock()
			if old := u.doqConns[key]; old != nil && old.conn != newConn {
				old.conn.CloseWithError(0, "replaced")
			}
			u.doqConns[key] = entry
			u.doqMu.Unlock()
			return entry, nil
		})

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case r := <-resCh:
			if r.Err != nil {
				return nil, r.Err
			}
			if e, ok := r.Val.(*doqConnEntry); ok {
				return e, nil
			}
			return nil, errors.New("doq dial failed")
		}
	}

	if entry := u.getDoQConn(key); entry != nil {
		echAccepted := entry.conn.ConnectionState().TLS.ECHAccepted
		resp, err := u.doqStreamExchange(ctx, entry.conn, req)
		if err == nil {
			u.updateDoQIdle(key, entry)
			return resp, entry.dialAddr, echAccepted, nil
		}
		u.removeDoQConn(key, entry, "stale")
		if ctx.Err() != nil {
			return nil, entry.dialAddr, echAccepted, ctx.Err()
		}
	}

	was0RTT := !u.no0RTT.Load() && !u.no0RTTVerified.Load()
	entry, err := dialWithSF(key)
	if err != nil {
		if was0RTT && ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			firstErr := err
			u.no0RTT.Store(true)
			entry, err = dialWithSF(key + "_no0rtt")
			if err != nil {
				u.revertUnverifiedNo0RTT()
				return nil, u.RawURL, false, err
			}
			u.lockNo0RTT()
			if logTLS || logSystem {
				log.Printf("[TLS] [QUIC] Upstream %s: DoQ dial succeeded after disabling Allow0RTT (previous error: %v); keeping 0-RTT disabled for this upstream.",
					u.RawURL, firstErr)
			}
			was0RTT = false
		} else {
			return nil, u.RawURL, false, err
		}
	}

	echAccepted := entry.conn.ConnectionState().TLS.ECHAccepted
	resp, err := u.doqStreamExchange(ctx, entry.conn, req)

	if err != nil {
		u.removeDoQConn(key, entry, "exchange failed")

		if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			firstErr := err
			if was0RTT {
				u.no0RTT.Store(true)
			}
			retryEntry, retryErr := dialWithSF(key + "_retry")
			if retryErr == nil && retryEntry != nil {
				retryEch := retryEntry.conn.ConnectionState().TLS.ECHAccepted
				resp, err = u.doqStreamExchange(ctx, retryEntry.conn, req)
				if err == nil {
					if was0RTT {
						u.lockNo0RTT()
						if logTLS || logSystem {
							log.Printf("[TLS] [QUIC] Upstream %s: DoQ exchange succeeded after disabling Allow0RTT (previous error: %v); keeping 0-RTT disabled for this upstream.",
								u.RawURL, firstErr)
						}
					}
					u.updateDoQIdle(key, retryEntry)
					return resp, retryEntry.dialAddr, retryEch, nil
				}
				u.removeDoQConn(key, retryEntry, "retry failed")
			}
			if was0RTT {
				u.revertUnverifiedNo0RTT()
			}
		}
		return nil, entry.dialAddr, echAccepted, err
	}

	u.updateDoQIdle(key, entry)
	return resp, entry.dialAddr, echAccepted, nil
}

func (u *Upstream) getDoQConn(key string) *doqConnEntry {
	u.doqMu.Lock()
	entry := u.doqConns[key]
	u.doqMu.Unlock()

	if entry == nil {
		return nil
	}
	if time.Since(entry.idleAt) > doqIdleMax || entry.conn.Context().Err() != nil {
		u.removeDoQConn(key, entry, "idle or dead session")
		return nil
	}
	return entry
}

func (u *Upstream) updateDoQIdle(key string, entry *doqConnEntry) {
	u.doqMu.Lock()
	if u.doqConns[key] == entry {
		entry.idleAt = time.Now()
	}
	u.doqMu.Unlock()
}

func (u *Upstream) removeDoQConn(key string, entry *doqConnEntry, reason string) {
	u.doqMu.Lock()
	if u.doqConns[key] == entry {
		delete(u.doqConns, key)
	}
	u.doqMu.Unlock()
	entry.conn.CloseWithError(0, reason)
}

func (u *Upstream) dialDoQ(ctx context.Context, host string, addrs []string, fallbackNoECH bool) (*quic.Conn, string, error) {
	var tlsConf *tls.Config
	if fallbackNoECH && u.baseTLSConfNoECH != nil {
		tlsConf = u.baseTLSConfNoECH.Clone()
	} else if u.baseTLSConf != nil {
		tlsConf = u.baseTLSConf.Clone()
	} else {
		tlsConf = getHardenedTLSConfig()
		tlsConf.NextProtos = []string{"doq"}
	}

	if host != "" {
		tlsConf.ServerName = host
	}

	qConf := &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second,
		MaxIdleTimeout:       doqIdleMax,
		KeepAlivePeriod:      15 * time.Second,
		MaxIncomingStreams:   0,
	}

	var lastErr error
	for _, addr := range addrs {
		var conn *quic.Conn
		conn, lastErr = u.dialQUIC(ctx, addr, tlsConf, qConf)
		if lastErr == nil {
			return conn, addr, nil
		}
	}

	if lastErr != nil {
		return nil, "", fmt.Errorf("doq: all dial addresses failed for %s: %w", host, lastErr)
	}
	return nil, "", fmt.Errorf("doq: all dial addresses failed for %s", host)
}

func (u *Upstream) doqStreamExchange(ctx context.Context, conn *quic.Conn, req *dns.Msg) (*dns.Msg, error) {
	if conn == nil {
		return nil, errors.New("doq: nil connection")
	}

	streamCtx := ctx
	var streamCancel context.CancelFunc
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > streamTimeout {
		streamCtx, streamCancel = context.WithTimeout(ctx, streamTimeout)
		defer streamCancel()
	}

	stream, err := conn.OpenStreamSync(streamCtx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.CancelRead(0)

	stopStreamCancel := context.AfterFunc(streamCtx, func() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		_ = stream.SetDeadline(time.Now())
	})
	defer stopStreamCancel()

	deadline, ok := streamCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}
	stream.SetDeadline(deadline)

	pBufPtr := largeBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*pBufPtr)[:0])
	if err != nil {
		largeBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("pack buffer: %w", err)
	}

	if len(packed) > 65535 {
		largeBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("doq query too large for the RFC 9250 length prefix: %d bytes", len(packed))
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		largeBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := stream.Write(packed); err != nil {
		largeBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("write payload: %w", err)
	}
	if err := stream.Close(); err != nil {
		largeBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("close write stream: %w", err)
	}
	largeBufPool.Put(pBufPtr)

	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 {
		return nil, errors.New("doq: zero-length response")
	}

	respBuf := make([]byte, respLen)

	if _, readErr := io.ReadFull(stream, respBuf); readErr != nil {
		return nil, fmt.Errorf("read payload: %w", readErr)
	}

	resp := new(dns.Msg)
	if unpackErr := resp.Unpack(respBuf); unpackErr != nil {
		return nil, fmt.Errorf("unpack response: %w", unpackErr)
	}

	if valErr := u.validateUpstreamResponse(req, resp, false, false, false); valErr != nil {
		return nil, valErr
	}

	return resp, nil
}
