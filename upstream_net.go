/*
File:    upstream_net.go
Version: 1.42.0
Last Updated: 05-Nov-2026 17:16 CET

Description:
  TCP, DoT, HTTP, and QUIC stream network dialers and protocol implementations.
  Extracted from upstream.go to isolate network transport bounds.

Changes:
  1.42.0 - [CRITICAL/FIX] Replaced `closer.Close()` with `CloseIdleConnections()`
           on `client.Transport` inside the `exchangeHTTP` retry path. In
           `quic-go/http3`, calling `http3.Transport.Close()` permanently sets
           `transport.closed = true` on the shared `http3.Transport` instance,
           causing every subsequent DoH3 / upgraded-DoH request on that upstream
           to fail forever with `http3: transport is closed`; `http3.Transport`
           implements `CloseIdleConnections()`, which safely evicts stale QUIC
           connections without permanently poisoning the transport.
  1.41.0 - [SECURITY/FIX] Closed idle HTTP/3 QUIC connections in addition to
           HTTP/2 inside the `exchangeHTTP` retry path.
  1.40.0 - [CRITICAL/FIX] Eliminated a silent stall in `exchangeHTTP` and `exchangeDoQ`:
             • Bounded each individual DoH/DoH3 HTTP attempt and body read in
               `exchangeHTTP` to a 5-second per-attempt deadline (`httpAttemptTimeout`)
               and wired a context-watcher goroutine to forcibly close `resp.Body` if
               the attempt or parent context expires mid-body-read.
             • Bounded `dialDoQ` and `u.doqDialGroup.Do` in `exchangeDoQ` with a
               dedicated 5-second dial context decoupled from the first caller's
               cancelable context, and checked `entry.conn.Context().Err() != nil` in
               `getDoQConn` so dead QUIC sessions are immediately evicted.
             • Added context-aware dial timeout in `dialStream`.
  1.39.0 - [SECURITY/FIX] Enforced `u.validateUpstreamResponse` across all stream
           and encrypted transports.
  1.38.0 - [FIX/CLEANUP] Added `conn == nil` defensive check in `doqStreamExchange`.
  1.37.0 - [SECURITY/FIX] Removed destructive `closer.Close()` call in `exchangeHTTP`
           retry path and added zero-progress read guard (`maxZeroReads = 64`).
  1.36.0 - [SECURITY/FIX] Fixed stale QUIC connection flush in `exchangeHTTP` retry path.
  1.35.0 - [BUG/FIX] Corrected `quic.Connection` to `*quic.Conn`.
  1.34.0 - [BUG/FIX] Corrected parameter usage when instantiating `quic.DialAddrEarly` and `quic.DialAddr`.
  1.33.0 - [SECURITY/FIX] Re-aligned DoQ 0-RTT anomaly fallback logic to definitively latch `doqNo0RTT` organically.
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
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// TCP / DoT connection reuse (Multiplexing Pool)
// ---------------------------------------------------------------------------

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
		var connReturned atomic.Bool
		doneReading := make(chan struct{})

		go func(c *dns.Conn) {
			select {
			case <-doneReading:
				return
			case <-ctx.Done():
				if connReturned.CompareAndSwap(false, true) {
					c.Close()
				}
			}
		}(conn)

		conn.SetDeadline(deadline)

		if err := conn.WriteMsg(req); err != nil {
			close(doneReading)
			conn.Close()
			return nil, false, fmt.Errorf("write msg: %w", err)
		}

		resp, err := conn.ReadMsg()
		close(doneReading)

		if err != nil || resp == nil {
			conn.Close()
			if err == nil {
				err = errors.New("empty response")
			} else {
				err = fmt.Errorf("read msg: %w", err)
			}
			return nil, false, err
		}

		if valErr := u.validateUpstreamResponse(req, resp, true, check0x20, false); valErr != nil {
			conn.Close()
			return nil, false, valErr
		}

		var echAccepted bool
		if tlsConn, ok := conn.Conn.(*tls.Conn); ok {
			echAccepted = tlsConn.ConnectionState().ECHAccepted
		}

		if ctx.Err() == nil {
			if connReturned.CompareAndSwap(false, true) {
				u.putStreamConn(poolKey, conn)
			} else {
				conn.Close()
			}
		} else {
			if connReturned.CompareAndSwap(false, true) {
				conn.Close()
			}
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

		doneBody := make(chan struct{})
		var bodyClosed atomic.Bool
		closeBody := func() {
			if bodyClosed.CompareAndSwap(false, true) {
				_ = resp.Body.Close()
			}
		}
		go func() {
			select {
			case <-doneBody:
			case <-reqCtx.Done():
				closeBody()
			}
		}()
		defer func() {
			close(doneBody)
			closeBody()
		}()

		var echAccepted bool
		if resp.TLS != nil {
			echAccepted = resp.TLS.ECHAccepted
		}

		if resp.StatusCode != http.StatusOK {
			return nil, echAccepted, fmt.Errorf("bad status code: %d", resp.StatusCode)
		}

		if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load() {
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

	dnsResp, echAccepted, err := doSingleAttempt()
	if err == nil {
		return dnsResp, remoteAddr, echAccepted, nil
	}

	if ctx.Err() == nil {
		errMsg := err.Error()
		if errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(errMsg, "H3 error") || strings.Contains(errMsg, "EOF") ||
			strings.Contains(errMsg, "connection reset") || strings.Contains(errMsg, "server closed") ||
			strings.Contains(errMsg, "PROTOCOL_ERROR") || strings.Contains(errMsg, "NO_ERROR") ||
			strings.Contains(errMsg, "CANCELLED") || strings.Contains(errMsg, "Application error") ||
			strings.Contains(errMsg, "Transport error") || strings.Contains(errMsg, "timeout") ||
			strings.Contains(errMsg, "Client.Timeout") || strings.Contains(errMsg, "0-RTT rejected") {

			// Both *http.Transport and *http3.Transport implement CloseIdleConnections().
			// Never call io.Closer.Close() on *http3.Transport as that permanently closes the shared transport.
			client.CloseIdleConnections()
			dnsResp, echAccepted, err = doSingleAttempt()
			if err == nil {
				return dnsResp, remoteAddr, echAccepted, nil
			}
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

	entry, err := dialWithSF(key)
	if err != nil {
		return nil, u.RawURL, false, err
	}

	echAccepted := entry.conn.ConnectionState().TLS.ECHAccepted
	resp, err := u.doqStreamExchange(ctx, entry.conn, req)

	if err != nil {
		u.removeDoQConn(key, entry, "exchange failed")

		if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			if !u.doqNo0RTT.Swap(true) {
				retryEntry, retryErr := dialWithSF(key + "_retry")
				if retryErr == nil && retryEntry != nil {
					retryEch := retryEntry.conn.ConnectionState().TLS.ECHAccepted
					resp, err = u.doqStreamExchange(ctx, retryEntry.conn, req)
					if err == nil {
						u.updateDoQIdle(key, retryEntry)
						return resp, retryEntry.dialAddr, retryEch, nil
					}
					u.removeDoQConn(key, retryEntry, "retry failed")
				}
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
		if !u.doqNo0RTT.Load() {
			qConf.Allow0RTT = true
			conn, lastErr = quic.DialAddrEarly(ctx, addr, tlsConf, qConf)
		} else {
			qConf.Allow0RTT = false
			conn, lastErr = quic.DialAddr(ctx, addr, tlsConf, qConf)
		}
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
