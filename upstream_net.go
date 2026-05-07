/*
File:    upstream_net.go
Version: 1.13.0 (Split)
Updated: 04-May-2026 22:02 CEST

Description:
  TCP, DoT, HTTP, and QUIC stream network dialers and protocol implementations.
  Extracted from upstream.go.

Changes:
  1.13.0 - [SECURITY/FIX] Injected explicit `User-Agent` headers into outbound HTTP 
           requests (DoH/DoH3) natively to prevent Web Application Firewalls (WAFs) 
           from indiscriminately dropping streams (H3 error 0x5 / REFUSED_STREAM).
  1.12.0 - [PERF] Addressed a fatal QUIC resumption regression in `dialDoQ`. 
           `baseTLSConf` is now securely cloned from the base configuration natively.
           This shares the `ClientSessionCache` across active dialects, radically 
           restoring 0-RTT handshakes and alleviating CPU negotiation spikes.
  1.11.0 - [PERF] Refactored `streamConns` to act as a deeply buffered LIFO slice 
           pool (`maxIdleStreamConns = 10`), resolving catastrophic TLS reconnection 
           floods under heavy TCP/DoT multiplexed caching workloads. Healthy 
           connections are now cleanly preserved.
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
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// TCP / DoT connection reuse (Multiplexing Pool)
// ---------------------------------------------------------------------------

const maxIdleStreamConns = 10

func (u *Upstream) takeStreamConn(addr string) *dns.Conn {
	u.streamMu.Lock()
	conns := u.streamConns[addr]
	var entry *streamConnEntry

	for len(conns) > 0 {
		entry = conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		
		if len(conns) == 0 {
			delete(u.streamConns, addr)
		} else {
			u.streamConns[addr] = conns
		}
		
		if time.Since(entry.idleAt) > streamIdleMax {
			entry.conn.Close()
			entry = nil
			continue
		}
		break
	}
	u.streamMu.Unlock()

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

func (u *Upstream) dialStream(addr, tlsHost string, fallbackNoECH bool) (*dns.Conn, error) {
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
		conn, err := dns.DialTimeoutWithTLS("tcp-tls", addr, tlsConf, streamTimeout)
		if err != nil {
			return nil, fmt.Errorf("dot dial: %w", err)
		}
		return conn, nil
	}
	
	conn, err := dns.DialTimeout("tcp", addr, streamTimeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	return conn, nil
}

func (u *Upstream) exchangeStream(ctx context.Context, req *dns.Msg, dialAddr, tlsHost string, fallbackNoECH bool) (*dns.Msg, bool, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	poolKey := dialAddr
	if fallbackNoECH {
		poolKey += "_noech"
	}

	if conn := u.takeStreamConn(poolKey); conn != nil {
		conn.SetDeadline(deadline)
		if err := conn.WriteMsg(req); err == nil {
			if resp, err := conn.ReadMsg(); err == nil && resp != nil {
				u.putStreamConn(poolKey, conn)
				
				var echAccepted bool
				if tlsConn, ok := conn.Conn.(*tls.Conn); ok {
					echAccepted = tlsConn.ConnectionState().ECHAccepted
				}
				return resp, echAccepted, nil
			}
		}
		conn.Close()
	}

	conn, err := u.dialStream(dialAddr, tlsHost, fallbackNoECH)
	if err != nil {
		return nil, false, err 
	}
	
	conn.SetDeadline(deadline)
	
	if err := conn.WriteMsg(req); err != nil {
		conn.Close()
		return nil, false, fmt.Errorf("write msg: %w", err)
	}
	
	resp, err := conn.ReadMsg()
	if err != nil {
		conn.Close()
		return nil, false, fmt.Errorf("read msg: %w", err)
	}
	
	if resp == nil {
		conn.Close()
		return nil, false, errors.New("empty response")
	}
	
	var echAccepted bool
	if tlsConn, ok := conn.Conn.(*tls.Conn); ok {
		echAccepted = tlsConn.ConnectionState().ECHAccepted
	}
	
	u.putStreamConn(poolKey, conn)
	return resp, echAccepted, nil
}

// ---------------------------------------------------------------------------
// HTTP (DoH / DoH3)
// ---------------------------------------------------------------------------

func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, string, bool, error) {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return nil, "", false, fmt.Errorf("pack buffer: %w", err)
	}

	var remoteAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if connInfo.Conn != nil {
				remoteAddr = connInfo.Conn.RemoteAddr().String()
			}
		},
	}
	ctx = httptrace.WithClientTrace(ctx, trace)

	var hReq *http.Request
	if u.useGET {
		encoded := base64.RawURLEncoding.EncodeToString(packed)
		smallBufPool.Put(bufPtr)
		hReq, err = http.NewRequestWithContext(ctx, http.MethodGet, targetURL+"?dns="+encoded, nil)
		if err != nil {
			return nil, "", false, fmt.Errorf("new http get request: %w", err)
		}
		hReq.Header.Set("Accept", "application/dns-message")
		hReq.Header.Set("User-Agent", "sdproxy/1.0")
	} else {
		defer smallBufPool.Put(bufPtr)
		hReq, err = http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(packed))
		if err != nil {
			return nil, "", false, fmt.Errorf("new http post request: %w", err)
		}
		hReq.Header.Set("Content-Type", "application/dns-message")
		hReq.Header.Set("Accept", "application/dns-message")
		hReq.Header.Set("User-Agent", "sdproxy/1.0")
	}

	resp, err := client.Do(hReq)
	if err != nil {
		return nil, remoteAddr, false, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	var echAccepted bool
	if resp.TLS != nil {
		echAccepted = resp.TLS.ECHAccepted
	}

	if resp.StatusCode != http.StatusOK {
		return nil, remoteAddr, echAccepted, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load() {
		if strings.Contains(resp.Header.Get("Alt-Svc"), "h3=") {
			u.h3Upgraded.Store(true)
		}
	}

	rBufPtr := largeBufPool.Get().(*[]byte)
	defer largeBufPool.Put(rBufPtr)
	rBuf := *rBufPtr

	n := 0
	lr := io.LimitReader(resp.Body, int64(len(rBuf)))
	for {
		c, readErr := lr.Read(rBuf[n:])
		n += c
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, remoteAddr, echAccepted, fmt.Errorf("read body: %w", readErr)
		}
		if n == len(rBuf) {
			return nil, remoteAddr, echAccepted, errors.New("security constraint: response payload exceeded maximum buffer capacity")
		}
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(rBuf[:n]); err != nil {
		return nil, remoteAddr, echAccepted, fmt.Errorf("unpack response: %w", err)
	}
	return dnsResp, remoteAddr, echAccepted, nil
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
	}

	resI, err, _ := u.doqDialGroup.Do(key, func() (any, error) {
		if entry := u.getDoQConn(key); entry != nil {
			return entry, nil
		}
		newConn, dialAddr, err := u.dialDoQ(ctx, host, u.dialAddrs, fallbackNoECH)
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

	if err != nil {
		return nil, u.RawURL, false, err
	}

	entry := resI.(*doqConnEntry)
	echAccepted := entry.conn.ConnectionState().TLS.ECHAccepted
	resp, err := u.doqStreamExchange(ctx, entry.conn, req)
	
	if err != nil {
		u.removeDoQConn(key, entry, "exchange failed")

		if !u.doqNo0RTT.Swap(true) {
			resI, retryErr, _ := u.doqDialGroup.Do(key+"_retry", func() (any, error) {
				retryConn, retryAddr, err := u.dialDoQ(ctx, host, u.dialAddrs, fallbackNoECH)
				if err != nil {
					return nil, err 
				}
				e := &doqConnEntry{conn: retryConn, dialAddr: retryAddr, idleAt: time.Now()}
				u.doqMu.Lock()
				if old := u.doqConns[key]; old != nil && old.conn != retryConn {
					old.conn.CloseWithError(0, "replaced")
				}
				u.doqConns[key] = e
				u.doqMu.Unlock()
				return e, nil
			})

			if retryErr == nil {
				retryEntry := resI.(*doqConnEntry)
				retryEch := retryEntry.conn.ConnectionState().TLS.ECHAccepted
				resp, err = u.doqStreamExchange(ctx, retryEntry.conn, req)
				if err == nil {
					u.updateDoQIdle(key, retryEntry)
					return resp, retryEntry.dialAddr, retryEch, nil
				}
				u.removeDoQConn(key, retryEntry, "retry failed")
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
	if time.Since(entry.idleAt) > doqIdleMax {
		u.removeDoQConn(key, entry, "idle timeout")
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
		MaxIdleTimeout:     doqIdleMax,
		MaxIncomingStreams: 0, 
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
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.CancelRead(0) 

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(streamTimeout)
	}
	stream.SetDeadline(deadline)

	pBufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*pBufPtr)[:0])
	if err != nil {
		smallBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("pack buffer: %w", err)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		smallBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := stream.Write(packed); err != nil {
		smallBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("write payload: %w", err)
	}
	if err := stream.Close(); err != nil {
		smallBufPool.Put(pBufPtr)
		return nil, fmt.Errorf("close write stream: %w", err)
	}
	smallBufPool.Put(pBufPtr) 

	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen == 0 {
		return nil, errors.New("doq: zero-length response")
	}

	var (
		rBufPtr *[]byte
		respBuf []byte
	)
	if respLen <= 4096 {
		rBufPtr = smallBufPool.Get().(*[]byte)
		respBuf = (*rBufPtr)[:respLen]
	} else {
		respBuf = make([]byte, respLen)
	}

	_, readErr := io.ReadFull(stream, respBuf)
	resp := new(dns.Msg)
	var unpackErr error
	if readErr == nil {
		unpackErr = resp.Unpack(respBuf)
	}
	
	if rBufPtr != nil {
		smallBufPool.Put(rBufPtr) 
	}
	
	if readErr != nil {
		return nil, fmt.Errorf("read payload: %w", readErr)
	}
	if unpackErr != nil {
		return nil, fmt.Errorf("unpack response: %w", unpackErr)
	}
	
	return resp, nil
}

