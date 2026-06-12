/*
File:    upstream_net.go
Version: 1.29.0
Updated: 06-Jun-2026 14:47 CEST

Description:
  TCP, DoT, HTTP, and QUIC stream network dialers and protocol implementations.
  Extracted from upstream.go to isolate network transport bounds.

Changes:
  1.29.0 - [PERF/FIX] Completely eradicated Map Lock saturation during high-volume 
           cache-miss floods natively. The multiplexing pool `takeStreamConn` array 
           assignment is now explicitly hoisted outside the iteration loop, preventing 
           redundant writes and Mutex-thrashing while evaluating idle socket capacities.
  1.28.0 - [SECURITY/FIX] Hardened DoH, DoH3, and DoQ transport retry logic.
           Implemented strict Context Expiration Guards (`errors.Is(err, context.Canceled)`) 
           to actively prevent exhausted contexts from triggering cascading retry 
           loops natively. Eradicates CPU thrashing and goroutine saturation during 
           prolonged upstream outages or severe DDoS events.
  1.27.0 - [SECURITY/FIX] Intercepted `0-RTT rejected` QUIC anomalies dynamically 
           within the `exchangeHTTP` retry block. Natively flushes broken session 
           tickets when an upstream server restarts, enforcing a 1-RTT recovery 
           to cleanly re-establish 0-RTT capabilities organically.
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
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// TCP / DoT connection reuse (Multiplexing Pool)
// ---------------------------------------------------------------------------

const maxIdleStreamConns = 10

// takeStreamConn retrieves an idle TCP or DoT connection from the multiplexer pool.
// Natively evaluates the expiration horizon to guarantee stale sockets are pruned securely.
func (u *Upstream) takeStreamConn(addr string) *dns.Conn {
	var expiredConns []*dns.Conn

	u.streamMu.Lock()
	conns := u.streamConns[addr]
	var entry *streamConnEntry

	for len(conns) > 0 {
		entry = conns[len(conns)-1]
		conns = conns[:len(conns)-1]
		
		// Actively assess the connection's idle duration against the structural limit.
		if time.Since(entry.idleAt) > streamIdleMax {
			expiredConns = append(expiredConns, entry.conn)
			entry = nil
			continue
		}
		break
	}
	
	// [PERF/FIX] Hoisted map assignment outside the loop to eliminate redundant lock writes natively.
	if len(conns) == 0 {
		delete(u.streamConns, addr)
	} else {
		u.streamConns[addr] = conns
	}
	u.streamMu.Unlock()

	// [SECURITY/PERF] Close expired sockets strictly OUTSIDE the mutex.
	// Eliminates critical lock contention and pipeline stalling if the OS 
	// TCP stack or TLS layer hangs during the teardown sequence natively.
	for _, c := range expiredConns {
		c.Close()
	}

	if entry == nil {
		return nil
	}
	return entry.conn
}

// putStreamConn actively returns a healthy connection back into the multiplexer pool.
// Enforces strict bounds to prevent unbounded file descriptor consumption.
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

// dialStream establishes a fresh outbound TCP or DoT connection natively.
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

// exchangeStream handles the robust transmission and extraction of DNS messages over stream transports.
func (u *Upstream) exchangeStream(ctx context.Context, req *dns.Msg, dialAddr, tlsHost string, fallbackNoECH bool) (*dns.Msg, bool, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}

	poolKey := dialAddr
	if fallbackNoECH {
		poolKey += "_noech"
	}

	// [SECURITY/FIX] Enforce instantaneous connection shedding organically upon context 
	// cancellation. Employs a deterministic atomic lock (`connReturned`) to prevent 
	// double-closing or severing connections actively returning to the multiplexer pool natively.
	// Resolves catastrophic race conditions during highly parallel staggered engine fallback arrays.
	executeExchange := func(conn *dns.Conn) (*dns.Msg, bool, error) {
		var connReturned atomic.Bool
		doneReading := make(chan struct{})
		
		go func(c *dns.Conn) {
			select {
			case <-doneReading:
				return // Read completed successfully, safely disarm the watcher
			case <-ctx.Done():
				// Execution timed out or lost a parallel race. 
				// Atomically claim the socket to prevent the main routine from pooling a closed connection.
				if connReturned.CompareAndSwap(false, true) {
					c.Close() // Forcefully interrupt the blocking IO process securely
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
		close(doneReading) // Disarm watcher immediately to protect connection pooling
		
		if err != nil || resp == nil {
			conn.Close()
			if err == nil {
				err = errors.New("empty response")
			} else {
				err = fmt.Errorf("read msg: %w", err)
			}
			return nil, false, err
		}
		
		var echAccepted bool
		if tlsConn, ok := conn.Conn.(*tls.Conn); ok {
			echAccepted = tlsConn.ConnectionState().ECHAccepted
		}
		
		// Prevent recycling structurally poisoned or externally killed connections natively.
		// `connReturned` strictly locks the state, prohibiting background watchers from striking it.
		if ctx.Err() == nil {
			if connReturned.CompareAndSwap(false, true) {
				u.putStreamConn(poolKey, conn)
			} else {
				// Watcher Goroutine already claimed and severed the connection
				conn.Close()
			}
		} else {
			// Context is dead, claim the lock so the watcher doesn't double-close, and discard socket natively
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
		// If pooled connection fails (due to remote closure), safely fall through to dial a fresh one
	}

	conn, err := u.dialStream(dialAddr, tlsHost, fallbackNoECH)
	if err != nil {
		return nil, false, err 
	}
	
	return executeExchange(conn)
}

// ---------------------------------------------------------------------------
// HTTP (DoH / DoH3)
// ---------------------------------------------------------------------------

// exchangeHTTP manages execution for HTTP/2 and HTTP/3 transports natively.
func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, string, bool, error) {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return nil, "", false, fmt.Errorf("pack buffer: %w", err)
	}
	// Securely recycle the buffer exclusively after the function completes
	defer smallBufPool.Put(bufPtr)

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
	var separator string
	var encoded string

	// Dynamically evaluate HTTP Method structure (GET vs POST)
	if u.useGET {
		encoded = base64.RawURLEncoding.EncodeToString(packed)
		
		separator = "?"
		if strings.Contains(targetURL, "?") {
			separator = "&"
		}
		
		hReq, err = http.NewRequestWithContext(ctx, http.MethodGet, targetURL+separator+"dns="+encoded, nil)
	} else {
		hReq, err = http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(packed))
	}

	if err != nil {
		return nil, "", false, fmt.Errorf("new http request: %w", err)
	}

	if !u.useGET {
		hReq.Header.Set("Content-Type", "application/dns-message")
	}
	hReq.Header.Set("Accept", "application/dns-message")
	hReq.Header.Set("User-Agent", cfg.Server.UserAgent)

	resp, err := client.Do(hReq)
	
	if err != nil {
		errMsg := err.Error()
		
		// [SECURITY/FIX] Context Expiration Guard
		// Explicitly prevent the network dialer from retrying operations if the 
		// parent context has already been formally canceled or breached its deadline.
		// Retrying an expired context guarantees an instantaneous failure, 
		// causing severe CPU thrashing and log spam under heavy DDoS constraints.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			// Context is irreparably dead. Bypass the retry block natively.
		} else if strings.Contains(errMsg, "H3 error") || strings.Contains(errMsg, "EOF") || 
		   strings.Contains(errMsg, "connection reset") || strings.Contains(errMsg, "server closed") || 
		   strings.Contains(errMsg, "PROTOCOL_ERROR") || strings.Contains(errMsg, "NO_ERROR") ||
		   strings.Contains(errMsg, "CANCELLED") || strings.Contains(errMsg, "Application error") || 
		   strings.Contains(errMsg, "Transport error") || strings.Contains(errMsg, "timeout") ||
		   strings.Contains(errMsg, "0-RTT rejected") {
			
			// Force flush stale idle connections natively from the transport pool
			if tr, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
				tr.CloseIdleConnections()
			}

			// Dynamically intercept potential configuration errors organically.
			// Prevent nil-pointer panics if the URL mutation unexpectedly faults mid-stream natively.
			if u.useGET {
				hReq, err = http.NewRequestWithContext(ctx, http.MethodGet, targetURL+separator+"dns="+encoded, nil)
			} else {
				hReq, err = http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(packed))
				if err == nil {
					hReq.Header.Set("Content-Type", "application/dns-message")
				}
			}
			
			if err == nil {
				hReq.Header.Set("Accept", "application/dns-message")
				hReq.Header.Set("User-Agent", cfg.Server.UserAgent)
				// Execute exact-once hot-path retry
				resp, err = client.Do(hReq)
			}
		}
	}

	if err != nil {
		return nil, "", false, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	var echAccepted bool
	if resp.TLS != nil {
		echAccepted = resp.TLS.ECHAccepted
	}

	if resp.StatusCode != http.StatusOK {
		return nil, remoteAddr, echAccepted, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	// Process dynamic DoH3 Alt-Svc upgrades natively.
	if u.Proto == "doh" && cfg.Server.UpgradeDoH3 && !u.h3Upgraded.Load() {
		if strings.Contains(resp.Header.Get("Alt-Svc"), "h3=") {
			u.h3Upgraded.Store(true)
		}
	}

	rBufPtr := largeBufPool.Get().(*[]byte)
	rBuf := *rBufPtr

	n := 0
	// Execute a strict, allocation-free payload reading loop.
	// Bypasses restrictive `io.LimitReader` constructs to definitively isolate 
	// legitimate 64KB DNS envelopes from true infinite-stream attacks natively.
	for {
		c, readErr := resp.Body.Read(rBuf[n:])
		n += c
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			largeBufPool.Put(rBufPtr)
			return nil, remoteAddr, echAccepted, fmt.Errorf("read body: %w", readErr)
		}
		if n == len(rBuf) {
			// Memory Exhaustion Guard: Attempt to pluck 1 more byte.
			// If successful, the stream definitively breaches maximum safe capacities.
			var dummy [1]byte
			if extra, _ := resp.Body.Read(dummy[:]); extra > 0 {
				largeBufPool.Put(rBufPtr)
				return nil, remoteAddr, echAccepted, errors.New("security constraint: response payload exceeded maximum buffer capacity")
			}
			break // Payload is exactly 64KB, fully intact
		}
	}

	// [SECURITY/FIX] Enforce strict deep copy for the extracted payload array.
	// `miekg/dns` retains memory slices from the unpacked array organically. 
	// Deep copying guarantees that returning the read buffer to the `largeBufPool` 
	// does not expose active structural elements (e.g., NSEC salts, EDNS0 Options) 
	// to catastrophic concurrent corruption natively.
	tightBuf := make([]byte, n)
	copy(tightBuf, rBuf[:n])
	largeBufPool.Put(rBufPtr) // Safely release the mutable pooling structure

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(tightBuf); err != nil {
		return nil, remoteAddr, echAccepted, fmt.Errorf("unpack response: %w", err)
	}
	return dnsResp, remoteAddr, echAccepted, nil
}

// ---------------------------------------------------------------------------
// QUIC (DoQ)
// ---------------------------------------------------------------------------

// exchangeDoQ manages the creation and transmission of DNS-over-QUIC streams.
func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, host string, fallbackNoECH bool) (*dns.Msg, string, bool, error) {
	key := host
	if fallbackNoECH {
		key += "_noech"
	}

	// If a connection exists in the active pool, leverage it immediately to bypass handshake penalties.
	if entry := u.getDoQConn(key); entry != nil {
		echAccepted := entry.conn.ConnectionState().TLS.ECHAccepted
		resp, err := u.doqStreamExchange(ctx, entry.conn, req)
		if err == nil {
			u.updateDoQIdle(key, entry)
			return resp, entry.dialAddr, echAccepted, nil
		}
		u.removeDoQConn(key, entry, "stale")
	}

	// Serialize connection generation via SingleFlight to prevent concurrent dials during cache-miss floods.
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

		// [SECURITY/FIX] Context Expiration Guard
		// Bypass 1-RTT fallback retries if the context itself is the source of the failure.
		// A canceled or deadlined context guarantees the exact same failure organically, 
		// wasting critical socket dial resources and amplifying DDoS impacts.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
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
						u.doqNo0RTT.Store(false) // [SECURITY/FIX] Re-enable 0-RTT capabilities natively after a successful 1-RTT recovery
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
		KeepAlivePeriod:    15 * time.Second,
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

	// [SECURITY/FIX] Execute O(1) exact-length allocation to completely eradicate 
	// volatile memory contamination. Replaces `smallBufPool`/`largeBufPool` structures 
	// exclusively with precise slice deployments natively. Neutralizes the vulnerability 
	// where unpacked payloads retained direct pointers to actively rotated buffer pools.
	respBuf := make([]byte, respLen)

	if _, readErr := io.ReadFull(stream, respBuf); readErr != nil {
		return nil, fmt.Errorf("read payload: %w", readErr)
	}
	
	resp := new(dns.Msg)
	if unpackErr := resp.Unpack(respBuf); unpackErr != nil {
		return nil, fmt.Errorf("unpack response: %w", unpackErr)
	}
	
	return resp, nil
}

