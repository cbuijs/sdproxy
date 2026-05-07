/*
File:    server.go
Version: 1.33.0 (Split)
Last Updated: 03-May-2026 03:20 EDT

Description: 
  DNS Request handlers and response writers for TCP, DoT, DoH, and DoQ.
  Listener initialization has been extracted into server_init.go, leaving this
  file purely focused on translating transport protocols into ProcessDNS payloads.

Changes:
  1.33.0 - [SECURITY/FIX] Resolved a severe False-Positive Penalty Box flaw in the 
           HTTP/2 DoH unpacker limit reader. Clients supplying perfectly matched 64KB 
           DNS payloads were inadvertently blackholed, resulting in permanent 
           isolation from the resolver array natively.
*/

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// --- Protocol handlers ---

func handleTCP(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	ProcessDNS(w, r, ip, "TCP", "", "")
}

func handleDoT(w dns.ResponseWriter, r *dns.Msg) {
	var ip string
	if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
	}
	var sni string
	proto := "DoT"
	if cs, ok := w.(dns.ConnectionStater); ok {
		if state := cs.ConnectionState(); state != nil {
			sni = state.ServerName
			if state.ECHAccepted {
				proto += "+ECH"
			}
		}
	}
	ProcessDNS(w, r, ip, proto, sni, "")
}

func handleDoH(w http.ResponseWriter, r *http.Request) {
	var (
		payload []byte
		err     error
	)

	switch r.Method {
	case http.MethodPost:
		bufPtr := largeBufPool.Get().(*[]byte)
		buf    := *bufPtr
		defer largeBufPool.Put(bufPtr)
		defer r.Body.Close()

		n := 0
		for {
			c, readErr := r.Body.Read(buf[n:])
			n += c
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			// [SECURITY/FIX] Detect infinite stream exhaustion attacks
			// without false-positively dropping perfectly sized 64KB payloads.
			if n == len(buf) {
				var dummy [1]byte
				if extra, _ := r.Body.Read(dummy[:]); extra > 0 {
					host, _, err := net.SplitHostPort(r.RemoteAddr)
					if err != nil {
						host = r.RemoteAddr
					}
					var parsedAddr netip.Addr
					if a, err := netip.ParseAddr(host); err == nil {
						parsedAddr = a.Unmap()
					}
					PenalizeClient(host, parsedAddr, -1) // Instant Blackhole Ban
					http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
					return
				}
				break // Payload is exactly 64KB, fully intact
			}
		}
		payload = buf[:n]

	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		b64 = strings.TrimRight(b64, "=")
		payload, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			http.Error(w, "Invalid base64 payload", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(payload); err != nil {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		var parsedAddr netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			parsedAddr = a.Unmap()
		}
		PenalizeClient(host, parsedAddr, -1) 
		http.Error(w, "Malformed DNS payload", http.StatusBadRequest)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	var localIP net.IP
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		if localHost, _, err := net.SplitHostPort(la.String()); err == nil {
			localIP = net.ParseIP(localHost)
		}
	}

	proto := "DoH"
	if r.ProtoMajor == 3 || strings.HasPrefix(r.Proto, "HTTP/3") {
		proto = "DoH3"
	}
	
	var sni string
	if r.TLS != nil {
		sni = r.TLS.ServerName
		if r.TLS.ECHAccepted {
			proto += "+ECH"
		}
	}
	path := r.URL.Path

	ProcessDNS(&dohResponseWriter{w: w, remoteIP: host, localIP: localIP}, msg, host, proto, sni, path)
}

func handleDoQConnection(conn *quic.Conn) {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	var localIP net.IP
	if localHost, _, err := net.SplitHostPort(conn.LocalAddr().String()); err == nil {
		localIP = net.ParseIP(localHost)
	}
	
	var sni string
	cs := conn.ConnectionState()
	sni = cs.TLS.ServerName
	proto := "DoQ"
	if cs.TLS.ECHAccepted {
		proto += "+ECH"
	}

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		go func(s *quic.Stream) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[PANIC] Recovered in DoQ stream handler: %v", r)
				}
			}()
			defer s.Close()

			var lenBuf [2]byte
			if _, err := io.ReadFull(s, lenBuf[:]); err != nil {
				return
			}
			length := binary.BigEndian.Uint16(lenBuf[:])

			bufPtr := largeBufPool.Get().(*[]byte)
			buf    := *bufPtr
			defer largeBufPool.Put(bufPtr)

			if _, err := io.ReadFull(s, buf[:length]); err != nil {
				return
			}
			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:length]); err != nil {
				var parsedAddr netip.Addr
				if a, err := netip.ParseAddr(host); err == nil {
					parsedAddr = a.Unmap()
				}
				PenalizeClient(host, parsedAddr, -1) 
				return
			}
			ProcessDNS(&doqResponseWriter{stream: s, remoteIP: host, localIP: localIP}, msg, host, proto, sni, "")
		}(stream)
	}
}

// --- Helpers ---

func buildAltSvc(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "443" 
	}
	return `h3=":` + port + `"; ma=86400`
}

// --- Response Writer Adapters ---

type dohResponseWriter struct {
	w        http.ResponseWriter
	remoteIP string
	localIP  net.IP
}

func (dw *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}
	dw.w.Header().Set("Content-Type", "application/dns-message")
	_, err = dw.w.Write(packed)
	smallBufPool.Put(bufPtr)
	return err
}

func (dw *dohResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *dohResponseWriter) RemoteAddr() net.Addr        { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *dohResponseWriter) Write(b []byte) (int, error) { return dw.w.Write(b) }
func (dw *dohResponseWriter) Close() error                { return nil }
func (dw *dohResponseWriter) TsigStatus() error           { return nil }
func (dw *dohResponseWriter) TsigTimersOnly(bool)         {}
func (dw *dohResponseWriter) Hijack()                     {}

type doqResponseWriter struct {
	stream   *quic.Stream 
	remoteIP string
	localIP  net.IP
}

func (dw *doqResponseWriter) WriteMsg(msg *dns.Msg) error {
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := msg.PackBuffer((*bufPtr)[:0])
	if err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err = dw.stream.Write(lenBuf[:]); err != nil {
		smallBufPool.Put(bufPtr)
		return err
	}
	_, err = dw.stream.Write(packed)
	smallBufPool.Put(bufPtr)
	return err
}

func (dw *doqResponseWriter) LocalAddr() net.Addr {
	if dw.localIP == nil {
		return nil
	}
	return &net.IPAddr{IP: dw.localIP}
}
func (dw *doqResponseWriter) RemoteAddr() net.Addr        { return &net.IPAddr{IP: net.ParseIP(dw.remoteIP)} }
func (dw *doqResponseWriter) Write(b []byte) (int, error) { return dw.stream.Write(b) }
func (dw *doqResponseWriter) Close() error                { return dw.stream.Close() }
func (dw *doqResponseWriter) TsigStatus() error           { return nil }
func (dw *doqResponseWriter) TsigTimersOnly(bool)         {}
func (dw *doqResponseWriter) Hijack()                     {}

