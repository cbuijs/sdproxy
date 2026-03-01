/*
File: upstream.go
Version: 1.13.0
Last Updated: 2026-03-01 14:00 CET
Description: Manages connections to external DNS upstream providers.
             Supports UDP, TCP, DoT, DoH (HTTP/2), DoH3 (QUIC/HTTP3), and DoQ.

Changes:
  1.13.0 - [PERF] Added hasClientNameTemplate bool to Upstream — checked once at
           ParseUpstream time. Avoids scanning RawURL for "{client-name}" on every
           single DNS query for the majority of upstreams that don't use it.
           [PERF] Added baseTLSConf *tls.Config to Upstream for DoT — the hardened
           TLS config (cipher suites, curves) is built once at parse time and
           Clone()'d per connection. Clone is significantly cheaper than a full
           struct + slice rebuild via getHardenedTLSConfig() on every DoT exchange.
           [PERF] Uses tiered buffer pools: smallBufPool (4KB) for message packing,
           largeBufPool (64KB) for stream/HTTP body reads where size is unknown.
  1.12.0 - Exchange returns actual resolved URL for accurate logging.
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type Upstream struct {
	Proto        string
	RawURL       string
	BootstrapIPs []string

	// hasClientNameTemplate is checked once at ParseUpstream time.
	// Avoids scanning RawURL on every DNS query for upstreams without {client-name}.
	hasClientNameTemplate bool

	// baseTLSConf is the pre-built hardened TLS config for DoT upstreams.
	// Clone()'d per connection to set ServerName — much cheaper than rebuilding
	// the full struct + cipher suite + curve slices on every exchange.
	baseTLSConf *tls.Config

	h2Client *http.Client
	h3Client *http.Client

	doqMu    sync.Mutex
	doqConns map[string]*quic.Conn
}

func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts  := strings.Split(raw, "#")
	urlPart := parts[0]
	if len(parts) > 1 {
		u.BootstrapIPs = strings.Split(parts[1], ",")
	}

	// Check once here so Exchange() can skip ReplaceAll for plain upstreams
	u.hasClientNameTemplate = strings.Contains(urlPart, "{client-name}")

	switch {
	case strings.HasPrefix(urlPart, "udp://"):
		u.Proto  = "udp"
		u.RawURL = strings.TrimPrefix(urlPart, "udp://")

	case strings.HasPrefix(urlPart, "tcp://"):
		u.Proto  = "tcp"
		u.RawURL = strings.TrimPrefix(urlPart, "tcp://")

	case strings.HasPrefix(urlPart, "dot://"), strings.HasPrefix(urlPart, "tls://"):
		u.Proto      = "dot"
		u.RawURL     = strings.TrimPrefix(strings.TrimPrefix(urlPart, "dot://"), "tls://")
		u.baseTLSConf = getHardenedTLSConfig() // Built once; Clone()'d in Exchange()

	case strings.HasPrefix(urlPart, "doh://"), strings.HasPrefix(urlPart, "https://"):
		u.Proto  = "doh"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh://"), "https://")
		dialer  := &net.Dialer{Timeout: 3 * time.Second}
		u.h2Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     getHardenedTLSConfig(),
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        5,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     5 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							if conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port)); err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return dialer.DialContext(ctx, network, addr)
				},
			},
		}

	case strings.HasPrefix(urlPart, "doh3://"), strings.HasPrefix(urlPart, "h3://"):
		u.Proto  = "doh3"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh3://"), "h3://")
		u.h3Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http3.Transport{
				TLSClientConfig: getHardenedTLSConfig(),
				QUICConfig: &quic.Config{
					Allow0RTT:          true,
					MaxIdleTimeout:     5 * time.Second,
					MaxIncomingStreams: 10,
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							if conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, port), tlsCfg, cfg); err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
				},
			},
		}

	case strings.HasPrefix(urlPart, "doq://"):
		u.Proto    = "doq"
		u.RawURL   = strings.TrimPrefix(urlPart, "doq://")
		u.doqConns = make(map[string]*quic.Conn)

	default:
		return nil, fmt.Errorf("unsupported protocol scheme in: %s", raw)
	}

	return u, nil
}

func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	// Conditional ReplaceAll: skip the scan for the majority of upstreams
	// that don't use {client-name} — checked once at ParseUpstream time.
	targetURL := u.RawURL
	if u.hasClientNameTemplate {
		targetURL = strings.ReplaceAll(u.RawURL, "{client-name}", clientName)
	}

	switch u.Proto {
	case "udp", "tcp", "dot":
		host, port := parseHostPort(targetURL, u.Proto)

		dialAddrs := []string{net.JoinHostPort(host, port)}
		if len(u.BootstrapIPs) > 0 {
			dialAddrs = nil
			for _, ip := range u.BootstrapIPs {
				dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
			}
		}

		var client *dns.Client
		if u.Proto == "dot" {
			// Clone the pre-built config (set in ParseUpstream) and add ServerName.
			// Clone is O(copy) vs getHardenedTLSConfig() which allocates fresh slices.
			tlsConf            := u.baseTLSConf.Clone()
			tlsConf.ServerName  = host
			client = &dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: tlsConf}
		} else {
			client = &dns.Client{Net: u.Proto, Timeout: 3 * time.Second}
		}

		var resp *dns.Msg
		var err  error
		for _, dialAddr := range dialAddrs {
			resp, _, err = client.ExchangeContext(ctx, req, dialAddr)
			if err == nil && resp != nil {
				return resp, targetURL, nil
			}
		}
		return nil, targetURL, err

	case "doh":
		resp, err := u.exchangeHTTP(ctx, req, targetURL, u.h2Client)
		return resp, targetURL, err

	case "doh3":
		resp, err := u.exchangeHTTP(ctx, req, targetURL, u.h3Client)
		return resp, targetURL, err

	case "doq":
		resp, err := u.exchangeDoQ(ctx, req, targetURL)
		return resp, targetURL, err

	default:
		return nil, targetURL, errors.New("unknown protocol")
	}
}

func parseHostPort(raw, proto string) (string, string) {
	host, port := raw, ""
	if parsed, err := url.Parse("http://" + raw); err == nil {
		host = parsed.Hostname()
		port = parsed.Port()
	} else if strings.Contains(raw, ":") {
		host, port, _ = net.SplitHostPort(raw)
	}
	if port == "" {
		switch proto {
		case "udp", "tcp":
			port = "53"
		case "dot", "doq":
			port = "853"
		}
	}
	return host, port
}

func (u *Upstream) exchangeHTTP(ctx context.Context, req *dns.Msg, targetURL string, client *http.Client) (*dns.Msg, error) {
	// smallBufPool for packing outgoing request — DNS messages are always small
	bufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*bufPtr)[:0])
	smallBufPool.Put(bufPtr)
	if err != nil {
		return nil, err
	}

	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/dns-message")
	hReq.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(hReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	// largeBufPool for reading the response body — size is unknown ahead of time
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
			return nil, readErr
		}
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(rBuf[:n]); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

func (u *Upstream) exchangeDoQ(ctx context.Context, req *dns.Msg, targetURL string) (*dns.Msg, error) {
	host, port := parseHostPort(targetURL, "doq")

	dialAddrs := []string{net.JoinHostPort(host, port)}
	if len(u.BootstrapIPs) > 0 {
		dialAddrs = nil
		for _, ip := range u.BootstrapIPs {
			dialAddrs = append(dialAddrs, net.JoinHostPort(ip, port))
		}
	}

	u.doqMu.Lock()
	conn, exists := u.doqConns[targetURL]
	if !exists || conn == nil {
		tlsConf            := getHardenedTLSConfig()
		tlsConf.ServerName  = host
		tlsConf.NextProtos  = []string{"doq"}

		var newConn  *quic.Conn
		var connErr  error
		for _, dialAddr := range dialAddrs {
			c, err := quic.DialAddr(context.Background(), dialAddr, tlsConf, &quic.Config{
				Allow0RTT:          true,
				MaxIdleTimeout:     5 * time.Second,
				MaxIncomingStreams: 10,
			})
			if err == nil {
				newConn = c
				break
			}
			connErr = err
		}
		if newConn == nil {
			u.doqMu.Unlock()
			return nil, connErr
		}
		conn = newConn
		u.doqConns[targetURL] = conn
	}
	u.doqMu.Unlock()

	stream, err := (*conn).OpenStreamSync(ctx)
	if err != nil {
		u.doqMu.Lock()
		delete(u.doqConns, targetURL)
		u.doqMu.Unlock()
		return nil, err
	}
	defer stream.Close()

	// smallBufPool for packing outgoing request
	sBufPtr := smallBufPool.Get().(*[]byte)
	packed, err := req.PackBuffer((*sBufPtr)[:0])
	smallBufPool.Put(sBufPtr)
	if err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packed)))
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return nil, err
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf[:])

	// largeBufPool for reading the response — length known but could be up to 65535
	rBufPtr := largeBufPool.Get().(*[]byte)
	defer largeBufPool.Put(rBufPtr)

	if _, err := io.ReadFull(stream, (*rBufPtr)[:length]); err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack((*rBufPtr)[:length]); err != nil {
		return nil, err
	}
	return dnsResp, nil
}

