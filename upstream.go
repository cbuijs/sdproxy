/*
File: upstream.go
Version: 1.12.0
Last Updated: 2026-02-27 21:10 CET
Description: Manages connections to external DNS providers.
             FIXED: Exchange returns the actual fully resolved targetURL for accurate logging.
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

	h2Client *http.Client
	h3Client *http.Client

	doqMu    sync.Mutex
	doqConns map[string]*quic.Conn
}

func ParseUpstream(raw string) (*Upstream, error) {
	u := &Upstream{}

	parts := strings.Split(raw, "#")
	urlPart := parts[0]
	if len(parts) > 1 {
		u.BootstrapIPs = strings.Split(parts[1], ",")
	}

	if strings.HasPrefix(urlPart, "udp://") {
		u.Proto = "udp"
		u.RawURL = strings.TrimPrefix(urlPart, "udp://")
	} else if strings.HasPrefix(urlPart, "tcp://") {
		u.Proto = "tcp"
		u.RawURL = strings.TrimPrefix(urlPart, "tcp://")
	} else if strings.HasPrefix(urlPart, "dot://") || strings.HasPrefix(urlPart, "tls://") {
		u.Proto = "dot"
		u.RawURL = strings.TrimPrefix(strings.TrimPrefix(urlPart, "dot://"), "tls://")
	} else if strings.HasPrefix(urlPart, "doh://") || strings.HasPrefix(urlPart, "https://") {
		u.Proto = "doh"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh://"), "https://")
		
		dialer := &net.Dialer{Timeout: 3 * time.Second}
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
							conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
							if err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return dialer.DialContext(ctx, network, addr)
				},
			},
		}
	} else if strings.HasPrefix(urlPart, "doh3://") || strings.HasPrefix(urlPart, "h3://") {
		u.Proto = "doh3"
		u.RawURL = "https://" + strings.TrimPrefix(strings.TrimPrefix(urlPart, "doh3://"), "h3://")
		
		u.h3Client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http3.Transport{
				TLSClientConfig: getHardenedTLSConfig(), 
				QUICConfig:      &quic.Config{
					Allow0RTT:          true,
					MaxIdleTimeout:     5 * time.Second,  
					MaxIncomingStreams: 10,               
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					if len(u.BootstrapIPs) > 0 {
						_, port, _ := net.SplitHostPort(addr)
						for _, ip := range u.BootstrapIPs {
							conn, err := quic.DialAddrEarly(ctx, net.JoinHostPort(ip, port), tlsCfg, cfg)
							if err == nil {
								return conn, nil
							}
						}
						return nil, errors.New("all bootstrap IPs failed")
					}
					return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
				},
			},
		}
	} else if strings.HasPrefix(urlPart, "doq://") {
		u.Proto = "doq"
		u.RawURL = strings.TrimPrefix(urlPart, "doq://")
		u.doqConns = make(map[string]*quic.Conn)
	} else {
		return nil, fmt.Errorf("unsupported protocol scheme in: %s", raw)
	}

	return u, nil
}

func (u *Upstream) Exchange(ctx context.Context, req *dns.Msg, clientName string) (*dns.Msg, string, error) {
	targetURL := strings.ReplaceAll(u.RawURL, "{client-name}", clientName)

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
			tlsConf := getHardenedTLSConfig() 
			tlsConf.ServerName = host         
			client = &dns.Client{
				Net:       "tcp-tls",
				Timeout:   3 * time.Second,
				TLSConfig: tlsConf,
			}
		} else {
			client = &dns.Client{Net: u.Proto, Timeout: 3 * time.Second}
		}

		var resp *dns.Msg
		var err error
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
	host := raw
	port := ""

	parsed, err := url.Parse("http://" + raw)
	if err == nil {
		host = parsed.Hostname()
		port = parsed.Port()
	} else {
		if strings.Contains(raw, ":") {
			host, port, _ = net.SplitHostPort(raw)
		}
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
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	packed, err := req.PackBuffer(buf[:0])
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

	respBufPtr := bufPool.Get().(*[]byte)
	respBuf := *respBufPtr
	defer bufPool.Put(respBufPtr)

	lr := io.LimitReader(resp.Body, 65535)
	n := 0
	for {
		c, err := lr.Read(respBuf[n:])
		n += c
		if err == io.EOF { break }
		if err != nil { return nil, err }
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(respBuf[:n]); err != nil {
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
		tlsConf := getHardenedTLSConfig() 
		tlsConf.ServerName = host
		tlsConf.NextProtos = []string{"doq"}
		
		var newConn *quic.Conn
		var connErr error

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

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufPool.Put(bufPtr)

	packed, err := req.PackBuffer(buf[:0])
	if err != nil {
		return nil, err
	}

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := stream.Write(lenBuf); err != nil {
		return nil, err
	}
	if _, err := stream.Write(packed); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(lenBuf)

	respBufPtr := bufPool.Get().(*[]byte)
	respBuf := *respBufPtr
	defer bufPool.Put(respBufPtr)

	if _, err := io.ReadFull(stream, respBuf[:length]); err != nil {
		return nil, err
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(respBuf[:length]); err != nil {
		return nil, err
	}

	return dnsResp, nil
}

