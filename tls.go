/*
File:    tls.go
Version: 1.13.0
Last Updated: 04-Nov-2026 19:58 CET

Description:
  TLS configuration helpers for sdproxy. Covers:
    - getHardenedTLSConfig: conservative cipher/curve base used by both server
      listeners (DoT, DoH, DoQ) and outbound upstream client dials (DoT, DoQ).
    - setupTLS: loads a cert/key pair from disk or generates an ephemeral
      self-signed P-256 cert when none is configured.
    - extractECHConfigs: parses binary ECHConfigList blobs natively.
    - generateSelfSignedCert: creates a 10-year ephemeral ECDSA certificate
      valid for both server auth and TLS negotiation.
    - extractPort: parses a "host:port" listener address and returns the port
      as uint16. Used only at startup to populate ddrDoH/T/QPort globals.

Changes:
  1.13.0 - [FIX] Enabled startup TLS certificate and ECH initialization logs in
           `setupTLS` when `logSystem` or `logTLS` is active so Simple Logging
           Mode (`logSimple: true`) retains all startup messages.
  1.12.0 - [SECURITY/FIX] Restored strict raw 32-byte X25519 ECH private seed ingestion. 
           Replaced aggressive `bytes.TrimSpace` operations with precise structural 
           newline truncations natively.
  1.11.0 - [LOGGING] Bound initialization diagnostics to `logTLS` toggle gracefully.
  1.10.0 - [FEAT] Exported validated, non-wildcard domains from the TLS leaf 
           certificate into `tlsAuthorizedNames` natively to power dynamic DDR 
           SVCB auto-population.
*/

package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func getHardenedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}
}

func extractECHConfigs(echConfigList []byte) ([][]byte, error) {
	var configs [][]byte
	if len(echConfigList) < 2 {
		return nil, errors.New("ECHConfigList too short")
	}

	listLen := int(binary.BigEndian.Uint16(echConfigList[0:2]))
	payload := echConfigList[2:]

	if listLen != len(payload) {
		payload = echConfigList
	}

	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, errors.New("malformed ECHConfig (truncated header)")
		}

		cfgLen := int(binary.BigEndian.Uint16(payload[2:4]))
		totalLen := 4 + cfgLen

		if len(payload) < totalLen {
			return nil, errors.New("malformed ECHConfig (truncated payload)")
		}

		configs = append(configs, payload[:totalLen])
		payload = payload[totalLen:]
	}

	return configs, nil
}

func setupTLS() *tls.Config {
	var (
		cert tls.Certificate
		err  error
	)
	if cfg.Server.TLSCert != "" && cfg.Server.TLSKey != "" {
		cert, err = tls.LoadX509KeyPair(cfg.Server.TLSCert, cfg.Server.TLSKey)
		if err != nil {
			log.Fatalf("[FATAL] TLS: cannot load cert/key: %v", err)
		}

		if logTLS || logSystem {
			log.Printf("[TLS] Loaded certificate from %s", cfg.Server.TLSCert)
		}

		if len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				var names []string
				if leaf.Subject.CommonName != "" {
					names = append(names, leaf.Subject.CommonName)
				}
				names = append(names, leaf.DNSNames...)

				for _, n := range names {
					if !strings.Contains(n, "*") && net.ParseIP(n) == nil {
						tlsAuthorizedNames = append(tlsAuthorizedNames, n)
					}
				}

				for _, ip := range leaf.IPAddresses {
					names = append(names, ip.String())
				}

				if logTLS || logSystem {
					if len(names) > 0 {
						log.Printf("[TLS] Certificate covers domains/IPs: %s", strings.Join(names, ", "))
					} else {
						log.Printf("[TLS] WARNING: Certificate has no explicit Subject CommonName or SANs")
					}
				}
			}
		}
	} else {
		if logTLS || logSystem {
			log.Println("[TLS] No cert/key configured — generating ephemeral self-signed certificate.")
		}
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[FATAL] TLS: cannot generate self-signed cert: %v", err)
		}
	}
	base := getHardenedTLSConfig()
	base.Certificates = []tls.Certificate{cert}
	base.NextProtos = []string{"h2", "http/1.1", "dot", "doq"}

	var echConfigBytes []byte
	if cfg.Server.ECHConfigList != "" {
		echConfigBytes, err = os.ReadFile(cfg.Server.ECHConfigList)
		if err != nil {
			log.Fatalf("[FATAL] TLS: cannot read ECH config list file %s: %v", cfg.Server.ECHConfigList, err)
		}
	}

	if cfg.Server.ECHKey != "" {
		keyBytes, err := os.ReadFile(cfg.Server.ECHKey)
		if err != nil {
			log.Fatalf("[FATAL] TLS: cannot read ECH key file %s: %v", cfg.Server.ECHKey, err)
		}

		var echPrivBytes []byte
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			privKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("[FATAL] TLS: failed to parse ECH PKCS8 private key: %v", err)
			}
			switch pk := privKeyAny.(type) {
			case []byte:
				echPrivBytes = pk
			case *ecdh.PrivateKey:
				echPrivBytes = pk.Bytes()
			default:
				log.Fatalf("[FATAL] TLS: unsupported ECH private key type %T", privKeyAny)
			}
		} else {
			rawKey := keyBytes
			if len(rawKey) == 33 && rawKey[32] == '\n' {
				rawKey = rawKey[:32]
			} else if len(rawKey) == 34 && rawKey[32] == '\r' && rawKey[33] == '\n' {
				rawKey = rawKey[:32]
			}
			if len(rawKey) == 32 {
				echPrivBytes = rawKey
			} else {
				log.Fatalf("[FATAL] TLS: ECH key file must be either PEM-encoded PKCS8 or a strictly 32-byte raw X25519 seed (got %d bytes)", len(keyBytes))
			}
		}

		if len(echConfigBytes) == 0 {
			log.Fatalf("[FATAL] TLS: ech_config_list must be provided if ech_key is set")
		}

		configs, err := extractECHConfigs(echConfigBytes)
		if err != nil || len(configs) == 0 {
			log.Fatalf("[FATAL] TLS: Failed to extract ECH configs from list: %v", err)
		}

		for _, cfgBytes := range configs {
			base.EncryptedClientHelloKeys = append(base.EncryptedClientHelloKeys, tls.EncryptedClientHelloKey{
				Config:     cfgBytes,
				PrivateKey: echPrivBytes,
			})
		}

		if logTLS || logSystem {
			log.Printf("[TLS] ECH (Encrypted Client Hello) keys enabled and loaded natively (Config: %s, Key: %s, Parsed %d config(s)).", cfg.Server.ECHConfigList, cfg.Server.ECHKey, len(configs))
		}
	} else if len(echConfigBytes) > 0 {
		log.Fatalf("[FATAL] TLS: ech_key must be provided if ech_config_list is set")
	}

	return base
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "sdproxy"},
		DNSNames:              []string{"localhost", "sdproxy"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func extractPort(addr string, defaultPort uint16) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return defaultPort
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return defaultPort
	}
	return uint16(p)
}
