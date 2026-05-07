/*
File:    tls.go
Version: 1.10.0
Updated: 06-May-2026 11:58 CEST

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
  1.10.0 - [FEAT] Exported validated, non-wildcard domains from the TLS leaf 
           certificate into `tlsAuthorizedNames` natively to power dynamic DDR 
           SVCB auto-population.
  1.9.0  - [FEAT] Added startup logging of authorized Domain Names (SANs and 
           CommonName) embedded within the configured TLS certificate natively.
  1.8.0  - [SECURITY/FIX] Repaired a fatal cryptographic corruption flaw when loading 
           raw 32-byte X25519 ECH private seeds natively. Removed indiscriminate execution 
           of `bytes.TrimSpace` which systematically corrupted perfectly valid keys ending 
           in bytes mirroring ASCII whitespace vectors (e.g., 0x20 Space, 0x0A Newline). 
           Trimming is now strictly bound to payloads padded by text editors.
  1.7.0  - [SECURITY/FIX] Severely fortified ephemeral TLS Certificate creation to properly 
           align with X.509 Basic Constraints. The `KeyUsageCertSign` flag was permanently 
           stripped as modern strict TLS implementations (e.g., Apple ATS, BoringSSL) 
           immediately sever handshakes against leaf certificates masquerading as rogue 
           Certificate Authorities (`IsCA: false` but signing capable).
  1.6.0  - [SECURITY/FIX] Fortified X25519 ECH private key loading. Exchanged rigid 
           array-length slice boundaries with `bytes.TrimSpace()` to natively 
           isolate keys padded by CRLF (\r\n) artifacts from text editors, 
           resolving startup panics.
  1.5.0  - [SECURITY/FIX] Resolved an ECH server initialization vulnerability where 
           the Go 1.24+ `crypto/tls` native library strictly requires isolated `ECHConfig` 
           structures, but `bssl` generates complete `ECHConfigList` bundles (required 
           for DDR/SVCB). Developed `extractECHConfigs` to parse, validate, and bridge 
           the lists dynamically.
*/

package main

import (
	"bytes"
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

// getHardenedTLSConfig returns a *tls.Config with a conservative cipher suite
// and curve list. No certificate is attached — callers that need a server cert
// call setupTLS() instead, which adds one on top.
//
// Used for:
//   - All encrypted server listeners (DoT, DoH, DoQ).
//   - Outbound upstream client dials where we're the TLS client (DoT, DoH, DoQ).
func getHardenedTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		
		// [PERFORMANCE HARDENING] 
		// Caching session tickets enables abbreviated TLS handshakes upon reconnecting 
		// to upstreams. This prevents CPU-intensive asymmetric cryptographic operations 
		// (Full Handshakes) when idle connection pools rotate.
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

// extractECHConfigs parses an RFC 9460 ECHConfigList and returns the individual ECHConfig payloads.
// Go's tls.Config.EncryptedClientHelloKeys expects single ECHConfigs natively, 
// whereas the raw file (and DDR/SVCB) contains the full length-prefixed list.
func extractECHConfigs(echConfigList []byte) ([][]byte, error) {
	var configs [][]byte
	if len(echConfigList) < 2 {
		return nil, errors.New("ECHConfigList too short")
	}
	
	// Check if the payload matches a 2-byte length-prefixed list (standard for bssl output)
	listLen := int(binary.BigEndian.Uint16(echConfigList[0:2]))
	payload := echConfigList[2:]
	
	if listLen != len(payload) {
		// Fallback: assume the buffer is already the un-prefixed ECHConfig array
		payload = echConfigList
	}
	
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, errors.New("malformed ECHConfig (truncated header)")
		}
		
		// ECHConfig structure:
		// uint16 version;
		// uint16 length;
		// opaque contents[length];
		
		cfgLen := int(binary.BigEndian.Uint16(payload[2:4]))
		totalLen := 4 + cfgLen
		
		if len(payload) < totalLen {
			return nil, errors.New("malformed ECHConfig (truncated payload)")
		}
		
		// Extract the exact, complete ECHConfig structure (including version and length headers)
		configs = append(configs, payload[:totalLen])
		
		// Advance the payload window
		payload = payload[totalLen:]
	}
	
	return configs, nil
}

// setupTLS loads or auto-generated TLS config for encrypted listeners.
//   - Both tls_cert and tls_key set → load from disk.
//   - Either absent                 → generate ephemeral self-signed P-256 cert.
//
// The returned *tls.Config has NextProtos set for H2, HTTP/1.1, DoT, and DoQ.
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
		log.Printf("[TLS] Loaded certificate from %s", cfg.Server.TLSCert)

		// Parse the loaded leaf certificate to log the configured domain identities.
		// Ensures operators have absolute visibility over accepted TLS handshakes.
		if len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				var names []string
				if leaf.Subject.CommonName != "" {
					names = append(names, leaf.Subject.CommonName)
				}
				names = append(names, leaf.DNSNames...)
				
				// Identify and store strictly valid domain names for DDR populations.
				// Explicitly prevents wildcard domains and IP Addresses from infecting the DDR lists natively.
				for _, n := range names {
					if !strings.Contains(n, "*") && net.ParseIP(n) == nil {
						tlsAuthorizedNames = append(tlsAuthorizedNames, n)
					}
				}

				for _, ip := range leaf.IPAddresses {
					names = append(names, ip.String())
				}
				if len(names) > 0 {
					log.Printf("[TLS] Certificate covers domains/IPs: %s", strings.Join(names, ", "))
				} else {
					log.Printf("[TLS] Certificate has no explicit Subject CommonName or SANs")
				}
			}
		}
	} else {
		log.Println("[TLS] No cert/key configured — generating ephemeral self-signed certificate.")
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("[FATAL] TLS: cannot generate self-signed cert: %v", err)
		}
	}
	base             := getHardenedTLSConfig()
	base.Certificates = []tls.Certificate{cert}
	base.NextProtos   = []string{"h2", "http/1.1", "dot", "doq"}

	// Configure Encrypted Client Hello (ECH) parameters securely.
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
		// Support both standard PEM (OpenSSL) and Raw X25519 32-byte Seeds (BoringSSL) natively.
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
			// [SECURITY/FIX] Only attempt to trim whitespace if the payload exceeds 32 bytes
			// to safely preserve raw 32-byte cryptographic seeds natively. Prevents corrupting
			// binary keys that legitimately end in ASCII-whitespace byte codes (e.g., 0x20 or 0x0A).
			if len(keyBytes) > 32 {
				rawKey = bytes.TrimSpace(keyBytes)
			}
			if len(rawKey) == 32 {
				echPrivBytes = rawKey
			} else {
				log.Fatalf("[FATAL] TLS: ECH key file must be either PEM-encoded PKCS8 or a raw 32-byte X25519 seed (got %d bytes)", len(keyBytes))
			}
		}
		
		if len(echConfigBytes) == 0 {
			log.Fatalf("[FATAL] TLS: ech_config_list must be provided if ech_key is set")
		}

		// Go's server ECH implementation strictly requires singular ECHConfig structures, 
		// whereas the `bssl` output contains the full ECHConfigList.
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

		log.Printf("[TLS] ECH (Encrypted Client Hello) keys enabled and loaded natively (Config: %s, Key: %s, Parsed %d config(s)).", cfg.Server.ECHConfigList, cfg.Server.ECHKey, len(configs))
	} else if len(echConfigBytes) > 0 {
		log.Fatalf("[FATAL] TLS: ech_key must be provided if ech_config_list is set")
	}

	return base
}

// generateSelfSignedCert creates an ephemeral P-256 ECDSA certificate valid
// for 10 years. The cert is self-signed and includes standard SANs so modern 
// clients (which ignore CommonName) will accept it for local routing.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Generate a cryptographically secure 128-bit random serial number
	// to comply with RFC 5280 and prevent trivial fingerprinting.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "sdproxy"},
		// Modern clients ignore CommonName; we must provide SANs
		DNSNames:     []string{"localhost", "sdproxy"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		
		// [SECURITY/FIX] Stripped x509.KeyUsageCertSign
		// Assigning Certificate Signing capabilities to a non-CA leaf certificate 
		// explicitly violates X.509 Basic Constraints parameters.
		// Modern strict TLS implementations (Apple ATS, BoringSSL) aggressively 
		// sever handshakes against these rogue CAs natively.
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		
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

// extractPort parses a listener address ("ip:port" or ":port") and returns
// the port as uint16. Returns defaultPort when parsing fails.
// Used at startup to populate ddrDoH/T/QPort globals.
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

