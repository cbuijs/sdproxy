/*
File:    dga.go
Version: 1.14.0
Last Updated: 25-Oct-2026 16:05 CET

Description:
  Zero-allocation Local Machine Learning inference engine for Domain Generation 
  Algorithm (DGA) detection. Implements a lightweight Logistic Regression classifier
  natively within the DNS pipeline to intercept stochastic botnet and C2 domains.

Changes:
  1.14.0 - [SECURITY/FIX] Removed the exploitable `strings.Contains(fullDomain, "awsdns-")`
           substring bypass and replaced it with `isVerifiedAWSDNS(fd)`, which
           strictly validates authentic AWS Route 53 nameserver apexes
           (`awsdns-<digits>.<org|com|net|co.uk>`) and optional `ns-<digits>.` prefixes.
         - [PERF] Pre-indexed `dgaSafeDomains` into `dgaSafeDomainMap` and replaced
           the linear slice scan with a zero-allocation label suffix walk.
  1.13.0 - [UPDATE] Updated SafeDomains with messengers and linkedin.
  1.12.0 - [SECURITY/FIX] Upgraded ML regression weights to comprehensively intercept 
           modern Dictionary DGAs.
  1.11.0 - [PERF] Deployed an O(1) pre-flight byte boundary evaluation inside the 
           Safe Domains whitelist.
  1.10.0 - [PERF] Replaced expensive floating-point transcendental math.Log2 calls 
           inside the Shannon Entropy hot loop with an O(1) precomputed lookup table.
  1.9.0  - [PERF] Optimized Shannon Entropy calculation mathematically.
  1.8.0  - [SECURITY/FIX] Resolved a severe ML inference evasion vulnerability natively.
  1.7.0  - [SECURITY] Expanded the DGA Safe Domains whitelist.
  1.6.0  - [FEAT] Added "arpa" to the DGA safe domains list.
  1.5.0  - [SECURITY] Integrated a static Safe CDN Whitelist.
*/

package main

import (
	"math"
	"strings"
)

// dgaSafeDomains provides a static whitelist of highly volatile, high-entropy
// CDNs, trackers, and telemetry endpoints.
var dgaSafeDomains = []string{
	// Amazon / AWS
	"amazonaws.com",
	"cloudfront.net",

	// Apple
	"apple.com",
	"icloud.com",
	"mac.com",
	"mzstatic.com",

	// CDNs & Edge Networks
	"akamai.net",
	"akamaiedge.net",
	"akamaized.net",
	"cdn77.org",
	"cloudflare.com",
	"cloudflare.net",
	"edgekey.net",
	"fastly.net",

	// Developer / Tech
	"github.com",
	"githubusercontent.com",

	// DNS Providers
	"adguard-dns.com",
	"cloudflare-dns.com",
	"dns.google",
	"dns.quad9.net",
	"nextdns.io",
	"opendns.com",

	// Google / Alphabet
	"googleapis.com",
	"googlevideo.com",
	"gstatic.com",

	// Infrastructure / Local
	"arpa",

	// Media / Social
	"deezer.com",
	"dzcdn.net",
	"fbcdn.net",
	"licdn.com",
	"linkedin.com",
	"netflix.com",
	"nflxext.com",
	"nflxvideo.net",
	"scdn.co",
	"spotify.com",
	"yahoo.com",
	"yimg.com",

	// Microsoft / Azure
	"azure.com",
	"azureedge.net",
	"microsoft.com",
	"office.com",
	"office365.com",
	"skype.com",
	"trafficmanager.net",
	"windows.com",
	"windows.net",
	"windowsupdate.com",

	// Messengers
	"signal.org",
	"whatsapp.com",
	"whatsapp.net",

	// Miscellaneous
	"local",
}

var dgaSafeDomainMap map[string]struct{}

var log2Table [257]float64

func init() {
	for i := 1; i <= 256; i++ {
		log2Table[i] = math.Log2(float64(i))
	}
	dgaSafeDomainMap = make(map[string]struct{}, len(dgaSafeDomains))
	for _, d := range dgaSafeDomains {
		dgaSafeDomainMap[d] = struct{}{}
	}
}

func getLog2(n int) float64 {
	if n <= 0 {
		return 0.0
	}
	if n <= 256 {
		return log2Table[n]
	}
	return math.Log2(float64(n))
}

// isVerifiedAWSDNS strictly validates whether fd is an official AWS Route 53
// nameserver domain: [ns-<digits>.]awsdns-<digits>.(org|com|net|co.uk).
// Prevents attackers from embedding "awsdns-" in arbitrary domains to evade DGA detection.
func isVerifiedAWSDNS(fd string) bool {
	var rest string
	switch {
	case strings.HasSuffix(fd, ".org"):
		rest = fd[:len(fd)-4]
	case strings.HasSuffix(fd, ".com"), strings.HasSuffix(fd, ".net"):
		rest = fd[:len(fd)-4]
	case strings.HasSuffix(fd, ".co.uk"):
		rest = fd[:len(fd)-6]
	default:
		return false
	}

	// Isolate the SLD label ("awsdns-<digits>")
	sld := rest
	prefix := ""
	if dot := strings.LastIndexByte(rest, '.'); dot >= 0 {
		prefix = rest[:dot]
		sld = rest[dot+1:]
	}

	if !strings.HasPrefix(sld, "awsdns-") {
		return false
	}
	sldNum := sld[7:]
	if len(sldNum) == 0 || len(sldNum) > 4 || !isAllDigits(sldNum) {
		return false
	}

	if prefix == "" {
		return true
	}

	// If a subdomain label is present, it must be "ns-<digits>"
	if !strings.HasPrefix(prefix, "ns-") {
		return false
	}
	nsNum := prefix[3:]
	return len(nsNum) > 0 && len(nsNum) <= 6 && isAllDigits(nsNum)
}

// isDGASafeDomain performs an O(1) per-label suffix walk against dgaSafeDomainMap.
func isDGASafeDomain(fd string) bool {
	search := fd
	for {
		if _, ok := dgaSafeDomainMap[search]; ok {
			return true
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}
	return false
}

// AnalyzeDGA evaluates the structural anomaly of a domain name string.
func AnalyzeDGA(fullDomain, domainCore string) float64 {
	length := len(domainCore)

	if length < 6 {
		return 0.0
	}

	if len(fullDomain) > 0 {
		fd := fullDomain
		if fd[len(fd)-1] == '.' {
			fd = fd[:len(fd)-1]
		}
		if len(fd) > 0 {
			if isDGASafeDomain(fd) || isVerifiedAWSDNS(fd) {
				return 0.0
			}
		}
	}

	var freqs [256]int
	vowels := 0
	consonants := 0
	digits := 0
	maxConsonants := 0
	currConsonants := 0
	effectiveLength := 0

	for i := 0; i < length; i++ {
		c := domainCore[i]

		if c == '.' {
			continue
		}
		effectiveLength++
		freqs[c]++

		isVowel := c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y'
		isDigit := c >= '0' && c <= '9'
		isAlpha := c >= 'a' && c <= 'z'

		if isVowel {
			vowels++
			currConsonants = 0
		} else if isDigit {
			digits++
			currConsonants = 0
		} else if isAlpha {
			consonants++
			currConsonants++
			if currConsonants > maxConsonants {
				maxConsonants = currConsonants
			}
		} else {
			currConsonants = 0
		}
	}

	trailingDigits := 0
	for i := length - 1; i >= 0; i-- {
		c := domainCore[i]
		if c == '.' {
			continue
		}
		if c >= '0' && c <= '9' {
			trailingDigits++
		} else {
			break
		}
	}

	if effectiveLength == 0 {
		return 0.0
	}

	sumFLogF := 0.0
	unique := 0.0
	fLength := float64(effectiveLength)

	for _, f := range freqs {
		if f > 0 {
			unique++
			sumFLogF += float64(f) * getLog2(f)
		}
	}
	entropy := getLog2(effectiveLength) - (sumFLogF / fLength)
	if entropy < 0 {
		entropy = 0
	}

	z := -8.0
	z += entropy * 1.2
	z += fLength * 0.02

	vRatio := float64(vowels) / fLength
	vSkew := math.Abs(vRatio - 0.3)
	z += vSkew * 4.0

	dRatio := float64(digits) / fLength
	z += dRatio * 8.5

	if maxConsonants > 4 {
		z += float64(maxConsonants-4) * 2.0
	}

	uRatio := unique / fLength
	z += uRatio * 3.0

	if trailingDigits > 3 {
		z += float64(trailingDigits-3) * 1.5
	}

	prob := 1.0 / (1.0 + math.Exp(-z))
	return prob * 100.0
}
