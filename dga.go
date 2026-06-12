/*
File:    dga.go
Version: 1.11.0
Updated: 04-Jun-2026 12:55 CEST

Description:
  Zero-allocation Local Machine Learning inference engine for Domain Generation 
  Algorithm (DGA) detection. Implements a lightweight Logistic Regression classifier
  natively within the DNS pipeline to intercept stochastic botnet and C2 domains.

Changes:
  1.11.0 - [PERF] Deployed an O(1) pre-flight byte boundary evaluation inside the 
           Safe Domains whitelist. Completely eradicates thousands of redundant 
           `strings.HasSuffix` overhead checks per second by aborting iterations 
           instantly if the terminal character mismatches natively.
  1.10.0 - [PERF] Replaced expensive floating-point transcendental math.Log2 calls 
           inside the Shannon Entropy hot loop with an O(1) precomputed lookup table.
           Saves CPU cycles, completely eliminating division operations in the loop.
  1.9.0  - [PERF] Optimized Shannon Entropy calculation mathematically to eliminate 
           costly float divisions inside the hot loop.
  1.8.0  - [SECURITY/FIX] Resolved a severe ML inference evasion vulnerability natively. 
           The DGA Safe Domains whitelist previously evaluated against the stripped `domainCore`, 
           causing legitimate infrastructure domains to artificially bypass the 
           whitelist logic and trigger false-positives. `AnalyzeDGA` now strictly 
           evaluates the pristine `fullDomain` bounds to guarantee accurate bypasses.
  1.7.0  - [SECURITY] Expanded the DGA Safe Domains whitelist to include YouTube 
           infrastructure (googlevideo.com), Deezer, and prominent DNS provider networks. 
           Integrated a dynamic substring bypass for AWS DNS (awsdns-) infrastructure.
  1.6.0  - [FEAT] Added "arpa" to the DGA safe domains list. Categorized and 
           sorted the safe domains list for better maintainability.
  1.5.0  - [SECURITY] Integrated a static Safe CDN Whitelist to explicitly bypass 
           ML inference for known high-entropy cloud providers (AWS, Azure, Google). 
           Eliminates false-positives on legitimate infrastructure.
*/

package main

import (
	"math"
	"strings"
)

// dgaSafeDomains provides a zero-allocation static whitelist of highly volatile, 
// high-entropy CDNs, trackers, and telemetry endpoints. Bypassing these natively 
// eliminates false-positives on legitimate infrastructure that frequently triggers ML models.
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
	"trafficmanager.net",
	"windowsupdate.com",
}

// log2Table precomputes float64 log2 values for the integers 1 to 256.
// Because DNS label lengths (max 63) and domain lengths (max 253) are strictly bounded,
// this allows O(1) table lookups for all possible character frequencies on the hot path.
var log2Table [257]float64

func init() {
	for i := 1; i <= 256; i++ {
		log2Table[i] = math.Log2(float64(i))
	}
}

// getLog2 returns the precomputed log2 value, or falls back to math.Log2 if n exceeds the table bounds.
func getLog2(n int) float64 {
	if n <= 0 {
		return 0.0
	}
	if n <= 256 {
		return log2Table[n]
	}
	return math.Log2(float64(n))
}

// AnalyzeDGA evaluates the structural anomaly of a domain name string.
// It extracts Shannon entropy, vowel/consonant skew, digit ratios, and consecutive 
// structural anomalies natively. These features are fed into a pre-weighted Logistic 
// Regression model (using a Sigmoid activation function) to output a highly accurate 
// probability anomaly score (0.0 to 100.0).
//
// [PERFORMANCE] 
// Executes in strict O(n) time complexity where n is the length of the domain.
// Operates with absolutely zero heap allocations (using stack arrays), ensuring it 
// can run safely on the hot-path for millions of queries without triggering Garbage 
// Collection (GC) pauses or latency spikes.
func AnalyzeDGA(fullDomain, domainCore string) float64 {
	length := len(domainCore)

	// [HEURISTIC BYPASS]
	// Extremely short domains (under 6 characters) do not possess enough statistical 
	// breadth (Information Density) for reliable ML inference. Bypassing them natively
	// prevents false positives on standard abbreviations, ccTLDs, or short vanity domains.
	if length < 6 {
		return 0.0
	}

	// [WHITELIST BYPASS]
	// Instantly bypass known legitimate high-entropy cloud providers natively.
	// We evaluate the pristine fullDomain string to guarantee infrastructural 
	// eTLD boundaries are accurately mapped without false-positives.
	if len(fullDomain) > 0 {
		lastByte := fullDomain[len(fullDomain)-1]
		for _, safe := range dgaSafeDomains {
			// [PERF/FIX] O(1) array truncation. Completely skip suffix evaluations 
			// if the terminating byte mismatches natively, saving CPU cycles.
			if len(safe) > 0 && safe[len(safe)-1] != lastByte {
				continue
			}
			if strings.HasSuffix(fullDomain, safe) {
				// Guarantee exact apex match or legitimate subdomain boundary
				if len(fullDomain) == len(safe) || fullDomain[len(fullDomain)-len(safe)-1] == '.' {
					return 0.0
				}
			}
		}
	}

	// [DYNAMIC INFRASTRUCTURE BYPASS]
	// Bypass dynamically numbered infrastructure domains that evade rigid suffix 
	// matching (e.g. AWS Route53 nameservers like ns-123.awsdns-45.net)
	if strings.Contains(fullDomain, "awsdns-") {
		return 0.0
	}

	// [MEMORY OPTIMIZATION]
	// Stack-allocated frequency map. Bypasses heap-escapes entirely, making the 
	// character distribution count incredibly fast and garbage-collection free.
	var freqs [256]int
	vowels := 0
	consonants := 0
	digits := 0
	maxConsonants := 0
	currConsonants := 0
	effectiveLength := 0

	// O(N) Single-Pass Feature Extraction against the core domain boundaries natively
	for i := 0; i < length; i++ {
		c := domainCore[i]

		// Bypass structural dot separators natively without creating string allocations
		if c == '.' {
			continue
		}
		effectiveLength++
		freqs[c]++ // Record byte frequency for Entropy calculation

		// Fast logical evaluations based on ASCII byte boundaries
		isVowel := c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y'
		isDigit := c >= '0' && c <= '9'
		isAlpha := c >= 'a' && c <= 'z'

		if isVowel {
			vowels++
			currConsonants = 0 // Reset consecutive consonant chain
		} else if isDigit {
			digits++
			currConsonants = 0 // Reset consecutive consonant chain
		} else if isAlpha {
			consonants++
			currConsonants++
			// Track the longest continuous chain of consonants (highly indicative of DGAs)
			if currConsonants > maxConsonants {
				maxConsonants = currConsonants
			}
		} else {
			// Hyphens or other non-alphanumeric structural characters reset the chain
			currConsonants = 0
		}
	}

	// Safe arithmetic guard if a domain consisted solely of delimiters
	if effectiveLength == 0 {
		return 0.0
	}

	// -----------------------------------------------------------------------
	// Shannon Entropy Calculation
	// -----------------------------------------------------------------------
	// Measures the Information Density (Stochastic Randomness) of the domain string.
	// Benign domains usually follow linguistic patterns (lower entropy). 
	// Base-36/Scrambled domains uniformly distribute characters (high entropy).
	//
	// [PERFORMANCE] Optimized via getLog2 O(1) table lookups to avoid expensive 
	// floating-point division and Log2 computations within the loop.
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

	// -----------------------------------------------------------------------
	// Logistic Regression Model (Hyper-plane weights)
	// -----------------------------------------------------------------------
	// The weights below represent a heuristic hyper-plane trained conceptually 
	// to separate human-readable domains from algorithmically generated ones 
	// (Cryptolocker, Conficker, Mirai, etc.).

	// Base intercept (Bias towards human-readable / benign classifications).
	// Pulls the baseline sigmoid curve deep into the negative (safe) territory 
	// to demand extraordinary proof of generation.
	z := -8.0

	// 1. Entropy: Flattened weight. High entropy correlates with DGA, but 
	// naturally scales upward linearly with long benign strings.
	z += entropy * 1.2

	// 2. Length: Flattened weight. DGA domains tend to be longer to avoid collisions, 
	// but aggressive penalization flags standard verbose API endpoints.
	z += fLength * 0.02

	// 3. Vowel Skew: Benign domains exhibit ~30% vowels natively based on linguistics.
	// DGA strings heavily deviate towards 0% (all consonants/numbers) or extreme imbalances.
	vRatio := float64(vowels) / fLength
	vSkew := math.Abs(vRatio - 0.3)
	z += vSkew * 4.0

	// 4. Digit Ratio: Heavy penalty. Reliance on numerical characters is highly anomalous 
	// outside of explicit CDN/Asset nodes and is a primary cryptographic DGA signature.
	dRatio := float64(digits) / fLength
	z += dRatio * 8.5

	// 5. Structural Anomaly: Excessive consecutive consonants (e.g., "bcdfghjkl")
	// trigger massive stochastic penalties as they physically violate phonetics.
	// Strictly penalizes the excess mass beyond the accepted deviation boundary.
	if maxConsonants > 4 {
		z += float64(maxConsonants-4) * 2.0
	}

	// 6. Unique Character Density: Scrambled domains utilize a wider alphabet breadth 
	// compared to semantic words which naturally repeat letters frequently.
	uRatio := unique / fLength
	z += uRatio * 3.0

	// -----------------------------------------------------------------------
	// Sigmoid Activation Function
	// -----------------------------------------------------------------------
	// Maps the linear regression combination (z) into a bounded probability score [0.0, 1.0].
	// This creates an S-curve where extreme values safely approach 100% or 0%.
	prob := 1.0 / (1.0 + math.Exp(-z))

	// Scale to a 100-point metric for user-friendly configuration thresholds.
	return prob * 100.0
}

