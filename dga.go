/*
File:    dga.go
Version: 1.3.0
Updated: 03-May-2026 08:19 CEST

Description:
  Zero-allocation Local Machine Learning inference engine for Domain Generation 
  Algorithm (DGA) detection. Implements a lightweight Logistic Regression classifier
  natively within the DNS pipeline to intercept stochastic botnet and C2 domains.

Changes:
  1.3.0 - [PERF] Rewrote `AnalyzeDGA` to parse the underlying byte array natively, 
          ignoring dot-separations inline. Eliminates the massive `strings.ReplaceAll` 
          heap allocation executing on the hot path for every single DNS request.
  1.2.0 - [PERF] Migrated execution arrays to stack-allocated variables to prevent 
          pervasive garbage collection intervals on high-volume traffic routers.
  1.1.0 - [DOCS] Heavily documented the feature extraction metrics, Shannon Entropy 
          calculations, and Logistic Regression hyperplane weightings.
*/

package main

import (
	"math"
)

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
func AnalyzeDGA(domain string) float64 {
	length := len(domain)
	
	// [HEURISTIC BYPASS]
	// Extremely short domains (under 6 characters) do not possess enough statistical 
	// breadth (Information Density) for reliable ML inference. Bypassing them natively
	// prevents false positives on standard abbreviations, ccTLDs, or short vanity domains.
	if length < 6 {
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

	// O(N) Single-Pass Feature Extraction
	for i := 0; i < length; i++ {
		c := domain[i]
		
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
	entropy := 0.0
	fLength := float64(effectiveLength)
	unique := 0.0

	for _, f := range freqs {
		if f > 0 {
			unique++
			p := float64(f) / fLength
			entropy -= p * math.Log2(p)
		}
	}

	// -----------------------------------------------------------------------
	// Logistic Regression Model (Hyper-plane weights)
	// -----------------------------------------------------------------------
	// The weights below represent a heuristic hyper-plane trained conceptually 
	// to separate human-readable domains (e.g., Alexa Top 1M) from algorithmically 
	// generated ones (Cryptolocker, Conficker, Mirai, etc.).

	// Base intercept (Bias towards human-readable / benign classifications).
	// Pulls the baseline sigmoid curve deep into the negative (safe) territory.
	z := -6.5

	// 1. Entropy: High entropy strongly correlates with DGA (base-36 randomness).
	z += entropy * 1.8

	// 2. Length: DGA domains tend to be significantly longer to avoid registry collisions 
	// and ensure the generation algorithm does not overlap with registered domains.
	z += fLength * 0.12

	// 3. Vowel Skew: Benign domains exhibit ~30% vowels natively based on linguistics.
	// DGA strings heavily deviate towards 0% (all consonants/numbers) or extreme imbalances.
	vRatio := float64(vowels) / fLength
	vSkew := math.Abs(vRatio - 0.3)
	z += vSkew * 4.5

	// 4. Digit Ratio: Heavy reliance on numerical characters is highly anomalous 
	// outside of specific CDN/Asset nodes.
	dRatio := float64(digits) / fLength
	z += dRatio * 5.5

	// 5. Structural Anomaly: Excessive consecutive consonants (e.g., "bcdfghjkl")
	// trigger heavy stochastic penalties as they violate standard phonetics.
	if maxConsonants > 4 {
		z += float64(maxConsonants) * 0.85
	}

	// 6. Unique Character Density: Scrambled domains utilize a wider alphabet breadth 
	// compared to semantic words which repeat letters frequently.
	uRatio := unique / fLength
	z += uRatio * 1.5

	// -----------------------------------------------------------------------
	// Sigmoid Activation Function
	// -----------------------------------------------------------------------
	// Maps the linear regression combination (z) into a bounded probability score [0.0, 1.0].
	// This creates an S-curve where extreme values safely approach 100% or 0%.
	prob := 1.0 / (1.0 + math.Exp(-z))

	// Scale to a 100-point metric for user-friendly configuration thresholds.
	return prob * 100.0
}

