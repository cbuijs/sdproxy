/*
File:    parental_consolidation.go
Description:
  Parent-domain consolidation and deduplication operations.
  Extracted from parental_categories.go to group heavy tree-optimization algorithms.
  
  Now includes explicit CPU yielding routines natively to preserve processing 
  integrity on constrained router implementations.
*/

package main

import (
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Parent-domain consolidation
// ---------------------------------------------------------------------------

func consolidateParentDomains(apex map[string]string, threshold, homogeneityPct int) int {
	if threshold <= 0 {
		return 0
	}
	if homogeneityPct <= 0 || homogeneityPct > 100 {
		homogeneityPct = 90
	}
	total := 0
	votes := make(map[string]map[string]int)
	
	for {
		for k := range votes {
			delete(votes, k)
		}

		yieldCounter := 0
		for d := range apex {
			yieldCounter++
			// Organically relinquish the CPU core safely back to pending IO connections natively
			if yieldCounter%10000 == 0 {
				time.Sleep(time.Millisecond)
			}
			
			idx := strings.IndexByte(d, '.')
			if idx < 0 {
				continue
			}
			parent := d[idx+1:]
			if _, exists := apex[parent]; exists {
				continue
			}
			if votes[parent] == nil {
				votes[parent] = make(map[string]int)
			}
			votes[parent][apex[d]]++
		}

		added := 0
		for parent, catCounts := range votes {
			if strings.IndexByte(parent, '.') < 0 {
				continue
			}
			if isPublicSuffix(parent) {
				continue
			}
			if isSharedHostingDomain(parent) {
				continue
			}
			childCount := 0
			for _, n := range catCounts {
				childCount += n
			}
			if childCount < threshold {
				continue
			}
			winCat, winCount := "", 0
			for cat, n := range catCounts {
				if n > winCount {
					winCat, winCount = cat, n
				}
			}
			if winCount*100/childCount < homogeneityPct {
				continue
			}
			apex[parent] = winCat
			added++
		}
		if added == 0 {
			break
		}
		total += added
	}
	return total
}

// ---------------------------------------------------------------------------
// Apex deduplication
// ---------------------------------------------------------------------------

func dedupeApex(apex map[string]string) int {
	var remove []string
	yieldCounter := 0
	
	for k, cat := range apex {
		yieldCounter++
		// Organically relinquish the CPU core safely back to pending IO connections natively
		if yieldCounter%10000 == 0 {
			time.Sleep(time.Millisecond)
		}
		
		search := k
		for {
			idx := strings.IndexByte(search, '.')
			if idx < 0 {
				break
			}
			search = search[idx+1:]
			if parentCat, parentExists := apex[search]; parentExists {
				if parentCat == cat {
					remove = append(remove, k)
				}
				break
			}
		}
	}
	for _, k := range remove {
		delete(apex, k)
	}
	return len(remove)
}

