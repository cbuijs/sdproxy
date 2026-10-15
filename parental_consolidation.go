/*
File:    parental_consolidation.go
Version: 1.0.0
Last Updated: 24-Jul-2026 14:05 CEST

Description:
  Parent-domain consolidation and deduplication operations.
  Extracted from parental_categories.go to group heavy tree-optimization algorithms.
  
  Now includes explicit CPU yielding routines natively to preserve processing 
  integrity on constrained router implementations.

  Exports two blocklist-compaction primitives consumed by the parental category
  loader pipeline:
    consolidateParentDomains - collapses a homogeneous cluster of sibling
                               sub-domains up into their shared parent apex once
                               the child count clears `threshold` and the category
                               agreement clears `homogeneityPct`. Iterates to a
                               fixed point so multi-level trees fully collapse.
    dedupeApex               - strips any entry already covered by a broader
                               parent apex already present in the map, shrinking
                               the resident rule set without changing match
                               semantics.

Changes:
  1.0.0  - [HOUSEKEEPING] Established the standard file header block. This file was
           the sole Go source in the package carrying no `Version:`, no
           `Last Updated:` and no `Changes:` trail, which broke the repository-wide
           header convention and made its revision state untrackable during audits.
           Baselined at 1.0.0 and documented against its current behaviour. No
           executable code was altered by this change — header/comment only.
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



