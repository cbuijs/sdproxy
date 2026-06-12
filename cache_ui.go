/*
File:    cache_ui.go
Version: 1.0.0 (Split)
Updated: 06-Jun-2026 15:00 CEST

Description:
  Web UI API structures and introspection routines for the sdproxy Cache.
  Extracted from cache.go to isolate JSON string allocations away from 
  high-performance cache interactions.
*/

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CacheEntryCount returns the total number of entries currently held across
// all 32 shards. Acquires each shard's read lock briefly — only called by the
// /api/stats poller (≤ once per 5 s), never in the DNS hot path.
func CacheEntryCount() int {
	if !cfg.Cache.Enabled {
		return 0
	}
	n := 0
	for _, s := range shards {
		s.RLock()
		n += len(s.items)
		s.RUnlock()
	}
	return n
}

// ---------------------------------------------------------------------------
// Cache Introspection (Web UI)
// ---------------------------------------------------------------------------

// CacheEntryDump encapsulates a single cache record dynamically extracted 
// for representation within the Web UI dashboard.
type CacheEntryDump struct {
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	Route    string `json:"upstream_group"`
	Response string `json:"response"`
	Hits     uint32 `json:"hits"`
	CachedAt string `json:"timestamp"`
	TimeLeft string `json:"time_left"`
}

// DumpCache iterates across all internal memory shards, securely locking and 
// replicating viable arrays to safely build an introspective snapshot of the 
// active DNS cache without inducing hot-path contention constraints natively.
func DumpCache() []CacheEntryDump {
	if !cfg.Cache.Enabled {
		return nil
	}

	var dumps []CacheEntryDump
	now := time.Now().UnixNano()

	type snapshot struct {
		Key      DNSCacheKey
		Item     *cacheItem
		Packed   []byte
		Hits     uint32
	}
	var snaps []snapshot

	// 1. Gather all active memory records natively using Read-Locks to minimize hot-path collision.
	for i := range shards {
		shard := shards[i]
		shard.RLock()
		for k, v := range shard.items {
			// Pre-emptively skip records completely outside the stale window bounds natively
			if now >= v.staleNano {
				continue
			}
			if p := v.packed.Load(); p != nil {
				packedCopy := make([]byte, len(*p))
				copy(packedCopy, *p)
				snaps = append(snaps, snapshot{
					Key:    k,
					Item:   v,
					Packed: packedCopy,
					Hits:   v.hits.Load(),
				})
			}
		}
		shard.RUnlock()
	}

	// 2. Unpack safely isolated from the core Mutexes natively
	msg := new(dns.Msg)
	for _, s := range snaps {
		*msg = dns.Msg{}
		if err := msg.Unpack(s.Packed); err != nil {
			continue
		}

		var answers []string
		for _, rr := range msg.Answer {
			// Strip tabs to maintain strict visual formatting boundaries
			str := strings.ReplaceAll(rr.String(), "\t", " ")
			answers = append(answers, str)
		}
		
		textValue := strings.Join(answers, "\n")
		if textValue == "" {
			if msg.Rcode != dns.RcodeSuccess {
				textValue = RcodeStr(msg.Rcode)
			} else {
				textValue = "NODATA"
			}
		}

		timeLeftSec := (s.Item.expireNano - now) / int64(time.Second)
		timeLeft := fmt.Sprintf("%ds", timeLeftSec)
		if timeLeftSec < 0 {
			timeLeft = fmt.Sprintf("Expired (%ds)", timeLeftSec)
		}

		cachedAt := time.Unix(0, s.Item.cachedAtNano).Format("2006-01-02 15:04:05")

		route := s.Item.routeName
		if route == "" {
			route = "synthetic"
		}
		
		// Append individualized client contexts strictly for introspection clarity
		if s.Key.ClientName != "" {
			route += " [" + s.Key.ClientName + "]"
		}
		if s.Key.ECS != "" && s.Key.ECS != "passed-ecs" {
			route += " [ECS: " + s.Key.ECS + "]"
		}

		dumps = append(dumps, CacheEntryDump{
			QName:    s.Key.Name,
			QType:    dns.TypeToString[s.Key.Qtype],
			Route:    route,
			Response: textValue,
			Hits:     s.Hits,
			CachedAt: cachedAt,
			TimeLeft: timeLeft,
		})
	}

	return dumps
}

