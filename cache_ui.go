/*
File:    cache_ui.go
Version: 1.3.0 (Split)
Last Updated: 27-Nov-2026 13:30 CET

Description:
  Web UI API structures and introspection routines for the sdproxy Cache.
  Extracted from cache.go to isolate JSON string allocations away from
  high-performance cache interactions.

Changes:
  1.3.0 - [FEAT/FIX] Rendered `routeLocalTag` as `"local"` (distinct from
          `"synthetic"`), used `fullMsgRcode(msg)` so cached Extended RCODEs
          display accurately, and appended `[DO]`, `[CD]`, and `[RD=0]` flags
          to `Route` so partitioned cache entries are visually distinguishable.
  1.2.0 - [FIX] Included infinite-stale upstream entries in `DumpCache()` and
          replaced `dns.TypeToString` with `qtypeName`.
  1.1.0 - [PERF] Removed unnecessary deep-copies of immutable cache byte slices.
  1.0.0 - Initial extraction mapping structural introspection arrays.
*/

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CacheEntryCount returns the total number of entries currently held across
// all 32 shards.
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

type CacheEntryDump struct {
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	Route    string `json:"upstream_group"`
	Response string `json:"response"`
	Hits     uint32 `json:"hits"`
	CachedAt string `json:"timestamp"`
	TimeLeft string `json:"time_left"`
}

func DumpCache() []CacheEntryDump {
	if !cfg.Cache.Enabled {
		return nil
	}

	var dumps []CacheEntryDump
	now := time.Now().UnixNano()

	type snapshot struct {
		Key    DNSCacheKey
		Item   *cacheItem
		Packed []byte
		Hits   uint32
	}
	var snaps []snapshot

	for i := range shards {
		shard := shards[i]
		shard.RLock()
		for k, v := range shard.items {
			if isEntryDead(v, now) {
				continue
			}
			if p := v.packed.Load(); p != nil {
				snaps = append(snaps, snapshot{
					Key:    k,
					Item:   v,
					Packed: *p,
					Hits:   v.hits.Load(),
				})
			}
		}
		shard.RUnlock()
	}

	msg := new(dns.Msg)
	for _, s := range snaps {
		*msg = dns.Msg{}
		if err := msg.Unpack(s.Packed); err != nil {
			continue
		}

		var answers []string
		for _, rr := range msg.Answer {
			str := strings.ReplaceAll(rr.String(), "\t", " ")
			answers = append(answers, str)
		}

		textValue := strings.Join(answers, "\n")
		if textValue == "" {
			effRcode := fullMsgRcode(msg)
			if effRcode != dns.RcodeSuccess {
				textValue = RcodeStr(effRcode)
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

		var route string
		switch s.Item.routeName {
		case "":
			route = "synthetic"
		case routeLocalTag:
			route = "local"
		default:
			route = s.Item.routeName
		}

		if s.Key.ClientName != "" {
			route += " [" + s.Key.ClientName + "]"
		}
		if s.Key.ECS != "" && s.Key.ECS != "passed-ecs" {
			route += " [ECS: " + s.Key.ECS + "]"
		} else if s.Key.ECS == "passed-ecs" {
			route += " [ECS]"
		}
		if s.Key.DoBit {
			route += " [DO]"
		}
		if s.Key.CdBit {
			route += " [CD]"
		}
		if !s.Key.RecursionDesired {
			route += " [RD=0]"
		}

		dumps = append(dumps, CacheEntryDump{
			QName:    s.Key.Name,
			QType:    qtypeName(s.Key.Qtype),
			Route:    route,
			Response: textValue,
			Hits:     s.Hits,
			CachedAt: cachedAt,
			TimeLeft: timeLeft,
		})
	}

	return dumps
}
