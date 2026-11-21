/*
File:    cache_persistence.go
Version: 2.24.0 (Split)
Last Updated: 18-Nov-2026 17:45 CET

Description:
  Disk persistence for the sdproxy cache engine. Serializes and restores the
  live memory cache across router reboots.

  Extracted from cache.go to decouple disk I/O from the DNS hot path.

Changes:
  2.24.0 - [SECURITY/FIX] Included `cfg.Cache.CacheUpstreamNegative` in the
           upstream route fingerprint (`computeRouteConfigHash`) so persisted
           negative / RCODE-only cache entries are invalidated across restarts
           if `cache_upstream_negative` is disabled.
  2.23.0 - [SECURITY/FIX] Included `cfg.Cache.MinTTL`, `cfg.Cache.MaxTTL`, and
           `cfg.Cache.NegativeTTL` in both the synthetic and upstream route
           fingerprints (`computeRouteConfigHash`) so persisted cache entries
           are invalidated across restarts if `min_ttl`, `max_ttl`, or
           `negative_ttl` changes.
  2.22.0 - [FEAT/SECURITY] Included `cfg.Cache.RcodeTTL`, `cfg.Cache.RcodeMinTTL`,
           and `cfg.Cache.RcodeMaxTTL` in both the synthetic and upstream route
           fingerprints in `computeRouteConfigHash` so persisted cache entries
           are invalidated if RCODE-only TTL overrides change across restarts.
  2.21.0 - [SECURITY/FIX] Added a deterministic cryptographic digest of
           `catMap` (`computeParentalCategoryDigest`) to the upstream route
           fingerprint (`computeRouteConfigHash`) when `cfg.Server.FilterIPs`
           or `cfg.Server.TargetName` is enabled, and included
           `cfg.Server.SupportIPVersion` (`ipVersionSupport`) in both the
           synthetic and upstream route fingerprints.
  2.20.0 - [SECURITY/FIX] Included `cfg.Cache.AnswerSort` and post-upstream
           response policy/transform settings (`RebindingProtection`,
           `FilterIPs`, `TargetName`, `FlattenCNAME`, `MinimizeAnswer`) in the
           upstream route fingerprint (`computeRouteConfigHash`).
  2.19.0 - [SECURITY/FIX] Added deterministic digests of compiled `rrs:`
           (`computeCompiledRRsDigest`) and Web UI Custom Rules
           (`computeCustomRulesDigest`) to the synthetic cache fingerprint in
           `computeRouteConfigHash`.
  2.18.0 - [SECURITY/FIX] Replaced rule-count (`len`) metadata in
           `computeRouteConfigHash` with a deterministic cryptographic digest
           (`computeCompiledPolicyDigest`) of the compiled `domainPolicySnap`,
           `domainPolicyCIDRSnap`, and `domainPolicyRegexSnap` tables, plus a
           deterministic digest of `identSnap` when `cfg.Cache.CacheLocalIdentity`
           is enabled.
  2.17.1 - [FIX] Changed `RP` struct field type from `map[string]int` to
           `map[uint16]int` to match `rtypePolicy` in `computeRouteConfigHash`.
  2.17.0 - [SECURITY/FIX] Included the contents (`sha256` digest) of external
           `rtype_policy_files` and `domain_policy_files` in `computeRouteConfigHash`.
  2.16.0 - [SECURITY/FIX] Included `cfg.RtypePolicy`, `cfg.RtypePolicyFiles`,
           and `computePolicyConfigHash()` (`domain_policy`) in the synthetic
           entry fingerprint (`routeName == ""`) in `computeRouteConfigHash`.
*/

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cacheDiskVersion uint8 = 3

type cacheDiskRecord struct {
	Version   uint8
	Key       DNSCacheKey
	Packed    []byte
	Expire    int64
	Stale     int64
	CachedAt  int64
	Route     string
	RouteHash string
	Hits      uint32
}

var saveCacheMu sync.Mutex

func computeCompiledPolicyDigest() string {
	h := sha256.New()
	if dpSnap := domainPolicySnap.Load(); dpSnap != nil && len(*dpSnap) > 0 {
		keys := make([]string, 0, len(*dpSnap))
		for k := range *dpSnap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte{'='})
			h.Write([]byte(strconv.Itoa((*dpSnap)[k])))
			h.Write([]byte{';'})
		}
	}
	h.Write([]byte{'|'})
	if dpCIDRs := domainPolicyCIDRSnap.Load(); dpCIDRs != nil && len(*dpCIDRs) > 0 {
		for _, c := range *dpCIDRs {
			h.Write([]byte(c.prefix.String()))
			h.Write([]byte{'='})
			h.Write([]byte(strconv.Itoa(c.action)))
			h.Write([]byte{';'})
		}
	}
	h.Write([]byte{'|'})
	if dpRegexes := domainPolicyRegexSnap.Load(); dpRegexes != nil && len(*dpRegexes) > 0 {
		for _, r := range *dpRegexes {
			h.Write([]byte(r.raw))
			h.Write([]byte{'='})
			h.Write([]byte(strconv.Itoa(r.action)))
			h.Write([]byte{';'})
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func computeCompiledRRsDigest() string {
	if !hasRRs {
		return ""
	}
	h := sha256.New()
	writeSpoofRec := func(rec spoofRecord) {
		h.Write([]byte(rec.CNAME))
		h.Write([]byte{'/'})
		for _, ip := range rec.IPs {
			h.Write([]byte(ip.String()))
			h.Write([]byte{','})
		}
	}
	if len(globalRRs) > 0 {
		keys := make([]string, 0, len(globalRRs))
		for k := range globalRRs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			h.Write([]byte(k))
			h.Write([]byte{'='})
			writeSpoofRec(globalRRs[k])
			h.Write([]byte{';'})
		}
	}
	h.Write([]byte{'|'})
	for _, r := range globalRRRegexes {
		h.Write([]byte(r.raw))
		h.Write([]byte{'='})
		writeSpoofRec(r.rec)
		h.Write([]byte{';'})
	}
	h.Write([]byte{'|'})
	if len(groupRRs) > 0 {
		gNames := make([]string, 0, len(groupRRs))
		for g := range groupRRs {
			gNames = append(gNames, g)
		}
		sort.Strings(gNames)
		for _, g := range gNames {
			h.Write([]byte(g))
			h.Write([]byte{':'})
			gm := groupRRs[g]
			keys := make([]string, 0, len(gm))
			for k := range gm {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				h.Write([]byte(k))
				h.Write([]byte{'='})
				writeSpoofRec(gm[k])
				h.Write([]byte{';'})
			}
		}
	}
	h.Write([]byte{'|'})
	if len(groupRRRegexes) > 0 {
		gNames := make([]string, 0, len(groupRRRegexes))
		for g := range groupRRRegexes {
			gNames = append(gNames, g)
		}
		sort.Strings(gNames)
		for _, g := range gNames {
			h.Write([]byte(g))
			h.Write([]byte{':'})
			for _, r := range groupRRRegexes[g] {
				h.Write([]byte(r.raw))
				h.Write([]byte{'='})
				writeSpoofRec(r.rec)
				h.Write([]byte{';'})
			}
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func computeCustomRulesDigest() string {
	rules := GetRules()
	if len(rules) == 0 {
		return ""
	}
	h := sha256.New()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		h.Write([]byte(r.Group))
		h.Write([]byte{':'})
		h.Write([]byte(r.Domain))
		h.Write([]byte{'='})
		h.Write([]byte(r.Action))
		h.Write([]byte{';'})
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func computeLocalIdentityDigest() string {
	if !cfg.Cache.CacheLocalIdentity {
		return ""
	}
	snap := identSnap.Load()
	if snap == nil {
		return ""
	}
	h := sha256.New()
	if len(snap.nameToIPs) > 0 {
		names := make([]string, 0, len(snap.nameToIPs))
		for k := range snap.nameToIPs {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			h.Write([]byte(k))
			h.Write([]byte{'='})
			for _, a := range snap.nameToIPs[k] {
				h.Write([]byte(a.String()))
				h.Write([]byte{','})
			}
			h.Write([]byte{';'})
		}
	}
	h.Write([]byte{'|'})
	if len(snap.arpaToNames) > 0 {
		arpas := make([]string, 0, len(snap.arpaToNames))
		for k := range snap.arpaToNames {
			arpas = append(arpas, k)
		}
		sort.Strings(arpas)
		for _, k := range arpas {
			h.Write([]byte(k))
			h.Write([]byte{'='})
			for _, n := range snap.arpaToNames[k] {
				h.Write([]byte(n))
				h.Write([]byte{','})
			}
			h.Write([]byte{';'})
		}
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func computeParentalCategoryDigest() string {
	if !hasParental || (!cfg.Server.FilterIPs && !cfg.Server.TargetName) {
		return ""
	}
	return computeConfigHash()
}

func computeRouteConfigHash(routeName string, routeIdx uint16) string {
	if routeName == "" {
		var idxTarget string
		for name, idx := range routeIdxByName {
			if idx == routeIdx {
				idxTarget = name
				break
			}
		}
		mixedScript := true
		if cfg.Server.IDNHomograph.MixedScript != nil {
			mixedScript = *cfg.Server.IDNHomograph.MixedScript
		}
		asciiLookalikes := true
		if cfg.Server.IDNHomograph.ASCIILookalikes != nil {
			asciiLookalikes = *cfg.Server.IDNHomograph.ASCIILookalikes
		}
		rtBytes, _ := json.Marshal(struct {
			RP  map[uint16]int
			RPF map[string]string
		}{
			RP:  rtypePolicy,
			RPF: cfg.RtypePolicyFiles,
		})
		synthDesc := fmt.Sprintf("synth:%s|ipv:%s|cs:%v|cli:%v:%s|sttl:%d|ttl:%d:%d:%d|rttl:%d:%d:%d|boq:%v|qmin:%d|qmax:%d|act:%s|ips:%s|faaaa:%v|sptr:%v|fs:%s|pk:%s|rfc:%s:%v:%s|idn:%s:%v:%v:%v:%s:%s|rt:%s|dp:%s:%s|rrs:%s|cr:%s",
			idxTarget,
			ipVersionSupport,
			cfg.Cache.CacheSynthetic,
			cfg.Cache.CacheLocalIdentity,
			computeLocalIdentityDigest(),
			syntheticTTL,
			cfg.Cache.MinTTL,
			cfg.Cache.MaxTTL,
			cfg.Cache.NegativeTTL,
			cfg.Cache.RcodeTTL,
			cfg.Cache.RcodeMinTTL,
			cfg.Cache.RcodeMaxTTL,
			cfg.Server.BlockObsoleteQtypes,
			cfg.Server.QnameMinLabels,
			cfg.Server.QnameMaxLabels,
			strings.ToUpper(strings.TrimSpace(cfg.Server.BlockAction)),
			strings.Join(cfg.Server.BlockIPs, ","),
			cfg.Server.FilterAAAA,
			cfg.Server.StrictPTR,
			cfg.Server.ForSale,
			cfg.Server.Parked,
			cfg.Server.RFCCompliance.Action,
			cfg.Server.RFCCompliance.Strict,
			strings.Join(cfg.Server.RFCCompliance.Checks, ","),
			cfg.Server.IDNHomograph.Action,
			cfg.Server.IDNHomograph.BlockAllIDN,
			mixedScript,
			asciiLookalikes,
			strings.Join(cfg.Server.IDNHomograph.Protect, ","),
			strings.Join(cfg.Server.IDNHomograph.Exempt, ","),
			string(rtBytes),
			computePolicyConfigHash(),
			computeCompiledPolicyDigest(),
			computeCompiledRRsDigest(),
			computeCustomRulesDigest(),
		)
		h := sha256.Sum256([]byte(synthDesc))
		return hex.EncodeToString(h[:8])
	}

	type routeDescriptor struct {
		RouteName        string
		IPVersion        string
		Group            UpstreamGroupConfig
		HasGroup         bool
		Default          UpstreamGroupConfig
		GlobalDNS0x20    bool
		GlobalCookies    bool
		GlobalRequireAD  bool
		GlobalUpgradeH3  bool
		GlobalDoH3Thresh int
		GlobalUseECH     string
		GlobalHostECH    string
		GlobalSelection  string
		GlobalECS        ECSConfig
		AnswerSort       string
		MinTTL           int
		MaxTTL           int
		NegativeTTL      int
		RcodeTTL         int
		RcodeMinTTL      int
		RcodeMaxTTL      int
		CacheUpNeg       bool
		Rebinding        bool
		FilterIPs        bool
		TargetName       bool
		FlattenCNAME     bool
		MinimizeAnswer   bool
		ParentalCatHash  string
	}
	ugc, hasGrp := cfg.Upstreams[routeName]
	defUgc := cfg.Upstreams["default"]
	b, _ := json.Marshal(routeDescriptor{
		RouteName:        routeName,
		IPVersion:        ipVersionSupport,
		Group:            ugc,
		HasGroup:         hasGrp,
		Default:          defUgc,
		GlobalDNS0x20:    cfg.Server.DNS0x20,
		GlobalCookies:    cfg.Server.DNSCookies,
		GlobalRequireAD:  cfg.Server.RequireDNSSECAD,
		GlobalUpgradeH3:  cfg.Server.UpgradeDoH3,
		GlobalDoH3Thresh: cfg.Server.DoH3FallbackThreshold,
		GlobalUseECH:     cfg.Server.UseUpstreamECH,
		GlobalHostECH:    cfg.Server.HostnameECH,
		GlobalSelection:  cfg.Server.UpstreamSelection,
		GlobalECS:        cfg.Server.ECS,
		AnswerSort:       cfg.Cache.AnswerSort,
		MinTTL:           cfg.Cache.MinTTL,
		MaxTTL:           cfg.Cache.MaxTTL,
		NegativeTTL:      cfg.Cache.NegativeTTL,
		RcodeTTL:         cfg.Cache.RcodeTTL,
		RcodeMinTTL:      cfg.Cache.RcodeMinTTL,
		RcodeMaxTTL:      cfg.Cache.RcodeMaxTTL,
		CacheUpNeg:       cfg.Cache.CacheUpstreamNegative,
		Rebinding:        cfg.Server.RebindingProtection,
		FilterIPs:        cfg.Server.FilterIPs,
		TargetName:       cfg.Server.TargetName,
		FlattenCNAME:     cfg.Server.FlattenCNAME,
		MinimizeAnswer:   cfg.Server.MinimizeAnswer,
		ParentalCatHash:  computeParentalCategoryDigest(),
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func buildRouteHashTable() map[string]string {
	out := make(map[string]string, len(routeIdxByName)+2)
	for name, idx := range routeIdxByName {
		out[name] = computeRouteConfigHash(name, idx)
	}
	return out
}

// LoadCache restores the DNS cache from disk.
func LoadCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	var records []cacheDiskRecord
	if err := loadGobInto(cfg.Cache.PersistFile, &records); err != nil {
		if (logCaching || logSystem) && !os.IsNotExist(err) {
			log.Printf("[CACHE] WARNING: cannot restore persistent cache: %v — file may be corrupt or from an older version", err)
		}
		return
	}

	now := time.Now().UnixNano()
	routeHashes := buildRouteHashTable()
	loaded := 0

	for _, r := range records {
		if r.Version != cacheDiskVersion {
			continue
		}
		if now >= r.Stale && (!serveStaleInfinite || r.Route == "") {
			continue
		}

		if r.Route != "" {
			idx, ok := routeIdxByName[r.Route]
			if !ok || idx != r.Key.RouteIdx {
				continue
			}
			if r.RouteHash == "" || r.RouteHash != routeHashes[r.Route] {
				continue
			}
		} else {
			if !cfg.Cache.CacheSynthetic && !cfg.Cache.CacheLocalIdentity {
				continue
			}
			expectedHash := computeRouteConfigHash("", r.Key.RouteIdx)
			if r.RouteHash == "" || r.RouteHash != expectedHash {
				continue
			}
		}

		ci := &cacheItem{
			expireNano:   r.Expire,
			staleNano:    r.Stale,
			cachedAtNano: r.CachedAt,
			routeName:    r.Route,
		}
		ci.hits.Store(r.Hits)
		ci.prefetched.Store(false)

		packed := make([]byte, len(r.Packed))
		copy(packed, r.Packed)
		ci.packed.Store(&packed)

		storeItem(r.Key, ci)
		loaded++
	}

	if logCaching || logSystem {
		log.Printf("[CACHE] Restored %d active entries from persistent storage (%s)", loaded, cfg.Cache.PersistFile)
	}
}

// SaveCache gathers all viable cache records and serializes them to disk without
// blocking the DNS path for the duration of the write.
func SaveCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	saveCacheMu.Lock()
	defer saveCacheMu.Unlock()

	now := time.Now().UnixNano()
	routeHashes := buildRouteHashTable()

	totalEst := 0
	for i := range shards {
		shards[i].RLock()
		totalEst += len(shards[i].items)
		shards[i].RUnlock()
	}

	var records []cacheDiskRecord
	if totalEst > 0 {
		records = make([]cacheDiskRecord, 0, totalEst)
	}

	for i := range shards {
		shard := shards[i]
		shard.RLock()
		for k, v := range shard.items {
			if now >= v.staleNano && (!serveStaleInfinite || v.routeName == "") {
				continue
			}
			if p := v.packed.Load(); p != nil {
				rHash := routeHashes[v.routeName]
				if rHash == "" {
					rHash = computeRouteConfigHash(v.routeName, k.RouteIdx)
				}
				records = append(records, cacheDiskRecord{
					Version:   cacheDiskVersion,
					Key:       k,
					Packed:    *p,
					Expire:    v.expireNano,
					Stale:     v.staleNano,
					CachedAt:  v.cachedAtNano,
					Route:     v.routeName,
					RouteHash: rHash,
					Hits:      v.hits.Load(),
				})
			}
		}
		shard.RUnlock()

		runtime.Gosched()
	}

	if len(records) == 0 {
		if err := os.Remove(cfg.Cache.PersistFile); err != nil && !os.IsNotExist(err) {
			_ = saveGob(cfg.Cache.PersistFile, []cacheDiskRecord{})
		} else if err == nil {
			syncDirForFile(cfg.Cache.PersistFile)
		}
		return
	}

	if err := saveGob(cfg.Cache.PersistFile, records); err != nil {
		if logCaching || logSystem {
			log.Printf("[CACHE] WARNING: failed to persist cache: %v", err)
		}
		return
	}

	if logCaching && !logSimple {
		log.Printf("[CACHE] Successfully persisted %d entries to disk", len(records))
	}
}
