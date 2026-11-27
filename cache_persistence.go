/*
File:    cache_persistence.go
Version: 2.27.0 (Split)
Last Updated: 27-Nov-2026 13:30 CET

Description:
  Disk persistence for the sdproxy cache engine. Serializes and restores the
  live memory cache across router reboots.

Changes:
  2.27.0 - [FIX/PERF] Distinguished `routeLocalTag` (`CacheLocalIdentity`) from
           `""` (`CacheSynthetic`) in `SaveCache`, `LoadCache`, and `routeHashMemo`
           so toggling one setting never restores or invalidates the other.
         - [PERF] Removed post-cache transforms (`RebindingProtection`, `FilterIPs`,
           `TargetName`, `FlattenCNAME`, `MinimizeAnswer`, `ParentalCatHash`, and
           non-`ip-sort` `AnswerSort`) from `computeUpstreamHash` because
           `serveFromCache` re-applies all of them dynamically on read; changing
           those options no longer wipes the persistent upstream cache on reboot.
  2.26.0 - [PERF/FIX] Precomputed shared policy, identity, RRs, custom-rules,
           and parental digests once per `SaveCache` / `LoadCache` pass via
           `routeHashMemo`.
  2.25.0 - [SECURITY/FIX] Included per-group `IgnoreQnameLabels` in the synthetic
           route fingerprint.
  2.24.0 - [SECURITY/FIX] Included `cfg.Cache.CacheUpstreamNegative` in the
           upstream route fingerprint.
  2.23.0 - [SECURITY/FIX] Included `cfg.Cache.MinTTL`, `cfg.Cache.MaxTTL`, and
           `cfg.Cache.NegativeTTL` in both route fingerprints.
  2.22.0 - [FEAT/SECURITY] Included `cfg.Cache.RcodeTTL`, `cfg.Cache.RcodeMinTTL`,
           and `cfg.Cache.RcodeMaxTTL` in both route fingerprints.
  2.21.0 - [SECURITY/FIX] Added `computeParentalCategoryDigest` and
           `ipVersionSupport` to route fingerprints.
  2.20.0 - [SECURITY/FIX] Included `AnswerSort` and post-upstream transform
           settings in upstream route fingerprints.
  2.19.0 - [SECURITY/FIX] Added deterministic digests of compiled `rrs:` and
           Web UI Custom Rules to the synthetic cache fingerprint.
  2.18.0 - [SECURITY/FIX] Replaced rule-count metadata with
           `computeCompiledPolicyDigest` and `computeLocalIdentityDigest`.
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

const cacheDiskVersion uint8 = 4

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

type routeHashMemo struct {
	routeHashes     map[string]string
	synthHashes     map[uint16]string
	localHashVal    string
	nameByIdx       map[uint16]string
	rtJSON          string
	localIdentHash  string
	policyCfgHash   string
	compiledPolHash string
	compiledRRsHash string
	customRulesHash string
}

func newRouteHashMemo() *routeHashMemo {
	rtBytes, _ := json.Marshal(struct {
		RP  map[uint16]int
		RPF map[string]string
	}{
		RP:  rtypePolicy,
		RPF: cfg.RtypePolicyFiles,
	})

	nameByIdx := make(map[uint16]string, len(routeIdxByName))
	for name, idx := range routeIdxByName {
		nameByIdx[idx] = name
	}

	m := &routeHashMemo{
		routeHashes:     make(map[string]string, len(routeIdxByName)+2),
		synthHashes:     make(map[uint16]string, len(routeIdxByName)+2),
		nameByIdx:       nameByIdx,
		rtJSON:          string(rtBytes),
		localIdentHash:  computeLocalIdentityDigest(),
		policyCfgHash:   computePolicyConfigHash(),
		compiledPolHash: computeCompiledPolicyDigest(),
		compiledRRsHash: computeCompiledRRsDigest(),
		customRulesHash: computeCustomRulesDigest(),
	}

	m.localHashVal = m.computeLocalHash()
	for name, idx := range routeIdxByName {
		m.routeHashes[name] = m.computeUpstreamHash(name)
		m.synthHashes[idx] = m.computeSynthHash(idx)
	}
	return m
}

func (m *routeHashMemo) computeLocalHash() string {
	desc := fmt.Sprintf("local|ipv:%s|cli:%v:%s|sttl:%d|ttl:%d:%d:%d|rttl:%d:%d:%d|rrs:%s|cr:%s",
		ipVersionSupport,
		cfg.Cache.CacheLocalIdentity,
		m.localIdentHash,
		syntheticTTL,
		cfg.Cache.MinTTL,
		cfg.Cache.MaxTTL,
		cfg.Cache.NegativeTTL,
		cfg.Cache.RcodeTTL,
		cfg.Cache.RcodeMinTTL,
		cfg.Cache.RcodeMaxTTL,
		m.compiledRRsHash,
		m.customRulesHash,
	)
	h := sha256.Sum256([]byte(desc))
	return hex.EncodeToString(h[:8])
}

func (m *routeHashMemo) synthHash(routeIdx uint16) string {
	if h, ok := m.synthHashes[routeIdx]; ok {
		return h
	}
	h := m.computeSynthHash(routeIdx)
	m.synthHashes[routeIdx] = h
	return h
}

func (m *routeHashMemo) upstreamHash(routeName string) string {
	if h, ok := m.routeHashes[routeName]; ok {
		return h
	}
	h := m.computeUpstreamHash(routeName)
	m.routeHashes[routeName] = h
	return h
}

func (m *routeHashMemo) computeSynthHash(routeIdx uint16) string {
	idxTarget := m.nameByIdx[routeIdx]
	var ignoreLabels bool
	if grp := effectiveUpstreamGroup(idxTarget); grp != nil {
		ignoreLabels = grp.IgnoreQnameLabels
	}
	mixedScript := true
	if cfg.Server.IDNHomograph.MixedScript != nil {
		mixedScript = *cfg.Server.IDNHomograph.MixedScript
	}
	asciiLookalikes := true
	if cfg.Server.IDNHomograph.ASCIILookalikes != nil {
		asciiLookalikes = *cfg.Server.IDNHomograph.ASCIILookalikes
	}
	synthDesc := fmt.Sprintf("synth:%s|ipv:%s|cs:%v|sttl:%d|ttl:%d:%d:%d|rttl:%d:%d:%d|boq:%v|qmin:%d|qmax:%d|igl:%v|act:%s|ips:%s|faaaa:%v|sptr:%v|fs:%s|pk:%s|rfc:%s:%v:%s|idn:%s:%v:%v:%v:%s:%s|rt:%s|dp:%s:%s|rrs:%s|cr:%s",
		idxTarget,
		ipVersionSupport,
		cfg.Cache.CacheSynthetic,
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
		ignoreLabels,
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
		m.rtJSON,
		m.policyCfgHash,
		m.compiledPolHash,
		m.compiledRRsHash,
		m.customRulesHash,
	)
	h := sha256.Sum256([]byte(synthDesc))
	return hex.EncodeToString(h[:8])
}

func (m *routeHashMemo) computeUpstreamHash(routeName string) string {
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
		PreCacheIPSort   bool
		MinTTL           int
		MaxTTL           int
		NegativeTTL      int
		RcodeTTL         int
		RcodeMinTTL      int
		RcodeMaxTTL      int
		CacheUpNeg       bool
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
		PreCacheIPSort:   cfg.Cache.AnswerSort == "ip-sort",
		MinTTL:           cfg.Cache.MinTTL,
		MaxTTL:           cfg.Cache.MaxTTL,
		NegativeTTL:      cfg.Cache.NegativeTTL,
		RcodeTTL:         cfg.Cache.RcodeTTL,
		RcodeMinTTL:      cfg.Cache.RcodeMinTTL,
		RcodeMaxTTL:      cfg.Cache.RcodeMaxTTL,
		CacheUpNeg:       cfg.Cache.CacheUpstreamNegative,
	})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
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
	memo := newRouteHashMemo()
	loaded := 0

	for _, r := range records {
		if r.Version != cacheDiskVersion {
			continue
		}
		if now >= r.Stale && (!serveStaleInfinite || isSyntheticRoute(r.Route)) {
			continue
		}

		switch r.Route {
		case "":
			if !cfg.Cache.CacheSynthetic {
				continue
			}
			if r.RouteHash == "" || r.RouteHash != memo.synthHash(r.Key.RouteIdx) {
				continue
			}
		case routeLocalTag:
			if !cfg.Cache.CacheLocalIdentity {
				continue
			}
			if r.RouteHash == "" || r.RouteHash != memo.localHashVal {
				continue
			}
		default:
			idx, ok := routeIdxByName[r.Route]
			if !ok || idx != r.Key.RouteIdx {
				continue
			}
			if r.RouteHash == "" || r.RouteHash != memo.upstreamHash(r.Route) {
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

// SaveCache serializes all viable cache records to disk without blocking hot-path shards.
func SaveCache() {
	if !cfg.Cache.Enabled || !cfg.Cache.Persist || cfg.Cache.PersistFile == "" {
		return
	}

	saveCacheMu.Lock()
	defer saveCacheMu.Unlock()

	now := time.Now().UnixNano()
	memo := newRouteHashMemo()

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
			if isEntryDead(v, now) {
				continue
			}
			if p := v.packed.Load(); p != nil {
				var rHash string
				switch v.routeName {
				case "":
					rHash = memo.synthHash(k.RouteIdx)
				case routeLocalTag:
					rHash = memo.localHashVal
				default:
					rHash = memo.upstreamHash(v.routeName)
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
