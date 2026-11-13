/*
File:    parked.go
Version: 1.13.0
Last Updated: 05-Nov-2026 17:30 CET

Description:
  Parked Domain detection and enforcement engine for sdproxy.

  Detects whether a queried domain, any intermediate parent domain, or its
  eTLD+1 apex is parked with a domain-parking or aftermarket monetization
  provider (Sedo, Bodis, ParkingCrew, Above.com, Dan.com, Afternic,
  CashParking, HugeDomains, Squadhelp/Atom, Uniregistry, Undeveloped,
  ParkLogic, RookMedia, Skenzo/Ztomy, Fabulous, etc.).

Changes:
  1.13.0 - [SECURITY/FIX] Evaluated `qc.originalQNameTrimmed` in addition to
           `qc.qNameTrimmed` in `enforceParkedCachedOnly` and `enforceParkedCheck`
           when a query was rewritten by an `rrs:` CNAME alias, preventing CNAME
           aliases from bypassing parked-domain detection on the original queried
           domain.
  1.12.0 - [CRITICAL/FIX] Marked outbound `probeParkedTarget` contexts with
           `WithBypassUpstreamThrottle` (`throttle.go` 2.7.0).
  1.11.0 - [FIX] Recorded `qc.originalQNameTrimmed` in `pkShards` alongside
           `targetQName` in `enforceParkedResponseCheck` when a query was
           rewritten by a `rrs:` CNAME alias.
  1.10.0 - [SECURITY/FIX] Extended `inspectMsgForParking` bailiwick chain walking
           and target matching to recognize RFC 6672 `DNAME` records.
  1.9.0  - [SECURITY/FIX] Aligned `effectiveDo` in `probeParkedTarget` cache
           lookaside with `group.RequireDNSSECAD`.
  1.8.0  - [SECURITY/FIX] Propagated `doBit` and `cdBit` into `probeParkedTarget`
           cache lookaside.
  1.7.0  - [FEAT] Added `cacheHit` tracking and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support in `applyParkedVerdict`.
  1.6.0  - [SECURITY/FIX] Hardened `inspectMsgForParking` to verify that `matchedOwner`
           in `msg.Answer` is the queried domain or a parent zone.
  1.5.0  - [SECURITY/FIX] Hardened `inspectMsgForParking` to attribute Authority
           (`msg.Ns`) NS/SOA parking matches to the authority record's owner zone.
  1.4.0  - [SECURITY/FIX] Attached validated incoming `EDNS0_SUBNET` (`ecsAddr` /
           `ecsPrefix`) to outbound parked probe requests when `group.ECSAction == "pass"`.
*/

package main

import (
	"context"
	"hash/maphash"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

const (
	pkShardCount      = 64
	pkMaxEntries      = 32768
	pkMaxPerShard     = pkMaxEntries / pkShardCount
	pkEvictSampleSize = 16

	pkMinTTL      = 300 * time.Second
	pkMaxTTL      = 3600 * time.Second
	pkNegTTL      = 900 * time.Second
	pkFailTTL     = 60 * time.Second
	pkProbeBudget = 1500 * time.Millisecond
)

type pkCacheKey struct {
	routeIdx uint16
	domain   string
}

type pkCacheEntry struct {
	parked     bool
	matchedTag string
	expireNano int64
}

type pkShard struct {
	sync.RWMutex
	items map[pkCacheKey]pkCacheEntry
}

var (
	parkedAction     string
	parkedActionCode int
	pkShards         [pkShardCount]*pkShard
	pkHashSeed       maphash.Seed
	pkSFGroup        singleflight.Group
)

var parkedHostSuffixes = map[string]string{
	// Sedo / SedoParking
	"sedoparking.com": "Sedo",
	"sedo.com":        "Sedo",
	"sedo.de":         "Sedo",

	// Bodis
	"bodis.com": "Bodis",

	// ParkingCrew / Team Internet
	"parkingcrew.net":  "ParkingCrew",
	"parkingcrew.com":  "ParkingCrew",
	"parking-page.net": "ParkingCrew",

	// Above.com / Trellian
	"above.com":        "Above.com",
	"abovedomains.com": "Above.com",

	// GoDaddy / Afternic / Dan.com / CashParking / Uniregistry / SmartName
	"afternic.com":           "Afternic",
	"dan.com":                "Dan.com",
	"undeveloped.com":        "Dan.com (Undeveloped)",
	"cashparking.com":        "GoDaddy CashParking",
	"smartname.com":          "SmartName",
	"uniregistrymarket.link": "Uniregistry",
	"uniregistry-dns.com":    "Uniregistry",
	"uniregistry-dns.net":    "Uniregistry",

	// HugeDomains
	"hugedomains.com":   "HugeDomains",
	"namebrightdns.com": "HugeDomains/NameBright",

	// Squadhelp / Atom / BrandBucket / BrandPa
	"squadhelp.com":   "Squadhelp",
	"atom.com":        "Atom",
	"brandbucket.com": "BrandBucket",
	"brandpa.com":     "BrandPa",

	// Skenzo / Ztomy / Oversee / DomainSponsor
	"ztomy.com":         "Ztomy/Skenzo",
	"skenzo.com":        "Skenzo",
	"domainsponsor.com": "DomainSponsor",
	"dsredirection.com": "DomainSponsor",
	"rookdns.com":       "RookMedia",
	"rookmedia.net":     "RookMedia",

	// ParkLogic / Fabulous / Voodoo / DomainNameSales
	"parklogic.com":       "ParkLogic",
	"fabulous.com":        "Fabulous",
	"voodoo.com":          "Voodoo",
	"domainnamesales.com": "DomainNameSales",
	"internettraffic.com": "InternetTraffic",
	"parked.com":          "Parked.com",
	"hitfarm.com":         "HitFarm",

	// Efty / Saw.com / DomainAgents / Porkbun / Sav / Dynadot Parking
	"eftydns.com":                "Efty",
	"efty.com":                   "Efty",
	"saw.com":                    "Saw.com",
	"domainagents.com":           "DomainAgents",
	"parktons.com":               "Parktons",
	"parking.namecheap.com":      "Namecheap Parking",
	"registrar-servers.com.park": "Namecheap Parking",
	"dynadot.com.park":           "Dynadot Parking",
	"parkpage.foundationapi.com": "LogicBoxes Parking",
}

var parkedHostKeywords = []struct {
	substr   string
	provider string
}{
	{"sedoparking", "Sedo"},
	{"parkingcrew", "ParkingCrew"},
	{"cashparking", "GoDaddy CashParking"},
	{"hugedomains", "HugeDomains"},
	{"parklogic", "ParkLogic"},
	{"domainsponsor", "DomainSponsor"},
	{"eftydns", "Efty"},
}

var parkedKnownIPs = map[netip.Addr]string{
	// Sedo Parking dedicated web parking IPs
	netip.MustParseAddr("64.190.63.222"):  "Sedo",
	netip.MustParseAddr("64.190.62.111"):  "Sedo",
	netip.MustParseAddr("82.98.86.171"):   "Sedo",
	netip.MustParseAddr("91.195.240.82"):  "Sedo",
	netip.MustParseAddr("91.195.240.94"):  "Sedo",
	netip.MustParseAddr("91.195.240.12"):  "Sedo",
	netip.MustParseAddr("91.195.240.126"): "Sedo",
	netip.MustParseAddr("91.195.241.232"): "Sedo",

	// Bodis dedicated parking IP
	netip.MustParseAddr("199.59.243.228"): "Bodis",

	// Above.com dedicated parking IPs
	netip.MustParseAddr("103.224.182.210"): "Above.com",
	netip.MustParseAddr("103.224.212.222"): "Above.com",

	// Dan.com / Afternic dedicated parking IPs
	netip.MustParseAddr("52.58.78.16"):   "Dan.com",
	netip.MustParseAddr("13.248.169.48"): "Afternic",
	netip.MustParseAddr("76.223.54.146"): "Afternic",
}

var parkedTXTIndicators = []struct {
	token    string
	provider string
}{
	{"v=forsale1;", "RFC10023 For-Sale"},
	{"sedoparking", "Sedo"},
	{"sedo-verification", "Sedo"},
	{"dan-ownership-verification", "Dan.com"},
	{"afternic-verification", "Afternic"},
	{"bodis-verification", "Bodis"},
	{"parkingcrew", "ParkingCrew"},
	{"squadhelp-verification", "Squadhelp"},
	{"atom-domain-verification", "Atom"},
	{"brandpa-verification", "BrandPa"},
	{"efty-verification", "Efty"},
	{"hugedomains", "HugeDomains"},
}

func InitParked() {
	act := strings.ToUpper(strings.TrimSpace(cfg.Server.Parked))
	switch act {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		hasParked = false
		parkedAction = "DISABLED"
		return
	case "LOG":
		parkedAction = "LOG"
		parkedActionCode = 0
	case "DROP":
		parkedAction = "DROP"
		parkedActionCode = PolicyActionDrop
	case "BLOCK":
		parkedAction = "BLOCK"
		parkedActionCode = PolicyActionBlock
	default:
		rc, ok := dns.StringToRcode[act]
		if !ok {
			if logSystem {
				log.Printf("[PARKED] WARNING: unknown server.parked action %q — disabling feature", cfg.Server.Parked)
			}
			hasParked = false
			parkedAction = "DISABLED"
			return
		}
		parkedAction = act
		parkedActionCode = rc
	}

	pkHashSeed = maphash.MakeSeed()
	for i := 0; i < pkShardCount; i++ {
		pkShards[i] = &pkShard{
			items: make(map[pkCacheKey]pkCacheEntry, 64),
		}
	}
	hasParked = true

	if logSystem {
		log.Printf("[PARKED] Parked domain detection enabled (Action: %s)", parkedAction)
	}

	go runParkedSweeper()
}

func getPKShard(key pkCacheKey) *pkShard {
	h := maphash.String(pkHashSeed, key.domain)
	h ^= uint64(key.routeIdx) * 0x9e3779b97f4a7c15
	return pkShards[h&(pkShardCount-1)]
}

func getPKCache(key pkCacheKey, now int64) (pkCacheEntry, bool) {
	sh := getPKShard(key)
	sh.RLock()
	entry, ok := sh.items[key]
	sh.RUnlock()
	if !ok || now >= entry.expireNano {
		return pkCacheEntry{}, false
	}
	return entry, true
}

func setPKCache(key pkCacheKey, entry pkCacheEntry, now int64) {
	sh := getPKShard(key)
	sh.Lock()
	defer sh.Unlock()

	if _, exists := sh.items[key]; !exists && len(sh.items) >= pkMaxPerShard {
		var (
			victimKey    pkCacheKey
			victimExpire int64
			sampled      int
		)
		for k, v := range sh.items {
			if now >= v.expireNano {
				victimKey = k
				sampled = 1
				break
			}
			if sampled == 0 || v.expireNano < victimExpire {
				victimKey = k
				victimExpire = v.expireNano
			}
			sampled++
			if sampled >= pkEvictSampleSize {
				break
			}
		}
		if sampled > 0 {
			delete(sh.items, victimKey)
		}
	}

	sh.items[key] = entry
}

func runParkedSweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			for i := 0; i < pkShardCount; i++ {
				sh := pkShards[i]
				sh.Lock()
				for k, v := range sh.items {
					if now >= v.expireNano {
						delete(sh.items, k)
					}
				}
				sh.Unlock()
			}
		case <-shutdownCh:
			return
		}
	}
}

func matchParkedHostname(host string) (bool, string) {
	clean := lowerTrimDot(host)
	if clean == "" {
		return false, ""
	}

	search := clean
	for {
		if provider, ok := parkedHostSuffixes[search]; ok {
			return true, provider + " (" + clean + ")"
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
	}

	for _, kw := range parkedHostKeywords {
		if strings.Contains(clean, kw.substr) {
			return true, kw.provider + " (" + clean + ")"
		}
	}

	firstDot := strings.IndexByte(clean, '.')
	if firstDot > 0 {
		firstLabel := clean[:firstDot]
		switch {
		case firstLabel == "parked" || firstLabel == "parking" || firstLabel == "sedoparking" || firstLabel == "domainparking":
			return true, "Parking-NS (" + clean + ")"
		case strings.HasPrefix(firstLabel, "parked-") || strings.HasPrefix(firstLabel, "parking-"):
			return true, "Parking-NS (" + clean + ")"
		case len(firstLabel) == 5 && strings.HasPrefix(firstLabel, "park") && firstLabel[4] >= '0' && firstLabel[4] <= '9':
			return true, "Parking-NS (" + clean + ")"
		}
	}

	return false, ""
}

func matchParkedTXT(txt *dns.TXT) (bool, string) {
	if txt == nil || len(txt.Txt) == 0 {
		return false, ""
	}
	if valid, raw := isValidRFC10023TXT(txt); valid {
		return true, "RFC10023 TXT (" + raw + ")"
	}
	for _, s := range txt.Txt {
		lower := strings.ToLower(s)
		for _, ind := range parkedTXTIndicators {
			if strings.Contains(lower, ind.token) {
				snippet := s
				if len(snippet) > 64 {
					snippet = snippet[:64] + "..."
				}
				return true, ind.provider + " TXT (" + snippet + ")"
			}
		}
	}
	return false, ""
}

func inspectMsgForParking(msg *dns.Msg) (isParked bool, matchedInfo string, matchedOwner string, ttl time.Duration) {
	if msg == nil {
		return false, "", "", pkFailTTL
	}
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return false, "", "", pkFailTTL
	}

	var qDomainClean string
	var chainStack [64]string
	validNames := chainStack[:0]
	if len(msg.Question) > 0 {
		qLower := strings.ToLower(msg.Question[0].Name)
		validNames = append(validNames, qLower)
		qDomainClean = strings.TrimSuffix(qLower, ".")
		for strings.HasPrefix(qDomainClean, forSalePrefix) {
			qDomainClean = strings.TrimPrefix(qDomainClean, forSalePrefix)
		}
	}

	for depth := 0; depth < 16; depth++ {
		added := false
		for _, rr := range msg.Answer {
			owner := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if len(validNames) == 0 || isValidBailiwickName(validNames, owner) {
					t := strings.ToLower(r.Target)
					if !isValidBailiwickName(validNames, t) && len(validNames) < 64 {
						validNames = append(validNames, t)
						added = true
					}
				}
			case *dns.DNAME:
				for _, vn := range validNames {
					if hasDotSuffix(vn, owner) {
						if !isValidBailiwickName(validNames, owner) && len(validNames) < 64 {
							validNames = append(validNames, owner)
							added = true
						}
						prefix := vn[:len(vn)-len(owner)]
						synthTarget := prefix + strings.ToLower(r.Target)
						if len(synthTarget) <= 254 && !isValidBailiwickName(validNames, synthTarget) && len(validNames) < 64 {
							validNames = append(validNames, synthTarget)
							added = true
						}
					}
				}
			}
		}
		if !added {
			break
		}
	}

	isInBailiwick := func(owner string, allowAncestor bool) bool {
		if len(validNames) == 0 {
			return true
		}
		ownerLower := strings.ToLower(owner)
		if isValidBailiwickName(validNames, ownerLower) {
			return true
		}
		if !allowAncestor {
			return false
		}
		cleanOwner := strings.TrimSuffix(ownerLower, ".")
		if isPublicSuffix(cleanOwner) || isDGASafeDomain(cleanOwner) {
			return false
		}
		if _, isShared := sharedHostingDomains[cleanOwner]; isShared {
			return false
		}
		if qDomainClean != "" && (cleanOwner == qDomainClean || hasDotSuffix(qDomainClean, cleanOwner)) {
			return true
		}
		return false
	}

	minRRTTL := uint32(3600)
	recordMatch := func(info, owner string, rrTTL uint32) {
		if !isParked {
			isParked = true
			matchedInfo = info
			cand := lowerTrimDot(owner)
			for strings.HasPrefix(cand, forSalePrefix) {
				cand = strings.TrimPrefix(cand, forSalePrefix)
			}
			if qDomainClean == "" || cand == qDomainClean || hasDotSuffix(qDomainClean, cand) {
				matchedOwner = cand
			} else {
				matchedOwner = qDomainClean
			}
		}
		if rrTTL > 0 && rrTTL < minRRTTL {
			minRRTTL = rrTTL
		}
	}

	checkSection := func(rrs []dns.RR, allowAncestor bool) {
		for _, rr := range rrs {
			owner := rr.Header().Name
			if !isInBailiwick(owner, allowAncestor) {
				continue
			}
			switch r := rr.(type) {
			case *dns.NS:
				if ok, prov := matchParkedHostname(r.Ns); ok {
					recordMatch("NS "+prov, owner, r.Hdr.Ttl)
					return
				}
			case *dns.SOA:
				if ok, prov := matchParkedHostname(r.Ns); ok {
					recordMatch("SOA MNAME "+prov, owner, r.Hdr.Ttl)
					return
				}
				if ok, prov := matchParkedHostname(r.Mbox); ok {
					recordMatch("SOA RNAME "+prov, owner, r.Hdr.Ttl)
					return
				}
			case *dns.CNAME:
				if ok, prov := matchParkedHostname(r.Target); ok {
					recordMatch("CNAME "+prov, owner, r.Hdr.Ttl)
					return
				}
			case *dns.DNAME:
				if ok, prov := matchParkedHostname(r.Target); ok {
					recordMatch("DNAME "+prov, owner, r.Hdr.Ttl)
					return
				}
			case *dns.TXT:
				if ok, prov := matchParkedTXT(r); ok {
					recordMatch(prov, owner, r.Hdr.Ttl)
					return
				}
			case *dns.A:
				if addr, ok := netip.AddrFromSlice(r.A); ok {
					if prov, found := parkedKnownIPs[addr.Unmap()]; found {
						recordMatch("IP "+prov+" ("+addr.Unmap().String()+")", owner, r.Hdr.Ttl)
						return
					}
				}
			case *dns.AAAA:
				if addr, ok := netip.AddrFromSlice(r.AAAA); ok {
					if prov, found := parkedKnownIPs[addr.Unmap()]; found {
						recordMatch("IP "+prov+" ("+addr.Unmap().String()+")", owner, r.Hdr.Ttl)
						return
					}
				}
			}
		}
	}

	checkSection(msg.Answer, false)
	if !isParked {
		checkSection(msg.Ns, true)
	}

	if !isParked {
		return false, "", "", pkNegTTL
	}

	ttl = time.Duration(minRRTTL) * time.Second
	if ttl < pkMinTTL {
		ttl = pkMinTTL
	} else if ttl > pkMaxTTL {
		ttl = pkMaxTTL
	}
	return true, matchedInfo, matchedOwner, ttl
}

func hasCachedParkedAncestor(routeIdx uint16, qname, apex string, now int64) (parked bool, matchedTarget string, matchedInfo string, qnameCachedNeg bool, apexCachedNeg bool) {
	search := qname
	for {
		if entry, ok := getPKCache(pkCacheKey{routeIdx: routeIdx, domain: search}, now); ok {
			if entry.parked {
				return true, search, entry.matchedTag, false, false
			}
			if search == qname {
				qnameCachedNeg = true
			}
			if search == apex {
				apexCachedNeg = true
			}
		}
		if hasForSale {
			if fsEntry, ok := getFSCache(fsCacheKey{routeIdx: routeIdx, domain: search}, now); ok && fsEntry.forSale {
				return true, forSalePrefix + search, "RFC10023 TXT (" + fsEntry.matchedTag + ")", false, false
			}
		}
		if search == apex || apex == "" {
			break
		}
		idx := strings.IndexByte(search, '.')
		if idx < 0 {
			break
		}
		search = search[idx+1:]
		if len(search) < len(apex) || isPublicSuffix(search) {
			break
		}
	}
	return false, "", "", qnameCachedNeg, apexCachedNeg
}

func probeParkedTarget(parentCtx context.Context, group *UpstreamGroup, routeIdx uint16, target, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (bool, string) {
	now := time.Now().UnixNano()
	ck := pkCacheKey{routeIdx: routeIdx, domain: target}
	if entry, ok := getPKCache(ck, now); ok {
		return entry.parked, entry.matchedTag
	}
	if hasForSale {
		if fsEntry, ok := getFSCache(fsCacheKey{routeIdx: routeIdx, domain: target}, now); ok && fsEntry.forSale {
			return true, "RFC10023 TXT (" + fsEntry.matchedTag + ")"
		}
	}

	if parentCtx.Err() != nil || len(target) == 0 || len(target) > 253 {
		return false, ""
	}

	sfKey := itoa64(int64(routeIdx)) + "|" + target
	resCh := pkSFGroup.DoChan(sfKey, func() (any, error) {
		nowInner := time.Now().UnixNano()
		if entry, ok := getPKCache(ck, nowInner); ok {
			return entry, nil
		}
		if hasForSale {
			if fsEntry, ok := getFSCache(fsCacheKey{routeIdx: routeIdx, domain: target}, nowInner); ok && fsEntry.forSale {
				return pkCacheEntry{
					parked:     true,
					matchedTag: "RFC10023 TXT (" + fsEntry.matchedTag + ")",
					expireNano: fsEntry.expireNano,
				}, nil
			}
		}

		fqdn := dns.Fqdn(target)
		cNameKey, ecsKey := probeCacheKeyPartitions(group, clientName, clientAddr, ecsAddr, ecsPrefix)
		effectiveDo := doBit || (group != nil && group.RequireDNSSECAD)

		for _, qtype := range []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeA} {
			for _, tryDO := range []bool{effectiveDo, false} {
				mainKey := DNSCacheKey{
					Name:             target,
					ClientName:       cNameKey,
					ECS:              ecsKey,
					Qtype:            qtype,
					Qclass:           dns.ClassINET,
					RouteIdx:         routeIdx,
					DoBit:            tryDO,
					CdBit:            cdBit,
					BypassGlobal:     bypassGlobal,
					BypassPolicies:   bypassPolicies,
					BypassLocal:      bypassLocal,
					RecursionDesired: true,
				}
				pooled := msgPool.Get().(*dns.Msg)
				*pooled = dns.Msg{}
				if _, _, cacheOK, _ := CacheGet(mainKey, fqdn, pooled); cacheOK && !pooled.Authoritative {
					isP, info, ownerZone, ttl := inspectMsgForParking(pooled)
					msgPool.Put(pooled)
					if isP {
						expNano := time.Now().Add(ttl).UnixNano()
						entry := pkCacheEntry{
							parked:     true,
							matchedTag: info,
							expireNano: expNano,
						}
						setPKCache(ck, entry, nowInner)
						if ownerZone != "" && ownerZone != target && !shouldSkipForSaleCheck(ownerZone, dns.TypeA) {
							setPKCache(pkCacheKey{routeIdx: routeIdx, domain: ownerZone}, entry, nowInner)
						}
						return entry, nil
					}
				} else {
					msgPool.Put(pooled)
				}
				if !effectiveDo {
					break
				}
			}
		}

		type qProbe struct {
			qname string
			qtype uint16
		}
		probes := make([]qProbe, 0, 3)
		probes = append(probes, qProbe{qname: fqdn, qtype: dns.TypeNS})
		probes = append(probes, qProbe{qname: fqdn, qtype: dns.TypeTXT})
		if !hasForSale && len(target)+len(forSalePrefix) <= 253 {
			probes = append(probes, qProbe{qname: dns.Fqdn(forSalePrefix + target), qtype: dns.TypeTXT})
		}

		type subRes struct {
			parked    bool
			info      string
			ownerZone string
			ttl       time.Duration
			ok        bool
		}

		ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), pkProbeBudget)
		defer cancel()

		subCh := make(chan subRes, len(probes))
		for _, p := range probes {
			go func(pr qProbe) {
				req := msgPool.Get().(*dns.Msg)
				*req = dns.Msg{}
				req.SetQuestion(pr.qname, pr.qtype)
				req.RecursionDesired = true
				if group.ECSAction == "pass" && ecsAddr.IsValid() {
					injectPassedECS(req, ecsAddr, ecsPrefix)
				}

				resp, _, err := group.Exchange(ctx, req, clientID, clientName, clientAddr)
				msgPool.Put(req)

				if err != nil || resp == nil {
					subCh <- subRes{ok: false}
					return
				}
				isP, info, ownerZone, ttl := inspectMsgForParking(resp)
				subCh <- subRes{parked: isP, info: info, ownerZone: ownerZone, ttl: ttl, ok: true}
			}(p)
		}

		anyOK := false
		for i := 0; i < len(probes); i++ {
			r := <-subCh
			if r.ok {
				anyOK = true
			}
			if r.parked {
				cancel()
				nowStore := time.Now().UnixNano()
				expNano := time.Now().Add(r.ttl).UnixNano()
				entry := pkCacheEntry{
					parked:     true,
					matchedTag: r.info,
					expireNano: expNano,
				}
				setPKCache(ck, entry, nowStore)
				if r.ownerZone != "" && r.ownerZone != target && !shouldSkipForSaleCheck(r.ownerZone, dns.TypeA) {
					setPKCache(pkCacheKey{routeIdx: routeIdx, domain: r.ownerZone}, entry, nowStore)
				}
				return entry, nil
			}
		}

		negTTL := pkNegTTL
		if !anyOK {
			negTTL = pkFailTTL
		}
		entry := pkCacheEntry{
			parked:     false,
			expireNano: time.Now().Add(negTTL).UnixNano(),
		}
		setPKCache(ck, entry, time.Now().UnixNano())
		return entry, nil
	})

	select {
	case <-parentCtx.Done():
		return false, ""
	case r := <-resCh:
		if res, ok := r.Val.(pkCacheEntry); ok {
			return res.parked, res.matchedTag
		}
		return false, ""
	}
}

func checkParkedDomain(group *UpstreamGroup, routeIdx uint16, qname, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (parked bool, matchedTarget string, matchedInfo string) {
	if group == nil || shouldSkipForSaleCheck(qname, dns.TypeA) {
		return false, "", ""
	}

	apex, _ := extractETLDPlusOne(qname)
	checkApex := apex != "" && apex != qname && !isPublicSuffix(apex) && !isDGASafeDomain(apex)
	if checkApex {
		if _, isShared := sharedHostingDomains[apex]; isShared {
			checkApex = false
		}
	}

	walkStop := qname
	if checkApex {
		walkStop = apex
	}

	now := time.Now().UnixNano()

	if hit, target, info, qNeg, aNeg := hasCachedParkedAncestor(routeIdx, qname, walkStop, now); hit {
		return true, target, info
	} else {
		if qNeg && (!checkApex || aNeg) {
			return false, "", ""
		}

		if !checkApex || aNeg {
			ok, info := probeParkedTarget(context.Background(), group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
			if ok {
				return true, qname, info
			}
			return false, "", ""
		}
		if qNeg {
			ok, info := probeParkedTarget(context.Background(), group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
			if ok {
				return true, apex, info
			}
			return false, "", ""
		}
	}

	type probeRes struct {
		parked bool
		target string
		info   string
	}
	ch := make(chan probeRes, 2)
	probeCtx, cancelProbes := context.WithCancel(context.Background())
	defer cancelProbes()

	go func() {
		ok, info := probeParkedTarget(probeCtx, group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{parked: ok, target: apex, info: info}
	}()
	go func() {
		ok, info := probeParkedTarget(probeCtx, group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{parked: ok, target: qname, info: info}
	}()

	r1 := <-ch
	if r1.parked {
		cancelProbes()
		return true, r1.target, r1.info
	}
	r2 := <-ch
	if r2.parked {
		return true, r2.target, r2.info
	}
	return false, "", ""
}

// applyParkedVerdict executes the configured action (`LOG`, `BLOCK`, `DROP`, or RCODE)
// once a parked domain match has been identified.
func (qc *queryCtx) applyParkedVerdict(matchedDomain, matchedInfo string, cacheHit bool) bool {
	if parkedAction == "LOG" || (parkedAction == "BLOCK" && globalBlockAction == BlockActionLog) {
		if logQueries && !logSimple {
			log.Printf("[DNS] [%s] %s -> %s %s | PARKED DETECTION (LOG ONLY) (%s: %s) | LOG",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), matchedDomain, matchedInfo)
		}
		return false
	}

	IncrPolicyBlock()
	reason := "Parked Domain (" + matchedDomain + " - " + matchedInfo + ")"
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	dropped := writePolicyAction(qc.w, qc.r, parkedActionCode)

	if cacheSynthFlag && !dropped && !(parkedActionCode == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, parkedActionCode)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		var actionLogStr string
		if parkedActionCode == PolicyActionBlock {
			actionLogStr = getBlockActionLogStr(qc.q.Qtype)
		} else if parkedActionCode == PolicyActionDrop {
			actionLogStr = "DROP"
		} else {
			actionLogStr = RcodeStr(parkedActionCode)
		}

		if logSimple {
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), actionLogStr, reason, cacheHit)
		} else {
			statusMark := "PARKED BLOCK"
			if dropped {
				statusMark = "PARKED DROP"
			}
			statusMark = qc.annotateAlias(statusMark)

			log.Printf("[DNS] [%s] %s -> %s %s | %s (%s: %s) | %s",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				statusMark, matchedDomain, matchedInfo, actionLogStr)
		}
	}

	return true
}

func (qc *queryCtx) enforceParkedCachedOnly() bool {
	if !hasParked || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}

	checkSingleCached := func(cand string) bool {
		targetQName, skip := normalizeForSaleTarget(cand, qc.q.Qtype)
		if skip {
			return false
		}
		if ddrHostnames != nil && ddrHostnames[targetQName] {
			return false
		}

		apex, _ := extractETLDPlusOne(targetQName)
		walkStop := targetQName
		if apex != "" && apex != targetQName && !isPublicSuffix(apex) && !isDGASafeDomain(apex) {
			if _, isShared := sharedHostingDomains[apex]; !isShared {
				walkStop = apex
			}
		}

		hit, matchedDomain, matchedInfo, _, _ := hasCachedParkedAncestor(
			qc.route.routeIdx,
			targetQName,
			walkStop,
			time.Now().UnixNano(),
		)
		if !hit {
			return false
		}
		return qc.applyParkedVerdict(matchedDomain, matchedInfo, true)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingleCached(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingleCached(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceParkedCheck() bool {
	if !hasParked || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}

	checkSingle := func(cand string) bool {
		targetQName, skip := normalizeForSaleTarget(cand, qc.q.Qtype)
		if skip {
			return false
		}
		if ddrHostnames != nil && ddrHostnames[targetQName] {
			return false
		}

		isParked, matchedDomain, matchedInfo := checkParkedDomain(
			qc.group,
			qc.route.routeIdx,
			targetQName,
			qc.clientID,
			qc.clientName,
			qc.clientAddr,
			qc.ecsAddr,
			qc.ecsPrefix,
			qc.doBit,
			qc.r.CheckingDisabled,
			qc.route.bypassLocal,
			qc.bypassGlobal,
			qc.bypassPolicies,
		)
		if !isParked {
			return false
		}
		return qc.applyParkedVerdict(matchedDomain, matchedInfo, false)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingle(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingle(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceParkedResponseCheck(resp *dns.Msg) bool {
	if !hasParked || resp == nil || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}
	targetQName := qc.qNameTrimmed
	for strings.HasPrefix(targetQName, forSalePrefix) {
		targetQName = strings.TrimPrefix(targetQName, forSalePrefix)
	}
	if shouldSkipForSaleCheck(targetQName, dns.TypeA) {
		return false
	}
	if ddrHostnames != nil && ddrHostnames[targetQName] {
		return false
	}

	isParked, matchedInfo, ownerZone, ttl := inspectMsgForParking(resp)
	now := time.Now().UnixNano()
	if !isParked {
		if qc.q.Qtype == dns.TypeNS || qc.q.Qtype == dns.TypeSOA {
			setPKCache(pkCacheKey{routeIdx: qc.route.routeIdx, domain: targetQName}, pkCacheEntry{
				parked:     false,
				expireNano: time.Now().Add(ttl).UnixNano(),
			}, now)
		}
		return false
	}

	expNano := time.Now().Add(ttl).UnixNano()
	entry := pkCacheEntry{
		parked:     true,
		matchedTag: matchedInfo,
		expireNano: expNano,
	}

	cacheDomain := targetQName
	if ownerZone != "" && (ownerZone == targetQName || hasDotSuffix(targetQName, ownerZone)) && !shouldSkipForSaleCheck(ownerZone, dns.TypeA) {
		cacheDomain = ownerZone
	}
	setPKCache(pkCacheKey{routeIdx: qc.route.routeIdx, domain: cacheDomain}, entry, now)
	if cacheDomain != targetQName {
		setPKCache(pkCacheKey{routeIdx: qc.route.routeIdx, domain: targetQName}, entry, now)
	}
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		origBase := qc.originalQNameTrimmed
		for strings.HasPrefix(origBase, forSalePrefix) {
			origBase = strings.TrimPrefix(origBase, forSalePrefix)
		}
		if origBase != targetQName && origBase != cacheDomain && !shouldSkipForSaleCheck(origBase, dns.TypeA) {
			setPKCache(pkCacheKey{routeIdx: qc.route.routeIdx, domain: origBase}, entry, now)
		}
	}

	return qc.applyParkedVerdict(cacheDomain, matchedInfo, false)
}
