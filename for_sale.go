/*
File:    for_sale.go
Version: 1.14.0
Last Updated: 13-Nov-2026 14:10 CET

Description:
  RFC 10023 ("The '_for-sale' Underscored and Globally Scoped DNS Node Name")
  detection and enforcement engine for sdproxy.

  Intelligently probes `_for-sale.<qname>` and `_for-sale.<apex>` (when the
  queried domain is a subdomain of an eTLD+1 apex) for valid RFC 10023 TXT
  records using the query's resolved upstream group.

Changes:
  1.14.0 - [SECURITY/FIX] Treated `consensus-log(...)` responses from
           `group.Exchange` in `probeForSaleTarget` identically to `consensus(...)`
           failure responses (`fsFailTTL`), preventing unverified consensus-failed
           responses in `block_action: "LOG"` mode from being cached as valid
           RFC 10023 `_for-sale.` verdicts.
  1.13.0 - [SECURITY/FIX] Treated `consensus(...)` failure responses from
           `group.Exchange` in `probeForSaleTarget` as probe failures (`fsFailTTL`)
           rather than valid negative DNS responses (`fsNegTTL`).
  1.12.0 - [SECURITY/FIX] Evaluated `qc.originalQNameTrimmed` in addition to
           `qc.qNameTrimmed` in `enforceForSaleCachedOnly` and `enforceForSaleCheck`
           when a query was rewritten by an `rrs:` CNAME alias, preventing CNAME
           aliases from bypassing RFC 10023 `_for-sale.` checks on the original
           queried domain.
  1.11.0 - [CRITICAL/FIX] Marked outbound `_for-sale.` probe contexts with
           `WithBypassUpstreamThrottle` (`throttle.go` 2.7.0).
  1.10.0 - [SECURITY/FIX] Extended `parseForSaleResponse` bailiwick chain walking
           to recognize RFC 6672 `DNAME` records alongside `CNAME` records.
  1.9.0  - [SECURITY/FIX] Aligned `effectiveDo` in `probeForSaleTarget` cache
           lookaside with `group.RequireDNSSECAD`.
  1.8.0  - [SECURITY/FIX] Propagated `doBit` and `cdBit` into `probeForSaleTarget`
           cache lookaside.
  1.7.0  - [FEAT] Added `cacheHit` tracking and Simple Logging Mode (`logSimple` /
           `logQuerySimple`) support in `applyForSaleVerdict`.
  1.6.0  - [SECURITY/FIX] Cached negative verdicts in `enforceForSaleResponseCheck`.
  1.5.0  - [SECURITY/FIX] Attached validated incoming `EDNS0_SUBNET` (`ecsAddr` /
           `ecsPrefix`) to outbound `_for-sale.` probe requests when `group.ECSAction == "pass"`.
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
	forSalePrefix     = "_for-sale."
	forSaleVersionTag = "v=FORSALE1;"

	fsShardCount      = 64
	fsMaxEntries      = 32768
	fsMaxPerShard     = fsMaxEntries / fsShardCount
	fsEvictSampleSize = 16

	fsMinTTL      = 300 * time.Second
	fsMaxTTL      = 3600 * time.Second
	fsNegTTL      = 900 * time.Second
	fsFailTTL     = 60 * time.Second
	fsProbeBudget = 1500 * time.Millisecond
)

type fsCacheKey struct {
	routeIdx uint16
	domain   string
}

type fsCacheEntry struct {
	forSale    bool
	matchedTag string
	expireNano int64
}

type fsShard struct {
	sync.RWMutex
	items map[fsCacheKey]fsCacheEntry
}

var (
	forSaleAction     string
	forSaleActionCode int
	fsShards          [fsShardCount]*fsShard
	fsHashSeed        maphash.Seed
	fsSFGroup         singleflight.Group
)

// InitForSale initializes the RFC 10023 `_for-sale.` detection subsystem.
func InitForSale() {
	act := strings.ToUpper(strings.TrimSpace(cfg.Server.ForSale))
	switch act {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		hasForSale = false
		forSaleAction = "DISABLED"
		return
	case "LOG":
		forSaleAction = "LOG"
		forSaleActionCode = 0
	case "DROP":
		forSaleAction = "DROP"
		forSaleActionCode = PolicyActionDrop
	case "BLOCK":
		forSaleAction = "BLOCK"
		forSaleActionCode = PolicyActionBlock
	default:
		rc, ok := dns.StringToRcode[act]
		if !ok {
			if logSystem {
				log.Printf("[FOR-SALE] WARNING: unknown server.for_sale action %q — disabling feature", cfg.Server.ForSale)
			}
			hasForSale = false
			forSaleAction = "DISABLED"
			return
		}
		forSaleAction = act
		forSaleActionCode = rc
	}

	fsHashSeed = maphash.MakeSeed()
	for i := 0; i < fsShardCount; i++ {
		fsShards[i] = &fsShard{
			items: make(map[fsCacheKey]fsCacheEntry, 64),
		}
	}
	hasForSale = true

	if logSystem {
		log.Printf("[FOR-SALE] RFC 10023 '_for-sale.' detection enabled (Action: %s)", forSaleAction)
	}

	go runForSaleSweeper()
}

func getFSShard(key fsCacheKey) *fsShard {
	h := maphash.String(fsHashSeed, key.domain)
	h ^= uint64(key.routeIdx) * 0x9e3779b97f4a7c15
	return fsShards[h&(fsShardCount-1)]
}

func getFSCache(key fsCacheKey, now int64) (fsCacheEntry, bool) {
	sh := getFSShard(key)
	sh.RLock()
	entry, ok := sh.items[key]
	sh.RUnlock()
	if !ok || now >= entry.expireNano {
		return fsCacheEntry{}, false
	}
	return entry, true
}

func setFSCache(key fsCacheKey, entry fsCacheEntry, now int64) {
	sh := getFSShard(key)
	sh.Lock()
	defer sh.Unlock()

	if _, exists := sh.items[key]; !exists && len(sh.items) >= fsMaxPerShard {
		var (
			victimKey    fsCacheKey
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
			if sampled >= fsEvictSampleSize {
				break
			}
		}
		if sampled > 0 {
			delete(sh.items, victimKey)
		}
	}

	sh.items[key] = entry
}

func runForSaleSweeper() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			for i := 0; i < fsShardCount; i++ {
				sh := fsShards[i]
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

func isValidRFC10023TXT(txt *dns.TXT) (bool, string) {
	if txt == nil || len(txt.Txt) != 1 {
		return false, ""
	}
	raw := txt.Txt[0]
	if !strings.HasPrefix(raw, forSaleVersionTag) {
		return false, ""
	}
	if len(raw) > 255 {
		return false, ""
	}
	return true, raw
}

func parseForSaleResponse(msg *dns.Msg, target string) (isForSale bool, matchedTxt string, ttl time.Duration) {
	if msg == nil {
		return false, "", fsFailTTL
	}
	if msg.Rcode != dns.RcodeSuccess {
		if msg.Rcode == dns.RcodeNameError {
			return false, "", fsNegTTL
		}
		return false, "", fsFailTTL
	}

	if len(msg.Answer) == 0 {
		return false, "", fsNegTTL
	}

	qName := forSalePrefix + target + "."
	var chainBuf [64]string
	validNames := chainBuf[:0]
	validNames = append(validNames, strings.ToLower(qName))

	for depth := 0; depth < 8; depth++ {
		added := false
		for _, rr := range msg.Answer {
			owner := strings.ToLower(rr.Header().Name)
			switch r := rr.(type) {
			case *dns.CNAME:
				if isValidBailiwickName(validNames, owner) {
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

	minRRTTL := uint32(3600)
	for _, rr := range msg.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}
		if !isValidBailiwickName(validNames, strings.ToLower(txt.Hdr.Name)) {
			continue
		}
		if valid, raw := isValidRFC10023TXT(txt); valid {
			isForSale = true
			if matchedTxt == "" {
				matchedTxt = raw
			}
			if txt.Hdr.Ttl > 0 && txt.Hdr.Ttl < minRRTTL {
				minRRTTL = txt.Hdr.Ttl
			}
		}
	}

	if !isForSale {
		return false, "", fsNegTTL
	}

	ttl = time.Duration(minRRTTL) * time.Second
	if ttl < fsMinTTL {
		ttl = fsMinTTL
	} else if ttl > fsMaxTTL {
		ttl = fsMaxTTL
	}
	return true, matchedTxt, ttl
}

func hasCachedForSaleAncestor(routeIdx uint16, qname, apex string, now int64) (forSale bool, matchedTarget string, matchedTxt string, qnameCachedNeg bool, apexCachedNeg bool) {
	search := qname
	for {
		if entry, ok := getFSCache(fsCacheKey{routeIdx: routeIdx, domain: search}, now); ok {
			if entry.forSale {
				return true, forSalePrefix + search, entry.matchedTag, false, false
			}
			if search == qname {
				qnameCachedNeg = true
			}
			if search == apex {
				apexCachedNeg = true
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

func probeCacheKeyPartitions(group *UpstreamGroup, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix) (cName, ecsStr string) {
	if group == nil {
		return "", ""
	}
	if group.HasClientName {
		cName = clientName
	}
	if group.ECSAction == "add" && clientAddr.IsValid() {
		var m int
		if clientAddr.Is4() {
			m = group.ECSV4Mask
		} else {
			m = group.ECSV6Mask
		}
		if prefix, err := clientAddr.Prefix(m); err == nil {
			ecsStr = prefix.Masked().String()
		}
	} else if group.ECSAction == "pass" && ecsAddr.IsValid() {
		if ecsPrefix.IsValid() {
			ecsStr = ecsPrefix.String()
		} else {
			ecsStr = ecsAddr.String()
		}
	}
	return cName, ecsStr
}

func probeForSaleTarget(parentCtx context.Context, group *UpstreamGroup, routeIdx uint16, target, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (bool, string) {
	now := time.Now().UnixNano()
	ck := fsCacheKey{routeIdx: routeIdx, domain: target}
	if entry, ok := getFSCache(ck, now); ok {
		return entry.forSale, entry.matchedTag
	}

	if parentCtx.Err() != nil || len(target) == 0 || len(target)+len(forSalePrefix) > 253 {
		return false, ""
	}

	sfKey := itoa64(int64(routeIdx)) + "|" + target
	resCh := fsSFGroup.DoChan(sfKey, func() (any, error) {
		nowInner := time.Now().UnixNano()
		if entry, ok := getFSCache(ck, nowInner); ok {
			return entry, nil
		}

		cNameKey, ecsKey := probeCacheKeyPartitions(group, clientName, clientAddr, ecsAddr, ecsPrefix)
		effectiveDo := doBit || (group != nil && group.RequireDNSSECAD)
		for _, tryDO := range []bool{effectiveDo, false} {
			mainKey := DNSCacheKey{
				Name:             forSalePrefix + target,
				ClientName:       cNameKey,
				ECS:              ecsKey,
				Qtype:            dns.TypeTXT,
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
			if _, _, cacheOK, _ := CacheGet(mainKey, dns.Fqdn(forSalePrefix+target), pooled); cacheOK && !pooled.Authoritative {
				forSale, txtVal, ttl := parseForSaleResponse(pooled, target)
				msgPool.Put(pooled)
				entry := fsCacheEntry{
					forSale:    forSale,
					matchedTag: txtVal,
					expireNano: time.Now().Add(ttl).UnixNano(),
				}
				setFSCache(ck, entry, nowInner)
				return entry, nil
			}
			msgPool.Put(pooled)
			if !effectiveDo {
				break
			}
		}

		req := msgPool.Get().(*dns.Msg)
		*req = dns.Msg{}
		req.SetQuestion(dns.Fqdn(forSalePrefix+target), dns.TypeTXT)
		req.RecursionDesired = true
		if group.ECSAction == "pass" && ecsAddr.IsValid() {
			injectPassedECS(req, ecsAddr, ecsPrefix)
		}

		ctx, cancel := context.WithTimeout(WithBypassUpstreamThrottle(context.Background()), fsProbeBudget)
		resp, uAddr, err := group.Exchange(ctx, req, clientID, clientName, clientAddr)
		cancel()
		msgPool.Put(req)

		var entry fsCacheEntry
		if err != nil || resp == nil || strings.HasPrefix(uAddr, "consensus(") || strings.HasPrefix(uAddr, "consensus-log(") {
			entry = fsCacheEntry{
				forSale:    false,
				expireNano: time.Now().Add(fsFailTTL).UnixNano(),
			}
		} else {
			forSale, txtVal, ttl := parseForSaleResponse(resp, target)
			entry = fsCacheEntry{
				forSale:    forSale,
				matchedTag: txtVal,
				expireNano: time.Now().Add(ttl).UnixNano(),
			}
		}

		setFSCache(ck, entry, time.Now().UnixNano())
		return entry, nil
	})

	select {
	case <-parentCtx.Done():
		return false, ""
	case r := <-resCh:
		if res, ok := r.Val.(fsCacheEntry); ok {
			return res.forSale, res.matchedTag
		}
		return false, ""
	}
}

func normalizeForSaleTarget(qname string, qtype uint16) (string, bool) {
	if qname == "" || qtype == dns.TypePTR {
		return "", true
	}
	target := qname
	if strings.HasPrefix(target, forSalePrefix) {
		if qtype == dns.TypeTXT {
			return "", true
		}
		for strings.HasPrefix(target, forSalePrefix) {
			target = strings.TrimPrefix(target, forSalePrefix)
		}
	}
	if shouldSkipForSaleCheck(target, qtype) {
		return "", true
	}
	return target, false
}

func shouldSkipForSaleCheck(qname string, qtype uint16) bool {
	if qname == "" || qtype == dns.TypePTR {
		return true
	}
	if strings.HasPrefix(qname, "_") || strings.Contains(qname, "._") {
		return true
	}
	if strings.HasSuffix(qname, ".arpa") || strings.HasSuffix(qname, ".local") || strings.HasSuffix(qname, ".localhost") {
		return true
	}
	if strings.IndexByte(qname, '.') < 0 {
		return true
	}
	if isPublicSuffix(qname) {
		return true
	}
	if isDGASafeDomain(qname) || isVerifiedAWSDNS(qname) {
		return true
	}
	return false
}

func checkForSaleDomain(group *UpstreamGroup, routeIdx uint16, qname, clientID, clientName string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies bool) (forSale bool, matchedTarget string, matchedTxt string) {
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

	if hit, target, txt, qNeg, aNeg := hasCachedForSaleAncestor(routeIdx, qname, walkStop, now); hit {
		return true, target, txt
	} else {
		if qNeg && (!checkApex || aNeg) {
			return false, "", ""
		}

		if !checkApex || aNeg {
			ok, pTxt := probeForSaleTarget(context.Background(), group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
			if ok {
				return true, forSalePrefix + qname, pTxt
			}
			return false, "", ""
		}
		if qNeg {
			ok, pTxt := probeForSaleTarget(context.Background(), group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
			if ok {
				return true, forSalePrefix + apex, pTxt
			}
			return false, "", ""
		}
	}

	type probeRes struct {
		forSale bool
		target  string
		txt     string
	}
	ch := make(chan probeRes, 2)
	probeCtx, cancelProbes := context.WithCancel(context.Background())
	defer cancelProbes()

	go func() {
		ok, txt := probeForSaleTarget(probeCtx, group, routeIdx, apex, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{forSale: ok, target: forSalePrefix + apex, txt: txt}
	}()
	go func() {
		ok, txt := probeForSaleTarget(probeCtx, group, routeIdx, qname, clientID, clientName, clientAddr, ecsAddr, ecsPrefix, doBit, cdBit, bypassLocal, bypassGlobal, bypassPolicies)
		ch <- probeRes{forSale: ok, target: forSalePrefix + qname, txt: txt}
	}()

	r1 := <-ch
	if r1.forSale {
		cancelProbes()
		return true, r1.target, r1.txt
	}
	r2 := <-ch
	if r2.forSale {
		return true, r2.target, r2.txt
	}
	return false, "", ""
}

// applyForSaleVerdict executes the configured action (`LOG`, `BLOCK`, `DROP`, or RCODE)
// once a positive RFC 10023 `_for-sale.` match has been identified.
func (qc *queryCtx) applyForSaleVerdict(matchedLabel, matchedTxt string, cacheHit bool) bool {
	if forSaleAction == "LOG" || (forSaleAction == "BLOCK" && globalBlockAction == BlockActionLog) {
		if logQueries && !logSimple {
			log.Printf("[DNS] [%s] %s -> %s %s | FOR-SALE DETECTION (LOG ONLY) (%s TXT %q) | LOG",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(), matchedLabel, matchedTxt)
		}
		return false
	}

	IncrPolicyBlock()
	reason := "RFC10023 For-Sale (" + matchedLabel + ")"
	RecordBlockEvent(qc.clientIP, qc.originalQNameTrimmed, reason)

	dropped := writePolicyAction(qc.w, qc.r, forSaleActionCode)

	if cacheSynthFlag && !dropped && !(forSaleActionCode == PolicyActionBlock && globalBlockAction == BlockActionDrop) {
		synthMsg := buildSynthCacheMsg(qc.r, qc.q, forSaleActionCode)
		CacheSetSynth(qc.cacheKey, synthMsg)
		msgPool.Put(synthMsg)
	}

	if logQueries {
		var actionLogStr string
		if forSaleActionCode == PolicyActionBlock {
			actionLogStr = getBlockActionLogStr(qc.q.Qtype)
		} else if forSaleActionCode == PolicyActionDrop {
			actionLogStr = "DROP"
		} else {
			actionLogStr = RcodeStr(forSaleActionCode)
		}

		if logSimple {
			logQuerySimple(qc.protoEndpoint, qc.clientIP, qc.originalQName, qc.qtypeStr(), actionLogStr, reason, cacheHit)
		} else {
			statusMark := "FOR-SALE BLOCK"
			if dropped {
				statusMark = "FOR-SALE DROP"
			}
			statusMark = qc.annotateAlias(statusMark)

			log.Printf("[DNS] [%s] %s -> %s %s | %s (%s TXT %q) | %s",
				qc.protocol, qc.clientID, qc.originalQName, qc.qtypeStr(),
				statusMark, matchedLabel, matchedTxt, actionLogStr)
		}
	}

	return true
}

func (qc *queryCtx) enforceForSaleCachedOnly() bool {
	if !hasForSale || qc.bypassPolicies || qc.bypassGlobal {
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

		hit, matchedLabel, matchedTxt, _, _ := hasCachedForSaleAncestor(
			qc.route.routeIdx,
			targetQName,
			walkStop,
			time.Now().UnixNano(),
		)
		if !hit {
			return false
		}
		return qc.applyForSaleVerdict(matchedLabel, matchedTxt, true)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingleCached(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingleCached(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceForSaleCheck() bool {
	if !hasForSale || qc.bypassPolicies || qc.bypassGlobal {
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

		isSale, matchedLabel, matchedTxt := checkForSaleDomain(
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
		if !isSale {
			return false
		}
		return qc.applyForSaleVerdict(matchedLabel, matchedTxt, false)
	}

	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		if checkSingle(qc.originalQNameTrimmed) {
			return true
		}
	}
	return checkSingle(qc.qNameTrimmed)
}

func (qc *queryCtx) enforceForSaleResponseCheck(resp *dns.Msg) bool {
	if !hasForSale || resp == nil || qc.bypassPolicies || qc.bypassGlobal {
		return false
	}
	if qc.q.Qtype != dns.TypeTXT || !strings.HasPrefix(qc.qNameTrimmed, forSalePrefix) {
		return false
	}
	baseDomain := qc.qNameTrimmed
	for strings.HasPrefix(baseDomain, forSalePrefix) {
		baseDomain = strings.TrimPrefix(baseDomain, forSalePrefix)
	}
	if shouldSkipForSaleCheck(baseDomain, dns.TypeA) {
		return false
	}
	if ddrHostnames != nil && ddrHostnames[baseDomain] {
		return false
	}

	forSale, matchedTxt, ttl := parseForSaleResponse(resp, baseDomain)
	now := time.Now().UnixNano()
	entry := fsCacheEntry{
		forSale:    forSale,
		matchedTag: matchedTxt,
		expireNano: time.Now().Add(ttl).UnixNano(),
	}
	setFSCache(fsCacheKey{routeIdx: qc.route.routeIdx, domain: baseDomain}, entry, now)
	if qc.originalQNameTrimmed != qc.qNameTrimmed {
		origBase := qc.originalQNameTrimmed
		for strings.HasPrefix(origBase, forSalePrefix) {
			origBase = strings.TrimPrefix(origBase, forSalePrefix)
		}
		if origBase != baseDomain && !shouldSkipForSaleCheck(origBase, dns.TypeA) {
			setFSCache(fsCacheKey{routeIdx: qc.route.routeIdx, domain: origBase}, entry, now)
		}
	}

	if !forSale {
		return false
	}

	return qc.applyForSaleVerdict(forSalePrefix+baseDomain, matchedTxt, false)
}
