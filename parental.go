/*
File:    parental.go
Version: 3.16.0 (Split)
Updated: 06-May-2026 12:33 CEST

Description:
  Parental control hot-path runtime for sdproxy.

Changes:
  3.16.0 - [FIX] Hardened `path:` routing assignments natively by cleanly trimming 
           trailing slashes and forcing case-insensitivity. Ensures dynamic path evaluations 
           are identical to their configured structures, avoiding resolution misses.
  3.15.0 - [SECURITY/FIX] Sorted `cidrToGroup` arrays natively by prefix length 
           descending to eradicate non-deterministic routing anomalies natively 
           caused by random map iterations spanning overlapping subnets.
  3.14.0 - [FEAT] Extracted `ResolveClientGroup` natively to power the Custom Rules Engine 
           early evaluation pipeline.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var budgetWarnThresholds = []int64{1800, 900, 300, 60} 
const blockLogRateLimit = 60 * time.Second

type groupState struct {
	mu sync.Mutex

	lastSeen map[string]time.Time
	remaining map[string]int64
	warnedThresholds map[string]bool
	lastBlockLog map[string]time.Time
	sessionActive map[string]bool
	hardBlocked map[string]bool
	hardAllowed map[string]bool
	hardFree map[string]bool
	hardLog map[string]bool

	lastClientIP   string
	lastClientName string
}

type cidrGroupEntry struct {
	net   netip.Prefix
	group string
}

type macWildGroupEntry struct {
	pattern string 
	group   string
}

var (
	macToStateKey map[string]string
	ipToStateKey  map[string]string
	cidrToGroup   []cidrGroupEntry
	macWildToGroup []macWildGroupEntry
	nameToGroup   map[string]string
	sniToGroup    map[string]string
	pathToGroup   map[string]string
	asnToGroup    map[string]string 
	stateToGroup  map[string]string
	groupStates   map[string]*groupState
	parentalStateMu sync.RWMutex
	ParentalGroupClients map[string]int 
)

var hasParental bool

func makeStateKey(groupName, clientID, mode string) string {
	if mode == "device" {
		return groupName + "/" + clientID
	}
	return groupName
}

func newGroupState(grp GroupConfig) *groupState {
	gs := &groupState{
		lastSeen:         make(map[string]time.Time),
		remaining:        make(map[string]int64),
		hardBlocked:      make(map[string]bool),
		hardAllowed:      make(map[string]bool),
		hardFree:         make(map[string]bool),
		hardLog:          make(map[string]bool),
		warnedThresholds: make(map[string]bool),
		lastBlockLog:     make(map[string]time.Time),
		sessionActive:    make(map[string]bool),
	}
	for key, val := range grp.Budget {
		switch strings.ToLower(val) {
		case "allow":
			gs.hardAllowed[key] = true
		case "block":
			gs.hardBlocked[key] = true
		case "free":
			gs.hardFree[key] = true
		case "log":
			gs.hardLog[key] = true
		case "unlimited":
		default:
			d, err := time.ParseDuration(val)
			if err != nil {
				log.Printf("[PARENTAL] Invalid budget value %q for key %q: %v", val, key, err)
				continue
			}
			gs.remaining[key] = int64(d.Seconds())
		}
	}
	return gs
}

func InitParental() {
	if len(cfg.Groups) == 0 {
		return
	}

	ParentalGroupClients = make(map[string]int)

	type groupInfo struct {
		macs     []string
		macGlobs []string
		ips      []string
		cidrs    []netip.Prefix
		names    []string
		snis     []string
		paths    []string
		asns     []string
	}
	groups := make(map[string]*groupInfo, len(cfg.Groups))
	for name := range cfg.Groups {
		groups[name] = &groupInfo{}
	}

	processParentalRoute := func(rawKey string, route RouteConfig) {
		if route.Group == "" {
			return
		}
		info, ok := groups[route.Group]
		if !ok {
			return
		}
		
		for _, key := range strings.Split(rawKey, ",") {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}

			ParentalGroupClients[route.Group]++ 

			switch classifyRouteKey(key) {
			case rkMAC:
				if mac, err := net.ParseMAC(key); err == nil {
					info.macs = append(info.macs, mac.String())
				}
			case rkMACGlob:
				info.macGlobs = append(info.macGlobs, normaliseMACGlob(key))
			case rkIP:
				if ip, err := netip.ParseAddr(key); err == nil {
					info.ips = append(info.ips, ip.Unmap().String())
				}
			case rkCIDR:
				if prefix, err := netip.ParsePrefix(key); err == nil {
					info.cidrs = append(info.cidrs, prefix.Masked())
				}
			case rkClientName:
				info.names = append(info.names, strings.ToLower(key))
			case rkSNI:
				info.snis = append(info.snis, strings.ToLower(strings.TrimPrefix(key, "sni:")))
			case rkPath:
				p := key
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimPrefix(p, "path:")
				}
				p = strings.ToLower(strings.TrimSuffix(p, "/"))
				info.paths = append(info.paths, p)
			case rkASN:
				info.asns = append(info.asns, strings.ToUpper(key))
			}
		}
	}

	for key, route := range cfg.Routes {
		processParentalRoute(key, route)
	}

	for filePath, route := range cfg.RoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			log.Printf("[WARN] parental: cannot read routes file %q: %v", filePath, err)
			continue
		}
		for _, line := range lines {
			processParentalRoute(line, route)
		}
	}

	macToStateKey  = make(map[string]string)
	ipToStateKey   = make(map[string]string)
	stateToGroup   = make(map[string]string)
	groupStates    = make(map[string]*groupState)
	nameToGroup    = make(map[string]string)
	sniToGroup     = make(map[string]string)
	pathToGroup    = make(map[string]string)
	asnToGroup     = make(map[string]string)
	macWildToGroup = nil
	cidrToGroup    = nil

	for name, grp := range cfg.Groups {
		info := groups[name]
		mode := strings.ToLower(grp.BudgetTracking)

		if mode == "device" {
			for _, mac := range info.macs {
				macToStateKey[mac] = makeStateKey(name, mac, "device")
				sk := macToStateKey[mac]
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs
				loadSnapshot(sk, gs)
			}
			for _, ip := range info.ips {
				ipToStateKey[ip] = makeStateKey(name, ip, "device")
				sk := ipToStateKey[ip]
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs
				loadSnapshot(sk, gs)
			}
			for _, prefix := range info.cidrs {
				cidrToGroup = append(cidrToGroup, cidrGroupEntry{net: prefix, group: name})
			}
			for _, pat := range info.macGlobs {
				macWildToGroup = append(macWildToGroup, macWildGroupEntry{pattern: pat, group: name})
			}
			for _, n := range info.names {
				nameToGroup[n] = name
			}
			for _, s := range info.snis {
				sniToGroup[s] = name
			}
			for _, p := range info.paths {
				pathToGroup[p] = name
			}
			for _, a := range info.asns {
				asnToGroup[a] = name
			}
			log.Printf("[PARENTAL] Group %q: device tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d ASN",
				name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.asns))
		} else {
			sk := name
			for _, mac := range info.macs {
				macToStateKey[mac] = sk
			}
			for _, ip := range info.ips {
				ipToStateKey[ip] = sk
			}
			for _, prefix := range info.cidrs {
				cidrToGroup = append(cidrToGroup, cidrGroupEntry{net: prefix, group: name})
			}
			for _, pat := range info.macGlobs {
				macWildToGroup = append(macWildToGroup, macWildGroupEntry{pattern: pat, group: name})
			}
			for _, n := range info.names {
				nameToGroup[n] = name
			}
			for _, s := range info.snis {
				sniToGroup[s] = name
			}
			for _, p := range info.paths {
				pathToGroup[p] = name
			}
			for _, a := range info.asns {
				asnToGroup[a] = name
			}
			stateToGroup[sk] = name
			gs := newGroupState(grp)
			groupStates[sk] = gs
			loadSnapshot(sk, gs)
			log.Printf("[PARENTAL] Group %q: group tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d ASN",
				name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.asns))
		}
	}

	if len(cidrToGroup) > 0 {
		// [SECURITY/FIX] Sort Parental CIDR routing arrays natively by prefix length descending
		// Eliminates arbitrary group mismatches resulting from randomized iteration across maps natively.
		sort.SliceStable(cidrToGroup, func(i, j int) bool {
			return cidrToGroup[i].net.Bits() > cidrToGroup[j].net.Bits()
		})
	}

	hasParental = true

	loadCatCache()

	go loadAllCategoryLists(forceRefreshStartup) 
	go runDebitTicker()
	go runWeeklyListRefresh()
	go runMidnightReset()

	log.Printf("[PARENTAL] Initialised: %d state(s)", len(groupStates))
}

// ResolveClientGroup returns the underlying group mapping for a client synchronously.
func ResolveClientGroup(clientMAC, clientIP string, clientAddr netip.Addr, clientName, sni, path string) string {
	if !hasParental {
		return ""
	}
	parentalStateMu.RLock()
	defer parentalStateMu.RUnlock()

	var sk, groupName string

	if clientMAC != "" {
		sk = macToStateKey[clientMAC]
	}
	if sk == "" && clientMAC != "" {
		for _, wg := range macWildToGroup {
			if matchMACGlob(wg.pattern, clientMAC) {
				groupName = wg.group
				break
			}
		}
	}
	if sk == "" && groupName == "" && clientIP != "" {
		sk = ipToStateKey[clientIP]
	}
	if sk == "" && groupName == "" && clientAddr.IsValid() && len(cidrToGroup) > 0 {
		for _, cr := range cidrToGroup {
			if cr.net.Contains(clientAddr) {
				groupName = cr.group
				break
			}
		}
	}
	if sk == "" && groupName == "" && clientAddr.IsValid() {
		if asn, _, _ := LookupASNDetails(clientAddr); asn != "" {
			if gName, ok := asnToGroup[asn]; ok {
				groupName = gName
			}
		}
	}
	if sk == "" && groupName == "" && clientName != "" {
		groupName = nameToGroup[strings.ToLower(clientName)]
	}
	if sk == "" && groupName == "" && sni != "" {
		groupName = sniToGroup[strings.ToLower(sni)]
	}
	cleanPath := strings.ToLower(strings.TrimSuffix(path, "/"))
	if sk == "" && groupName == "" && cleanPath != "" {
		groupName = pathToGroup[cleanPath]
	}

	if sk != "" {
		groupName = stateToGroup[sk]
	}

	return groupName
}

func CheckParental(clientMAC, clientIP string, clientAddr netip.Addr, clientName, sni, path, domain string, targetAddr netip.Addr, silentStats bool, bypassParental bool) (blocked bool, blockTTL, forcedTTL uint32, reason string, category string, matchedApex string) {
	if bypassParental {
		return false, 0, 0, "ALLOW", "", ""
	}
	if !hasParental {
		if !silentStats {
			IncrGroup("default")
		}
		return false, 0, 0, "", "", ""
	}

	targetType := "domain"
	if targetAddr.IsValid() {
		targetType = "IP"
	} else if _, err := netip.ParseAddr(domain); err == nil {
		targetType = "IP"
	}

	parentalStateMu.RLock()
	var sk, groupName string

	if clientMAC != "" {
		sk = macToStateKey[clientMAC]
	}
	if sk == "" && clientMAC != "" {
		for _, wg := range macWildToGroup {
			if matchMACGlob(wg.pattern, clientMAC) {
				groupName = wg.group
				break
			}
		}
	}
	if sk == "" && groupName == "" && clientIP != "" {
		sk = ipToStateKey[clientIP]
	}
	
	if sk == "" && groupName == "" && clientAddr.IsValid() && len(cidrToGroup) > 0 {
		for _, cr := range cidrToGroup {
			if cr.net.Contains(clientAddr) {
				groupName = cr.group
				break
			}
		}
	}
	if sk == "" && groupName == "" && clientAddr.IsValid() {
		if asn, _, _ := LookupASNDetails(clientAddr); asn != "" {
			if gName, ok := asnToGroup[asn]; ok {
				groupName = gName
			}
		}
	}
	if sk == "" && groupName == "" && clientName != "" {
		groupName = nameToGroup[strings.ToLower(clientName)]
	}
	if sk == "" && groupName == "" && sni != "" {
		groupName = sniToGroup[strings.ToLower(sni)]
	}
	cleanPath := strings.ToLower(strings.TrimSuffix(path, "/"))
	if sk == "" && groupName == "" && cleanPath != "" {
		groupName = pathToGroup[cleanPath]
	}

	if sk != "" {
		groupName = stateToGroup[sk]
	}
	parentalStateMu.RUnlock()

	if sk == "" && groupName == "" {
		if !silentStats {
			IncrGroup("default")
		}
		return false, 0, 0, "", "", "" 
	}

	if sk == "" && groupName != "" {
		grpCfg, ok := cfg.Groups[groupName]
		if !ok {
			return false, 0, 0, "", "", ""
		}
		mode := strings.ToLower(grpCfg.BudgetTracking)

		deviceID := clientIP
		if mode == "device" {
			if clientMAC != "" {
				deviceID = clientMAC
			} else if clientIP != "" {
				deviceID = clientIP
			} else if clientName != "" {
				deviceID = clientName
			} else if sni != "" {
				deviceID = "sni:" + sni
			} else if path != "" {
				deviceID = "path:" + path
			}
		}

		if mode == "device" {
			sk = makeStateKey(groupName, deviceID, "device")
		} else {
			sk = groupName
		}

		parentalStateMu.Lock()
		if _, exists := groupStates[sk]; !exists {
			gs := newGroupState(grpCfg)
			stateToGroup[sk] = groupName
			groupStates[sk]  = gs
			if mode == "device" {
				if clientMAC != "" {
					macToStateKey[clientMAC] = sk
				} else if clientIP != "" {
					ipToStateKey[clientIP] = sk
				}
			}
			loadSnapshot(sk, gs)
		} else if mode == "device" {
			if clientMAC != "" && macToStateKey[clientMAC] == "" {
				macToStateKey[clientMAC] = sk
			} else if clientIP != "" && ipToStateKey[clientIP] == "" {
				ipToStateKey[clientIP] = sk
			}
		}
		parentalStateMu.Unlock()
	}

	parentalStateMu.RLock()
	groupName = stateToGroup[sk]
	gs        := groupStates[sk]
	parentalStateMu.RUnlock()

	if !silentStats {
		if groupName != "" {
			IncrGroup(groupName)
		} else {
			IncrGroup("default")
		}
	}

	grpCfg, ok := cfg.Groups[groupName]
	if !ok || gs == nil {
		return false, 0, 0, "", "", ""
	}

	cat, matchedApex := categoryOf(domain, targetAddr)

	if !silentStats {
		IncrCategory(cat)
	}

	btl := uint32(effectiveBlockTTL(grpCfg.BlockTTL))
	ftl := uint32(cfg.Parental.ForcedTTL)
	if ftl == 0 {
		ftl = 60
	}

	ov := GetGroupOverride(groupName)

	if ov == "ALLOW" {
		return false, 0, 0, "ALLOW", cat, matchedApex
	}
	if ov == "BLOCK" {
		return true, btl, 0, "Manual Override (" + groupName + ")", cat, matchedApex
	}

	gs.mu.Lock()
	defer gs.mu.Unlock()

	gs.lastClientIP   = clientIP
	gs.lastClientName = clientName

	catConfigured := false
	if cat != "" {
		_, catConfigured = grpCfg.Budget[cat]
	}

	domainStr := domain
	if domainStr == "" && targetAddr.IsValid() {
		domainStr = targetAddr.String()
	}

	if catConfigured {
		if gs.hardLog[cat] {
			log.Printf("[PARENTAL] [%s] PARENTAL LOG: %q (match: %s) | client: %s | %s: %s",
				sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr)
			return false, 0, ftl, "LOG", cat, matchedApex
		}
		if gs.hardFree[cat] {
			return false, 0, ftl, "FREE", cat, matchedApex
		}
		if gs.hardAllowed[cat] {
			return false, 0, 0, "ALLOW", cat, matchedApex
		}
		if gs.hardBlocked[cat] {
			logBlockRateLimited(gs, sk, cat,
				fmt.Sprintf("[PARENTAL] [%s] Blocked: %q is BLOCK (match: %s) | client: %s | %s: %s",
					sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
			return true, btl, 0, "Blocked: " + cat + " (" + groupName + ")", cat, matchedApex
		}
	} else {
		if gs.hardLog["total"] {
			if cat != "" {
				log.Printf("[PARENTAL] [%s] PARENTAL LOG: %q (match: %s) | client: %s | %s: %s",
					sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr)
			}
			return false, 0, ftl, "LOG", cat, matchedApex
		}
		if gs.hardFree["total"] {
			return false, 0, ftl, "FREE", cat, matchedApex
		}
		if gs.hardAllowed["total"] {
			return false, 0, 0, "ALLOW", cat, matchedApex
		}
		if gs.hardBlocked["total"] {
			catStr := ""
			if cat != "" {
				catStr = " (Category: " + cat + ", match: " + matchedApex + ")"
			}
			logBlockRateLimited(gs, sk, "total",
				fmt.Sprintf("[PARENTAL] [%s] Blocked: total is BLOCK%s | client: %s | %s: %s",
					sk, catStr, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
			return true, btl, 0, "Blocked: total (" + groupName + ")", cat, matchedApex
		}
	}

	if ov == "LOG" {
		if cat != "" {
			log.Printf("[PARENTAL] [%s] PARENTAL LOG: %q (match: %s) | client: %s | %s: %s",
				sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr)
		}
		return false, 0, ftl, "LOG", cat, matchedApex
	}
	if ov == "FREE" {
		return false, 0, ftl, "FREE", cat, matchedApex
	}

	if len(grpCfg.Schedule) > 0 && !inAnyScheduleWindow(grpCfg.Schedule) {
		catStr := ""
		if cat != "" {
			catStr = " (Category: " + cat + ", match: " + matchedApex + ")"
		}
		logBlockRateLimited(gs, sk, "schedule",
			fmt.Sprintf("[PARENTAL] [%s] Blocked: outside schedule%s | client: %s | %s: %s",
				sk, catStr, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
		return true, btl, 0, "Schedule (" + groupName + ")", cat, matchedApex
	}

	if cat != "" {
		gs.lastSeen[cat] = time.Now()
		if rem, limited := gs.remaining[cat]; limited {
			if rem <= 0 {
				logBlockRateLimited(gs, sk, cat,
					fmt.Sprintf("[PARENTAL] [%s] Blocked: %q budget exhausted (match: %s) | client: %s | %s: %s",
						sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
				return true, btl, 0, "Budget: " + cat + " (" + groupName + ")", cat, matchedApex
			}
			if !gs.sessionActive[cat] {
				gs.sessionActive[cat] = true
				log.Printf("[PARENTAL] [%s] Category %q session started | client: %s | remaining: %s",
					sk, cat, buildClientID(clientIP, clientName, clientAddr), remainingStr(gs, cat))
			}
			checkBudgetWarning(gs, sk, cat)
		}
	}
	
	if rem, limited := gs.remaining["total"]; limited {
		if rem <= 0 {
			catStr := ""
			if cat != "" {
				catStr = " (Category: " + cat + ", match: " + matchedApex + ")"
			}
			logBlockRateLimited(gs, sk, "total",
				fmt.Sprintf("[PARENTAL] [%s] Blocked: total budget exhausted%s | client: %s | %s: %s",
					sk, catStr, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
			return true, btl, 0, "Budget: total (" + groupName + ")", cat, matchedApex
		}
		checkBudgetWarning(gs, sk, "total")
	}

	return false, 0, ftl, "", cat, matchedApex
}

