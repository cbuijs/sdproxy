/*
File:    parental.go
Version: 3.39.0 (Split)
Updated: 17-Aug-2026 18:00 CEST

Description:
  Parental control hot-path runtime for sdproxy.

Changes:
  3.39.0 - [SECURITY/FIX] Replaced the destructive 1000-element blind eviction 
           routine triggered during tracking capacity saturation (50,000 bounds).
           Employs power-of-N-choices sampled eviction to definitively discard 
           the absolute oldest inactive trackers natively, resolving vulnerabilities 
           where active residential client budgets were randomly wiped during IP floods.
  3.38.0 - [FEAT] Integrated `countryToGroup` evaluations inside `ResolveStateKeyAndGroup` 
           natively. Allows mapping distinct ISO 3166-1 alpha-2 constraints precisely.
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

	lastSeen           map[string]time.Time
	lastDeductibleSeen map[string]time.Time // Isolates budget-draining traffic from visibility tracking
	remaining          map[string]int64
	warnedThresholds   map[string]bool
	lastBlockLog       map[string]time.Time
	sessionActive      map[string]bool
	lastProgressLog    map[string]time.Time 

	hardBlocked   map[string]bool
	hardAllowed   map[string]bool
	hardFree      map[string]bool
	hardLog       map[string]bool
	hardUntrigger map[string]time.Duration // Maps categories flagged as UNTRIGGER to their explicit duration bounds

	untriggerUntil time.Time // Tracks the exact temporal boundary where the current UNTRIGGER state lapses

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
	countryToGroup map[string]string
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
		lastSeen:           make(map[string]time.Time),
		lastDeductibleSeen: make(map[string]time.Time),
		remaining:          make(map[string]int64),
		hardBlocked:        make(map[string]bool),
		hardAllowed:        make(map[string]bool),
		hardFree:           make(map[string]bool),
		hardLog:            make(map[string]bool),
		hardUntrigger:      make(map[string]time.Duration),
		warnedThresholds:   make(map[string]bool),
		lastBlockLog:       make(map[string]time.Time),
		sessionActive:      make(map[string]bool),
		lastProgressLog:    make(map[string]time.Time),
	}
	for key, val := range grp.Budget {
		upperVal := strings.ToUpper(val)
		switch {
		case upperVal == "ALLOW":
			gs.hardAllowed[key] = true
		case upperVal == "BLOCK":
			gs.hardBlocked[key] = true
		case upperVal == "FREE":
			gs.hardFree[key] = true
		case upperVal == "LOG":
			gs.hardLog[key] = true
		case upperVal == "UNLIMITED":
			// No logic appended, naturally drains "total" natively without restricting itself
		case strings.HasPrefix(upperVal, "UNTRIGGER"):
			var durStr string
			if len(val) > 9 {
				durStr = strings.TrimSpace(val[9:])
			}
			if durStr == "" {
				gs.hardUntrigger[key] = 5 * time.Minute
			} else {
				d, err := time.ParseDuration(durStr)
				if err != nil {
					if logParental {
						log.Printf("[PARENTAL] Invalid UNTRIGGER duration %q for key %q, defaulting to 5m", durStr, key)
					}
					d = 5 * time.Minute
				}
				gs.hardUntrigger[key] = d
			}
		default:
			d, err := time.ParseDuration(val)
			if err != nil {
				if logParental {
					log.Printf("[PARENTAL] Invalid budget value %q for key %q: %v", val, key, err)
				}
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
		countries []string
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
				if prefix, err := ParsePrefixUnmapped(key); err == nil {
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
			case rkCountry:
				info.countries = append(info.countries, strings.ToUpper(strings.TrimPrefix(strings.ToUpper(key), "CC:")))
			}
		}
	}

	for key, route := range cfg.Routes {
		processParentalRoute(key, route)
	}

	for filePath, route := range cfg.RoutesFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
			if logParental {
				log.Printf("[WARN] parental: cannot read routes file %q: %v", filePath, err)
			}
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
	countryToGroup = make(map[string]string)
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
				
				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
			}
			for _, ip := range info.ips {
				ipToStateKey[ip] = makeStateKey(name, ip, "device")
				sk := ipToStateKey[ip]
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs
				
				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
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
			for _, c := range info.countries {
				countryToGroup[c] = name
			}
			if logParental {
				log.Printf("[PARENTAL] Group %q: device tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.asns), len(info.countries))
			}
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
			for _, c := range info.countries {
				countryToGroup[c] = name
			}
			stateToGroup[sk] = name
			gs := newGroupState(grp)
			groupStates[sk] = gs
			
			gs.mu.Lock()
			loadSnapshot(sk, gs)
			gs.mu.Unlock()
			
			if logParental {
				log.Printf("[PARENTAL] Group %q: group tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.asns), len(info.countries))
			}
		}
	}

	if len(cidrToGroup) > 0 {
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

	if logParental {
		log.Printf("[PARENTAL] Initialised: %d state(s)", len(groupStates))
	}
}

func ResolveStateKeyAndGroup(clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientNameLower, sni, sniLower, path, pathLower string) (string, string) {
	parentalStateMu.RLock()
	defer parentalStateMu.RUnlock()

	var sk, groupName string

	if clientMAC != "" {
		if stKey, ok := macToStateKey[clientMAC]; ok {
			sk = stKey
		}
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
		if stKey, ok := ipToStateKey[clientIP]; ok {
			sk = stKey
		}
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
		if asn, _, country := LookupASNDetails(clientAddr); asn != "" || country != "" {
			if asn != "" {
				if gName, ok := asnToGroup[asn]; ok {
					groupName = gName
				}
			}
			if groupName == "" && country != "" {
				if gName, ok := countryToGroup[strings.ToUpper(country)]; ok {
					groupName = gName
				}
			}
		}
	}
	if sk == "" && groupName == "" && clientNameLower != "" {
		if gName, ok := nameToGroup[clientNameLower]; ok {
			groupName = gName
		}
	}
	if sk == "" && groupName == "" && sniLower != "" {
		if gName, ok := sniToGroup[sniLower]; ok {
			groupName = gName
		}
	}
	cleanPath := pathLower
	if strings.HasSuffix(cleanPath, "/") {
		cleanPath = strings.TrimSuffix(cleanPath, "/")
	}
	if sk == "" && groupName == "" && cleanPath != "" {
		if gName, ok := pathToGroup[cleanPath]; ok {
			groupName = gName
		}
	}

	if sk != "" && groupName == "" {
		groupName = stateToGroup[sk]
		if groupName == "" {
			if idx := strings.IndexByte(sk, '/'); idx >= 0 {
				groupName = sk[:idx]
			} else {
				groupName = sk
			}
		}
	}

	if sk == "" && groupName != "" {
		grpCfg, ok := cfg.Groups[groupName]
		if ok {
			mode := strings.ToLower(grpCfg.BudgetTracking)
			if mode == "device" {
				deviceID := clientIP
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
				sk = makeStateKey(groupName, deviceID, "device")
			} else {
				sk = groupName
			}
		}
	}

	return sk, groupName
}

func CheckParental(sk, groupName, clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientNameLower, sni, sniLower, path, pathLower, domain string, targetAddr netip.Addr, silentStats bool, bypassPolicies bool) (blocked bool, blockTTL, forcedTTL uint32, reason string, category string, matchedApex string) {
	if bypassPolicies {
		return false, 0, 0, "ALLOW", "", ""
	}

	if sk == "" && groupName == "" {
		if !silentStats {
			IncrGroup("default")
		}
		return false, 0, 0, "", "", "" 
	}

	targetType := "domain"
	if targetAddr.IsValid() {
		targetType = "IP"
	} else if a, err := netip.ParseAddr(domain); err == nil {
		targetType = "IP"
		targetAddr = a.Unmap()
	}

	if groupName != "" {
		parentalStateMu.RLock()
		_, stateExists := groupStates[sk]
		parentalStateMu.RUnlock()

		if !stateExists {
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

			if sk == "" {
				if mode == "device" {
					sk = makeStateKey(groupName, deviceID, "device")
				} else {
					sk = groupName
				}
			}

			var needsLoad bool
			var newGs *groupState

			parentalStateMu.Lock()
			if _, existsNow := groupStates[sk]; !existsNow {
				if len(groupStates) >= 50000 {
					// [PERF/FIX] Employ power-of-N-choices sampled eviction targeting the 
					// absolute oldest inactive profiles dynamically. Definitively replaces 
					// the destructive 1000-element blind deletion which arbitrarily wiped 
					// active residential client budgets during saturation events organically.
					var oldestKey string
					var oldestTS time.Time
					var sampled int
					
					for evictKey, evictState := range groupStates {
						evictState.mu.Lock()
						ls := evictState.lastSeen["total"]
						evictState.mu.Unlock()
						
						if sampled == 0 || ls.Before(oldestTS) {
							oldestTS = ls
							oldestKey = evictKey
						}
						sampled++
						if sampled >= 64 {
							break
						}
					}
					
					if oldestKey != "" {
						delete(groupStates, oldestKey)
						delete(stateToGroup, oldestKey)
					}
				}

				gs := newGroupState(grpCfg)
				
				gs.mu.Lock()
				newGs = gs
				needsLoad = true
				
				stateToGroup[sk] = groupName
				groupStates[sk]  = gs
			}
			parentalStateMu.Unlock()
			
			if needsLoad {
				loadSnapshot(sk, newGs)
				newGs.mu.Unlock()
			}
		}
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

	isUntriggered := false
	var untriggerRemaining uint32
	var newlyActivated bool
	isUntriggerSource := false

	now := time.Now()

	if catConfigured && gs.hardUntrigger[cat] > 0 {
		isUntriggerSource = true
		if gs.untriggerUntil.IsZero() || now.After(gs.untriggerUntil) { 
			newlyActivated = true 
			gs.untriggerUntil = now.Add(gs.hardUntrigger[cat])
			if logParental {
				log.Printf("[PARENTAL] [%s] UNTRIGGER activated by category %q. Unblocking strict 'BLOCK' domains for %s", sk, cat, gs.hardUntrigger[cat])
			}
		}
	} else if !catConfigured && gs.hardUntrigger["total"] > 0 {
		isUntriggerSource = true
		if gs.untriggerUntil.IsZero() || now.After(gs.untriggerUntil) { 
			newlyActivated = true 
			gs.untriggerUntil = now.Add(gs.hardUntrigger["total"])
			if logParental {
				log.Printf("[PARENTAL] [%s] UNTRIGGER activated by 'total'. Unblocking strict 'BLOCK' domains for %s", sk, gs.hardUntrigger["total"])
			}
		}
	}

	if !gs.untriggerUntil.IsZero() {
		if now.Before(gs.untriggerUntil) {
			isUntriggered = true
			untriggerRemaining = uint32(gs.untriggerUntil.Sub(now).Seconds())
		}
	}

	bypassReason := ""
	if ov == "LOG" || (catConfigured && gs.hardLog[cat]) || (!catConfigured && gs.hardLog["total"]) {
		bypassReason = "LOG"
	} else if ov == "FREE" || (catConfigured && gs.hardFree[cat]) || (!catConfigured && gs.hardFree["total"]) {
		bypassReason = "FREE"
	} else if ov == "ALLOW" || (catConfigured && gs.hardAllowed[cat]) || (!catConfigured && gs.hardAllowed["total"]) {
		bypassReason = "ALLOW"
	} else if isUntriggerSource {
		if newlyActivated {
			bypassReason = "ACTIVATING_UNTRIGGER"
		} else {
			bypassReason = "UNTRIGGER_SOURCE"
		}
	} else if isUntriggered {
		bypassReason = "UNTRIGGER"
		
		if logParental {
			catStr := ""
			if cat != "" {
				catStr = " (Category: " + cat + ", match: " + matchedApex + ")"
			}
			log.Printf("[PARENTAL] [%s] UNTRIGGER actively bypassing blocks%s | client: %s | %s: %s",
				sk, catStr, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr)
		}
	}

	if bypassReason == "" {
		if catConfigured {
			if gs.hardBlocked[cat] {
				logBlockRateLimited(gs, sk, cat,
					fmt.Sprintf("[PARENTAL] [%s] Blocked: %q is BLOCK (match: %s) | client: %s | %s: %s",
						sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
				return true, btl, 0, "Blocked: " + cat + " (" + groupName + ")", cat, matchedApex
			}
		} else {
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
			if rem, limited := gs.remaining[cat]; limited {
				if rem <= 0 {
					logBlockRateLimited(gs, sk, cat,
						fmt.Sprintf("[PARENTAL] [%s] Blocked: %q budget exhausted (match: %s) | client: %s | %s: %s",
							sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr))
					return true, btl, 0, "Budget: " + cat + " (" + groupName + ")", cat, matchedApex
				}
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
		}
	}

	now = time.Now()
	gs.lastSeen["total"] = now
	
	if bypassReason == "" {
		gs.lastDeductibleSeen["total"] = now
	}
	
	if !gs.sessionActive["total"] {
		gs.sessionActive["total"] = true
		gs.lastProgressLog["total"] = now
		if logParental {
			log.Printf("[PARENTAL] [%s] Total screen-time session started | client: %s | remaining: %s",
				sk, buildClientID(clientIP, clientName, clientAddr), remainingStr(gs, "total"))
		}
	}
	if bypassReason == "" {
		if _, limited := gs.remaining["total"]; limited {
			checkBudgetWarning(gs, sk, "total")
		}
	}

	if cat != "" {
		gs.lastSeen[cat] = now
		if bypassReason == "" {
			gs.lastDeductibleSeen[cat] = now
		}
		if !gs.sessionActive[cat] {
			gs.sessionActive[cat] = true
			gs.lastProgressLog[cat] = now
			if logParental {
				log.Printf("[PARENTAL] [%s] Category %q session started | client: %s | remaining: %s",
					sk, cat, buildClientID(clientIP, clientName, clientAddr), remainingStr(gs, cat))
			}
		}
		if bypassReason == "" {
			if _, limited := gs.remaining[cat]; limited {
				checkBudgetWarning(gs, sk, cat)
			}
		}
	}

	if bypassReason == "LOG" && cat != "" {
		if logParental {
			log.Printf("[PARENTAL] [%s] PARENTAL LOG: %q (match: %s) | client: %s | %s: %s",
				sk, cat, matchedApex, buildClientID(clientIP, clientName, clientAddr), targetType, domainStr)
		}
	}

	forcedReturn := ftl
	if bypassReason == "ALLOW" {
		forcedReturn = 0 
	}

	if bypassReason == "UNTRIGGER" || bypassReason == "ACTIVATING_UNTRIGGER" || bypassReason == "UNTRIGGER_SOURCE" {
		if untriggerRemaining < forcedReturn || forcedReturn == 0 {
			if untriggerRemaining < 1 {
				untriggerRemaining = 1
			}
			forcedReturn = untriggerRemaining
		}
	}

	return false, 0, forcedReturn, bypassReason, cat, matchedApex
}

