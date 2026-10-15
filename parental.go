/*
File:    parental.go
Version: 3.45.0 (Split)
Last Updated: 15-Oct-2026 18:35 CEST

Description:
  Parental control hot-path runtime for sdproxy.

Changes:
  3.45.0 - [FIX] Passed `portStr` to `CheckParental` so `device` budget tracking mode
           can derive a valid `deviceID` (`port:<port>`) when a client is identified
           exclusively via a listener `port:` route.
  3.44.0 - [FIX] Normalized `rkIP`, `rkSNI`, and `rkPath` matching in `InitParental`
           and `ResolveStateKeyAndGroup` to handle unmapped IPv4-in-IPv6 addresses,
           case-insensitive `sni:`/`path:` prefixes, and root path `"/"` preservation.
  3.43.0 - [FEAT/FIX] Added support for `port:` and `force-and` compound routing
           in `InitParental` and `ResolveStateKeyAndGroup`. Previously, routes
           assigning a parental group via `port:` or `force-and` were silently
           ignored by the parental engine.
  3.42.0 - [SECURITY/FIX] Resolved a severe sampling eviction logic flaw within 
           `CheckParental`. `oldestTS` was instantiated as a `time.Time` zero-value, 
           preventing `ls.Before(oldestTS)` from ever correctly triggering organically.
           Power-of-N-Choices is now strictly evaluated against proper maximal boundaries natively.
           Additionally, corrected the bounds extraction to accurately map to the `TryLock` 
           closure.
  3.41.0 - [PERF/FIX] Eradicated severe Mutex lock contention and latency spikes 
           during emergency memory evictions natively. `CheckParental` now utilizes 
           `TryLock` organically when scanning group states during tracker saturation floods, 
           preventing active DNS requests from deadlocking the global admission pipeline.
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

type compoundGroupEntry struct {
	keys  []string
	group string
}

var (
	macToStateKey        map[string]string
	ipToStateKey         map[string]string
	cidrToGroup          []cidrGroupEntry
	macWildToGroup       []macWildGroupEntry
	nameToGroup          map[string]string
	sniToGroup           map[string]string
	pathToGroup          map[string]string
	portToGroup          map[string]string
	asnToGroup           map[string]string
	countryToGroup       map[string]string
	compoundToGroup      []compoundGroupEntry
	stateToGroup         map[string]string
	groupStates          map[string]*groupState
	parentalStateMu      sync.RWMutex
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
	compoundToGroup = nil

	type groupInfo struct {
		macs      []string
		macGlobs  []string
		ips       []string
		cidrs     []netip.Prefix
		names     []string
		snis      []string
		paths     []string
		ports     []string
		asns      []string
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

		var validKeys []string
		for _, key := range strings.Split(rawKey, ",") {
			key = strings.TrimSpace(key)
			if key != "" {
				validKeys = append(validKeys, key)
			}
		}
		if len(validKeys) == 0 {
			return
		}

		if route.ForceAnd && len(validKeys) > 1 {
			ParentalGroupClients[route.Group]++
			compoundToGroup = append(compoundToGroup, compoundGroupEntry{
				keys:  validKeys,
				group: route.Group,
			})
			return
		}

		for _, key := range validKeys {
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
				info.snis = append(info.snis, lowerTrimDot(strings.TrimPrefix(strings.ToLower(key), "sni:")))
			case rkPath:
				p := strings.ToLower(key)
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimPrefix(p, "path:")
				}
				if len(p) > 1 {
					p = strings.TrimSuffix(p, "/")
				}
				info.paths = append(info.paths, p)
			case rkPort:
				if p, ok := parsePort(key); ok {
					info.ports = append(info.ports, p)
				}
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

	macToStateKey = make(map[string]string)
	ipToStateKey = make(map[string]string)
	stateToGroup = make(map[string]string)
	groupStates = make(map[string]*groupState)
	nameToGroup = make(map[string]string)
	sniToGroup = make(map[string]string)
	pathToGroup = make(map[string]string)
	portToGroup = make(map[string]string)
	asnToGroup = make(map[string]string)
	countryToGroup = make(map[string]string)
	macWildToGroup = nil
	cidrToGroup = nil

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
			for _, p := range info.ports {
				portToGroup[p] = name
			}
			for _, a := range info.asns {
				asnToGroup[a] = name
			}
			for _, c := range info.countries {
				countryToGroup[c] = name
			}
			if logParental {
				log.Printf("[PARENTAL] Group %q: device tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d Port, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.ports), len(info.asns), len(info.countries))
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
			for _, p := range info.ports {
				portToGroup[p] = name
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
				log.Printf("[PARENTAL] Group %q: group tracking — %d MAC, %d Glob, %d IP, %d CIDR, %d Name, %d SNI, %d Path, %d Port, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ips), len(info.cidrs), len(info.names), len(info.snis), len(info.paths), len(info.ports), len(info.asns), len(info.countries))
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

func ResolveStateKeyAndGroup(clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientNameLower, sni, sniLower, path, pathLower, portStr string) (string, string) {
	parentalStateMu.RLock()
	defer parentalStateMu.RUnlock()

	var sk, groupName string

	cleanPath := pathLower
	if len(cleanPath) > 1 {
		cleanPath = strings.TrimSuffix(cleanPath, "/")
	}
	cleanSNI := lowerTrimDot(sniLower)

	// 0. Compound (ForceAnd) group mappings
	for _, cg := range compoundToGroup {
		allMatched := true
		for _, rawKey := range cg.keys {
			keyMatched := false
			switch classifyRouteKey(rawKey) {
			case rkMAC:
				keyMatched = clientMAC != "" && strings.EqualFold(clientMAC, rawKey)
			case rkMACGlob:
				keyMatched = clientMAC != "" && matchMACGlob(normaliseMACGlob(rawKey), clientMAC)
			case rkIP:
				if clientAddr.IsValid() {
					if ip, err := netip.ParseAddr(rawKey); err == nil && ip.Unmap() == clientAddr {
						keyMatched = true
					}
				}
			case rkCIDR:
				if clientAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(rawKey); err == nil && prefix.Contains(clientAddr) {
						keyMatched = true
					}
				}
			case rkASN:
				if clientAddr.IsValid() {
					if asn, _, _ := LookupASNDetails(clientAddr); asn != "" && strings.EqualFold(asn, rawKey) {
						keyMatched = true
					}
				}
			case rkCountry:
				if clientAddr.IsValid() {
					if _, _, country := LookupASNDetails(clientAddr); country != "" {
						cc := strings.TrimPrefix(strings.ToUpper(rawKey), "CC:")
						keyMatched = strings.EqualFold(country, cc)
					}
				}
			case rkClientName:
				keyMatched = clientNameLower != "" && clientNameLower == strings.ToLower(rawKey)
			case rkSNI:
				keyMatched = cleanSNI != "" && cleanSNI == lowerTrimDot(strings.TrimPrefix(strings.ToLower(rawKey), "sni:"))
			case rkPath:
				if cleanPath != "" {
					p := strings.ToLower(rawKey)
					if strings.HasPrefix(p, "path:") {
						p = strings.TrimPrefix(p, "path:")
					}
					if len(p) > 1 {
						p = strings.TrimSuffix(p, "/")
					}
					keyMatched = cleanPath == p
				}
			case rkPort:
				if portStr != "" {
					if p, ok := parsePort(rawKey); ok && p == portStr {
						keyMatched = true
					}
				}
			}
			if !keyMatched {
				allMatched = false
				break
			}
		}
		if allMatched {
			groupName = cg.group
			break
		}
	}

	if groupName == "" && clientMAC != "" {
		if stKey, ok := macToStateKey[clientMAC]; ok {
			sk = stKey
		}
	}
	if sk == "" && groupName == "" && clientMAC != "" {
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
	if sk == "" && groupName == "" && cleanSNI != "" {
		if gName, ok := sniToGroup[cleanSNI]; ok {
			groupName = gName
		}
	}
	if sk == "" && groupName == "" && cleanPath != "" {
		if gName, ok := pathToGroup[cleanPath]; ok {
			groupName = gName
		}
	}
	if sk == "" && groupName == "" && portStr != "" {
		if gName, ok := portToGroup[portStr]; ok {
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
				} else if portStr != "" {
					deviceID = "port:" + portStr
				}
				sk = makeStateKey(groupName, deviceID, "device")
			} else {
				sk = groupName
			}
		}
	}

	return sk, groupName
}

func CheckParental(sk, groupName, clientMAC, clientIP string, clientAddr netip.Addr, clientName, clientNameLower, sni, sniLower, path, pathLower, portStr, domain string, targetAddr netip.Addr, silentStats bool, bypassPolicies bool) (blocked bool, blockTTL, forcedTTL uint32, reason string, category string, matchedApex string) {
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
				} else if portStr != "" {
					deviceID = "port:" + portStr
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
					var oldestKey string
					oldestTS := time.Now().Add(time.Hour * 87600)
					var sampled int
					var found bool

					for evictKey, evictState := range groupStates {
						if evictState.mu.TryLock() {
							ls := evictState.lastSeen["total"]
							evictState.mu.Unlock()

							if !found || ls.Before(oldestTS) {
								oldestTS = ls
								oldestKey = evictKey
								found = true
							}
							sampled++
						}

						if sampled >= 64 {
							break
						}
					}

					if found && oldestKey != "" {
						delete(groupStates, oldestKey)
						delete(stateToGroup, oldestKey)
					}
				}

				gs := newGroupState(grpCfg)

				gs.mu.Lock()
				newGs = gs
				needsLoad = true

				stateToGroup[sk] = groupName
				groupStates[sk] = gs
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
	gs := groupStates[sk]
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

	gs.lastClientIP = clientIP
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
