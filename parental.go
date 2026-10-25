/*
File:    parental.go
Version: 3.51.0 (Split)
Last Updated: 22-Oct-2026 14:15 CEST

Description:
  Parental control hot-path runtime for sdproxy.

Changes:
  3.51.0 - [FIX] Preserved the exact matched identifier (`matchedDeviceID`) in
           `ResolveStateKeyAndGroup` across all route types (`CLIENT-NAME`, `SNI`,
           `PATH`, `PORT`, `ASN`, `COUNTRY`, `MAC`, `EDNS-MAC`, `IP`, `CIDR`, `ECS`)
           and added a `force` priority tier matching `resolveClientRoute` so
           `force: true` routes with a `group:` assignment take precedence over
           standard routes and `device` budget tracking keys match the winning rule.
  3.50.0 - [FIX] Preserved the matched route origin (`matchedEDNSMAC`, `matchedECS`)
           when constructing `deviceID` in `ResolveStateKeyAndGroup` and `CheckParental`
           so a query carrying an EDNS0 Option 65001 MAC (`ednsMAC`) or ECS IP
           (`ecsAddr`) alongside a physical router/forwarder IP (`clientIP`) or
           ARP MAC (`clientMAC`) isolates its `device` budget per EDNS0 MAC or
           ECS client rather than collapsing all forwarded clients onto the
           forwarder's `clientMAC`/`clientIP`.
  3.49.0 - [FEAT] Added `ednsMACToStateKey` and `ednsMACWildToGroup` in `InitParental`,
           `ResolveStateKeyAndGroup`, and `CheckParental` to support assigning
           parental control groups and device-level budgets via EDNS0 Option 65001
           (`mac:<mac>` and `mac:<mac-glob>`) routes.
  3.48.0 - [FIX] Skipped `rkInvalid` route keys in `InitParental` so malformed
           `ecs:`, `port:`, `sni:`, and `path:` keys do not inflate
           `ParentalGroupClients` or register bogus compound group rules.
         - [FIX] Normalized `sni:` and `path:` keys with `strings.TrimSpace`
           and leading `/` enforcement in `InitParental` and `ResolveStateKeyAndGroup`.
  3.47.0 - [FIX] Passed `ecsAddr` into `CheckParental` so `device` budget tracking
           mode derives `ecs:<ip>` as `deviceID` consistently with
           `ResolveStateKeyAndGroup` when a client is matched via an `ecs:` route.
  3.46.0 - [FEAT] Added `ecsIPToStateKey` and `ecsCIDRToGroup` in `InitParental`,
           `ResolveStateKeyAndGroup`, and `CheckParental`.
  3.45.0 - [FIX] Passed `portStr` to `CheckParental` so `device` budget tracking mode
           can derive a valid `deviceID` (`port:<port>`).
  3.44.0 - [FIX] Normalized `rkIP`, `rkSNI`, and `rkPath` matching in `InitParental`
           and `ResolveStateKeyAndGroup`.
  3.43.0 - [FEAT/FIX] Added support for `port:` and `force-and` compound routing
           in `InitParental` and `ResolveStateKeyAndGroup`.
  3.42.0 - [SECURITY/FIX] Resolved a severe sampling eviction logic flaw within 
           `CheckParental`.
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
	lastDeductibleSeen map[string]time.Time
	remaining          map[string]int64
	warnedThresholds   map[string]bool
	lastBlockLog       map[string]time.Time
	sessionActive      map[string]bool
	lastProgressLog    map[string]time.Time

	hardBlocked   map[string]bool
	hardAllowed   map[string]bool
	hardFree      map[string]bool
	hardLog       map[string]bool
	hardUntrigger map[string]time.Duration

	untriggerUntil time.Time

	lastClientIP   string
	lastClientName string
}

type parentalKeyTarget struct {
	sk    string
	group string
	force bool
}

type cidrGroupEntry struct {
	net   netip.Prefix
	group string
	force bool
}

type macWildGroupEntry struct {
	pattern string
	group   string
	force   bool
}

type compoundGroupEntry struct {
	keys  []string
	group string
	force bool
}

var (
	macToStateKey        map[string]parentalKeyTarget
	ednsMACToStateKey    map[string]parentalKeyTarget
	ipToStateKey         map[string]parentalKeyTarget
	ecsIPToStateKey      map[string]parentalKeyTarget
	cidrToGroup          []cidrGroupEntry
	ecsCIDRToGroup       []cidrGroupEntry
	macWildToGroup       []macWildGroupEntry
	ednsMACWildToGroup   []macWildGroupEntry
	nameToGroup          map[string]parentalKeyTarget
	sniToGroup           map[string]parentalKeyTarget
	pathToGroup          map[string]parentalKeyTarget
	portToGroup          map[string]parentalKeyTarget
	asnToGroup           map[string]parentalKeyTarget
	countryToGroup       map[string]parentalKeyTarget
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

	type strForce struct {
		val   string
		force bool
	}
	type prefixForce struct {
		net   netip.Prefix
		force bool
	}

	type groupInfo struct {
		macs         []strForce
		macGlobs     []strForce
		ednsMACs     []strForce
		ednsMACGlobs []strForce
		ips          []strForce
		cidrs        []prefixForce
		ecsIPs       []strForce
		ecsCIDRs     []prefixForce
		names        []strForce
		snis         []strForce
		paths        []strForce
		ports        []strForce
		asns         []strForce
		countries    []strForce
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
			if key == "" {
				continue
			}
			if classifyRouteKey(key) == rkInvalid {
				if logParental {
					log.Printf("[WARN] parental: invalid route key %q for group %q — skipped", key, route.Group)
				}
				if route.ForceAnd {
					return
				}
				continue
			}
			validKeys = append(validKeys, key)
		}
		if len(validKeys) == 0 {
			return
		}

		if route.ForceAnd && len(validKeys) > 1 {
			ParentalGroupClients[route.Group]++
			compoundToGroup = append(compoundToGroup, compoundGroupEntry{
				keys:  validKeys,
				group: route.Group,
				force: route.Force,
			})
			return
		}

		for _, key := range validKeys {
			ParentalGroupClients[route.Group]++

			switch classifyRouteKey(key) {
			case rkMAC:
				if mac, err := net.ParseMAC(key); err == nil {
					info.macs = append(info.macs, strForce{mac.String(), route.Force})
				}
			case rkMACGlob:
				info.macGlobs = append(info.macGlobs, strForce{normaliseMACGlob(key), route.Force})
			case rkEDNSMAC:
				if mac, err := net.ParseMAC(parseMACKey(key)); err == nil {
					info.ednsMACs = append(info.ednsMACs, strForce{mac.String(), route.Force})
				}
			case rkEDNSMACGlob:
				info.ednsMACGlobs = append(info.ednsMACGlobs, strForce{normaliseMACGlob(parseMACKey(key)), route.Force})
			case rkIP:
				if ip, err := netip.ParseAddr(key); err == nil {
					info.ips = append(info.ips, strForce{ip.Unmap().String(), route.Force})
				}
			case rkCIDR:
				if prefix, err := ParsePrefixUnmapped(key); err == nil {
					info.cidrs = append(info.cidrs, prefixForce{prefix.Masked(), route.Force})
				}
			case rkECSIP:
				if ip, err := netip.ParseAddr(parseECSKey(key)); err == nil {
					info.ecsIPs = append(info.ecsIPs, strForce{ip.Unmap().String(), route.Force})
				}
			case rkECSCIDR:
				if prefix, err := ParsePrefixUnmapped(parseECSKey(key)); err == nil {
					info.ecsCIDRs = append(info.ecsCIDRs, prefixForce{prefix.Masked(), route.Force})
				}
			case rkClientName:
				info.names = append(info.names, strForce{strings.ToLower(key), route.Force})
			case rkSNI:
				info.snis = append(info.snis, strForce{lowerTrimDot(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(key), "sni:"))), route.Force})
			case rkPath:
				p := strings.ToLower(key)
				if strings.HasPrefix(p, "path:") {
					p = strings.TrimSpace(strings.TrimPrefix(p, "path:"))
				}
				if p != "" && p[0] != '/' {
					p = "/" + p
				}
				if len(p) > 1 {
					p = strings.TrimSuffix(p, "/")
				}
				info.paths = append(info.paths, strForce{p, route.Force})
			case rkPort:
				if p, ok := parsePort(key); ok {
					info.ports = append(info.ports, strForce{p, route.Force})
				}
			case rkASN:
				info.asns = append(info.asns, strForce{strings.ToUpper(key), route.Force})
			case rkCountry:
				info.countries = append(info.countries, strForce{strings.ToUpper(strings.TrimPrefix(strings.ToUpper(key), "CC:")), route.Force})
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

	macToStateKey = make(map[string]parentalKeyTarget)
	ednsMACToStateKey = make(map[string]parentalKeyTarget)
	ipToStateKey = make(map[string]parentalKeyTarget)
	ecsIPToStateKey = make(map[string]parentalKeyTarget)
	stateToGroup = make(map[string]string)
	groupStates = make(map[string]*groupState)
	nameToGroup = make(map[string]parentalKeyTarget)
	sniToGroup = make(map[string]parentalKeyTarget)
	pathToGroup = make(map[string]parentalKeyTarget)
	portToGroup = make(map[string]parentalKeyTarget)
	asnToGroup = make(map[string]parentalKeyTarget)
	countryToGroup = make(map[string]parentalKeyTarget)
	macWildToGroup = nil
	ednsMACWildToGroup = nil
	cidrToGroup = nil
	ecsCIDRToGroup = nil

	for name, grp := range cfg.Groups {
		info := groups[name]
		mode := strings.ToLower(grp.BudgetTracking)

		if mode == "device" {
			for _, mac := range info.macs {
				sk := makeStateKey(name, mac.val, "device")
				macToStateKey[mac.val] = parentalKeyTarget{sk: sk, group: name, force: mac.force}
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs

				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
			}
			for _, ednsMAC := range info.ednsMACs {
				sk := makeStateKey(name, "mac:"+ednsMAC.val, "device")
				ednsMACToStateKey[ednsMAC.val] = parentalKeyTarget{sk: sk, group: name, force: ednsMAC.force}
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs

				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
			}
			for _, ip := range info.ips {
				sk := makeStateKey(name, ip.val, "device")
				ipToStateKey[ip.val] = parentalKeyTarget{sk: sk, group: name, force: ip.force}
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs

				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
			}
			for _, ecsIP := range info.ecsIPs {
				sk := makeStateKey(name, "ecs:"+ecsIP.val, "device")
				ecsIPToStateKey[ecsIP.val] = parentalKeyTarget{sk: sk, group: name, force: ecsIP.force}
				stateToGroup[sk] = name
				gs := newGroupState(grp)
				groupStates[sk] = gs

				gs.mu.Lock()
				loadSnapshot(sk, gs)
				gs.mu.Unlock()
			}
			for _, prefix := range info.cidrs {
				cidrToGroup = append(cidrToGroup, cidrGroupEntry{net: prefix.net, group: name, force: prefix.force})
			}
			for _, prefix := range info.ecsCIDRs {
				ecsCIDRToGroup = append(ecsCIDRToGroup, cidrGroupEntry{net: prefix.net, group: name, force: prefix.force})
			}
			for _, pat := range info.macGlobs {
				macWildToGroup = append(macWildToGroup, macWildGroupEntry{pattern: pat.val, group: name, force: pat.force})
			}
			for _, pat := range info.ednsMACGlobs {
				ednsMACWildToGroup = append(ednsMACWildToGroup, macWildGroupEntry{pattern: pat.val, group: name, force: pat.force})
			}
			for _, n := range info.names {
				nameToGroup[n.val] = parentalKeyTarget{group: name, force: n.force}
			}
			for _, s := range info.snis {
				sniToGroup[s.val] = parentalKeyTarget{group: name, force: s.force}
			}
			for _, p := range info.paths {
				pathToGroup[p.val] = parentalKeyTarget{group: name, force: p.force}
			}
			for _, p := range info.ports {
				portToGroup[p.val] = parentalKeyTarget{group: name, force: p.force}
			}
			for _, a := range info.asns {
				asnToGroup[a.val] = parentalKeyTarget{group: name, force: a.force}
			}
			for _, c := range info.countries {
				countryToGroup[c.val] = parentalKeyTarget{group: name, force: c.force}
			}
			if logParental {
				log.Printf("[PARENTAL] Group %q: device tracking — %d MAC, %d Glob, %d EDNS-MAC, %d EDNS-Glob, %d IP, %d CIDR, %d ECS-IP, %d ECS-CIDR, %d Name, %d SNI, %d Path, %d Port, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ednsMACs), len(info.ednsMACGlobs), len(info.ips), len(info.cidrs), len(info.ecsIPs), len(info.ecsCIDRs), len(info.names), len(info.snis), len(info.paths), len(info.ports), len(info.asns), len(info.countries))
			}
		} else {
			sk := name
			for _, mac := range info.macs {
				macToStateKey[mac.val] = parentalKeyTarget{sk: sk, group: name, force: mac.force}
			}
			for _, ednsMAC := range info.ednsMACs {
				ednsMACToStateKey[ednsMAC.val] = parentalKeyTarget{sk: sk, group: name, force: ednsMAC.force}
			}
			for _, ip := range info.ips {
				ipToStateKey[ip.val] = parentalKeyTarget{sk: sk, group: name, force: ip.force}
			}
			for _, ecsIP := range info.ecsIPs {
				ecsIPToStateKey[ecsIP.val] = parentalKeyTarget{sk: sk, group: name, force: ecsIP.force}
			}
			for _, prefix := range info.cidrs {
				cidrToGroup = append(cidrToGroup, cidrGroupEntry{net: prefix.net, group: name, force: prefix.force})
			}
			for _, prefix := range info.ecsCIDRs {
				ecsCIDRToGroup = append(ecsCIDRToGroup, cidrGroupEntry{net: prefix.net, group: name, force: prefix.force})
			}
			for _, pat := range info.macGlobs {
				macWildToGroup = append(macWildToGroup, macWildGroupEntry{pattern: pat.val, group: name, force: pat.force})
			}
			for _, pat := range info.ednsMACGlobs {
				ednsMACWildToGroup = append(ednsMACWildToGroup, macWildGroupEntry{pattern: pat.val, group: name, force: pat.force})
			}
			for _, n := range info.names {
				nameToGroup[n.val] = parentalKeyTarget{sk: sk, group: name, force: n.force}
			}
			for _, s := range info.snis {
				sniToGroup[s.val] = parentalKeyTarget{sk: sk, group: name, force: s.force}
			}
			for _, p := range info.paths {
				pathToGroup[p.val] = parentalKeyTarget{sk: sk, group: name, force: p.force}
			}
			for _, p := range info.ports {
				portToGroup[p.val] = parentalKeyTarget{sk: sk, group: name, force: p.force}
			}
			for _, a := range info.asns {
				asnToGroup[a.val] = parentalKeyTarget{sk: sk, group: name, force: a.force}
			}
			for _, c := range info.countries {
				countryToGroup[c.val] = parentalKeyTarget{sk: sk, group: name, force: c.force}
			}
			stateToGroup[sk] = name
			gs := newGroupState(grp)
			groupStates[sk] = gs

			gs.mu.Lock()
			loadSnapshot(sk, gs)
			gs.mu.Unlock()

			if logParental {
				log.Printf("[PARENTAL] Group %q: group tracking — %d MAC, %d Glob, %d EDNS-MAC, %d EDNS-Glob, %d IP, %d CIDR, %d ECS-IP, %d ECS-CIDR, %d Name, %d SNI, %d Path, %d Port, %d ASN, %d Country",
					name, len(info.macs), len(info.macGlobs), len(info.ednsMACs), len(info.ednsMACGlobs), len(info.ips), len(info.cidrs), len(info.ecsIPs), len(info.ecsCIDRs), len(info.names), len(info.snis), len(info.paths), len(info.ports), len(info.asns), len(info.countries))
			}
		}
	}

	if len(cidrToGroup) > 0 {
		sort.SliceStable(cidrToGroup, func(i, j int) bool {
			return cidrToGroup[i].net.Bits() > cidrToGroup[j].net.Bits()
		})
	}
	if len(ecsCIDRToGroup) > 0 {
		sort.SliceStable(ecsCIDRToGroup, func(i, j int) bool {
			return ecsCIDRToGroup[i].net.Bits() > ecsCIDRToGroup[j].net.Bits()
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

func ResolveStateKeyAndGroup(clientMAC, ednsMAC, clientIP string, clientAddr, ecsAddr netip.Addr, ecsPrefix netip.Prefix, clientName, clientNameLower, sni, sniLower, path, pathLower, portStr string) (string, string) {
	parentalStateMu.RLock()
	defer parentalStateMu.RUnlock()

	var normalSK, normalGroup, normalDevID string
	var normalMatched bool

	recordMatch := func(sk, grp, devID string, force bool) (string, string, string, bool) {
		if force {
			return sk, grp, devID, true
		}
		if !normalMatched {
			normalSK, normalGroup, normalDevID, normalMatched = sk, grp, devID, true
		}
		return "", "", "", false
	}

	cleanPath := pathLower
	if len(cleanPath) > 1 {
		cleanPath = strings.TrimSuffix(cleanPath, "/")
	}
	cleanSNI := lowerTrimDot(sniLower)

	var sk, groupName, matchedDevID string
	var forced bool

	// 0. Compound (ForceAnd) group mappings
	for _, cg := range compoundToGroup {
		allMatched := true
		var compDevID string
		for _, rawKey := range cg.keys {
			keyMatched := false
			switch classifyRouteKey(rawKey) {
			case rkMAC:
				if clientMAC != "" && strings.EqualFold(clientMAC, rawKey) {
					keyMatched = true
					if compDevID == "" {
						compDevID = clientMAC
					}
				}
			case rkMACGlob:
				if clientMAC != "" && matchMACGlob(normaliseMACGlob(rawKey), clientMAC) {
					keyMatched = true
					if compDevID == "" {
						compDevID = clientMAC
					}
				}
			case rkEDNSMAC:
				if ednsMAC != "" && strings.EqualFold(ednsMAC, parseMACKey(rawKey)) {
					keyMatched = true
					if compDevID == "" {
						compDevID = "mac:" + ednsMAC
					}
				}
			case rkEDNSMACGlob:
				if ednsMAC != "" && matchMACGlob(normaliseMACGlob(parseMACKey(rawKey)), ednsMAC) {
					keyMatched = true
					if compDevID == "" {
						compDevID = "mac:" + ednsMAC
					}
				}
			case rkIP:
				if clientAddr.IsValid() {
					if ip, err := netip.ParseAddr(rawKey); err == nil && ip.Unmap() == clientAddr {
						keyMatched = true
						if compDevID == "" {
							compDevID = clientIP
						}
					}
				}
			case rkCIDR:
				if clientAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(rawKey); err == nil && prefix.Contains(clientAddr) {
						keyMatched = true
						if compDevID == "" {
							compDevID = clientIP
						}
					}
				}
			case rkECSIP:
				if ecsAddr.IsValid() {
					if ip, err := netip.ParseAddr(parseECSKey(rawKey)); err == nil && ip.Unmap() == ecsAddr {
						keyMatched = true
						if compDevID == "" {
							compDevID = "ecs:" + ecsAddr.String()
						}
					}
				}
			case rkECSCIDR:
				if ecsAddr.IsValid() {
					if prefix, err := ParsePrefixUnmapped(parseECSKey(rawKey)); err == nil && matchECSCIDR(prefix.Masked(), ecsPrefix, ecsAddr) {
						keyMatched = true
						if compDevID == "" {
							compDevID = "ecs:" + ecsAddr.String()
						}
					}
				}
			case rkASN:
				if clientAddr.IsValid() {
					if asn, _, _ := LookupASNDetails(clientAddr); asn != "" && strings.EqualFold(asn, rawKey) {
						keyMatched = true
						if compDevID == "" {
							compDevID = clientIP
						}
					}
				}
			case rkCountry:
				if clientAddr.IsValid() {
					if _, _, country := LookupASNDetails(clientAddr); country != "" {
						cc := strings.TrimPrefix(strings.ToUpper(rawKey), "CC:")
						if strings.EqualFold(country, cc) {
							keyMatched = true
							if compDevID == "" {
								compDevID = clientIP
							}
						}
					}
				}
			case rkClientName:
				if clientNameLower != "" && clientNameLower == strings.ToLower(rawKey) {
					keyMatched = true
					if compDevID == "" {
						compDevID = clientName
					}
				}
			case rkSNI:
				if cleanSNI != "" && cleanSNI == lowerTrimDot(strings.TrimSpace(strings.TrimPrefix(strings.ToLower(rawKey), "sni:"))) {
					keyMatched = true
					if compDevID == "" {
						compDevID = "sni:" + cleanSNI
					}
				}
			case rkPath:
				if cleanPath != "" {
					p := strings.ToLower(rawKey)
					if strings.HasPrefix(p, "path:") {
						p = strings.TrimSpace(strings.TrimPrefix(p, "path:"))
					}
					if p != "" && p[0] != '/' {
						p = "/" + p
					}
					if len(p) > 1 {
						p = strings.TrimSuffix(p, "/")
					}
					if cleanPath == p {
						keyMatched = true
						if compDevID == "" {
							compDevID = "path:" + cleanPath
						}
					}
				}
			case rkPort:
				if portStr != "" {
					if p, ok := parsePort(rawKey); ok && p == portStr {
						keyMatched = true
						if compDevID == "" {
							compDevID = "port:" + portStr
						}
					}
				}
			}
			if !keyMatched {
				allMatched = false
				break
			}
		}
		if allMatched {
			if sk, groupName, matchedDevID, forced = recordMatch("", cg.group, compDevID, cg.force); forced {
				break
			}
		}
	}

	if !forced && clientMAC != "" {
		if t, ok := macToStateKey[clientMAC]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, clientMAC, t.force)
		}
	}
	if !forced && clientMAC != "" {
		for _, wg := range macWildToGroup {
			if matchMACGlob(wg.pattern, clientMAC) {
				if sk, groupName, matchedDevID, forced = recordMatch("", wg.group, clientMAC, wg.force); forced {
					break
				}
				if !wg.force {
					break
				}
			}
		}
	}
	if !forced && ednsMAC != "" && len(ednsMACToStateKey) > 0 {
		if t, ok := ednsMACToStateKey[ednsMAC]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, "mac:"+ednsMAC, t.force)
		}
	}
	if !forced && ednsMAC != "" && len(ednsMACWildToGroup) > 0 {
		for _, wg := range ednsMACWildToGroup {
			if matchMACGlob(wg.pattern, ednsMAC) {
				if sk, groupName, matchedDevID, forced = recordMatch("", wg.group, "mac:"+ednsMAC, wg.force); forced {
					break
				}
				if !wg.force {
					break
				}
			}
		}
	}
	if !forced && clientIP != "" {
		if t, ok := ipToStateKey[clientIP]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, clientIP, t.force)
		}
	}
	if !forced && clientAddr.IsValid() && len(cidrToGroup) > 0 {
		for _, cr := range cidrToGroup {
			if cr.net.Contains(clientAddr) {
				if sk, groupName, matchedDevID, forced = recordMatch("", cr.group, clientIP, cr.force); forced {
					break
				}
				if !cr.force {
					break
				}
			}
		}
	}
	if !forced && ecsAddr.IsValid() && len(ecsIPToStateKey) > 0 {
		if t, ok := ecsIPToStateKey[ecsAddr.String()]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, "ecs:"+ecsAddr.String(), t.force)
		}
	}
	if !forced && ecsAddr.IsValid() && len(ecsCIDRToGroup) > 0 {
		for _, cr := range ecsCIDRToGroup {
			if matchECSCIDR(cr.net, ecsPrefix, ecsAddr) {
				if sk, groupName, matchedDevID, forced = recordMatch("", cr.group, "ecs:"+ecsAddr.String(), cr.force); forced {
					break
				}
				if !cr.force {
					break
				}
			}
		}
	}
	if !forced && clientAddr.IsValid() && (len(asnToGroup) > 0 || len(countryToGroup) > 0) {
		if asn, _, country := LookupASNDetails(clientAddr); asn != "" || country != "" {
			if asn != "" {
				if t, ok := asnToGroup[asn]; ok {
					sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, clientIP, t.force)
				}
			}
			if !forced && country != "" {
				if t, ok := countryToGroup[strings.ToUpper(country)]; ok {
					sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, clientIP, t.force)
				}
			}
		}
	}
	if !forced && clientNameLower != "" {
		if t, ok := nameToGroup[clientNameLower]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, clientName, t.force)
		}
	}
	if !forced && cleanSNI != "" {
		if t, ok := sniToGroup[cleanSNI]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, "sni:"+cleanSNI, t.force)
		}
	}
	if !forced && cleanPath != "" {
		if t, ok := pathToGroup[cleanPath]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, "path:"+cleanPath, t.force)
		}
	}
	if !forced && portStr != "" {
		if t, ok := portToGroup[portStr]; ok {
			sk, groupName, matchedDevID, forced = recordMatch(t.sk, t.group, "port:"+portStr, t.force)
		}
	}

	if !forced && normalMatched {
		sk, groupName, matchedDevID = normalSK, normalGroup, normalDevID
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
				deviceID := matchedDevID
				if deviceID == "" {
					if clientMAC != "" {
						deviceID = clientMAC
					} else if ednsMAC != "" {
						deviceID = "mac:" + ednsMAC
					} else if clientIP != "" {
						deviceID = clientIP
					} else if ecsAddr.IsValid() {
						deviceID = "ecs:" + ecsAddr.String()
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
				sk = makeStateKey(groupName, deviceID, "device")
			} else {
				sk = groupName
			}
		}
	}

	return sk, groupName
}

func CheckParental(sk, groupName, clientMAC, ednsMAC, clientIP string, clientAddr, ecsAddr netip.Addr, clientName, clientNameLower, sni, sniLower, path, pathLower, portStr, domain string, targetAddr netip.Addr, silentStats bool, bypassPolicies bool) (blocked bool, blockTTL, forcedTTL uint32, reason string, category string, matchedApex string) {
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

			if sk == "" {
				deviceID := clientIP
				if mode == "device" {
					if clientMAC != "" {
						deviceID = clientMAC
					} else if ednsMAC != "" {
						deviceID = "mac:" + ednsMAC
					} else if clientIP != "" {
						deviceID = clientIP
					} else if ecsAddr.IsValid() {
						deviceID = "ecs:" + ecsAddr.String()
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
