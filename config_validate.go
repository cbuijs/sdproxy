/*
File:    config_validate.go
Version: 1.2.0 (Split)
Last Updated: 24-Nov-2026 12:30 CET

Description:
  Strict fail-closed configuration validation and default normalization
  executed at startup and during `--test` CLI runs.

Changes:
  1.2.0 - [SECURITY/FIX] Validated `server.ddr.hostnames` entries as RFC-valid
          domain names (non-IP, non-wildcard QNAMEs) and rejected negative
          `identity.poll_interval` values in `validateConfig`.
        - [SECURITY/FIX] Validated `?ech=<base64>` (via `decodeBase64Flex` and
          `extractECHConfigs`) and `?echdomain=<domain>` (via `isValidQNAME`) in
          `validateUpstreamURLSyntax`.
  1.1.0 - [SECURITY/FIX] Failed closed in `validateConfig` when `webui.enabled`
          is true with an empty `webui.password`, or when `groups.<g>.budget`,
          `routes[*].group`, or any `upstream` reference points to a non-existent
          category, parental group, or upstream group.
        - [FIX] Defaulted `rate_limit.max_tracked_ips` (1000) and
          `exfiltration.max_tracked_ips` (50000) when enabled and unset, fixed
          portless bracketed IPv6 bootstrap handling in `validateUpstreamURLSyntax`,
          and validated `doh://` / `https://` / `doh3://` URLs via `url.Parse`.
  1.0.0 - [REFACTOR] Extracted `validateConfig` and validation helpers from
          `config.go`.
*/

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Validation Helpers
// ---------------------------------------------------------------------------

func validateSecurityAction(field, raw, defaultAct string) (string, error) {
	act := strings.ToUpper(strings.TrimSpace(raw))
	if act == "" {
		return defaultAct, nil
	}
	switch act {
	case "BLOCK", "DROP", "LOG":
		return act, nil
	default:
		if _, ok := dns.StringToRcode[act]; !ok {
			return "", fmt.Errorf("%s %q must be 'BLOCK', 'DROP', 'LOG', or a valid DNS RCODE", field, raw)
		}
		return act, nil
	}
}

func validatePolicyActionStr(field, raw string) error {
	act := strings.ToUpper(strings.TrimSpace(raw))
	switch act {
	case "BLOCK", "DROP":
		return nil
	default:
		if _, ok := dns.StringToRcode[act]; !ok {
			return fmt.Errorf("%s %q must be 'BLOCK', 'DROP', or a valid DNS RCODE", field, raw)
		}
		return nil
	}
}

func validateListenAddrs(field string, addrs []string) error {
	for _, raw := range addrs {
		a := strings.TrimSpace(raw)
		if a == "" {
			return fmt.Errorf("%s contains an empty listener address", field)
		}
		_, portStr, err := net.SplitHostPort(a)
		if err != nil {
			return fmt.Errorf("%s %q must be in host:port format: %w", field, raw, err)
		}
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("%s %q has invalid port %q", field, raw, portStr)
		}
	}
	return nil
}

func validatePrefixEntries(field string, entries []string) error {
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if _, err := netip.ParseAddr(s); err != nil {
				return fmt.Errorf("%s: invalid IP address %q: %w", field, raw, err)
			}
			continue
		}
		if _, err := ParsePrefixUnmapped(s); err != nil {
			return fmt.Errorf("%s: invalid CIDR prefix %q: %w", field, raw, err)
		}
	}
	return nil
}

func validateOptionalDuration(field, raw string, allowZero bool) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil
	}
	if allowZero && (s == "0" || s == "0s") {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		if allowZero {
			return fmt.Errorf("%s %q must be a positive duration or 0s", field, raw)
		}
		return fmt.Errorf("%s %q must be a positive duration", field, raw)
	}
	return nil
}

func validateUpstreamURLSyntax(field, raw string, requireBootstrapIP bool) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		if requireBootstrapIP {
			return nil
		}
		return fmt.Errorf("%s contains an empty upstream URL", field)
	}

	full := trimmed
	if requireBootstrapIP && !strings.Contains(full, "://") {
		idx := strings.IndexByte(full, '#')
		addrPart := full
		hashSuffix := ""
		if idx >= 0 {
			addrPart = full[:idx]
			hashSuffix = full[idx:]
		}
		host, port, err := net.SplitHostPort(addrPart)
		if err != nil {
			host = strings.TrimPrefix(strings.TrimSuffix(addrPart, "]"), "[")
			port = "53"
		}
		full = "udp://" + net.JoinHostPort(host, port) + hashSuffix
	}

	parts := strings.SplitN(full, "#", 2)
	urlPart := parts[0]

	isHTTP := false
	switch {
	case strings.HasPrefix(urlPart, "udp://"),
		strings.HasPrefix(urlPart, "tcp://"),
		strings.HasPrefix(urlPart, "dot://"),
		strings.HasPrefix(urlPart, "tls://"),
		strings.HasPrefix(urlPart, "doq://"):
	case strings.HasPrefix(urlPart, "doh://"),
		strings.HasPrefix(urlPart, "https://"),
		strings.HasPrefix(urlPart, "doh3://"):
		isHTTP = true
	default:
		return fmt.Errorf("%s: unsupported upstream scheme in %q", field, raw)
	}

	var hasExplicitIP bool
	if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
		for _, rip := range strings.Split(parts[1], ",") {
			rip = strings.TrimSpace(rip)
			if rip == "" {
				continue
			}
			if _, err := netip.ParseAddr(rip); err != nil {
				return fmt.Errorf("%s: invalid bootstrap IP %q in %q: %w", field, rip, raw, err)
			}
			hasExplicitIP = true
		}
	}

	clean := urlPart
	if idx := strings.Index(clean, "://"); idx >= 0 {
		clean = clean[idx+3:]
	}
	if qIdx := strings.IndexByte(clean, '?'); qIdx >= 0 {
		queryPart := clean[qIdx+1:]
		clean = clean[:qIdx]
		for _, param := range strings.Split(queryPart, "&") {
			if param == "" {
				continue
			}
			switch {
			case strings.HasPrefix(param, "ech="):
				echB64 := param[4:]
				decoded, decErr := decodeBase64Flex(echB64)
				if decErr != nil || len(decoded) == 0 {
					return fmt.Errorf("%s: invalid base64 in ?ech= parameter of %q: %v", field, raw, decErr)
				}
				if cfgs, cfgErr := extractECHConfigs(decoded); cfgErr != nil || len(cfgs) == 0 {
					return fmt.Errorf("%s: malformed ECHConfigList in ?ech= parameter of %q: %v", field, raw, cfgErr)
				}
			case strings.HasPrefix(param, "echdomain="):
				echDom := lowerTrimDot(strings.TrimSpace(strings.ReplaceAll(param[10:], "{client-name}", "client")))
				if echDom == "" || strings.Contains(echDom, "*") || net.ParseIP(echDom) != nil || !isValidQNAME(echDom, dns.TypeHTTPS) {
					return fmt.Errorf("%s: invalid domain in ?echdomain= parameter of %q", field, raw)
				}
			}
		}
	}
	clean, _ = stripMethodModifier(clean)

	if isHTTP {
		uTest := "https://" + strings.ReplaceAll(clean, "{client-name}", "client")
		parsedURL, uErr := url.Parse(uTest)
		if uErr != nil || parsedURL.Host == "" {
			return fmt.Errorf("%s: malformed HTTP/DoH URL %q", field, raw)
		}
	}

	hostPart := clean
	if sIdx := strings.IndexByte(hostPart, '/'); sIdx >= 0 {
		hostPart = hostPart[:sIdx]
	}
	if strings.TrimSpace(hostPart) == "" {
		return fmt.Errorf("%s: missing host in %q", field, raw)
	}
	hostOnly, portStr, splitErr := net.SplitHostPort(hostPart)
	if splitErr == nil {
		p, pErr := strconv.ParseUint(portStr, 10, 16)
		if pErr != nil || p == 0 {
			return fmt.Errorf("%s: invalid port %q in %q", field, portStr, raw)
		}
	} else {
		hostOnly = strings.TrimPrefix(strings.TrimSuffix(hostPart, "]"), "[")
	}

	if _, err := netip.ParseAddr(hostOnly); err == nil {
		hasExplicitIP = true
	}

	if requireBootstrapIP && !hasExplicitIP {
		return fmt.Errorf("%s: bootstrap server %q must contain an explicit IP address (e.g. #1.1.1.1)", field, raw)
	}
	return nil
}

func validateScheduleSpec(groupName, entry string) error {
	parts := strings.Fields(strings.TrimSpace(entry))
	if len(parts) == 0 || len(parts) > 2 {
		return fmt.Errorf("groups.%s.schedule: invalid entry %q", groupName, entry)
	}
	var dayPart, timePart string
	if len(parts) == 1 {
		timePart = parts[0]
	} else {
		dayPart, timePart = parts[0], parts[1]
	}
	if dayPart != "" {
		spec := strings.ToLower(dayPart)
		spec = strings.ReplaceAll(spec, "weekdays", "mon-fri")
		spec = strings.ReplaceAll(spec, "weekend", "sat,sun")
		for _, tok := range strings.Split(spec, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				return fmt.Errorf("groups.%s.schedule: empty day token in %q", groupName, entry)
			}
			if idx := strings.IndexByte(tok, '-'); idx >= 0 {
				_, ok1 := dayNamesMap[tok[:idx]]
				_, ok2 := dayNamesMap[tok[idx+1:]]
				if !ok1 || !ok2 {
					return fmt.Errorf("groups.%s.schedule: invalid day range %q in %q", groupName, tok, entry)
				}
			} else if _, ok := dayNamesMap[tok]; !ok {
				return fmt.Errorf("groups.%s.schedule: unknown day %q in %q", groupName, tok, entry)
			}
		}
	}
	idx := strings.IndexByte(timePart, '-')
	if idx <= 0 {
		return fmt.Errorf("groups.%s.schedule: invalid time range %q in %q (expected HH:MM-HH:MM)", groupName, timePart, entry)
	}
	if _, _, ok1 := parseHHMM(timePart[:idx]); !ok1 {
		return fmt.Errorf("groups.%s.schedule: invalid start time in %q", groupName, entry)
	}
	if _, _, ok2 := parseHHMM(timePart[idx+1:]); !ok2 {
		return fmt.Errorf("groups.%s.schedule: invalid end time in %q", groupName, entry)
	}
	return nil
}

func validateBudgetValue(groupName, key, val string) error {
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return fmt.Errorf("groups.%s.budget.%s cannot be empty", groupName, key)
	}
	upper := strings.ToUpper(trimmed)
	switch {
	case upper == "ALLOW", upper == "BLOCK", upper == "FREE", upper == "LOG", upper == "UNLIMITED":
		return nil
	case upper == "UNTRIGGER":
		return nil
	case strings.HasPrefix(upper, "UNTRIGGER "):
		durStr := strings.TrimSpace(trimmed[len("UNTRIGGER "):])
		d, err := time.ParseDuration(durStr)
		if err != nil || d <= 0 {
			return fmt.Errorf("groups.%s.budget.%s: invalid UNTRIGGER duration %q", groupName, key, val)
		}
		return nil
	default:
		d, err := time.ParseDuration(trimmed)
		if err != nil || d < 0 {
			return fmt.Errorf("groups.%s.budget.%s: invalid budget %q (expected duration, ALLOW, BLOCK, FREE, LOG, UNLIMITED, or UNTRIGGER)", groupName, key, val)
		}
		return nil
	}
}

func validateRRMap(field string, source map[string]interface{}) error {
	for rawKey, rawVal := range source {
		keys := splitDomainPolicyKeys(rawKey)
		if len(keys) == 0 {
			return fmt.Errorf("%s: empty domain key", field)
		}
		for _, tok := range keys {
			if isRegexKey(tok) {
				if _, err := compileDomainRegex(tok); err != nil {
					return fmt.Errorf("%s: %w", field, err)
				}
			}
		}
		switch val := rawVal.(type) {
		case string:
			if strings.TrimSpace(val) == "" {
				return fmt.Errorf("%s[%q]: target cannot be empty", field, rawKey)
			}
		case []interface{}:
			validIPs := 0
			for _, item := range val {
				str, ok := item.(string)
				if !ok {
					return fmt.Errorf("%s[%q]: list elements must be IP strings", field, rawKey)
				}
				if _, err := netip.ParseAddr(strings.TrimSpace(str)); err != nil {
					return fmt.Errorf("%s[%q]: invalid IP %q in list (lists only support A/AAAA IPs, not CNAMEs)", field, rawKey, str)
				}
				validIPs++
			}
			if validIPs == 0 {
				return fmt.Errorf("%s[%q]: IP list cannot be empty", field, rawKey)
			}
		default:
			return fmt.Errorf("%s[%q]: value must be a string (IP/CNAME) or list of IP strings", field, rawKey)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Master Configuration Validation
// ---------------------------------------------------------------------------

func validateConfig() error {
	if err := validateListenAddrs("server.listen_udp", cfg.Server.ListenUDP); err != nil {
		return err
	}
	if err := validateListenAddrs("server.listen_tcp", cfg.Server.ListenTCP); err != nil {
		return err
	}
	if err := validateListenAddrs("server.listen_dot", cfg.Server.ListenDoT); err != nil {
		return err
	}
	if err := validateListenAddrs("server.listen_doh", cfg.Server.ListenDoH); err != nil {
		return err
	}
	if err := validateListenAddrs("server.listen_doq", cfg.Server.ListenDoQ); err != nil {
		return err
	}

	v := strings.ToLower(strings.TrimSpace(cfg.Server.SupportIPVersion))
	switch v {
	case "", "both":
		cfg.Server.SupportIPVersion = "both"
	case "ipv4", "ipv6":
		cfg.Server.SupportIPVersion = v
	default:
		return fmt.Errorf("server.support_ip_version %q must be 'both', 'ipv4', or 'ipv6'", cfg.Server.SupportIPVersion)
	}

	blkAct := strings.ToUpper(strings.TrimSpace(cfg.Server.BlockAction))
	switch blkAct {
	case "", "NULL":
		cfg.Server.BlockAction = "NULL"
	case "DROP", "LOG", "IP":
		cfg.Server.BlockAction = blkAct
	default:
		if _, ok := dns.StringToRcode[blkAct]; !ok {
			return fmt.Errorf("server.block_action %q must be 'NULL', 'DROP', 'LOG', 'IP', or a valid DNS RCODE", cfg.Server.BlockAction)
		}
		cfg.Server.BlockAction = blkAct
	}

	for _, ipStr := range cfg.Server.BlockIPs {
		if _, err := netip.ParseAddr(strings.TrimSpace(ipStr)); err != nil {
			return fmt.Errorf("server.block_ips: invalid IP address %q: %w", ipStr, err)
		}
	}

	if cfg.Server.UDPWorkers < 0 || cfg.Server.MemoryLimitMB < 0 || cfg.Server.MaxTCPConnections < 0 ||
		cfg.Server.UpstreamStaggerMs < 0 || cfg.Server.UpstreamTimeoutMs < 0 || cfg.Server.SyntheticTTL < 0 {
		return fmt.Errorf("server worker, memory, connection, timeout, and TTL settings must not be negative")
	}

	if (cfg.Server.TLSCert != "") != (cfg.Server.TLSKey != "") {
		return fmt.Errorf("server.tls_cert and server.tls_key must both be set or both be empty")
	}
	if (cfg.Server.ECHConfigList != "") != (cfg.Server.ECHKey != "") {
		return fmt.Errorf("server.ech_config_list and server.ech_key must both be set or both be empty")
	}

	if err := validatePrefixEntries("server.acl.allow", cfg.Server.ACL.Allow); err != nil {
		return err
	}
	if err := validatePrefixEntries("server.acl.deny", cfg.Server.ACL.Deny); err != nil {
		return err
	}
	if err := validatePrefixEntries("server.trusted_proxies", cfg.Server.TrustedProxies); err != nil {
		return err
	}
	if err := validatePrefixEntries("server.rate_limit.exempt", cfg.Server.RateLimit.Exempt); err != nil {
		return err
	}
	if err := validatePrefixEntries("server.exfiltration.exempt", cfg.Server.Exfiltration.Exempt); err != nil {
		return err
	}

	if cfg.Server.RateLimit.QPS < 0 || cfg.Server.RateLimit.Burst < 0 || cfg.Server.RateLimit.MaxTrackedIPs < 0 ||
		cfg.Server.RateLimit.PenaltyBox.StrikeThreshold < 0 || cfg.Server.RateLimit.PenaltyBox.BanDurationMin < 0 {
		return fmt.Errorf("server.rate_limit settings must not be negative")
	}
	if cfg.Server.RateLimit.IPv4PrefixLength < 0 || cfg.Server.RateLimit.IPv4PrefixLength > 32 {
		return fmt.Errorf("server.rate_limit.ipv4_prefix_length (%d) must be between 0 and 32", cfg.Server.RateLimit.IPv4PrefixLength)
	}
	if cfg.Server.RateLimit.IPv6PrefixLength < 0 || cfg.Server.RateLimit.IPv6PrefixLength > 128 {
		return fmt.Errorf("server.rate_limit.ipv6_prefix_length (%d) must be between 0 and 128", cfg.Server.RateLimit.IPv6PrefixLength)
	}
	if cfg.Server.RateLimit.Enabled && cfg.Server.RateLimit.MaxTrackedIPs == 0 {
		cfg.Server.RateLimit.MaxTrackedIPs = 1000
	}

	if cfg.Server.Exfiltration.MinThresholdBPS < 0 || cfg.Server.Exfiltration.AnomalyMultiplier < 0 ||
		cfg.Server.Exfiltration.MaxTrackedIPs < 0 || cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold < 0 ||
		cfg.Server.Exfiltration.PenaltyBox.BanDurationMin < 0 {
		return fmt.Errorf("server.exfiltration settings must not be negative")
	}
	if cfg.Server.Exfiltration.IPv4PrefixLength < 0 || cfg.Server.Exfiltration.IPv4PrefixLength > 32 {
		return fmt.Errorf("server.exfiltration.ipv4_prefix_length (%d) must be between 0 and 32", cfg.Server.Exfiltration.IPv4PrefixLength)
	}
	if cfg.Server.Exfiltration.IPv6PrefixLength < 0 || cfg.Server.Exfiltration.IPv6PrefixLength > 128 {
		return fmt.Errorf("server.exfiltration.ipv6_prefix_length (%d) must be between 0 and 128", cfg.Server.Exfiltration.IPv6PrefixLength)
	}

	vUpSel := strings.ToLower(strings.TrimSpace(cfg.Server.UpstreamSelection))
	switch vUpSel {
	case "", "stagger":
		cfg.Server.UpstreamSelection = "stagger"
	case "round-robin", "random", "fastest", "secure":
		cfg.Server.UpstreamSelection = vUpSel
	default:
		return fmt.Errorf("server.upstream_selection %q must be 'stagger', 'round-robin', 'random', 'fastest', or 'secure'", cfg.Server.UpstreamSelection)
	}

	vUseECH := strings.ToLower(strings.TrimSpace(cfg.Server.UseUpstreamECH))
	switch vUseECH {
	case "", "disable":
		cfg.Server.UseUpstreamECH = "disable"
	case "try", "strict":
		cfg.Server.UseUpstreamECH = vUseECH
	default:
		return fmt.Errorf("server.use_upstream_ech %q must be 'disable', 'try', or 'strict'", cfg.Server.UseUpstreamECH)
	}

	vHostnameECH := strings.ToLower(strings.TrimSpace(cfg.Server.HostnameECH))
	switch vHostnameECH {
	case "", "strict":
		cfg.Server.HostnameECH = "strict"
	case "loose", "apex", "any":
		cfg.Server.HostnameECH = vHostnameECH
	default:
		return fmt.Errorf("server.hostname_ech %q must be 'strict', 'loose', 'apex', or 'any'", cfg.Server.HostnameECH)
	}

	vDDRSource := strings.ToLower(strings.TrimSpace(cfg.Server.DDR.HostnameSource))
	switch vDDRSource {
	case "", "strict":
		cfg.Server.DDR.HostnameSource = "strict"
	case "tls", "both":
		cfg.Server.DDR.HostnameSource = vDDRSource
	default:
		return fmt.Errorf("server.ddr.hostname_source %q must be 'strict', 'tls', or 'both'", cfg.Server.DDR.HostnameSource)
	}
	for _, h := range cfg.Server.DDR.Hostnames {
		clean := lowerTrimDot(strings.TrimSpace(h))
		if clean == "" || strings.Contains(clean, "*") || net.ParseIP(clean) != nil || !isValidQNAME(clean, dns.TypeA) {
			return fmt.Errorf("server.ddr.hostnames: invalid resolver hostname %q", h)
		}
	}
	for _, s := range cfg.Server.DDR.IPv4 {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.Unmap().Is4() {
			return fmt.Errorf("server.ddr.ipv4: invalid IPv4 address %q", s)
		}
	}
	for _, s := range cfg.Server.DDR.IPv6 {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil || !a.Is6() || a.Is4In6() {
			return fmt.Errorf("server.ddr.ipv6: invalid IPv6 address %q", s)
		}
	}

	if cfg.Server.UserAgent == "" {
		cfg.Server.UserAgent = "sdproxy/1.0"
	}

	if cfg.Server.MaxSecureUpstreams < 0 {
		return fmt.Errorf("server.max_secure_upstreams must not be negative")
	}
	if cfg.Server.MaxSecureUpstreams == 0 {
		cfg.Server.MaxSecureUpstreams = 5
	}

	if cfg.Server.DoH3FallbackThreshold < 0 {
		return fmt.Errorf("server.doh3_fallback_threshold must not be negative")
	}

	if err := validateOptionalDuration("server.policy_poll_interval", cfg.Server.PolicyPollInterval, true); err != nil {
		return err
	}

	for _, bs := range cfg.Server.BootstrapServers {
		if err := validateUpstreamURLSyntax("server.bootstrap_servers", bs, true); err != nil {
			return err
		}
	}

	fsAct := strings.ToUpper(strings.TrimSpace(cfg.Server.ForSale))
	switch fsAct {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		cfg.Server.ForSale = "disabled"
	case "BLOCK", "DROP", "LOG":
		cfg.Server.ForSale = fsAct
	default:
		if _, ok := dns.StringToRcode[fsAct]; !ok {
			return fmt.Errorf("server.for_sale %q must be 'disabled', 'BLOCK', 'DROP', 'LOG', or a valid DNS RCODE", cfg.Server.ForSale)
		}
		cfg.Server.ForSale = fsAct
	}

	pkAct := strings.ToUpper(strings.TrimSpace(cfg.Server.Parked))
	switch pkAct {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		cfg.Server.Parked = "disabled"
	case "BLOCK", "DROP", "LOG":
		cfg.Server.Parked = pkAct
	default:
		if _, ok := dns.StringToRcode[pkAct]; !ok {
			return fmt.Errorf("server.parked %q must be 'disabled', 'BLOCK', 'DROP', 'LOG', or a valid DNS RCODE", cfg.Server.Parked)
		}
		cfg.Server.Parked = pkAct
	}

	rfcAct := strings.ToUpper(strings.TrimSpace(cfg.Server.RFCCompliance.Action))
	switch rfcAct {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		cfg.Server.RFCCompliance.Action = "disabled"
	case "LOG", "BLOCK":
		cfg.Server.RFCCompliance.Action = rfcAct
	default:
		return fmt.Errorf("server.rfc_compliance.action %q must be 'disabled', 'LOG', or 'BLOCK'", cfg.Server.RFCCompliance.Action)
	}

	if len(cfg.Server.RFCCompliance.Checks) > 0 {
		normChecks := make([]string, 0, len(cfg.Server.RFCCompliance.Checks))
		for _, raw := range cfg.Server.RFCCompliance.Checks {
			for _, tok := range strings.Split(raw, ",") {
				c := strings.ToUpper(strings.TrimSpace(tok))
				if c == "" {
					continue
				}
				switch c {
				case "NS", "MX", "SRV", "SOA", "PTR", "CNAME", "ALL", "*":
					normChecks = append(normChecks, c)
				default:
					return fmt.Errorf("server.rfc_compliance.checks: unknown check %q (valid: NS, MX, SRV, SOA, PTR, CNAME, ALL)", tok)
				}
			}
		}
		cfg.Server.RFCCompliance.Checks = normChecks
	}

	idnAct := strings.ToUpper(strings.TrimSpace(cfg.Server.IDNHomograph.Action))
	switch idnAct {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		cfg.Server.IDNHomograph.Action = "disabled"
	case "BLOCK", "DROP", "LOG":
		cfg.Server.IDNHomograph.Action = idnAct
	default:
		if _, ok := dns.StringToRcode[idnAct]; !ok {
			return fmt.Errorf("server.idn_homograph.action %q must be 'disabled', 'BLOCK', 'DROP', 'LOG', or a valid DNS RCODE", cfg.Server.IDNHomograph.Action)
		}
		cfg.Server.IDNHomograph.Action = idnAct
	}

	if cfg.Server.DGA.Threshold < 0 || cfg.Server.DGA.Threshold > 100 {
		return fmt.Errorf("server.dga.threshold (%.1f) must be between 0.0 and 100.0", cfg.Server.DGA.Threshold)
	}
	if cfg.Server.DGA.Enabled || cfg.Server.DGA.Action != "" {
		act, err := validateSecurityAction("server.dga.action", cfg.Server.DGA.Action, "BLOCK")
		if err != nil {
			return err
		}
		if cfg.Server.DGA.Enabled {
			cfg.Server.DGA.Action = act
		}
	}

	if cfg.Server.Exfiltration.Enabled || cfg.Server.Exfiltration.Action != "" {
		act, err := validateSecurityAction("server.exfiltration.action", cfg.Server.Exfiltration.Action, "LOG")
		if err != nil {
			return err
		}
		if cfg.Server.Exfiltration.Enabled {
			cfg.Server.Exfiltration.Action = act
		}
	}

	if cfg.Server.Exfiltration.Enabled {
		if cfg.Server.Exfiltration.MinThresholdBPS <= 0 {
			cfg.Server.Exfiltration.MinThresholdBPS = 1500
		}
		if cfg.Server.Exfiltration.AnomalyMultiplier <= 0 {
			cfg.Server.Exfiltration.AnomalyMultiplier = 3.0
		}
		if cfg.Server.Exfiltration.MaxTrackedIPs <= 0 {
			cfg.Server.Exfiltration.MaxTrackedIPs = 50000
		}
		if cfg.Server.Exfiltration.PenaltyBox.Enabled {
			if cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold <= 0 {
				cfg.Server.Exfiltration.PenaltyBox.StrikeThreshold = 3
			}
			if cfg.Server.Exfiltration.PenaltyBox.BanDurationMin <= 0 {
				cfg.Server.Exfiltration.PenaltyBox.BanDurationMin = 15
			}
		}
	}

	mergeSubdomainLimitConfig(&cfg.Server.SubdomainLimit, cfg.Server.SubdomainLimiter)
	mergeSubdomainLimitConfig(&cfg.Server.SubdomainLimit, cfg.Server.SubnetLimiter)
	mergeSubdomainLimitConfig(&cfg.Server.SubdomainLimit, cfg.Server.SubnetLimit)

	if cfg.Server.SubdomainLimit.Threshold < 0 || cfg.Server.SubdomainLimit.WindowMinutes < 0 || cfg.Server.SubdomainLimit.MaxTrackedApexes < 0 {
		return fmt.Errorf("server.subdomain_limit numeric settings must not be negative")
	}
	if cfg.Server.SubdomainLimit.Enabled || cfg.Server.SubdomainLimit.Action != "" {
		act, err := validateSecurityAction("server.subdomain_limit.action", cfg.Server.SubdomainLimit.Action, "BLOCK")
		if err != nil {
			return err
		}
		if cfg.Server.SubdomainLimit.Enabled {
			cfg.Server.SubdomainLimit.Action = act
		}
	}

	if cfg.Server.SubdomainLimit.Enabled {
		if cfg.Server.SubdomainLimit.Threshold <= 0 {
			cfg.Server.SubdomainLimit.Threshold = 100
		}
		if cfg.Server.SubdomainLimit.WindowMinutes <= 0 {
			cfg.Server.SubdomainLimit.WindowMinutes = 60
		}
		if cfg.Server.SubdomainLimit.MaxTrackedApexes <= 0 {
			cfg.Server.SubdomainLimit.MaxTrackedApexes = 10000
		}
	}

	ecsAction := strings.ToLower(strings.TrimSpace(cfg.Server.ECS.Action))
	switch ecsAction {
	case "", "remove":
		cfg.Server.ECS.Action = "remove"
	case "add", "pass":
		cfg.Server.ECS.Action = ecsAction
	default:
		return fmt.Errorf("server.ecs.action %q must be 'remove', 'add', or 'pass'", cfg.Server.ECS.Action)
	}
	if cfg.Server.ECS.IPv4Mask < 0 || cfg.Server.ECS.IPv4Mask > 32 {
		return fmt.Errorf("server.ecs.ipv4_mask (%d) must be between 0 and 32", cfg.Server.ECS.IPv4Mask)
	}
	if cfg.Server.ECS.IPv6Mask < 0 || cfg.Server.ECS.IPv6Mask > 128 {
		return fmt.Errorf("server.ecs.ipv6_mask (%d) must be between 0 and 128", cfg.Server.ECS.IPv6Mask)
	}
	if cfg.Server.ECS.IPv4Mask == 0 {
		cfg.Server.ECS.IPv4Mask = 24
	}
	if cfg.Server.ECS.IPv6Mask == 0 {
		cfg.Server.ECS.IPv6Mask = 56
	}

	if cfg.Server.QnameMinLabels < 0 || cfg.Server.QnameMaxLabels < 0 {
		return fmt.Errorf("server.qname_min_labels and server.qname_max_labels must not be negative")
	}
	if cfg.Server.QnameMinLabels == 0 {
		cfg.Server.QnameMinLabels = 1
	}
	if cfg.Server.QnameMaxLabels == 0 {
		cfg.Server.QnameMaxLabels = 20
	}
	if cfg.Server.QnameMaxLabels > 127 {
		cfg.Server.QnameMaxLabels = 127
	}
	if cfg.Server.QnameMinLabels >= 127 {
		cfg.Server.QnameMinLabels = 126
	}
	if cfg.Server.QnameMinLabels >= cfg.Server.QnameMaxLabels {
		cfg.Server.QnameMaxLabels = cfg.Server.QnameMinLabels + 1
	}

	if cfg.Cache.Enabled {
		if cfg.Cache.Size == 0 {
			cfg.Cache.Size = 5000
		}
		if cfg.Cache.Size < 1 {
			return fmt.Errorf("cache.size must be >= 1 when cache is enabled")
		}
	} else if cfg.Cache.Size < 0 {
		return fmt.Errorf("cache.size must not be negative")
	}

	if cfg.Cache.MinTTL < 0 || cfg.Cache.MaxTTL < 0 || cfg.Cache.NegativeTTL < 0 ||
		cfg.Cache.RcodeTTL < 0 || cfg.Cache.RcodeMinTTL < 0 || cfg.Cache.RcodeMaxTTL < 0 ||
		cfg.Cache.StaleTTL < 0 || cfg.Cache.PrefetchBefore < 0 ||
		cfg.Cache.PrefetchMinHits < 0 || cfg.Cache.SweepIntervalS < 0 {
		return fmt.Errorf("cache TTL, prefetch, and sweep settings must not be negative")
	}
	if cfg.Cache.MaxTTL > 0 && cfg.Cache.MinTTL > cfg.Cache.MaxTTL {
		return fmt.Errorf("cache.min_ttl (%d) cannot exceed cache.max_ttl (%d)", cfg.Cache.MinTTL, cfg.Cache.MaxTTL)
	}
	if cfg.Cache.RcodeMaxTTL > 0 && cfg.Cache.RcodeMinTTL > cfg.Cache.RcodeMaxTTL {
		return fmt.Errorf("cache.rcode_min_ttl (%d) cannot exceed cache.rcode_max_ttl (%d)", cfg.Cache.RcodeMinTTL, cfg.Cache.RcodeMaxTTL)
	}

	if cfg.Cache.Persist {
		if cfg.Cache.PersistFile == "" {
			cfg.Cache.PersistFile = "/var/lib/sdproxy/dns_cache.bin"
		}
		if cfg.Cache.PersistSaveInterval == "" {
			cfg.Cache.PersistSaveInterval = "5m"
		}
		if err := validateOptionalDuration("cache.persist_save_interval", cfg.Cache.PersistSaveInterval, true); err != nil {
			return err
		}
	}

	if cfg.Identity.PollInterval < 0 {
		return fmt.Errorf("identity.poll_interval (%d) must not be negative", cfg.Identity.PollInterval)
	}
	if err := validateOptionalDuration("identity.asn_poll_interval", cfg.Identity.ASNPollInterval, true); err != nil {
		return err
	}

	if cfg.Cache.CacheLocalIdentity {
		st := cfg.Server.SyntheticTTL
		if st == 0 {
			st = 60
		}
		pi := cfg.Identity.PollInterval
		if pi > 0 && st > pi && !quietInit {
			log.Printf("[WARN] cache_local_identity: synthetic_ttl (%ds) > identity.poll_interval (%ds) — stale local addresses may be served; lower synthetic_ttl or raise poll_interval\n", st, pi)
		}
	}

	sortMethod := strings.ToLower(strings.TrimSpace(cfg.Cache.AnswerSort))
	switch sortMethod {
	case "", "none":
		cfg.Cache.AnswerSort = "none"
	case "round-robin", "random", "ip-sort", "proximity":
		cfg.Cache.AnswerSort = sortMethod
	default:
		return fmt.Errorf("cache.answer_sort %q must be 'none', 'round-robin', 'random', 'ip-sort', or 'proximity'", cfg.Cache.AnswerSort)
	}

	if cfg.Parental.ForcedTTL < 0 || cfg.Parental.BlockTTL < 0 || cfg.Parental.TickerInterval < 0 ||
		cfg.Parental.ParentConsolidationThreshold < 0 || cfg.Parental.ConsolidationHomogeneityPct < 0 || cfg.Parental.ConsolidationHomogeneityPct > 100 {
		return fmt.Errorf("parental TTL, ticker, and consolidation bounds are out of valid range")
	}
	if err := validateOptionalDuration("parental.default_idle_pause", cfg.Parental.DefaultIdlePause, false); err != nil {
		return err
	}
	if err := validateOptionalDuration("parental.default_session_window", cfg.Parental.DefaultSessionWindow, false); err != nil {
		return err
	}

	if len(cfg.Parental.Categories) > 0 {
		normCats := make(map[string]CategoryConfig, len(cfg.Parental.Categories))
		for k, cat := range cfg.Parental.Categories {
			kLower := strings.ToLower(strings.TrimSpace(k))
			if err := validateOptionalDuration("parental.categories."+kLower+".idle_pause", cat.IdlePause, false); err != nil {
				return err
			}
			if err := validateOptionalDuration("parental.categories."+kLower+".session_window", cat.SessionWindow, false); err != nil {
				return err
			}
			normCats[kLower] = cat
		}
		cfg.Parental.Categories = normCats
	}

	if len(cfg.Upstreams) > 0 {
		normUpstreams := make(map[string]UpstreamGroupConfig, len(cfg.Upstreams))
		for k, u := range cfg.Upstreams {
			kLower := strings.ToLower(strings.TrimSpace(k))
			u.Strategy = strings.ToLower(strings.TrimSpace(u.Strategy))
			switch u.Strategy {
			case "", "stagger", "round-robin", "random", "fastest", "secure":
			default:
				return fmt.Errorf("upstreams.%s.strategy %q must be 'stagger', 'round-robin', 'random', 'fastest', or 'secure'", kLower, u.Strategy)
			}

			u.Preference = strings.ToLower(strings.TrimSpace(u.Preference))
			switch u.Preference {
			case "", "fastest", "ordered", "consolidate":
			default:
				return fmt.Errorf("upstreams.%s.preference %q must be 'fastest', 'ordered', or 'consolidate'", kLower, u.Preference)
			}

			u.Mode = strings.ToLower(strings.TrimSpace(u.Mode))
			switch u.Mode {
			case "", "loose", "strict":
			default:
				return fmt.Errorf("upstreams.%s.mode %q must be 'loose' or 'strict'", kLower, u.Mode)
			}

			u.ECS.Action = strings.ToLower(strings.TrimSpace(u.ECS.Action))
			switch u.ECS.Action {
			case "", "remove", "add", "pass":
			default:
				return fmt.Errorf("upstreams.%s.ecs.action %q must be 'remove', 'add', or 'pass'", kLower, u.ECS.Action)
			}
			if u.ECS.IPv4Mask < 0 || u.ECS.IPv4Mask > 32 {
				return fmt.Errorf("upstreams.%s.ecs.ipv4_mask (%d) must be between 0 and 32", kLower, u.ECS.IPv4Mask)
			}
			if u.ECS.IPv6Mask < 0 || u.ECS.IPv6Mask > 128 {
				return fmt.Errorf("upstreams.%s.ecs.ipv6_mask (%d) must be between 0 and 128", kLower, u.ECS.IPv6Mask)
			}

			if u.DoH3FallbackThreshold != nil && *u.DoH3FallbackThreshold < 0 {
				return fmt.Errorf("upstreams.%s.doh3_fallback_threshold must not be negative", kLower)
			}

			for _, srv := range u.Servers {
				if err := validateUpstreamURLSyntax("upstreams."+kLower, srv, false); err != nil {
					return err
				}
			}

			normUpstreams[kLower] = u
		}
		cfg.Upstreams = normUpstreams
	} else {
		cfg.Upstreams = make(map[string]UpstreamGroupConfig)
	}

	checkUpstreamRef := func(field, upName string) error {
		if upName == "" {
			return nil
		}
		if len(cfg.Upstreams) == 0 && upName == "default" {
			return nil
		}
		if _, exists := cfg.Upstreams[upName]; !exists {
			return fmt.Errorf("%s references unknown upstream group %q", field, upName)
		}
		return nil
	}

	if len(cfg.Groups) > 0 {
		normGroups := make(map[string]GroupConfig, len(cfg.Groups))
		for k, g := range cfg.Groups {
			kLower := strings.ToLower(strings.TrimSpace(k))
			if g.BlockTTL < 0 {
				return fmt.Errorf("groups.%s.block_ttl must not be negative", kLower)
			}
			bt := strings.ToLower(strings.TrimSpace(g.BudgetTracking))
			switch bt {
			case "", "group", "device":
				g.BudgetTracking = bt
			default:
				return fmt.Errorf("groups.%s.budget_tracking %q must be 'group' or 'device'", kLower, g.BudgetTracking)
			}
			if g.Upstream != "" {
				g.Upstream = strings.ToLower(strings.TrimSpace(g.Upstream))
				if err := checkUpstreamRef("groups."+kLower+".upstream", g.Upstream); err != nil {
					return err
				}
			}
			for _, sched := range g.Schedule {
				if err := validateScheduleSpec(kLower, sched); err != nil {
					return err
				}
			}
			if len(g.Budget) > 0 {
				normBudget := make(map[string]string, len(g.Budget))
				for bk, bv := range g.Budget {
					bkLower := strings.ToLower(strings.TrimSpace(bk))
					if bkLower != "total" {
						if _, catOK := cfg.Parental.Categories[bkLower]; !catOK {
							return fmt.Errorf("groups.%s.budget references unknown parental category %q", kLower, bkLower)
						}
					}
					if err := validateBudgetValue(kLower, bkLower, bv); err != nil {
						return err
					}
					normBudget[bkLower] = bv
				}
				g.Budget = normBudget
			}
			normGroups[kLower] = g
		}
		cfg.Groups = normGroups
	} else {
		cfg.Groups = make(map[string]GroupConfig)
	}

	hasConsolidate := false
	for _, u := range cfg.Upstreams {
		effStrat := u.Strategy
		if effStrat == "" {
			effStrat = cfg.Server.UpstreamSelection
		}
		if effStrat == "secure" && u.Preference == "consolidate" {
			hasConsolidate = true
			break
		}
	}
	if hasConsolidate && !cfg.Server.FlattenCNAME {
		cfg.Server.FlattenCNAME = true
		autoEnabledFlattenCNAME = true
	}

	normRouteMap := func(field string, src map[string]RouteConfig) (map[string]RouteConfig, error) {
		out := make(map[string]RouteConfig, len(src))
		for k, r := range src {
			if field == "routes" {
				hasKey := false
				for _, tok := range strings.Split(k, ",") {
					tok = strings.TrimSpace(tok)
					if tok == "" {
						continue
					}
					if classifyRouteKey(tok) == rkInvalid {
						return nil, fmt.Errorf("%s: invalid route key %q", field, tok)
					}
					hasKey = true
				}
				if !hasKey {
					return nil, fmt.Errorf("%s: empty route key %q", field, k)
				}
			}
			if r.Rcode != "" {
				if err := validatePolicyActionStr(field+"["+k+"].rcode", r.Rcode); err != nil {
					return nil, err
				}
			}
			if r.Group != "" {
				r.Group = strings.ToLower(strings.TrimSpace(r.Group))
				if _, ok := cfg.Groups[r.Group]; !ok {
					return nil, fmt.Errorf("%s[%q].group references unknown group %q", field, k, r.Group)
				}
			}
			if r.Upstream != "" {
				r.Upstream = strings.ToLower(strings.TrimSpace(r.Upstream))
				if err := checkUpstreamRef(field+"["+k+"].upstream", r.Upstream); err != nil {
					return nil, err
				}
			}
			out[k] = r
		}
		return out, nil
	}

	var err error
	if cfg.Routes, err = normRouteMap("routes", cfg.Routes); err != nil {
		return err
	}
	if cfg.RoutesFiles, err = normRouteMap("routes_files", cfg.RoutesFiles); err != nil {
		return err
	}

	normDomainRouteMap := func(field string, src map[string]DomainRouteConfig) (map[string]DomainRouteConfig, error) {
		out := make(map[string]DomainRouteConfig, len(src))
		for k, dr := range src {
			dr.Upstream = strings.ToLower(strings.TrimSpace(dr.Upstream))
			if dr.Upstream == "" {
				return nil, fmt.Errorf("%s[%q]: upstream cannot be empty", field, k)
			}
			if err := checkUpstreamRef(field+"["+k+"].upstream", dr.Upstream); err != nil {
				return nil, err
			}
			out[k] = dr
		}
		return out, nil
	}

	if cfg.DomainRoutes, err = normDomainRouteMap("domain_routes", cfg.DomainRoutes); err != nil {
		return err
	}
	if cfg.DomainRoutesFiles, err = normDomainRouteMap("domain_routes_files", cfg.DomainRoutesFiles); err != nil {
		return err
	}

	if err := validateRRMap("rrs", cfg.RRs); err != nil {
		return err
	}
	for grpName, grpCfg := range cfg.Groups {
		if err := validateRRMap("groups."+grpName+".rrs", grpCfg.RRs); err != nil {
			return err
		}
	}

	for rawKey, act := range cfg.RtypePolicy {
		if err := validatePolicyActionStr("rtype_policy["+rawKey+"]", act); err != nil {
			return err
		}
		for _, typeName := range strings.Split(rawKey, ",") {
			typeName = strings.TrimSpace(typeName)
			if typeName == "" {
				continue
			}
			if _, ok := dns.StringToType[strings.ToUpper(typeName)]; !ok {
				return fmt.Errorf("rtype_policy: unknown DNS RR type %q", typeName)
			}
		}
	}
	for filePath, act := range cfg.RtypePolicyFiles {
		if err := validatePolicyActionStr("rtype_policy_files["+filePath+"]", act); err != nil {
			return err
		}
		if lines, fErr := readConfigListFile(filePath); fErr == nil {
			for _, line := range lines {
				for _, typeName := range strings.Split(line, ",") {
					typeName = strings.TrimSpace(typeName)
					if typeName == "" {
						continue
					}
					if _, ok := dns.StringToType[strings.ToUpper(typeName)]; !ok {
						return fmt.Errorf("rtype_policy_files (%s): unknown DNS RR type %q", filePath, typeName)
					}
				}
			}
		}
	}

	for rawKey, act := range cfg.DomainPolicy {
		if err := validatePolicyActionStr("domain_policy["+rawKey+"]", act); err != nil {
			return err
		}
		for _, tok := range splitDomainPolicyKeys(rawKey) {
			if isRegexKey(tok) {
				if _, err := compileDomainRegex(tok); err != nil {
					return fmt.Errorf("domain_policy: %w", err)
				}
			}
		}
	}
	for filePath, act := range cfg.DomainPolicyFiles {
		if err := validatePolicyActionStr("domain_policy_files["+filePath+"]", act); err != nil {
			return err
		}
		lines, fErr := readConfigListFile(filePath)
		if fErr != nil {
			continue
		}
		for _, line := range lines {
			for _, tok := range splitDomainPolicyKeys(line) {
				if isRegexKey(tok) {
					if _, err := compileDomainRegex(tok); err != nil {
						return fmt.Errorf("domain_policy_files (%s): %w", filePath, err)
					}
				}
			}
		}
	}
	for urlStr, act := range cfg.DomainPolicyURLs {
		if !isSourceURL(strings.TrimSpace(urlStr)) {
			return fmt.Errorf("domain_policy_urls: %q must start with http:// or https://", urlStr)
		}
		if err := validatePolicyActionStr("domain_policy_urls["+urlStr+"]", act); err != nil {
			return err
		}
	}

	if cfg.WebUI.Enabled && cfg.WebUI.Password == "" {
		return fmt.Errorf("webui.password must not be empty when webui.enabled is true")
	}
	if cfg.WebUI.Listen != "" {
		if err := validateListenAddrs("webui.listen", []string{cfg.WebUI.Listen}); err != nil {
			return err
		}
	}
	if err := validateListenAddrs("webui.listen_http", cfg.WebUI.ListenHTTP); err != nil {
		return err
	}
	if err := validateListenAddrs("webui.listen_https", cfg.WebUI.ListenHTTPS); err != nil {
		return err
	}
	if err := validatePrefixEntries("webui.acl.allow", cfg.WebUI.ACL.Allow); err != nil {
		return err
	}
	if err := validatePrefixEntries("webui.acl.deny", cfg.WebUI.ACL.Deny); err != nil {
		return err
	}
	if err := validateOptionalDuration("webui.history_save_interval", cfg.WebUI.HistorySaveInterval, true); err != nil {
		return err
	}
	if cfg.WebUI.LoginRatelimit.MaxAttempts < 0 || cfg.WebUI.LoginRatelimit.LockoutMinutes < 0 ||
		cfg.WebUI.StatsRefreshSec < 0 || cfg.WebUI.StatsTopN < 0 || cfg.WebUI.HistoryRetentionHours < 0 {
		return fmt.Errorf("webui numeric settings must not be negative")
	}
	if cfg.WebUI.LoginRatelimit.Enabled {
		if cfg.WebUI.LoginRatelimit.MaxAttempts == 0 {
			cfg.WebUI.LoginRatelimit.MaxAttempts = 5
		}
		if cfg.WebUI.LoginRatelimit.LockoutMinutes == 0 {
			cfg.WebUI.LoginRatelimit.LockoutMinutes = 15
		}
	}

	return nil
}
