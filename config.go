/*
File:    config.go
Version: 1.100.0
Last Updated: 10-Nov-2026 11:45 CET

Description:
  All YAML-mapped configuration structs for sdproxy. Covers every top-level
  config section: server, logging, cache, identity, upstreams, routes,
  domain_routes, rtype/domain policy, parental groups, categories, webui,
  and spoofed records (RRs). Also provides config minimization, full clean
  and embedded reference config output helpers.

Changes:
  1.100.0 - [FEAT] Added `DoH3FallbackThreshold` (`doh3_fallback_threshold`) under
            `server:` and per-group `upstreams:` to support sticky downgrade from
            DoH3 to standard DoH after N consecutive errors when standard DoH is
            available on the same server.
  1.99.2  - [CLEANUP] Removed redundant `len(userDoc.Content[0].Content) >= 0`
            condition in `UpdateConfigYAML`.
  1.99.1  - [FIX] Fixed `c.Server.RateLimit.PenaltyBox.StrikeThreshold` field path
            in `CleanConfigYAML`.
  1.99.0  - [FIX] Stripped documented default `max_tracked_ips: 1000` (as well as
            legacy `100000`) under `server.rate_limit` in `CleanConfigYAML`.
  1.98.0  - [FEAT] Added `"proximity"` to valid `cache.answer_sort` values in
            `validateConfig`.
  1.97.0  - [FEAT] Added `FullCleanConfigYAML` to support `-F` / `--full-clean-config`,
            emitting all configuration options (including default values) in exact
            canonical section and key order with zero comments and single blank-line
            top-level section spacing.
  1.96.0  - [FEAT/FIX] Overhauled `UpdateConfigYAML` (`-U` / `--update-config`) and
            `CleanConfigYAML` (`-C` / `--clean-config`).
  1.95.0  - [FIX] Guarded `[WARN]` logs in `validateConfig` with `!quietInit` so
            one-shot CLI commands (`--test`, `--clean-config`, `--update-config`)
            never emit startup runtime warnings to stderr or pollute stdout.
  1.94.0  - [FEAT/FIX] Reordered `Config` struct fields to match the exact section
            and key order of `full_reference_config.yaml`.
  1.93.0  - [SECURITY/FEAT] Added configurable cache-poisoning defense options
            under `server:` and per-group `upstreams:`.
*/

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

//go:embed full_reference_config.yaml
var FullReferenceConfigYAML string

// quietInit suppresses `[WARN]` log lines in `validateConfig` when running
// one-shot CLI operations (`--test`, `--clean-config`, `--full-clean-config`, `--update-config`).
var quietInit bool

// ---------------------------------------------------------------------------
// Regex helpers for domain_policy and rrs
// ---------------------------------------------------------------------------

func isRegexKey(s string) bool {
	return len(s) >= 2 && s[0] == '/' && s[len(s)-1] == '/'
}

func compileDomainRegex(s string) (*regexp.Regexp, error) {
	if !isRegexKey(s) {
		return nil, fmt.Errorf("regex key %q must start and end with '/'", s)
	}
	pattern := s[1 : len(s)-1]
	if pattern == "" {
		return nil, fmt.Errorf("empty regex pattern in %q", s)
	}
	pattern = strings.ReplaceAll(pattern, `\/`, `/`)
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", s, err)
	}
	return re, nil
}

func sanitizeYAMLRegexEscapes(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data) + 64)

	i := 0
	n := len(data)
	for i < n {
		c := data[i]

		if c == '#' && (i == 0 || data[i-1] == ' ' || data[i-1] == '\t' || data[i-1] == '\n' || data[i-1] == '\r') {
			for i < n && data[i] != '\n' {
				out.WriteByte(data[i])
				i++
			}
			continue
		}

		if c == '\'' {
			out.WriteByte(c)
			i++
			for i < n {
				out.WriteByte(data[i])
				if data[i] == '\'' {
					if i+1 < n && data[i+1] == '\'' {
						i++
						out.WriteByte(data[i])
						i++
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		}

		if c == '"' {
			start := i
			i++
			for i < n {
				if data[i] == '\\' {
					if i+1 < n && data[i+1] != '\n' && data[i+1] != '\r' {
						i += 2
						continue
					}
					i++
					continue
				}
				if data[i] == '"' || data[i] == '\n' {
					break
				}
				i++
			}
			if i < n && data[i] == '"' {
				content := data[start+1 : i]
				trimmed := bytes.TrimSpace(content)
				if len(trimmed) >= 2 && trimmed[0] == '/' && trimmed[len(trimmed)-1] == '/' {
					out.WriteByte('"')
					for j := 0; j < len(content); j++ {
						if content[j] == '\\' {
							if j+1 < len(content) {
								next := content[j+1]
								switch next {
								case '\\', '"':
									out.WriteByte('\\')
									out.WriteByte(next)
									j++
								default:
									out.WriteByte('\\')
									out.WriteByte('\\')
									out.WriteByte(next)
									j++
								}
							} else {
								out.WriteByte('\\')
								out.WriteByte('\\')
							}
						} else {
							out.WriteByte(content[j])
						}
					}
					out.WriteByte('"')
					i++
					continue
				}
				out.Write(data[start : i+1])
				i++
				continue
			}
			out.Write(data[start:i])
			continue
		}

		out.WriteByte(c)
		i++
	}

	return out.Bytes()
}

func splitDomainPolicyKeys(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var out []string
	n := len(trimmed)
	i := 0
	for i < n {
		for i < n && (trimmed[i] == ' ' || trimmed[i] == '\t' || trimmed[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		if trimmed[i] == '/' {
			start := i
			j := i + 1
			inCharClass := false
			closed := false
			for j < n {
				if trimmed[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if trimmed[j] == '[' && !inCharClass {
					inCharClass = true
					j++
					continue
				}
				if trimmed[j] == ']' && inCharClass {
					inCharClass = false
					j++
					continue
				}
				if trimmed[j] == '/' && !inCharClass {
					j++
					closed = true
					break
				}
				j++
			}
			if closed {
				for j < n && trimmed[j] != ',' {
					j++
				}
				tok := strings.TrimSpace(trimmed[start:j])
				if tok != "" {
					out = append(out, tok)
				}
				i = j
				continue
			}
		}

		start := i
		for i < n && trimmed[i] != ',' {
			i++
		}
		tok := strings.TrimSpace(trimmed[start:i])
		if tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ACLConfig
// ---------------------------------------------------------------------------

type ACLConfig struct {
	Deny  []string `yaml:"deny,omitempty"`
	Allow []string `yaml:"allow,omitempty"`
}

// ---------------------------------------------------------------------------
// ECSConfig (EDNS0 Client Subnet)
// ---------------------------------------------------------------------------

type ECSConfig struct {
	Action   string `yaml:"action,omitempty"`
	IPv4Mask int    `yaml:"ipv4_mask,omitempty"`
	IPv6Mask int    `yaml:"ipv6_mask,omitempty"`
}

// ---------------------------------------------------------------------------
// SubdomainLimitConfig
// ---------------------------------------------------------------------------

type SubdomainLimitConfig struct {
	Enabled             bool     `yaml:"enabled,omitempty"`
	Threshold           int      `yaml:"threshold,omitempty"`
	WindowMinutes       int      `yaml:"window_minutes,omitempty"`
	Action              string   `yaml:"action,omitempty"`
	MaxTrackedApexes    int      `yaml:"max_tracked_apexes,omitempty"`
	ExemptSharedHosting bool     `yaml:"exempt_shared_hosting,omitempty"`
	Exempt              []string `yaml:"exempt,omitempty"`
}

func mergeSubdomainLimitConfig(dst *SubdomainLimitConfig, src SubdomainLimitConfig) {
	if src.Enabled {
		dst.Enabled = true
	}
	if src.Threshold > 0 && dst.Threshold == 0 {
		dst.Threshold = src.Threshold
	}
	if src.WindowMinutes > 0 && dst.WindowMinutes == 0 {
		dst.WindowMinutes = src.WindowMinutes
	}
	if src.Action != "" && dst.Action == "" {
		dst.Action = src.Action
	}
	if src.MaxTrackedApexes > 0 && dst.MaxTrackedApexes == 0 {
		dst.MaxTrackedApexes = src.MaxTrackedApexes
	}
	if src.ExemptSharedHosting {
		dst.ExemptSharedHosting = true
	}
	if len(src.Exempt) > 0 {
		dst.Exempt = append(dst.Exempt, src.Exempt...)
	}
}

// ---------------------------------------------------------------------------
// RouteConfig / ParsedRoute
// ---------------------------------------------------------------------------

type RouteConfig struct {
	Rcode        string `yaml:"rcode,omitempty"`
	Upstream     string `yaml:"upstream,omitempty"`
	ClientName   string `yaml:"client_name,omitempty"`
	BypassLocal  bool   `yaml:"bypass_local,omitempty"`
	BypassGlobal bool   `yaml:"bypass_global,omitempty"`
	Group        string `yaml:"group,omitempty"`
	Force        bool   `yaml:"force,omitempty"`
	ForceAnd     bool   `yaml:"force-and,omitempty"`
}

type ParsedRoute struct {
	HasRcode     bool
	Rcode        int
	Upstream     string
	ClientName   string
	BypassLocal  bool
	BypassGlobal bool
	Force        bool
	ForceAnd     bool
}

// ---------------------------------------------------------------------------
// DomainRouteConfig / domainRouteEntry
// ---------------------------------------------------------------------------

type DomainRouteConfig struct {
	Upstream    string `yaml:"upstream,omitempty"`
	BypassLocal bool   `yaml:"bypass_local,omitempty"`
}

func (d *DomainRouteConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		d.Upstream = value.Value
		return nil
	case yaml.MappingNode:
		type plain DomainRouteConfig
		return value.Decode((*plain)(d))
	default:
		return fmt.Errorf("domain_routes: expected string or map, got %s", value.Tag)
	}
}

func (d DomainRouteConfig) MarshalYAML() (interface{}, error) {
	if !d.BypassLocal {
		return d.Upstream, nil
	}
	type plain DomainRouteConfig
	return plain(d), nil
}

type domainRouteEntry struct {
	upstream    string
	bypassLocal bool
}

// ---------------------------------------------------------------------------
// UpstreamGroupConfig
// ---------------------------------------------------------------------------

type UpstreamGroupConfig struct {
	Strategy              string    `yaml:"strategy,omitempty"`
	Preference            string    `yaml:"preference,omitempty"`
	Mode                  string    `yaml:"mode,omitempty"`
	IgnoreQnameLabels     bool      `yaml:"ignore_qname_labels,omitempty"`
	DNS0x20               *bool     `yaml:"dns_0x20,omitempty"`
	DNSCookies            *bool     `yaml:"dns_cookies,omitempty"`
	RequireDNSSECAD       *bool     `yaml:"require_dnssec_ad,omitempty"`
	DoH3FallbackThreshold *int      `yaml:"doh3_fallback_threshold,omitempty"`
	ECS                   ECSConfig `yaml:"ecs,omitempty"`
	Servers               []string  `yaml:"servers,omitempty"`
}

func (u *UpstreamGroupConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.SequenceNode {
		return value.Decode(&u.Servers)
	} else if value.Kind == yaml.MappingNode {
		type plain UpstreamGroupConfig
		return value.Decode((*plain)(u))
	}
	return fmt.Errorf("upstreams: expected list of strings or map, got %v", value.Kind)
}

func (u UpstreamGroupConfig) MarshalYAML() (interface{}, error) {
	if u.Strategy == "" && u.Preference == "" && u.Mode == "" && !u.IgnoreQnameLabels &&
		u.DNS0x20 == nil && u.DNSCookies == nil && u.RequireDNSSECAD == nil &&
		u.DoH3FallbackThreshold == nil &&
		u.ECS.Action == "" && u.ECS.IPv4Mask == 0 && u.ECS.IPv6Mask == 0 {
		return u.Servers, nil
	}
	type plain UpstreamGroupConfig
	return plain(u), nil
}

// ---------------------------------------------------------------------------
// ScheduleList
// ---------------------------------------------------------------------------

type ScheduleList []string

func (sl *ScheduleList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Value != "" {
			*sl = ScheduleList{value.Value}
		}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := value.Decode(&list); err != nil {
			return err
		}
		*sl = ScheduleList(list)
		return nil
	default:
		return fmt.Errorf("schedule: expected a string or a list of strings, got %s", value.Tag)
	}
}

func (sl ScheduleList) MarshalYAML() (interface{}, error) {
	if len(sl) == 1 {
		return sl[0], nil
	}
	return []string(sl), nil
}

// ---------------------------------------------------------------------------
// GroupConfig
// ---------------------------------------------------------------------------

type GroupConfig struct {
	Upstream       string                 `yaml:"upstream,omitempty"`
	BypassLocal    bool                   `yaml:"bypass_local,omitempty"`
	Schedule       ScheduleList           `yaml:"schedule,omitempty"`
	BlockTTL       int                    `yaml:"block_ttl,omitempty"`
	BudgetTracking string                 `yaml:"budget_tracking,omitempty"`
	RRs            map[string]interface{} `yaml:"rrs,omitempty"`
	Budget         map[string]string      `yaml:"budget,omitempty"`
}

// ---------------------------------------------------------------------------
// CategoryConfig
// ---------------------------------------------------------------------------

type CategoryConfig struct {
	ListURLs      []string `yaml:"-"`
	IdlePause     string   `yaml:"idle_pause,omitempty"`
	SessionWindow string   `yaml:"session_window,omitempty"`
	Add           []string `yaml:"add,omitempty"`
	Remove        []string `yaml:"remove,omitempty"`
}

func (c *CategoryConfig) UnmarshalYAML(value *yaml.Node) error {
	type plain CategoryConfig
	type withURL struct {
		plain    `yaml:",inline"`
		Source   yaml.Node `yaml:"source"`
		ListURL  string    `yaml:"list_url"`
		ListURLs []string  `yaml:"list_urls"`
	}
	var w withURL
	if err := value.Decode(&w); err != nil {
		return err
	}
	*c = CategoryConfig(w.plain)

	switch {
	case w.Source.Kind == yaml.ScalarNode && w.Source.Value != "":
		c.ListURLs = []string{w.Source.Value}
	case w.Source.Kind == yaml.SequenceNode:
		var list []string
		if err := w.Source.Decode(&list); err != nil {
			return fmt.Errorf("source: %w", err)
		}
		c.ListURLs = list
	case len(w.ListURLs) > 0:
		c.ListURLs = w.ListURLs
	case w.ListURL != "":
		c.ListURLs = []string{w.ListURL}
	}
	return nil
}

func (c CategoryConfig) MarshalYAML() (interface{}, error) {
	type outCat struct {
		Source        interface{} `yaml:"source,omitempty"`
		IdlePause     string      `yaml:"idle_pause,omitempty"`
		SessionWindow string      `yaml:"session_window,omitempty"`
		Add           []string    `yaml:"add,omitempty"`
		Remove        []string    `yaml:"remove,omitempty"`
	}
	var src interface{}
	if len(c.ListURLs) == 1 {
		src = c.ListURLs[0]
	} else if len(c.ListURLs) > 1 {
		src = c.ListURLs
	}
	return outCat{
		Source:        src,
		IdlePause:     c.IdlePause,
		SessionWindow: c.SessionWindow,
		Add:           c.Add,
		Remove:        c.Remove,
	}, nil
}

// ---------------------------------------------------------------------------
// ParentalConfig
// ---------------------------------------------------------------------------

type ParentalConfig struct {
	FastStart                    bool                      `yaml:"fast_start,omitempty"`
	ForcedTTL                    int                       `yaml:"forced_ttl,omitempty"`
	BlockTTL                     int                       `yaml:"block_ttl,omitempty"`
	TickerInterval               int                       `yaml:"ticker_interval,omitempty"`
	DefaultIdlePause             string                    `yaml:"default_idle_pause,omitempty"`
	DefaultSessionWindow         string                    `yaml:"default_session_window,omitempty"`
	TimeOffsetHours              int                       `yaml:"time_offset_hours,omitempty"`
	SnapshotDir                  string                    `yaml:"snapshot_dir,omitempty"`
	Consolidation                *bool                     `yaml:"consolidation,omitempty"`
	SynthesiseParents            *bool                     `yaml:"synthesise_parents,omitempty"`
	RemoveRedundantSubdomains    *bool                     `yaml:"remove_redundant_subdomains,omitempty"`
	StripServiceLabels           *bool                     `yaml:"strip_service_labels,omitempty"`
	ParentConsolidationThreshold int                       `yaml:"parent_consolidation_threshold,omitempty"`
	ConsolidationHomogeneityPct  int                       `yaml:"consolidation_homogeneity_pct,omitempty"`
	Categories                   map[string]CategoryConfig `yaml:"categories,omitempty"`
}

// ---------------------------------------------------------------------------
// WebUIConfig
// ---------------------------------------------------------------------------

type WebUIConfig struct {
	Enabled     bool      `yaml:"enabled,omitempty"`
	Listen      string    `yaml:"listen,omitempty"`
	ListenHTTP  []string  `yaml:"listen_http,omitempty"`
	ListenHTTPS []string  `yaml:"listen_https,omitempty"`
	ForceHTTPS  bool      `yaml:"force_https,omitempty"`
	Password    string    `yaml:"password,omitempty"`
	APIToken    string    `yaml:"api_token,omitempty"`
	ACL         ACLConfig `yaml:"acl,omitempty"`

	LoginRatelimit struct {
		Enabled        bool `yaml:"enabled,omitempty"`
		MaxAttempts    int  `yaml:"max_attempts,omitempty"`
		LockoutMinutes int  `yaml:"lockout_minutes,omitempty"`
	} `yaml:"login_ratelimit,omitempty"`

	StatsEnabled          bool   `yaml:"stats_enabled,omitempty"`
	StatsRefreshSec       int    `yaml:"stats_refresh_sec,omitempty"`
	StatsTopN             int    `yaml:"stats_top_n,omitempty"`
	StatsGraphsEnabled    bool   `yaml:"stats_graphs_enabled,omitempty"`
	HistoryDir            string `yaml:"history_dir,omitempty"`
	HistoryRetentionHours int    `yaml:"history_retention_hours,omitempty"`
	HistorySaveInterval   string `yaml:"history_save_interval,omitempty"`
}

// ---------------------------------------------------------------------------
// Top-level Config (Ordered identically to full_reference_config.yaml)
// ---------------------------------------------------------------------------

type Config struct {
	Server struct {
		FastStart         bool      `yaml:"fast_start,omitempty"`
		ListenUDP         []string  `yaml:"listen_udp,omitempty"`
		ListenTCP         []string  `yaml:"listen_tcp,omitempty"`
		ListenDoT         []string  `yaml:"listen_dot,omitempty"`
		ListenDoH         []string  `yaml:"listen_doh,omitempty"`
		ListenDoQ         []string  `yaml:"listen_doq,omitempty"`
		SupportIPVersion  string    `yaml:"support_ip_version,omitempty"`
		BlockAction       string    `yaml:"block_action,omitempty"`
		BlockIPs          []string  `yaml:"block_ips,omitempty"`
		UDPWorkers        int       `yaml:"udp_workers,omitempty"`
		TLSCert           string    `yaml:"tls_cert,omitempty"`
		TLSKey            string    `yaml:"tls_key,omitempty"`
		ECHConfigList     string    `yaml:"ech_config_list,omitempty"`
		ECHKey            string    `yaml:"ech_key,omitempty"`
		MemoryLimitMB     int       `yaml:"memory_limit_mb,omitempty"`
		MaxTCPConnections int       `yaml:"max_tcp_connections,omitempty"`
		ACL               ACLConfig `yaml:"acl,omitempty"`

		RateLimit struct {
			Enabled          bool     `yaml:"enabled,omitempty"`
			QPS              float64  `yaml:"qps,omitempty"`
			Burst            float64  `yaml:"burst,omitempty"`
			IPv4PrefixLength int      `yaml:"ipv4_prefix_length,omitempty"`
			IPv6PrefixLength int      `yaml:"ipv6_prefix_length,omitempty"`
			MaxTrackedIPs    int      `yaml:"max_tracked_ips,omitempty"`
			Exempt           []string `yaml:"exempt,omitempty"`

			PenaltyBox struct {
				Enabled         bool `yaml:"enabled,omitempty"`
				StrikeThreshold int  `yaml:"strike_threshold,omitempty"`
				BanDurationMin  int  `yaml:"ban_duration_min,omitempty"`
			} `yaml:"penalty_box,omitempty"`
		} `yaml:"rate_limit,omitempty"`

		Exfiltration struct {
			Enabled           bool     `yaml:"enabled,omitempty"`
			MinThresholdBPS   float64  `yaml:"min_threshold_bps,omitempty"`
			AnomalyMultiplier float64  `yaml:"anomaly_multiplier,omitempty"`
			Action            string   `yaml:"action,omitempty"`
			IPv4PrefixLength  int      `yaml:"ipv4_prefix_length,omitempty"`
			IPv6PrefixLength  int      `yaml:"ipv6_prefix_length,omitempty"`
			MaxTrackedIPs     int      `yaml:"max_tracked_ips,omitempty"`
			Exempt            []string `yaml:"exempt,omitempty"`

			PenaltyBox struct {
				Enabled         bool `yaml:"enabled,omitempty"`
				StrikeThreshold int  `yaml:"strike_threshold,omitempty"`
				BanDurationMin  int  `yaml:"ban_duration_min,omitempty"`
			} `yaml:"penalty_box,omitempty"`
		} `yaml:"exfiltration,omitempty"`

		SubdomainLimit   SubdomainLimitConfig `yaml:"subdomain_limit,omitempty"`
		SubdomainLimiter SubdomainLimitConfig `yaml:"subdomain_limiter,omitempty"`
		SubnetLimiter    SubdomainLimitConfig `yaml:"subnet_limiter,omitempty"`
		SubnetLimit      SubdomainLimitConfig `yaml:"subnet_limit,omitempty"`

		ForSale string `yaml:"for_sale,omitempty"`
		Parked  string `yaml:"parked,omitempty"`

		DGA struct {
			Enabled   bool    `yaml:"enabled,omitempty"`
			Threshold float64 `yaml:"threshold,omitempty"`
			Action    string  `yaml:"action,omitempty"`
		} `yaml:"dga,omitempty"`

		SearchDomainLeakPrevention *bool     `yaml:"search_domain_leak_prevention,omitempty"`
		QnameMinLabels             int       `yaml:"qname_min_labels,omitempty"`
		QnameMaxLabels             int       `yaml:"qname_max_labels,omitempty"`
		TrustedProxies             []string  `yaml:"trusted_proxies,omitempty"`
		ECS                        ECSConfig `yaml:"ecs,omitempty"`
		RebindingProtection        bool      `yaml:"rebinding_protection,omitempty"`
		FilterAAAA                 bool      `yaml:"filter_aaaa,omitempty"`
		FilterIPs                  bool      `yaml:"filter_ips,omitempty"`
		StrictPTR                  bool      `yaml:"strict_ptr,omitempty"`
		FlattenCNAME               bool      `yaml:"flatten_cname,omitempty"`
		TargetName                 bool      `yaml:"target_name,omitempty"`
		MinimizeAnswer             bool      `yaml:"minimize_answer,omitempty"`
		BlockObsoleteQtypes        bool      `yaml:"block_obsolete_qtypes,omitempty"`
		DNS0x20                    bool      `yaml:"dns_0x20,omitempty"`
		DNSCookies                 bool      `yaml:"dns_cookies,omitempty"`
		RequireDNSSECAD            bool      `yaml:"require_dnssec_ad,omitempty"`
		AllowCDBit                 bool      `yaml:"allow_cd_bit,omitempty"`

		DDR struct {
			Enabled        bool     `yaml:"enabled,omitempty"`
			HostnameSource string   `yaml:"hostname_source,omitempty"`
			Hostnames      []string `yaml:"hostnames,omitempty"`
			IPv4           []string `yaml:"ipv4,omitempty"`
			IPv6           []string `yaml:"ipv6,omitempty"`
		} `yaml:"ddr,omitempty"`

		UpstreamSelection     string   `yaml:"upstream_selection,omitempty"`
		UpstreamStaggerMs     int      `yaml:"upstream_stagger_ms,omitempty"`
		UpstreamTimeoutMs     int      `yaml:"upstream_timeout_ms,omitempty"`
		MaxSecureUpstreams    int      `yaml:"max_secure_upstreams,omitempty"`
		BootstrapServers      []string `yaml:"bootstrap_servers,omitempty"`
		UseUpstreamECH        string   `yaml:"use_upstream_ech,omitempty"`
		HostnameECH           string   `yaml:"hostname_ech,omitempty"`
		UpgradeDoH3           bool     `yaml:"upgrade_doh3,omitempty"`
		DoH3FallbackThreshold int      `yaml:"doh3_fallback_threshold,omitempty"`
		PolicyCacheDir        string   `yaml:"policy_cache_dir,omitempty"`
		PolicyPollInterval    string   `yaml:"policy_poll_interval,omitempty"`
		UserAgent             string   `yaml:"user_agent,omitempty"`
		SyntheticTTL          int      `yaml:"synthetic_ttl,omitempty"`
	} `yaml:"server,omitempty"`

	Logging struct {
		Simple        *bool `yaml:"simple,omitempty"`
		StripTime     bool  `yaml:"strip_time,omitempty"`
		LogQueries    *bool `yaml:"log_queries,omitempty"`
		LogASNDetails bool  `yaml:"log_asn_details,omitempty"`
		LogStrategy   bool  `yaml:"log_strategy,omitempty"`
		LogParental   *bool `yaml:"log_parental,omitempty"`
		LogIdentity   *bool `yaml:"log_identity,omitempty"`
		LogCaching    *bool `yaml:"log_caching,omitempty"`
		LogDDR        *bool `yaml:"log_ddr,omitempty"`
		LogTLS        *bool `yaml:"log_tls,omitempty"`
		LogSystem     *bool `yaml:"log_system,omitempty"`
		LogWebUI      *bool `yaml:"log_webui,omitempty"`
		LogRouting    *bool `yaml:"log_routing,omitempty"`
	} `yaml:"logging,omitempty"`

	Cache struct {
		Enabled               bool   `yaml:"enabled,omitempty"`
		Size                  int    `yaml:"size,omitempty"`
		Persist               bool   `yaml:"persist,omitempty"`
		PersistFile           string `yaml:"persist_file,omitempty"`
		PersistSaveInterval   string `yaml:"persist_save_interval,omitempty"`
		MinTTL                int    `yaml:"min_ttl,omitempty"`
		MaxTTL                int    `yaml:"max_ttl,omitempty"`
		NegativeTTL           int    `yaml:"negative_ttl,omitempty"`
		StaleTTL              int    `yaml:"stale_ttl,omitempty"`
		ServeStaleInfinite    bool   `yaml:"serve_stale_infinite,omitempty"`
		PrefetchBefore        int    `yaml:"prefetch_before,omitempty"`
		PrefetchMinHits       int    `yaml:"prefetch_min_hits,omitempty"`
		SweepIntervalS        int    `yaml:"sweep_interval_s,omitempty"`
		CacheSynthetic        bool   `yaml:"cache_synthetic,omitempty"`
		CacheLocalIdentity    bool   `yaml:"cache_local_identity,omitempty"`
		CacheUpstreamNegative bool   `yaml:"cache_upstream_negative,omitempty"`
		AnswerSort            string `yaml:"answer_sort,omitempty"`
	} `yaml:"cache,omitempty"`

	Identity struct {
		HostsFiles      []string `yaml:"hosts_files,omitempty"`
		DnsmasqLeases   []string `yaml:"dnsmasq_leases,omitempty"`
		IscLeases       []string `yaml:"isc_leases,omitempty"`
		KeaLeases       []string `yaml:"kea_leases,omitempty"`
		OdhcpdLeases    []string `yaml:"odhcpd_leases,omitempty"`
		IPInfoASN       []string `yaml:"ipinfo_asn,omitempty"`
		ASNCacheDir     string   `yaml:"asn_cache_dir,omitempty"`
		ASNPollInterval string   `yaml:"asn_poll_interval,omitempty"`
		ASNFastStart    bool     `yaml:"asn_fast_start,omitempty"`
		PollInterval    int      `yaml:"poll_interval,omitempty"`
	} `yaml:"identity,omitempty"`

	RRs map[string]interface{} `yaml:"rrs,omitempty"`

	RtypePolicy      map[string]string `yaml:"rtype_policy,omitempty"`
	RtypePolicyFiles map[string]string `yaml:"rtype_policy_files,omitempty"`

	DomainPolicy      map[string]string `yaml:"domain_policy,omitempty"`
	DomainPolicyFiles map[string]string `yaml:"domain_policy_files,omitempty"`
	DomainPolicyURLs  map[string]string `yaml:"domain_policy_urls,omitempty"`

	Upstreams map[string]UpstreamGroupConfig `yaml:"upstreams,omitempty"`

	Routes      map[string]RouteConfig `yaml:"routes,omitempty"`
	RoutesFiles map[string]RouteConfig `yaml:"routes_files,omitempty"`

	DomainRoutes      map[string]DomainRouteConfig `yaml:"domain_routes,omitempty"`
	DomainRoutesFiles map[string]DomainRouteConfig `yaml:"domain_routes_files,omitempty"`

	Groups   map[string]GroupConfig `yaml:"groups,omitempty"`
	Parental ParentalConfig         `yaml:"parental,omitempty"`
	WebUI    WebUIConfig            `yaml:"webui,omitempty"`
}

var cfg Config

func validateConfig() error {
	v := strings.ToLower(cfg.Server.SupportIPVersion)
	switch v {
	case "ipv4", "ipv6", "both":
		cfg.Server.SupportIPVersion = v
	default:
		cfg.Server.SupportIPVersion = "both"
	}

	vUseECH := strings.ToLower(cfg.Server.UseUpstreamECH)
	switch vUseECH {
	case "disable", "try", "strict":
		cfg.Server.UseUpstreamECH = vUseECH
	default:
		cfg.Server.UseUpstreamECH = "disable"
	}

	vHostnameECH := strings.ToLower(cfg.Server.HostnameECH)
	switch vHostnameECH {
	case "strict", "loose", "apex", "any":
		cfg.Server.HostnameECH = vHostnameECH
	default:
		cfg.Server.HostnameECH = "strict"
	}

	vDDRSource := strings.ToLower(cfg.Server.DDR.HostnameSource)
	switch vDDRSource {
	case "strict", "tls", "both":
		cfg.Server.DDR.HostnameSource = vDDRSource
	default:
		cfg.Server.DDR.HostnameSource = "strict"
	}

	if cfg.Server.UserAgent == "" {
		cfg.Server.UserAgent = "sdproxy/1.0"
	}

	if cfg.Server.MaxSecureUpstreams <= 0 {
		cfg.Server.MaxSecureUpstreams = 5
	}

	if cfg.Server.DoH3FallbackThreshold < 0 {
		cfg.Server.DoH3FallbackThreshold = 0
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

	if cfg.Server.Exfiltration.Enabled {
		if cfg.Server.Exfiltration.MinThresholdBPS <= 0 {
			cfg.Server.Exfiltration.MinThresholdBPS = 1500
		}
		if cfg.Server.Exfiltration.AnomalyMultiplier <= 0 {
			cfg.Server.Exfiltration.AnomalyMultiplier = 3.0
		}
		if cfg.Server.Exfiltration.Action == "" {
			cfg.Server.Exfiltration.Action = "LOG"
		} else {
			cfg.Server.Exfiltration.Action = strings.ToUpper(cfg.Server.Exfiltration.Action)
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

	if cfg.Server.SubdomainLimit.Enabled {
		if cfg.Server.SubdomainLimit.Threshold <= 0 {
			cfg.Server.SubdomainLimit.Threshold = 100
		}
		if cfg.Server.SubdomainLimit.WindowMinutes <= 0 {
			cfg.Server.SubdomainLimit.WindowMinutes = 60
		}
		if cfg.Server.SubdomainLimit.Action == "" {
			cfg.Server.SubdomainLimit.Action = "BLOCK"
		} else {
			cfg.Server.SubdomainLimit.Action = strings.ToUpper(cfg.Server.SubdomainLimit.Action)
		}
		if cfg.Server.SubdomainLimit.MaxTrackedApexes <= 0 {
			cfg.Server.SubdomainLimit.MaxTrackedApexes = 10000
		}
	}

	ecsAction := strings.ToLower(cfg.Server.ECS.Action)
	if ecsAction != "add" && ecsAction != "pass" {
		ecsAction = "remove"
	}
	cfg.Server.ECS.Action = ecsAction
	if cfg.Server.ECS.IPv4Mask <= 0 || cfg.Server.ECS.IPv4Mask > 32 {
		cfg.Server.ECS.IPv4Mask = 24
	}
	if cfg.Server.ECS.IPv6Mask <= 0 || cfg.Server.ECS.IPv6Mask > 128 {
		cfg.Server.ECS.IPv6Mask = 56
	}

	if cfg.Server.QnameMinLabels == 0 {
		cfg.Server.QnameMinLabels = 1
	}
	if cfg.Server.QnameMaxLabels == 0 {
		cfg.Server.QnameMaxLabels = 20
	}
	if cfg.Server.QnameMinLabels < 1 {
		cfg.Server.QnameMinLabels = 1
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
	}

	if cfg.Cache.MinTTL < 0 || cfg.Cache.MaxTTL < 0 || cfg.Cache.NegativeTTL < 0 ||
		cfg.Cache.StaleTTL < 0 || cfg.Cache.PrefetchBefore < 0 ||
		cfg.Cache.PrefetchMinHits < 0 || cfg.Cache.SweepIntervalS < 0 {
		return fmt.Errorf("cache TTL, prefetch, and sweep settings must not be negative")
	}
	if cfg.Cache.MaxTTL > 0 && cfg.Cache.MinTTL > cfg.Cache.MaxTTL {
		return fmt.Errorf("cache.min_ttl (%d) cannot exceed cache.max_ttl (%d)", cfg.Cache.MinTTL, cfg.Cache.MaxTTL)
	}

	if cfg.Cache.Persist {
		if cfg.Cache.PersistFile == "" {
			cfg.Cache.PersistFile = "/var/lib/sdproxy/dns_cache.bin"
		}
		if cfg.Cache.PersistSaveInterval == "" {
			cfg.Cache.PersistSaveInterval = "5m"
		}
		if cfg.Cache.PersistSaveInterval != "0" && cfg.Cache.PersistSaveInterval != "0s" {
			interval, err := time.ParseDuration(cfg.Cache.PersistSaveInterval)
			if err != nil || interval <= 0 {
				return fmt.Errorf("cache.persist_save_interval %q must be a positive duration or 0s", cfg.Cache.PersistSaveInterval)
			}
		}
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

	sortMethod := strings.ToLower(cfg.Cache.AnswerSort)
	switch sortMethod {
	case "", "none", "round-robin", "random", "ip-sort", "proximity":
		cfg.Cache.AnswerSort = sortMethod
	default:
		if !quietInit {
			log.Printf("[WARN] Invalid cache.answer_sort %q — falling back to 'none'", sortMethod)
		}
		cfg.Cache.AnswerSort = "none"
	}

	if len(cfg.Parental.Categories) > 0 {
		normCats := make(map[string]CategoryConfig, len(cfg.Parental.Categories))
		for k, v := range cfg.Parental.Categories {
			normCats[strings.ToLower(k)] = v
		}
		cfg.Parental.Categories = normCats
	}

	if len(cfg.Groups) > 0 {
		normGroups := make(map[string]GroupConfig, len(cfg.Groups))
		for k, v := range cfg.Groups {
			kLower := strings.ToLower(k)
			if v.Upstream != "" {
				v.Upstream = strings.ToLower(v.Upstream)
			}
			if len(v.Budget) > 0 {
				normBudget := make(map[string]string, len(v.Budget))
				for bk, bv := range cfg.Groups[k].Budget {
					normBudget[strings.ToLower(bk)] = bv
				}
				v.Budget = normBudget
			}
			normGroups[kLower] = v
		}
		cfg.Groups = normGroups
	} else {
		cfg.Groups = make(map[string]GroupConfig)
	}

	if len(cfg.Upstreams) > 0 {
		normUpstreams := make(map[string]UpstreamGroupConfig, len(cfg.Upstreams))
		for k, v := range cfg.Upstreams {
			kLower := strings.ToLower(k)
			v.Strategy = strings.ToLower(v.Strategy)
			v.Preference = strings.ToLower(v.Preference)
			v.Mode = strings.ToLower(v.Mode)
			if v.DoH3FallbackThreshold != nil && *v.DoH3FallbackThreshold < 0 {
				zero := 0
				v.DoH3FallbackThreshold = &zero
			}
			normUpstreams[kLower] = v
		}
		cfg.Upstreams = normUpstreams
	} else {
		cfg.Upstreams = make(map[string]UpstreamGroupConfig)
	}

	hasConsolidate := false
	for _, v := range cfg.Upstreams {
		if strings.ToLower(v.Strategy) == "secure" && strings.ToLower(v.Preference) == "consolidate" {
			hasConsolidate = true
		}
	}
	if hasConsolidate && !cfg.Server.FlattenCNAME {
		cfg.Server.FlattenCNAME = true
		autoEnabledFlattenCNAME = true
	}

	if cfg.Routes == nil {
		cfg.Routes = make(map[string]RouteConfig)
	}
	for k, v := range cfg.Routes {
		if v.Group != "" {
			v.Group = strings.ToLower(v.Group)
		}
		if v.Upstream != "" {
			v.Upstream = strings.ToLower(v.Upstream)
		}
		cfg.Routes[k] = v
	}
	if cfg.RoutesFiles == nil {
		cfg.RoutesFiles = make(map[string]RouteConfig)
	}
	for k, v := range cfg.RoutesFiles {
		if v.Group != "" {
			v.Group = strings.ToLower(v.Group)
		}
		if v.Upstream != "" {
			v.Upstream = strings.ToLower(v.Upstream)
		}
		cfg.RoutesFiles[k] = v
	}

	if cfg.DomainRoutes == nil {
		cfg.DomainRoutes = make(map[string]DomainRouteConfig)
	}
	for k, v := range cfg.DomainRoutes {
		if v.Upstream != "" {
			v.Upstream = strings.ToLower(v.Upstream)
		}
		cfg.DomainRoutes[k] = v
	}
	if cfg.DomainRoutesFiles == nil {
		cfg.DomainRoutesFiles = make(map[string]DomainRouteConfig)
	}
	for k, v := range cfg.DomainRoutesFiles {
		if v.Upstream != "" {
			v.Upstream = strings.ToLower(v.Upstream)
		}
		cfg.DomainRoutesFiles[k] = v
	}

	for rawKey := range cfg.RRs {
		for _, tok := range splitDomainPolicyKeys(rawKey) {
			if isRegexKey(tok) {
				if _, err := compileDomainRegex(tok); err != nil {
					return fmt.Errorf("rrs: %w", err)
				}
			}
		}
	}
	for grpName, grpCfg := range cfg.Groups {
		for rawKey := range grpCfg.RRs {
			for _, tok := range splitDomainPolicyKeys(rawKey) {
				if isRegexKey(tok) {
					if _, err := compileDomainRegex(tok); err != nil {
						return fmt.Errorf("groups.%s.rrs: %w", grpName, err)
					}
				}
			}
		}
	}

	for rawKey := range cfg.DomainPolicy {
		for _, tok := range splitDomainPolicyKeys(rawKey) {
			if isRegexKey(tok) {
				if _, err := compileDomainRegex(tok); err != nil {
					return fmt.Errorf("domain_policy: %w", err)
				}
			}
		}
	}
	for filePath := range cfg.DomainPolicyFiles {
		lines, err := readConfigListFile(filePath)
		if err != nil {
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

	return nil
}

// ---------------------------------------------------------------------------
// Update / Complement Config with Full Documentation & Canonical Ordering
// ---------------------------------------------------------------------------

var userDefinedMapPaths = map[string]bool{
	"upstreams":           true,
	"routes":              true,
	"routes_files":        true,
	"domain_routes":       true,
	"domain_routes_files": true,
	"rtype_policy":        true,
	"rtype_policy_files":  true,
	"domain_policy":       true,
	"domain_policy_files": true,
	"domain_policy_urls":  true,
	"rrs":                 true,
	"groups":              true,
	"parental.categories": true,
}

func UpdateConfigYAML(userYAMLBytes []byte) ([]byte, error) {
	var refDoc yaml.Node
	if err := yaml.Unmarshal([]byte(FullReferenceConfigYAML), &refDoc); err != nil {
		return nil, fmt.Errorf("parse reference config: %w", err)
	}

	var userDoc yaml.Node
	if err := yaml.Unmarshal(userYAMLBytes, &userDoc); err != nil {
		return nil, fmt.Errorf("parse user config: %w", err)
	}

	if len(refDoc.Content) == 0 || refDoc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("reference config is not a YAML mapping document")
	}

	refRoot := refDoc.Content[0]

	var userRoot *yaml.Node
	if len(userDoc.Content) > 0 && userDoc.Content[0].Kind == yaml.MappingNode {
		userRoot = userDoc.Content[0]
		stripAllYAMLComments(userRoot)
		normalizeUserConfigAliases(userRoot)
	} else {
		userRoot = &yaml.Node{Kind: yaml.MappingNode}
	}

	clearUnsetUserDefinedMaps(refRoot, userRoot)

	mergeYAMLMappingNodes(refRoot, userRoot, "")

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&refDoc); err != nil {
		return nil, err
	}
	_ = enc.Close()

	return formatUpdatedYAMLSpacing(buf.Bytes()), nil
}

func FullCleanConfigYAML(userYAMLBytes []byte) ([]byte, error) {
	var refDoc yaml.Node
	if err := yaml.Unmarshal([]byte(FullReferenceConfigYAML), &refDoc); err != nil {
		return nil, fmt.Errorf("parse reference config: %w", err)
	}

	var userDoc yaml.Node
	if err := yaml.Unmarshal(userYAMLBytes, &userDoc); err != nil {
		return nil, fmt.Errorf("parse user config: %w", err)
	}

	if len(refDoc.Content) == 0 || refDoc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("reference config is not a YAML mapping document")
	}

	refRoot := refDoc.Content[0]

	var userRoot *yaml.Node
	if len(userDoc.Content) > 0 && userDoc.Content[0].Kind == yaml.MappingNode {
		userRoot = userDoc.Content[0]
		stripAllYAMLComments(userRoot)
		normalizeUserConfigAliases(userRoot)
	} else {
		userRoot = &yaml.Node{Kind: yaml.MappingNode}
	}

	clearUnsetUserDefinedMaps(refRoot, userRoot)
	mergeYAMLMappingNodes(refRoot, userRoot, "")
	stripAllYAMLComments(&refDoc)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&refDoc); err != nil {
		return nil, err
	}
	_ = enc.Close()

	return formatCleanYAMLTopLevelSpacing(buf.Bytes()), nil
}

func stripAllYAMLComments(n *yaml.Node) {
	if n == nil {
		return
	}
	n.HeadComment = ""
	n.LineComment = ""
	n.FootComment = ""
	for _, child := range n.Content {
		stripAllYAMLComments(child)
	}
}

func clearUnsetUserDefinedMaps(refRoot, userRoot *yaml.Node) {
	if refRoot == nil || refRoot.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(refRoot.Content); i += 2 {
		rKey := refRoot.Content[i]
		rVal := refRoot.Content[i+1]

		if userDefinedMapPaths[rKey.Value] {
			if findYAMLMapKeyIndex(userRoot, rKey.Value) < 0 {
				if rKey.Value == "upstreams" && rVal.Kind == yaml.MappingNode {
					defIdx := findYAMLMapKeyIndex(rVal, "default")
					if defIdx >= 0 {
						rVal.Content = []*yaml.Node{rVal.Content[defIdx], rVal.Content[defIdx+1]}
					} else {
						rVal.Content = nil
						rVal.Style = yaml.FlowStyle
					}
				} else {
					rVal.Content = nil
					rVal.Style = yaml.FlowStyle
				}
			}
			continue
		}

		if rKey.Value == "parental" && rVal.Kind == yaml.MappingNode {
			catIdx := findYAMLMapKeyIndex(rVal, "categories")
			if catIdx >= 0 {
				var userHasCats bool
				if uParIdx := findYAMLMapKeyIndex(userRoot, "parental"); uParIdx >= 0 {
					uParVal := userRoot.Content[uParIdx+1]
					if findYAMLMapKeyIndex(uParVal, "categories") >= 0 {
						userHasCats = true
					}
				}
				if !userHasCats {
					catVal := rVal.Content[catIdx+1]
					catVal.Content = nil
					catVal.Style = yaml.FlowStyle
				}
			}
		}
	}
}

func formatUpdatedYAMLSpacing(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	var out []string

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# =====") && i > 0 {
			prevTrim := strings.TrimSpace(lines[i-1])
			if prevTrim != "" && !strings.HasPrefix(prevTrim, "# =====") && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
		}
		out = append(out, line)
	}

	res := strings.Join(out, "\n")
	if !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return []byte(res)
}

func normalizeUserConfigAliases(root *yaml.Node) {
	if root == nil || root.Kind != yaml.MappingNode {
		return
	}

	for i := 0; i+1 < len(root.Content); i += 2 {
		kNode := root.Content[i]
		vNode := root.Content[i+1]

		switch kNode.Value {
		case "server":
			if vNode.Kind == yaml.MappingNode {
				canonicalIdx := findYAMLMapKeyIndex(vNode, "subdomain_limit")
				for j := 0; j+1 < len(vNode.Content); {
					sk := vNode.Content[j]
					sv := vNode.Content[j+1]
					if sk.Value == "subdomain_limiter" || sk.Value == "subnet_limiter" || sk.Value == "subnet_limit" {
						if canonicalIdx < 0 {
							sk.Value = "subdomain_limit"
							canonicalIdx = j
							j += 2
						} else {
							mergeYAMLMappingNodes(vNode.Content[canonicalIdx+1], sv, "server.subdomain_limit")
							vNode.Content = append(vNode.Content[:j], vNode.Content[j+2:]...)
						}
						continue
					}
					j += 2
				}
			}
		case "webui":
			if vNode.Kind == yaml.MappingNode {
				listenIdx := findYAMLMapKeyIndex(vNode, "listen")
				httpIdx := findYAMLMapKeyIndex(vNode, "listen_http")
				if listenIdx >= 0 {
					listenVal := vNode.Content[listenIdx+1]
					if httpIdx < 0 {
						vNode.Content[listenIdx].Value = "listen_http"
						if listenVal.Kind == yaml.ScalarNode {
							seq := &yaml.Node{
								Kind:    yaml.SequenceNode,
								Style:   yaml.FlowStyle,
								Content: []*yaml.Node{cloneYAMLNode(listenVal)},
							}
							vNode.Content[listenIdx+1] = seq
						}
					} else {
						vNode.Content = append(vNode.Content[:listenIdx], vNode.Content[listenIdx+2:]...)
					}
				}
			}
		case "parental":
			if vNode.Kind == yaml.MappingNode {
				dipIdx := findYAMLMapKeyIndex(vNode, "default_idle_pause")
				dswIdx := findYAMLMapKeyIndex(vNode, "default_session_window")
				if dswIdx >= 0 {
					if dipIdx < 0 {
						vNode.Content[dswIdx].Value = "default_idle_pause"
					} else {
						vNode.Content = append(vNode.Content[:dswIdx], vNode.Content[dswIdx+2:]...)
					}
				}
				catIdx := findYAMLMapKeyIndex(vNode, "categories")
				if catIdx >= 0 && vNode.Content[catIdx+1].Kind == yaml.MappingNode {
					catsNode := vNode.Content[catIdx+1]
					for c := 0; c+1 < len(catsNode.Content); c += 2 {
						catVal := catsNode.Content[c+1]
						if catVal.Kind == yaml.MappingNode {
							srcIdx := findYAMLMapKeyIndex(catVal, "source")
							for m := 0; m+1 < len(catVal.Content); {
								mk := catVal.Content[m]
								if mk.Value == "list_url" || mk.Value == "list_urls" {
									if srcIdx < 0 {
										mk.Value = "source"
										srcIdx = m
										m += 2
									} else {
										catVal.Content = append(catVal.Content[:m], catVal.Content[m+2:]...)
									}
									continue
								}
								if mk.Value == "session_window" {
									if findYAMLMapKeyIndex(catVal, "idle_pause") < 0 {
										mk.Value = "idle_pause"
										m += 2
									} else {
										catVal.Content = append(catVal.Content[:m], catVal.Content[m+2:]...)
									}
									continue
								}
								m += 2
							}
						}
					}
				}
			}
		}
	}
}

func findYAMLMapKeyIndex(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}

var canonicalSubKeyOrder = map[string][]string{
	"upstreams.*": {
		"strategy", "preference", "mode", "ignore_qname_labels",
		"dns_0x20", "dns_cookies", "require_dnssec_ad", "doh3_fallback_threshold", "ecs", "servers",
	},
	"upstreams.*.ecs": {
		"action", "ipv4_mask", "ipv6_mask",
	},
	"routes.*": {
		"rcode", "upstream", "client_name", "bypass_local",
		"bypass_global", "group", "force", "force-and",
	},
	"routes_files.*": {
		"rcode", "upstream", "client_name", "bypass_local",
		"bypass_global", "group", "force", "force-and",
	},
	"domain_routes.*": {
		"upstream", "bypass_local",
	},
	"domain_routes_files.*": {
		"upstream", "bypass_local",
	},
	"groups.*": {
		"upstream", "bypass_local", "schedule", "block_ttl",
		"budget_tracking", "rrs", "budget",
	},
	"parental.categories.*": {
		"source", "idle_pause", "session_window", "add", "remove",
	},
}

func canonicalSchemaPath(path string) string {
	for _, prefix := range []string{
		"upstreams.",
		"routes.",
		"routes_files.",
		"domain_routes.",
		"domain_routes_files.",
		"groups.",
		"parental.categories.",
	} {
		if strings.HasPrefix(path, prefix) {
			rest := path[len(prefix):]
			if dot := strings.IndexByte(rest, '.'); dot >= 0 {
				return prefix + "*" + rest[dot:]
			}
			return prefix + "*"
		}
	}
	return path
}

func reorderMappingByKeyList(m *yaml.Node, order []string) {
	if m == nil || m.Kind != yaml.MappingNode || len(m.Content) <= 2 || len(order) == 0 {
		return
	}

	used := make([]bool, len(m.Content)/2)
	reordered := make([]*yaml.Node, 0, len(m.Content))

	for _, wantKey := range order {
		for idx := 0; idx+1 < len(m.Content); idx += 2 {
			pairIdx := idx / 2
			if !used[pairIdx] && m.Content[idx].Value == wantKey {
				used[pairIdx] = true
				reordered = append(reordered, m.Content[idx], m.Content[idx+1])
				break
			}
		}
	}

	for idx := 0; idx+1 < len(m.Content); idx += 2 {
		pairIdx := idx / 2
		if !used[pairIdx] {
			reordered = append(reordered, m.Content[idx], m.Content[idx+1])
		}
	}

	m.Content = reordered
}

func mergeYAMLMappingNodes(refMap, userMap *yaml.Node, path string) {
	if refMap == nil || userMap == nil || refMap.Kind != yaml.MappingNode || userMap.Kind != yaml.MappingNode {
		return
	}

	if userDefinedMapPaths[path] {
		if len(userMap.Content) == 0 {
			refMap.Content = nil
			refMap.Style = yaml.FlowStyle
			return
		}

		used := make([]bool, len(userMap.Content)/2)
		orderedPairs := make([]int, 0, len(userMap.Content)/2)

		for rIdx := 0; rIdx+1 < len(refMap.Content); rIdx += 2 {
			rKeyVal := refMap.Content[rIdx].Value
			for uIdx := 0; uIdx+1 < len(userMap.Content); uIdx += 2 {
				pIdx := uIdx / 2
				if !used[pIdx] && userMap.Content[uIdx].Value == rKeyVal {
					used[pIdx] = true
					orderedPairs = append(orderedPairs, uIdx)
					break
				}
			}
		}
		for uIdx := 0; uIdx+1 < len(userMap.Content); uIdx += 2 {
			pIdx := uIdx / 2
			if !used[pIdx] {
				used[pIdx] = true
				orderedPairs = append(orderedPairs, uIdx)
			}
		}

		newContent := make([]*yaml.Node, 0, len(userMap.Content))
		for _, j := range orderedPairs {
			uKey := cloneYAMLNode(userMap.Content[j])
			uVal := cloneYAMLNode(userMap.Content[j+1])

			subPath := uKey.Value
			if path != "" {
				subPath = path + "." + uKey.Value
			}

			refIdx := findYAMLMapKeyIndex(refMap, uKey.Value)
			if refIdx >= 0 {
				rKey := refMap.Content[refIdx]
				rVal := refMap.Content[refIdx+1]
				if rKey.HeadComment != "" {
					uKey.HeadComment = rKey.HeadComment
				}
				if rKey.LineComment != "" {
					uKey.LineComment = rKey.LineComment
				}
				if rVal.Kind == yaml.MappingNode && uVal.Kind == yaml.MappingNode {
					if order, ok := canonicalSubKeyOrder[canonicalSchemaPath(subPath)]; ok {
						reorderMappingByKeyList(uVal, order)
					}
					for c := 0; c+1 < len(uVal.Content); c += 2 {
						ck := uVal.Content[c]
						cv := uVal.Content[c+1]
						if ck.Value == "ecs" && cv.Kind == yaml.MappingNode {
							if ecsOrder, ok := canonicalSubKeyOrder["upstreams.*.ecs"]; ok {
								reorderMappingByKeyList(cv, ecsOrder)
							}
						}
						if rSubIdx := findYAMLMapKeyIndex(rVal, ck.Value); rSubIdx >= 0 {
							rkSub := rVal.Content[rSubIdx]
							rvSub := rVal.Content[rSubIdx+1]
							if rkSub.HeadComment != "" {
								ck.HeadComment = rkSub.HeadComment
							}
							if rkSub.LineComment != "" {
								ck.LineComment = rkSub.LineComment
							}
							if rvSub.LineComment != "" {
								cv.LineComment = rvSub.LineComment
							}
						}
					}
				} else if rVal.LineComment != "" {
					uVal.LineComment = rVal.LineComment
				}
			} else if uVal.Kind == yaml.MappingNode {
				if order, ok := canonicalSubKeyOrder[canonicalSchemaPath(subPath)]; ok {
					reorderMappingByKeyList(uVal, order)
				}
				for c := 0; c+1 < len(uVal.Content); c += 2 {
					if uVal.Content[c].Value == "ecs" && uVal.Content[c+1].Kind == yaml.MappingNode {
						if ecsOrder, ok := canonicalSubKeyOrder["upstreams.*.ecs"]; ok {
							reorderMappingByKeyList(uVal.Content[c+1], ecsOrder)
						}
					}
				}
			}

			newContent = append(newContent, uKey, uVal)
		}

		refMap.Style = 0
		refMap.Content = newContent
		return
	}

	for j := 0; j+1 < len(userMap.Content); j += 2 {
		uKey := userMap.Content[j]
		uVal := userMap.Content[j+1]

		subPath := uKey.Value
		if path != "" {
			subPath = path + "." + uKey.Value
		}

		refIdx := findYAMLMapKeyIndex(refMap, uKey.Value)
		if refIdx >= 0 {
			rVal := refMap.Content[refIdx+1]

			if rVal.Kind == yaml.MappingNode && uVal.Kind == yaml.MappingNode && !userDefinedMapPaths[subPath] {
				mergeYAMLMappingNodes(rVal, uVal, subPath)
			} else if userDefinedMapPaths[subPath] && rVal.Kind == yaml.MappingNode && uVal.Kind == yaml.MappingNode {
				mergeYAMLMappingNodes(rVal, uVal, subPath)
			} else {
				replacement := cloneYAMLNode(uVal)
				if rVal.HeadComment != "" {
					replacement.HeadComment = rVal.HeadComment
				}
				if rVal.LineComment != "" {
					replacement.LineComment = rVal.LineComment
				}
				if rVal.FootComment != "" {
					replacement.FootComment = rVal.FootComment
				}
				if rVal.Kind == yaml.SequenceNode && replacement.Kind == yaml.SequenceNode && rVal.Style == yaml.FlowStyle {
					replacement.Style = yaml.FlowStyle
				}
				refMap.Content[refIdx+1] = replacement
			}
		} else {
			refMap.Content = append(refMap.Content, cloneYAMLNode(uKey), cloneYAMLNode(uVal))
		}
	}
}

func cloneYAMLNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			cp.Content[i] = cloneYAMLNode(child)
		}
	}
	return &cp
}

func CleanConfigYAML(c Config, userYAMLBytes ...[]byte) ([]byte, error) {
	// ── SERVER ────────────────────────────────────────────────────────────
	if c.Server.UDPWorkers == 10 {
		c.Server.UDPWorkers = 0
	}
	if c.Server.MaxTCPConnections == 250 {
		c.Server.MaxTCPConnections = 0
	}
	if strings.EqualFold(c.Server.SupportIPVersion, "both") {
		c.Server.SupportIPVersion = ""
	}
	if strings.EqualFold(c.Server.BlockAction, "NULL") {
		c.Server.BlockAction = ""
	}
	if !strings.EqualFold(c.Server.BlockAction, "IP") {
		c.Server.BlockIPs = nil
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.ForSale)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.ForSale = ""
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.Parked)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.Parked = ""
	}
	if c.Server.SearchDomainLeakPrevention != nil && *c.Server.SearchDomainLeakPrevention {
		c.Server.SearchDomainLeakPrevention = nil
	}
	if strings.EqualFold(c.Server.UpstreamSelection, "stagger") {
		c.Server.UpstreamSelection = ""
	}
	if c.Server.MaxSecureUpstreams == 5 {
		c.Server.MaxSecureUpstreams = 0
	}
	if c.Server.SyntheticTTL == 60 {
		c.Server.SyntheticTTL = 0
	}
	if strings.EqualFold(c.Server.UseUpstreamECH, "disable") {
		c.Server.UseUpstreamECH = ""
	}
	if strings.EqualFold(c.Server.HostnameECH, "strict") {
		c.Server.HostnameECH = ""
	}
	if c.Server.DoH3FallbackThreshold <= 0 {
		c.Server.DoH3FallbackThreshold = 0
	}
	if c.Server.UserAgent == "sdproxy/1.0" {
		c.Server.UserAgent = ""
	}
	if c.Server.PolicyPollInterval == "6h" {
		c.Server.PolicyPollInterval = ""
	}
	if len(c.DomainPolicyURLs) == 0 {
		c.Server.PolicyCacheDir = ""
		c.Server.PolicyPollInterval = ""
	}
	if c.Server.QnameMinLabels == 1 {
		c.Server.QnameMinLabels = 0
	}
	if c.Server.QnameMaxLabels == 20 {
		c.Server.QnameMaxLabels = 0
	}

	// Server ECS
	if strings.EqualFold(c.Server.ECS.Action, "remove") || c.Server.ECS.Action == "" {
		c.Server.ECS = ECSConfig{}
	} else {
		if c.Server.ECS.IPv4Mask == 24 {
			c.Server.ECS.IPv4Mask = 0
		}
		if c.Server.ECS.IPv6Mask == 56 {
			c.Server.ECS.IPv6Mask = 0
		}
	}

	// Server DDR
	if !c.Server.DDR.Enabled {
		c.Server.DDR.HostnameSource = ""
		c.Server.DDR.Hostnames = nil
		c.Server.DDR.IPv4 = nil
		c.Server.DDR.IPv6 = nil
	} else if strings.EqualFold(c.Server.DDR.HostnameSource, "strict") {
		c.Server.DDR.HostnameSource = ""
	}

	// Server RateLimit
	if !c.Server.RateLimit.Enabled {
		c.Server.RateLimit.QPS = 0
		c.Server.RateLimit.Burst = 0
		c.Server.RateLimit.IPv4PrefixLength = 0
		c.Server.RateLimit.IPv6PrefixLength = 0
		c.Server.RateLimit.MaxTrackedIPs = 0
		c.Server.RateLimit.Exempt = nil
		c.Server.RateLimit.PenaltyBox.Enabled = false
		c.Server.RateLimit.PenaltyBox.StrikeThreshold = 0
		c.Server.RateLimit.PenaltyBox.BanDurationMin = 0
	} else {
		if c.Server.RateLimit.QPS == 20 {
			c.Server.RateLimit.QPS = 0
		}
		if c.Server.RateLimit.Burst == 100 {
			c.Server.RateLimit.Burst = 0
		}
		if c.Server.RateLimit.IPv4PrefixLength == 32 {
			c.Server.RateLimit.IPv4PrefixLength = 0
		}
		if c.Server.RateLimit.IPv6PrefixLength == 128 {
			c.Server.RateLimit.IPv6PrefixLength = 0
		}
		if c.Server.RateLimit.MaxTrackedIPs == 1000 || c.Server.RateLimit.MaxTrackedIPs == 100000 {
			c.Server.RateLimit.MaxTrackedIPs = 0
		}
		if !c.Server.RateLimit.PenaltyBox.Enabled {
			c.Server.RateLimit.PenaltyBox.StrikeThreshold = 0
			c.Server.RateLimit.PenaltyBox.BanDurationMin = 0
		} else {
			if c.Server.RateLimit.PenaltyBox.StrikeThreshold == 100 {
				c.Server.RateLimit.PenaltyBox.StrikeThreshold = 0
			}
			if c.Server.RateLimit.PenaltyBox.BanDurationMin == 15 {
				c.Server.RateLimit.PenaltyBox.BanDurationMin = 0
			}
		}
	}

	// Server DGA
	if !c.Server.DGA.Enabled {
		c.Server.DGA.Threshold = 0
		c.Server.DGA.Action = ""
	} else {
		if c.Server.DGA.Threshold == 80.0 {
			c.Server.DGA.Threshold = 0
		}
		if strings.EqualFold(c.Server.DGA.Action, "BLOCK") {
			c.Server.DGA.Action = ""
		}
	}

	// Server Exfiltration
	if !c.Server.Exfiltration.Enabled {
		c.Server.Exfiltration.MinThresholdBPS = 0
		c.Server.Exfiltration.AnomalyMultiplier = 0
		c.Server.Exfiltration.Action = ""
		c.Server.Exfiltration.IPv4PrefixLength = 0
		c.Server.Exfiltration.IPv6PrefixLength = 0
		c.Server.Exfiltration.MaxTrackedIPs = 0
		c.Server.Exfiltration.Exempt = nil
		c.Server.Exfiltration.PenaltyBox.Enabled = false
		c.Server.Exfiltration.PenaltyBox.StrikeThreshold = 0
		c.Server.Exfiltration.PenaltyBox.BanDurationMin = 0
	} else {
		if c.Server.Exfiltration.MinThresholdBPS == 1500 {
			c.Server.Exfiltration.MinThresholdBPS = 0
		}
		if c.Server.Exfiltration.AnomalyMultiplier == 3.0 {
			c.Server.Exfiltration.AnomalyMultiplier = 0
		}
		if strings.EqualFold(c.Server.Exfiltration.Action, "LOG") {
			c.Server.Exfiltration.Action = ""
		}
		if c.Server.Exfiltration.MaxTrackedIPs == 50000 {
			c.Server.Exfiltration.MaxTrackedIPs = 0
		}
		if c.Server.Exfiltration.IPv4PrefixLength == 32 {
			c.Server.Exfiltration.IPv4PrefixLength = 0
		}
		if c.Server.Exfiltration.IPv6PrefixLength == 128 {
			c.Server.Exfiltration.IPv6PrefixLength = 0
		}
		if !c.Server.Exfiltration.PenaltyBox.Enabled {
			c.Server.Exfiltration.PenaltyBox.StrikeThreshold = 0
			c.Server.Exfiltration.PenaltyBox.BanDurationMin = 0
		} else {
			if c.Server.Exfiltration.PenaltyBox.StrikeThreshold == 3 {
				c.Server.Exfiltration.PenaltyBox.StrikeThreshold = 0
			}
			if c.Server.Exfiltration.PenaltyBox.BanDurationMin == 15 {
				c.Server.Exfiltration.PenaltyBox.BanDurationMin = 0
			}
		}
	}

	// Server SubdomainLimit (merge aliases and strip alias structs)
	mergeSubdomainLimitConfig(&c.Server.SubdomainLimit, c.Server.SubdomainLimiter)
	mergeSubdomainLimitConfig(&c.Server.SubdomainLimit, c.Server.SubnetLimiter)
	mergeSubdomainLimitConfig(&c.Server.SubdomainLimit, c.Server.SubnetLimit)
	c.Server.SubdomainLimiter = SubdomainLimitConfig{}
	c.Server.SubnetLimiter = SubdomainLimitConfig{}
	c.Server.SubnetLimit = SubdomainLimitConfig{}

	if !c.Server.SubdomainLimit.Enabled {
		c.Server.SubdomainLimit = SubdomainLimitConfig{}
	} else {
		if c.Server.SubdomainLimit.Threshold == 100 {
			c.Server.SubdomainLimit.Threshold = 0
		}
		if c.Server.SubdomainLimit.WindowMinutes == 60 {
			c.Server.SubdomainLimit.WindowMinutes = 0
		}
		if strings.EqualFold(c.Server.SubdomainLimit.Action, "BLOCK") {
			c.Server.SubdomainLimit.Action = ""
		}
		if c.Server.SubdomainLimit.MaxTrackedApexes == 10000 {
			c.Server.SubdomainLimit.MaxTrackedApexes = 0
		}
	}

	// ── LOGGING ───────────────────────────────────────────────────────────
	if c.Logging.Simple != nil && *c.Logging.Simple {
		c.Logging.Simple = nil
	}
	if c.Logging.LogQueries != nil && *c.Logging.LogQueries {
		c.Logging.LogQueries = nil
	}
	if c.Logging.LogParental != nil && !*c.Logging.LogParental {
		c.Logging.LogParental = nil
	}
	if c.Logging.LogIdentity != nil && !*c.Logging.LogIdentity {
		c.Logging.LogIdentity = nil
	}
	if c.Logging.LogCaching != nil && !*c.Logging.LogCaching {
		c.Logging.LogCaching = nil
	}
	if c.Logging.LogDDR != nil && !*c.Logging.LogDDR {
		c.Logging.LogDDR = nil
	}
	if c.Logging.LogTLS != nil && !*c.Logging.LogTLS {
		c.Logging.LogTLS = nil
	}
	if c.Logging.LogSystem != nil && *c.Logging.LogSystem {
		c.Logging.LogSystem = nil
	}
	if c.Logging.LogWebUI != nil && *c.Logging.LogWebUI {
		c.Logging.LogWebUI = nil
	}
	if c.Logging.LogRouting != nil && !*c.Logging.LogRouting {
		c.Logging.LogRouting = nil
	}

	// ── CACHE ─────────────────────────────────────────────────────────────
	if !c.Cache.Enabled {
		c.Cache.Size = 0
		c.Cache.Persist = false
		c.Cache.PersistFile = ""
		c.Cache.PersistSaveInterval = ""
		c.Cache.MinTTL = 0
		c.Cache.MaxTTL = 0
		c.Cache.NegativeTTL = 0
		c.Cache.StaleTTL = 0
		c.Cache.ServeStaleInfinite = false
		c.Cache.PrefetchBefore = 0
		c.Cache.PrefetchMinHits = 0
		c.Cache.SweepIntervalS = 0
		c.Cache.CacheSynthetic = false
		c.Cache.CacheLocalIdentity = false
		c.Cache.CacheUpstreamNegative = false
		c.Cache.AnswerSort = ""
	} else {
		if c.Cache.Size == 5000 {
			c.Cache.Size = 0
		}
		if !c.Cache.Persist {
			c.Cache.PersistFile = ""
			c.Cache.PersistSaveInterval = ""
		} else {
			if c.Cache.PersistFile == "/var/lib/sdproxy/dns_cache.bin" {
				c.Cache.PersistFile = ""
			}
			if c.Cache.PersistSaveInterval == "5m" {
				c.Cache.PersistSaveInterval = ""
			}
		}
		if c.Cache.SweepIntervalS == 60 {
			c.Cache.SweepIntervalS = 0
		}
		if strings.EqualFold(c.Cache.AnswerSort, "none") {
			c.Cache.AnswerSort = ""
		}
	}

	// ── IDENTITY ──────────────────────────────────────────────────────────
	if len(c.Identity.IPInfoASN) == 0 {
		c.Identity.ASNCacheDir = ""
		c.Identity.ASNPollInterval = ""
		c.Identity.ASNFastStart = false
	} else if c.Identity.ASNPollInterval == "6h" {
		c.Identity.ASNPollInterval = ""
	}
	hasIdentityFiles := len(c.Identity.HostsFiles) > 0 ||
		len(c.Identity.DnsmasqLeases) > 0 ||
		len(c.Identity.IscLeases) > 0 ||
		len(c.Identity.KeaLeases) > 0 ||
		len(c.Identity.OdhcpdLeases) > 0
	if !hasIdentityFiles {
		c.Identity.PollInterval = 0
	}

	// ── UPSTREAMS ─────────────────────────────────────────────────────────
	effectiveGlobalStrategy := strings.ToLower(c.Server.UpstreamSelection)
	if effectiveGlobalStrategy == "" {
		effectiveGlobalStrategy = "stagger"
	}
	effectiveGlobalECSAction := strings.ToLower(c.Server.ECS.Action)
	if effectiveGlobalECSAction == "" {
		effectiveGlobalECSAction = "remove"
	}
	for k, u := range c.Upstreams {
		if strings.EqualFold(u.Strategy, effectiveGlobalStrategy) {
			u.Strategy = ""
		}
		if strings.EqualFold(u.Preference, "fastest") {
			u.Preference = ""
		}
		if strings.EqualFold(u.Mode, "loose") {
			u.Mode = ""
		}
		if u.DNS0x20 != nil && *u.DNS0x20 == c.Server.DNS0x20 {
			u.DNS0x20 = nil
		}
		if u.DNSCookies != nil && *u.DNSCookies == c.Server.DNSCookies {
			u.DNSCookies = nil
		}
		if u.RequireDNSSECAD != nil && *u.RequireDNSSECAD == c.Server.RequireDNSSECAD {
			u.RequireDNSSECAD = nil
		}
		if u.DoH3FallbackThreshold != nil && *u.DoH3FallbackThreshold == c.Server.DoH3FallbackThreshold {
			u.DoH3FallbackThreshold = nil
		}
		if strings.EqualFold(u.ECS.Action, effectiveGlobalECSAction) {
			u.ECS.Action = ""
		}
		if u.ECS.Action == "" {
			u.ECS.IPv4Mask = 0
			u.ECS.IPv6Mask = 0
		} else {
			if u.ECS.IPv4Mask == 24 {
				u.ECS.IPv4Mask = 0
			}
			if u.ECS.IPv6Mask == 56 {
				u.ECS.IPv6Mask = 0
			}
		}
		c.Upstreams[k] = u
	}

	// ── GROUPS & PARENTAL ─────────────────────────────────────────────────
	if len(c.Groups) == 0 {
		c.Parental = ParentalConfig{}
	} else {
		for k, g := range c.Groups {
			if strings.EqualFold(g.BudgetTracking, "group") {
				g.BudgetTracking = ""
			}
			if g.BlockTTL == 20 {
				g.BlockTTL = 0
			}
			c.Groups[k] = g
		}

		if c.Parental.ForcedTTL == 60 {
			c.Parental.ForcedTTL = 0
		}
		if c.Parental.BlockTTL == 20 {
			c.Parental.BlockTTL = 0
		}
		if c.Parental.TickerInterval == 10 {
			c.Parental.TickerInterval = 0
		}
		if c.Parental.DefaultIdlePause == "2m" {
			c.Parental.DefaultIdlePause = ""
		}
		if c.Parental.SnapshotDir == "/tmp/sdproxy" {
			c.Parental.SnapshotDir = ""
		}
		if c.Parental.Consolidation != nil && *c.Parental.Consolidation {
			c.Parental.Consolidation = nil
		}
		if c.Parental.SynthesiseParents != nil && !*c.Parental.SynthesiseParents {
			c.Parental.SynthesiseParents = nil
		}
		if c.Parental.RemoveRedundantSubdomains != nil && *c.Parental.RemoveRedundantSubdomains {
			c.Parental.RemoveRedundantSubdomains = nil
		}
		if c.Parental.StripServiceLabels != nil && !*c.Parental.StripServiceLabels {
			c.Parental.StripServiceLabels = nil
		}
		if c.Parental.ParentConsolidationThreshold == 10 {
			c.Parental.ParentConsolidationThreshold = 0
		}
		if c.Parental.ConsolidationHomogeneityPct == 90 {
			c.Parental.ConsolidationHomogeneityPct = 0
		}

		effDefaultIdle := c.Parental.DefaultIdlePause
		if effDefaultIdle == "" {
			effDefaultIdle = "2m"
		}
		for k, cat := range c.Parental.Categories {
			if cat.IdlePause == effDefaultIdle {
				cat.IdlePause = ""
			}
			if len(cat.ListURLs) == 0 && len(cat.Add) == 0 && len(cat.Remove) == 0 && cat.IdlePause == "" && cat.SessionWindow == "" {
				delete(c.Parental.Categories, k)
			} else {
				c.Parental.Categories[k] = cat
			}
		}
	}

	// ── WEBUI ─────────────────────────────────────────────────────────────
	if !c.WebUI.Enabled {
		c.WebUI = WebUIConfig{}
	} else {
		if len(c.WebUI.ListenHTTP) == 1 && c.WebUI.ListenHTTP[0] == "127.0.0.1:8080" && len(c.WebUI.ListenHTTPS) == 0 {
			c.WebUI.ListenHTTP = nil
		}
		if !c.WebUI.LoginRatelimit.Enabled {
			c.WebUI.LoginRatelimit.MaxAttempts = 0
			c.WebUI.LoginRatelimit.LockoutMinutes = 0
		} else {
			if c.WebUI.LoginRatelimit.MaxAttempts <= 0 {
				c.WebUI.LoginRatelimit.MaxAttempts = 5
			}
			if c.WebUI.LoginRatelimit.LockoutMinutes == 15 {
				c.WebUI.LoginRatelimit.LockoutMinutes = 0
			}
		}
		if c.WebUI.StatsRefreshSec == 30 {
			c.WebUI.StatsRefreshSec = 0
		}
		if c.WebUI.StatsTopN == 10 {
			c.WebUI.StatsTopN = 0
		}
		if c.WebUI.HistoryRetentionHours == 24 {
			c.WebUI.HistoryRetentionHours = 0
		}
		if c.WebUI.HistorySaveInterval == "5m" {
			c.WebUI.HistorySaveInterval = ""
		}
	}

	rawBytes, err := yaml.Marshal(&c)
	if err != nil {
		return nil, err
	}

	var cleanDoc yaml.Node
	if err := yaml.Unmarshal(rawBytes, &cleanDoc); err != nil {
		return nil, err
	}

	var refDoc yaml.Node
	_ = yaml.Unmarshal([]byte(FullReferenceConfigYAML), &refDoc)

	var userDoc yaml.Node
	if len(userYAMLBytes) > 0 && len(userYAMLBytes[0]) > 0 {
		_ = yaml.Unmarshal(userYAMLBytes[0], &userDoc)
		if len(userDoc.Content) > 0 && userDoc.Content[0].Kind == yaml.MappingNode {
			normalizeUserConfigAliases(userDoc.Content[0])
		}
	}

	if len(cleanDoc.Content) > 0 && cleanDoc.Content[0].Kind == yaml.MappingNode {
		var refRoot, userRoot *yaml.Node
		if len(refDoc.Content) > 0 && refDoc.Content[0].Kind == yaml.MappingNode {
			refRoot = refDoc.Content[0]
		}
		if len(userDoc.Content) > 0 && userDoc.Content[0].Kind == yaml.MappingNode {
			userRoot = userDoc.Content[0]
		}
		pruneAndOrderYAMLMapping(cleanDoc.Content[0], refRoot, userRoot, "")
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&cleanDoc); err != nil {
		return nil, err
	}
	_ = enc.Close()

	return formatCleanYAMLTopLevelSpacing(buf.Bytes()), nil
}

func formatCleanYAMLTopLevelSpacing(raw []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		return []byte("\n")
	}

	var out []string
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if i > 0 && len(line) > 0 && line[0] != ' ' && line[0] != '\t' && line[0] != '-' {
			if len(out) > 0 && out[len(out)-1] != "" {
				out = append(out, "")
			}
		}
		out = append(out, line)
	}

	return []byte(strings.Join(out, "\n") + "\n")
}

func pruneAndOrderYAMLMapping(node, refMap, userMap *yaml.Node, path string) {
	if node == nil || node.Kind != yaml.MappingNode {
		return
	}

	node.HeadComment = ""
	node.LineComment = ""
	node.FootComment = ""

	kept := make([]*yaml.Node, 0, len(node.Content))
	for i := 0; i+1 < len(node.Content); i += 2 {
		kNode := node.Content[i]
		vNode := node.Content[i+1]

		kNode.HeadComment = ""
		kNode.LineComment = ""
		kNode.FootComment = ""
		vNode.HeadComment = ""
		vNode.LineComment = ""
		vNode.FootComment = ""

		subPath := kNode.Value
		if path != "" {
			subPath = path + "." + kNode.Value
		}

		var refSub, userSub *yaml.Node
		if refMap != nil && refMap.Kind == yaml.MappingNode {
			if idx := findYAMLMapKeyIndex(refMap, kNode.Value); idx >= 0 {
				refSub = refMap.Content[idx+1]
			}
		}
		if userMap != nil && userMap.Kind == yaml.MappingNode {
			if idx := findYAMLMapKeyIndex(userMap, kNode.Value); idx >= 0 {
				userSub = userMap.Content[idx+1]
			}
		}

		if vNode.Kind == yaml.MappingNode {
			pruneAndOrderYAMLMapping(vNode, refSub, userSub, subPath)
		} else if vNode.Kind == yaml.SequenceNode {
			stripSequenceComments(vNode)
		}

		if isEmptyYAMLNode(vNode) {
			continue
		}
		kept = append(kept, kNode, vNode)
	}
	node.Content = kept

	if len(node.Content) <= 2 {
		return
	}

	if order, ok := canonicalSubKeyOrder[canonicalSchemaPath(path)]; ok {
		reorderMappingByKeyList(node, order)
		return
	}

	if userDefinedMapPaths[path] {
		var order []string
		if refMap != nil && refMap.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(refMap.Content); i += 2 {
				order = append(order, refMap.Content[i].Value)
			}
		}
		if userMap != nil && userMap.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(userMap.Content); i += 2 {
				order = append(order, userMap.Content[i].Value)
			}
		}
		if len(order) > 0 {
			reorderMappingByKeyList(node, order)
		}
		return
	}

	if refMap != nil && refMap.Kind == yaml.MappingNode {
		order := make([]string, 0, len(refMap.Content)/2)
		for i := 0; i+1 < len(refMap.Content); i += 2 {
			order = append(order, refMap.Content[i].Value)
		}
		reorderMappingByKeyList(node, order)
	}
}

func stripSequenceComments(seq *yaml.Node) {
	if seq == nil {
		return
	}
	seq.HeadComment = ""
	seq.LineComment = ""
	seq.FootComment = ""
	for _, child := range seq.Content {
		stripSequenceComments(child)
	}
}

func isEmptyYAMLNode(n *yaml.Node) bool {
	if n == nil {
		return true
	}
	switch n.Kind {
	case yaml.MappingNode, yaml.SequenceNode:
		return len(n.Content) == 0
	case yaml.ScalarNode:
		return n.Tag == "!!null" || (n.Value == "" && n.Tag != "!!str")
	}
	return false
}
