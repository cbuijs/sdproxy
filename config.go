/*
File:    config.go
Version: 2.0.0 (Split)
Last Updated: 23-Nov-2026 11:43 CET

Description:
  Core YAML-mapped configuration structs, custom YAML marshalers/unmarshalers,
  embedded reference config, and global `cfg` state for sdproxy.

  Related modules:
    config_parse.go    — YAML regex-escape sanitizer and domain/regex key parsers
    config_validate.go — Startup and `--test` fail-closed configuration validation
    config_yaml.go     — `--update-config`, `--full-clean-config`, and `--clean-config` AST engine

Changes:
  2.0.0   - [REFACTOR] Split `config.go` into `config.go` (structs and YAML
            marshalers), `config_parse.go` (regex/key parsing),
            `config_validate.go` (validation), and `config_yaml.go` (YAML AST
            update/clean output).
  1.106.0 - [SECURITY/FIX] Added strict fail-closed validation in `validateConfig`
            for ACL/exempt/trusted_proxies CIDRs, listener addresses, TLS/ECH file
            pairing, DDR/block IPs, upstream/bootstrap URLs, upstream group/ECS
            enums, policy/route keys and actions, durations, parental schedules
            and budgets, and numeric bounds so `--test` catches fatal/fail-open typos.
          - [SECURITY/FIX] Defaulted `webui.login_ratelimit.max_attempts` (5) and
            `lockout_minutes` (15) in `validateConfig`, and stripped default `5`
            instead of injecting it in `CleanConfigYAML`.
          - [PERF/FIX] Normalized empty `cache.answer_sort` to `"none"` in
            `validateConfig` to eliminate no-op `applyAnswerSort` calls on every query.
          - [FIX] Evaluated inherited global `server.upstream_selection: "secure"`
            when auto-enabling `flatten_cname` for `consolidate` groups.
          - [FIX] Eliminated in-place map/slice mutations on `cfg` in `validateConfig`
            and `CleanConfigYAML` so shallow struct copies (`rawCfg`) stay intact.
          - [FIX] Fixed `CleanConfigYAML` regressions wiping per-upstream ECS masks,
            stripping group `block_ttl: 20` when `parental.block_ttl != 20`, and
            ignoring legacy `webui.listen` / `session_window` aliases.
          - [FIX] Fixed slice-shift index corruption and precedence in
            `normalizeUserConfigAliases`, fixed sequence-to-map key ordering in
            `mergeYAMLMappingNodes`, hardened `sanitizeYAMLRegexEscapes` and
            `splitDomainPolicyKeys`, and deduplicated `UpdateConfigYAML` /
            `FullCleanConfigYAML`.
  1.105.0 - [FEAT] Added `RcodeTTL` (`rcode_ttl`), `RcodeMinTTL` (`rcode_min_ttl`),
            and `RcodeMaxTTL` (`rcode_max_ttl`) under `cache:`.
  1.104.0 - [SECURITY/FIX] Added strict startup validation in `validateConfig`
            for `server.block_action`.
  1.103.0 - [SECURITY/FIX] Added strict startup validation in `validateConfig`
            for `server.dga.action`, `server.exfiltration.action`, and
            `server.subdomain_limit.action`.
  1.102.1 - [FIX] Normalized `RFCCompliance.Action` and `IDNHomograph.Action`
            to uppercase in `CleanConfigYAML`.
  1.102.0 - [FEAT] Added `IDNHomographConfig` (`server.idn_homograph`).
  1.101.0 - [FEAT] Added `RFCComplianceConfig` (`server.rfc_compliance`).
  1.100.0 - [FEAT] Added `DoH3FallbackThreshold` (`doh3_fallback_threshold`) under
            `server:` and per-group `upstreams:`.
  1.99.2  - [CLEANUP] Removed redundant `len(userDoc.Content[0].Content) >= 0`
            condition in `UpdateConfigYAML`.
*/

package main

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed full_reference_config.yaml
var FullReferenceConfigYAML string

// quietInit suppresses `[WARN]` log lines in `validateConfig` when running
// one-shot CLI operations (`--test`, `--clean-config`, `--full-clean-config`, `--update-config`).
var quietInit bool

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
// RFCComplianceConfig
// ---------------------------------------------------------------------------

type RFCComplianceConfig struct {
	Action string   `yaml:"action,omitempty"`
	Strict bool     `yaml:"strict,omitempty"`
	Checks []string `yaml:"checks,omitempty"`
}

func (r *RFCComplianceConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		r.Action = value.Value
		return nil
	case yaml.MappingNode:
		type plain RFCComplianceConfig
		return value.Decode((*plain)(r))
	default:
		return fmt.Errorf("rfc_compliance: expected string or map, got %s", value.Tag)
	}
}

// ---------------------------------------------------------------------------
// IDNHomographConfig
// ---------------------------------------------------------------------------

type IDNHomographConfig struct {
	Action          string   `yaml:"action,omitempty"`
	BlockAllIDN     bool     `yaml:"block_all_idn,omitempty"`
	MixedScript     *bool    `yaml:"mixed_script,omitempty"`
	ASCIILookalikes *bool    `yaml:"ascii_lookalikes,omitempty"`
	Protect         []string `yaml:"protect,omitempty"`
	Exempt          []string `yaml:"exempt,omitempty"`
}

func (h *IDNHomographConfig) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		h.Action = value.Value
		return nil
	case yaml.MappingNode:
		type plain IDNHomographConfig
		return value.Decode((*plain)(h))
	default:
		return fmt.Errorf("idn_homograph: expected string or map, got %s", value.Tag)
	}
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
		combined := make([]string, 0, len(dst.Exempt)+len(src.Exempt))
		seen := make(map[string]struct{}, len(dst.Exempt)+len(src.Exempt))
		for _, e := range dst.Exempt {
			k := strings.ToLower(strings.TrimSpace(e))
			if k == "" {
				continue
			}
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				combined = append(combined, e)
			}
		}
		for _, e := range src.Exempt {
			k := strings.ToLower(strings.TrimSpace(e))
			if k == "" {
				continue
			}
			if _, ok := seen[k]; !ok {
				seen[k] = struct{}{}
				combined = append(combined, e)
			}
		}
		dst.Exempt = combined
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
	return fmt.Errorf("upstreams: expected list of strings or map, got %s", value.Tag)
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

	if w.Source.Kind != 0 && w.Source.Kind != yaml.ScalarNode && w.Source.Kind != yaml.SequenceNode && w.Source.Tag != "!!null" {
		return fmt.Errorf("source: expected string or list of strings, got %s", w.Source.Tag)
	}

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

		ForSale       string              `yaml:"for_sale,omitempty"`
		Parked        string              `yaml:"parked,omitempty"`
		RFCCompliance RFCComplianceConfig `yaml:"rfc_compliance,omitempty"`
		IDNHomograph  IDNHomographConfig  `yaml:"idn_homograph,omitempty"`

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
		RcodeTTL              int    `yaml:"rcode_ttl,omitempty"`
		RcodeMinTTL           int    `yaml:"rcode_min_ttl,omitempty"`
		RcodeMaxTTL           int    `yaml:"rcode_max_ttl,omitempty"`
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
