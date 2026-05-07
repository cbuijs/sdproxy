/*
File:    config.go
Version: 1.58.0
Updated: 07-May-2026 09:20 CEST

Description:
  All YAML-mapped configuration structs for sdproxy. Covers every top-level
  config section: server, logging, cache, identity, upstreams, routes,
  domain_routes, rtype/domain policy, parental groups, categories, webui,
  and spoofed records (RRs).

Changes:
  1.58.0 - [FEAT] Introduced `rrs:` (Spoofed Records) mappings natively within 
           the global `Config` and local `GroupConfig` structs to empower 
           explicit A/AAAA/CNAME overrides.
  1.57.0 - [FEAT] Injected `Force` into `RouteConfig` and `ParsedRoute` structs 
           to accommodate overriding standard hierarchical client routing priorities 
           natively on the hot path.
*/

package main

import (
	"fmt"
	"log"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// ACLConfig
// ---------------------------------------------------------------------------

// ACLConfig holds IP/Subnet allow and deny lists.
type ACLConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ---------------------------------------------------------------------------
// RouteConfig / ParsedRoute
// ---------------------------------------------------------------------------

// RouteConfig maps a MAC/IP/CIDR/ASN key to an upstream group, an optional client
// name override, the optional bypass_local flag, an optional parental group, 
// and an explicit DNS return code (rcode) for instant policy enforcement.
type RouteConfig struct {
	Rcode       string `yaml:"rcode"`
	Upstream    string `yaml:"upstream"`
	ClientName  string `yaml:"client_name"`
	BypassLocal bool   `yaml:"bypass_local"`
	Group       string `yaml:"group"`
	Force       bool   `yaml:"force"`
}

// ParsedRoute is the resolved runtime form of RouteConfig.
// Evaluates explicit policy actions (HasRcode) strictly over network targets.
type ParsedRoute struct {
	HasRcode    bool
	Rcode       int
	Upstream    string
	ClientName  string
	BypassLocal bool
	Force       bool
}

// ---------------------------------------------------------------------------
// DomainRouteConfig / domainRouteEntry
// ---------------------------------------------------------------------------

// DomainRouteConfig is the YAML config form for domain_routes entries.
type DomainRouteConfig struct {
	Upstream    string `yaml:"upstream"`
	BypassLocal bool   `yaml:"bypass_local"`
}

// UnmarshalYAML handles both the compact scalar and the expanded map form.
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

type domainRouteEntry struct {
	upstream    string
	bypassLocal bool
}

// ---------------------------------------------------------------------------
// UpstreamGroupConfig
// ---------------------------------------------------------------------------

// UpstreamGroupConfig is the YAML config form for upstreams entries.
type UpstreamGroupConfig struct {
	Strategy   string   `yaml:"strategy"`
	Preference string   `yaml:"preference"`
	Mode       string   `yaml:"mode"`
	Servers    []string `yaml:"servers"`
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

// ---------------------------------------------------------------------------
// GroupConfig
// ---------------------------------------------------------------------------

type GroupConfig struct {
	Upstream       string                 `yaml:"upstream"`
	BypassLocal    bool                   `yaml:"bypass_local"`
	Schedule       ScheduleList           `yaml:"schedule"`
	BlockTTL       int                    `yaml:"block_ttl"`
	Budget         map[string]string      `yaml:"budget"`
	BudgetTracking string                 `yaml:"budget_tracking"`
	RRs            map[string]interface{} `yaml:"rrs"` // Group-specific A/AAAA/CNAME spoofed records
}

// ---------------------------------------------------------------------------
// CategoryConfig
// ---------------------------------------------------------------------------

type CategoryConfig struct {
	ListURLs      []string
	IdlePause     string   `yaml:"idle_pause"`
	SessionWindow string   `yaml:"session_window"`
	Add           []string `yaml:"add"`
	Remove        []string `yaml:"remove"`
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
		if err := w.Source.Decode(&c.ListURLs); err != nil {
			return fmt.Errorf("source: %w", err)
		}
	case len(w.ListURLs) > 0:
		c.ListURLs = w.ListURLs
	case w.ListURL != "":
		c.ListURLs = []string{w.ListURL}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ParentalConfig
// ---------------------------------------------------------------------------

type ParentalConfig struct {
	FastStart bool `yaml:"fast_start"`
	ForcedTTL int `yaml:"forced_ttl"`
	BlockTTL int `yaml:"block_ttl"`
	TickerInterval int `yaml:"ticker_interval"`
	DefaultIdlePause string `yaml:"default_idle_pause"`
	DefaultSessionWindow string `yaml:"default_session_window"`
	SnapshotDir string `yaml:"snapshot_dir"`
	Consolidation *bool `yaml:"consolidation"`
	SynthesiseParents *bool `yaml:"synthesise_parents"`
	RemoveRedundantSubdomains *bool `yaml:"remove_redundant_subdomains"`
	StripServiceLabels *bool `yaml:"strip_service_labels"`
	ParentConsolidationThreshold int `yaml:"parent_consolidation_threshold"`
	ConsolidationHomogeneityPct int `yaml:"consolidation_homogeneity_pct"`
	Categories map[string]CategoryConfig `yaml:"categories"`
}

// ---------------------------------------------------------------------------
// WebUIConfig
// ---------------------------------------------------------------------------

type WebUIConfig struct {
	Enabled bool `yaml:"enabled"`
	Listen string `yaml:"listen"`
	ListenHTTP []string `yaml:"listen_http"`
	ListenHTTPS []string `yaml:"listen_https"`
	ForceHTTPS bool `yaml:"force_https"`
	Password string `yaml:"password"`
	APIToken string `yaml:"api_token"`
	ACL ACLConfig `yaml:"acl"`

	LoginRatelimit struct {
		Enabled        bool `yaml:"enabled"`
		MaxAttempts    int  `yaml:"max_attempts"`
		LockoutMinutes int  `yaml:"lockout_minutes"`
	} `yaml:"login_ratelimit"`

	StatsEnabled bool `yaml:"stats_enabled"`
	StatsRefreshSec int `yaml:"stats_refresh_sec"`
	StatsTopN int `yaml:"stats_top_n"`
	StatsGraphsEnabled bool `yaml:"stats_graphs_enabled"`
	HistoryDir string `yaml:"history_dir"`
	HistoryRetentionHours int `yaml:"history_retention_hours"`
	HistorySaveInterval string `yaml:"history_save_interval"`
}

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

type Config struct {
	Server struct {
		ListenUDP  []string `yaml:"listen_udp"`
		ListenTCP  []string `yaml:"listen_tcp"`
		ListenDoT  []string `yaml:"listen_dot"`
		ListenDoH  []string `yaml:"listen_doh"`
		ListenDoQ  []string `yaml:"listen_doq"`
		UDPWorkers int      `yaml:"udp_workers"`
		TLSCert    string   `yaml:"tls_cert"`
		TLSKey     string   `yaml:"tls_key"`
		MemoryLimitMB int `yaml:"memory_limit_mb"`
		MaxTCPConnections int `yaml:"max_tcp_connections"`
		ACL ACLConfig `yaml:"acl"`

		RateLimit struct {
			Enabled          bool     `yaml:"enabled"`
			QPS              float64  `yaml:"qps"`
			Burst            float64  `yaml:"burst"`
			IPv4PrefixLength int      `yaml:"ipv4_prefix_length"`
			IPv6PrefixLength int      `yaml:"ipv6_prefix_length"`
			MaxTrackedIPs    int      `yaml:"max_tracked_ips"` 
			Exempt           []string `yaml:"exempt"`          
			
			PenaltyBox struct {
				Enabled         bool `yaml:"enabled"`
				StrikeThreshold int  `yaml:"strike_threshold"`
				BanDurationMin  int  `yaml:"ban_duration_min"`
			} `yaml:"penalty_box"`
		} `yaml:"rate_limit"`

		// DGA (Domain Generation Algorithm) ML Inference Engine
		DGA struct {
			Enabled   bool    `yaml:"enabled"`
			Threshold float64 `yaml:"threshold"`
			Action    string  `yaml:"action"`
		} `yaml:"dga"`

		// Exfiltration (DNS Tunneling) Anomaly Detection Engine
		Exfiltration struct {
			Enabled           bool     `yaml:"enabled"`
			MinThresholdBPS   float64  `yaml:"min_threshold_bps"`
			AnomalyMultiplier float64  `yaml:"anomaly_multiplier"`
			Action            string   `yaml:"action"`
			IPv4PrefixLength  int      `yaml:"ipv4_prefix_length"`
			IPv6PrefixLength  int      `yaml:"ipv6_prefix_length"`
			MaxTrackedIPs     int      `yaml:"max_tracked_ips"`
			Exempt            []string `yaml:"exempt"`
			
			PenaltyBox struct {
				Enabled         bool `yaml:"enabled"`
				StrikeThreshold int  `yaml:"strike_threshold"`
				BanDurationMin  int  `yaml:"ban_duration_min"`
			} `yaml:"penalty_box"`
		} `yaml:"exfiltration"`

		SupportIPVersion    string   `yaml:"support_ip_version"`
		BlockAction         string   `yaml:"block_action"`
		BlockIPs            []string `yaml:"block_ips"`
		RebindingProtection bool     `yaml:"rebinding_protection"`
		FilterAAAA          bool     `yaml:"filter_aaaa"`
		FilterIPs           bool     `yaml:"filter_ips"`
		StrictPTR           bool     `yaml:"strict_ptr"`
		FlattenCNAME        bool     `yaml:"flatten_cname"`
		TargetName          bool     `yaml:"target_name"`
		MinimizeAnswer      bool     `yaml:"minimize_answer"`
		BlockObsoleteQtypes bool     `yaml:"block_obsolete_qtypes"`
		UpstreamSelection   string   `yaml:"upstream_selection"`
		UpstreamStaggerMs   int      `yaml:"upstream_stagger_ms"`
		UpstreamTimeoutMs   int      `yaml:"upstream_timeout_ms"`
		SyntheticTTL        int      `yaml:"synthetic_ttl"`
		BootstrapServers    []string `yaml:"bootstrap_servers"`
		UseUpstreamECH      string   `yaml:"use_upstream_ech"`
		HostnameECH         string   `yaml:"hostname_ech"`
		UpgradeDoH3         bool     `yaml:"upgrade_doh3"`
		PolicyCacheDir      string   `yaml:"policy_cache_dir"`
		PolicyPollInterval  string   `yaml:"policy_poll_interval"`
		UserAgent           string   `yaml:"user_agent"`
		ECHConfigList       string   `yaml:"ech_config_list"`
		ECHKey              string   `yaml:"ech_key"`

		DDR struct {
			Enabled        bool     `yaml:"enabled"`
			HostnameSource string   `yaml:"hostname_source"`
			Hostnames      []string `yaml:"hostnames"`
			IPv4           []string `yaml:"ipv4"`
			IPv6           []string `yaml:"ipv6"`
		} `yaml:"ddr"`
	} `yaml:"server"`

	Logging struct {
		LogQueries *bool `yaml:"log_queries"`
		StripTime bool `yaml:"strip_time"`
		LogASNDetails bool `yaml:"log_asn_details"`
		LogStrategy bool `yaml:"log_strategy"`
	} `yaml:"logging"`

	Cache struct {
		Enabled         bool   `yaml:"enabled"`
		Size            int    `yaml:"size"`
		MinTTL          int    `yaml:"min_ttl"`
		MaxTTL          int    `yaml:"max_ttl"`
		NegativeTTL     int    `yaml:"negative_ttl"`
		StaleTTL        int    `yaml:"stale_ttl"`
		ServeStaleInfinite bool `yaml:"serve_stale_infinite"`
		PrefetchBefore  int    `yaml:"prefetch_before"`
		PrefetchMinHits int    `yaml:"prefetch_min_hits"`
		SweepIntervalS  int    `yaml:"sweep_interval_s"`
		CacheSynthetic  bool   `yaml:"cache_synthetic"`
		CacheLocalIdentity bool   `yaml:"cache_local_identity"`
		CacheUpstreamNegative bool   `yaml:"cache_upstream_negative"`
		AnswerSort      string `yaml:"answer_sort"`
	} `yaml:"cache"`

	Identity struct {
		HostsFiles      []string `yaml:"hosts_files"`
		DnsmasqLeases   []string `yaml:"dnsmasq_leases"`
		IscLeases       []string `yaml:"isc_leases"`
		KeaLeases       []string `yaml:"kea_leases"`
		OdhcpdLeases    []string `yaml:"odhcpd_leases"`
		IPInfoASN       []string `yaml:"ipinfo_asn"`
		ASNCacheDir     string   `yaml:"asn_cache_dir"`
		ASNPollInterval string   `yaml:"asn_poll_interval"`
		ASNFastStart    bool     `yaml:"asn_fast_start"`
		PollInterval    int      `yaml:"poll_interval"`
	} `yaml:"identity"`

	Upstreams map[string]UpstreamGroupConfig `yaml:"upstreams"`

	Routes map[string]RouteConfig `yaml:"routes"`
	RoutesFiles map[string]RouteConfig `yaml:"routes_files"`

	DomainRoutes map[string]DomainRouteConfig `yaml:"domain_routes"`
	DomainRoutesFiles map[string]DomainRouteConfig `yaml:"domain_routes_files"`

	RtypePolicy map[string]string `yaml:"rtype_policy"`
	RtypePolicyFiles map[string]string `yaml:"rtype_policy_files"`

	DomainPolicy map[string]string `yaml:"domain_policy"`
	DomainPolicyFiles map[string]string `yaml:"domain_policy_files"`
	DomainPolicyURLs map[string]string `yaml:"domain_policy_urls"`
	
	RRs map[string]interface{} `yaml:"rrs"` // Global A/AAAA/CNAME spoofed records

	Groups map[string]GroupConfig `yaml:"groups"`
	Parental ParentalConfig `yaml:"parental"`
	WebUI WebUIConfig `yaml:"webui"`
}

var cfg Config

func validateConfig() error {
	// Normalize support_ip_version
	v := strings.ToLower(cfg.Server.SupportIPVersion)
	switch v {
	case "ipv4", "ipv6", "both":
		cfg.Server.SupportIPVersion = v
	default:
		cfg.Server.SupportIPVersion = "both"
	}

	// Normalize Upstream ECH constraint setting
	vUseECH := strings.ToLower(cfg.Server.UseUpstreamECH)
	switch vUseECH {
	case "disable", "try", "strict":
		cfg.Server.UseUpstreamECH = vUseECH
	default:
		cfg.Server.UseUpstreamECH = "disable"
	}

	// Normalize Upstream ECH Hostname evaluation setting
	vHostnameECH := strings.ToLower(cfg.Server.HostnameECH)
	switch vHostnameECH {
	case "strict", "loose", "apex", "any":
		cfg.Server.HostnameECH = vHostnameECH
	default:
		cfg.Server.HostnameECH = "strict"
	}
	
	// Normalize DDR Hostname Source setting
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

	if cfg.Cache.CacheLocalIdentity {
		st := cfg.Server.SyntheticTTL
		if st == 0 {
			st = 60
		}
		pi := cfg.Identity.PollInterval
		if pi > 0 && st > pi {
			return fmt.Errorf(
				"cache_local_identity: synthetic_ttl (%ds) > identity.poll_interval (%ds) — "+
					"stale local addresses may be served; lower synthetic_ttl or raise poll_interval",
				st, pi)
		}
	}

	sortMethod := strings.ToLower(cfg.Cache.AnswerSort)
	switch sortMethod {
	case "", "none", "round-robin", "random", "ip-sort":
		cfg.Cache.AnswerSort = sortMethod
	default:
		log.Printf("[WARN] Invalid cache.answer_sort %q — falling back to 'none'", sortMethod)
		cfg.Cache.AnswerSort = "none"
	}

	for name, grp := range cfg.Groups {
		if grp.Budget == nil {
			continue
		}
		norm := make(map[string]string, len(grp.Budget))
		for k, v := range grp.Budget {
			norm[strings.ToLower(k)] = v
		}
		grp.Budget = norm
		cfg.Groups[name] = grp
	}

	return nil
}

