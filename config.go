/*
File:    config.go
Version: 1.83.0
Last Updated: 23-Oct-2026 17:03 CEST

Description:
  All YAML-mapped configuration structs for sdproxy. Covers every top-level
  config section: server, logging, cache, identity, upstreams, routes,
  domain_routes, rtype/domain policy, parental groups, categories, webui,
  and spoofed records (RRs).

Changes:
  1.83.0 - [FIX] Handled escaped forward slashes (`\/`) inside character classes
           `[...]` and preserved regex patterns containing unescaped `/` inside
           character classes (e.g. `/^[a/b]\.com$/`) in `splitDomainPolicyKeys`.
  1.82.0 - [FIX] Supported mixed comma-separated plain domains and slash-delimited
           regex patterns (`/pattern/`) on the same key in `splitDomainPolicyKeys`
           without splitting commas inside regex quantifiers (e.g. `{1,3}`) or
           escaped slashes (`\/`).
  1.81.0 - [FIX] Preserved escaped double quotes (`\"`) inside double-quoted regex
           keys when compiling patterns in `compileDomainRegex`.
  1.80.0 - [FIX] Fixed comment-awareness in `sanitizeYAMLRegexEscapes` so `#`
           characters inside unquoted URLs (e.g. `doh://...#1.1.1.1`) are not
           misidentified as YAML comments when a double-quoted regex appears on
           the same line, and prevented comment scanning from swallowing quotes.
  1.79.0 - [FEAT/FIX] Added `sanitizeYAMLRegexEscapes` so double-quoted YAML regex
           scalars (`"/^...\.com$/"`) support standard single-backslash regex escapes
           (`\d`, `\.`, `\b`, `\w`, `\-`, etc.) without YAML escape errors or double
           backslashes, and normalized `\/` inside `compileDomainRegex`.
  1.78.0 - [FEAT] Added startup/config-test regex validation (`isRegexKey`,
           `compileDomainRegex`, `splitDomainPolicyKeys`) for `domain_policy`,
           `domain_policy_files`, `rrs`, and `groups.<group>.rrs`.
  1.77.0 - [FEAT] Added `ExemptSharedHosting` boolean option (`exempt_shared_hosting`)
           under `Server.SubdomainLimit` (default: false) to optionally include
           `sharedHostingDomains` from `sharedhosting.go` as exempted domains.
  1.76.0 - [SECURITY/FIX] Resolved YAML unmarshaling nil pointer dereference 
           vulnerabilities. Instantiated default map structures natively within 
           `UnmarshalYAML` logic for `RouteConfig`, `DomainRouteConfig`, and 
           `UpstreamGroupConfig` to definitively prevent panics on partial arrays.
  1.75.0 - [FEAT] Added `SubdomainLimit` configuration structures and validation bounds.
*/

package main

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Regex helpers for domain_policy and rrs
// ---------------------------------------------------------------------------

// isRegexKey reports whether s is enclosed in forward slashes ("/pattern/").
func isRegexKey(s string) bool {
	return len(s) >= 2 && s[0] == '/' && s[len(s)-1] == '/'
}

// compileDomainRegex validates and compiles a slash-delimited regex key ("/pattern/").
// Case-insensitivity (?i) is prepended automatically because DNS domain names
// are normalized to lowercase before matching. Escaped forward slashes (\/) are
// unescaped to / for PCRE/JS convention compatibility.
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

// sanitizeYAMLRegexEscapes pre-processes raw YAML configuration bytes so that
// double-quoted regex scalars ("/.../") can use standard single-backslash regex
// escapes (e.g., \., \d, \w, \s, \b, \-, \(, \)) without triggering YAML's
// "unknown escape character" lexer error or turning \b into an ASCII backspace.
func sanitizeYAMLRegexEscapes(data []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(data) + 64)

	i := 0
	n := len(data)
	for i < n {
		c := data[i]

		// Skip YAML comments (only when '#' is at start of line or preceded by whitespace)
		if c == '#' && (i == 0 || data[i-1] == ' ' || data[i-1] == '\t' || data[i-1] == '\n' || data[i-1] == '\r') {
			for i < n && data[i] != '\n' {
				out.WriteByte(data[i])
				i++
			}
			continue
		}

		// Skip single-quoted YAML strings untouched
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

		// Inspect double-quoted YAML strings
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
									// Already escaped backslash or escaped double-quote: keep as-is
									out.WriteByte('\\')
									out.WriteByte(next)
									j++
								default:
									// Escape the backslash for YAML so the regex engine receives \<next>
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

// splitDomainPolicyKeys splits a raw domain_policy or rrs key into individual tokens.
// Commas outside slash-delimited regex tokens (/.../) split tokens, while commas
// inside regex quantifiers (e.g. {1,3}), character classes ([...]), and escaped
// slashes (\/) are preserved intact.
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
			i++
			inCharClass := false
			for i < n {
				if trimmed[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if trimmed[i] == '[' && !inCharClass {
					inCharClass = true
					i++
					continue
				}
				if trimmed[i] == ']' && inCharClass {
					inCharClass = false
					i++
					continue
				}
				if trimmed[i] == '/' && !inCharClass {
					i++
					break
				}
				i++
			}
			for i < n && trimmed[i] != ',' {
				i++
			}
			tok := strings.TrimSpace(trimmed[start:i])
			if tok != "" {
				out = append(out, tok)
			}
		} else {
			start := i
			for i < n && trimmed[i] != ',' {
				i++
			}
			tok := strings.TrimSpace(trimmed[start:i])
			if tok != "" {
				out = append(out, tok)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// ACLConfig
// ---------------------------------------------------------------------------

// ACLConfig holds IP/Subnet allow and deny lists.
type ACLConfig struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

// ---------------------------------------------------------------------------
// ECSConfig (EDNS0 Client Subnet)
// ---------------------------------------------------------------------------

// ECSConfig manages the insertion or removal of client IP subnets from upstream queries.
type ECSConfig struct {
	Action   string `yaml:"action"`
	IPv4Mask int    `yaml:"ipv4_mask"`
	IPv6Mask int    `yaml:"ipv6_mask"`
}

// ---------------------------------------------------------------------------
// RouteConfig / ParsedRoute
// ---------------------------------------------------------------------------

// RouteConfig maps a MAC/IP/CIDR/ASN key to an upstream group, an optional client
// name override, the optional bypass_local flag, an optional parental group,
// and an explicit DNS return code (rcode) for instant policy enforcement.
type RouteConfig struct {
	Rcode        string `yaml:"rcode"`
	Upstream     string `yaml:"upstream"`
	ClientName   string `yaml:"client_name"`
	BypassLocal  bool   `yaml:"bypass_local"`
	BypassGlobal bool   `yaml:"bypass_global"`
	Group        string `yaml:"group"`
	Force        bool   `yaml:"force"`
	ForceAnd     bool   `yaml:"force-and"`
}

// ParsedRoute is the resolved runtime form of RouteConfig.
// Evaluates explicit policy actions (HasRcode) strictly over network targets.
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
	Strategy          string    `yaml:"strategy"`
	Preference        string    `yaml:"preference"`
	Mode              string    `yaml:"mode"`
	IgnoreQnameLabels bool      `yaml:"ignore_qname_labels"`
	ECS               ECSConfig `yaml:"ecs"`
	Servers           []string  `yaml:"servers"`
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

// ---------------------------------------------------------------------------
// ParentalConfig
// ---------------------------------------------------------------------------

type ParentalConfig struct {
	FastStart                    bool                      `yaml:"fast_start"`
	ForcedTTL                    int                       `yaml:"forced_ttl"`
	BlockTTL                     int                       `yaml:"block_ttl"`
	TickerInterval               int                       `yaml:"ticker_interval"`
	DefaultIdlePause             string                    `yaml:"default_idle_pause"`
	DefaultSessionWindow         string                    `yaml:"default_session_window"`
	TimeOffsetHours              int                       `yaml:"time_offset_hours"` // Adjusts schedule logic cleanly against specific timezones
	SnapshotDir                  string                    `yaml:"snapshot_dir"`
	Consolidation                *bool                     `yaml:"consolidation"`
	SynthesiseParents            *bool                     `yaml:"synthesise_parents"`
	RemoveRedundantSubdomains    *bool                     `yaml:"remove_redundant_subdomains"`
	StripServiceLabels           *bool                     `yaml:"strip_service_labels"`
	ParentConsolidationThreshold int                       `yaml:"parent_consolidation_threshold"`
	ConsolidationHomogeneityPct  int                       `yaml:"consolidation_homogeneity_pct"`
	Categories                   map[string]CategoryConfig `yaml:"categories"`
}

// ---------------------------------------------------------------------------
// WebUIConfig
// ---------------------------------------------------------------------------

type WebUIConfig struct {
	Enabled     bool      `yaml:"enabled"`
	Listen      string    `yaml:"listen"`
	ListenHTTP  []string  `yaml:"listen_http"`
	ListenHTTPS []string  `yaml:"listen_https"`
	ForceHTTPS  bool      `yaml:"force_https"`
	Password    string    `yaml:"password"`
	APIToken    string    `yaml:"api_token"`
	ACL         ACLConfig `yaml:"acl"`

	LoginRatelimit struct {
		Enabled        bool `yaml:"enabled"`
		MaxAttempts    int  `yaml:"max_attempts"`
		LockoutMinutes int  `yaml:"lockout_minutes"`
	} `yaml:"login_ratelimit"`

	StatsEnabled          bool   `yaml:"stats_enabled"`
	StatsRefreshSec       int    `yaml:"stats_refresh_sec"`
	StatsTopN             int    `yaml:"stats_top_n"`
	StatsGraphsEnabled    bool   `yaml:"stats_graphs_enabled"`
	HistoryDir            string `yaml:"history_dir"`
	HistoryRetentionHours int    `yaml:"history_retention_hours"`
	HistorySaveInterval   string `yaml:"history_save_interval"`
}

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

type Config struct {
	Server struct {
		FastStart         bool      `yaml:"fast_start"`
		ListenUDP         []string  `yaml:"listen_udp"`
		ListenTCP         []string  `yaml:"listen_tcp"`
		ListenDoT         []string  `yaml:"listen_dot"`
		ListenDoH         []string  `yaml:"listen_doh"`
		ListenDoQ         []string  `yaml:"listen_doq"`
		UDPWorkers        int       `yaml:"udp_workers"`
		TLSCert           string    `yaml:"tls_cert"`
		TLSKey            string    `yaml:"tls_key"`
		MemoryLimitMB     int       `yaml:"memory_limit_mb"`
		MaxTCPConnections int       `yaml:"max_tcp_connections"`
		ACL               ACLConfig `yaml:"acl"`

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

		// Subdomain Rate Limiting (Info-Stealer Defense)
		SubdomainLimit struct {
			Enabled             bool     `yaml:"enabled"`
			Threshold           int      `yaml:"threshold"`
			WindowMinutes       int      `yaml:"window_minutes"`
			Action              string   `yaml:"action"`
			MaxTrackedApexes    int      `yaml:"max_tracked_apexes"`
			ExemptSharedHosting bool     `yaml:"exempt_shared_hosting"`
			Exempt              []string `yaml:"exempt"`
		} `yaml:"subdomain_limit"`

		SupportIPVersion           string    `yaml:"support_ip_version"`
		BlockAction                string    `yaml:"block_action"`
		BlockIPs                   []string  `yaml:"block_ips"`
		RebindingProtection        bool      `yaml:"rebinding_protection"`
		SearchDomainLeakPrevention *bool     `yaml:"search_domain_leak_prevention"`
		FilterAAAA                 bool      `yaml:"filter_aaaa"`
		FilterIPs                  bool      `yaml:"filter_ips"`
		StrictPTR                  bool      `yaml:"strict_ptr"`
		FlattenCNAME               bool      `yaml:"flatten_cname"`
		TargetName                 bool      `yaml:"target_name"`
		MinimizeAnswer             bool      `yaml:"minimize_answer"`
		BlockObsoleteQtypes        bool      `yaml:"block_obsolete_qtypes"`
		UpstreamSelection          string    `yaml:"upstream_selection"`
		UpstreamStaggerMs          int       `yaml:"upstream_stagger_ms"`
		UpstreamTimeoutMs          int       `yaml:"upstream_timeout_ms"`
		MaxSecureUpstreams         int       `yaml:"max_secure_upstreams"`
		SyntheticTTL               int       `yaml:"synthetic_ttl"`
		BootstrapServers           []string  `yaml:"bootstrap_servers"`
		UseUpstreamECH             string    `yaml:"use_upstream_ech"`
		HostnameECH                string    `yaml:"hostname_ech"`
		UpgradeDoH3                bool      `yaml:"upgrade_doh3"`
		PolicyCacheDir             string    `yaml:"policy_cache_dir"`
		PolicyPollInterval         string    `yaml:"policy_poll_interval"`
		UserAgent                  string    `yaml:"user_agent"`
		ECHConfigList              string    `yaml:"ech_config_list"`
		ECHKey                     string    `yaml:"ech_key"`
		ECS                        ECSConfig `yaml:"ecs"`

		QnameMinLabels int `yaml:"qname_min_labels"`
		QnameMaxLabels int `yaml:"qname_max_labels"`

		DDR struct {
			Enabled        bool     `yaml:"enabled"`
			HostnameSource string   `yaml:"hostname_source"`
			Hostnames      []string `yaml:"hostnames"`
			IPv4           []string `yaml:"ipv4"`
			IPv6           []string `yaml:"ipv6"`
		} `yaml:"ddr"`
	} `yaml:"server"`

	Logging struct {
		LogQueries    *bool `yaml:"log_queries"`
		StripTime     bool  `yaml:"strip_time"`
		LogASNDetails bool  `yaml:"log_asn_details"`
		LogStrategy   bool  `yaml:"log_strategy"`
		LogParental   *bool `yaml:"log_parental"`
		LogIdentity   *bool `yaml:"log_identity"`
		LogCaching    *bool `yaml:"log_caching"`
		LogDDR        *bool `yaml:"log_ddr"`
		LogTLS        *bool `yaml:"log_tls"`
		LogSystem     *bool `yaml:"log_system"`
		LogWebUI      *bool `yaml:"log_webui"`
		LogRouting    *bool `yaml:"log_routing"`
	} `yaml:"logging"`

	Cache struct {
		Enabled               bool   `yaml:"enabled"`
		Size                  int    `yaml:"size"`
		Persist               bool   `yaml:"persist"`
		PersistFile           string `yaml:"persist_file"`
		PersistSaveInterval   string `yaml:"persist_save_interval"`
		MinTTL                int    `yaml:"min_ttl"`
		MaxTTL                int    `yaml:"max_ttl"`
		NegativeTTL           int    `yaml:"negative_ttl"`
		StaleTTL              int    `yaml:"stale_ttl"`
		ServeStaleInfinite    bool   `yaml:"serve_stale_infinite"`
		PrefetchBefore        int    `yaml:"prefetch_before"`
		PrefetchMinHits       int    `yaml:"prefetch_min_hits"`
		SweepIntervalS        int    `yaml:"sweep_interval_s"`
		CacheSynthetic        bool   `yaml:"cache_synthetic"`
		CacheLocalIdentity    bool   `yaml:"cache_local_identity"`
		CacheUpstreamNegative bool   `yaml:"cache_upstream_negative"`
		AnswerSort            string `yaml:"answer_sort"`
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

	Routes      map[string]RouteConfig `yaml:"routes"`
	RoutesFiles map[string]RouteConfig `yaml:"routes_files"`

	DomainRoutes      map[string]DomainRouteConfig `yaml:"domain_routes"`
	DomainRoutesFiles map[string]DomainRouteConfig `yaml:"domain_routes_files"`

	RtypePolicy      map[string]string `yaml:"rtype_policy"`
	RtypePolicyFiles map[string]string `yaml:"rtype_policy_files"`

	DomainPolicy      map[string]string `yaml:"domain_policy"`
	DomainPolicyFiles map[string]string `yaml:"domain_policy_files"`
	DomainPolicyURLs  map[string]string `yaml:"domain_policy_urls"`

	RRs map[string]interface{} `yaml:"rrs"` // Global A/AAAA/CNAME spoofed records

	Groups   map[string]GroupConfig `yaml:"groups"`
	Parental ParentalConfig         `yaml:"parental"`
	WebUI    WebUIConfig            `yaml:"webui"`
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

	if cfg.Server.MaxSecureUpstreams <= 0 {
		cfg.Server.MaxSecureUpstreams = 5
	}

	// Subdomain Limit Normalization
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

	// Normalize global ECS parameters
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

	// Normalize QNAME label bounds dynamically natively ensuring correct bounds
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
		if pi > 0 && st > pi {
			log.Printf("[WARN] cache_local_identity: synthetic_ttl (%ds) > identity.poll_interval (%ds) — stale local addresses may be served; lower synthetic_ttl or raise poll_interval\n", st, pi)
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
				for bk, bv := range v.Budget {
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

	// Validate regex syntax in rrs (global and per-group)
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

	// Validate regex syntax in domain_policy and domain_policy_files
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
