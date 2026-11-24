/*
File:    config_yaml.go
Version: 1.1.0 (Split)
Last Updated: 23-Nov-2026 14:35 CET

Description:
  YAML AST transformation engine powering `--update-config` (`-U`),
  `--full-clean-config` (`-F`), and `--clean-config` (`-C`).
  Handles reference-comment preservation, legacy alias normalization,
  default-value pruning, and canonical section/key ordering.

  Extracted from config.go 2.0.0 to isolate CLI YAML AST serialization.

Changes:
  1.1.0 - [FIX] Dropped empty `webui.listen: ""` scalars in
          `normalizeUserConfigAliases` instead of converting them into invalid
          `listen_http: [""]` lists, and normalized non-default `upstreams`
          enum fields (`strategy`, `preference`, `mode`, `ecs.action`) to
          lowercase in `CleanConfigYAML`.
  1.0.0 - [REFACTOR] Extracted `UpdateConfigYAML`, `FullCleanConfigYAML`,
          `CleanConfigYAML`, and YAML AST helper routines from `config.go`.
*/

package main

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

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

func buildMergedReferenceYAMLDoc(userYAMLBytes []byte) (*yaml.Node, error) {
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
	return &refDoc, nil
}

func UpdateConfigYAML(userYAMLBytes []byte) ([]byte, error) {
	refDoc, err := buildMergedReferenceYAMLDoc(userYAMLBytes)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(refDoc); err != nil {
		return nil, err
	}
	_ = enc.Close()

	return formatUpdatedYAMLSpacing(buf.Bytes()), nil
}

func FullCleanConfigYAML(userYAMLBytes []byte) ([]byte, error) {
	refDoc, err := buildMergedReferenceYAMLDoc(userYAMLBytes)
	if err != nil {
		return nil, err
	}

	stripAllYAMLComments(refDoc)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(refDoc); err != nil {
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

func fillMissingYAMLMappingKeys(targetMap, aliasMap *yaml.Node) {
	if targetMap == nil || aliasMap == nil || targetMap.Kind != yaml.MappingNode || aliasMap.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(aliasMap.Content); i += 2 {
		ak := aliasMap.Content[i]
		av := aliasMap.Content[i+1]
		if findYAMLMapKeyIndex(targetMap, ak.Value) < 0 {
			targetMap.Content = append(targetMap.Content, cloneYAMLNode(ak), cloneYAMLNode(av))
		}
	}
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
				for j := 0; j+1 < len(vNode.Content); {
					sk := vNode.Content[j]
					sv := vNode.Content[j+1]
					if sk.Value == "subdomain_limiter" || sk.Value == "subnet_limiter" || sk.Value == "subnet_limit" {
						canonicalIdx := findYAMLMapKeyIndex(vNode, "subdomain_limit")
						if canonicalIdx < 0 {
							sk.Value = "subdomain_limit"
							j += 2
						} else {
							fillMissingYAMLMappingKeys(vNode.Content[canonicalIdx+1], sv)
							vNode.Content = append(vNode.Content[:j], vNode.Content[j+2:]...)
						}
						continue
					}
					j += 2
				}
				if rfcIdx := findYAMLMapKeyIndex(vNode, "rfc_compliance"); rfcIdx >= 0 {
					rfcVal := vNode.Content[rfcIdx+1]
					if rfcVal.Kind == yaml.ScalarNode {
						vNode.Content[rfcIdx+1] = &yaml.Node{
							Kind: yaml.MappingNode,
							Content: []*yaml.Node{
								{Kind: yaml.ScalarNode, Tag: "!!str", Value: "action"},
								cloneYAMLNode(rfcVal),
							},
						}
					}
				}
				if idnIdx := findYAMLMapKeyIndex(vNode, "idn_homograph"); idnIdx >= 0 {
					idnVal := vNode.Content[idnIdx+1]
					if idnVal.Kind == yaml.ScalarNode {
						vNode.Content[idnIdx+1] = &yaml.Node{
							Kind: yaml.MappingNode,
							Content: []*yaml.Node{
								{Kind: yaml.ScalarNode, Tag: "!!str", Value: "action"},
								cloneYAMLNode(idnVal),
							},
						}
					}
				}
			}
		case "webui":
			if vNode.Kind == yaml.MappingNode {
				listenIdx := findYAMLMapKeyIndex(vNode, "listen")
				if listenIdx >= 0 {
					listenVal := vNode.Content[listenIdx+1]
					if findYAMLMapKeyIndex(vNode, "listen_http") < 0 && listenVal.Kind == yaml.ScalarNode && strings.TrimSpace(listenVal.Value) != "" {
						vNode.Content[listenIdx].Value = "listen_http"
						vNode.Content[listenIdx+1] = &yaml.Node{
							Kind:    yaml.SequenceNode,
							Style:   yaml.FlowStyle,
							Content: []*yaml.Node{cloneYAMLNode(listenVal)},
						}
					} else {
						vNode.Content = append(vNode.Content[:listenIdx], vNode.Content[listenIdx+2:]...)
					}
				}
			}
		case "parental":
			if vNode.Kind == yaml.MappingNode {
				dswIdx := findYAMLMapKeyIndex(vNode, "default_session_window")
				if dswIdx >= 0 {
					if findYAMLMapKeyIndex(vNode, "default_idle_pause") < 0 {
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
							for m := 0; m+1 < len(catVal.Content); {
								mk := catVal.Content[m]
								if mk.Value == "list_url" || mk.Value == "list_urls" {
									if findYAMLMapKeyIndex(catVal, "source") < 0 {
										mk.Value = "source"
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

			if uVal.Kind == yaml.MappingNode {
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
					for c := 0; c+1 < len(uVal.Content); c += 2 {
						ck := uVal.Content[c]
						cv := uVal.Content[c+1]
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

			if rVal.Kind == yaml.MappingNode && uVal.Kind == yaml.MappingNode {
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

func isDefaultRFCChecks(checks []string) bool {
	if len(checks) != 5 {
		return false
	}
	want := [5]string{"NS", "MX", "SRV", "SOA", "CNAME"}
	for i := range want {
		if !strings.EqualFold(strings.TrimSpace(checks[i]), want[i]) {
			return false
		}
	}
	return true
}

func CleanConfigYAML(c Config, userYAMLBytes ...[]byte) ([]byte, error) {
	effectiveGlobalStrategy := strings.ToLower(strings.TrimSpace(c.Server.UpstreamSelection))
	if effectiveGlobalStrategy == "" {
		effectiveGlobalStrategy = "stagger"
	}
	effectiveGlobalECSAction := strings.ToLower(strings.TrimSpace(c.Server.ECS.Action))
	if effectiveGlobalECSAction == "" {
		effectiveGlobalECSAction = "remove"
	}
	effectiveGlobalECSV4Mask := c.Server.ECS.IPv4Mask
	if effectiveGlobalECSV4Mask <= 0 || effectiveGlobalECSV4Mask > 32 {
		effectiveGlobalECSV4Mask = 24
	}
	effectiveGlobalECSV6Mask := c.Server.ECS.IPv6Mask
	if effectiveGlobalECSV6Mask <= 0 || effectiveGlobalECSV6Mask > 128 {
		effectiveGlobalECSV6Mask = 56
	}

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
	} else if c.Server.BlockAction != "" {
		c.Server.BlockAction = strings.ToUpper(strings.TrimSpace(c.Server.BlockAction))
	}
	if !strings.EqualFold(c.Server.BlockAction, "IP") {
		c.Server.BlockIPs = nil
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.ForSale)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.ForSale = ""
	default:
		c.Server.ForSale = strings.ToUpper(strings.TrimSpace(c.Server.ForSale))
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.Parked)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.Parked = ""
	default:
		c.Server.Parked = strings.ToUpper(strings.TrimSpace(c.Server.Parked))
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.RFCCompliance.Action)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.RFCCompliance = RFCComplianceConfig{}
	default:
		c.Server.RFCCompliance.Action = strings.ToUpper(strings.TrimSpace(c.Server.RFCCompliance.Action))
		if isDefaultRFCChecks(c.Server.RFCCompliance.Checks) {
			c.Server.RFCCompliance.Checks = nil
		}
	}
	switch strings.ToUpper(strings.TrimSpace(c.Server.IDNHomograph.Action)) {
	case "", "DISABLE", "DISABLED", "OFF", "FALSE", "NONE":
		c.Server.IDNHomograph = IDNHomographConfig{}
	default:
		c.Server.IDNHomograph.Action = strings.ToUpper(strings.TrimSpace(c.Server.IDNHomograph.Action))
		if c.Server.IDNHomograph.MixedScript != nil && *c.Server.IDNHomograph.MixedScript {
			c.Server.IDNHomograph.MixedScript = nil
		}
		if c.Server.IDNHomograph.ASCIILookalikes != nil && *c.Server.IDNHomograph.ASCIILookalikes {
			c.Server.IDNHomograph.ASCIILookalikes = nil
		}
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

	if strings.EqualFold(c.Server.ECS.Action, "remove") || c.Server.ECS.Action == "" {
		c.Server.ECS = ECSConfig{}
	} else {
		c.Server.ECS.Action = strings.ToLower(strings.TrimSpace(c.Server.ECS.Action))
		if c.Server.ECS.IPv4Mask == 24 {
			c.Server.ECS.IPv4Mask = 0
		}
		if c.Server.ECS.IPv6Mask == 56 {
			c.Server.ECS.IPv6Mask = 0
		}
	}

	if !c.Server.DDR.Enabled {
		c.Server.DDR.HostnameSource = ""
		c.Server.DDR.Hostnames = nil
		c.Server.DDR.IPv4 = nil
		c.Server.DDR.IPv6 = nil
	} else if strings.EqualFold(c.Server.DDR.HostnameSource, "strict") {
		c.Server.DDR.HostnameSource = ""
	}

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

	if !c.Server.DGA.Enabled {
		c.Server.DGA.Threshold = 0
		c.Server.DGA.Action = ""
	} else {
		if c.Server.DGA.Threshold == 80.0 {
			c.Server.DGA.Threshold = 0
		}
		if strings.EqualFold(c.Server.DGA.Action, "BLOCK") {
			c.Server.DGA.Action = ""
		} else if c.Server.DGA.Action != "" {
			c.Server.DGA.Action = strings.ToUpper(strings.TrimSpace(c.Server.DGA.Action))
		}
	}

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
		} else if c.Server.Exfiltration.Action != "" {
			c.Server.Exfiltration.Action = strings.ToUpper(strings.TrimSpace(c.Server.Exfiltration.Action))
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

	mergedSDL := c.Server.SubdomainLimit
	if len(mergedSDL.Exempt) > 0 {
		mergedSDL.Exempt = append([]string(nil), mergedSDL.Exempt...)
	}
	mergeSubdomainLimitConfig(&mergedSDL, c.Server.SubdomainLimiter)
	mergeSubdomainLimitConfig(&mergedSDL, c.Server.SubnetLimiter)
	mergeSubdomainLimitConfig(&mergedSDL, c.Server.SubnetLimit)
	c.Server.SubdomainLimit = mergedSDL
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
		} else if c.Server.SubdomainLimit.Action != "" {
			c.Server.SubdomainLimit.Action = strings.ToUpper(strings.TrimSpace(c.Server.SubdomainLimit.Action))
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
		c.Cache.RcodeTTL = 0
		c.Cache.RcodeMinTTL = 0
		c.Cache.RcodeMaxTTL = 0
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
	if len(c.Upstreams) > 0 {
		cleanUpstreams := make(map[string]UpstreamGroupConfig, len(c.Upstreams))
		for k, u := range c.Upstreams {
			u.Strategy = strings.ToLower(strings.TrimSpace(u.Strategy))
			if u.Strategy == effectiveGlobalStrategy {
				u.Strategy = ""
			}
			u.Preference = strings.ToLower(strings.TrimSpace(u.Preference))
			if u.Preference == "fastest" {
				u.Preference = ""
			}
			u.Mode = strings.ToLower(strings.TrimSpace(u.Mode))
			if u.Mode == "loose" {
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

			u.ECS.Action = strings.ToLower(strings.TrimSpace(u.ECS.Action))
			effGroupECSAction := u.ECS.Action
			if effGroupECSAction == "" {
				effGroupECSAction = effectiveGlobalECSAction
			}
			if u.ECS.Action == effectiveGlobalECSAction {
				u.ECS.Action = ""
			}
			if effGroupECSAction == "remove" {
				u.ECS.IPv4Mask = 0
				u.ECS.IPv6Mask = 0
			} else {
				if u.ECS.IPv4Mask == effectiveGlobalECSV4Mask {
					u.ECS.IPv4Mask = 0
				}
				if u.ECS.IPv6Mask == effectiveGlobalECSV6Mask {
					u.ECS.IPv6Mask = 0
				}
			}
			cleanUpstreams[k] = u
		}
		c.Upstreams = cleanUpstreams
	}

	// ── GROUPS & PARENTAL ─────────────────────────────────────────────────
	if len(c.Groups) == 0 {
		c.Parental = ParentalConfig{}
	} else {
		effParentalBlockTTL := c.Parental.BlockTTL
		if effParentalBlockTTL <= 0 {
			effParentalBlockTTL = 20
		}

		cleanGroups := make(map[string]GroupConfig, len(c.Groups))
		for k, g := range c.Groups {
			if strings.EqualFold(g.BudgetTracking, "group") {
				g.BudgetTracking = ""
			}
			if g.BlockTTL == effParentalBlockTTL {
				g.BlockTTL = 0
			}
			cleanGroups[k] = g
		}
		c.Groups = cleanGroups

		if c.Parental.DefaultIdlePause == "" && c.Parental.DefaultSessionWindow != "" {
			c.Parental.DefaultIdlePause = c.Parental.DefaultSessionWindow
		}
		c.Parental.DefaultSessionWindow = ""

		effDefaultIdle := c.Parental.DefaultIdlePause
		if effDefaultIdle == "" {
			effDefaultIdle = "2m"
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

		if len(c.Parental.Categories) > 0 {
			cleanCats := make(map[string]CategoryConfig, len(c.Parental.Categories))
			for k, cat := range c.Parental.Categories {
				if cat.IdlePause == "" && cat.SessionWindow != "" {
					cat.IdlePause = cat.SessionWindow
				}
				cat.SessionWindow = ""
				if cat.IdlePause == effDefaultIdle {
					cat.IdlePause = ""
				}
				if len(cat.ListURLs) > 0 || len(cat.Add) > 0 || len(cat.Remove) > 0 || cat.IdlePause != "" {
					cleanCats[k] = cat
				}
			}
			c.Parental.Categories = cleanCats
		}
	}

	// ── WEBUI ─────────────────────────────────────────────────────────────
	if !c.WebUI.Enabled {
		c.WebUI = WebUIConfig{}
	} else {
		if len(c.WebUI.ListenHTTP) == 0 && c.WebUI.Listen != "" {
			c.WebUI.ListenHTTP = []string{c.WebUI.Listen}
		}
		c.WebUI.Listen = ""
		if len(c.WebUI.ListenHTTP) == 1 && c.WebUI.ListenHTTP[0] == "127.0.0.1:8080" && len(c.WebUI.ListenHTTPS) == 0 {
			c.WebUI.ListenHTTP = nil
		}
		if !c.WebUI.LoginRatelimit.Enabled {
			c.WebUI.LoginRatelimit.MaxAttempts = 0
			c.WebUI.LoginRatelimit.LockoutMinutes = 0
		} else {
			if c.WebUI.LoginRatelimit.MaxAttempts == 5 {
				c.WebUI.LoginRatelimit.MaxAttempts = 0
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
