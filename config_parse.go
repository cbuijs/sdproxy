/*
File:    config_parse.go
Version: 1.0.0 (Split)
Last Updated: 23-Nov-2026 11:43 CET

Description:
  YAML regex-escape pre-sanitization and comma-aware domain/regex key
  tokenizers for `domain_policy` and `rrs`.

  Extracted from config.go 2.0.0 to isolate raw YAML and regex parsing helpers.

Changes:
  1.0.0 - [REFACTOR] Extracted `isRegexKey`, `compileDomainRegex`,
          `rewriteQuotedRegexTokens`, `sanitizeYAMLRegexEscapes`, and
          `splitDomainPolicyKeys` from `config.go`.
*/

package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

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

// rewriteQuotedRegexTokens escapes bare regex backslashes inside `/.../` tokens
// within a single-line YAML double-quoted scalar while leaving non-regex tokens intact.
func rewriteQuotedRegexTokens(content []byte) ([]byte, bool) {
	if bytes.IndexByte(content, '\\') < 0 || bytes.IndexByte(content, '/') < 0 {
		return nil, false
	}

	type span struct{ start, end int }
	var spans []span
	n := len(content)
	k := 0

	for k < n {
		for k < n && (content[k] == ' ' || content[k] == '\t' || content[k] == ',') {
			k++
		}
		if k >= n {
			break
		}
		if content[k] == '/' {
			tokStart := k
			j := k + 1
			inCharClass := false
			classStart := 0
			closed := false
			for j < n {
				if content[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if content[j] == '[' && !inCharClass {
					inCharClass = true
					classStart = j + 1
					j++
					continue
				}
				if content[j] == ']' && inCharClass {
					if j == classStart || (j == classStart+1 && content[classStart] == '^') {
						j++
						continue
					}
					inCharClass = false
					j++
					continue
				}
				if content[j] == '/' && !inCharClass {
					j++
					closed = true
					break
				}
				j++
			}
			if closed && j > tokStart+2 {
				endSpan := j
				onlyWS := true
				for j < n && content[j] != ',' {
					if content[j] != ' ' && content[j] != '\t' {
						onlyWS = false
					}
					j++
				}
				if onlyWS && bytes.IndexByte(content[tokStart:endSpan], '\\') >= 0 {
					spans = append(spans, span{start: tokStart, end: endSpan})
				}
				k = j
				continue
			}
		}
		for k < n && content[k] != ',' {
			k++
		}
	}

	if len(spans) == 0 {
		return nil, false
	}

	var buf bytes.Buffer
	buf.Grow(len(content) + 16)
	pos := 0
	for _, sp := range spans {
		buf.Write(content[pos:sp.start])
		for j := sp.start; j < sp.end; j++ {
			if content[j] == '\\' {
				if j+1 < sp.end {
					next := content[j+1]
					switch next {
					case '\\', '"':
						buf.WriteByte('\\')
						buf.WriteByte(next)
						j++
					default:
						buf.WriteByte('\\')
						buf.WriteByte('\\')
						buf.WriteByte(next)
						j++
					}
				} else {
					buf.WriteByte('\\')
					buf.WriteByte('\\')
				}
			} else {
				buf.WriteByte(content[j])
			}
		}
		pos = sp.end
	}
	buf.Write(content[pos:])
	return buf.Bytes(), true
}

func sanitizeYAMLRegexEscapes(data []byte) []byte {
	if bytes.IndexByte(data, '\\') < 0 {
		return data
	}

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
				if rewritten, changed := rewriteQuotedRegexTokens(content); changed {
					out.WriteByte('"')
					out.Write(rewritten)
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
			classStart := 0
			closed := false
			for j < n {
				if trimmed[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if trimmed[j] == '[' && !inCharClass {
					inCharClass = true
					classStart = j + 1
					j++
					continue
				}
				if trimmed[j] == ']' && inCharClass {
					if j == classStart || (j == classStart+1 && trimmed[classStart] == '^') {
						j++
						continue
					}
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
