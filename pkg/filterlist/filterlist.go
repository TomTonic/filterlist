// Package filterlist parses AdGuard, EasyList, and hosts-style filter lists
// into canonical Rule objects that represent domain-focused blocking or allow rules.
//
// Supported constructs:
//   - Domain filters: "example.com", "||example.com^", "||sub.example.com^"
//   - Exception rules: "@@||example.com^"
//   - Wildcards: "||*.ads.example.com^", "ads*.example.com"
//   - Hosts entries: "0.0.0.0 example.com", "127.0.0.1 example.com"
//
// Unsupported constructs (logged and skipped):
//   - CSS selectors (##, #@#)
//   - Scriptlets and advanced modifiers ($script, $domain=, $third-party, etc.)
//   - Path-only rules without hostnames
package filterlist

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/tomtonic/coredns-regfilter/internal/util"
)

// Rule represents a single parsed filter rule with a canonical pattern.
type Rule struct {
	// Pattern is the canonical domain pattern.
	// It uses a restricted subset: literal chars, '*' for wildcard sequences,
	// '.' for literal dot. Implicitly anchored as a full-match.
	Pattern string
	// Source is the origin of this rule, typically "filepath:line".
	Source string
	// IsAllow is true for exception/whitelist rules (@@).
	IsAllow bool
}

// Logger is a minimal logging interface to avoid hard dependency on a specific logger.
type Logger interface {
	Warnf(format string, args ...interface{})
}

type nopLogger struct{}

func (nopLogger) Warnf(string, ...interface{}) {}

// ParseFile reads a filter list file and returns all successfully parsed rules.
// Lines that cannot be parsed are logged via logger and skipped.
func ParseFile(path string, logger Logger) ([]Rule, error) {
	if logger == nil {
		logger = nopLogger{}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("filterlist: open %s: %w", path, err)
	}
	defer f.Close()

	var rules []Rule
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		rule, err := ParseLine(line)
		if err != nil {
			if err != errSkip {
				logger.Warnf("%s:%d: %v", path, lineNum, err)
			}
			continue
		}
		rule.Source = fmt.Sprintf("%s:%d", path, lineNum)
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return rules, fmt.Errorf("filterlist: read %s: %w", path, err)
	}
	return rules, nil
}

// errSkip is a sentinel for blank/comment lines that should be silently skipped.
var errSkip = fmt.Errorf("skip")

// ParseLine parses a single filter list line into a Rule.
// Returns errSkip for blank lines and comments.
// Returns a descriptive error for unsupported or invalid constructs.
func ParseLine(line string) (Rule, error) {
	line = strings.TrimSpace(line)

	// Skip empty lines
	if line == "" {
		return Rule{}, errSkip
	}

	// Skip comments
	if line[0] == '!' || line[0] == '#' || strings.HasPrefix(line, "[Adblock") {
		return Rule{}, errSkip
	}

	// Reject CSS selectors
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") {
		return Rule{}, fmt.Errorf("unsupported CSS selector rule: %s", truncate(line, 80))
	}

	// Check for exception rule prefix
	isAllow := false
	work := line
	if strings.HasPrefix(work, "@@") {
		isAllow = true
		work = work[2:]
	}

	// Try hosts-style first: "IP domain [domain...]"
	if rule, err := tryParseHosts(work, isAllow); err == nil {
		return rule, nil
	} else if err == errSkip {
		return Rule{}, errSkip
	}
	// err == errNotHosts means it's not a hosts line, fall through

	// Strip AdGuard/EasyList modifiers ($...) — we ignore rules with
	// non-domain modifiers but still try to extract the domain part.
	if idx := strings.LastIndex(work, "$"); idx >= 0 {
		modifiers := work[idx+1:]
		// Check for modifiers we explicitly don't support as they change semantics
		if containsUnsupportedModifier(modifiers) {
			return Rule{}, fmt.Errorf("unsupported modifier in rule: %s", truncate(line, 80))
		}
		work = work[:idx]
	}

	// Parse AdGuard/EasyList domain pattern
	pattern, err := parseAdGuardPattern(work)
	if err != nil {
		return Rule{}, err
	}

	if pattern == "" {
		return Rule{}, fmt.Errorf("empty pattern after parsing: %s", truncate(line, 80))
	}

	return Rule{Pattern: pattern, IsAllow: isAllow}, nil
}

var errNotHosts = fmt.Errorf("not hosts")

// tryParseHosts attempts to parse a hosts-style line (e.g. "0.0.0.0 example.com").
// Returns errNotHosts if the line is not hosts-style, errSkip for localhost entries.
func tryParseHosts(line string, isAllow bool) (Rule, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Rule{}, errNotHosts
	}

	ip := fields[0]
	if !isHostsIP(ip) {
		return Rule{}, errNotHosts
	}

	// Take the first domain (ignore additional domains on the same line for simplicity,
	// but a production version could emit multiple rules).
	domain := strings.ToLower(fields[1])

	// Skip localhost entries
	if domain == "localhost" || domain == "localhost.localdomain" ||
		domain == "local" || domain == "broadcasthost" ||
		domain == "ip6-localhost" || domain == "ip6-loopback" ||
		domain == "ip6-localnet" || domain == "ip6-mcastprefix" ||
		domain == "ip6-allnodes" || domain == "ip6-allrouters" {
		return Rule{}, errSkip
	}

	if !util.IsValidDNSName(domain) {
		return Rule{}, errNotHosts
	}

	return Rule{Pattern: domain, IsAllow: isAllow}, nil
}

// isHostsIP returns true if s looks like a common hosts-file IP address.
func isHostsIP(s string) bool {
	return s == "0.0.0.0" || s == "127.0.0.1" || s == "::1" || s == "::" || s == "::0" || s == "fe80::1%lo0"
}

// parseAdGuardPattern converts an AdGuard/EasyList pattern string into a
// canonical domain pattern. Returns an error for unsupported constructs.
func parseAdGuardPattern(s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("empty pattern")
	}

	// Strip leading || (domain anchor)
	hasAnchor := false
	if strings.HasPrefix(s, "||") {
		hasAnchor = true
		s = s[2:]
	}

	// Strip leading | (start anchor) — less common but valid
	if strings.HasPrefix(s, "|") {
		s = s[1:]
	}

	// Strip trailing ^ (separator) and | (end anchor)
	s = strings.TrimRight(s, "^|")

	// Strip leading/trailing wildcards that are purely cosmetic trailing wildcards
	s = strings.TrimRight(s, "*")
	// Strip leading * only if preceded by nothing (bare leading wildcard is kept)
	// We keep leading * because it means "match any subdomain prefix"

	if s == "" {
		return "", fmt.Errorf("empty pattern after stripping anchors")
	}

	s = strings.ToLower(s)

	// Check for path components — we only handle domain filters
	if strings.ContainsAny(s, "/:?=&") {
		return "", fmt.Errorf("path-based rule not supported: %s", truncate(s, 80))
	}

	// Validate remaining characters: allow DNS chars + wildcard
	for _, r := range s {
		if !util.IsDNSChar(r) && r != '*' {
			return "", fmt.Errorf("invalid character %q in pattern: %s", r, truncate(s, 80))
		}
	}

	if !hasAnchor && !strings.Contains(s, "*") && !strings.Contains(s, ".") {
		// Single label without anchor — not useful as a domain filter
		return "", fmt.Errorf("single label without anchor not supported: %s", s)
	}

	return s, nil
}

// containsUnsupportedModifier checks a modifier string for constructs we can't handle.
func containsUnsupportedModifier(mods string) bool {
	parts := strings.Split(strings.ToLower(mods), ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// We support "important" and "document" as no-ops for domain filters.
		// Everything else is unsupported.
		switch {
		case p == "important", p == "document", p == "all",
			p == "first-party", p == "1p",
			p == "third-party", p == "3p":
			continue
		default:
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
