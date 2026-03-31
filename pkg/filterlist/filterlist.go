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
//   - Non-network rules (##, #@#, #?#, #$#, $$, #%, ...)
//   - Advanced modifiers that change rule semantics ($script, $domain=, etc.)
//   - Path-only rules without hostnames
package filterlist

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/idna"
)

// Rule represents one canonicalized filter entry ready for compilation.
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

// Logger is the minimal warning sink required by the parser.
//
// Implementations receive best-effort warnings for unsupported lines or other
// non-fatal parse issues. The interface keeps the package decoupled from any
// concrete logging implementation used by callers.
type Logger interface {
	Warnf(format string, args ...interface{})
}

// nopLogger discards warnings when callers pass nil for the Logger parameter.
type nopLogger struct{}

// Warnf discards parser warnings when callers do not provide a logger.
func (nopLogger) Warnf(string, ...interface{}) {}

// ParseFile loads one filter list from path and returns the parsed Rule slice.
//
// The path parameter may point to AdGuard, EasyList, or hosts-style files.
// The logger parameter receives warnings for unsupported or malformed lines and
// may be nil when the caller wants silent best-effort parsing. ParseFile
// returns the successfully parsed rules together with any terminal read error;
// individual line failures are logged and skipped so callers can continue with
// partially valid upstream lists.
func ParseFile(path string, logger Logger) (rules []Rule, err error) {
	if logger == nil {
		logger = nopLogger{}
	}

	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("filterlist: open %s: %w", cleanPath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("filterlist: close %s: %w", cleanPath, closeErr)
		}
	}()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		rule, parseErr := ParseLine(line)
		if parseErr != nil {
			if !errors.Is(parseErr, errSkip) {
				logger.Warnf("%s:%d: %v", cleanPath, lineNum, parseErr)
			}
			continue
		}
		rule.Source = fmt.Sprintf("%s:%d", cleanPath, lineNum)
		rules = append(rules, rule)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return rules, fmt.Errorf("filterlist: read %s: %w", cleanPath, scanErr)
	}
	return rules, nil
}

// errSkip is a sentinel for blank/comment lines that should be silently skipped.
var errSkip = errors.New("skip")

// ParseLine parses one raw filter line into a canonical Rule.
//
// The line parameter may contain AdGuard, EasyList, or hosts-style syntax. The
// returned Rule contains the normalized domain pattern and allow/deny flag when
// parsing succeeds. ParseLine returns errSkip for comments and blank lines and
// returns a descriptive error for unsupported modifiers, path-based rules, or
// invalid pattern characters. Callers normally use ParseLine inside ParseFile
// or fuzz and unit tests that exercise individual rule forms.
func ParseLine(line string) (Rule, error) {
	line = strings.TrimSpace(line)

	// Skip empty lines
	if line == "" {
		return Rule{}, errSkip
	}

	// Skip comments: '!' prefix, '[Adblock' header, and '#' prefix (hosts-style comments).
	// The '#' check must come before the non-network marker check because
	// hosts-style comments like '# tracking ## info' contain '##' but are not rules.
	if line[0] == '!' || line[0] == '#' || strings.HasPrefix(line, "[Adblock") {
		return Rule{}, errSkip
	}

	if containsUnsupportedNonNetworkMarker(line) {
		return Rule{}, fmt.Errorf("unsupported non-network rule: %s", truncate(line))
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
	} else if errors.Is(err, errSkip) {
		return Rule{}, errSkip
	}
	// err == errNotHosts means it's not a hosts line, fall through

	// Strip AdGuard/EasyList modifiers ($...) — we ignore rules with
	// non-domain modifiers but still try to extract the domain part.
	if idx := strings.LastIndex(work, "$"); idx >= 0 {
		modifiers := work[idx+1:]
		// Check for modifiers we explicitly don't support as they change semantics
		if containsUnsupportedModifier(modifiers) {
			return Rule{}, fmt.Errorf("unsupported modifier in rule: %s", truncate(line))
		}
		work = work[:idx]
	}

	// Parse AdGuard/EasyList domain pattern
	pattern, err := parseAdGuardPattern(work)
	if err != nil {
		return Rule{}, err
	}

	if pattern == "" {
		return Rule{}, fmt.Errorf("empty pattern after parsing: %s", truncate(line))
	}

	return Rule{Pattern: pattern, IsAllow: isAllow}, nil
}

// errNotHosts signals that a line is not in hosts-file format.
var errNotHosts = errors.New("not hosts")

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

	// Convert internationalized domain names (IDN) to Punycode.
	if needsIDNConversion(domain) {
		ascii, err := toASCII(domain)
		if err != nil {
			return Rule{}, errNotHosts
		}
		domain = ascii
	}

	// Skip localhost entries
	if domain == "localhost" || domain == "localhost.localdomain" ||
		domain == "local" || domain == "broadcasthost" ||
		domain == "ip6-localhost" || domain == "ip6-loopback" ||
		domain == "ip6-localnet" || domain == "ip6-mcastprefix" ||
		domain == "ip6-allnodes" || domain == "ip6-allrouters" {
		return Rule{}, errSkip
	}

	if !isValidDNSName(domain) {
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
		return "", errors.New("empty pattern")
	}

	// Strip leading || (domain anchor)
	hasAnchor := false
	if strings.HasPrefix(s, "||") {
		hasAnchor = true
		s = s[2:]
	}

	// Strip leading | (start anchor) — less common but valid
	s = strings.TrimPrefix(s, "|")

	// Strip trailing ^ (separator) and | (end anchor)
	s = strings.TrimRight(s, "^|")

	// Strip leading/trailing wildcards that are purely cosmetic trailing wildcards
	s = strings.TrimRight(s, "*")
	// Strip leading * only if preceded by nothing (bare leading wildcard is kept)
	// We keep leading * because it means "match any subdomain prefix"

	if s == "" {
		return "", errors.New("empty pattern after stripping anchors")
	}

	s = strings.ToLower(s)

	// Convert internationalized domain names (IDN) to Punycode (ASCII).
	// This allows filter lists to use Unicode domains like "münchen.de"
	// which will be converted to "xn--mnchen-3ya.de" to match DNS queries.
	if needsIDNConversion(s) {
		ascii, err := toASCII(s)
		if err != nil {
			return "", fmt.Errorf("IDN conversion failed for %s: %w", truncate(s), err)
		}
		s = ascii
	}

	// Check for path components — we only handle domain filters
	if strings.ContainsAny(s, "/:?=&") {
		return "", fmt.Errorf("path-based rule not supported: %s", truncate(s))
	}

	// Validate remaining characters: allow DNS chars + wildcard
	for _, r := range s {
		if !isDNSChar(r) && r != '*' {
			return "", fmt.Errorf("invalid character %q in pattern: %s", r, truncate(s))
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
		switch p {
		case "important", "document", "all", "first-party", "1p", "third-party", "3p",
			"badfilter", "match-case", "popup":
			continue
		default:
			return true
		}
	}
	return false
}

// containsUnsupportedNonNetworkMarker detects cosmetic and scriptlet rule syntax.
func containsUnsupportedNonNetworkMarker(line string) bool {
	markers := []string{
		"##",
		"#@#",
		"#?#",
		"#@?#",
		"#$#",
		"#@$#",
		"#$?#",
		"#@$?#",
		"#%#",
		"#@%#",
		"$$",
		"$@$",
	}

	for _, marker := range markers {
		if strings.Contains(line, marker) {
			return true
		}
	}

	return false
}

const truncateLimit = 80

// truncate shortens long strings for safe inclusion in log and error messages.
func truncate(s string) string {
	if len(s) <= truncateLimit {
		return s
	}
	return s[:truncateLimit] + "..."
}

// needsIDNConversion returns true if s contains non-ASCII characters that
// may represent an internationalized domain name requiring Punycode conversion.
func needsIDNConversion(s string) bool {
	for _, r := range s {
		if r > 0x7F {
			return true
		}
	}
	return false
}

// isDNSChar reports whether r belongs to the supported DNS matching alphabet.
func isDNSChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '.'
}

// isValidDNSName reports whether name uses only supported DNS pattern characters.
func isValidDNSName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range strings.ToLower(name) {
		if !isDNSChar(r) && r != '*' {
			return false
		}
	}
	return true
}

// toASCII converts name into its ASCII DNS representation via IDNA lookup.
func toASCII(name string) (string, error) {
	return idna.Lookup.ToASCII(name)
}
