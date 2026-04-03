package filterlist

import "golang.org/x/net/idna"

const (
	// maxStrictDNSNameLength is the maximum DNS name length in octets without
	// the trailing root dot, as defined by RFC 1035 section 2.3.4.
	maxStrictDNSNameLength = 253

	// maxStrictDNSLabelLength is the maximum DNS label length in octets, as
	// defined by RFC 1035 section 2.3.4.
	maxStrictDNSLabelLength = 63
)

// isStrictDNSQueryName reports whether qname is a well-formed DNS query name
// under RFC 1035 label rules and the IDNA Lookup profile.
//
// The qname parameter may include a trailing root dot and may contain ASCII
// upper-case letters. The function validates label boundaries and the 253/63
// length limits with a single scan over the input using nested loops and two
// counters (total name length and current label length). It does not allocate
// on the common pure-ASCII path.
//
// While scanning, the function also detects whether any label begins with the
// ACE prefix "xn--". Only then does it perform an IDNA Lookup.ToUnicode conversion
// to validate the punycode encoding. Names without an ACE-prefixed label
// return directly after the ASCII scan succeeds.
//
// Returns true only when qname is valid. Empty labels, labels that start or end
// with a hyphen, labels longer than 63 octets, names longer than 253 octets,
// non-LDH ASCII bytes, and invalid ACE labels all return false.
func isStrictDNSQueryName(qname string) bool {
	if qname == "." {
		return true
	}

	end := len(qname)
	if end == 0 {
		return false
	}
	if qname[end-1] == '.' {
		end--
	}
	if end == 0 || end > maxStrictDNSNameLength {
		return false
	}

	needsIDNACheck, ok := validateStrictDNSASCIIName(qname, end)
	if !ok {
		return false
	}
	if !needsIDNACheck {
		return true
	}

	_, err := idna.Lookup.ToUnicode(qname[:end])
	return err == nil
}

// validateStrictDNSASCIIName validates RFC 1035 LDH syntax and length limits
// for the first end bytes of name.
//
// The function accepts ASCII letters in either case, digits, hyphens, and dot
// separators. It returns whether an IDNA ACE label was seen and whether the
// scanned name is structurally valid. The implementation uses an outer loop for
// labels and an inner loop for bytes within each label so total and per-label
// lengths are tracked without slicing or allocations.
func validateStrictDNSASCIIName(name string, end int) (bool, bool) {
	totalLen := 0
	needsIDNACheck := false

	for labelStart := 0; labelStart < end; {
		labelLen := 0
		acePrefixLen := 0

		for index := labelStart; index < end && name[index] != '.'; index++ {
			current := asciiLower(name[index])
			if !isStrictDNSLabelByte(current) {
				return false, false
			}
			if labelLen == 0 && current == '-' {
				return false, false
			}

			labelLen++
			totalLen++
			if labelLen > maxStrictDNSLabelLength || totalLen > maxStrictDNSNameLength {
				return false, false
			}

			if acePrefixLen < 4 {
				switch acePrefixLen {
				case 0:
					if current == 'x' {
						acePrefixLen = 1
					} else {
						acePrefixLen = 4
					}
				case 1:
					if current == 'n' {
						acePrefixLen = 2
					} else {
						acePrefixLen = 4
					}
				case 2, 3:
					if current == '-' {
						acePrefixLen++
						if acePrefixLen == 4 {
							needsIDNACheck = true
						}
					} else {
						acePrefixLen = 4
					}
				}
			}
		}

		if labelLen == 0 {
			return false, false
		}

		labelEnd := labelStart + labelLen
		if asciiLower(name[labelEnd-1]) == '-' {
			return false, false
		}

		if labelEnd == end {
			break
		}

		totalLen++
		if totalLen > maxStrictDNSNameLength {
			return false, false
		}
		labelStart = labelEnd + 1
	}

	return needsIDNACheck, totalLen > 0
}

func asciiLower(value byte) byte {
	if value >= 'A' && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func isStrictDNSLabelByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '-'
}
