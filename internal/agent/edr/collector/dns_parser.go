// Package collector — DNS wire format parser for userspace DNS event enrichment.
// When the eBPF layer captures UDP port 53 payload (future enhancement),
// this parser extracts the domain name, query type, and response code.
package collector

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DNSHeader represents the DNS message header (RFC 1035 Section 4.1.1).
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16 // Number of questions
	ANCount uint16 // Number of answers
	NSCount uint16 // Number of authority records
	ARCount uint16 // Number of additional records
}

// DNSResult holds parsed DNS query/response information.
type DNSResult struct {
	Domain   string // e.g. "example.com"
	QType    string // "A", "AAAA", "CNAME", "MX", "TXT", etc.
	RCode    int    // 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, etc.
	RCodeStr string // human-readable rcode
	IsQuery  bool   // true = query, false = response
}

// ParseDNS parses a raw DNS message (UDP payload).
// Returns nil if the payload is too short or malformed.
func ParseDNS(payload []byte) *DNSResult {
	if len(payload) < 12 {
		return nil
	}

	header := DNSHeader{
		ID:      binary.BigEndian.Uint16(payload[0:2]),
		Flags:   binary.BigEndian.Uint16(payload[2:4]),
		QDCount: binary.BigEndian.Uint16(payload[4:6]),
		ANCount: binary.BigEndian.Uint16(payload[6:8]),
		NSCount: binary.BigEndian.Uint16(payload[8:10]),
		ARCount: binary.BigEndian.Uint16(payload[10:12]),
	}

	isQuery := (header.Flags & 0x8000) == 0
	rcode := int(header.Flags & 0x000F)

	if header.QDCount == 0 {
		return nil
	}

	// Parse first question section.
	domain, qtype, offset := parseQuestion(payload, 12)
	if domain == "" || offset < 0 {
		return nil
	}

	return &DNSResult{
		Domain:   domain,
		QType:    qtypeToString(qtype),
		RCode:    rcode,
		RCodeStr: rcodeToString(rcode),
		IsQuery:  isQuery,
	}
}

// parseQuestion parses a DNS question section starting at offset.
// Returns the domain name, query type, and the offset after the question.
func parseQuestion(payload []byte, offset int) (string, uint16, int) {
	domain, newOffset := parseDomainName(payload, offset)
	if newOffset < 0 || newOffset+4 > len(payload) {
		return "", 0, -1
	}

	qtype := binary.BigEndian.Uint16(payload[newOffset : newOffset+2])
	// qclass at newOffset+2:newOffset+4 (usually IN=1, skip)

	return domain, qtype, newOffset + 4
}

// parseDomainName parses a DNS domain name with label compression support.
func parseDomainName(payload []byte, offset int) (string, int) {
	var parts []string
	visited := make(map[int]bool) // prevent infinite loops
	originalOffset := -1

	for {
		if offset >= len(payload) {
			return "", -1
		}

		labelLen := int(payload[offset])

		// End of name.
		if labelLen == 0 {
			offset++
			break
		}

		// Compression pointer (top 2 bits set).
		if labelLen&0xC0 == 0xC0 {
			if offset+1 >= len(payload) {
				return "", -1
			}
			ptr := int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 0x3FFF)
			if visited[ptr] {
				return "", -1 // loop detected
			}
			visited[ptr] = true

			if originalOffset < 0 {
				originalOffset = offset + 2
			}
			offset = ptr
			continue
		}

		// Regular label.
		if offset+1+labelLen > len(payload) {
			return "", -1
		}

		parts = append(parts, string(payload[offset+1:offset+1+labelLen]))
		offset += 1 + labelLen

		if len(parts) > 128 { // sanity limit
			return "", -1
		}
	}

	if originalOffset >= 0 {
		return strings.Join(parts, "."), originalOffset
	}
	return strings.Join(parts, "."), offset
}

func qtypeToString(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

func rcodeToString(rcode int) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}
