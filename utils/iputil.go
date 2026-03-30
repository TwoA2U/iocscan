// utils/iputil.go — IP-specific validation and shared utility types.
package utils

import (
	"fmt"
	"net"
	"strings"
)

const maxIPs = 100

type VendorDiagnostic struct {
	Cache  string `json:"cache"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// CheckIP parses and validates one or more IP addresses from a raw string.
// IPs may be separated by newlines, commas, spaces, or tabs.
func CheckIP(raw string) ([]string, error) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\r' || r == '\n' || r == ',' || r == ' ' || r == '\t'
	})
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if net.ParseIP(p) == nil {
			return nil, fmt.Errorf("%q is not a valid IP address", p)
		}
		ips = append(ips, p)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no valid IP addresses provided")
	}
	if len(ips) > maxIPs {
		return nil, fmt.Errorf("too many IPs: %d provided, maximum is %d", len(ips), maxIPs)
	}
	return ips, nil
}
