// utils/iocutil.go — IOC type detection helper.
//
// Kept as a separate file for future expansion (domain/URL scanning).
// Domain detection is intentionally omitted — it will be added alongside
// actual domain enrichment support. The actual API fetching lives in iputil.go.
package utils

import (
	"net"
	"regexp"
	"strings"
)

// IOCType classifies what kind of indicator we are dealing with.
type IOCType string

const (
	TypeIP      IOCType = "ip"
	TypeDomain  IOCType = "domain" // reserved — detection not yet implemented
	TypeHash    IOCType = "hash"
	TypeUnknown IOCType = "unknown"
)

var (
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
)

// DetectIOCType classifies the given string as IP, hash, or unknown.
// Domain detection is not yet implemented — domain strings return TypeUnknown
// until domain enrichment is added.
func DetectIOCType(ioc string) IOCType {
	ioc = strings.TrimSpace(ioc)
	if net.ParseIP(ioc) != nil {
		return TypeIP
	}
	if reMD5.MatchString(ioc) || reSHA1.MatchString(ioc) || reSHA256.MatchString(ioc) {
		return TypeHash
	}
	return TypeUnknown
}
