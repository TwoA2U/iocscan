// utils/iocutil.go — IOC type detection helper.
//
// Kept as a separate file for future expansion (domain/hash scanning).
// The actual API fetching lives in iputil.go.
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
	TypeDomain  IOCType = "domain"
	TypeHash    IOCType = "hash"
	TypeUnknown IOCType = "unknown"
)

var (
	reMD5    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	reSHA1   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	reSHA256 = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	reDomain = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// DetectIOCType classifies the given string as IP, domain, hash, or unknown.
func DetectIOCType(ioc string) IOCType {
	ioc = strings.TrimSpace(ioc)
	if net.ParseIP(ioc) != nil {
		return TypeIP
	}
	if reMD5.MatchString(ioc) || reSHA1.MatchString(ioc) || reSHA256.MatchString(ioc) {
		return TypeHash
	}
	if reDomain.MatchString(ioc) {
		return TypeDomain
	}
	return TypeUnknown
}
