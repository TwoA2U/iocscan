package utils

import (
	"testing"

	"github.com/TwoA2U/iocscan/integrations"
)

func TestCacheTableValidationAllowsRegisteredTablesAndRejectsUnsafeNames(t *testing.T) {
	for _, table := range integrations.CacheTables() {
		if !isAllowedCacheTable(table) {
			t.Fatalf("expected registered cache table %q to be allowed", table)
		}
	}

	cases := []string{
		"",
		"vt_ip",
		"VT_IP;DROP TABLE users",
		"VT-IP",
		"UNKNOWN_TABLE",
	}
	for _, table := range cases {
		if isAllowedCacheTable(table) {
			t.Fatalf("expected table %q to be rejected", table)
		}
	}
}
