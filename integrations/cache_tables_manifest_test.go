package integrations

import "testing"

func TestManifestDeclaredCacheTablesAreUniqueAndNonEmpty(t *testing.T) {
	tables := CacheTables()
	if len(tables) == 0 {
		t.Fatal("expected at least one cache table")
	}

	seen := map[string]bool{}
	for _, table := range tables {
		if table == "" {
			t.Fatal("CacheTables returned an empty table name")
		}
		if seen[table] {
			t.Fatalf("CacheTables returned duplicate table %q", table)
		}
		seen[table] = true
	}
}
