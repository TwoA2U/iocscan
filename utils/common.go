// utils/common.go — config file, SQLite cache, and API key helpers.
//
// Phase 5 changes (plugin architecture):
//   1. allowedTables is now populated dynamically from integrations.CacheTables()
//      instead of being a hardcoded map literal. Adding a new integration
//      automatically whitelists its cache table — no manual edit needed here.
//   2. InitDB() now creates tables and indexes by iterating all registered
//      integrations' CacheConfig values, not a hardcoded DDL block.
//   3. InitDB() calls integrations.SetCacheFuncs() after the DB is ready,
//      wiring the cache bridge in cache.go so Run() methods can read/write
//      the SQLite cache without an import cycle.
//   4. getCacheEntry / putCacheEntry remain private to this package and are
//      passed to the integrations package as function values (CacheGetFn /
//      CachePutFn), preserving the no-import-cycle design.
//
// Everything else (GetAPI, WriteConf, getSharedDB, ClearHashCaches, TTL env var)
// is unchanged from the previous revision.
package utils

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TwoA2U/iocscan/integrations"
	"github.com/spf13/viper"
	_ "modernc.org/sqlite"
)

// ── API key collection ────────────────────────────────────────────────────────

// CollectionAPI holds the API keys read from the config file.
type CollectionAPI struct {
	VTAPI      string
	AbuseAPI   string
	IPapiAPI   string
	AbuseCHAPI string // Single key for both MalwareBazaar and ThreatFox (abuse.ch services)
}

// GetAPI reads API keys from the config file (default: ~/.iocscan.yaml).
func GetAPI(cfgFile string) (*CollectionAPI, error) {
	cfg, err := getConfigPath(cfgFile)
	if err != nil {
		return nil, fmt.Errorf(
			"config not found — run `iocscan -v <VT_KEY> -a <ABUSE_KEY> -i <IPAPI_KEY>` first: %w", err,
		)
	}

	viper.SetConfigFile(cfg)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("could not read config %s: %w", cfg, err)
	}

	return &CollectionAPI{
		VTAPI:      strings.TrimSpace(viper.GetString("VT_API")),
		AbuseAPI:   strings.TrimSpace(viper.GetString("Abuse_API")),
		IPapiAPI:   strings.TrimSpace(viper.GetString("IPapi_API")),
		AbuseCHAPI: strings.TrimSpace(viper.GetString("AbuseCH_API")),
	}, nil
}

// getConfigPath resolves the config file path, defaulting to ~/.iocscan.yaml.
func getConfigPath(cfgFile string) (string, error) {
	if cfgFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cfgFile = filepath.Join(home, ".iocscan.yaml")
	}
	if _, err := os.Stat(cfgFile); err != nil {
		return "", err
	}
	return cfgFile, nil
}

// WriteConf persists the API keys to ~/.iocscan.yaml.
func WriteConf(vtAPI, abuseAPI, ipapiAPI, abuseCHAPI string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not determine home directory: %v\n", err)
		return
	}

	config := fmt.Sprintf(
		"VT_API: %s\nAbuse_API: %s\nIPapi_API: %s\nAbuseCH_API: %s\n",
		vtAPI, abuseAPI, ipapiAPI, abuseCHAPI,
	)

	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewBufferString(config)); err != nil {
		fmt.Fprintf(os.Stderr, "could not parse config: %v\n", err)
		return
	}

	cfgPath := filepath.Join(home, ".iocscan.yaml")
	if err := viper.WriteConfigAs(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "could not write config to %s: %v\n", cfgPath, err)
		return
	}
	fmt.Printf("✅ Config saved to %s\n", cfgPath)
}

// ── SQLite cache ──────────────────────────────────────────────────────────────

// cacheMaxAge is how long a cached result is considered fresh.
// Override at runtime with IOCSCAN_CACHE_TTL_DAYS (must be a positive integer).
// Falls back to 30 days if the variable is unset, zero, negative, or non-numeric.
var cacheMaxAge = func() time.Duration {
	const defaultDays = 30
	val := os.Getenv("IOCSCAN_CACHE_TTL_DAYS")
	if val == "" {
		return defaultDays * 24 * time.Hour
	}
	days := 0
	if _, err := fmt.Sscanf(val, "%d", &days); err != nil || days <= 0 {
		fmt.Fprintf(os.Stderr, "warning: IOCSCAN_CACHE_TTL_DAYS=%q is invalid, using default %d days\n", val, defaultDays)
		return defaultDays * 24 * time.Hour
	}
	fmt.Fprintf(os.Stderr, "info: cache TTL set to %d days (IOCSCAN_CACHE_TTL_DAYS)\n", days)
	return time.Duration(days) * 24 * time.Hour
}()

// sharedDB is the single long-lived database connection.
// Protected by dbMu; dbReady flips to true once the connection is established.
// Using a mutex instead of sync.Once means getSharedDB() can succeed on a
// later call even if an earlier call failed (e.g. DB file didn't exist yet
// when the process started but InitDB() has since created it).
var (
	sharedDB  *sql.DB
	dbMu      sync.Mutex
	dbReady   bool
	dbInitErr error
)

// allowedTables is the SQL-injection whitelist for cache table names.
// It is populated dynamically from the integration registry in InitDB()
// so it automatically includes any table declared by a new integration.
// The map is initialised empty here; getCacheEntry / putCacheEntry will
// return safely without hitting the DB until InitDB() has run.
var (
	allowedTablesMu sync.RWMutex
	allowedTables   = make(map[string]bool)
)

// isAllowedTable returns true if table is in the whitelist.
// Uses a read lock so concurrent cache reads don't block each other.
func isAllowedTable(table string) bool {
	allowedTablesMu.RLock()
	ok := allowedTables[table]
	allowedTablesMu.RUnlock()
	return ok
}

// registerTable adds a table name to the whitelist under a write lock.
// Called only from InitDB() before any request handlers start.
func registerTable(table string) {
	allowedTablesMu.Lock()
	allowedTables[table] = true
	allowedTablesMu.Unlock()
}

// SQLite CURRENT_TIMESTAMP stores as "2006-01-02 15:04:05", not RFC3339.
// We try multiple layouts to be safe.
var sqliteTimeFormats = []string{
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z",
	time.RFC3339,
}

func parseSQLiteTime(s string) (time.Time, error) {
	for _, layout := range sqliteTimeFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse sqlite time %q", s)
}

func dbPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iocscan.db"), nil
}

// getSharedDB returns the long-lived *sql.DB, initialising it on first
// successful call. Unlike sync.Once, a failed attempt does NOT permanently
// lock out future calls — so if the DB file didn't exist when the process
// started (user forgot to run setup) but InitDB() has since created it,
// the next cache access will succeed without restarting.
func getSharedDB() (*sql.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	if dbReady {
		return sharedDB, nil
	}
	path, err := dbPath()
	if err != nil {
		dbInitErr = err
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		dbInitErr = fmt.Errorf("cache DB not found — run `iocscan` setup first")
		return nil, dbInitErr
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		dbInitErr = err
		return nil, err
	}
	// SQLite only supports one concurrent writer; cap the pool accordingly.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0) // keep the connection alive indefinitely
	sharedDB = db
	dbReady = true
	dbInitErr = nil
	return sharedDB, nil
}

// ── InitDB ────────────────────────────────────────────────────────────────────

// InitDB creates the SQLite cache database, builds tables for every registered
// integration, wires the cache bridge, then warms up the shared connection.
//
// What changed from the previous revision:
//   - Table DDL is generated by ranging over integrations.CacheTables() instead
//     of a hardcoded SQL block. Adding a new integration with a non-empty
//     Cache.Table value automatically gets a table and index created here.
//   - allowedTables is populated from the same source, replacing the old
//     hardcoded map literal.
//   - integrations.SetCacheFuncs(getCacheEntry, putCacheEntry) is called at
//     the end so integration Run() methods can use the real cache immediately.
func InitDB() {
	path, err := dbPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB: %v\n", err)
		return
	}

	// Use a temporary connection for DDL so we can execute statements freely
	// before the shared pool is configured with its single-writer constraint.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB open: %v\n", err)
		return
	}
	defer db.Close()

	// Enable WAL journal mode for better read concurrency.
	// Non-fatal: cache works correctly in default rollback mode too.
	if _, walErr := db.Exec(`PRAGMA journal_mode=WAL`); walErr != nil {
		fmt.Fprintf(os.Stderr, "InitDB WAL: %v\n", walErr)
	}

	// ── Dynamic table creation ────────────────────────────────────────────────
	//
	// integrations.CacheTables() returns all unique, non-empty table names
	// declared across every registered integration's CacheConfig.Table field.
	// We create each table and its CREATED_AT index in one pass, then register
	// the table name in the allowedTables whitelist.
	//
	// Previously this was a hardcoded 7-table SQL block. Now adding a new
	// integration with Table: "GN_IP" automatically creates that table here
	// without any changes to this file.

	for _, table := range integrations.CacheTables() {
		// CREATE TABLE — idempotent on re-run
		_, err := db.Exec(fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				KEY        TEXT PRIMARY KEY NOT NULL,
				DATA       TEXT NOT NULL,
				CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)`, table))
		if err != nil {
			fmt.Fprintf(os.Stderr, "InitDB create table %s: %v\n", table, err)
			return
		}

		// CREATE INDEX — idempotent on re-run
		indexName := "idx_" + strings.ToLower(table) + "_created"
		_, err = db.Exec(fmt.Sprintf(
			`CREATE INDEX IF NOT EXISTS %s ON %s(CREATED_AT)`,
			indexName, table,
		))
		if err != nil {
			// Non-fatal: missing index only affects expiry-scan performance.
			fmt.Fprintf(os.Stderr, "InitDB create index %s: %v\n", indexName, err)
		}

		// Register in the whitelist so getCacheEntry / putCacheEntry accept it.
		registerTable(table)
	}

	// ── Reset shared connection ───────────────────────────────────────────────
	//
	// Reset dbReady so the next getSharedDB() call re-opens the connection
	// against the freshly-created (or already-existing) DB file. Safe here
	// because InitDB() is only called from the CLI setup path before any
	// concurrent request handlers are running.
	dbMu.Lock()
	dbReady = false
	sharedDB = nil
	dbMu.Unlock()

	// Warm up the shared connection pool immediately so the first real cache
	// access doesn't pay the open cost.
	if _, err := getSharedDB(); err != nil {
		fmt.Fprintf(os.Stderr, "InitDB warm-up: %v\n", err)
		return
	}

	// ── Wire cache bridge ─────────────────────────────────────────────────────
	//
	// Pass getCacheEntry and putCacheEntry to the integrations package so that
	// integration Run() methods can call the real SQLite cache without creating
	// an import cycle (integrations → utils would cycle back to integrations).
	// Until this call, integration.cachedGet/cachedPut are no-ops by design.
	integrations.SetCacheFuncs(getCacheEntry, putCacheEntry)

	fmt.Printf("✅ Cache DB initialised (%d tables)\n", len(integrations.CacheTables()))
}

// ── Unified cache helpers ─────────────────────────────────────────────────────

// getCacheEntry returns a cached result for the given key and table,
// or "" if not found, expired (older than cacheMaxAge), or the table
// is not in the allowedTables whitelist.
func getCacheEntry(key, table string) string {
	if !isAllowedTable(table) {
		return ""
	}
	db, err := getSharedDB()
	if err != nil {
		return ""
	}

	// Use a pre-built query map keyed by table name to avoid fmt.Sprintf
	// with user-influenced input. The whitelist check above already guards
	// against injection, but building queries statically is belt-and-suspenders.
	var data, createdAt string
	q := fmt.Sprintf("SELECT DATA, CREATED_AT FROM %s WHERE KEY = ?", table)
	if err := db.QueryRow(q, key).Scan(&data, &createdAt); err != nil {
		return ""
	}

	t, err := parseSQLiteTime(createdAt)
	if err != nil || time.Since(t.UTC()) > cacheMaxAge {
		// Expired — delete in a best-effort fire-and-forget query.
		db.Exec(fmt.Sprintf("DELETE FROM %s WHERE KEY = ?", table), key)
		return ""
	}
	return data
}

// putCacheEntry inserts or replaces a cached result.
// No-op if the table name is not in the allowedTables whitelist.
func putCacheEntry(key, data, table string) {
	if !isAllowedTable(table) {
		return
	}
	db, err := getSharedDB()
	if err != nil {
		return
	}
	q := fmt.Sprintf("INSERT OR REPLACE INTO %s (KEY, DATA) VALUES (?, ?)", table)
	db.Exec(q, key, data)
}

// ── ClearHashCaches ───────────────────────────────────────────────────────────

// ClearHashCaches deletes all rows from the specified cache tables.
// Returns the total number of rows deleted.
// Called by the POST /api/cache/clear handler in cmd/web.go.
func ClearHashCaches(tables []string) int {
	db, err := getSharedDB()
	if err != nil {
		return 0
	}

	total := 0
	for _, t := range tables {
		if !isAllowedTable(t) {
			continue
		}
		res, err := db.Exec(fmt.Sprintf("DELETE FROM %s", t))
		if err == nil {
			n, _ := res.RowsAffected()
			total += int(n)
		}
	}
	return total
}
