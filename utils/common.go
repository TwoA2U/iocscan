// utils/common.go — config file, SQLite cache, and API key helpers.
//
// Improvements in this revision:
//   1. Single shared *sql.DB opened once at InitDB() time — no more open/close per query.
//   2. hashCacheTables merged into allowedTables — single unified whitelist, no init() coupling.
//   3. getCacheEntry / putCacheEntry replace the duplicate getCached/getHashCached pairs.
//   4. Cache TTL is configurable via IOCSCAN_CACHE_TTL_DAYS env var (default: 30 days).
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

// allowedTables is the unified whitelist of valid cache table names.
// Covers both IP tables (previously in allowedTables) and hash tables
// (previously in hashCacheTables, populated via a fragile init() in hashutil.go).
// Keeping them together eliminates the implicit cross-file init() dependency.
var allowedTables = map[string]bool{
	// IP-keyed tables
	"VT_IP":      true,
	"ABUSE_IP":   true,
	"IPAPIIS_IP": true,
	// Hash/mixed-key tables
	"VT_HASH": true,
	"MB_HASH": true,
	"TF_IP":   true,
	"TF_HASH": true,
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

// InitDB creates the SQLite cache database and all tables, then warms up the
// shared connection so the first real query doesn't pay the open cost.
func InitDB() {
	path, err := dbPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB: %v\n", err)
		return
	}

	// Use a temporary connection for schema setup so we can use DDL freely
	// before the shared pool is configured.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB open: %v\n", err)
		return
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS VT_IP (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS ABUSE_IP (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS IPAPIIS_IP (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS VT_HASH (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS MB_HASH (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS TF_IP (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS TF_HASH (
			KEY        TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_vt_ip_created      ON VT_IP(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_abuse_ip_created   ON ABUSE_IP(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_ipapiis_created    ON IPAPIIS_IP(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_vt_hash_created    ON VT_HASH(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_mb_hash_created    ON MB_HASH(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_tf_ip_created      ON TF_IP(CREATED_AT);
		CREATE INDEX IF NOT EXISTS idx_tf_hash_created    ON TF_HASH(CREATED_AT);
	`)
	db.Close() // close the setup connection before the shared pool takes over

	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB create tables: %v\n", err)
		return
	}

	// Reset dbReady so the next getSharedDB() call re-opens the connection
	// against the newly created (or already-existing) DB file. This is safe
	// here because InitDB() is only called from the CLI setup path, not from
	// concurrent request handlers.
	dbMu.Lock()
	dbReady = false
	sharedDB = nil
	dbMu.Unlock()

	// Warm up the shared connection pool immediately.
	if _, err := getSharedDB(); err != nil {
		fmt.Fprintf(os.Stderr, "InitDB warm-up: %v\n", err)
		return
	}

	fmt.Println("✅ Cache DB initialised")
}

// ── Unified cache helpers ─────────────────────────────────────────────────────
//
// getCacheEntry and putCacheEntry replace the previous four helpers:
//   getCached / putCached       (IP tables)
//   getHashCached / putHashCached (hash tables)
//
// Both IP and hash lookups use the same underlying schema (KEY column),
// so a single pair of helpers is sufficient.

// getCacheEntry returns a cached result for the given key and table,
// or "" if not found, expired (older than cacheMaxAge), or the table is not whitelisted.
func getCacheEntry(key, table string) string {
	if !allowedTables[table] {
		return ""
	}
	db, err := getSharedDB()
	if err != nil {
		return ""
	}

	var data, createdAt string
	q := fmt.Sprintf("SELECT DATA, CREATED_AT FROM %s WHERE KEY = ?", table)
	if err := db.QueryRow(q, key).Scan(&data, &createdAt); err != nil {
		return ""
	}

	t, err := parseSQLiteTime(createdAt)
	if err != nil || time.Since(t.UTC()) > cacheMaxAge {
		db.Exec(fmt.Sprintf("DELETE FROM %s WHERE KEY = ?", table), key)
		return ""
	}
	return data
}

// putCacheEntry inserts or replaces a cached result.
// No-op if the table name is not in the allowedTables whitelist.
func putCacheEntry(key, data, table string) {
	if !allowedTables[table] {
		return
	}
	db, err := getSharedDB()
	if err != nil {
		return
	}
	q := fmt.Sprintf("INSERT OR REPLACE INTO %s (KEY, DATA) VALUES (?, ?)", table)
	db.Exec(q, key, data)
}

// ── ClearCaches ───────────────────────────────────────────────────────────────

// ClearHashCaches deletes all rows from the specified cache tables.
// Returns the total number of rows deleted.
func ClearHashCaches(tables []string) int {
	db, err := getSharedDB()
	if err != nil {
		return 0
	}

	total := 0
	for _, t := range tables {
		if !allowedTables[t] {
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
