// utils/common.go — config file, SQLite cache, and API key helpers.
package utils

import (
	"database/sql"
	"fmt"
	"github.com/TwoA2U/iocscan/integrations"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── API key collection ────────────────────────────────────────────────────────

// CollectionAPI holds the API keys read from the config file.
type CollectionAPI struct {
	VTAPI        string `yaml:"VT_API"`
	AbuseAPI     string `yaml:"Abuse_API"`
	IPapiAPI     string `yaml:"IPapi_API"`
	AbuseCHAPI   string `yaml:"AbuseCH_API"`
	GreyNoiseAPI string `yaml:"GreyNoise_API"`
}

// GetAPI reads API keys from the config file (default: ~/.iocscan.yaml).
func GetAPI(cfgFile string) (*CollectionAPI, error) {
	path, err := getConfigPath(cfgFile)
	if err != nil {
		return nil, fmt.Errorf(
			"config not found — run `iocscan -v <VT_KEY> -a <ABUSE_KEY>` first: %w", err,
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config %s: %w", path, err)
	}

	var cfg CollectionAPI
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("could not parse config %s: %w", path, err)
	}

	cfg.VTAPI = strings.TrimSpace(cfg.VTAPI)
	cfg.AbuseAPI = strings.TrimSpace(cfg.AbuseAPI)
	cfg.IPapiAPI = strings.TrimSpace(cfg.IPapiAPI)
	cfg.AbuseCHAPI = strings.TrimSpace(cfg.AbuseCHAPI)
	cfg.GreyNoiseAPI = strings.TrimSpace(cfg.GreyNoiseAPI)
	return &cfg, nil
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
func WriteConf(vtAPI, abuseAPI, ipapiAPI, abuseCHAPI, greynoiseAPI string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not determine home directory: %v\n", err)
		return
	}

	cfg := CollectionAPI{
		VTAPI:        vtAPI,
		AbuseAPI:     abuseAPI,
		IPapiAPI:     ipapiAPI,
		AbuseCHAPI:   abuseCHAPI,
		GreyNoiseAPI: greynoiseAPI,
	}

	data, err := yaml.Marshal(&cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not serialize config: %v\n", err)
		return
	}

	cfgPath := filepath.Join(home, ".iocscan.yaml")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "could not write config to %s: %v\n", cfgPath, err)
		return
	}
	fmt.Printf("✅ Config saved to %s\n", cfgPath)
}

// ── SQLite cache ──────────────────────────────────────────────────────────────

var cacheMaxAge = func() time.Duration {
	const defaultDays = 30
	val := os.Getenv("IOCSCAN_CACHE_TTL_DAYS")
	if val == "" {
		return defaultDays * 24 * time.Hour
	}
	days := 0
	if _, err := fmt.Sscanf(val, "%d", &days); err != nil || days <= 0 {
		fmt.Fprintf(os.Stderr, "warning: IOCSCAN_CACHE_TTL_DAYS=%q invalid, using default %d days\n", val, defaultDays)
		return defaultDays * 24 * time.Hour
	}
	return time.Duration(days) * 24 * time.Hour
}()

var (
	sharedDB *sql.DB
	dbMu     sync.Mutex
	dbReady  bool
)

var cacheTableNameRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

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

func getSharedDB() (*sql.DB, error) {
	dbMu.Lock()
	defer dbMu.Unlock()
	if dbReady {
		return sharedDB, nil
	}
	path, err := dbPath()
	if err != nil {
		return nil, err
	}
	// Open (and create if needed) — InitDB may not have run yet on first call.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	sharedDB = db
	dbReady = true
	return sharedDB, nil
}

// GetSharedDB returns the shared *sql.DB for use by other packages (e.g. auth).
// The connection is initialised lazily on first call.
func GetSharedDB() (*sql.DB, error) {
	return getSharedDB()
}

// InitDB creates the SQLite cache database and all tables.
func InitDB() {
	path, err := dbPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB: %v\n", err)
		return
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB open: %v\n", err)
		return
	}

	for _, table := range integrations.CacheTables() {
		if !isAllowedCacheTable(table) {
			fmt.Fprintf(os.Stderr, "InitDB cache tables: invalid table name %q\n", table)
			return
		}
		stmt := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s (KEY TEXT PRIMARY KEY NOT NULL, DATA TEXT NOT NULL, CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
			table,
		)
		if _, err := db.Exec(stmt); err != nil {
			fmt.Fprintf(os.Stderr, "InitDB cache table %s: %v\n", table, err)
			return
		}
		indexName := "idx_" + strings.ToLower(table) + "_created"
		indexStmt := fmt.Sprintf(`CREATE INDEX IF NOT EXISTS %s ON %s(CREATED_AT)`, indexName, table)
		if _, err := db.Exec(indexStmt); err != nil {
			fmt.Fprintf(os.Stderr, "InitDB cache index %s: %v\n", table, err)
			return
		}
	}

	// Auth tables — additive, safe to run on existing DBs.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id             TEXT PRIMARY KEY NOT NULL,
			username       TEXT UNIQUE NOT NULL,
			password_hash  TEXT NOT NULL,
			is_admin       INTEGER NOT NULL DEFAULT 0,
			must_change_pw INTEGER NOT NULL DEFAULT 1,
			created_at     TEXT NOT NULL,
			created_by     TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS api_keys (
			user_id        TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			vt_key         BLOB,
			abuse_key      BLOB,
			ipapi_key      BLOB,
			abusech_key    BLOB,
			greynoise_key  BLOB,
			updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		);
		CREATE TABLE IF NOT EXISTS sessions (
			token  TEXT PRIMARY KEY NOT NULL,
			data   BLOB NOT NULL,
			expiry REAL NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expiry);
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB create tables: %v\n", err)
		return
	}

	// Enable WAL journal mode on the schema-creation connection BEFORE
	// the shared pool opens its own connection — WAL is per-database,
	// so it must be set while we still hold the only open connection.
	if _, walErr := db.Exec(`PRAGMA journal_mode=WAL`); walErr != nil {
		fmt.Fprintf(os.Stderr, "InitDB WAL: %v\n", walErr)
		// Non-fatal — cache works in rollback mode, WAL is a performance hint.
	}

	// Close the schema connection before opening the shared pool so SQLite
	// does not see two connections trying to acquire the WAL write lock.
	db.Close()

	// Reset and warm up the shared connection pool.
	dbMu.Lock()
	dbReady = false
	sharedDB = nil
	dbMu.Unlock()

	if _, err := getSharedDB(); err != nil {
		fmt.Fprintf(os.Stderr, "InitDB warm-up: %v\n", err)
		return
	}

	integrations.SetCacheFuncs(getCacheEntry, putCacheEntry)
	fmt.Println("✅ Database initialised")

}

// ── Unified cache helpers ─────────────────────────────────────────────────────

func getCacheEntry(key, table string) string {
	if !isAllowedCacheTable(table) {
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

func putCacheEntry(key, data, table string) {
	if !isAllowedCacheTable(table) {
		return
	}
	db, err := getSharedDB()
	if err != nil {
		return
	}
	q := fmt.Sprintf("INSERT OR REPLACE INTO %s (KEY, DATA) VALUES (?, ?)", table)
	db.Exec(q, key, data)
}

// ClearCaches deletes all rows from the specified cache tables.
func ClearCaches(tables []string) int {
	db, err := getSharedDB()
	if err != nil {
		return 0
	}
	total := 0
	for _, t := range tables {
		if !isAllowedCacheTable(t) {
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

// ClearHashCaches is kept as a compatibility wrapper for older call sites.
func ClearHashCaches(tables []string) int {
	return ClearCaches(tables)
}

func isAllowedCacheTable(table string) bool {
	if !cacheTableNameRe.MatchString(table) {
		return false
	}
	for _, allowed := range integrations.CacheTables() {
		if table == allowed {
			return true
		}
	}
	return false
}
