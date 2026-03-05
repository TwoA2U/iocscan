// utils/common.go — config file, SQLite cache, and API key helpers.
package utils

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	_ "modernc.org/sqlite"
)

// ── API key collection ────────────────────────────────────────────────────────

// CollectionAPI holds the API keys read from the config file.
type CollectionAPI struct {
	VTAPI    string
	AbuseAPI string
	IPapiAPI string
	MBAPI    string
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
		VTAPI:    strings.TrimSpace(viper.GetString("VT_API")),
		AbuseAPI: strings.TrimSpace(viper.GetString("Abuse_API")),
		IPapiAPI: strings.TrimSpace(viper.GetString("IPapi_API")),
		MBAPI:    strings.TrimSpace(viper.GetString("MB_API")),
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
func WriteConf(vtAPI, abuseAPI, ipapiAPI, mbAPI string) {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not determine home directory: %v\n", err)
		return
	}

	config := fmt.Sprintf("VT_API: %s\nAbuse_API: %s\nIPapi_API: %s\nMB_API: %s\n", vtAPI, abuseAPI, ipapiAPI, mbAPI)

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

const cacheMaxAge = 30 * 24 * time.Hour

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

// allowedTables whitelists valid cache table names to prevent SQL injection.
var allowedTables = map[string]bool{
	"VT_IP":      true,
	"ABUSE_IP":   true,
	"IPAPIIS_IP": true,
}

func dbPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".iocscan.db"), nil
}

func openDB() (*sql.DB, error) {
	path, err := dbPath()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("cache DB not found — run `iocscan` setup first")
	}
	return sql.Open("sqlite", path)
}

// InitDB creates the SQLite cache database and its three tables.
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
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS VT_IP (
			IP         TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS ABUSE_IP (
			IP         TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS IPAPIIS_IP (
			IP         TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS VT_HASH (
			IP         TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS MB_HASH (
			IP         TEXT PRIMARY KEY NOT NULL,
			DATA       TEXT NOT NULL,
			CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "InitDB create tables: %v\n", err)
		return
	}
	fmt.Println("✅ Cache DB initialised")
}

// getCached returns a cached result for the given IP and table,
// or "" if not found or expired (> 30 days old).
func getCached(ip, table string) string {
	if !allowedTables[table] {
		return ""
	}
	db, err := openDB()
	if err != nil {
		return ""
	}
	defer db.Close()

	var data, createdAt string
	query := fmt.Sprintf("SELECT DATA, CREATED_AT FROM %s WHERE IP = ?", table)
	if err := db.QueryRow(query, ip).Scan(&data, &createdAt); err != nil {
		return ""
	}

	t, err := parseSQLiteTime(createdAt)
	if err != nil || time.Since(t.UTC()) > cacheMaxAge {
		db.Exec(fmt.Sprintf("DELETE FROM %s WHERE IP = ?", table), ip)
		return ""
	}
	return data
}

// putCached inserts or replaces a cached result.
func putCached(ip, data, table string) {
	if !allowedTables[table] {
		return
	}
	db, err := openDB()
	if err != nil {
		return
	}
	defer db.Close()

	query := fmt.Sprintf("INSERT OR REPLACE INTO %s (IP, DATA) VALUES (?, ?)", table)
	db.Exec(query, ip, data)
}
