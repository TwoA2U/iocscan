// config/config.go — Application configuration loader.
//
// Reads ~/.iocscan/config.yaml (or a custom path via -c flag).
// Falls back to sensible defaults when the file is absent or a field is empty.
// Environment variables override file values for every field.
//
// Format:
//
//	server:
//	  port: 8080
//	database:
//	  path: ""   # default: ~/.iocscan/iocscan.db
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds all application-level configuration.
// Fields intentionally kept minimal — auth fields added in the auth phase.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Database DatabaseConfig `yaml:"database"`
}

type ServerConfig struct {
	Port int `yaml:"port"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

// DefaultPath returns the canonical config file location: ~/.iocscan/config.yaml
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".iocscan", "config.yaml"), nil
}

// DefaultDBPath returns the canonical database location: ~/.iocscan/iocscan.db
func DefaultDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".iocscan", "iocscan.db"), nil
}

// Load reads the config file at cfgPath and applies defaults for missing fields.
// If cfgPath is empty, DefaultPath() is used.
// If the file does not exist, all defaults are returned — not an error.
// Environment variables take precedence over file values:
//
//	IOCSCAN_PORT     overrides server.port
//	IOCSCAN_DB_PATH  overrides database.path
func Load(cfgPath string) (*Config, error) {
	cfg := defaults()

	// Resolve path
	if cfgPath == "" {
		p, err := DefaultPath()
		if err != nil {
			return cfg, nil // can't find home — return defaults silently
		}
		cfgPath = p
	}

	// Read file — missing file is not an error
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnv(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", cfgPath, err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", cfgPath, err)
	}

	// Fill any zero values with defaults
	fillDefaults(cfg)

	// Environment overrides (highest priority)
	applyEnv(cfg)

	return cfg, nil
}

// DBPath returns the resolved database path, creating the directory if needed.
func (c *Config) DBPath() (string, error) {
	if c.Database.Path != "" {
		return c.Database.Path, nil
	}
	return DefaultDBPath()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func defaults() *Config {
	return &Config{
		Server:   ServerConfig{Port: 8080},
		Database: DatabaseConfig{Path: ""},
	}
}

func fillDefaults(c *Config) {
	if c.Server.Port == 0 {
		c.Server.Port = 8080
	}
}

func applyEnv(c *Config) {
	if v := os.Getenv("IOCSCAN_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			c.Server.Port = n
		}
	}
	if v := os.Getenv("IOCSCAN_DB_PATH"); v != "" {
		c.Database.Path = v
	}
}
