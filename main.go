// main.go — iocscan entry point.
//
// Usage:
//   iocscan              Start web UI on the configured port (default :8080)
//   iocscan -p 9090      Start web UI on a custom port
//   iocscan -c /path     Use a custom config file
//   iocscan --help       Print usage
//
// Authentication: session-based via scs. Default admin/admin on first run.
package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/TwoA2U/iocscan/auth"
	"github.com/TwoA2U/iocscan/config"
	"github.com/TwoA2U/iocscan/server"
	"github.com/TwoA2U/iocscan/utils"
)

//go:embed all:web
var embeddedWeb embed.FS

func main() {
	portFlag := flag.Int("p", 0, "Port to listen on (overrides config, default 8080)")
	cfgFlag := flag.String("c", "", "Config file path (default: ~/.iocscan/config.yaml)")
	flag.Usage = usage
	flag.Parse()

	// Load config — missing file is not an error, defaults are used.
	cfg, err := config.Load(*cfgFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	// CLI flag overrides config file port.
	if *portFlag != 0 {
		cfg.Server.Port = *portFlag
	}

	// Ensure the ~/.iocscan/ directory exists for the database.
	ensureDataDir()

	// Initialise the SQLite cache database and auth tables.
	utils.InitDB()

	// Load the encryption key (creates ~/.iocscan.secret on first run).
	encKey, err := auth.LoadOrCreateSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "crypto init error: %v\n", err)
		os.Exit(1)
	}

	// Bootstrap default admin account if no users exist.
	db, err := utils.GetSharedDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "db init error: %v\n", err)
		os.Exit(1)
	}
	if err := auth.BootstrapAdmin(db); err != nil {
		fmt.Fprintf(os.Stderr, "bootstrap error: %v\n", err)
		os.Exit(1)
	}
	// Strip the "web/" prefix so the embedded FS root is the web/ directory
	// itself — http.FileServer will then serve index.html at "/" correctly.
	sub, err := fs.Sub(embeddedWeb, "web")
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed error: %v\n", err)
		os.Exit(1)
	}

	server.Start(cfg.Server.Port, *cfgFlag, sub, db, encKey)
}

// ensureDataDir creates ~/.iocscan/ if it does not already exist.
// Non-fatal — if it fails the server continues and SQLite will report
// its own error when InitDB() tries to open the database file.
func ensureDataDir() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	dir := home + "/.iocscan"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0700)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `iocscan — threat intelligence enrichment for IPs, hashes, and domains

Usage:
  iocscan [flags]

Flags:
  -p int     Port to listen on (default: 8080, or value from config)
  -c string  Config file path (default: ~/.iocscan/config.yaml)
  --help     Show this message

Config file (~/.iocscan/config.yaml):
  server:
    port: 8080
  database:
    path: ""     # default: ~/.iocscan/iocscan.db

Examples:
  iocscan                  Start on :8080
  iocscan -p 9090          Start on :9090
  iocscan -c /etc/iocscan/config.yaml

API keys are entered in the web UI and sent per-scan request.
`)
}
