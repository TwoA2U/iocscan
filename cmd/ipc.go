// cmd/ipc.go — "ipc" subcommand: full IP enrichment (AbuseIPDB + VirusTotal + geo + ThreatFox).
//
// Usage:
//   iocscan ipc -i 8.8.8.8
//   iocscan ipc -i "8.8.8.8, 1.1.1.1"
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

// ipcIPAddr holds the -i flag value for the ipc subcommand.
var ipcIPAddr string

var ipcCmd = &cobra.Command{
	Use:   "ipc",
	Short: "Complex IP enrichment — AbuseIPDB + VirusTotal + ThreatFox (requires all API keys)",
	Long:  `Queries AbuseIPDB, VirusTotal and ThreatFox concurrently for full threat-intel enrichment.`,
	Example: `  iocscan ipc -i 8.8.8.8
  iocscan ipc -i "8.8.8.8, 1.1.1.1"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ips, err := utils.CheckIP(ipcIPAddr)
		if err != nil {
			return fmt.Errorf("invalid IP address: %w", err)
		}

		apis, err := utils.GetAPI(cfgFile)
		if err != nil {
			return err
		}

		processor := utils.NewIPProcessor(apis.VTAPI, apis.AbuseAPI, apis.IPapiAPI, apis.AbuseCHAPI)

		// Collect all results — success and error — into a raw JSON slice so
		// the final output is always a valid JSON array regardless of failures.
		entries := make([]string, 0, len(ips))
		for _, ip := range ips {
			result, err := processor.Lookup(context.Background(), ip, true)
			if err != nil {
				// Emit a structured error object so piped tools (jq, etc.) don't break.
				b, _ := json.Marshal(map[string]string{"ip": ip, "error": err.Error()})
				entries = append(entries, string(b))
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  %s: %v\n", ip, err)
				continue
			}
			entries = append(entries, result)
		}

		fmt.Printf("[%s]\n", strings.Join(entries, ","))
		return nil
	},
}

func init() {
	ipcCmd.Flags().StringVarP(&ipcIPAddr, "ipaddr", "i", "", "IP address(es), comma-separated (required)")
	ipcCmd.MarkFlagRequired("ipaddr")
	rootCmd.AddCommand(ipcCmd)
}
