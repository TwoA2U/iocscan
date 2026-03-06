// cmd/ipc.go — "ipc" subcommand: full IP enrichment (AbuseIPDB + VirusTotal + geo + ThreatFox).
//
// Usage:
//   iocscan ipc -i 8.8.8.8
//   iocscan ipc -i "8.8.8.8, 1.1.1.1"
package cmd

import (
	"fmt"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

// ipcIPAddr is local to ipc to avoid conflict with ips.go
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

		fmt.Println("[")
		for i, ip := range ips {
			result, err := processor.Lookup(ip, "complex", true)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "  // ⚠️  %s: %v\n", ip, err)
				continue
			}
			// Add comma separator between items (valid JSON array)
			if i < len(ips)-1 {
				fmt.Println(result + ",")
			} else {
				fmt.Println(result)
			}
		}
		fmt.Println("]")
		return nil
	},
}

func init() {
	ipcCmd.Flags().StringVarP(&ipcIPAddr, "ipaddr", "i", "", "IP address(es), comma-separated (required)")
	ipcCmd.MarkFlagRequired("ipaddr")
	rootCmd.AddCommand(ipcCmd)
}
