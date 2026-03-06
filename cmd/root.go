// cmd/root.go — root command: stores API keys to ~/.iocscan.yaml and initialises the DB.
package cmd

import (
	"fmt"
	"os"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Package-level vars shared across subcommands.
var (
	vtAPI      string
	abuseAPI   string
	ipapiAPI   string
	abuseCHAPI string
	cfgFile    string
)

var rootCmd = &cobra.Command{
	Use:   "iocscan",
	Short: "Fast IoC enrichment against AbuseIPDB, VirusTotal, ipapi.is, MalwareBazaar and ThreatFox",
	Long: `iocscan queries IPs and file hashes against multiple threat intel sources:
  • ipapi.is       — Geo & ASN info
  • AbuseIPDB      — Abuse confidence score & reports
  • VirusTotal     — Multi-engine malware verdicts (IPs + hashes)
  • MalwareBazaar  — Malware sample intel (hashes)        ┐ same key
  • ThreatFox      — Malware IOC intel (IPs + hashes)     ┘ (abuse.ch)

First-time setup — save your API keys:
  iocscan -v <VT_KEY> -a <ABUSE_KEY> -i <IPAPI_KEY> -b <ABUSECH_KEY>

Then scan:
  iocscan ips -i 8.8.8.8          (simple: geo/ASN only)
  iocscan ipc -i 8.8.8.8          (complex: all sources)
  iocscan web                      (start web UI on :8080)`,

	Run: func(cmd *cobra.Command, args []string) {
		vtSet := cmd.Flags().Changed("VT_API")
		abuseSet := cmd.Flags().Changed("Abuse_API")
		ipapiSet := cmd.Flags().Changed("IPapi_API")
		abuseCHSet := cmd.Flags().Changed("AbuseCH_API")

		if !vtSet && !abuseSet && !ipapiSet && !abuseCHSet {
			cmd.Help()
			return
		}

		if !(vtSet && abuseSet) {
			fmt.Fprintln(os.Stderr, "error: VT_API (-v) and Abuse_API (-a) are required")
			os.Exit(1)
		}

		utils.WriteConf(vtAPI, abuseAPI, ipapiAPI, abuseCHAPI)
		utils.InitDB()
	},
}

// Execute is called by main.go.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&vtAPI, "VT_API", "v", "", "VirusTotal API key")
	rootCmd.Flags().StringVarP(&abuseAPI, "Abuse_API", "a", "", "AbuseIPDB API key")
	rootCmd.Flags().StringVarP(&ipapiAPI, "IPapi_API", "i", "", "ipapi.is API key (optional)")
	rootCmd.Flags().StringVarP(&abuseCHAPI, "AbuseCH_API", "b", "", "abuse.ch key — used for MalwareBazaar + ThreatFox (optional)")

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: ~/.iocscan.yaml)")

	viper.BindPFlag("VT_API", rootCmd.Flags().Lookup("VT_API"))
	viper.BindPFlag("Abuse_API", rootCmd.Flags().Lookup("Abuse_API"))
	viper.BindPFlag("IPapi_API", rootCmd.Flags().Lookup("IPapi_API"))
	viper.BindPFlag("AbuseCH_API", rootCmd.Flags().Lookup("AbuseCH_API"))
}
