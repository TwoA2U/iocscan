// cmd/ips.go — "ips" subcommand: lightweight IP lookup via ipapi.is.
//
// Usage:
//   iocscan ips -i 8.8.8.8
//   iocscan ips -i "8.8.8.8, 1.1.1.1, 9.9.9.9"
package cmd

import (
	"fmt"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

// ipsIPAddr is local to ips to avoid conflict with ipc.go
var ipsIPAddr string

var ipsCmd = &cobra.Command{
	Use:   "ips",
	Short: "Simple IP lookup — geo & ASN info via ipapi.is",
	Long:  `Queries ipapi.is for lightweight geo and ASN information about one or more IPs.`,
	Example: `  iocscan ips -i 8.8.8.8
  iocscan ips -i "8.8.8.8, 1.1.1.1, 9.9.9.9"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ips, err := utils.CheckIP(ipsIPAddr)
		if err != nil {
			return fmt.Errorf("invalid IP address: %w", err)
		}

		apis, err := utils.GetAPI(cfgFile)
		if err != nil {
			return err
		}

		processor := utils.NewIPProcessor(apis.VTAPI, apis.AbuseAPI, apis.IPapiAPI)

		fmt.Println("[")
		for i, ip := range ips {
			result, err := processor.Lookup(ip, "simple", true)
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
	ipsCmd.Flags().StringVarP(&ipsIPAddr, "ipaddr", "i", "", "IP address(es), comma-separated (required)")
	ipsCmd.MarkFlagRequired("ipaddr")
	rootCmd.AddCommand(ipsCmd)
}
