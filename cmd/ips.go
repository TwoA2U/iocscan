/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

var (
	ipaddr  string
	CfgFile string
)

// ipsCmd represents the ips command
var ipsCmd = &cobra.Command{
	Use:   "ips",
	Short: "Simple command to check IP information",
	Long:  `A way to check information about a given IP Address, like its ASN, ORG, and country`,
	RunE: func(cmd *cobra.Command, args []string) error {

		processedip, err := utils.CheckIP(ipaddr)
		if err != nil {
			return fmt.Errorf("checkIP failed: %w", err)
		}

		C_API, err := utils.Get_API(CfgFile)
		cobra.CheckErr(err)
		ipprocessor := utils.NewIPProcessor(C_API.VT_API, C_API.Abuse_API, C_API.IPapi_API)

		fmt.Println("[")
		for _, ip := range processedip {
			res, err := ipprocessor.Lookup(ip, "simple")
			if err != nil {
				return fmt.Errorf("prosessing IP failed: %w", err)
			}
			fmt.Println(res)

		}
		fmt.Println("]")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ipsCmd)
	ipsCmd.Flags().StringVarP(&ipaddr, "ipaddr", "i", "", "Ip address that want to be checked")
	rootCmd.Flags().StringVarP(&CfgFile, "config", "c", "", "config file (default is $HOME/.checksec.yaml)")

}
