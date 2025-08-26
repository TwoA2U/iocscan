/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/TwoA2U/iocscan/utils"
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	VT_API    string
	Abuse_API string
	IPapi_API string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "checksec",
	Short: "an application to take a quick check on the reputation of an IP",
	Long:  `an application to take a quick check on the reputation of an IP, By TwoA2U`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		utils.WriteConf(VT_API, Abuse_API, IPapi_API)
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// cobra.OnInitialize(initConfig)
	rootCmd.Flags().StringVarP(&VT_API, "VT_API", "v", "", "Virus Total API Key")
	rootCmd.Flags().StringVarP(&Abuse_API, "Abuse_API", "a", "", "Abuse IPDB API Key")
	rootCmd.Flags().StringVarP(&IPapi_API, "IPapi_API", "i", "", "IPApi API Key")
	rootCmd.MarkFlagsRequiredTogether("VT_API", "Abuse_API", "IPapi_API")

	// viper.BindPFlag("VT_API", rootCmd.PersistentFlags().Lookup("VT_API"))
	// viper.BindPFlag("Abuse_API", rootCmd.PersistentFlags().Lookup("Abuse_API"))
	// viper.BindPFlag("IPapi_API", rootCmd.PersistentFlags().Lookup("IPapi_API"))

}
