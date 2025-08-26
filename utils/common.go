package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Collection_API struct {
	VT_API    string
	Abuse_API string
	IPapi_API string
}

func Get_API(cfgFile string) (*Collection_API, error) {
	cfg, err := GetConfig(cfgFile)
	if err != nil {
		fmt.Println("Please initate all the API first before executing this program")
		fmt.Println("checksec -v {VT_API} -a {Abuse_API} -i {IPapi_API}")
		return nil, err
	}
	viper.SetConfigFile(cfg)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}
	res := Collection_API{
		VT_API:    strings.TrimSpace(viper.GetString("VT_API")),
		Abuse_API: strings.TrimSpace(viper.GetString("Abuse_API")),
		IPapi_API: strings.TrimSpace(viper.GetString("IPapi_API")),
	}

	return &res, nil
}

func GetConfig(cfgFile string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if cfgFile == "" {
		cfgFile = filepath.Join(home, ".checksec.yaml")
	}

	if _, err := os.Stat(cfgFile); err != nil {
		return "", err
	}
	return cfgFile, nil
}

func WriteConf(VT_API string, Abuse_APIstring, IPapi_API string) {

	config := fmt.Sprintf(`
VT_API: %s
Abuse_API: %s
IPapi_API: %s
`, VT_API, Abuse_APIstring, IPapi_API)

	viper.SetConfigType("yaml")
	if err := viper.ReadConfig(bytes.NewBuffer([]byte(config))); err != nil {
		cobra.CheckErr(err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		cobra.CheckErr(err)
	}

	configFilePath := filepath.Join(home, ".checksec.yaml")
	if err := viper.SafeWriteConfigAs(configFilePath); err != nil {
		cobra.CheckErr(err)
	}
	fmt.Printf("Config file successfully written to %s\n", configFilePath)
}
