package utils

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	_ "modernc.org/sqlite"
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
		cfgFile = filepath.Join(home, ".iocscan.yaml")
	}

	if _, err := os.Stat(cfgFile); err != nil {
		return "", err
	}
	return cfgFile, nil
}

func GetDB() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	databaseFile := filepath.Join(home, ".iocscan.db")

	if _, err := os.Stat(databaseFile); err != nil {
		return "", err
	}
	return databaseFile, nil
}

func GetValuetDB(ip string, table string) string {
	DBFile, err := GetDB()
	cobra.CheckErr(err)

	db, err := sql.Open("sqlite", DBFile)
	cobra.CheckErr(err)
	defer db.Close()

	var data string
	var created_at string
	query := fmt.Sprintf("select data, created_at from %s where IP = ?", table)
	err = db.QueryRow(query, ip).Scan(&data, &created_at)
	if err == sql.ErrNoRows {
		return ""
	}
	cobra.CheckErr(err)

	parsedtime, err := time.Parse(time.RFC3339, created_at)
	cobra.CheckErr(err)
	parsedtime = parsedtime.UTC()
	cutoff := time.Now().AddDate(0, 0, -30).UTC()

	if parsedtime.Before(cutoff) {
		query := fmt.Sprintf("delete from %s where IP = ?", table)
		_, err = db.Exec(query, ip)
		cobra.CheckErr(err)
		return ""
	}
	return data
}

func InsertValueDB(ip string, data string, table string) {
	DBFile, err := GetDB()
	cobra.CheckErr(err)
	db, err := sql.Open("sqlite", DBFile)
	cobra.CheckErr(err)
	defer db.Close()

	query := fmt.Sprintf("INSERT INTO %s (ip, data) VALUES (?, ?)", table)
	_, err = db.Exec(query, ip, data)
	cobra.CheckErr(err)
}

func InitDB() {
	home, err := os.UserHomeDir()
	if err != nil {
		cobra.CheckErr(err)
	}
	databaseFile := filepath.Join(home, ".iocscan.db")
	f, err := os.Create(databaseFile)
	if err != nil {
		cobra.CheckErr(err)
	}
	defer f.Close()
	db, err := sql.Open("sqlite", databaseFile)
	if err != nil {
		cobra.CheckErr(err)
	}

	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS VT_IP (IP TEXT PRIMARY KEY NOT NULL, DATA TEXT NOT NULL, CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP);	
CREATE TABLE IF NOT EXISTS ABUSE_IP (IP TEXT PRIMARY KEY NOT NULL , DATA TEXT NOT NULL, CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP);	
CREATE TABLE IF NOT EXISTS IPAPIIS_IP (IP TEXT PRIMARY KEY NOT NULL ,DATA TEXT NOT NULL, CREATED_AT TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`,
	); err != nil {
		cobra.CheckErr(err)
	}
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
