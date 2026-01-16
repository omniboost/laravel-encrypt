package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "laravel_encrypt",
	Short: "Encrypt / Decrypt Laravel encrypted strings",
	Long: `This tool can encrypt and decrypt laravel encrypted strings.
Reads data from stdin`,
	Run: func(cmd *cobra.Command, args []string) {
		key := viper.GetString("app_key")
		if key == "" {
			println(`Error: required flag(s) "app_key" not set`)
			cmd.Usage()
			os.Exit(1)
		}

		if strings.HasPrefix(key, "base64:") {
			AppKey, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(key, "base64:"))
		} else {
			AppKey = []byte(key)
		}
		if len(AppKey) != 32 {
			println(`Error: app_key should be 32 bytes long (decoded)`)
		}

		if !isInputPiped() {
			println(`Error: No stdin received`)
			cmd.Usage()
			os.Exit(1)
		}

		rawMode := viper.GetBool("raw")
		data, err := getData(rawMode)
		if err != nil {
			println(err.Error())
			cmd.Usage()
			os.Exit(1)
		}

		decryptMode, _ := cmd.Flags().GetBool("decrypt")
		var output string
		if decryptMode {
			output, err = decryptString(data)
			if data == output {
				println("Error: Failed to decrypt data, input is not in correct format")
				os.Exit(1)
			}

		} else {
			output, err = encryptString(data)
		}
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
		if rawMode || isOutputPiped() {
			fmt.Print(output)
		} else {
			fmt.Println(output)
		}
	},
}

func isInputPiped() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func isOutputPiped() bool {
	stat, _ := os.Stdout.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("app_key", "k", "", "APP_KEY used for encryption, can be prefixed with 'base64:' which will automatically decode it before using the key")
	rootCmd.PersistentFlags().BoolP("raw", "r", false, "Don't strip newlines on single line input")
	rootCmd.Flags().BoolP("decrypt", "d", false, "If set input will be decrypted")
	viper.BindPFlags(rootCmd.PersistentFlags())
	viper.AutomaticEnv()
}

func getData(raw bool) (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}

	if raw {
		return string(data), nil
	}

	if lines := strings.Split(string(data), "\n"); len(lines) == 2 && lines[1] == "" {
		return lines[0], nil
	}
	return string(data), nil
}
