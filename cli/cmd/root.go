package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/subchen/go-log"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	//Long: `vgw_cli`,
}

func Execute() {
	RootCmd.Use = os.Args[0]
	RootCmd.Short = os.Args[0]

	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	log.Default.Level = log.DEBUG

	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	//RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cobra-example.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//RootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	/*
		if cfgFile != "" {
			// Use config file from the flag.
			viper.SetConfigFile(cfgFile)
		} else {
			// Find home directory.
			home, err := homedir.Dir()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			// Search config in home directory with name ".cobra-example" (without extension).
			viper.AddConfigPath(home)
			viper.SetConfigName(".cobra-example")
		}

		viper.AutomaticEnv() // read in environment variables that match

		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	*/
}
