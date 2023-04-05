/*
Copyright © 2023 FairwindsOps, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/fairwindsops/bif"
)

var (
	version       string
	versionCommit string
	cfgFile       string
	insightsURL   string

	bifClient bif.Client
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bif",
	Short: "The Fairwinds Base Image Finder (BIF) Client",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("You must specify a sub-command.")
	},
}

var findCmd = &cobra.Command{
	Use:     "find [image]",
	Short:   "Finds the base image and any known vulnerabilities",
	PreRunE: validateTokenPreRunE,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fmt.Println("The find command requires a single docker image reference as an argument.")
			os.Exit(1)
		}
		if err := bifClient.GetBaseImage(args[0]); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	},
}

var requestTokenCmd = &cobra.Command{
	Use:   "request-token",
	Short: "Requests an API token for BIF",
	Run: func(cmd *cobra.Command, args []string) {
		if err := requestInsightsOSSToken(); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	},
}

func validateTokenPreRunE(cmd *cobra.Command, args []string) error {
	if bifClient.Token == "" {
		return fmt.Errorf("You must supply a token via the --insights-oss-token flag.")
	}
	return nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(VERSION, COMMIT string) {
	version = VERSION
	versionCommit = COMMIT

	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bif.yaml)")

	findCmd.PersistentFlags().StringVarP(&bifClient.Token, "insights-oss-token", "t", "", "Your Fairwinds OSS Token")
	findCmd.PersistentFlags().StringVar(&bifClient.APIURL, "bif-url", "https://bif-server-6biex2p5nq-uc.a.run.app", "The URL of the BIF server.")

	requestTokenCmd.PersistentFlags().StringVar(&insightsURL, "insights-url", "https://insights.fairwinds.com", "The Insights API URL")

	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(requestTokenCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bif")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	bindFlags(rootCmd, viper.GetViper())
	bindFlags(findCmd, viper.GetViper())
	bindFlags(requestTokenCmd, viper.GetViper())
}

// bindFlags binds the flags to the viper config, as well as to environment variables
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, "-") {
			envVar := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			err := v.BindEnv(f.Name, envVar)
			if err != nil {
				fmt.Printf("error parsing flag %s\n", f.Name)
				os.Exit(1)
			}
		}

		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				fmt.Printf("error parsing flag %s\n", f.Name)
				os.Exit(1)
			}
		}
	})
}
