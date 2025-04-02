package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/things-go/go-socks5"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "proxysocks",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

		// Get credentials from environment variables
		username := getEnvOrDefault("PROXY_USERNAME", "")
		password := getEnvOrDefault("PROXY_PASSWORD", "")

		// Setup server options
		opts := []socks5.Option{
			socks5.WithLogger(socks5.NewLogger(logger)),
			socks5.WithDial(LoggingDialer),
		}

		if username != "" && password != "" {
			// Use static credentials authenticator if credentials are provided
			creds := socks5.StaticCredentials{
				username: password,
			}
			authenticator := socks5.UserPassAuthenticator{Credentials: creds}
			opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{authenticator}))
			log.Println("Authentication enabled")
		} else {
			noAuth := socks5.NoAuthAuthenticator{}
			opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{noAuth}))
			log.Println("No authentication required")
		}

		server := socks5.NewServer(opts...)

		log.Println("Starting SOCKS5 proxy server on :1080")
		if err := server.ListenAndServe("tcp", ":1080"); err != nil {
			panic(err)
		}
	},
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
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.proxysocks.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".proxysocks" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".proxysocks")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func LoggingDialer(ctx context.Context, network, address string) (net.Conn, error) {
	log.Printf("New connection: %s %s", network, address)
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, address)
}

// Helper function to get environment variable with a default value
func getEnvOrDefault(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
