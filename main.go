package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/things-go/go-socks5"
)

const (
	Version = "0.1.0"
)

func main() {

	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("gs-proxy version %s\n", Version)
		return
	}

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

	log.Println("Starting SOCKS5 proxy server on :8000")
	if err := server.ListenAndServe("tcp", ":8000"); err != nil {
		panic(err)
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
