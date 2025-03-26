package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/things-go/go-socks5"
)

func main() {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Get credentials from environment variables
	username := getEnvOrDefault("PROXY_USERNAME", "")
	password := getEnvOrDefault("PROXY_PASSWORD", "")

	var authenticator socks5.Authenticator
	if username != "" && password != "" {
		// Use static credentials authenticator if credentials are provided
		creds := socks5.StaticCredentials{
			username: password,
		}
		authenticator = socks5.UserPassAuthenticator{Credentials: creds}
		log.Println("Authentication enabled")
	} else {
		log.Println("Warning: No authentication credentials provided")
	}

	// Create a SOCKS5 server with authentication
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithDial(LoggingDialer),
		socks5.WithAuthMethods([]socks5.Authenticator{authenticator}),
	)

	// Create SOCKS5 proxy on localhost port 8000
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
