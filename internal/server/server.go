package server

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/things-go/go-socks5"
)

func New() *socks5.Server {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Get credentials from environment variables
	username := os.Getenv("PROXY_USERNAME")
	password := os.Getenv("PROXY_PASSWORD")

	// Setup server options
	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithConnectMiddleware(UserConnect),
	}

	var authenticator socks5.Authenticator
	if username != "" && password != "" {
		// Use static credentials authenticator if credentials are provided
		creds := socks5.StaticCredentials{
			username: password,
		}
		authenticator = socks5.UserPassAuthenticator{Credentials: creds}
		log.Println("Authentication enabled")
	} else {
		authenticator = socks5.NoAuthAuthenticator{}
		log.Println("No authentication required")
	}
	opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{authenticator}))

	server := socks5.NewServer(opts...)
	return server
}

func UserConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	log.Printf("socks5: new connection from/to: %s %s", request.RemoteAddr, request.DestAddr)
	return nil
}
