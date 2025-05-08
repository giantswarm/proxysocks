package server

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/things-go/go-socks5"
)

var (
	userConnectMetric = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxysocks_user_connect_total",
		Help: "The total number of user connections",
	})
)

func New() *socks5.Server {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Setup server options
	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithConnectMiddleware(UserConnect),
	}

	// Setup auth
	username := os.Getenv("PROXY_USERNAME")
	password := os.Getenv("PROXY_PASSWORD")

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

	// Setup server
	server := socks5.NewServer(opts...)
	return server
}

func UserConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	userConnectMetric.Inc()
	log.Printf("socks5: new connection from/to: %s %s", request.RemoteAddr, request.DestAddr)
	return nil
}
