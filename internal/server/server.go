package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/spf13/viper"
	"github.com/things-go/go-socks5"
)

// defaultConfigFile is the location where the users config file is expected
// when PROXY_CONFIG_FILE is not set. In Kubernetes this is a mounted Secret.
const defaultConfigFile = "/etc/proxysocks/users.yaml"

var (
	userConnectMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxysocks_user_connect_total",
		Help: "The total number of user connections",
	}, []string{"user"})
)

// user represents a single set of proxy credentials.
type user struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// New builds the SOCKS5 server with an authenticator derived from the
// available configuration.
func New() *socks5.Server {
	logger := log.New(os.Stdout, "socks5: ", log.LstdFlags)

	// Setup server options
	opts := []socks5.Option{
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithConnectMiddleware(UserConnect),
	}

	// Setup auth
	authenticator, err := authenticatorFromConfig()
	if err != nil {
		log.Fatalf("failed to configure authentication: %s", err)
	}
	opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{authenticator}))

	// Setup server
	server := socks5.NewServer(opts...)
	return server
}

// authenticatorFromConfig builds the authenticator from a users config file,
// or falls back to no authentication when no config file is present.
func authenticatorFromConfig() (socks5.Authenticator, error) {
	users, err := loadUsers()
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		log.Println("No authentication required")
		return socks5.NoAuthAuthenticator{}, nil
	}

	creds := socks5.StaticCredentials{}
	for _, u := range users {
		if u.Username == "" || u.Password == "" {
			return nil, fmt.Errorf("user entries must have a non-empty username and password")
		}
		if _, exists := creds[u.Username]; exists {
			return nil, fmt.Errorf("duplicate username %q in configuration", u.Username)
		}
		creds[u.Username] = u.Password
	}

	log.Printf("Authentication enabled for %d user(s)", len(creds))
	return socks5.UserPassAuthenticator{Credentials: creds}, nil
}

// loadUsers reads the users config file if it exists. A missing file is not an
// error and yields an empty list so the caller can fall back to other sources.
// A present file that yields no users is an error, so a misconfigured mount
// cannot silently start the server without authentication.
func loadUsers() ([]user, error) {
	path := os.Getenv("PROXY_CONFIG_FILE")
	if path == "" {
		path = defaultConfigFile
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("checking config file %q: %w", path, err)
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var users []user
	if err := v.UnmarshalKey("users", &users); err != nil {
		return nil, fmt.Errorf("parsing users from %q: %w", path, err)
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("config file %q contains no users", path)
	}
	return users, nil
}

func UserConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	user := "anonymous"
	if request.AuthContext != nil {
		if u, ok := request.AuthContext.Payload["username"]; ok && u != "" {
			user = u
		}
	}
	userConnectMetric.WithLabelValues(user).Inc()
	log.Printf("socks5: new connection from/to: %s %s (user: %s)", request.RemoteAddr, request.DestAddr, user)
	return nil
}
