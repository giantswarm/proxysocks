package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/tg123/go-htpasswd"
	"github.com/things-go/go-socks5"
)

// defaultConfigFile is the location where the htpasswd credentials file is
// expected when PROXY_CONFIG_FILE is not set. In Kubernetes this is a mounted
// Secret.
const defaultConfigFile = "/etc/proxysocks/htpasswd"

var (
	userConnectMetric = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxysocks_user_connect_total",
		Help: "The total number of user connections",
	}, []string{"user"})
)

// htpasswdStore adapts an htpasswd file to the socks5.CredentialStore interface.
type htpasswdStore struct {
	file *htpasswd.File
}

// Valid implements socks5.CredentialStore.
func (s htpasswdStore) Valid(user, password, _ string) bool {
	return s.file.Match(user, password)
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

// authenticatorFromConfig builds the authenticator from an htpasswd file, or
// falls back to no authentication when no config file is present.
func authenticatorFromConfig() (socks5.Authenticator, error) {
	file, count, err := loadHtpasswd()
	if err != nil {
		return nil, err
	}

	if file == nil {
		log.Println("No authentication required")
		return socks5.NoAuthAuthenticator{}, nil
	}

	log.Printf("Authentication enabled for %d user(s)", count)
	return socks5.UserPassAuthenticator{Credentials: htpasswdStore{file: file}}, nil
}

// loadHtpasswd reads the htpasswd credentials file if it exists. A missing file
// is not an error and yields a nil file so the caller can fall back to no
// authentication. A present file is parsed strictly: a malformed line, a
// duplicate username, or a file with no credentials is an error, so a
// misconfigured mount cannot silently start the server without authentication.
func loadHtpasswd() (*htpasswd.File, int, error) {
	path := os.Getenv("PROXY_CONFIG_FILE")
	if path == "" {
		path = defaultConfigFile
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, 0, nil
	} else if err != nil {
		return nil, 0, fmt.Errorf("checking config file %q: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("reading config file %q: %w", path, err)
	}

	count, err := countCredentials(data)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	if count == 0 {
		return nil, 0, fmt.Errorf("config file %q contains no credentials", path)
	}

	var badLine error
	file, err := htpasswd.NewFromReader(bytes.NewReader(data), htpasswd.DefaultSystems, func(err error) {
		if badLine == nil {
			badLine = err
		}
	})
	if err != nil {
		return nil, 0, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	if badLine != nil {
		return nil, 0, fmt.Errorf("parsing config file %q: %w", path, badLine)
	}

	return file, count, nil
}

// countCredentials scans htpasswd content, counting entries and rejecting
// duplicate usernames. It mirrors go-htpasswd's line handling: whitespace-only
// lines are ignored and each remaining line is split on the first colon.
func countCredentials(data []byte) (int, error) {
	seen := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		username, _, ok := strings.Cut(line, ":")
		if !ok {
			return 0, fmt.Errorf("malformed line, no colon: %q", line)
		}
		if _, exists := seen[username]; exists {
			return 0, fmt.Errorf("duplicate username %q", username)
		}
		seen[username] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return len(seen), nil
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
