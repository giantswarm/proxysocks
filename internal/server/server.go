package server

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/bcrypt"
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

	authFailureMetric = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxysocks_auth_failures_total",
		Help: "The total number of failed authentication attempts",
	})

	activeConnectionsMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxysocks_active_connections",
		Help: "The number of connections currently being served",
	})

	connectionErrorMetric = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxysocks_connection_errors_total",
		Help: "The total number of connections that ended with an error",
	})
)

// bcryptCredentials maps usernames to bcrypt password hashes and implements
// socks5.CredentialStore.
type bcryptCredentials map[string]string

// Valid implements socks5.CredentialStore.
func (c bcryptCredentials) Valid(user, password, _ string) bool {
	hash, ok := c[user]
	if !ok {
		authFailureMetric.Inc()
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		authFailureMetric.Inc()
		return false
	}
	return true
}

// socksLog returns a logger tagged with the socks5 component. It resolves the
// default logger lazily so it picks up the handler configured in Execute.
func socksLog() *slog.Logger {
	return slog.With("component", "socks5")
}

// slogAdapter implements socks5.Logger on top of slog.
type slogAdapter struct {
	logger *slog.Logger
}

// Errorf implements socks5.Logger.
func (a slogAdapter) Errorf(format string, args ...interface{}) {
	a.logger.Error(fmt.Sprintf(format, args...))
}

// New builds the SOCKS5 server with an authenticator derived from the
// available configuration.
func New() (*socks5.Server, error) {
	opts := []socks5.Option{
		socks5.WithLogger(slogAdapter{logger: socksLog()}),
		socks5.WithConnectMiddleware(UserConnect),
	}

	authenticator, err := authenticatorFromConfig()
	if err != nil {
		return nil, fmt.Errorf("configuring authentication: %w", err)
	}
	opts = append(opts, socks5.WithAuthMethods([]socks5.Authenticator{authenticator}))

	return socks5.NewServer(opts...), nil
}

// Serve accepts connections on ln and serves them with srv until ctx is
// canceled, then stops accepting and waits for in-flight connections to
// finish before returning.
func Serve(ctx context.Context, srv *socks5.Server, ln net.Listener) error {
	defer context.AfterFunc(ctx, func() { _ = ln.Close() })()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		wg.Add(1)
		activeConnectionsMetric.Inc()
		go func() {
			defer wg.Done()
			defer activeConnectionsMetric.Dec()
			if err := srv.ServeConn(conn); err != nil {
				connectionErrorMetric.Inc()
				socksLog().Error("connection error", "error", err)
			}
		}()
	}

	socksLog().Info("draining in-flight connections")
	wg.Wait()
	return nil
}

// authenticatorFromConfig builds the authenticator from an htpasswd file, or
// falls back to no authentication when no config file is present.
func authenticatorFromConfig() (socks5.Authenticator, error) {
	creds, err := loadHtpasswd()
	if err != nil {
		return nil, err
	}

	if creds == nil {
		slog.Info("no authentication required")
		return socks5.NoAuthAuthenticator{}, nil
	}

	slog.Info("authentication enabled", "users", len(creds))
	return socks5.UserPassAuthenticator{Credentials: creds}, nil
}

// loadHtpasswd reads the htpasswd credentials file if it exists. A missing file
// is not an error and yields a nil map so the caller can fall back to no
// authentication. A present file is parsed strictly: a malformed line, a
// non-bcrypt hash, a duplicate username, or a file with no credentials is an
// error, so a misconfigured mount cannot silently start the server without
// authentication.
func loadHtpasswd() (bcryptCredentials, error) {
	path := os.Getenv("PROXY_CONFIG_FILE")
	if path == "" {
		path = defaultConfigFile
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("checking config file %q: %w", path, err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	creds, err := parseHtpasswd(data)
	if err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("config file %q contains no credentials", path)
	}

	return creds, nil
}

// parseHtpasswd parses htpasswd content into a credential map. Whitespace-only
// lines are ignored; every other line must be a "user:hash" pair with a bcrypt
// hash. Only bcrypt is supported (e.g. from `htpasswd -B`); other schemes are
// rejected so a misconfigured file fails at startup rather than silently never
// matching.
func parseHtpasswd(data []byte) (bcryptCredentials, error) {
	creds := bcryptCredentials{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		user, hash, ok := strings.Cut(text, ":")
		if !ok || user == "" || hash == "" {
			return nil, fmt.Errorf("line %d: malformed entry, expected user:hash", line)
		}
		if _, exists := creds[user]; exists {
			return nil, fmt.Errorf("line %d: duplicate username %q", line, user)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, fmt.Errorf("line %d: user %q has a non-bcrypt hash (use `htpasswd -B`): %w", line, user, err)
		}
		creds[user] = hash
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return creds, nil
}

func UserConnect(ctx context.Context, writer io.Writer, request *socks5.Request) error {
	user := "anonymous"
	if request.AuthContext != nil {
		if u, ok := request.AuthContext.Payload["username"]; ok && u != "" {
			user = u
		}
	}
	userConnectMetric.WithLabelValues(user).Inc()
	socksLog().Info("new connection", "remote", request.RemoteAddr.String(), "destination", request.DestAddr.String(), "user", user)
	return nil
}
