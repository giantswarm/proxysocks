package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/bcrypt"
)

// defaultConfigFile is the location where the htpasswd credentials file is
// expected when PROXY_CONFIG_FILE is not set. In Kubernetes this is a mounted
// Secret.
const defaultConfigFile = "/etc/proxysocks/htpasswd"

// Timeouts bound a connection's lifecycle. go-socks5 sets no deadlines of its
// own, so without these a client that connects and never speaks holds a
// goroutine and a file descriptor for as long as the process lives, and blocks
// shutdown while it does.
type Timeouts struct {
	// Handshake bounds how long a client has to complete the SOCKS5 greeting,
	// authentication and request. It is lifted once the request is accepted,
	// since a tunnel is expected to then stay open and idle.
	Handshake time.Duration

	// Drain bounds how long Serve waits for in-flight connections once the
	// context is canceled. Proxied tunnels are long-lived by nature, so
	// without a cap a single idle tunnel keeps the process alive until the
	// container runtime kills it.
	Drain time.Duration
}

// DefaultTimeouts returns the timeouts the proxy runs with.
func DefaultTimeouts() Timeouts {
	return Timeouts{
		Handshake: 10 * time.Second,
		Drain:     25 * time.Second,
	}
}

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

// bcryptCredentials holds usernames mapped to bcrypt password hashes and
// implements socks5.CredentialStore.
type bcryptCredentials struct {
	hashes map[string]string
	// dummyHash is compared for unknown usernames so that authenticating an
	// unknown user costs the same as authenticating a known one. Its cost
	// matches the cheapest hash in hashes, which is what makes the two
	// indistinguishable by timing. It hashes a random password generated at
	// startup, so it can never authenticate anyone.
	dummyHash []byte
}

// newBcryptCredentials builds a credential store from username to bcrypt hash
// pairs. It derives the dummy hash used for unknown users from the costs
// actually present in hashes: a hardcoded cost would only equalize timing for
// files that happen to use the same one, and `htpasswd -B` defaults to cost 5
// while a hardcoded cost 10 hash takes roughly 30 times longer to compare,
// which turns the comparison into a username enumeration oracle.
func newBcryptCredentials(hashes map[string]string) (bcryptCredentials, error) {
	if len(hashes) == 0 {
		return bcryptCredentials{}, errors.New("no credentials")
	}

	minCost, maxCost := 0, 0
	for user, hash := range hashes {
		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			return bcryptCredentials{}, fmt.Errorf("user %q has a non-bcrypt hash: %w", user, err)
		}
		if minCost == 0 || cost < minCost {
			minCost = cost
		}
		if cost > maxCost {
			maxCost = cost
		}
	}
	if minCost != maxCost {
		// Entries cheaper than the others stay distinguishable by how long
		// they take to compare, whatever the unknown-user path costs.
		slog.Warn("htpasswd entries use mixed bcrypt costs, which leaks which usernames exist by timing; rehash them at a single cost",
			"min_cost", minCost, "max_cost", maxCost)
	}

	// A random password keeps the dummy hash from ever matching, even if its
	// plaintext were guessed from the source.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return bcryptCredentials{}, fmt.Errorf("generating dummy password: %w", err)
	}
	dummyHash, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(secret)), minCost)
	if err != nil {
		return bcryptCredentials{}, fmt.Errorf("generating dummy hash at cost %d: %w", minCost, err)
	}

	return bcryptCredentials{hashes: hashes, dummyHash: dummyHash}, nil
}

// Valid implements socks5.CredentialStore.
func (c bcryptCredentials) Valid(user, password, _ string) bool {
	hash, ok := c.hashes[user]
	// An unknown username is compared against the dummy hash so that it costs
	// the same as a known one and cannot be distinguished by timing.
	candidate := c.dummyHash
	if ok {
		candidate = []byte(hash)
	}
	err := bcrypt.CompareHashAndPassword(candidate, []byte(password))
	if !ok || err != nil {
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
		// The handshake deadline set in Serve has to be lifted once the
		// request is through, for every command, or long-lived tunnels would
		// be torn down mid-transfer.
		socks5.WithConnectMiddleware(clearHandshakeDeadline),
		socks5.WithBindMiddleware(clearHandshakeDeadline),
		socks5.WithAssociateMiddleware(clearHandshakeDeadline),
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
// canceled, then stops accepting and waits up to timeouts.Drain for in-flight
// connections to finish before returning. Each connection has
// timeouts.Handshake to get through the SOCKS5 handshake.
func Serve(ctx context.Context, srv *socks5.Server, ln net.Listener, timeouts Timeouts) error {
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
			// Bound the handshake. clearHandshakeDeadline lifts this once the
			// client's request has been accepted.
			if err := conn.SetDeadline(time.Now().Add(timeouts.Handshake)); err != nil {
				socksLog().Error("setting handshake deadline", "error", err)
				_ = conn.Close()
				return
			}
			if err := srv.ServeConn(conn); err != nil {
				// A client that opens a connection and closes it before
				// completing the SOCKS5 handshake (e.g. a TCP health check or
				// port probe) surfaces as EOF. That is benign, so log it at
				// debug and do not count it as a connection error.
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					socksLog().Debug("client disconnected before handshake", "error", err)
					return
				}
				// A client that stalls mid-handshake trips the deadline set
				// above. That is not an error worth alerting on either.
				if errors.Is(err, os.ErrDeadlineExceeded) {
					socksLog().Debug("client timed out during handshake", "error", err, "timeout", timeouts.Handshake)
					return
				}
				connectionErrorMetric.Inc()
				socksLog().Error("connection error", "error", err)
			}
		}()
	}

	socksLog().Info("draining in-flight connections", "timeout", timeouts.Drain)
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(timeouts.Drain):
		// The remaining connections are closed by the process exiting. Waiting
		// any longer only delays that until the container runtime steps in.
		socksLog().Warn("drain timeout reached, leaving connections to close on exit", "timeout", timeouts.Drain)
	}
	return nil
}

// clearHandshakeDeadline lifts the handshake deadline Serve set on the
// connection, now that the client's request has been accepted and the
// connection may legitimately sit idle. The writer a middleware receives is
// the client connection itself.
func clearHandshakeDeadline(_ context.Context, writer io.Writer, _ *socks5.Request) error {
	conn, ok := writer.(net.Conn)
	if !ok {
		return nil
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clearing handshake deadline: %w", err)
	}
	return nil
}

// authenticatorFromConfig builds the authenticator from an htpasswd file, or
// falls back to no authentication when no config file is present.
func authenticatorFromConfig() (socks5.Authenticator, error) {
	hashes, err := loadHtpasswd()
	if err != nil {
		return nil, err
	}

	if hashes == nil {
		slog.Info("no authentication required")
		return socks5.NoAuthAuthenticator{}, nil
	}

	creds, err := newBcryptCredentials(hashes)
	if err != nil {
		return nil, err
	}

	slog.Info("authentication enabled", "users", len(hashes))
	return socks5.UserPassAuthenticator{Credentials: creds}, nil
}

// loadHtpasswd reads the htpasswd credentials file if it exists. A missing file
// is not an error and yields a nil map so the caller can fall back to no
// authentication. A present file is parsed strictly: a malformed line, a
// non-bcrypt hash, a duplicate username, or a file with no credentials is an
// error, so a misconfigured mount cannot silently start the server without
// authentication.
func loadHtpasswd() (map[string]string, error) {
	path := os.Getenv("PROXY_CONFIG_FILE")
	if path == "" {
		path = defaultConfigFile
	}

	// #nosec G304 G703 -- the path is operator-provided configuration, not user input.
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
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
func parseHtpasswd(data []byte) (map[string]string, error) {
	creds := map[string]string{}
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
