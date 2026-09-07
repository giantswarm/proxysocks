package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"golang.org/x/crypto/bcrypt"
)

// bcryptEntry builds an htpasswd line with a bcrypt hash, as produced by
// `htpasswd -B`.
func bcryptEntry(t *testing.T, username, password string) string {
	t.Helper()
	return username + ":" + mustHash(t, password, bcrypt.MinCost)
}

// mustHash returns a bcrypt hash of password at the given cost, failing the
// test on error.
func mustHash(t *testing.T, password string, cost int) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatalf("generate hash: %s", err)
	}
	return string(hash)
}

// mustCredentials builds a credential store from username to bcrypt hash
// pairs, failing the test on error.
func mustCredentials(t *testing.T, hashes map[string]string) bcryptCredentials {
	t.Helper()
	creds, err := newBcryptCredentials(hashes)
	if err != nil {
		t.Fatalf("build credentials: %s", err)
	}
	return creds
}

// noAuthServer builds the real server via New with authentication disabled, so
// the middleware wiring is exercised end to end.
func noAuthServer(t *testing.T) *socks5.Server {
	t.Helper()
	t.Setenv("PROXY_CONFIG_FILE", filepath.Join(t.TempDir(), "missing"))
	srv, err := New()
	if err != nil {
		t.Fatalf("new server: %s", err)
	}
	return srv
}

// serve runs Serve on a fresh listener and returns the address plus a channel
// carrying its return value.
func serve(t *testing.T, ctx context.Context, srv *socks5.Server, timeouts Timeouts) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %s", err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, srv, ln, timeouts) }()
	return ln.Addr().String(), done
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "htpasswd")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %s", err)
	}
	return path
}

// echoListener starts a TCP server that echoes everything back, for use as a
// SOCKS5 CONNECT target.
func echoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %s", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}()
		}
	}()
	return ln
}

// socksConnect dials the proxy and performs a no-auth SOCKS5 handshake plus a
// CONNECT to target, returning the tunneled connection.
func socksConnect(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("dial proxy: %s", err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: version 5, one method, no-auth.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %s", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read method selection: %s", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("unexpected method selection: %v", reply)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split target: %s", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("target port: %s", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01} // CONNECT, IPv4
	req = append(req, net.ParseIP(host).To4()...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect request: %s", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read connect reply: %s", err)
	}
	if head[1] != 0x00 {
		t.Fatalf("connect failed, reply code %d", head[1])
	}
	// Consume the bound address: 4 (IPv4) or 16 (IPv6) bytes plus 2 port bytes.
	addrLen := 4
	if head[3] == 0x04 {
		addrLen = 16
	}
	if _, err := io.ReadFull(conn, make([]byte, addrLen+2)); err != nil {
		t.Fatalf("read bound address: %s", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

// echoRoundTrip sends msg through the tunnel and expects it echoed back.
func echoRoundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write through tunnel: %s", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through tunnel: %s", err)
	}
	if string(buf) != msg {
		t.Fatalf("expected %q echoed back, got %q", msg, buf)
	}
	_ = conn.SetDeadline(time.Time{})
}

func TestServe(t *testing.T) {
	t.Run("drains in-flight connections", func(t *testing.T) {
		echo := echoListener(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, done := serve(t, ctx, socks5.NewServer(), DefaultTimeouts())

		client := socksConnect(t, addr, echo.Addr().String())
		defer client.Close() // nolint: errcheck
		echoRoundTrip(t, client, "hello")

		cancel()

		// New connections must be refused once the listener is closed.
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				break
			}
			_ = conn.Close()
			if time.Now().After(deadline) {
				t.Fatalf("listener still accepting after cancel")
			}
			time.Sleep(10 * time.Millisecond)
		}

		// The in-flight tunnel keeps working while draining.
		echoRoundTrip(t, client, "still alive")

		select {
		case err := <-done:
			t.Fatalf("Serve returned before the connection finished: %v", err)
		default:
		}

		_ = client.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve returned error: %s", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Serve did not return after draining")
		}
	})

	t.Run("returns promptly when idle", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		_, done := serve(t, ctx, socks5.NewServer(), DefaultTimeouts())
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve returned error: %s", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Serve did not return after cancel")
		}
	})

	t.Run("closes a client that never sends the greeting", func(t *testing.T) {
		timeouts := Timeouts{Handshake: 100 * time.Millisecond, Drain: 25 * time.Second}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, _ := serve(t, ctx, socks5.NewServer(), timeouts)

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial proxy: %s", err)
		}
		defer conn.Close() // nolint: errcheck

		// Send nothing at all. The read must end once the handshake deadline
		// passes rather than hanging on to the connection.
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatalf("expected the proxy to close a silent client")
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("proxy kept a silent client open past the handshake timeout")
		}
	})

	t.Run("closes a client that stalls mid-handshake", func(t *testing.T) {
		timeouts := Timeouts{Handshake: 100 * time.Millisecond, Drain: 25 * time.Second}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, _ := serve(t, ctx, socks5.NewServer(), timeouts)

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial proxy: %s", err)
		}
		defer conn.Close() // nolint: errcheck

		// Greet, then stall before sending the request.
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %s", err)
		}
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			t.Fatalf("read method selection: %s", err)
		}

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatalf("expected the proxy to close a stalled client")
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("proxy kept a stalled client open past the handshake timeout")
		}
	})

	t.Run("keeps an idle tunnel open past the handshake timeout", func(t *testing.T) {
		// The handshake deadline must be lifted once the request is accepted,
		// or a tunnel that sits idle would be torn down mid-session.
		timeouts := Timeouts{Handshake: 200 * time.Millisecond, Drain: 25 * time.Second}
		echo := echoListener(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, _ := serve(t, ctx, noAuthServer(t), timeouts)

		client := socksConnect(t, addr, echo.Addr().String())
		defer client.Close() // nolint: errcheck

		time.Sleep(500 * time.Millisecond)
		echoRoundTrip(t, client, "still alive")
	})

	t.Run("stops draining after the drain timeout", func(t *testing.T) {
		timeouts := Timeouts{Handshake: 10 * time.Second, Drain: 200 * time.Millisecond}
		echo := echoListener(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		addr, done := serve(t, ctx, noAuthServer(t), timeouts)

		client := socksConnect(t, addr, echo.Addr().String())
		defer client.Close() // nolint: errcheck
		echoRoundTrip(t, client, "hello")

		// The tunnel stays open, so without a bounded drain Serve would never
		// return.
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve returned error: %s", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Serve did not return after the drain timeout")
		}
	})
}

func TestValid(t *testing.T) {
	creds := mustCredentials(t, map[string]string{"alice": mustHash(t, "s3cr3t", bcrypt.MinCost)})

	t.Run("correct credentials succeed without counting a failure", func(t *testing.T) {
		before := testutil.ToFloat64(authFailureMetric)
		if !creds.Valid("alice", "s3cr3t", "") {
			t.Fatalf("expected valid credentials to pass")
		}
		if got := testutil.ToFloat64(authFailureMetric) - before; got != 0 {
			t.Fatalf("expected no auth failures, got %v", got)
		}
	})

	t.Run("wrong password counts a failure", func(t *testing.T) {
		before := testutil.ToFloat64(authFailureMetric)
		if creds.Valid("alice", "wrong", "") {
			t.Fatalf("expected wrong password to fail")
		}
		if got := testutil.ToFloat64(authFailureMetric) - before; got != 1 {
			t.Fatalf("expected one auth failure, got %v", got)
		}
	})

	t.Run("unknown user counts a failure", func(t *testing.T) {
		before := testutil.ToFloat64(authFailureMetric)
		if creds.Valid("mallory", "whatever", "") {
			t.Fatalf("expected unknown user to fail")
		}
		if got := testutil.ToFloat64(authFailureMetric) - before; got != 1 {
			t.Fatalf("expected one auth failure, got %v", got)
		}
	})

	t.Run("unknown user fails whatever the password", func(t *testing.T) {
		// The dummy hash is compared for unknown users to equalize timing; it
		// must never authenticate anyone.
		for _, password := range []string{"", "s3cr3t", string(creds.dummyHash)} {
			if creds.Valid("mallory", password, "") {
				t.Fatalf("expected unknown user to fail with password %q", password)
			}
		}
	})
}

func TestNewBcryptCredentials(t *testing.T) {
	t.Run("dummy hash matches the cheapest cost in the file", func(t *testing.T) {
		// The unknown-user path must cost the same as the fastest known user,
		// otherwise the response time reveals whether a username exists.
		// `htpasswd -B` defaults to cost 5, so a hardcoded cost would not do.
		creds := mustCredentials(t, map[string]string{
			"expensive": mustHash(t, "s3cr3t", 6),
			"cheap":     mustHash(t, "hunter2", 4),
		})

		cost, err := bcrypt.Cost(creds.dummyHash)
		if err != nil {
			t.Fatalf("dummy hash is not a bcrypt hash: %s", err)
		}
		if cost != 4 {
			t.Fatalf("expected dummy hash at cost 4, got %d", cost)
		}
	})

	t.Run("dummy hash differs across stores", func(t *testing.T) {
		hashes := map[string]string{"user": mustHash(t, "s3cr3t", bcrypt.MinCost)}
		first := mustCredentials(t, hashes)
		second := mustCredentials(t, hashes)

		if string(first.dummyHash) == string(second.dummyHash) {
			t.Fatalf("expected a freshly generated dummy hash per store")
		}
	})

	t.Run("no credentials rejected", func(t *testing.T) {
		if _, err := newBcryptCredentials(map[string]string{}); err == nil {
			t.Fatalf("expected error for an empty credential map")
		}
	})

	t.Run("non-bcrypt hash rejected", func(t *testing.T) {
		hashes := map[string]string{"user": "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="}
		if _, err := newBcryptCredentials(hashes); err == nil {
			t.Fatalf("expected error for a non-bcrypt hash")
		}
	})
}

func TestUserConnect(t *testing.T) {
	req := func(user string) *socks5.Request {
		r := &socks5.Request{
			RemoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
			DestAddr:   &statute.AddrSpec{IP: net.IPv4(10, 0, 0, 1), Port: 80},
		}
		if user != "" {
			r.AuthContext = &socks5.AuthContext{Payload: map[string]string{"username": user}}
		}
		return r
	}

	t.Run("counts against the authenticated user", func(t *testing.T) {
		before := testutil.ToFloat64(userConnectMetric.WithLabelValues("alice"))
		if err := UserConnect(context.Background(), io.Discard, req("alice")); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got := testutil.ToFloat64(userConnectMetric.WithLabelValues("alice")) - before; got != 1 {
			t.Fatalf("expected one connection for alice, got %v", got)
		}
	})

	t.Run("falls back to anonymous without auth context", func(t *testing.T) {
		before := testutil.ToFloat64(userConnectMetric.WithLabelValues("anonymous"))
		if err := UserConnect(context.Background(), io.Discard, req("")); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if got := testutil.ToFloat64(userConnectMetric.WithLabelValues("anonymous")) - before; got != 1 {
			t.Fatalf("expected one anonymous connection, got %v", got)
		}
	})
}

func TestAuthenticatorFromConfig(t *testing.T) {
	t.Run("users from config file", func(t *testing.T) {
		path := writeConfig(t, bcryptEntry(t, "alice", "s3cr3t")+"\n"+bcryptEntry(t, "bob", "hunter2")+"\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		auth, err := authenticatorFromConfig()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		upa, ok := auth.(socks5.UserPassAuthenticator)
		if !ok {
			t.Fatalf("expected UserPassAuthenticator, got %T", auth)
		}
		if !upa.Credentials.Valid("alice", "s3cr3t", "") || !upa.Credentials.Valid("bob", "hunter2", "") {
			t.Fatalf("expected both users to validate")
		}
		if upa.Credentials.Valid("alice", "wrong", "") {
			t.Fatalf("expected wrong password to fail")
		}
	})

	t.Run("duplicate username rejected", func(t *testing.T) {
		path := writeConfig(t, bcryptEntry(t, "alice", "a")+"\n"+bcryptEntry(t, "alice", "b")+"\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for duplicate username")
		}
	})

	t.Run("malformed line rejected", func(t *testing.T) {
		path := writeConfig(t, "this-line-has-no-colon\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for malformed line")
		}
	})

	t.Run("non-bcrypt hash rejected", func(t *testing.T) {
		path := writeConfig(t, "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for non-bcrypt hash")
		}
	})

	t.Run("empty file rejected", func(t *testing.T) {
		path := writeConfig(t, "\n  \n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for config file with no credentials")
		}
	})

	t.Run("no auth when no config file present", func(t *testing.T) {
		t.Setenv("PROXY_CONFIG_FILE", filepath.Join(t.TempDir(), "missing"))

		auth, err := authenticatorFromConfig()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if _, ok := auth.(socks5.NoAuthAuthenticator); !ok {
			t.Fatalf("expected NoAuthAuthenticator, got %T", auth)
		}
	})
}
