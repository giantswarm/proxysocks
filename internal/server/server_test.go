package server

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
	"golang.org/x/crypto/bcrypt"
)

// bcryptEntry builds an htpasswd line with a bcrypt hash, as produced by
// `htpasswd -B`.
func bcryptEntry(t *testing.T, username, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate hash: %s", err)
	}
	return username + ":" + string(hash)
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
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("target port: %s", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01} // CONNECT, IPv4
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port))
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
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen proxy: %s", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, socks5.NewServer(), ln) }()

		client := socksConnect(t, ln.Addr().String(), echo.Addr().String())
		defer client.Close() // nolint: errcheck
		echoRoundTrip(t, client, "hello")

		cancel()

		// New connections must be refused once the listener is closed.
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.Dial("tcp", ln.Addr().String())
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
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen proxy: %s", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, socks5.NewServer(), ln) }()
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
