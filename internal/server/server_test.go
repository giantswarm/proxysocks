package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/things-go/go-socks5"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %s", err)
	}
	return path
}

func TestAuthenticatorFromConfig(t *testing.T) {
	t.Run("users from config file", func(t *testing.T) {
		path := writeConfig(t, "users:\n  - username: alice\n    password: s3cr3t\n  - username: bob\n    password: hunter2\n")
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
		path := writeConfig(t, "users:\n  - username: alice\n    password: a\n  - username: alice\n    password: b\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for duplicate username")
		}
	})

	t.Run("empty password rejected", func(t *testing.T) {
		path := writeConfig(t, "users:\n  - username: alice\n    password: \"\"\n")
		t.Setenv("PROXY_CONFIG_FILE", path)

		if _, err := authenticatorFromConfig(); err == nil {
			t.Fatalf("expected error for empty password")
		}
	})

	t.Run("legacy env fallback", func(t *testing.T) {
		t.Setenv("PROXY_CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
		t.Setenv("PROXY_USERNAME", "legacy")
		t.Setenv("PROXY_PASSWORD", "pass")

		auth, err := authenticatorFromConfig()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		upa, ok := auth.(socks5.UserPassAuthenticator)
		if !ok {
			t.Fatalf("expected UserPassAuthenticator, got %T", auth)
		}
		if !upa.Credentials.Valid("legacy", "pass", "") {
			t.Fatalf("expected legacy user to validate")
		}
	})

	t.Run("no auth when nothing configured", func(t *testing.T) {
		t.Setenv("PROXY_CONFIG_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
		os.Unsetenv("PROXY_USERNAME")
		os.Unsetenv("PROXY_PASSWORD")

		auth, err := authenticatorFromConfig()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if _, ok := auth.(socks5.NoAuthAuthenticator); !ok {
			t.Fatalf("expected NoAuthAuthenticator, got %T", auth)
		}
	})
}
