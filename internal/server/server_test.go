package server

import (
	"os"
	"path/filepath"
	"testing"

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
