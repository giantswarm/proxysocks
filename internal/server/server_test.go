package server

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/things-go/go-socks5"
)

// shaEntry builds an htpasswd line using the {SHA} scheme, which go-htpasswd
// recognizes via its DefaultSystems parsers.
func shaEntry(username, password string) string {
	sum := sha1.Sum([]byte(password))
	return fmt.Sprintf("%s:{SHA}%s", username, base64.StdEncoding.EncodeToString(sum[:]))
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
		path := writeConfig(t, shaEntry("alice", "s3cr3t")+"\n"+shaEntry("bob", "hunter2")+"\n")
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
		path := writeConfig(t, shaEntry("alice", "a")+"\n"+shaEntry("alice", "b")+"\n")
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
