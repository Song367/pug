package sessiongateway

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfigFailsClosed(t *testing.T) {
	valid := config{
		Environment:       "test",
		Addr:              ":8443",
		PublicOrigin:      "https://dashboard.example.test",
		APIUpstreamURL:    "http://server:3000",
		StaticUpstreamURL: "http://dashboard:8080",
		TLSCertFile:       "/run/tls/tls.crt",
		TLSKeyFile:        "/run/tls/tls.key",
		RedisURL:          "redis://redis:6379",
		EncryptionKeyHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
	}
	if _, err := valid.validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*config){
		"non-HTTPS public origin": func(c *config) { c.PublicOrigin = "http://dashboard.example.test" },
		"origin path":             func(c *config) { c.PublicOrigin += "/login" },
		"upstream credentials":    func(c *config) { c.APIUpstreamURL = "http://user:pass@server:3000" },
		"short key":               func(c *config) { c.EncryptionKeyHex = "abcd" },
		"repeated key":            func(c *config) { c.EncryptionKeyHex = strings.Repeat("aa", encryptionKeyBytes) },
		"unknown environment":     func(c *config) { c.Environment = "staging" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := candidate.validate(); err == nil {
				t.Fatal("validate unexpectedly succeeded")
			}
		})
	}
}

func TestSessionPayloadEncryptionBindsCiphertextToSessionID(t *testing.T) {
	key := bytes.Repeat([]byte{1}, encryptionKeyBytes)
	key[0] = 2
	store, err := newRedisSessionStore(nil, key)
	if err != nil {
		t.Fatal(err)
	}
	record := sessionRecord{AccessToken: "access-secret", RefreshToken: "refresh-secret", CustomerID: "cust-1"}
	payload, err := store.seal("session-a", record)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("access-secret")) || bytes.Contains(payload, []byte("refresh-secret")) {
		t.Fatal("encrypted Redis payload contains plaintext credentials")
	}
	decoded, err := store.open("session-a", payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.AccessToken != record.AccessToken || decoded.RefreshToken != record.RefreshToken {
		t.Fatal("session payload did not round-trip")
	}
	if _, err := store.open("session-b", payload); err == nil {
		t.Fatal("ciphertext opened under a different session identifier")
	}
	payload[len(payload)-1] ^= 1
	if _, err := store.open("session-a", payload); err == nil {
		t.Fatal("tampered ciphertext opened successfully")
	}
}
