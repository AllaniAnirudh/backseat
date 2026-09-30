package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
)

func mustSecret(t *testing.T) string {
	t.Helper()
	s, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	return "secret=" + base64.RawURLEncoding.EncodeToString(s[:])
}

func TestParseJoinFullLink(t *testing.T) {
	frag := mustSecret(t)
	jt, err := parseJoinArg("https://expert.example/join/sess-1#"+frag, "ws://localhost:8080/ws")
	if err != nil {
		t.Fatal(err)
	}
	if jt.sessionID != "sess-1" {
		t.Fatalf("session id = %q", jt.sessionID)
	}
	if jt.relayURL != "ws://localhost:8080/ws" {
		t.Fatalf("relay = %q", jt.relayURL)
	}
	if !jt.hasSecret() {
		t.Fatal("secret not parsed")
	}
}

func TestParseJoinQueryParam(t *testing.T) {
	frag := mustSecret(t)
	jt, err := parseJoinArg("https://expert.example/?session=abc123#"+frag, "ws://r/ws")
	if err != nil {
		t.Fatal(err)
	}
	if jt.sessionID != "abc123" || !jt.hasSecret() {
		t.Fatalf("got %+v", jt)
	}
}

func TestParseJoinShortCode(t *testing.T) {
	// Short code mirrors the fragment scheme: <session>#<secret>.
	s, _ := pairing.GenerateSecret()
	code := "sess-9#" + base64.RawURLEncoding.EncodeToString(s[:])
	jt, err := parseJoinArg(code, "ws://r/ws")
	if err != nil {
		t.Fatal(err)
	}
	if jt.sessionID != "sess-9" || jt.secret != s {
		t.Fatalf("got %+v", jt)
	}
}

func TestParseJoinRelayURL(t *testing.T) {
	frag := mustSecret(t)
	jt, err := parseJoinArg("wss://relay.example:8443/ws?session=s1#"+frag, "ws://ignored/ws")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(jt.relayURL, "wss://relay.example:8443/ws") {
		t.Fatalf("relay = %q", jt.relayURL)
	}
	if strings.Contains(jt.relayURL, "#") {
		t.Fatalf("relay URL must not carry the fragment: %q", jt.relayURL)
	}
}

func TestParseJoinBareSession(t *testing.T) {
	_, err := parseJoinArg("just-a-session", "ws://r/ws")
	if err != errNeedSecret {
		t.Fatalf("expected errNeedSecret, got %v", err)
	}
}

func TestParseJoinBadSecret(t *testing.T) {
	if _, err := parseJoinArg("s1#not-valid!!!", "ws://r/ws"); err == nil {
		t.Fatal("expected error for bad secret")
	}
	if _, err := parseJoinArg("https://h/?session=s1", "ws://r/ws"); err == nil {
		t.Fatal("expected error for missing secret")
	}
	if _, err := parseJoinArg("ftp://h/s#secret=abc", "ws://r/ws"); err == nil {
		t.Fatal("expected error for bad scheme")
	}
}
