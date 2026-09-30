package mcphost

import (
	"strings"
	"testing"
)

func TestMaskSecretsAssignments(t *testing.T) {
	cases := []struct{ in, want string }{
		{`api_key=sk-abcdef1234567890`, `api_key=[REDACTED]`},
		{`API_KEY: "hunter2-value"`, `API_KEY: [REDACTED]`},
		{`password='s3cr3t!'`, `password=[REDACTED]`},
		{`"token": "abc123xyz"`, `"token": [REDACTED]`},
		{`client_secret=shhh`, `client_secret=[REDACTED]`},
	}
	for _, c := range cases {
		got := MaskSecrets(c.in)
		if got != c.want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.ContainsAny(got, "hunter2sk-abcdef") && strings.Contains(got, "sk-abcdef") {
			t.Errorf("secret leaked through: %q", got)
		}
	}
}

func TestMaskSecretsTokenPrefixes(t *testing.T) {
	ins := []string{
		"deploy with ghp_abcDEF1234567890 now",
		"slack xoxb-1234-abcdef token here",
		"openai sk-abcdefghijklmnopqrstuvwx",
		"aws AKIAIOSFODNN7EXAMPLE key",
		"google AIzaSyAbcDefGhIjKlMnOpQrStUvWx",
	}
	for _, in := range ins {
		got := MaskSecrets(in)
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("MaskSecrets(%q) = %q, want redaction", in, got)
		}
	}
}

func TestMaskSecretsBearerAndPEM(t *testing.T) {
	got := MaskSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
	if !strings.Contains(got, "Bearer [REDACTED]") {
		t.Errorf("bearer not masked: %q", got)
	}
	pem := "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAAJ\n-----END RSA PRIVATE KEY-----\ndone"
	got = MaskSecrets(pem)
	if strings.Contains(got, "MIIBPAIBAAJ") {
		t.Errorf("PEM body leaked: %q", got)
	}
}

func TestMaskSecretsLeavesOrdinaryText(t *testing.T) {
	in := "the api keyring is in the drawer, token effort was great"
	if got := MaskSecrets(in); got != in {
		t.Errorf("ordinary text changed: %q", got)
	}
}

func TestMaskFields(t *testing.T) {
	fields := map[string]any{
		"summary":   "called with api_key=sk-abcdef1234567890",
		"api_key":   "sk-abcdef1234567890",
		"exit_code": 0,
		"nested":    map[string]any{"password": "hunter2", "ok": true},
		"list":      []any{"ghp_abcDEF1234567890", "plain"},
	}
	out := maskFields(fields)
	if out["api_key"] != "[REDACTED]" {
		t.Errorf("secret key not fully redacted: %v", out["api_key"])
	}
	if s := out["summary"].(string); !strings.Contains(s, "[REDACTED]") || strings.Contains(s, "sk-abcdef") {
		t.Errorf("summary not masked: %v", s)
	}
	if n := out["nested"].(map[string]any); n["password"] != "[REDACTED]" {
		t.Errorf("nested password not redacted: %v", n)
	}
	if l := out["list"].([]any); l[0] != "[REDACTED]" || l[1] != "plain" {
		t.Errorf("list masking wrong: %v", l)
	}
	if out["exit_code"] != 0 {
		t.Errorf("non-string changed: %v", out["exit_code"])
	}
	if maskFields(nil) != nil {
		t.Errorf("nil fields should stay nil")
	}
}
