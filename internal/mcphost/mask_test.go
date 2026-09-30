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

func TestMaskSecretsNewTokenShapes(t *testing.T) {
	ins := []string{
		"stripe key sk_live_abcDEF1234567890wxyz",
		"restricted rk_live_abcDEF1234567890wxyz",
		"openai sk-proj-abcDEF1234567890wxyz-0987",
		"gitlab glpat-abcdefghijklmnopqrst",
		"npm npm_abcdefghijklmnopqrstuvwx",
		"aws ASIAIOSFODNN7EXAMPLE key id",
	}
	for _, in := range ins {
		got := MaskSecrets(in)
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("MaskSecrets(%q) = %q, want redaction", in, got)
		}
	}
}

func TestMaskSecretsURLCredentials(t *testing.T) {
	in := "postgres://deploy:s3cr3t-pw@db.internal:5432/app"
	got := MaskSecrets(in)
	if strings.Contains(got, "s3cr3t-pw") || strings.Contains(got, "deploy:") {
		t.Errorf("url credentials leaked: %q", got)
	}
	if !strings.Contains(got, "db.internal") || !strings.Contains(got, "[REDACTED]@") {
		t.Errorf("url mangled: %q", got)
	}
}

func TestMaskSecretsQuotedValueWithSpaces(t *testing.T) {
	cases := []struct{ in, want string }{
		{`password="my secret phrase"`, `password=[REDACTED]`},
		{`api_key: 'hunter2 hunter3'`, `api_key: [REDACTED]`},
		{`"token": "abc 123 xyz"`, `"token": [REDACTED]`},
	}
	for _, c := range cases {
		if got := MaskSecrets(c.in); got != c.want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMaskSecretFieldsStructural(t *testing.T) {
	in := map[string]any{
		"token":  "ghp_abcDEF1234567890",
		"nested": map[string]any{"password": "hunter2"},
		"ok":     true,
		"count":  3,
	}
	out := MaskSecretFields(in)
	if out["token"] != "[REDACTED]" {
		t.Errorf("token = %v", out["token"])
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["password"] != "[REDACTED]" {
		t.Errorf("nested = %v", out["nested"])
	}
	if out["ok"] != true || out["count"] != 3 {
		t.Errorf("non-secrets changed: %v", out)
	}
}
