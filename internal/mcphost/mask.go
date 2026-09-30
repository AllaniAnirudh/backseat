// Package mcphost: secret masking for the expert-facing publish path.
//
// The novice's agent publishes transcript events that an expert watches.
// Agents constantly handle credentials, so before anything reaches the
// expert the text (and string metadata) goes through MaskSecrets, which
// redacts common secret shapes: assignment-style key=value pairs, known
// token prefixes (GitHub, Slack, OpenAI, AWS, Google), Bearer tokens, and
// PEM private key blocks. Masking is best-effort, not a guarantee: the
// skill warns the novice that a viewer sees everything the agent
// publishes.
package mcphost

import "regexp"

// [REDACTED] replaces any detected secret value.
const redacted = "[REDACTED]"

// assignRe matches assignment-style secrets: api_key=..., "token": "...",
// password='...'. The value is redacted, the key name is kept so the
// expert still sees which field was involved.
var assignRe = regexp.MustCompile(`(?i)(["']?)(api[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|secret|token|password|passwd|pwd)(["']?)(\s*[:=]\s*)(["']?)[^\s"';,}]+(["']?)`)

// tokenRe matches known token prefixes.
var tokenRe = regexp.MustCompile(`\b(ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|xox[baprs]-[A-Za-z0-9-]+|sk-ant-[A-Za-z0-9-]+|sk-[A-Za-z0-9]{16,}|AIza[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b`)

// bearerRe matches Authorization: Bearer <token> shapes.
var bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/-]+`)

// pemRe matches PEM private key blocks, including newlines.
var pemRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^-]*-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// secretKeyRe marks metadata keys whose string value is always redacted.
var secretKeyRe = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|passwd|pwd|credential|private[_-]?key)`)

// MaskSecrets redacts common secret patterns in s.
func MaskSecrets(s string) string {
	s = pemRe.ReplaceAllString(s, redacted+" PRIVATE KEY "+redacted)
	s = assignRe.ReplaceAllString(s, `${1}${2}${3}${4}`+redacted)
	s = bearerRe.ReplaceAllString(s, `${1}`+redacted)
	s = tokenRe.ReplaceAllString(s, redacted)
	return s
}

// maskFields redacts secrets inside a metadata map: string values under
// secret-looking keys are fully redacted, other strings go through
// MaskSecrets, and nested maps/slices are handled recursively.
func maskFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = maskValue(k, v)
	}
	return out
}

func maskValue(key string, v any) any {
	switch t := v.(type) {
	case string:
		if secretKeyRe.MatchString(key) {
			return redacted
		}
		return MaskSecrets(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v2 := range t {
			out[k] = maskValue(k, v2)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, v2 := range t {
			out[i] = maskValue("", v2)
		}
		return out
	default:
		return v
	}
}
