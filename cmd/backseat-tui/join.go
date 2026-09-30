// Join target resolution for `backseat-tui join <code>`.
//
// The novice's session link looks like the browser invite link:
//
//	https://expert-page.example/?session=<session-id>#secret=<base64url>
//
// and the short code the MCP tool prints is the compact form:
//
//	<session-id>#<secret>
//
// Both mirror the same invite-secret scheme as the browser flow: the
// secret travels only in the URL fragment / after the '#', never as a
// query param or in the relay handshake. The relay address comes from
// --relay-ws; a code given as a full ws(s):// URL overrides it.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
)

// joinTarget is everything the client needs to attach to a session.
type joinTarget struct {
	relayURL  string
	sessionID string
	secret    [pairing.SecretLen]byte
}

// parseJoinArg resolves the `join` argument into a joinTarget.
// Accepted forms:
//   - full invite link: https://host/?session=<id>#secret=<b64> (or /join/<id>)
//   - relay URL with session+secret: wss://host/ws?session=<id>#secret=<b64>
//   - short code: <session-id>#<secret>
//   - bare session id (secret must come from --secret or an interactive prompt)
func parseJoinArg(arg, defaultRelay string) (joinTarget, error) {
	var t joinTarget
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return t, errors.New("empty join code")
	}
	t.relayURL = defaultRelay

	if strings.Contains(arg, "://") {
		u, err := url.Parse(arg)
		if err != nil {
			return t, fmt.Errorf("bad join URL: %w", err)
		}
		secret, err := secretFromFragment(u.Fragment)
		if err != nil {
			return t, err
		}
		t.secret = secret
		sid := u.Query().Get("session")
		if sid == "" {
			if parts := strings.Split(strings.Trim(u.Path, "/"), "/"); len(parts) == 2 && parts[0] == "join" {
				sid = parts[1]
			}
		}
		if sid == "" {
			return t, errors.New("join URL has no session id (?session= or /join/<id>)")
		}
		t.sessionID = sid
		if u.Scheme == "ws" || u.Scheme == "wss" {
			u.Fragment = ""
			t.relayURL = u.String()
		} else if u.Scheme != "http" && u.Scheme != "https" {
			return t, fmt.Errorf("unsupported join URL scheme %q", u.Scheme)
		}
		return t, nil
	}

	if i := strings.Index(arg, "#"); i >= 0 {
		sid, frag := arg[:i], arg[i+1:]
		if sid == "" {
			return t, errors.New("short code has no session id before '#'")
		}
		secret, err := secretFromFragment(frag)
		if err != nil {
			return t, err
		}
		t.sessionID, t.secret = sid, secret
		return t, nil
	}

	// Bare session id; the caller fills in the secret afterwards.
	t.sessionID = arg
	return t, errNeedSecret
}

// errNeedSecret signals that parseJoinArg accepted the session id but the
// invite secret still has to come from --secret or an interactive prompt.
var errNeedSecret = errors.New("no secret in code: pass --secret or paste it at the prompt")

// secretFromFragment decodes the invite secret from a URL fragment of the
// form "secret=<base64url>" or a bare base64url secret.
func secretFromFragment(frag string) ([pairing.SecretLen]byte, error) {
	var zero [pairing.SecretLen]byte
	frag = strings.TrimPrefix(frag, "#")
	if strings.HasPrefix(frag, "secret=") {
		s, err := pairing.ParseSecret(frag)
		if err != nil {
			return zero, err
		}
		return s, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(frag))
	if err != nil {
		return zero, fmt.Errorf("bad secret encoding: %w", err)
	}
	if len(raw) != pairing.SecretLen {
		return zero, fmt.Errorf("secret must be %d bytes, got %d", pairing.SecretLen, len(raw))
	}
	var s [pairing.SecretLen]byte
	copy(s[:], raw)
	return s, nil
}

// hasSecret reports whether t already carries the invite secret. A bare
// session id parses to a zero secret; callers treat that as "ask the user".
func (t joinTarget) hasSecret() bool {
	return t.secret != [pairing.SecretLen]byte{}
}
