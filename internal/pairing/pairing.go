// Package pairing implements backseat's trust bootstrap: a one-time invite
// URL carrying a secret in its fragment, followed by a two-phase
// HMAC-SHA256 enrollment that derives per-direction session keys with
// HKDF-SHA256. The relay never sees the secret or the derived keys.
package pairing

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// SecretLen is the invite secret size in bytes.
const SecretLen = 32

// InviteTTL is how long an invite link stays valid.
const InviteTTL = 10 * time.Minute

// Info string domain-separates derived keys from any other use of HKDF.
const deriveInfo = "backseat-v1-pairing"

// GenerateSecret returns a fresh random 32-byte invite secret.
func GenerateSecret() ([SecretLen]byte, error) {
	var s [SecretLen]byte
	if _, err := io.ReadFull(rand.Reader, s[:]); err != nil {
		return s, fmt.Errorf("pairing: rand: %w", err)
	}
	return s, nil
}

// InviteURL builds the one-time link the novice sends to the expert.
// The session id is a plain query param; the secret lives only in the URL
// fragment so it never reaches any server in an HTTP request.
func InviteURL(base, sessionID string, secret [SecretLen]byte) string {
	enc := base64.RawURLEncoding.EncodeToString(secret[:])
	base = strings.TrimRight(base, "/")
	return fmt.Sprintf("%s/?session=%s#secret=%s", base, sessionID, enc)
}

// ParseSecret extracts the invite secret from a URL fragment of the form
// "secret=<base64url>".
func ParseSecret(fragment string) ([SecretLen]byte, error) {
	var s [SecretLen]byte
	fragment = strings.TrimPrefix(fragment, "#")
	for _, part := range strings.Split(fragment, "&") {
		k, v, ok := strings.Cut(part, "=")
		if ok && k == "secret" {
			raw, err := base64.RawURLEncoding.DecodeString(v)
			if err != nil {
				return s, fmt.Errorf("pairing: bad secret encoding: %w", err)
			}
			if len(raw) != SecretLen {
				return s, fmt.Errorf("pairing: secret must be %d bytes", SecretLen)
			}
			copy(s[:], raw)
			return s, nil
		}
	}
	return s, errors.New("pairing: no secret in fragment")
}

// Verifier returns hex(SHA-256(secret)). The host puts it in the session
// announcement so the relay can gate room joins without ever seeing the
// secret itself.
func Verifier(secret [SecretLen]byte) string {
	sum := sha256.Sum256(secret[:])
	return hex.EncodeToString(sum[:])
}

// CheckSecret compares a presented base64url secret against a verifier in
// constant time. Used by the relay to gate room joins.
func CheckSecret(presentedB64URL, verifier string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(presentedB64URL)
	if err != nil || len(raw) != SecretLen {
		return false
	}
	var s [SecretLen]byte
	copy(s[:], raw)
	a, b := Verifier(s), verifier
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewChallenge returns a fresh random challenge for enrollment phase 1.
func NewChallenge() ([SecretLen]byte, error) {
	return GenerateSecret()
}

// EnrollmentResponse computes HMAC-SHA256(secret, challenge): the phase 2
// answer proving the expert holds the invite secret without revealing it.
func EnrollmentResponse(secret, challenge [SecretLen]byte) [SecretLen]byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(challenge[:])
	var out [SecretLen]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// VerifyEnrollment checks a phase 2 response in constant time.
func VerifyEnrollment(secret, challenge, response [SecretLen]byte) bool {
	want := EnrollmentResponse(secret, challenge)
	return subtle.ConstantTimeCompare(want[:], response[:]) == 1
}

// Keys holds the derived per-direction session keys.
type Keys struct {
	// HostToExpert encrypts traffic from the novice's host to the expert.
	HostToExpert [SecretLen]byte
	// ExpertToHost encrypts traffic from the expert back to the host.
	ExpertToHost [SecretLen]byte
}

// DeriveKeys runs HKDF-SHA256 over the invite secret (salted with the
// enrollment challenge) and splits the output into two directional keys.
// Both sides run this locally after a successful enrollment; the keys
// never travel the wire.
func DeriveKeys(secret, challenge [SecretLen]byte) (Keys, error) {
	var k Keys
	r := hkdf.New(sha256.New, secret[:], challenge[:], []byte(deriveInfo))
	out := make([]byte, 2*SecretLen)
	if _, err := io.ReadFull(r, out); err != nil {
		return k, fmt.Errorf("pairing: hkdf: %w", err)
	}
	copy(k.HostToExpert[:], out[:SecretLen])
	copy(k.ExpertToHost[:], out[SecretLen:])
	return k, nil
}
