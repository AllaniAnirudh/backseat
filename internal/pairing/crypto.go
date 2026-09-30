package pairing

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Wire envelope for an AES-256-GCM encrypted payload:
//
//	{"v":1,"alg":"AES-256-GCM","nonce":b64,"ct":b64}
//
// ct is ciphertext || 16-byte tag, which matches both Go's gcm.Seal output
// and WebCrypto's subtle.encrypt output, so envelopes cross the Go/JS
// boundary byte for byte.
type Envelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	Nonce string `json:"nonce"` // base64, 12 bytes
	CT    string `json:"ct"`    // base64, ciphertext || tag
}

// Envelope parameters pinned on the wire.
const (
	EnvelopeVersion = 1
	EnvelopeAlg     = "AES-256-GCM"
	nonceLen        = 12
)

func gcmFor(key [SecretLen]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("pairing: cipher: %w", err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pairing: gcm: %w", err)
	}
	return g, nil
}

// Seal encrypts plaintext with key and returns the JSON envelope.
func Seal(key [SecretLen]byte, plaintext []byte) ([]byte, error) {
	g, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	var nonce [nonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("pairing: nonce: %w", err)
	}
	ct := g.Seal(nil, nonce[:], plaintext, nil)
	env := Envelope{
		V:     EnvelopeVersion,
		Alg:   EnvelopeAlg,
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]),
		CT:    base64.StdEncoding.EncodeToString(ct),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("pairing: envelope: %w", err)
	}
	return out, nil
}

// Open parses an envelope and decrypts it with key. Any failure — bad
// envelope, wrong key, tampered bytes — returns an error and the message
// must be dropped.
func Open(key [SecretLen]byte, envelope []byte) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("pairing: bad envelope: %w", err)
	}
	if env.V != EnvelopeVersion || env.Alg != EnvelopeAlg {
		return nil, errors.New("pairing: unsupported envelope")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, errors.New("pairing: bad nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return nil, errors.New("pairing: bad ciphertext")
	}
	g, err := gcmFor(key)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("pairing: decrypt failed")
	}
	return pt, nil
}
