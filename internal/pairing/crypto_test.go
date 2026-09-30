package pairing

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// Fixed inputs for the interop vectors. The browser client runs the same
// HKDF/HMAC through WebCrypto and must produce these exact bytes; the node
// script in cmd/backseat-expert asserts the same values.
func vecSecret() (s [SecretLen]byte) {
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func vecChallenge() (c [SecretLen]byte) {
	for i := range c {
		c[i] = byte(0xa0 + i)
	}
	return c
}

func TestDeriveKeysVector(t *testing.T) {
	k, err := DeriveKeys(vecSecret(), vecChallenge())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k.HostToExpert[:]); got != "6892f29095fa58434f9b45c4eebb486b6f5d099bf41c94a09b10fa0e4b1a7b76" {
		t.Fatalf("HostToExpert mismatch: %s", got)
	}
	if got := hex.EncodeToString(k.ExpertToHost[:]); got != "6873e2ec1ce8727d77a2fd8bfcfb8ff1c06bd075c3d48ad1c8eb46687ed99867" {
		t.Fatalf("ExpertToHost mismatch: %s", got)
	}
}

func TestEnrollmentResponseVector(t *testing.T) {
	r := EnrollmentResponse(vecSecret(), vecChallenge())
	if got := hex.EncodeToString(r[:]); got != "0c95bd8bdd96004ec3f84f7bcc9526ee33491925dae778d32b6b81a42c38fe93" {
		t.Fatalf("HMAC response mismatch: %s", got)
	}
}

func TestVerifyEnrollment(t *testing.T) {
	s, c := vecSecret(), vecChallenge()
	good := EnrollmentResponse(s, c)
	if !VerifyEnrollment(s, c, good) {
		t.Fatal("valid response rejected")
	}
	var bad [SecretLen]byte
	copy(bad[:], good[:])
	bad[0] ^= 1
	if VerifyEnrollment(s, c, bad) {
		t.Fatal("tampered response accepted")
	}
	var other [SecretLen]byte
	other[0] = 1
	if VerifyEnrollment(other, c, good) {
		t.Fatal("response for wrong secret accepted")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k, err := DeriveKeys(vecSecret(), vecChallenge())
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("agent ran `rm -rf /` and I watched")
	env, err := Seal(k.HostToExpert, pt)
	if err != nil {
		t.Fatal(err)
	}
	// Envelope shape pinned on the wire.
	var shape struct {
		V     int             `json:"v"`
		Alg   string          `json:"alg"`
		Nonce string          `json:"nonce"`
		CT    string          `json:"ct"`
		Extra json.RawMessage `json:"-"`
	}
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(env, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 {
		t.Fatalf("envelope has %d fields, want 4", len(raw))
	}
	if err := json.Unmarshal(env, &shape); err != nil {
		t.Fatal(err)
	}
	if shape.V != 1 || shape.Alg != "AES-256-GCM" {
		t.Fatalf("bad envelope header: %+v", shape)
	}
	if n, err := base64.StdEncoding.DecodeString(shape.Nonce); err != nil || len(n) != 12 {
		t.Fatalf("bad nonce: %v", err)
	}
	got, err := Open(k.HostToExpert, env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestSealNonceUnique(t *testing.T) {
	k, _ := DeriveKeys(vecSecret(), vecChallenge())
	a, _ := Seal(k.HostToExpert, []byte("same"))
	b, _ := Seal(k.HostToExpert, []byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext are identical; nonce reuse?")
	}
}

func TestOpenRejects(t *testing.T) {
	k, _ := DeriveKeys(vecSecret(), vecChallenge())
	env, _ := Seal(k.HostToExpert, []byte("secret stuff"))
	mk := func(mut func(*Envelope)) []byte {
		var e Envelope
		if err := json.Unmarshal(env, &e); err != nil {
			t.Fatal(err)
		}
		mut(&e)
		out, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := map[string][]byte{
		"flipped ct bit": mk(func(e *Envelope) {
			raw, _ := base64.StdEncoding.DecodeString(e.CT)
			raw[0] ^= 1
			e.CT = base64.StdEncoding.EncodeToString(raw)
		}),
		"flipped tag bit": mk(func(e *Envelope) {
			raw, _ := base64.StdEncoding.DecodeString(e.CT)
			raw[len(raw)-1] ^= 1
			e.CT = base64.StdEncoding.EncodeToString(raw)
		}),
		"wrong version": mk(func(e *Envelope) { e.V = 2 }),
		"wrong alg":     mk(func(e *Envelope) { e.Alg = "AES-128-GCM" }),
		"bad nonce":     mk(func(e *Envelope) { e.Nonce = base64.StdEncoding.EncodeToString([]byte("short")) }),
		"not json":      []byte("{oops"),
	}
	for name, bad := range cases {
		if _, err := Open(k.HostToExpert, bad); err == nil {
			t.Fatalf("%s: tampered envelope accepted", name)
		}
	}
	// Wrong key must also fail.
	var other [SecretLen]byte
	other[0] = 9
	if _, err := Open(other, env); err == nil {
		t.Fatal("envelope opened with wrong key")
	}
	// Directional keys are not interchangeable.
	if _, err := Open(k.ExpertToHost, env); err == nil {
		t.Fatal("envelope opened with the reverse-direction key")
	}
}
