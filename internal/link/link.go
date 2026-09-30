// Package link is the shared relay transport for backseat host endpoints.
//
// It dials the relay WebSocket, runs the HMAC challenge-response
// enrollment for joining experts, and encrypts per-expert payloads with
// the HKDF-derived directional keys from internal/pairing. Both the PTY
// host (internal/host) and the in-harness MCP host (internal/mcphost)
// build on it so the enrollment and crypto code exists exactly once.
package link

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// Config wires up one relay link.
type Config struct {
	RelayURL  string
	SessionID string
	HostName  string // From field on outbound envelopes
	Secret    [pairing.SecretLen]byte
}

// Link is one host-side connection to the relay.
type Link struct {
	cfg  Config
	conn *websocket.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	// challenges holds the in-flight HMAC challenge per joining expert.
	challenges map[string][pairing.SecretLen]byte
	// enrolled holds the derived directional keys per enrolled expert.
	enrolled map[string]pairing.Keys

	idSeq     atomic.Int64
	done      chan struct{}
	closeOnce sync.Once
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Dial connects to the relay. A missing path becomes /ws.
func Dial(cfg Config) (*Link, error) {
	u, err := url.Parse(cfg.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("link: relay url: %w", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("link: dial relay: %w", err)
	}
	return &Link{
		cfg:        cfg,
		conn:       conn,
		challenges: make(map[string][pairing.SecretLen]byte),
		enrolled:   make(map[string]pairing.Keys),
		done:       make(chan struct{}),
	}, nil
}

// SessionID reports the session this link serves.
func (l *Link) SessionID() string { return l.cfg.SessionID }

// HostName reports the From name used on outbound envelopes.
func (l *Link) HostName() string { return l.cfg.HostName }

// SendPlain writes a relay-readable envelope (session_announce,
// pairing_enroll, peer_kick, session_end). To "" broadcasts.
func (l *Link) SendPlain(msgType string, payload any, to string) error {
	msg, err := protocol.New(msgType, newID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	msg.To = to
	msg.From = l.cfg.HostName
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return l.conn.WriteJSON(msg)
}

// SendTo encrypts the payload with the expert's HostToExpert key and
// routes it to them. It fails if the expert has not completed enrollment.
func (l *Link) SendTo(expert, msgType string, payload any) error {
	l.mu.Lock()
	ks, ok := l.enrolled[expert]
	l.mu.Unlock()
	if !ok {
		return fmt.Errorf("link: expert %q not enrolled", expert)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env, err := pairing.Seal(ks.HostToExpert, raw)
	if err != nil {
		return err
	}
	msg := protocol.Message{
		Type:      msgType,
		ID:        newID(),
		Timestamp: time.Now().UnixMilli(),
		To:        expert,
		From:      l.cfg.HostName,
		Payload:   env,
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return l.conn.WriteJSON(msg)
}

// Decrypt opens an expert's envelope with their ExpertToHost key. A
// failed open (wrong key, tampered bytes, spoofed From) drops the message.
func (l *Link) Decrypt(from string, payload json.RawMessage) ([]byte, bool) {
	l.mu.Lock()
	ks, ok := l.enrolled[from]
	l.mu.Unlock()
	if !ok {
		return nil, false
	}
	raw, err := pairing.Open(ks.ExpertToHost, payload)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// BeginEnrollment starts the HMAC enrollment for a newcomer: a fresh
// challenge goes out as plaintext phase 1, routed to them by name.
func (l *Link) BeginEnrollment(expert string) error {
	ch, err := pairing.NewChallenge()
	if err != nil {
		return err
	}
	l.mu.Lock()
	if _, ok := l.enrolled[expert]; ok {
		l.mu.Unlock()
		return nil // already enrolled
	}
	l.challenges[expert] = ch
	l.mu.Unlock()
	return l.SendPlain(protocol.TypePairingEnroll, protocol.PairingEnroll{
		SessionID: l.cfg.SessionID,
		Phase:     1,
		Challenge: base64.StdEncoding.EncodeToString(ch[:]),
	}, expert)
}

// ErrNoChallenge reports a phase 2 response with no matching phase 1.
var ErrNoChallenge = errors.New("link: no pending challenge")

// FinishEnrollment verifies a phase 2 HMAC response. Success derives and
// stores the directional keys; the challenge is consumed on both paths so
// it can never be replayed.
func (l *Link) FinishEnrollment(from string, pe protocol.PairingEnroll) error {
	l.mu.Lock()
	ch, ok := l.challenges[from]
	if ok {
		delete(l.challenges, from)
	}
	l.mu.Unlock()
	if !ok {
		return ErrNoChallenge
	}
	raw, err := base64.StdEncoding.DecodeString(pe.Response)
	if err != nil || len(raw) != pairing.SecretLen {
		return errors.New("link: bad response encoding")
	}
	var resp [pairing.SecretLen]byte
	copy(resp[:], raw)
	if !pairing.VerifyEnrollment(l.cfg.Secret, ch, resp) {
		return errors.New("link: bad challenge response")
	}
	keys, err := pairing.DeriveKeys(l.cfg.Secret, ch)
	if err != nil {
		return fmt.Errorf("link: key derivation: %w", err)
	}
	l.mu.Lock()
	l.enrolled[from] = keys
	l.mu.Unlock()
	return nil
}

// AckEnrollment sends the phase 3 enrollment confirmation.
func (l *Link) AckEnrollment(expert string) error {
	return l.SendPlain(protocol.TypePairingEnroll, protocol.PairingEnroll{
		SessionID: l.cfg.SessionID,
		Phase:     3,
	}, expert)
}

// Enrolled reports whether the named expert completed enrollment.
func (l *Link) Enrolled(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.enrolled[name]
	return ok
}

// EnrolledNames lists every enrolled expert.
func (l *Link) EnrolledNames() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := make([]string, 0, len(l.enrolled))
	for n := range l.enrolled {
		names = append(names, n)
	}
	return names
}

// Forget drops an expert's keys and any pending challenge.
func (l *Link) Forget(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.enrolled, name)
	delete(l.challenges, name)
}

// Read blocks for the next relay envelope.
func (l *Link) Read() (protocol.Message, error) {
	var msg protocol.Message
	err := l.conn.ReadJSON(&msg)
	return msg, err
}

// Close tears down the connection. Safe to call from any goroutine.
func (l *Link) Close() error {
	l.closeOnce.Do(func() {
		l.conn.Close()
		close(l.done)
	})
	return nil
}

// Done fires when the link is closed.
func (l *Link) Done() <-chan struct{} { return l.done }
