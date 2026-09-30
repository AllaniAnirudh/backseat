// Package host implements the novice side of a backseat session: it wraps
// the agent command in a PTY, announces the session to the relay, runs the
// HMAC enrollment for each joining expert, then streams terminal output
// encrypted per expert and enforces control state locally. Only the current
// controller's input reaches the PTY, and the host tracks that state itself
// so a compromised relay cannot grant input rights on its own.
//
// The interactive console (grant/deny/yield/kick/end) lives in
// cmd/backseat-host; this package exposes the same operations as methods so
// tests can drive them without a terminal.
package host

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	bpty "github.com/AllaniAnirudh/backseat/internal/pty"
)

// Config wires up one host session.
type Config struct {
	RelayURL  string
	SessionID string
	Secret    [pairing.SecretLen]byte
	HostName  string
	Harness   string
	AgentCmd  []string
	// Decide is called on each control request. True grants, false denies.
	// Nil leaves the request pending for manual handling via Grant/Deny.
	Decide func(protocol.ControlRequest) bool
	// OnOutput mirrors raw PTY output (for the novice's own terminal).
	OnOutput func([]byte)
	// OnEvent reports control-plane events (requests, grants, joins).
	OnEvent func(string)
}

// Host runs one live session.
type Host struct {
	cfg  Config
	conn *websocket.Conn
	sess *bpty.Session

	writeMu sync.Mutex
	mu      sync.Mutex
	// controller is "" when the host holds control, else the expert name.
	controller string
	// pending is the expert name awaiting a grant/deny decision.
	pending string
	// pendingChallenges holds the in-flight HMAC challenge per joining expert.
	pendingChallenges map[string][pairing.SecretLen]byte
	// enrolled holds the derived directional keys per enrolled expert.
	enrolled map[string]pairing.Keys
	// announce is the session description, sent plaintext to the relay and
	// encrypted to each expert after enrollment.
	announce protocol.SessionAnnounce

	idSeq      int64
	shutOnce   sync.Once
	endOnce    sync.Once
	wg         sync.WaitGroup
	terminated chan struct{}
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// New starts the agent in a PTY, dials the relay, and announces the session.
func New(cfg Config) (*Host, error) {
	if len(cfg.AgentCmd) == 0 {
		return nil, errors.New("host: empty agent command")
	}
	if cfg.HostName == "" {
		cfg.HostName = "novice"
	}
	sess, err := bpty.Start(cfg.AgentCmd[0], cfg.AgentCmd[1:]...)
	if err != nil {
		return nil, fmt.Errorf("host: pty: %w", err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(cfg.RelayURL, nil)
	if err != nil {
		sess.Close()
		return nil, fmt.Errorf("host: dial relay: %w", err)
	}
	announce := protocol.SessionAnnounce{
		SessionID:  cfg.SessionID,
		HostName:   cfg.HostName,
		Harness:    cfg.Harness,
		AgentCmd:   strings.Join(cfg.AgentCmd, " "),
		SecretHash: pairing.Verifier(cfg.Secret),
		ExpiresAt:  time.Now().Add(pairing.InviteTTL).Unix(),
	}
	h := &Host{
		cfg:               cfg,
		conn:              conn,
		sess:              sess,
		pendingChallenges: make(map[string][pairing.SecretLen]byte),
		enrolled:          make(map[string]pairing.Keys),
		announce:          announce,
		terminated:        make(chan struct{}),
	}
	if err := h.send(protocol.TypeSessionAnnounce, announce); err != nil {
		sess.Close()
		conn.Close()
		return nil, fmt.Errorf("host: announce: %w", err)
	}
	h.wg.Add(2)
	go h.pumpOutput()
	go h.readLoop()
	return h, nil
}

func (h *Host) event(s string) {
	if h.cfg.OnEvent != nil {
		h.cfg.OnEvent(s)
	}
}

// send writes a plaintext envelope (relay-readable control types only:
// session_announce, pairing_enroll, peer_kick, session_end).
func (h *Host) send(msgType string, payload any) error {
	return h.sendRouted(msgType, payload, "")
}

// sendRouted writes a plaintext envelope addressed to one expert.
func (h *Host) sendRouted(msgType string, payload any, to string) error {
	h.idSeq++
	msg, err := protocol.New(msgType, newID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	msg.To = to
	msg.From = h.cfg.HostName
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.conn.WriteJSON(msg)
}

// sendTo encrypts the payload with the expert's HostToExpert key and routes
// it to them. It fails if the expert has not completed enrollment.
func (h *Host) sendTo(expert, msgType string, payload any) error {
	h.mu.Lock()
	ks, ok := h.enrolled[expert]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("host: expert %q not enrolled", expert)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env, err := pairing.Seal(ks.HostToExpert, raw)
	if err != nil {
		return err
	}
	h.idSeq++
	msg := protocol.Message{
		Type:      msgType,
		ID:        newID(),
		Timestamp: time.Now().UnixMilli(),
		To:        expert,
		From:      h.cfg.HostName,
		Payload:   env,
	}
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.conn.WriteJSON(msg)
}

// decryptFrom opens an expert's envelope with their ExpertToHost key. A
// failed open — wrong key, tampered bytes, or a spoofed From — drops the
// message.
func (h *Host) decryptFrom(from string, payload json.RawMessage) ([]byte, bool) {
	h.mu.Lock()
	ks, ok := h.enrolled[from]
	h.mu.Unlock()
	if !ok {
		return nil, false
	}
	raw, err := pairing.Open(ks.ExpertToHost, payload)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// pumpOutput streams PTY output to the relay and the local mirror. Each
// enrolled expert gets their own copy, encrypted with their HostToExpert
// key: the relay routes opaque envelopes and learns nothing about the
// content.
func (h *Host) pumpOutput() {
	defer h.wg.Done()
	ch := h.sess.Subscribe()
	defer h.sess.Unsubscribe(ch)
	for b := range ch {
		if h.cfg.OnOutput != nil {
			cp := make([]byte, len(b))
			copy(cp, b)
			h.cfg.OnOutput(cp)
		}
		h.mu.Lock()
		names := make([]string, 0, len(h.enrolled))
		for n := range h.enrolled {
			names = append(names, n)
		}
		h.mu.Unlock()
		for _, n := range names {
			_ = h.sendTo(n, protocol.TypeTermOutput, protocol.TermOutput{
				SessionID: h.cfg.SessionID,
				Data:      base64.StdEncoding.EncodeToString(b),
			})
		}
	}
	// Agent exited: end the session for everyone and tear down locally.
	h.endWithReason("agent exited")
	h.shutdown()
}

// readLoop routes relay messages into the session.
func (h *Host) readLoop() {
	defer h.wg.Done()
	for {
		var msg protocol.Message
		if err := h.conn.ReadJSON(&msg); err != nil {
			h.shutdown()
			return
		}
		switch msg.Type {
		case protocol.TypeRoomJoin:
			var join protocol.RoomJoin
			if msg.Decode(&join) != nil || join.ExpertName == "" {
				continue
			}
			h.onJoin(join.ExpertName)
		case protocol.TypePairingEnroll:
			var pe protocol.PairingEnroll
			if msg.Decode(&pe) != nil {
				continue
			}
			if pe.Phase == 2 {
				h.onEnrollResponse(msg.From, pe)
			}
		case protocol.TypeControlRequest:
			raw, ok := h.decryptFrom(msg.From, msg.Payload)
			if !ok {
				continue
			}
			var req protocol.ControlRequest
			if json.Unmarshal(raw, &req) != nil {
				continue
			}
			h.onRequest(req)
		case protocol.TypeControlYield:
			raw, ok := h.decryptFrom(msg.From, msg.Payload)
			if !ok {
				continue
			}
			var y protocol.ControlYield
			if json.Unmarshal(raw, &y) != nil {
				continue
			}
			// Only the actual controller can release control.
			h.mu.Lock()
			if h.controller != "" && h.controller == msg.From {
				h.controller = ""
				h.mu.Unlock()
				h.event("control returned to you")
			} else {
				h.mu.Unlock()
			}
		case protocol.TypeTermInput:
			h.onInput(msg)
		case protocol.TypeSessionEnd:
			h.event("session ended by relay")
			h.shutdown()
			return
		}
	}
}

// onJoin starts the HMAC enrollment for a newcomer: a fresh challenge goes
// out as plaintext phase 1, routed to them by name.
func (h *Host) onJoin(name string) {
	ch, err := pairing.NewChallenge()
	if err != nil {
		return
	}
	h.mu.Lock()
	h.pendingChallenges[name] = ch
	h.mu.Unlock()
	h.event(fmt.Sprintf("%s joined, enrolling…", name))
	_ = h.sendRouted(protocol.TypePairingEnroll, protocol.PairingEnroll{
		SessionID: h.cfg.SessionID,
		Phase:     1,
		Challenge: base64.StdEncoding.EncodeToString(ch[:]),
	}, name)
}

// onEnrollResponse verifies the phase 2 HMAC. Success derives the
// directional keys, acks with plaintext phase 3, and follows with the
// session announcement encrypted for that expert. Failure kicks the peer
// with a plaintext peer_kick the relay can act on.
func (h *Host) onEnrollResponse(from string, pe protocol.PairingEnroll) {
	if from == "" {
		return
	}
	h.mu.Lock()
	ch, ok := h.pendingChallenges[from]
	h.mu.Unlock()
	if !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(pe.Response)
	if err != nil || len(raw) != pairing.SecretLen {
		h.failEnroll(from, "bad response encoding")
		return
	}
	var resp [pairing.SecretLen]byte
	copy(resp[:], raw)
	if !pairing.VerifyEnrollment(h.cfg.Secret, ch, resp) {
		h.failEnroll(from, "bad challenge response")
		return
	}
	keys, err := pairing.DeriveKeys(h.cfg.Secret, ch)
	if err != nil {
		h.failEnroll(from, "key derivation failed")
		return
	}
	h.mu.Lock()
	h.enrolled[from] = keys
	delete(h.pendingChallenges, from)
	h.mu.Unlock()
	h.event(fmt.Sprintf("%s enrolled, channel encrypted", from))
	_ = h.sendRouted(protocol.TypePairingEnroll, protocol.PairingEnroll{
		SessionID: h.cfg.SessionID,
		Phase:     3,
	}, from)
	_ = h.sendTo(from, protocol.TypeSessionAnnounce, h.announce)
}

func (h *Host) failEnroll(name, reason string) {
	h.mu.Lock()
	delete(h.pendingChallenges, name)
	h.mu.Unlock()
	_ = h.send(protocol.TypePeerKick, protocol.PeerKick{
		SessionID:  h.cfg.SessionID,
		ExpertName: name,
		Reason:     reason,
	})
	h.event(fmt.Sprintf("enrollment failed for %s: %s", name, reason))
}

// onInput applies decrypted expert input to the PTY, but only when the
// sender is the current controller. Anything else is dropped.
func (h *Host) onInput(msg protocol.Message) {
	raw, ok := h.decryptFrom(msg.From, msg.Payload)
	if !ok {
		return
	}
	h.mu.Lock()
	controller := h.controller
	h.mu.Unlock()
	if controller == "" || msg.From != controller {
		return
	}
	var in protocol.TermInput
	if json.Unmarshal(raw, &in) != nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(in.Data)
	if err != nil {
		return
	}
	h.sess.Write(data)
}

func (h *Host) onRequest(req protocol.ControlRequest) {
	h.mu.Lock()
	if h.pending != "" {
		name := req.ExpertName
		h.mu.Unlock()
		h.sendDeny(name, "another request is pending")
		return
	}
	if h.controller == req.ExpertName {
		h.mu.Unlock()
		return // already driving
	}
	// Decide runs with the state lock held: it must be fast and non-blocking.
	decided := h.cfg.Decide != nil
	grant := decided && h.cfg.Decide(req)
	if !decided {
		h.pending = req.ExpertName
		note := ""
		if req.Note != "" {
			note = " (" + req.Note + ")"
		}
		name := req.ExpertName
		h.mu.Unlock()
		h.event(fmt.Sprintf("%s requests control%s. Type 'grant' or 'deny'.", name, note))
		return
	}
	name := req.ExpertName
	if grant {
		h.controller = name
		h.pending = ""
	}
	h.mu.Unlock()
	if grant {
		h.sendGrant(name)
	} else {
		h.sendDeny(name, "")
	}
}

// Grant hands control to the expert with a pending request.
func (h *Host) Grant() error {
	h.mu.Lock()
	if h.pending == "" {
		h.mu.Unlock()
		return errors.New("host: no pending control request")
	}
	expert := h.pending
	h.controller = expert
	h.pending = ""
	h.mu.Unlock()
	h.sendGrant(expert)
	return nil
}

func (h *Host) sendGrant(expert string) {
	_ = h.sendTo(expert, protocol.TypeControlGrant, protocol.ControlGrant{
		SessionID:  h.cfg.SessionID,
		ExpertName: expert,
	})
	h.event(fmt.Sprintf("control handed to %s", expert))
}

// Deny refuses the pending control request.
func (h *Host) Deny(reason string) error {
	h.mu.Lock()
	if h.pending == "" {
		h.mu.Unlock()
		return errors.New("host: no pending control request")
	}
	expert := h.pending
	h.pending = ""
	h.mu.Unlock()
	h.sendDeny(expert, reason)
	return nil
}

func (h *Host) sendDeny(expert, reason string) {
	_ = h.sendTo(expert, protocol.TypeControlDeny, protocol.ControlDeny{
		SessionID:  h.cfg.SessionID,
		ExpertName: expert,
		Reason:     reason,
	})
}

// Yield reclaims control from the expert back to the novice.
func (h *Host) Yield() {
	h.mu.Lock()
	prev := h.controller
	h.controller = ""
	h.mu.Unlock()
	if prev != "" {
		_ = h.sendTo(prev, protocol.TypeControlYield, protocol.ControlYield{
			SessionID:  h.cfg.SessionID,
			ExpertName: prev,
		})
		h.event("control reclaimed from " + prev)
	}
}

// Kick drops one expert from the room. If they held control it returns to
// the novice. The kick itself is plaintext so the relay can enforce it.
func (h *Host) Kick(expert, reason string) {
	h.mu.Lock()
	if h.controller == expert {
		h.controller = ""
	}
	delete(h.enrolled, expert)
	delete(h.pendingChallenges, expert)
	h.mu.Unlock()
	_ = h.send(protocol.TypePeerKick, protocol.PeerKick{
		SessionID:  h.cfg.SessionID,
		ExpertName: expert,
		Reason:     reason,
	})
	h.event("kicked " + expert)
}

// Controller reports who currently drives the PTY: "" means the host.
func (h *Host) Controller() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.controller
}

// Pending reports the expert name awaiting a grant/deny decision.
func (h *Host) Pending() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.pending
}

// Enrolled reports whether the named expert completed enrollment.
func (h *Host) Enrolled(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.enrolled[name]
	return ok
}

// End terminates the session for everyone and tears down locally.
func (h *Host) End(reason string) {
	h.endWithReason(reason)
	h.shutdown()
	h.wg.Wait()
}

func (h *Host) endWithReason(reason string) {
	h.endOnce.Do(func() {
		_ = h.send(protocol.TypeSessionEnd, protocol.SessionEnd{
			SessionID: h.cfg.SessionID,
			Reason:    reason,
		})
	})
}

// shutdown closes the PTY and the relay connection; loops exit on their own.
// It never blocks and is safe to call from any goroutine.
func (h *Host) shutdown() {
	h.shutOnce.Do(func() {
		h.sess.Close()
		h.conn.Close()
		close(h.terminated)
	})
}

// Wait blocks until the session has fully shut down.
func (h *Host) Wait() {
	h.wg.Wait()
}

// Done fires when the session shuts down (agent exit, relay drop, End).
func (h *Host) Done() <-chan struct{} {
	return h.terminated
}
