// Package host implements the novice side of a backseat session: it wraps
// the agent command in a PTY, announces the session to the relay, streams
// terminal output out, and enforces control state locally. Only the current
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
	h := &Host{
		cfg:        cfg,
		conn:       conn,
		sess:       sess,
		terminated: make(chan struct{}),
	}
	if err := h.send(protocol.TypeSessionAnnounce, protocol.SessionAnnounce{
		SessionID:  cfg.SessionID,
		HostName:   cfg.HostName,
		Harness:    cfg.Harness,
		AgentCmd:   strings.Join(cfg.AgentCmd, " "),
		SecretHash: pairing.Verifier(cfg.Secret),
		ExpiresAt:  time.Now().Add(pairing.InviteTTL).Unix(),
	}); err != nil {
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

func (h *Host) send(msgType string, payload any) error {
	h.idSeq++
	msg, err := protocol.New(msgType, newID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.conn.WriteJSON(msg)
}

// pumpOutput streams PTY output to the relay and the local mirror.
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
		_ = h.send(protocol.TypeTermOutput, protocol.TermOutput{
			SessionID: h.cfg.SessionID,
			Data:      base64.StdEncoding.EncodeToString(b),
		})
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
		case protocol.TypeControlRequest:
			var req protocol.ControlRequest
			if msg.Decode(&req) != nil {
				continue
			}
			h.onRequest(req)
		case protocol.TypeControlYield:
			// Control returns to the novice, whether the expert yielded
			// voluntarily or the host reclaimed it.
			h.mu.Lock()
			h.controller = ""
			h.mu.Unlock()
			h.event("control returned to you")
		case protocol.TypeTermInput:
			h.mu.Lock()
			held := h.controller != ""
			h.mu.Unlock()
			if !held {
				continue // host holds control; no expert input applies
			}
			var in protocol.TermInput
			if msg.Decode(&in) != nil {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(in.Data)
			if err != nil {
				continue
			}
			h.sess.Write(raw)
		case protocol.TypeSessionEnd:
			h.event("session ended by relay")
			h.shutdown()
			return
		}
	}
}

func (h *Host) onRequest(req protocol.ControlRequest) {
	// Decide must be fast and non-blocking: it runs with the state lock held.
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != "" {
		h.sendDeny(req.ExpertName, "another request is pending")
		return
	}
	if h.controller == req.ExpertName {
		return // already driving
	}
	if h.cfg.Decide != nil {
		if h.cfg.Decide(req) {
			h.grantLocked(req.ExpertName)
		} else {
			h.sendDeny(req.ExpertName, "")
		}
		return
	}
	h.pending = req.ExpertName
	note := ""
	if req.Note != "" {
		note = " (" + req.Note + ")"
	}
	h.event(fmt.Sprintf("%s requests control%s. Type 'grant' or 'deny'.", req.ExpertName, note))
}

// Grant hands control to the expert with a pending request.
func (h *Host) Grant() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == "" {
		return errors.New("host: no pending control request")
	}
	h.grantLocked(h.pending)
	return nil
}

func (h *Host) grantLocked(expert string) {
	h.controller = expert
	h.pending = ""
	_ = h.send(protocol.TypeControlGrant, protocol.ControlGrant{
		SessionID:  h.cfg.SessionID,
		ExpertName: expert,
	})
	h.event(fmt.Sprintf("control handed to %s", expert))
}

// Deny refuses the pending control request.
func (h *Host) Deny(reason string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == "" {
		return errors.New("host: no pending control request")
	}
	h.sendDeny(h.pending, reason)
	h.pending = ""
	return nil
}

func (h *Host) sendDeny(expert, reason string) {
	_ = h.send(protocol.TypeControlDeny, protocol.ControlDeny{
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
		_ = h.send(protocol.TypeControlYield, protocol.ControlYield{
			SessionID:  h.cfg.SessionID,
			ExpertName: prev,
		})
		h.event("control reclaimed from " + prev)
	}
}

// Kick drops one expert from the room. If they held control it returns to
// the novice.
func (h *Host) Kick(expert, reason string) {
	h.mu.Lock()
	if h.controller == expert {
		h.controller = ""
	}
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
