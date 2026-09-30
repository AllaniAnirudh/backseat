// Expert protocol client for the TUI.
//
// This is the Go twin of the browser expert page (cmd/backseat-expert):
// secretless room_join, two-phase HMAC enrollment with the invite secret,
// HKDF-derived directional AES-256-GCM keys, then sealed envelopes in both
// directions. The handshake and crypto live in internal/pairing; this file
// only wires them to a WebSocket and translates frames into clientEvents
// for the Bubble Tea model.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// maxJoinAttempts mirrors the browser client: the host's announce can lag,
// so a fresh session may need a few retries before room_join is accepted.
const maxJoinAttempts = 6

// Events delivered to the model. Decrypted payloads arrive as evMessage
// with the raw plaintext; the model decodes per message type.
type clientEvent any

type evEnrolled struct{}
type evLatency struct{ d time.Duration }
type evError struct {
	code    string
	message string
}
type evSessionEnd struct{ reason string }
type evClosed struct{ err error }
type evMessage struct {
	msg   protocol.Message
	plain []byte // decrypted payload
}

// Client is a connected expert session. It implements the outbound
// interface the TUI model drives.
type Client struct {
	target  joinTarget
	name    string
	deliver func(clientEvent)

	conn    *websocket.Conn
	writeMu sync.Mutex
	msgSeq  atomic.Int64

	secret [pairing.SecretLen]byte
	keys   pairing.Keys

	rttNanos atomic.Int64
	closed   atomic.Bool
}

// newClient builds the client; run dials and pumps until the session ends.
func newClient(t joinTarget, name string, deliver func(clientEvent)) *Client {
	return &Client{target: t, name: name, deliver: deliver, secret: t.secret}
}

// Latency returns the last measured relay round-trip time.
func (c *Client) Latency() time.Duration {
	return time.Duration(c.rttNanos.Load())
}

// run dials the relay, joins, enrolls, and pumps messages until the
// connection drops or the context is cancelled.
func (c *Client) run(ctx context.Context) error {
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.DialContext(ctx, c.target.relayURL, nil)
	if err != nil {
		return fmt.Errorf("dial relay: %w", err)
	}
	c.conn = conn
	defer c.closeConn()

	conn.SetPongHandler(func(appData string) error {
		if ns, err := strconv.ParseInt(appData, 10, 64); err == nil {
			c.rttNanos.Store(time.Since(time.Unix(0, ns)).Nanoseconds())
		}
		return nil
	})

	stopPing := make(chan struct{})
	defer close(stopPing)
	go c.pingLoop(stopPing)

	joinAttempts := 0
	sendJoin := func() {
		joinAttempts++
		_ = c.sendPlain(protocol.TypeRoomJoin, protocol.RoomJoin{
			SessionID:  c.target.sessionID,
			ExpertName: c.name,
		})
	}
	sendJoin()

	enrolled := false
	for {
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			c.deliver(evClosed{err: err})
			return err
		}
		switch msg.Type {
		case protocol.TypeError:
			var pe protocol.Error
			_ = msg.Decode(&pe)
			if pe.Code == "no_session" && joinAttempts < maxJoinAttempts {
				c.deliver(evError{code: pe.Code, message: "session not up yet, retrying"})
				time.Sleep(700 * time.Millisecond)
				sendJoin()
				continue
			}
			c.deliver(evError{code: pe.Code, message: pe.Message})
			return errors.New("relay: " + pe.Code)
		case protocol.TypeSessionEnd:
			var se protocol.SessionEnd
			_ = msg.Decode(&se)
			c.deliver(evSessionEnd{reason: se.Reason})
			return nil
		case protocol.TypePairingEnroll:
			if c.onEnroll(msg) {
				enrolled = true
				c.deliver(evEnrolled{})
			}
			continue
		}
		if !enrolled {
			continue // nothing flows before enrollment completes
		}
		plain, err := pairing.Open(c.keys.HostToExpert, msg.Payload)
		if err != nil {
			continue // tampered or misaddressed: drop
		}
		c.deliver(evMessage{msg: msg, plain: plain})
	}
}

// onEnroll handles one phase of the HMAC enrollment. It returns true when
// phase 3 confirms the enrollment.
func (c *Client) onEnroll(msg protocol.Message) bool {
	var pe protocol.PairingEnroll
	if err := msg.Decode(&pe); err != nil {
		return false
	}
	switch pe.Phase {
	case 1:
		chRaw, err := base64.StdEncoding.DecodeString(pe.Challenge)
		if err != nil || len(chRaw) != pairing.SecretLen {
			return false
		}
		var challenge [pairing.SecretLen]byte
		copy(challenge[:], chRaw)
		resp := pairing.EnrollmentResponse(c.secret, challenge)
		keys, err := pairing.DeriveKeys(c.secret, challenge)
		if err != nil {
			return false
		}
		c.keys = keys
		_ = c.sendPlain(protocol.TypePairingEnroll, protocol.PairingEnroll{
			SessionID: c.target.sessionID,
			Phase:     2,
			Response:  base64.StdEncoding.EncodeToString(resp[:]),
		})
		return false
	case 3:
		return true
	default:
		return false
	}
}

// pingLoop measures relay RTT with websocket pings; the relay's default
// ping handler echoes the payload in its pong.
func (c *Client) pingLoop(stop <-chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			c.writeMu.Lock()
			_ = c.conn.WriteControl(websocket.PingMessage,
				[]byte(strconv.FormatInt(time.Now().UnixNano(), 10)),
				time.Now().Add(5*time.Second))
			c.writeMu.Unlock()
			if d := c.Latency(); d > 0 {
				c.deliver(evLatency{d: d})
			}
		}
	}
}

func (c *Client) closeConn() {
	if c.closed.CompareAndSwap(false, true) && c.conn != nil {
		_ = c.conn.Close()
	}
}

// Close drops the connection; the read loop exits and the model sees
// evClosed.
func (c *Client) Close() { c.closeConn() }

func (c *Client) nextID() string {
	return "e" + strconv.FormatInt(c.msgSeq.Add(1), 10)
}

// sendPlain writes one unencrypted envelope (join + enrollment only).
func (c *Client) sendPlain(msgType string, payload any) error {
	msg, err := protocol.New(msgType, c.nextID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	msg.From = c.name
	msg.To = "host"
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteJSON(msg)
}

// sendEncrypted seals the payload with the expert->host key and writes it.
func (c *Client) sendEncrypted(msgType string, payload any) error {
	msg, err := protocol.New(msgType, c.nextID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	env, err := pairing.Seal(c.keys.ExpertToHost, msg.Payload)
	if err != nil {
		return err
	}
	msg.Payload = env
	msg.From = c.name
	msg.To = "host"
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteJSON(msg)
}

// Outbound actions driven by the TUI model.

// decide answers an approval. It sends the structured in-harness decision;
// the TUI never writes answer bytes itself, that stays server-side.
func (c *Client) decide(approvalID string, req protocol.ApprovalRequest, approved bool) {
	decision := protocol.ApprovalDeny
	if approved {
		decision = protocol.ApprovalApprove
	}
	_ = c.sendEncrypted(protocol.TypeApprovalDecision, protocol.ApprovalDecision{
		SessionID:  c.target.sessionID,
		ApprovalID: approvalID,
		Decision:   decision,
		DecidedBy:  c.name,
		DecidedAt:  time.Now().Unix(),
		ExpiresAt:  req.ExpiresAt,
	})
}

// chat sends a message to the agent inbox.
func (c *Client) chat(text string) {
	_ = c.sendEncrypted(protocol.TypeExpertChat, protocol.ExpertChat{
		SessionID:  c.target.sessionID,
		ExpertName: c.name,
		Text:       text,
	})
}

// checkpoint asks the host to snapshot the session.
func (c *Client) checkpoint(label string) {
	_ = c.sendEncrypted(protocol.TypeCheckpointCreate, protocol.CheckpointCreate{
		SessionID: c.target.sessionID,
		Label:     label,
	})
}

// restore asks to rewind to a checkpoint; the novice confirms server-side.
func (c *Client) restore(label string) {
	_ = c.sendEncrypted(protocol.TypeCheckpointRestore, protocol.CheckpointRestore{
		SessionID: c.target.sessionID,
		Label:     label,
	})
}

// requestControl asks the novice for the controller grant.
func (c *Client) requestControl() {
	_ = c.sendEncrypted(protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  c.target.sessionID,
		ExpertName: c.name,
	})
}

// yieldControl returns control to the novice.
func (c *Client) yieldControl() {
	_ = c.sendEncrypted(protocol.TypeControlYield, protocol.ControlYield{
		SessionID:  c.target.sessionID,
		ExpertName: c.name,
	})
}

// exec runs a shell command on the host; controller-only, enforced host-side.
func (c *Client) exec(cmd string) {
	var id [8]byte
	_, _ = rand.Read(id[:])
	_ = c.sendEncrypted(protocol.TypeExecRequest, protocol.ExecRequest{
		SessionID: c.target.sessionID,
		ID:        hex.EncodeToString(id[:]),
		Command:   cmd,
	})
}
