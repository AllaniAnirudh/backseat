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
	"sync/atomic"
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
	// WorkDir is the agent's working directory, snapshotted by
	// checkpoints. Empty means the host's current directory.
	WorkDir string
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
	// approvals holds forwarded prompts awaiting a decision, by ID.
	approvals map[string]*pendingApproval
	// approvalTail is a rolling window of recent stripped PTY text the
	// approval matcher scans.
	approvalTail strings.Builder
	// checkpoints snapshots the agent workdir for rewind.
	checkpoints *CheckpointManager
	// outputBytes counts PTY output bytes streamed so far (transcript
	// position recorded with each checkpoint).
	outputBytes int64
	// pendingRestore is an expert-requested rewind awaiting novice
	// confirmation. Nil when none is outstanding.
	pendingRestore *pendingRestoreReq

	idSeq      atomic.Int64
	shutOnce   sync.Once
	endOnce    sync.Once
	wg         sync.WaitGroup
	terminated chan struct{}
}

// pendingRestoreReq is one expert rewind request waiting on the novice.
type pendingRestoreReq struct {
	expert    string
	label     string
	requested time.Time
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
		approvals:         make(map[string]*pendingApproval),
		announce:          announce,
		terminated:        make(chan struct{}),
	}
	cpm, err := NewCheckpointManager(cfg.WorkDir)
	if err != nil {
		sess.Close()
		conn.Close()
		return nil, fmt.Errorf("host: checkpoints: %w", err)
	}
	h.checkpoints = cpm
	if err := h.send(protocol.TypeSessionAnnounce, announce); err != nil {
		sess.Close()
		conn.Close()
		return nil, fmt.Errorf("host: announce: %w", err)
	}
	h.wg.Add(3)
	go h.pumpOutput()
	go h.readLoop()
	go h.sweepApprovals()
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
	h.idSeq.Add(1)
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
	h.idSeq.Add(1)
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
// content. It also feeds the approval matcher.
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
		h.outputBytes += int64(len(b))
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
		h.scanApprovals(b)
	}
	// Agent exited: end the session for everyone and tear down locally.
	h.endWithReason("agent exited")
	h.shutdown()
}

// scanApprovals feeds PTY output through the approval matcher and
// forwards newly detected prompts to the expert(s).
func (h *Host) scanApprovals(b []byte) {
	h.mu.Lock()
	h.approvalTail.WriteString(stripANSI(string(b)))
	tail := h.approvalTail.String()
	if len(tail) > 8192 {
		tail = tail[len(tail)-8192:]
		h.approvalTail.Reset()
		h.approvalTail.WriteString(tail)
	}
	h.mu.Unlock()

	match := MatchApprovalPrompt(tail)
	h.mu.Lock()
	// Cancel pending prompts the agent has moved past: the prompt text
	// still appears in the tail but no longer ends it, so somebody (or a
	// timeout) already answered it. The pending answer bytes must die
	// here, or they could land on a later, unrelated prompt.
	var cancelled []*pendingApproval
	for id, p := range h.approvals {
		if !strings.HasSuffix(tail, p.prompt) && strings.Contains(tail, p.prompt) {
			cancelled = append(cancelled, p)
			delete(h.approvals, id)
		}
	}
	var allEnrolled []string
	for n := range h.enrolled {
		allEnrolled = append(allEnrolled, n)
	}
	if match == nil {
		h.mu.Unlock()
		for _, p := range cancelled {
			h.dismissApproval(p.id, allEnrolled, "agent moved past the prompt")
		}
		return
	}
	for _, p := range h.approvals {
		if p.prompt == match.Prompt {
			h.mu.Unlock()
			for _, c := range cancelled {
				h.dismissApproval(c.id, allEnrolled, "agent moved past the prompt")
			}
			return // already forwarded
		}
	}
	appr := &pendingApproval{
		id:        newApprovalID(),
		prompt:    match.Prompt,
		approve:   match.Pattern.Approve,
		deny:      match.Pattern.Deny,
		tool:      match.Pattern.Tool,
		createdAt: time.Now(),
	}
	h.approvals[appr.id] = appr
	// Recipients: the controller if one holds the wheel, else every
	// enrolled expert.
	var recipients []string
	if h.controller != "" {
		recipients = []string{h.controller}
	} else {
		recipients = allEnrolled
	}
	h.mu.Unlock()

	for _, c := range cancelled {
		h.dismissApproval(c.id, allEnrolled, "agent moved past the prompt")
	}
	if len(recipients) == 0 {
		return // nobody to ask; the novice answers locally
	}
	req := protocol.ApprovalRequest{
		SessionID:    h.cfg.SessionID,
		ApprovalID:   appr.id,
		Tool:         appr.tool,
		Summary:      match.Prompt,
		Prompt:       match.Prompt,
		ApproveLabel: "Approve",
		DenyLabel:    "Deny",
		ExpiresAt:    appr.createdAt.Add(approvalTTL).Unix(),
	}
	for _, n := range recipients {
		_ = h.sendTo(n, protocol.TypeApprovalRequest, req)
	}
	h.event(fmt.Sprintf("approval prompt forwarded to %s: %q", strings.Join(recipients, ","), match.Prompt))
}

// dismissApproval tells experts to drop a prompt card (cancelled or
// expired). Must be called without h.mu held.
func (h *Host) dismissApproval(id string, recipients []string, reason string) {
	ev := protocol.ApprovalResponse{
		SessionID:  h.cfg.SessionID,
		ApprovalID: id,
		Responder:  "host",
		Broadcast:  true,
	}
	for _, n := range recipients {
		_ = h.sendTo(n, protocol.TypeApprovalResponse, ev)
	}
	h.event(fmt.Sprintf("approval %s dismissed: %s", id, reason))
}

// sweepApprovals expires stale forwarded prompts so a late answer can
// never inject a stale "y" into the PTY.
func (h *Host) sweepApprovals() {
	defer h.wg.Done()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-h.terminated:
			return
		case <-t.C:
			now := time.Now()
			h.mu.Lock()
			var expired []*pendingApproval
			for id, p := range h.approvals {
				if p.expired(now) {
					expired = append(expired, p)
					delete(h.approvals, id)
				}
			}
			var allEnrolled []string
			for n := range h.enrolled {
				allEnrolled = append(allEnrolled, n)
			}
			if h.pendingRestore != nil && now.Sub(h.pendingRestore.requested) > restoreConfirmTTL {
				pr := h.pendingRestore
				h.pendingRestore = nil
				h.mu.Unlock()
				h.broadcastCheckpointEvent("restore_expired", pr.label, "novice did not confirm in time")
				h.event(fmt.Sprintf("rewind to %q expired without novice confirmation", pr.label))
			} else {
				h.mu.Unlock()
			}
			for _, p := range expired {
				h.dismissApproval(p.id, allEnrolled, "expired without an answer")
			}
		}
	}
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
		case protocol.TypeApprovalResponse:
			h.onApprovalResponse(msg)
		case protocol.TypeCheckpointCreate:
			h.onCheckpointCreate(msg)
		case protocol.TypeCheckpointRestore:
			h.onCheckpointRestore(msg)
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
	// A prompt may have been detected before anyone enrolled (or while a
	// different expert held control). Flush pending, unexpired prompts to
	// the newcomer so a waiting agent question is never silently missed.
	h.forwardPendingApprovals(from)
}

// forwardPendingApprovals re-sends unexpired pending prompts to a newly
// enrolled expert. Must be called without h.mu held.
func (h *Host) forwardPendingApprovals(to string) {
	now := time.Now()
	h.mu.Lock()
	if h.controller != "" && h.controller != to {
		h.mu.Unlock()
		return // prompts go to the controller only
	}
	var pending []*pendingApproval
	for _, p := range h.approvals {
		if !p.expired(now) {
			pending = append(pending, p)
		}
	}
	h.mu.Unlock()
	for _, p := range pending {
		_ = h.sendTo(to, protocol.TypeApprovalRequest, protocol.ApprovalRequest{
			SessionID:    h.cfg.SessionID,
			ApprovalID:   p.id,
			Tool:         p.tool,
			Summary:      p.prompt,
			Prompt:       p.prompt,
			ApproveLabel: "Approve",
			DenyLabel:    "Deny",
			ExpiresAt:    p.createdAt.Add(approvalTTL).Unix(),
		})
	}
	if len(pending) > 0 {
		h.event(fmt.Sprintf("forwarded %d pending approval(s) to %s", len(pending), to))
	}
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

// restoreConfirmTTL is how long the novice has to confirm an
// expert-requested rewind before it auto-denies (fail closed).
const restoreConfirmTTL = 60 * time.Second

// onApprovalResponse applies an expert's approval decision: the answer
// bytes go into the PTY, and every expert's card is dismissed via a
// broadcast. Only the controller (or any enrolled expert when nobody
// holds control) may answer, and only while the prompt is still fresh.
func (h *Host) onApprovalResponse(msg protocol.Message) {
	raw, ok := h.decryptFrom(msg.From, msg.Payload)
	if !ok {
		return
	}
	var resp protocol.ApprovalResponse
	if json.Unmarshal(raw, &resp) != nil || resp.ApprovalID == "" || resp.Broadcast {
		return
	}
	h.mu.Lock()
	if h.controller != "" && msg.From != h.controller {
		h.mu.Unlock()
		return // not the controller
	}
	appr, ok := h.approvals[resp.ApprovalID]
	if !ok || appr.expired(time.Now()) {
		h.mu.Unlock()
		return // unknown or stale: never inject a stale answer
	}
	delete(h.approvals, resp.ApprovalID)
	answer := appr.deny
	decision := "denied"
	if resp.Approved {
		answer = appr.approve
		decision = "approved"
	}
	from := msg.From
	h.mu.Unlock()

	if _, err := h.sess.Write(answer); err != nil {
		h.event(fmt.Sprintf("approval %s: failed to answer PTY: %v", resp.ApprovalID, err))
		return
	}
	h.event(fmt.Sprintf("approval %q %s by %s", appr.prompt, decision, from))
	// Dismiss every expert's card.
	bc := protocol.ApprovalResponse{
		SessionID:  h.cfg.SessionID,
		ApprovalID: resp.ApprovalID,
		Approved:   resp.Approved,
		Responder:  from,
		Broadcast:  true,
	}
	h.mu.Lock()
	var recipients []string
	for n := range h.enrolled {
		recipients = append(recipients, n)
	}
	h.mu.Unlock()
	for _, n := range recipients {
		_ = h.sendTo(n, protocol.TypeApprovalResponse, bc)
	}
}

// onCheckpointCreate snapshots the workdir. Experts may only checkpoint
// while they hold control; the novice always may (via console).
func (h *Host) onCheckpointCreate(msg protocol.Message) {
	raw, ok := h.decryptFrom(msg.From, msg.Payload)
	if !ok {
		return
	}
	var cc protocol.CheckpointCreate
	if json.Unmarshal(raw, &cc) != nil {
		return
	}
	h.mu.Lock()
	controller := h.controller
	h.mu.Unlock()
	if controller == "" || msg.From != controller {
		_ = h.sendTo(msg.From, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: h.cfg.SessionID,
			Action:    "failed",
			Label:     cc.Label,
			Message:   "only the controller can create checkpoints",
		})
		return
	}
	if _, err := h.Checkpoint(cc.Label); err != nil {
		_ = h.sendTo(msg.From, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: h.cfg.SessionID,
			Action:    "failed",
			Label:     cc.Label,
			Message:   err.Error(),
		})
		return
	}
	h.broadcastCheckpointEvent("created", cc.Label, fmt.Sprintf("checkpoint %q by %s", cc.Label, msg.From))
}

// onCheckpointRestore starts the novice-confirmed rewind flow: the
// request is parked until the novice confirms or denies it (or it
// expires). Only the controller may request.
func (h *Host) onCheckpointRestore(msg protocol.Message) {
	raw, ok := h.decryptFrom(msg.From, msg.Payload)
	if !ok {
		return
	}
	var cr protocol.CheckpointRestore
	if json.Unmarshal(raw, &cr) != nil {
		return
	}
	h.mu.Lock()
	controller := h.controller
	if controller == "" || msg.From != controller {
		h.mu.Unlock()
		_ = h.sendTo(msg.From, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: h.cfg.SessionID,
			Action:    "failed",
			Label:     cr.Label,
			Message:   "only the controller can request a rewind",
		})
		return
	}
	if _, ok := h.checkpoints.Get(cr.Label); !ok {
		h.mu.Unlock()
		_ = h.sendTo(msg.From, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: h.cfg.SessionID,
			Action:    "failed",
			Label:     cr.Label,
			Message:   "no such checkpoint",
		})
		return
	}
	if h.pendingRestore != nil {
		h.mu.Unlock()
		return // one rewind at a time
	}
	h.pendingRestore = &pendingRestoreReq{
		expert:    msg.From,
		label:     cr.Label,
		requested: time.Now(),
	}
	h.mu.Unlock()
	h.event(fmt.Sprintf("%s requests rewind to checkpoint %q. Type 'confirm-rewind' to allow or 'deny-rewind' to refuse (60s).", msg.From, cr.Label))
	h.broadcastCheckpointEvent("restore_requested", cr.Label,
		fmt.Sprintf("%s requested a rewind; waiting on the novice", msg.From))
}

// Checkpoint creates a named snapshot of the agent workdir.
func (h *Host) Checkpoint(label string) (*Checkpoint, error) {
	h.mu.Lock()
	n := h.outputBytes
	h.mu.Unlock()
	cp, err := h.checkpoints.Create(label, n)
	if err != nil {
		return nil, err
	}
	h.event(fmt.Sprintf("checkpoint %q created (%s)", label, cp.Kind))
	return cp, nil
}

// ListCheckpoints returns all checkpoints oldest first.
func (h *Host) ListCheckpoints() []*Checkpoint {
	return h.checkpoints.List()
}

// ConfirmRewind executes the pending expert-requested rewind. The novice
// calls this from their console; it is the veto gate.
func (h *Host) ConfirmRewind() error {
	h.mu.Lock()
	pr := h.pendingRestore
	h.pendingRestore = nil
	h.mu.Unlock()
	if pr == nil {
		return errors.New("host: no pending rewind request")
	}
	return h.doRestore(pr.label, "confirmed by novice")
}

// DenyRewind refuses the pending expert-requested rewind.
func (h *Host) DenyRewind(reason string) error {
	h.mu.Lock()
	pr := h.pendingRestore
	h.pendingRestore = nil
	h.mu.Unlock()
	if pr == nil {
		return errors.New("host: no pending rewind request")
	}
	if reason == "" {
		reason = "novice declined"
	}
	h.broadcastCheckpointEvent("restore_denied", pr.label, reason)
	h.event(fmt.Sprintf("rewind to %q denied: %s", pr.label, reason))
	return nil
}

// RestoreCheckpoint rewinds the workdir immediately. The novice uses this
// from their console; experts go through the confirm flow.
func (h *Host) RestoreCheckpoint(label string) error {
	return h.doRestore(label, "by novice")
}

func (h *Host) doRestore(label, how string) error {
	cp, err := h.checkpoints.Restore(label)
	if err != nil {
		h.broadcastCheckpointEvent("failed", label, err.Error())
		return err
	}
	msg := fmt.Sprintf("rewound to checkpoint %q %s (transcript was at %d bytes; files restored, new files removed)",
		label, how, cp.TranscriptBytes)
	h.event(msg)
	h.broadcastCheckpointEvent("restored", label, msg)
	return nil
}

// broadcastCheckpointEvent sends a checkpoint event to every enrolled
// expert, encrypted.
func (h *Host) broadcastCheckpointEvent(action, label, message string) {
	ev := protocol.CheckpointEvent{
		SessionID: h.cfg.SessionID,
		Action:    action,
		Label:     label,
		Message:   message,
	}
	h.mu.Lock()
	var recipients []string
	for n := range h.enrolled {
		recipients = append(recipients, n)
	}
	h.mu.Unlock()
	for _, n := range recipients {
		_ = h.sendTo(n, protocol.TypeCheckpointEvent, ev)
	}
}

// cancelApprovals drops all forwarded prompts. Called on session end:
// the kill switch always wins over a pending approval.
func (h *Host) cancelApprovals() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id := range h.approvals {
		delete(h.approvals, id)
	}
	h.pendingRestore = nil
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
	h.cancelApprovals()
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

// PendingApprovalCount reports how many approval prompts are waiting for
// an answer. Used by tests to wait for prompt detection.
func (h *Host) PendingApprovalCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.approvals)
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
	h.cancelApprovals() // kill switch beats any pending approval
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
