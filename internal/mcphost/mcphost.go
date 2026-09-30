// Package mcphost is the trusted host endpoint for in-harness backseat
// sessions (v0.3 milestone).
//
// The novice's agent drives it through MCP tools (cmd/backseat-mcp); the
// expert reaches it over the relay WebSocket using the same encrypted
// envelopes as the v0.2 PTY host (HMAC enrollment, HKDF AES-256-GCM, via
// internal/link). Control state (grant/deny/yield/kick/end) is enforced
// here, never by the relay.
//
// Trust properties, carried over from v0.2 and extended:
//   - Session creation is human-gated: the skill requires explicit human
//     confirmation before the agent calls backseat__create_session, so a
//     prompt-injected agent must never mint sessions.
//   - Every control grant is novice-confirmed out-of-band of the model's
//     tool calls. The MCP tool surface has no grant tool; the human
//     confirms through the local control socket (ServeControl), e.g.
//     `backseat-mcp ctl <sock> grant`.
//   - Invites are single-use: the secret burns on the first successful
//     enrollment, and expires after 10 minutes either way.
//   - Approval prompts from backseat__request_approval fail closed after
//     a 2-minute TTL.
//   - Published events are secret-masked before reaching the expert.
//   - The exec side-channel is controller-only, novice-visible (every run
//     lands in the agent's poll inbox), and bounded in time and output.
package mcphost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/link"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// Approval TTL bounds: a forwarded prompt stays answerable for at most
// two minutes, then fails closed (deny). The agent may ask for less.
const maxApprovalTTL = 2 * time.Minute

// restoreConfirmTTL is how long the novice has to confirm an
// expert-requested rewind before it auto-denies (fail closed).
const restoreConfirmTTL = 60 * time.Second

// maxExecConcurrent bounds how many expert shell commands run at once.
const maxExecConcurrent = 2

// maxInbox caps queued poll items; oldest are dropped past the cap.
const maxInbox = 500

// Decision values returned to the agent from RequestApproval.
const (
	DecisionApprove = "approve"
	DecisionDeny    = "deny"
)

// Fail-closed errors from RequestApproval. The decision is always
// DecisionDeny on these paths.
var (
	ErrNoExpertConnected = errors.New("mcphost: no expert connected")
	ErrApprovalExpired   = errors.New("mcphost: approval expired without a decision")
	ErrSessionEnded      = errors.New("mcphost: session ended")
)

// Config wires up one in-harness session.
type Config struct {
	RelayURL string
	UIBase   string // public base URL of the expert web UI, for the invite link
	// SessionID and Secret are minted when empty/zero.
	SessionID string
	Secret    [pairing.SecretLen]byte
	HostName  string // display name shown to the expert
	Harness   string // e.g. "claude", "opencode"
	WorkDir   string // exec and checkpoint directory; empty means cwd
	// ApprovalTTL caps request_approval waits; 0 means maxApprovalTTL.
	ApprovalTTL time.Duration
	// OnEvent reports control-plane events (joins, grants, exec runs).
	OnEvent func(string)
}

// InboxItem is one queued event for the agent's backseat__poll inbox.
type InboxItem struct {
	ID   string         `json:"id"`
	Type string         `json:"type"` // expert_chat, control_request, control_state, peer_joined, peer_left, exec, checkpoint, restore_requested
	At   int64          `json:"at"`   // unix millis
	From string         `json:"from,omitempty"`
	Text string         `json:"text,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

// Status is the backseat__session_status answer.
type Status struct {
	SessionID        string   `json:"session_id"`
	Controller       string   `json:"controller"`
	PendingControl   string   `json:"pending_control,omitempty"`
	Experts          []string `json:"experts"`
	InviteExpiresAt  int64    `json:"invite_expires_at"`
	InviteBurned     bool     `json:"invite_burned"`
	Checkpoints      []string `json:"checkpoints"`
	PendingApprovals int      `json:"pending_approvals"`
	EventsPublished  int64    `json:"events_published"`
}

// pendingApproval is one agent approval prompt awaiting the expert.
type pendingApproval struct {
	id       string
	prompt   string
	options  []string
	deadline time.Time
	resolve  chan approvalOutcome
}

type approvalOutcome struct {
	decision string
	by       string
}

// pendingRestoreReq is one expert rewind request awaiting novice confirm.
type pendingRestoreReq struct {
	expert    string
	label     string
	requested time.Time
}

// Session is one live in-harness backseat session.
type Session struct {
	cfg  Config
	link *link.Link

	mu sync.Mutex
	// controller is "" when the novice holds control, else the expert name.
	controller string
	// pendingControl is the expert awaiting a novice grant/deny.
	pendingControl string
	// peers tracks enrolled experts and their enroll time.
	peers map[string]time.Time
	// inviteBurned marks the one-time invite as consumed.
	inviteBurned bool
	inviteExpiry time.Time
	// inbox queues poll items for the agent.
	inbox []InboxItem
	// approvals holds forwarded prompts awaiting a decision, by ID.
	approvals map[string]*pendingApproval
	// pendingRestore is an expert-requested rewind awaiting novice
	// confirmation. Nil when none is outstanding.
	pendingRestore *pendingRestoreReq

	checkpoints *host.CheckpointManager
	execSem     chan struct{}
	events      atomic.Int64

	announce protocol.SessionAnnounce

	endOnce    sync.Once
	shutOnce   sync.Once
	wg         sync.WaitGroup
	terminated chan struct{}
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isZeroSecret(s [pairing.SecretLen]byte) bool {
	var z [pairing.SecretLen]byte
	return s == z
}

// New dials the relay, announces the session, and starts the read loop.
func New(cfg Config) (*Session, error) {
	if cfg.HostName == "" {
		cfg.HostName = "novice"
	}
	if cfg.SessionID == "" {
		cfg.SessionID = newID()
	}
	if isZeroSecret(cfg.Secret) {
		s, err := pairing.GenerateSecret()
		if err != nil {
			return nil, fmt.Errorf("mcphost: secret: %w", err)
		}
		cfg.Secret = s
	}
	rl, err := link.Dial(link.Config{
		RelayURL:  cfg.RelayURL,
		SessionID: cfg.SessionID,
		HostName:  cfg.HostName,
		Secret:    cfg.Secret,
	})
	if err != nil {
		return nil, err
	}
	cpm, err := host.NewCheckpointManager(cfg.WorkDir)
	if err != nil {
		rl.Close()
		return nil, fmt.Errorf("mcphost: checkpoints: %w", err)
	}
	s := &Session{
		cfg:          cfg,
		link:         rl,
		peers:        make(map[string]time.Time),
		inbox:        make([]InboxItem, 0, 32),
		approvals:    make(map[string]*pendingApproval),
		checkpoints:  cpm,
		execSem:      make(chan struct{}, maxExecConcurrent),
		inviteExpiry: time.Now().Add(pairing.InviteTTL),
		terminated:   make(chan struct{}),
		announce: protocol.SessionAnnounce{
			SessionID:  cfg.SessionID,
			HostName:   cfg.HostName,
			Harness:    cfg.Harness,
			AgentCmd:   "in-harness",
			SecretHash: pairing.Verifier(cfg.Secret),
			ExpiresAt:  time.Now().Add(pairing.InviteTTL).Unix(),
		},
	}
	if err := s.link.SendPlain(protocol.TypeSessionAnnounce, s.announce, ""); err != nil {
		rl.Close()
		return nil, fmt.Errorf("mcphost: announce: %w", err)
	}
	s.wg.Add(2)
	go s.readLoop()
	go s.sweepLoop()
	return s, nil
}

func (s *Session) event(text string) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(text)
	}
}

// InviteURL is the one-time link the novice shares with the expert. The
// secret lives in the URL fragment, never in a server request.
func (s *Session) InviteURL() string {
	return pairing.InviteURL(s.cfg.UIBase, s.cfg.SessionID, s.cfg.Secret)
}

// InviteCode is the short code form of the invite secret, for
// `backseat-tui join <code>`.
func (s *Session) InviteCode() string {
	return pairing.Verifier(s.cfg.Secret)[:16]
}

// SessionID reports the session id.
func (s *Session) SessionID() string { return s.cfg.SessionID }

// approvalTTL returns the configured cap, defaulting to maxApprovalTTL.
func (s *Session) approvalTTL() time.Duration {
	if s.cfg.ApprovalTTL > 0 {
		return s.cfg.ApprovalTTL
	}
	return maxApprovalTTL
}

// pushInbox queues one poll item, dropping the oldest past the cap.
func (s *Session) pushInbox(item InboxItem) {
	if item.ID == "" {
		item.ID = "inbox-" + newID()
	}
	if item.At == 0 {
		item.At = time.Now().UnixMilli()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inbox) >= maxInbox {
		copy(s.inbox, s.inbox[1:])
		s.inbox = s.inbox[:len(s.inbox)-1]
	}
	s.inbox = append(s.inbox, item)
}

// Poll drains the agent inbox: expert chat, control state changes,
// exec notifications, peer and checkpoint events.
func (s *Session) Poll() []InboxItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]InboxItem, len(s.inbox))
	copy(out, s.inbox)
	s.inbox = s.inbox[:0]
	return out
}

// PublishEvent masks secrets and forwards a structured transcript event
// to every enrolled expert.
func (s *Session) PublishEvent(kind, text string, fields map[string]any) {
	ev := protocol.TranscriptEvent{
		SessionID: s.cfg.SessionID,
		Harness:   s.cfg.Harness,
		Kind:      kind,
		Text:      MaskSecrets(text),
		Fields:    maskFields(fields),
	}
	n := s.events.Add(1)
	_ = n
	for _, name := range s.link.EnrolledNames() {
		_ = s.link.SendTo(name, protocol.TypeTranscriptEvent, ev)
	}
}

// validDecision checks an expert answer against the prompt's options.
func validDecision(decision string, options []string) bool {
	if len(options) == 0 {
		return decision == DecisionApprove || decision == DecisionDeny
	}
	for _, o := range options {
		if decision == o {
			return true
		}
	}
	return false
}

// RequestApproval forwards a structured approval prompt to the expert and
// blocks until they decide or the TTL lapses. It fails closed: expiry,
// cancellation, a vanished expert, or session end all resolve to deny.
func (s *Session) RequestApproval(ctx context.Context, prompt string, options []string, timeout time.Duration) (string, error) {
	ttl := timeout
	if ttl <= 0 {
		ttl = s.approvalTTL()
	}
	if ttl > maxApprovalTTL {
		ttl = maxApprovalTTL
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	deadline := time.Now().Add(ttl)

	s.mu.Lock()
	controller := s.controller
	s.mu.Unlock()
	var recipients []string
	if controller != "" {
		recipients = []string{controller}
	} else {
		recipients = s.link.EnrolledNames()
	}
	if len(recipients) == 0 {
		return DecisionDeny, ErrNoExpertConnected
	}

	p := &pendingApproval{
		id:       "appr-" + newID(),
		prompt:   prompt,
		options:  options,
		deadline: deadline,
		resolve:  make(chan approvalOutcome, 1),
	}
	s.mu.Lock()
	s.approvals[p.id] = p
	s.mu.Unlock()

	req := protocol.ApprovalRequest{
		SessionID:  s.cfg.SessionID,
		ApprovalID: p.id,
		Tool:       "agent",
		Summary:    prompt,
		Prompt:     prompt,
		Options:    options,
		TimeoutSec: int(ttl.Seconds()),
		ExpiresAt:  deadline.Unix(),
	}
	for _, name := range recipients {
		_ = s.link.SendTo(name, protocol.TypeApprovalRequest, req)
	}
	s.event(fmt.Sprintf("approval %s forwarded to %s", p.id, strings.Join(recipients, ",")))

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case out := <-p.resolve:
		return out.decision, nil
	case <-timer.C:
		s.failApproval(p.id, "expired without a decision")
		return DecisionDeny, ErrApprovalExpired
	case <-ctx.Done():
		s.failApproval(p.id, "request cancelled")
		return DecisionDeny, ctx.Err()
	case <-s.terminated:
		s.failApproval(p.id, "session ended")
		return DecisionDeny, ErrSessionEnded
	}
}

// failApproval drops a pending prompt as denied and tells every expert to
// dismiss the card. The v0.2 approval_response broadcast dismisses cards
// on old and new clients alike.
func (s *Session) failApproval(id, reason string) {
	s.mu.Lock()
	p, ok := s.approvals[id]
	if ok {
		delete(s.approvals, id)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	s.broadcastApprovalDismissal(p.id, false, "host")
	s.event(fmt.Sprintf("approval %s failed closed: %s", id, reason))
	select {
	case p.resolve <- approvalOutcome{decision: DecisionDeny, by: "host"}:
	default:
	}
}

// broadcastApprovalDismissal tells every expert to drop a prompt card.
func (s *Session) broadcastApprovalDismissal(id string, approved bool, by string) {
	ev := protocol.ApprovalResponse{
		SessionID:  s.cfg.SessionID,
		ApprovalID: id,
		Approved:   approved,
		Responder:  by,
		Broadcast:  true,
	}
	for _, name := range s.link.EnrolledNames() {
		_ = s.link.SendTo(name, protocol.TypeApprovalResponse, ev)
	}
}

// onApprovalDecision applies an expert's answer: only the controller (or
// any enrolled expert when nobody holds control) may answer, only while
// the prompt is fresh, and only with a valid choice.
func (s *Session) onApprovalDecision(from string, msg protocol.Message) {
	raw, ok := s.link.Decrypt(from, msg.Payload)
	if !ok {
		return
	}
	var dec protocol.ApprovalDecision
	if json.Unmarshal(raw, &dec) != nil || dec.ApprovalID == "" {
		return
	}
	if dec.DecidedBy != "" && dec.DecidedBy != from {
		return // decider must match the sender
	}
	s.mu.Lock()
	p, ok := s.approvals[dec.ApprovalID]
	controller := s.controller
	if ok {
		delete(s.approvals, dec.ApprovalID)
	}
	s.mu.Unlock()
	if !ok || time.Now().After(p.deadline) {
		return // unknown or stale: never apply a stale answer
	}
	if controller != "" && from != controller {
		return
	}
	if !validDecision(dec.Decision, p.options) {
		return
	}
	s.broadcastApprovalDismissal(p.id, dec.Decision == DecisionApprove, from)
	s.event(fmt.Sprintf("approval %q decided %q by %s", p.prompt, dec.Decision, from))
	select {
	case p.resolve <- approvalOutcome{decision: dec.Decision, by: from}:
	default:
	}
}

// Checkpoint snapshots the session working directory and announces it.
func (s *Session) Checkpoint(label string) (*host.Checkpoint, error) {
	cp, err := s.checkpoints.Create(label, s.events.Load())
	if err != nil {
		return nil, err
	}
	s.broadcastCheckpointEvent("created", label, fmt.Sprintf("checkpoint %q created", label), cp.Ref,
		fmt.Sprintf("events:%d", s.events.Load()))
	return cp, nil
}

// ListCheckpoints returns checkpoints oldest first.
func (s *Session) ListCheckpoints() []*host.Checkpoint {
	return s.checkpoints.List()
}

// broadcastCheckpointEvent sends a checkpoint event to every expert.
func (s *Session) broadcastCheckpointEvent(action, label, message, snapshotID, marker string) {
	ev := protocol.CheckpointEvent{
		SessionID:        s.cfg.SessionID,
		Action:           action,
		Label:            label,
		Message:          message,
		SnapshotID:       snapshotID,
		TranscriptMarker: marker,
	}
	for _, name := range s.link.EnrolledNames() {
		_ = s.link.SendTo(name, protocol.TypeCheckpointEvent, ev)
	}
	s.pushInbox(InboxItem{Type: "checkpoint", Text: message,
		Data: map[string]any{"action": action, "label": label}})
}

// onCheckpointCreate snapshots on expert request. Only the controller may.
func (s *Session) onCheckpointCreate(from string, msg protocol.Message) {
	raw, ok := s.link.Decrypt(from, msg.Payload)
	if !ok {
		return
	}
	var cc protocol.CheckpointCreate
	if json.Unmarshal(raw, &cc) != nil {
		return
	}
	s.mu.Lock()
	controller := s.controller
	s.mu.Unlock()
	if controller == "" || from != controller {
		_ = s.link.SendTo(from, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: s.cfg.SessionID,
			Action:    "failed",
			Label:     cc.Label,
			Message:   "only the controller can create checkpoints",
		})
		return
	}
	if _, err := s.Checkpoint(cc.Label); err != nil {
		_ = s.link.SendTo(from, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: s.cfg.SessionID,
			Action:    "failed",
			Label:     cc.Label,
			Message:   err.Error(),
		})
	}
}

// onCheckpointRestore parks an expert rewind request for novice confirm.
// Only the controller may ask; one rewind at a time.
func (s *Session) onCheckpointRestore(from string, msg protocol.Message) {
	raw, ok := s.link.Decrypt(from, msg.Payload)
	if !ok {
		return
	}
	var cr protocol.CheckpointRestore
	if json.Unmarshal(raw, &cr) != nil {
		return
	}
	deny := func(message string) {
		_ = s.link.SendTo(from, protocol.TypeCheckpointEvent, protocol.CheckpointEvent{
			SessionID: s.cfg.SessionID,
			Action:    "failed",
			Label:     cr.Label,
			Message:   message,
		})
	}
	s.mu.Lock()
	if s.controller == "" || from != s.controller {
		s.mu.Unlock()
		deny("only the controller can request a rewind")
		return
	}
	if _, ok := s.checkpoints.Get(cr.Label); !ok {
		s.mu.Unlock()
		deny("no such checkpoint")
		return
	}
	if s.pendingRestore != nil {
		s.mu.Unlock()
		return // one rewind at a time
	}
	s.pendingRestore = &pendingRestoreReq{expert: from, label: cr.Label, requested: time.Now()}
	s.mu.Unlock()
	s.event(fmt.Sprintf("%s requests rewind to %q; novice confirm needed (60s)", from, cr.Label))
	s.pushInbox(InboxItem{Type: "restore_requested", From: from,
		Text: fmt.Sprintf("%s requests a rewind to checkpoint %q. Confirm out-of-band: backseat-mcp ctl grant path uses confirm-restore.", from, cr.Label),
		Data: map[string]any{"label": cr.Label, "expert": from}})
	s.broadcastCheckpointEvent("restore_requested", cr.Label,
		fmt.Sprintf("%s requested a rewind; waiting on the novice", from), "", "")
}

// ConfirmRestore executes the pending expert-requested rewind. The novice
// calls this out-of-band; it is the veto gate.
func (s *Session) ConfirmRestore() error {
	s.mu.Lock()
	pr := s.pendingRestore
	s.pendingRestore = nil
	s.mu.Unlock()
	if pr == nil {
		return errors.New("mcphost: no pending rewind request")
	}
	cp, err := s.checkpoints.Restore(pr.label)
	if err != nil {
		s.broadcastCheckpointEvent("failed", pr.label, err.Error(), "", "")
		return err
	}
	msg := fmt.Sprintf("rewound to checkpoint %q confirmed by novice (files restored, new files removed)", pr.label)
	_ = cp
	s.event(msg)
	s.broadcastCheckpointEvent("restored", pr.label, msg, "", "")
	return nil
}

// DenyRestore refuses the pending expert-requested rewind.
func (s *Session) DenyRestore(reason string) error {
	s.mu.Lock()
	pr := s.pendingRestore
	s.pendingRestore = nil
	s.mu.Unlock()
	if pr == nil {
		return errors.New("mcphost: no pending rewind request")
	}
	if reason == "" {
		reason = "novice declined"
	}
	s.broadcastCheckpointEvent("restore_denied", pr.label, reason, "", "")
	s.event(fmt.Sprintf("rewind to %q denied: %s", pr.label, reason))
	return nil
}

// readLoop routes relay messages into the session.
func (s *Session) readLoop() {
	defer s.wg.Done()
	for {
		msg, err := s.link.Read()
		if err != nil {
			s.shutdown()
			return
		}
		switch msg.Type {
		case protocol.TypeRoomJoin:
			var join protocol.RoomJoin
			if msg.Decode(&join) != nil || join.ExpertName == "" {
				continue
			}
			s.onJoin(join.ExpertName)
		case protocol.TypePairingEnroll:
			var pe protocol.PairingEnroll
			if msg.Decode(&pe) != nil {
				continue
			}
			if pe.Phase == 2 {
				s.onEnrollResponse(msg.From, pe)
			}
		case protocol.TypeControlRequest:
			s.onControlRequest(msg)
		case protocol.TypeControlYield:
			s.onControlYield(msg)
		case protocol.TypeExpertChat:
			s.onExpertChat(msg)
		case protocol.TypeApprovalDecision:
			s.onApprovalDecision(msg.From, msg)
		case protocol.TypeExecRequest:
			s.onExecRequest(msg)
		case protocol.TypeCheckpointCreate:
			s.onCheckpointCreate(msg.From, msg)
		case protocol.TypeCheckpointRestore:
			s.onCheckpointRestore(msg.From, msg)
		case protocol.TypeSessionEnd:
			s.event("session ended by relay")
			s.shutdown()
			return
		}
	}
}

// onJoin starts enrollment unless the invite is spent or expired.
func (s *Session) onJoin(name string) {
	s.mu.Lock()
	burned := s.inviteBurned
	expired := time.Now().After(s.inviteExpiry)
	s.mu.Unlock()
	if burned || expired {
		reason := "invite already used"
		if expired {
			reason = "invite expired"
		}
		_ = s.link.SendPlain(protocol.TypePeerKick, protocol.PeerKick{
			SessionID:  s.cfg.SessionID,
			ExpertName: name,
			Reason:     reason,
		}, "")
		s.event(fmt.Sprintf("rejected join from %s: %s", name, reason))
		return
	}
	if err := s.link.BeginEnrollment(name); err != nil {
		s.event(fmt.Sprintf("enrollment challenge for %s failed: %v", name, err))
		return
	}
	s.event(fmt.Sprintf("%s joined, enrolling…", name))
}

// onEnrollResponse verifies phase 2 and burns the invite on the first
// success: one invite admits exactly one expert.
func (s *Session) onEnrollResponse(from string, pe protocol.PairingEnroll) {
	if from == "" {
		return
	}
	if err := s.link.FinishEnrollment(from, pe); err != nil {
		if errors.Is(err, link.ErrNoChallenge) {
			return
		}
		s.failEnroll(from, err.Error())
		return
	}
	s.mu.Lock()
	if s.inviteBurned {
		s.mu.Unlock()
		s.link.Forget(from)
		s.failEnroll(from, "invite already used")
		return
	}
	s.inviteBurned = true
	s.peers[from] = time.Now()
	s.mu.Unlock()
	s.event(fmt.Sprintf("%s enrolled, channel encrypted, invite burned", from))
	_ = s.link.AckEnrollment(from)
	_ = s.link.SendTo(from, protocol.TypeSessionAnnounce, s.announce)
	s.pushInbox(InboxItem{Type: "peer_joined", From: from, Text: fmt.Sprintf("%s joined the session", from)})
}

func (s *Session) failEnroll(name, reason string) {
	s.link.Forget(name)
	_ = s.link.SendPlain(protocol.TypePeerKick, protocol.PeerKick{
		SessionID:  s.cfg.SessionID,
		ExpertName: name,
		Reason:     reason,
	}, "")
	s.event(fmt.Sprintf("enrollment failed for %s: %s", name, reason))
}

// onControlRequest parks an expert control request for novice confirmation.
// Exactly one controller at a time; a second request is denied while one
// is pending. Grants never happen without the novice.
func (s *Session) onControlRequest(msg protocol.Message) {
	raw, ok := s.link.Decrypt(msg.From, msg.Payload)
	if !ok {
		return
	}
	var req protocol.ControlRequest
	if json.Unmarshal(raw, &req) != nil || req.ExpertName == "" {
		return
	}
	s.mu.Lock()
	if s.pendingControl != "" {
		s.mu.Unlock()
		_ = s.link.SendTo(req.ExpertName, protocol.TypeControlDeny, protocol.ControlDeny{
			SessionID:  s.cfg.SessionID,
			ExpertName: req.ExpertName,
			Reason:     "another request is pending",
		})
		return
	}
	if s.controller == req.ExpertName {
		s.mu.Unlock()
		return // already driving
	}
	s.pendingControl = req.ExpertName
	s.mu.Unlock()
	note := ""
	if req.Note != "" {
		note = " (" + req.Note + ")"
	}
	s.event(fmt.Sprintf("%s requests control%s; novice confirm needed", req.ExpertName, note))
	s.pushInbox(InboxItem{Type: "control_request", From: req.ExpertName,
		Text: fmt.Sprintf("%s requests control%s. The human must confirm out-of-band before any grant.", req.ExpertName, note),
		Data: map[string]any{"expert": req.ExpertName, "note": req.Note}})
}

// Grant hands control to the expert with a pending request. Called by the
// novice out-of-band (control socket), never by the agent's tools.
func (s *Session) Grant() error {
	s.mu.Lock()
	if s.pendingControl == "" {
		s.mu.Unlock()
		return errors.New("mcphost: no pending control request")
	}
	expert := s.pendingControl
	s.controller = expert
	s.pendingControl = ""
	s.mu.Unlock()
	_ = s.link.SendTo(expert, protocol.TypeControlGrant, protocol.ControlGrant{
		SessionID:  s.cfg.SessionID,
		ExpertName: expert,
	})
	s.event(fmt.Sprintf("control handed to %s", expert))
	s.pushInbox(InboxItem{Type: "control_state", From: expert, Text: fmt.Sprintf("%s now holds control", expert),
		Data: map[string]any{"controller": expert}})
	return nil
}

// Deny refuses the pending control request.
func (s *Session) Deny(reason string) error {
	s.mu.Lock()
	if s.pendingControl == "" {
		s.mu.Unlock()
		return errors.New("mcphost: no pending control request")
	}
	expert := s.pendingControl
	s.pendingControl = ""
	s.mu.Unlock()
	_ = s.link.SendTo(expert, protocol.TypeControlDeny, protocol.ControlDeny{
		SessionID:  s.cfg.SessionID,
		ExpertName: expert,
		Reason:     reason,
	})
	s.event(fmt.Sprintf("control denied for %s", expert))
	s.pushInbox(InboxItem{Type: "control_state", From: expert, Text: fmt.Sprintf("control denied for %s", expert),
		Data: map[string]any{"controller": ""}})
	return nil
}

// Yield reclaims control from the expert back to the novice.
func (s *Session) Yield() {
	s.mu.Lock()
	prev := s.controller
	s.controller = ""
	s.mu.Unlock()
	if prev != "" {
		_ = s.link.SendTo(prev, protocol.TypeControlYield, protocol.ControlYield{
			SessionID:  s.cfg.SessionID,
			ExpertName: prev,
		})
		s.event("control reclaimed from " + prev)
		s.pushInbox(InboxItem{Type: "control_state", From: prev, Text: "control returned to the novice",
			Data: map[string]any{"controller": ""}})
	}
}

// onControlYield handles the controller releasing control themselves.
func (s *Session) onControlYield(msg protocol.Message) {
	raw, ok := s.link.Decrypt(msg.From, msg.Payload)
	if !ok {
		return
	}
	var y protocol.ControlYield
	if json.Unmarshal(raw, &y) != nil {
		return
	}
	s.mu.Lock()
	if s.controller != "" && s.controller == msg.From {
		s.controller = ""
		s.mu.Unlock()
		s.event("control returned by " + msg.From)
		s.pushInbox(InboxItem{Type: "control_state", From: msg.From, Text: msg.From + " yielded control",
			Data: map[string]any{"controller": ""}})
	} else {
		s.mu.Unlock()
	}
}

// Kick drops the expert from the session. Control returns to the novice
// and pending approvals fail closed.
func (s *Session) Kick(expert, reason string) {
	s.mu.Lock()
	if s.controller == expert {
		s.controller = ""
	}
	if s.pendingControl == expert {
		s.pendingControl = ""
	}
	delete(s.peers, expert)
	s.mu.Unlock()
	s.link.Forget(expert)
	s.cancelApprovals()
	_ = s.link.SendPlain(protocol.TypePeerKick, protocol.PeerKick{
		SessionID:  s.cfg.SessionID,
		ExpertName: expert,
		Reason:     reason,
	}, "")
	s.event("kicked " + expert)
	s.pushInbox(InboxItem{Type: "peer_left", From: expert, Text: fmt.Sprintf("%s was removed", expert)})
}

// cancelApprovals fails every pending approval closed. The kill switch
// always wins over a waiting prompt.
func (s *Session) cancelApprovals() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.approvals))
	for id := range s.approvals {
		ids = append(ids, id)
	}
	s.pendingRestore = nil
	s.mu.Unlock()
	for _, id := range ids {
		s.failApproval(id, "session ended")
	}
}

// onExpertChat drops an expert message into the agent inbox.
func (s *Session) onExpertChat(msg protocol.Message) {
	raw, ok := s.link.Decrypt(msg.From, msg.Payload)
	if !ok {
		return
	}
	var chat protocol.ExpertChat
	if json.Unmarshal(raw, &chat) != nil || strings.TrimSpace(chat.Text) == "" {
		return
	}
	s.event(fmt.Sprintf("chat from %s: %q", msg.From, chat.Text))
	s.pushInbox(InboxItem{Type: "expert_chat", From: msg.From, Text: chat.Text,
		Data: map[string]any{"expert": msg.From}})
}

// onExecRequest runs a controller shell command, bounded. Only the
// controller's requests run; anything else is dropped. Every run is
// reported to the agent inbox, so exec is novice-visible.
func (s *Session) onExecRequest(msg protocol.Message) {
	raw, ok := s.link.Decrypt(msg.From, msg.Payload)
	if !ok {
		return
	}
	var req protocol.ExecRequest
	if json.Unmarshal(raw, &req) != nil || req.ID == "" {
		return
	}
	s.mu.Lock()
	controller := s.controller
	s.mu.Unlock()
	if controller == "" || msg.From != controller {
		s.event(fmt.Sprintf("exec from %s dropped: not the controller", msg.From))
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		_ = s.link.SendTo(msg.From, protocol.TypeExecOutput, protocol.ExecOutput{
			SessionID: s.cfg.SessionID,
			ID:        req.ID,
			Stderr:    "empty command",
			ExitCode:  -1,
		})
		return
	}
	select {
	case s.execSem <- struct{}{}:
	default:
		_ = s.link.SendTo(msg.From, protocol.TypeExecOutput, protocol.ExecOutput{
			SessionID: s.cfg.SessionID,
			ID:        req.ID,
			Stderr:    "too many concurrent execs",
			ExitCode:  -1,
		})
		return
	}
	go func() {
		defer func() { <-s.execSem }()
		timeout := time.Duration(req.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = protocol.DefaultExecTimeoutSec * time.Second
		}
		if timeout > maxExecTimeout {
			timeout = maxExecTimeout
		}
		res := runBounded(s.checkpoints.WorkDir(), req.Command, timeout, protocol.MaxExecOutputBytes)
		out := protocol.ExecOutput{
			SessionID: s.cfg.SessionID,
			ID:        req.ID,
			Stdout:    res.stdout,
			Stderr:    res.stderr,
			ExitCode:  res.exitCode,
			Truncated: res.truncated,
		}
		if res.timedOut {
			out.Stderr += "\n[backseat] command killed after timeout"
			out.Truncated = true
		}
		_ = s.link.SendTo(msg.From, protocol.TypeExecOutput, out)
		cmd := req.Command
		if len(cmd) > 160 {
			cmd = cmd[:160] + "…"
		}
		s.event(fmt.Sprintf("exec by %s exited %d: %s", msg.From, res.exitCode, cmd))
		s.pushInbox(InboxItem{Type: "exec", From: msg.From,
			Text: fmt.Sprintf("%s ran a shell command (exit %d): %s", msg.From, res.exitCode, cmd),
			Data: map[string]any{
				"expert":    msg.From,
				"command":   req.Command,
				"exit_code": res.exitCode,
				"truncated": out.Truncated,
			}})
	}()
}

// sweepLoop expires expert rewind requests the novice never confirms.
func (s *Session) sweepLoop() {
	defer s.wg.Done()
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.terminated:
			return
		case <-t.C:
			s.mu.Lock()
			if s.pendingRestore != nil && time.Since(s.pendingRestore.requested) > restoreConfirmTTL {
				pr := s.pendingRestore
				s.pendingRestore = nil
				s.mu.Unlock()
				s.broadcastCheckpointEvent("restore_expired", pr.label, "novice did not confirm in time", "", "")
				s.event(fmt.Sprintf("rewind to %q expired without novice confirmation", pr.label))
			} else {
				s.mu.Unlock()
			}
		}
	}
}

// Controller reports who holds control: "" means the novice.
func (s *Session) Controller() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.controller
}

// PendingControl reports the expert awaiting a grant/deny.
func (s *Session) PendingControl() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingControl
}

// EnrolledNames lists enrolled experts.
func (s *Session) EnrolledNames() []string { return s.link.EnrolledNames() }

// Status reports the session state for backseat__session_status.
func (s *Session) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	cps := s.checkpoints.List()
	labels := make([]string, 0, len(cps))
	for _, cp := range cps {
		labels = append(labels, cp.Label)
	}
	return Status{
		SessionID:        s.cfg.SessionID,
		Controller:       s.controller,
		PendingControl:   s.pendingControl,
		Experts:          s.link.EnrolledNames(),
		InviteExpiresAt:  s.inviteExpiry.Unix(),
		InviteBurned:     s.inviteBurned,
		Checkpoints:      labels,
		PendingApprovals: len(s.approvals),
		EventsPublished:  s.events.Load(),
	}
}

// End terminates the session for everyone and tears down locally.
func (s *Session) End(reason string) {
	s.endOnce.Do(func() {
		s.cancelApprovals()
		_ = s.link.SendPlain(protocol.TypeSessionEnd, protocol.SessionEnd{
			SessionID: s.cfg.SessionID,
			Reason:    reason,
		}, "")
	})
	s.shutdown()
	s.wg.Wait()
}

// shutdown closes the relay connection; loops exit on their own.
func (s *Session) shutdown() {
	s.shutOnce.Do(func() {
		s.link.Close()
		close(s.terminated)
	})
}

// Wait blocks until the session has fully shut down.
func (s *Session) Wait() { s.wg.Wait() }

// Done fires when the session shuts down.
func (s *Session) Done() <-chan struct{} { return s.terminated }
