// Package protocol defines the JSON wire protocol spoken between the
// backseat host daemon, the relay server, and expert clients.
//
// Every frame on the WebSocket is a Message envelope carrying one typed
// payload. Payloads are encrypted end to end between host and expert when
// pairing has completed; the relay only routes opaque envelopes.
package protocol

import "encoding/json"

// Message type names.
const (
	TypeSessionAnnounce   = "session_announce"
	TypePairingInvite     = "pairing_invite"
	TypePairingEnroll     = "pairing_enroll"
	TypeControlRequest    = "control_request"
	TypeControlGrant      = "control_grant"
	TypeControlDeny       = "control_deny"
	TypeControlYield      = "control_yield"
	TypeControlForce      = "control_force"
	TypeTermInput         = "term_input"
	TypeTermOutput        = "term_output"
	TypeTranscriptEvent   = "transcript_event"
	TypeApprovalRequest   = "approval_request"
	TypeApprovalResponse  = "approval_response"
	TypeCheckpointCreate  = "checkpoint_create"
	TypeCheckpointRestore = "checkpoint_restore"
	TypeSessionEnd        = "session_end"
)

// Message is the envelope for every protocol frame.
type Message struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Timestamp int64           `json:"ts"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// New builds a Message with the payload marshalled to JSON.
func New(msgType, id string, ts int64, payload any) (Message, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Type: msgType, ID: id, Timestamp: ts, Payload: raw}, nil
}

// Decode unmarshals the payload into v.
func (m Message) Decode(v any) error {
	return json.Unmarshal(m.Payload, v)
}

// SessionAnnounce is sent by the host when a session goes live.
type SessionAnnounce struct {
	SessionID string `json:"session_id"`
	HostName  string `json:"host_name"`
	Harness   string `json:"harness"` // e.g. "claude", "copilot", "opencode", "aider"
	AgentCmd  string `json:"agent_cmd"`
}

// PairingInvite carries a fresh one-time invitation for an expert.
type PairingInvite struct {
	SessionID string `json:"session_id"`
	InviteID  string `json:"invite_id"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds
}

// PairingEnroll carries one step of the two-phase HMAC enrollment.
type PairingEnroll struct {
	SessionID string `json:"session_id"`
	InviteID  string `json:"invite_id"`
	Phase     int    `json:"phase"`               // 1 = host challenge, 2 = expert response
	Challenge string `json:"challenge,omitempty"` // base64, phase 1
	Response  string `json:"response,omitempty"`  // base64 HMAC, phase 2
}

// ControlRequest asks the novice to hand over control of the session.
type ControlRequest struct {
	SessionID  string `json:"session_id"`
	ExpertName string `json:"expert_name"`
	Note       string `json:"note,omitempty"`
}

// ControlGrant hands control to the requesting expert.
type ControlGrant struct {
	SessionID  string `json:"session_id"`
	ExpertName string `json:"expert_name"`
}

// ControlDeny refuses a control request.
type ControlDeny struct {
	SessionID  string `json:"session_id"`
	ExpertName string `json:"expert_name"`
	Reason     string `json:"reason,omitempty"`
}

// ControlYield releases control back to the novice.
type ControlYield struct {
	SessionID  string `json:"session_id"`
	ExpertName string `json:"expert_name"`
}

// ControlForce seizes control without a handshake. Only valid when the
// novice pre-authorized force-takeover for this session.
type ControlForce struct {
	SessionID     string `json:"session_id"`
	ExpertName    string `json:"expert_name"`
	PreAuthorized bool   `json:"pre_authorized"`
}

// TermInput is keystrokes from the current controller to the PTY.
type TermInput struct {
	SessionID string `json:"session_id"`
	Data      string `json:"data"` // base64-encoded bytes
}

// TermOutput is PTY output broadcast to all attached viewers.
type TermOutput struct {
	SessionID string `json:"session_id"`
	Data      string `json:"data"` // base64-encoded bytes
}

// TranscriptEvent is a parsed harness event from a transcript adapter.
type TranscriptEvent struct {
	SessionID string         `json:"session_id"`
	Harness   string         `json:"harness"`
	Kind      string         `json:"kind"` // prompt, tool_call, tool_result, approval, text
	Text      string         `json:"text"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// ApprovalRequest forwards an agent tool approval prompt to the expert.
type ApprovalRequest struct {
	SessionID  string `json:"session_id"`
	ApprovalID string `json:"approval_id"`
	Tool       string `json:"tool"`
	Summary    string `json:"summary"`
	Command    string `json:"command,omitempty"`
}

// ApprovalResponse carries the expert's one-tap decision.
type ApprovalResponse struct {
	SessionID  string `json:"session_id"`
	ApprovalID string `json:"approval_id"`
	Approved   bool   `json:"approved"`
}

// CheckpointCreate snapshots the session (git stash style) before risky work.
type CheckpointCreate struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label"`
}

// CheckpointRestore rewinds the session to a named checkpoint.
type CheckpointRestore struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label"`
}

// SessionEnd terminates the session and drops all attachments.
type SessionEnd struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}
