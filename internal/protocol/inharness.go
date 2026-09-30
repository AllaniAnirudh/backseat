// In-harness protocol additions (v0.3 milestone).
//
// The in-harness design extends the v0.2 relay protocol without replacing
// it: every new message rides the existing encrypted envelopes (HMAC
// enrollment, HKDF AES-256-GCM), routing metadata stays plaintext, and all
// v0.2 types keep decoding byte-for-byte. New in-harness payloads live in
// this file; a few v0.2 structs were extended with additive omitempty
// fields in message.go (ApprovalRequest, CheckpointEvent) instead of being
// duplicated, so old and new clients interoperate on the same type names.
package protocol

// v0.3 message type names (in-harness milestone).
const (
	TypeExpertChat       = "expert_chat"
	TypeExecRequest      = "exec_request"
	TypeExecOutput       = "exec_output"
	TypeApprovalDecision = "approval_decision"
)

// Bounds for the shell side-channel. The host (MCP server) enforces them;
// the protocol only documents the contract so every client renders the
// same limits.
const (
	// DefaultExecTimeoutSec applies when ExecRequest.TimeoutSec is 0.
	DefaultExecTimeoutSec = 30
	// MaxExecOutputBytes caps the combined stdout+stderr bytes a host may
	// send in one ExecOutput. Longer output is truncated and flagged.
	MaxExecOutputBytes = 64 * 1024
)

// ExpertChat carries a chat message from the expert to the novice's agent.
// The MCP server drops it into the agent inbox surfaced via
// backseat__poll. This is the primary in-harness "fix anything" loop.
type ExpertChat struct {
	SessionID  string `json:"session_id"`
	ExpertName string `json:"expert_name,omitempty"`
	Text       string `json:"text"`
}

// ExecRequest asks the host (MCP server) to run a shell command in the
// session working directory. Controller-only, explicitly granted, logged,
// and novice-visible per the trust rules. Never sent before the controller
// grant; the host rejects it otherwise.
type ExecRequest struct {
	SessionID  string `json:"session_id"`
	ID         string `json:"id"` // caller-chosen correlation id, echoed in ExecOutput
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec,omitempty"` // 0 means DefaultExecTimeoutSec
}

// ExecOutput reports the result of one ExecRequest. The host truncates
// stdout+stderr to MaxExecOutputBytes total and sets Truncated when it
// does; the client must show the truncation so output is never silently
// cut.
type ExecOutput struct {
	SessionID string `json:"session_id"`
	ID        string `json:"id"` // matches ExecRequest.ID
	Stdout    string `json:"stdout,omitempty"`
	Stderr    string `json:"stderr,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Decision values for ApprovalDecision.Decision.
const (
	ApprovalApprove = "approve"
	ApprovalDeny    = "deny"
)

// ApprovalDecision is the structured in-harness approval answer.
//
// Compat choice: the v0.2 TypeApprovalResponse ("approval_response") is
// kept byte-for-byte for the PTY path, including its expert->host decision
// and host->experts broadcast (Responder/Broadcast) semantics. A new type
// was added here rather than extending ApprovalResponse because the MCP
// path answers a different question: no PTY answer bytes are written, the
// decision is an enum string, DecidedBy names the decider, and the request
// TTL travels with the decision so the MCP server can reject stale
// answers. The two types are not interchangeable; the MCP server bridges
// between them when a session mixes PTY and in-harness clients.
type ApprovalDecision struct {
	SessionID  string `json:"session_id"`
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"` // ApprovalApprove or ApprovalDeny
	DecidedBy  string `json:"decided_by"`
	DecidedAt  int64  `json:"decided_at"`           // unix seconds
	ExpiresAt  int64  `json:"expires_at,omitempty"` // echoes the request deadline for staleness checks
}
