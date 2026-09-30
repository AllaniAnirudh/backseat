package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

// roundTrip marshals v through a Message envelope and decodes it back,
// returning the decoded value.
func roundTrip(t *testing.T, msgType string, v, out any) {
	t.Helper()
	m, err := New(msgType, "msg-1", 1780000000, v)
	if err != nil {
		t.Fatalf("New(%s): %v", msgType, err)
	}
	if m.Type != msgType {
		t.Fatalf("envelope type = %q, want %q", m.Type, msgType)
	}
	if err := m.Decode(out); err != nil {
		t.Fatalf("Decode(%s): %v", msgType, err)
	}
	if !reflect.DeepEqual(v, out) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, v)
	}
}

func TestExpertChatRoundTrip(t *testing.T) {
	in := &ExpertChat{SessionID: "s1", ExpertName: "dee", Text: "try checking the migration order first"}
	out := &ExpertChat{}
	roundTrip(t, TypeExpertChat, in, out)
}

func TestExecRequestRoundTrip(t *testing.T) {
	in := &ExecRequest{SessionID: "s1", ID: "exec-7", Command: "go test ./...", TimeoutSec: 60}
	out := &ExecRequest{}
	roundTrip(t, TypeExecRequest, in, out)
}

func TestExecRequestDefaultTimeout(t *testing.T) {
	in := &ExecRequest{SessionID: "s1", ID: "exec-8", Command: "ls"}
	out := &ExecRequest{}
	roundTrip(t, TypeExecRequest, in, out)
	if out.TimeoutSec != 0 {
		t.Fatalf("TimeoutSec = %d, want 0 (host applies DefaultExecTimeoutSec)", out.TimeoutSec)
	}
}

func TestExecOutputRoundTrip(t *testing.T) {
	in := &ExecOutput{SessionID: "s1", ID: "exec-7", Stdout: "ok\n", Stderr: "warn\n", ExitCode: 0, Truncated: true}
	out := &ExecOutput{}
	roundTrip(t, TypeExecOutput, in, out)
}

func TestApprovalDecisionRoundTrip(t *testing.T) {
	in := &ApprovalDecision{
		SessionID:  "s1",
		ApprovalID: "a1",
		Decision:   ApprovalApprove,
		DecidedBy:  "dee",
		DecidedAt:  1780000001,
		ExpiresAt:  1780000120,
	}
	out := &ApprovalDecision{}
	roundTrip(t, TypeApprovalDecision, in, out)
}

func TestApprovalRequestStructuredRoundTrip(t *testing.T) {
	in := &ApprovalRequest{
		SessionID:  "s1",
		ApprovalID: "a1",
		Tool:       "bash",
		Summary:    "run migrations",
		Prompt:     "Allow the agent to run: migrate up?",
		Options:    []string{"approve", "deny", "approve-once"},
		TimeoutSec: 120,
		ExpiresAt:  1780000120,
	}
	out := &ApprovalRequest{}
	roundTrip(t, TypeApprovalRequest, in, out)
}

// TestApprovalRequestV02BackwardCompat decodes a literal v0.2-encoded
// approval_request payload and requires it to decode to exactly the same
// struct values as before the v0.3 field additions.
func TestApprovalRequestV02BackwardCompat(t *testing.T) {
	raw := []byte(`{"session_id":"s1","approval_id":"a1","tool":"bash","summary":"run tests","command":"go test ./...","prompt":"Allow running: go test ./...?","approve_label":"Allow","deny_label":"Deny","expires_at":1780000000}`)
	var got ApprovalRequest
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal v0.2 payload: %v", err)
	}
	want := ApprovalRequest{
		SessionID:    "s1",
		ApprovalID:   "a1",
		Tool:         "bash",
		Summary:      "run tests",
		Command:      "go test ./...",
		Prompt:       "Allow running: go test ./...?",
		ApproveLabel: "Allow",
		DenyLabel:    "Deny",
		ExpiresAt:    1780000000,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v0.2 decode mismatch:\n got %+v\nwant %+v", got, want)
	}
	if got.Options != nil || got.TimeoutSec != 0 {
		t.Fatalf("new fields not zero on v0.2 payload: %+v", got)
	}

	// Re-encoding a struct with only v0.2 fields set must produce the
	// identical bytes: additive omitempty fields change nothing.
	re, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(re) != string(raw) {
		t.Fatalf("byte mismatch:\n got %s\nwant %s", re, raw)
	}
}

// TestCheckpointEventV02BackwardCompat pins the v0.2 checkpoint_event
// encoding while exercising the new v0.3 snapshot fields.
func TestCheckpointEventV02BackwardCompat(t *testing.T) {
	raw := []byte(`{"session_id":"s1","action":"created","label":"pre-migrate","message":"ok"}`)
	var v02 CheckpointEvent
	if err := json.Unmarshal(raw, &v02); err != nil {
		t.Fatalf("unmarshal v0.2 payload: %v", err)
	}
	if v02.SnapshotID != "" || v02.TranscriptMarker != "" {
		t.Fatalf("new fields not zero on v0.2 payload: %+v", v02)
	}
	re, err := json.Marshal(v02)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(re) != string(raw) {
		t.Fatalf("byte mismatch:\n got %s\nwant %s", re, raw)
	}

	v03 := &CheckpointEvent{
		SessionID:        "s1",
		Action:           "created",
		Label:            "pre-migrate",
		SnapshotID:       "snap-9",
		TranscriptMarker: "[checkpoint pre-migrate]",
	}
	out := &CheckpointEvent{}
	roundTrip(t, TypeCheckpointEvent, v03, out)
}

// TestTranscriptEventMCPMetaPath checks that the MCP publish_event shape
// (type/text/meta) maps onto the existing TranscriptEvent without new
// fields: type -> Kind, meta -> Fields.
func TestTranscriptEventMCPMetaPath(t *testing.T) {
	raw := []byte(`{"session_id":"s1","harness":"mcp","kind":"tool_call","text":"ran go test","fields":{"tool":"bash","summary":"go test ./..."}}`)
	var got TranscriptEvent
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Kind != "tool_call" || got.Text != "ran go test" {
		t.Fatalf("kind/text mismatch: %+v", got)
	}
	if got.Fields["tool"] != "bash" || got.Fields["summary"] != "go test ./..." {
		t.Fatalf("meta fields mismatch: %+v", got.Fields)
	}
	out := &TranscriptEvent{}
	roundTrip(t, TypeTranscriptEvent, &got, out)
}
