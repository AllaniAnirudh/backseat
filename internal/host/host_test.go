package host

import (
	"testing"
	"time"
)

// TestApprovalDecisionBridgesToPTYBytes exercises the in-harness
// approval_decision bridge at the decision layer: takeApproval validates
// and consumes the pending prompt, and the caller maps approve/deny to
// the pattern's PTY answer bytes. No PTY or relay is needed.
func TestApprovalDecisionBridgesToPTYBytes(t *testing.T) {
	h := &Host{
		approvals: map[string]*pendingApproval{
			"a1": {id: "a1", prompt: "run it? [y/n]", approve: []byte("y\n"), deny: []byte("n\n"), createdAt: time.Now()},
			"a2": {id: "a2", prompt: "format? [y/n]", approve: []byte("y\n"), deny: []byte("n\n"), createdAt: time.Now()},
			"a3": {id: "a3", prompt: "stale? [y/n]", approve: []byte("y\n"), deny: []byte("n\n"), createdAt: time.Now().Add(-3 * time.Minute)},
		},
	}
	// Approve maps to the pattern's approve bytes and consumes the entry.
	appr, ok := h.takeApproval("alice", "a1")
	if !ok || appr.id != "a1" || string(appr.approve) != "y\n" {
		t.Fatalf("takeApproval(a1) = %+v, %v", appr, ok)
	}
	if _, ok := h.takeApproval("alice", "a1"); ok {
		t.Error("approval answered twice")
	}
	// Non-controller cannot answer while someone else drives.
	h.controller = "bob"
	if _, ok := h.takeApproval("alice", "a2"); ok {
		t.Error("non-controller answered a pending approval")
	}
	// Deny maps to the deny bytes.
	appr, ok = h.takeApproval("bob", "a2")
	if !ok || string(appr.deny) != "n\n" {
		t.Fatalf("takeApproval(a2) by controller = %+v, %v", appr, ok)
	}
	// Expired prompts never answer.
	h.controller = ""
	if _, ok := h.takeApproval("alice", "a3"); ok {
		t.Error("expired approval answered")
	}
	// Unknown ids never answer.
	if _, ok := h.takeApproval("alice", "nope"); ok {
		t.Error("unknown approval answered")
	}
}

// TestConfirmRewindPastDeadlineRefused parks a rewind, lets the deadline
// pass (shrunk for the test), and confirms: refused, fail closed.
func TestConfirmRewindPastDeadlineRefused(t *testing.T) {
	old := restoreConfirmTTL
	restoreConfirmTTL = time.Millisecond
	t.Cleanup(func() { restoreConfirmTTL = old })

	h := &Host{
		approvals:      make(map[string]*pendingApproval),
		pendingRestore: &pendingRestoreReq{expert: "alice", label: "cp1", requested: time.Now()},
	}
	time.Sleep(5 * time.Millisecond)
	if err := h.ConfirmRewind(); err == nil {
		t.Fatal("ConfirmRewind past the deadline should be refused")
	}
}
