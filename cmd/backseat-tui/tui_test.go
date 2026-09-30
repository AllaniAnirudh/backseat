package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// fakeOutbound records the wire actions the model takes.
type fakeOutbound struct {
	decisions []fakeDecision
	chats     []string
	ckpts     []string
	restores  []string
	ctrlReq   int
	ctrlYield int
	execs     []string
}

type fakeDecision struct {
	id       string
	approved bool
}

func (f *fakeOutbound) decide(id string, _ protocol.ApprovalRequest, approved bool) {
	f.decisions = append(f.decisions, fakeDecision{id: id, approved: approved})
}
func (f *fakeOutbound) chat(text string)        { f.chats = append(f.chats, text) }
func (f *fakeOutbound) checkpoint(label string) { f.ckpts = append(f.ckpts, label) }
func (f *fakeOutbound) restore(label string)    { f.restores = append(f.restores, label) }
func (f *fakeOutbound) requestControl()         { f.ctrlReq++ }
func (f *fakeOutbound) yieldControl()           { f.ctrlYield++ }
func (f *fakeOutbound) exec(cmd string)         { f.execs = append(f.execs, cmd) }

func testModel() (*model, *fakeOutbound) {
	f := &fakeOutbound{}
	m := newModel(f, "sess-1", "tester")
	m.width, m.height = 100, 30
	m.layout()
	return m, f
}

func keyMsg(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func specialKey(t tea.KeyType) tea.KeyMsg {
	return tea.KeyMsg{Type: t}
}

func (m *model) applyKey(s string) {
	updated, _ := m.Update(keyMsg(s))
	*m = *updated.(*model)
}

func (m *model) applySpecial(t tea.KeyType) {
	updated, _ := m.Update(specialKey(t))
	*m = *updated.(*model)
}

func (m *model) applyEvent(ev clientEvent) {
	updated, _ := m.Update(clientEventMsg{ev: ev})
	*m = *updated.(*model)
}

func (m *model) applyTick(now time.Time) {
	updated, _ := m.Update(tickMsg(now))
	*m = *updated.(*model)
}

func TestApproveDenyKeys(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.onApprovalRequest(protocol.ApprovalRequest{
		SessionID: "sess-1", ApprovalID: "a1", Tool: "bash", Summary: "rm -rf /tmp/x",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	if len(m.approvals) != 1 {
		t.Fatalf("card not added: %+v", m.approvals)
	}
	m.applyKey("y")
	if len(f.decisions) != 1 || !f.decisions[0].approved || f.decisions[0].id != "a1" {
		t.Fatalf("approve not sent: %+v", f.decisions)
	}
	if len(m.approvals) != 0 {
		t.Fatal("card not dismissed after decision")
	}

	m.onApprovalRequest(protocol.ApprovalRequest{
		SessionID: "sess-1", ApprovalID: "a2", Summary: "write file",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	m.applyKey("n")
	if len(f.decisions) != 2 || f.decisions[1].approved {
		t.Fatalf("deny not sent: %+v", f.decisions)
	}
}

func TestApprovalExpiryFailClosed(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.onApprovalRequest(protocol.ApprovalRequest{
		SessionID: "sess-1", ApprovalID: "a1", Summary: "do it",
		ExpiresAt: time.Now().Add(-time.Second).Unix(), // already expired
	})
	// y must not answer an expired card, and the tick must drop it.
	m.applyKey("y")
	if len(f.decisions) != 0 {
		t.Fatalf("expired card was answered: %+v", f.decisions)
	}
	m.applyTick(time.Now())
	if len(m.approvals) != 0 {
		t.Fatal("expired card not removed by tick")
	}
}

func TestApprovalTTLCountdown(t *testing.T) {
	m, _ := testModel()
	m.onApprovalRequest(protocol.ApprovalRequest{
		SessionID: "sess-1", ApprovalID: "a1", Summary: "x",
		ExpiresAt: time.Now().Add(90 * time.Second).Unix(),
	})
	rem := m.approvals[0].remaining(time.Now())
	if rem < 80*time.Second || rem > 90*time.Second {
		t.Fatalf("countdown wrong: %v", rem)
	}
	view := m.View()
	if !strings.Contains(view, "1m") {
		t.Fatalf("countdown not rendered in view:\n%s", view)
	}
}

func TestApprovalDedupAndBroadcastDismiss(t *testing.T) {
	m, _ := testModel()
	ar := protocol.ApprovalRequest{SessionID: "sess-1", ApprovalID: "a1", Summary: "x",
		ExpiresAt: time.Now().Add(time.Minute).Unix()}
	m.onApprovalRequest(ar)
	m.onApprovalRequest(ar) // duplicate
	if len(m.approvals) != 1 {
		t.Fatalf("duplicate card added: %d", len(m.approvals))
	}
	// Another expert answers; broadcast dismisses the card.
	dec, _ := json.Marshal(protocol.ApprovalDecision{
		SessionID: "sess-1", ApprovalID: "a1",
		Decision: protocol.ApprovalApprove, DecidedBy: "other",
	})
	m.onMessage(protocol.Message{Type: protocol.TypeApprovalDecision}, dec)
	if len(m.approvals) != 0 {
		t.Fatal("broadcast decision did not dismiss the card")
	}
}

func TestDetailsToggle(t *testing.T) {
	m, _ := testModel()
	m.onApprovalRequest(protocol.ApprovalRequest{
		SessionID: "sess-1", ApprovalID: "a1", Tool: "bash",
		Command: "rm -rf /tmp/x", Prompt: "Run this?",
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
	})
	// Focus is on approvals, so ? toggles details.
	m.applyKey("?")
	if !m.approvals[0].details {
		t.Fatal("? did not toggle details in approvals focus")
	}
	view := m.View()
	if !strings.Contains(view, "rm -rf /tmp/x") {
		t.Fatalf("details not rendered:\n%s", view)
	}
	// In transcript focus ? opens help instead.
	m.focus = focusTranscript
	m.applyKey("?")
	if !m.help {
		t.Fatal("? did not open help in transcript focus")
	}
}

func TestChatInput(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.applyKey("/")
	if m.inputKind != inputChat {
		t.Fatal("chat input not opened")
	}
	for _, r := range "hello agent" {
		m.applyKey(string(r))
	}
	m.applySpecial(tea.KeyEnter)
	if len(f.chats) != 1 || f.chats[0] != "hello agent" {
		t.Fatalf("chat not sent: %+v", f.chats)
	}
	if m.inputKind != inputNone {
		t.Fatal("input not closed after send")
	}
	// Escape cancels.
	m.applyKey("/")
	m.applySpecial(tea.KeyEsc)
	if m.inputKind != inputNone {
		t.Fatal("esc did not cancel input")
	}
}

func TestCheckpointAndRewind(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.applyKey("c")
	for _, r := range "before-refactor" {
		m.applyKey(string(r))
	}
	m.applySpecial(tea.KeyEnter)
	if len(f.ckpts) != 1 || f.ckpts[0] != "before-refactor" {
		t.Fatalf("checkpoint not sent: %+v", f.ckpts)
	}

	// Checkpoint events feed the picker.
	ce, _ := json.Marshal(protocol.CheckpointEvent{
		SessionID: "sess-1", Action: "created", Label: "before-refactor",
	})
	m.onMessage(protocol.Message{Type: protocol.TypeCheckpointEvent}, ce)
	m.applyKey("r")
	if !m.picking {
		t.Fatal("picker not opened")
	}
	view := m.View()
	if !strings.Contains(view, "before-refactor") {
		t.Fatalf("checkpoint missing from picker:\n%s", view)
	}
	m.applySpecial(tea.KeyEnter) // select the checkpoint
	if m.pendingRestore != "before-refactor" {
		t.Fatalf("pending restore = %q", m.pendingRestore)
	}
	m.applyKey("y") // confirm
	if len(f.restores) != 1 || f.restores[0] != "before-refactor" {
		t.Fatalf("restore not sent: %+v", f.restores)
	}
}

func TestControlToggle(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.applyKey("g")
	if f.ctrlReq != 1 {
		t.Fatal("control request not sent")
	}
	grant, _ := json.Marshal(protocol.ControlGrant{SessionID: "sess-1", ExpertName: "tester"})
	m.onMessage(protocol.Message{Type: protocol.TypeControlGrant}, grant)
	if !m.driving {
		t.Fatal("not driving after grant")
	}
	m.applyKey("g")
	if f.ctrlYield != 1 || m.driving {
		t.Fatal("yield not sent")
	}
}

func TestExecNeedsControl(t *testing.T) {
	m, f := testModel()
	m.conn = connLive
	m.applyKey("x")
	if m.inputKind != inputNone {
		t.Fatal("exec input opened without control")
	}
	m.driving = true
	m.applyKey("x")
	if m.inputKind != inputExec {
		t.Fatal("exec input not opened while driving")
	}
	for _, r := range "ls" {
		m.applyKey(string(r))
	}
	m.applySpecial(tea.KeyEnter)
	if len(f.execs) != 1 || f.execs[0] != "ls" {
		t.Fatalf("exec not sent: %+v", f.execs)
	}
}

func TestTranscriptEventRendering(t *testing.T) {
	m, _ := testModel()
	te, _ := json.Marshal(protocol.TranscriptEvent{
		SessionID: "sess-1", Harness: "claude", Kind: "tool_call",
		Fields: map[string]any{"tool": "bash", "summary": "ls /tmp"},
	})
	m.onMessage(protocol.Message{Type: protocol.TypeTranscriptEvent}, te)
	if len(m.lines) != 1 || m.lines[0].kind != "tool" {
		t.Fatalf("tool_call not rendered inline: %+v", m.lines)
	}
	if !strings.Contains(m.lines[0].text, "bash") || !strings.Contains(m.lines[0].text, "ls /tmp") {
		t.Fatalf("tool line wrong: %q", m.lines[0].text)
	}

	te2, _ := json.Marshal(protocol.TranscriptEvent{
		SessionID: "sess-1", Kind: "text", Text: "working on it",
	})
	m.onMessage(protocol.Message{Type: protocol.TypeTranscriptEvent}, te2)
	if m.lines[1].text != "working on it" {
		t.Fatalf("text event wrong: %q", m.lines[1].text)
	}
}

func TestSessionEnd(t *testing.T) {
	m, _ := testModel()
	m.applyEvent(evSessionEnd{reason: "novice left"})
	if m.conn != connEnded {
		t.Fatal("conn not ended")
	}
	if !strings.Contains(m.View(), "session ended") {
		t.Fatal("end banner missing from view")
	}
}

func TestStatusBar(t *testing.T) {
	m, _ := testModel()
	m.conn = connLive
	m.driving = true
	m.latency = 14 * time.Millisecond
	view := m.View()
	for _, want := range []string{"DRIVING", "14ms", "sess-1"} {
		if !strings.Contains(view, want) {
			t.Fatalf("status bar missing %q:\n%s", want, view)
		}
	}
}

func TestWrapLine(t *testing.T) {
	out := wrapLine("aa bb cc dd ee ff", 11)
	if len(out) != 2 || out[0] != "aa bb cc dd" || out[1] != "ee ff" {
		t.Fatalf("wrap wrong: %q", out)
	}
	out = wrapLine("supercalifragilistic", 5)
	if len(out) == 0 {
		t.Fatal("long word produced no lines")
	}
}
