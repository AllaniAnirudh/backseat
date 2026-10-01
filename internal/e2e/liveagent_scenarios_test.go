// Live multi-scenario test: one real `opencode` agent driven through the
// full Backseat protocol. No model calls here (except the optional approval
// probe at the end); every scenario below is deterministic against the
// live TUI.
//
// Scenarios: multi-viewer enrollment, control grant, non-controller input
// gating, control deny, yield + handoff to a second expert, driving as the
// new controller, kick, checkpoint/rewind under a live agent, session end.
package e2e

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/gorilla/websocket"
)

func liveDrive(t *testing.T, conn *websocket.Conn, keys pairing.Keys, name, text string) {
	t.Helper()
	sendEncrypted(t, conn, keys.ExpertToHost, name, protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte(text)),
	})
}

// liveAwaitText scans one expert's incoming stream until text appears in
// decrypted PTY output (or failText shows up first, or the deadline hits).
func liveAwaitText(t *testing.T, conn *websocket.Conn, keys pairing.Keys, want, failText string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msg := readEnvelope(t, conn, time.Until(deadline))
		if msg.Type != protocol.TypeTermOutput {
			continue
		}
		out := decodeOutput(t, msg, keys.HostToExpert)
		if failText != "" && strings.Contains(out, failText) {
			t.Fatalf("forbidden text %q appeared in PTY output", failText)
		}
		if strings.Contains(out, want) {
			return
		}
	}
	t.Fatalf("timed out waiting for %q in PTY output", want)
}

func TestLiveOpenCodeScenarios(t *testing.T) {
	if os.Getenv("BACKSEAT_LIVE_AGENT_TEST") == "" {
		t.Skip("live agent test: set BACKSEAT_LIVE_AGENT_TEST=1")
	}
	agentBin := findOpenCode(t)
	workDir := t.TempDir()

	wsURL := startTestRelay(t)
	stage("S0 relay up; booting one live opencode agent for the scenario matrix")
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	var autoGrant atomic.Bool
	autoGrant.Store(true)
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "opencode",
		AgentCmd:  []string{agentBin},
		WorkDir:   workDir,
		Decide:    func(protocol.ControlRequest) bool { return autoGrant.Load() },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("live scenarios cleanup")

	expert1, keys1 := enrollExpertHarness(t, wsURL, "expert1", secret, "opencode")
	expert2, keys2 := enrollExpertHarness(t, wsURL, "expert2", secret, "opencode")
	waitFor(t, 10*time.Second, func() bool { return h.Enrolled("expert1") && h.Enrolled("expert2") }, "both experts enrolled")

	// S1: multi-viewer. Both experts see the live TUI render.
	stage("S1 multi-viewer: both experts watch the live TUI")
	awaitTuiReady(t, expert1, keys1, 60*time.Second)
	awaitTuiReady(t, expert2, keys2, 60*time.Second)
	stage("S1 ok: expert1 and expert2 both render the agent")

	// S2: expert1 takes control (auto-grant).
	stage("S2 control grant to expert1")
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID: sessionID, ExpertName: "expert1",
	})
	readUntil(t, expert1, 10*time.Second, protocol.TypeControlGrant)
	waitFor(t, 10*time.Second, func() bool { return h.Controller() == "expert1" }, "controller expert1")
	stage("S2 ok: expert1 holds control")

	// S3: input gating. expert2 has no control: its keystrokes must never
	// reach the PTY. expert1's marker proves the channel is live, so a
	// missing intruder marker is signal, not silence. No newlines: nothing
	// is submitted to the model.
	stage("S3 input gating: expert2 (no control) types, must be dropped")
	liveDrive(t, expert2, keys2, "expert2", "ZZINTRUDER999")
	liveDrive(t, expert1, keys1, "expert1", "ZZMARKER111")
	liveAwaitText(t, expert2, keys2, "ZZMARKER111", "ZZINTRUDER999", 10*time.Second)
	stage("S3 ok: intruder input dropped, controller input flowed")

	// S4: deny. Flip the decider off; expert2's request is refused and the
	// controller does not change.
	stage("S4 control deny for expert2")
	autoGrant.Store(false)
	sendEncrypted(t, expert2, keys2.ExpertToHost, "expert2", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID: sessionID, ExpertName: "expert2",
	})
	denyMsg := readUntil(t, expert2, 10*time.Second, protocol.TypeControlDeny)
	var deny protocol.ControlDeny
	openPayload(t, denyMsg, keys2.HostToExpert, &deny)
	if h.Controller() != "expert1" {
		t.Fatalf("controller changed on deny: %q", h.Controller())
	}
	autoGrant.Store(true)
	stage("S4 ok: deny received, expert1 still driving")

	// S5: yield + handoff. expert1 yields, expert2 takes over.
	stage("S5 yield by expert1, handoff to expert2")
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeControlYield, protocol.ControlYield{
		SessionID: sessionID, ExpertName: "expert1",
	})
	waitFor(t, 10*time.Second, func() bool { return h.Controller() == "" }, "controller released")
	sendEncrypted(t, expert2, keys2.ExpertToHost, "expert2", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID: sessionID, ExpertName: "expert2",
	})
	readUntil(t, expert2, 10*time.Second, protocol.TypeControlGrant)
	waitFor(t, 10*time.Second, func() bool { return h.Controller() == "expert2" }, "controller expert2")
	stage("S5 ok: expert2 now holds control")

	// S6: drive as the new controller; the watching expert sees it land.
	stage("S6 expert2 drives; expert1 watches it land")
	liveDrive(t, expert2, keys2, "expert2", "ZZHANDOFF222")
	liveAwaitText(t, expert1, keys1, "ZZHANDOFF222", "", 10*time.Second)
	stage("S6 ok: handoff drive confirmed on the wire")

	// S7: kick. expert1 is dropped; its connection dies.
	stage("S7 kick expert1")
	h.Kick("expert1", "scenario kick")
	deadline := time.Now().Add(10 * time.Second)
	kicked := false
	for time.Now().Before(deadline) && !kicked {
		_ = expert1.SetReadDeadline(deadline)
		var msg protocol.Message
		if err := expert1.ReadJSON(&msg); err != nil {
			kicked = true // connection closed
			break
		}
		if msg.Type == protocol.TypePeerKick {
			kicked = true
		}
	}
	if !kicked {
		t.Fatal("expert1 was not kicked")
	}
	waitFor(t, 10*time.Second, func() bool { return !h.Enrolled("expert1") }, "expert1 unenrolled")
	stage("S7 ok: expert1 kicked and unenrolled")

	// S8: checkpoint + rewind under the live agent. Snapshot, add a file,
	// restore, prove the file is gone and prior state is intact.
	stage("S8 checkpoint + rewind with the live agent running")
	if err := os.WriteFile(filepath.Join(workDir, "keep.txt"), []byte("KEEP"), 0o644); err != nil {
		t.Fatal(err)
	}
	cp, err := h.Checkpoint("live-scenario")
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "rewind-me.txt"), []byte("TEMP"), 0o644); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range h.ListCheckpoints() {
		if c.Label == cp.Label {
			found = true
		}
	}
	if !found {
		t.Fatal("checkpoint missing from list")
	}
	if err := h.RestoreCheckpoint(cp.Label); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workDir, "rewind-me.txt")); !os.IsNotExist(err) {
		t.Fatal("rewind did not remove the new file")
	}
	keep, err := os.ReadFile(filepath.Join(workDir, "keep.txt"))
	if err != nil || string(keep) != "KEEP" {
		t.Fatalf("rewind damaged prior state: %v %q", err, keep)
	}
	stage("S8 ok: checkpoint listed, rewind removed the new file, prior state intact")

	// S9: session end reaches the remaining expert.
	stage("S9 session end")
	h.End("live scenarios done")
	endMsg := readUntil(t, expert2, 10*time.Second, protocol.TypeSessionEnd)
	var gotEnd protocol.SessionEnd
	if err := endMsg.Decode(&gotEnd); err != nil || gotEnd.Reason != "live scenarios done" {
		t.Fatalf("bad session_end: %v %+v", err, gotEnd)
	}
	stage("S9 ok: expert2 got session_end; matrix complete")
}
