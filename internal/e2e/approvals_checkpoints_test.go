// Package e2e: approval-prompt forwarding and checkpoints/rewind over the
// encrypted channel, against the same in-process relay harness.
package e2e

import (
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/AllaniAnirudh/backseat/internal/relay"
)

// startTestRelay brings up an in-process relay and returns its ws URL.
func startTestRelay(t *testing.T) string {
	t.Helper()
	srv := relay.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(ln, srv)
	return "ws://" + ln.Addr().String() + "/ws"
}

// driveControl enrolls an expert and hands it control via auto-grant.
func driveControl(t *testing.T, wsURL string, h *host.Host, name string, secret [32]byte) (*websocket.Conn, pairing.Keys) {
	t.Helper()
	conn, keys := enrollExpert(t, wsURL, name, secret)
	sendEncrypted(t, conn, keys.ExpertToHost, name, protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  sessionID,
		ExpertName: name,
	})
	readUntil(t, conn, 5*time.Second, protocol.TypeControlGrant)
	waitFor(t, 5*time.Second, func() bool { return h.Controller() == name }, "controller "+name)
	return conn, keys
}

// readCheckpointEvent reads envelopes until the wanted checkpoint action
// arrives, decrypting with the expert's HostToExpert key.
func readCheckpointEvent(t *testing.T, conn *websocket.Conn, keys pairing.Keys, action string) protocol.CheckpointEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msg := readEnvelope(t, conn, time.Until(deadline))
		if msg.Type != protocol.TypeCheckpointEvent {
			continue
		}
		var ev protocol.CheckpointEvent
		openPayload(t, msg, keys.HostToExpert, &ev)
		if ev.Action == action {
			return ev
		}
	}
	t.Fatalf("timed out waiting for checkpoint event %q", action)
	return protocol.CheckpointEvent{}
}

func TestApprovalForwardAndAnswer(t *testing.T) {
	wsURL := startTestRelay(t)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Fake agent: prints an approval prompt when told.
	harness := "while IFS= read -r line; do\n" +
		"  case \"$line\" in\n" +
		"    PROMPT) printf 'Deploy to prod? [y/n] ';;\n" +
		"    *) printf 'echo:%s\\n' \"$line\";;\n" +
		"  esac\ndone\n"
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		AgentCmd:  []string{"sh", "-c", harness},
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	expert1, keys1 := driveControl(t, wsURL, h, "expert1", secret)
	expert2, keys2 := enrollExpert(t, wsURL, "expert2", secret)

	// Trigger the prompt on the PTY.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("PROMPT\n")),
	})
	// The controller gets the encrypted approval request.
	reqMsg := readUntil(t, expert1, 5*time.Second, protocol.TypeApprovalRequest)
	var req protocol.ApprovalRequest
	openPayload(t, reqMsg, keys1.HostToExpert, &req)
	if !strings.Contains(req.Prompt, "Deploy to prod?") {
		t.Fatalf("bad prompt: %+v", req)
	}
	if req.ApprovalID == "" || req.ApproveLabel == "" || req.DenyLabel == "" {
		t.Fatalf("missing fields: %+v", req)
	}
	if req.ExpiresAt*1000 <= time.Now().UnixMilli() {
		t.Fatalf("approval already expired: %+v", req)
	}

	// Approve it: the answer bytes must reach the PTY (echoed back).
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeApprovalResponse, protocol.ApprovalResponse{
		SessionID:  sessionID,
		ApprovalID: req.ApprovalID,
		Approved:   true,
	})
	deadline := time.Now().Add(5 * time.Second)
	sawY := false
	for time.Now().Before(deadline) && !sawY {
		msg := readEnvelope(t, expert1, time.Until(deadline))
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:y") {
			sawY = true
		}
	}
	if !sawY {
		t.Fatal("approved answer never reached the PTY")
	}

	// Every enrolled expert gets the broadcast dismissal.
	bcMsg := readUntil(t, expert2, 5*time.Second, protocol.TypeApprovalResponse)
	var bc protocol.ApprovalResponse
	openPayload(t, bcMsg, keys2.HostToExpert, &bc)
	if !bc.Broadcast || bc.ApprovalID != req.ApprovalID || bc.Responder != "expert1" || !bc.Approved {
		t.Fatalf("bad broadcast dismissal: %+v", bc)
	}

	// A replayed answer is dropped: no second echo of the answer.
	// (A read timeout here is the expected outcome.)
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeApprovalResponse, protocol.ApprovalResponse{
		SessionID:  sessionID,
		ApprovalID: req.ApprovalID,
		Approved:   true,
	})
	_ = expert1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		var msg protocol.Message
		if err := expert1.ReadJSON(&msg); err != nil {
			break // timeout: nothing else arrived, as expected
		}
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:y") {
			t.Fatal("replayed approval answer reached the PTY")
		}
	}
	_ = expert1.SetReadDeadline(time.Time{})
}

// TestApprovalCancelledWhenAgentMovesOn proves a forwarded prompt dies as
// soon as the agent's output moves past it: a late expert answer must not
// inject bytes into whatever the agent is asking next.
func TestApprovalCancelledWhenAgentMovesOn(t *testing.T) {
	wsURL := startTestRelay(t)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	harness := "while IFS= read -r line; do\n" +
		"  case \"$line\" in\n" +
		"    PROMPT) printf 'Deploy to prod? [y/n] ';;\n" +
		"    *) printf 'echo:%s\\n' \"$line\";;\n" +
		"  esac\ndone\n"
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		AgentCmd:  []string{"sh", "-c", harness},
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	expert1, keys1 := driveControl(t, wsURL, h, "expert1", secret)
	expert2, keys2 := enrollExpert(t, wsURL, "expert2", secret)

	// Forward a prompt.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("PROMPT\n")),
	})
	reqMsg := readUntil(t, expert1, 5*time.Second, protocol.TypeApprovalRequest)
	var req protocol.ApprovalRequest
	openPayload(t, reqMsg, keys1.HostToExpert, &req)

	// The agent moves on (answers itself / times out): more output.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("moving-on\n")),
	})
	// Wait for the echo so we know the host saw the new output.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msg := readEnvelope(t, expert1, time.Until(deadline))
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:moving-on") {
			break
		}
	}
	// Every expert gets the cancellation dismissal.
	bcMsg := readUntil(t, expert2, 5*time.Second, protocol.TypeApprovalResponse)
	var bc protocol.ApprovalResponse
	openPayload(t, bcMsg, keys2.HostToExpert, &bc)
	if !bc.Broadcast || bc.ApprovalID != req.ApprovalID {
		t.Fatalf("bad cancellation broadcast: %+v", bc)
	}

	// A late answer to the cancelled prompt injects nothing.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeApprovalResponse, protocol.ApprovalResponse{
		SessionID:  sessionID,
		ApprovalID: req.ApprovalID,
		Approved:   true,
	})
	_ = expert1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		var msg protocol.Message
		if err := expert1.ReadJSON(&msg); err != nil {
			break // timeout: nothing arrived, as expected
		}
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:y") {
			t.Fatal("late answer to a cancelled approval reached the PTY")
		}
	}
	_ = expert1.SetReadDeadline(time.Time{})
}

func TestCheckpointCreateRestore(t *testing.T) {
	wsURL := startTestRelay(t)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Git workdir: the primary snapshot path.
	workDir := t.TempDir()
	filePath := filepath.Join(workDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
		{"add", "-A"},
		{"commit", "-qm", "base"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", workDir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
	}

	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		WorkDir:   workDir,
		AgentCmd:  []string{"sh", "-c", `while IFS= read -r line; do printf 'echo:%s\n' "$line"; done`},
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	expert1, keys1 := driveControl(t, wsURL, h, "expert1", secret)

	// A non-controller cannot create checkpoints.
	expert2, keys2 := enrollExpert(t, wsURL, "expert2", secret)
	sendEncrypted(t, expert2, keys2.ExpertToHost, "expert2", protocol.TypeCheckpointCreate, protocol.CheckpointCreate{
		SessionID: sessionID,
		Label:     "nope",
	})
	ev := readCheckpointEvent(t, expert2, keys2, "failed")
	if !strings.Contains(ev.Message, "controller") {
		t.Fatalf("unexpected failure message: %+v", ev)
	}

	// Controller creates a checkpoint.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeCheckpointCreate, protocol.CheckpointCreate{
		SessionID: sessionID,
		Label:     "pre",
	})
	created := readCheckpointEvent(t, expert1, keys1, "created")
	if created.Label != "pre" {
		t.Fatalf("bad created event: %+v", created)
	}

	// Wreck the workdir, then request a rewind: the novice must confirm.
	if err := os.WriteFile(filePath, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(workDir, "newfile.txt")
	if err := os.WriteFile(newPath, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeCheckpointRestore, protocol.CheckpointRestore{
		SessionID: sessionID,
		Label:     "pre",
	})
	requested := readCheckpointEvent(t, expert1, keys1, "restore_requested")
	if requested.Label != "pre" {
		t.Fatalf("bad restore_requested event: %+v", requested)
	}
	// Files must NOT change before the novice confirms.
	if got := string(mustRead(t, filePath)); got != "changed\n" {
		t.Fatalf("file changed before novice confirmation: %q", got)
	}
	if err := h.ConfirmRewind(); err != nil {
		t.Fatalf("ConfirmRewind: %v", err)
	}
	restored := readCheckpointEvent(t, expert1, keys1, "restored")
	if restored.Label != "pre" {
		t.Fatalf("bad restored event: %+v", restored)
	}
	if got := string(mustRead(t, filePath)); got != "original\n" {
		t.Fatalf("file.txt = %q, want original", got)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("newfile.txt survived the rewind")
	}
}

func TestCheckpointRestoreDenied(t *testing.T) {
	wsURL := startTestRelay(t)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	filePath := filepath.Join(workDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		WorkDir:   workDir,
		AgentCmd:  []string{"sh", "-c", `while IFS= read -r line; do printf 'echo:%s\n' "$line"; done`},
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	expert1, keys1 := driveControl(t, wsURL, h, "expert1", secret)
	if _, err := h.Checkpoint("pre"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}

	// Request a rewind, then the novice vetoes it.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeCheckpointRestore, protocol.CheckpointRestore{
		SessionID: sessionID,
		Label:     "pre",
	})
	readCheckpointEvent(t, expert1, keys1, "restore_requested")
	if err := os.WriteFile(filePath, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.DenyRewind("novice said no"); err != nil {
		t.Fatalf("DenyRewind: %v", err)
	}
	denied := readCheckpointEvent(t, expert1, keys1, "restore_denied")
	if denied.Label != "pre" {
		t.Fatalf("bad restore_denied event: %+v", denied)
	}
	if got := string(mustRead(t, filePath)); got != "changed\n" {
		t.Fatalf("file.txt = %q, want changed (veto must not rewind)", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestApprovalFlushedOnLateEnroll proves a prompt detected before any
// expert enrolled is forwarded when an expert later joins, instead of
// sitting pending and invisible forever.
func TestApprovalFlushedOnLateEnroll(t *testing.T) {
	wsURL := startTestRelay(t)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	// Fake agent: prints the prompt immediately, before anyone enrolls.
	harness := "sleep 2; printf 'Deploy to prod? [y/n] '; sleep 30\n"
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		AgentCmd:  []string{"sh", "-c", harness},
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	// Wait until the host has detected the prompt with nobody to ask.
	waitFor(t, 5*time.Second, func() bool { return h.PendingApprovalCount() > 0 }, "pending approval")

	// Enroll late: the pending prompt must be flushed to the newcomer.
	conn, keys := enrollExpert(t, wsURL, "late", secret)
	reqMsg := readUntil(t, conn, 5*time.Second, protocol.TypeApprovalRequest)
	var req protocol.ApprovalRequest
	openPayload(t, reqMsg, keys.HostToExpert, &req)
	if !strings.Contains(req.Prompt, "Deploy to prod?") {
		t.Fatalf("bad prompt: %+v", req)
	}
	if req.ApprovalID == "" {
		t.Fatalf("missing approval id: %+v", req)
	}
}
