// Integration test for the v0.3 in-harness path: an mcphost.Session (the
// trusted host endpoint, no PTY) against an in-process relay, with a
// scripted expert completing the HMAC enrollment and exercising the full
// loop: control grant, expert chat, published transcript events with secret
// masking, structured approval, bounded exec, checkpoint, teardown.
package e2e

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/mcphost"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/AllaniAnirudh/backseat/internal/relay"
)

func TestInHarnessFlow(t *testing.T) {
	srv := relay.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, srv)
	wsURL := "ws://" + ln.Addr().String() + "/ws"

	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	workDir := t.TempDir()
	sess, err := mcphost.New(mcphost.Config{
		RelayURL:  wsURL,
		UIBase:    "https://expert.example",
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "agent",
		Harness:   "test",
		WorkDir:   workDir,
	})
	if err != nil {
		t.Fatalf("mcphost.New: %v", err)
	}
	defer sess.End("test cleanup")

	// The short code the agent prints must parse as a TUI join target and
	// carry the real secret (a hash fragment would be useless).
	code := sess.InviteCode()
	if !strings.HasPrefix(code, sessionID+"#") {
		t.Fatalf("InviteCode %q does not start with session id", code)
	}
	frag := strings.TrimPrefix(code, sessionID+"#")
	if _, err := pairing.ParseSecret("secret=" + frag); err != nil {
		t.Fatalf("InviteCode secret does not parse: %v", err)
	}

	// 1. Expert enrolls through the HMAC ceremony.
	expert, keys := enrollExpertHarness(t, wsURL, "expert1", secret, "test")

	// 2. Control request, then the novice grants out-of-band.
	sendEncrypted(t, expert, keys.ExpertToHost, "expert1", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	waitFor(t, 5*time.Second, func() bool {
		st := sess.Status()
		return st.PendingControl == "expert1"
	}, "pending control request")
	if err := sess.Grant(); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	grantMsg := readUntil(t, expert, 5*time.Second, protocol.TypeControlGrant)
	var gotGrant protocol.ControlGrant
	openPayload(t, grantMsg, keys.HostToExpert, &gotGrant)
	if gotGrant.ExpertName != "expert1" {
		t.Fatalf("bad grant: %+v", gotGrant)
	}

	// 3. Expert chat lands in the agent's poll inbox.
	sendEncrypted(t, expert, keys.ExpertToHost, "expert1", protocol.TypeExpertChat, protocol.ExpertChat{
		SessionID:  sessionID,
		ExpertName: "expert1",
		Text:       "check the migration order first",
	})
	waitFor(t, 5*time.Second, func() bool {
		for _, it := range sess.Poll() {
			if it.Type == "expert_chat" && strings.Contains(it.Text, "migration order") {
				return true
			}
		}
		return false
	}, "expert chat in agent inbox")

	// 4. Published events reach the expert as transcript events, with
	// secrets masked on the publish path.
	sess.PublishEvent("assistant", "using key sk-ant-secretvalue123 for the call", nil)
	evMsg := readUntil(t, expert, 5*time.Second, protocol.TypeTranscriptEvent)
	var tev protocol.TranscriptEvent
	openPayload(t, evMsg, keys.HostToExpert, &tev)
	if strings.Contains(tev.Text, "sk-ant-secretvalue123") {
		t.Fatalf("secret leaked to expert: %q", tev.Text)
	}
	if !strings.Contains(tev.Text, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %q", tev.Text)
	}

	// 5. Structured approval: expert approves, the blocking call returns.
	decCh := make(chan string, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dec, err := sess.RequestApproval(ctx, "Run the migration?", []string{"yes", "no"}, 0)
		if err != nil {
			t.Errorf("RequestApproval: %v", err)
			decCh <- ""
			return
		}
		decCh <- dec
	}()
	reqMsg := readUntil(t, expert, 5*time.Second, protocol.TypeApprovalRequest)
	var areq protocol.ApprovalRequest
	openPayload(t, reqMsg, keys.HostToExpert, &areq)
	if !strings.Contains(areq.Prompt, "migration") {
		t.Fatalf("bad approval prompt: %+v", areq)
	}
	sendEncrypted(t, expert, keys.ExpertToHost, "expert1", protocol.TypeApprovalDecision, protocol.ApprovalDecision{
		SessionID:  sessionID,
		ApprovalID: areq.ApprovalID,
		Decision:   protocol.ApprovalApprove,
		DecidedBy:  "expert1",
	})
	select {
	case dec := <-decCh:
		if dec != mcphost.DecisionApprove {
			t.Fatalf("expected approve, got %q", dec)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("approval decision never returned")
	}

	// 6. Bounded exec: controller-only, novice-visible, output returned.
	sendEncrypted(t, expert, keys.ExpertToHost, "expert1", protocol.TypeExecRequest, protocol.ExecRequest{
		SessionID:  sessionID,
		ID:         "exec-1",
		Command:    "echo hello-exec",
		TimeoutSec: 5,
	})
	outMsg := readUntil(t, expert, 10*time.Second, protocol.TypeExecOutput)
	var eout protocol.ExecOutput
	openPayload(t, outMsg, keys.HostToExpert, &eout)
	if eout.ID != "exec-1" || !strings.Contains(eout.Stdout, "hello-exec") || eout.ExitCode != 0 {
		t.Fatalf("bad exec output: %+v", eout)
	}
	sawExecInbox := false
	for _, it := range sess.Poll() {
		if it.Type == "exec" {
			sawExecInbox = true
		}
	}
	if !sawExecInbox {
		t.Fatal("exec run was not reported to the agent inbox (not novice-visible)")
	}

	// 7. Checkpoint announces to the expert.
	if _, err := sess.Checkpoint("pre-fix"); err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	cpMsg := readUntil(t, expert, 5*time.Second, protocol.TypeCheckpointEvent)
	var cev protocol.CheckpointEvent
	openPayload(t, cpMsg, keys.HostToExpert, &cev)
	if cev.Label != "pre-fix" {
		t.Fatalf("bad checkpoint event: %+v", cev)
	}

	// 8. Second expert cannot enroll with a spent invite (single-use burn).
	dup := dialWS(t, wsURL)
	sendEnvelope(t, dup, protocol.TypeRoomJoin, "expert2", "", protocol.RoomJoin{
		SessionID:  sessionID,
		ExpertName: "expert2",
	})
	rej := readUntil(t, dup, 5*time.Second, protocol.TypeError)
	var rejErr protocol.Error
	if err := rej.Decode(&rejErr); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	t.Logf("second join rejected: %s", rejErr.Code)
}
