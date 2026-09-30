// Session tests run against an in-process relay with a fake expert that
// performs the real HMAC enrollment, mirroring internal/e2e's helpers.
package mcphost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/AllaniAnirudh/backseat/internal/relay"
)

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

func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func sendEnvelope(t *testing.T, conn *websocket.Conn, msgType, from, to string, payload any) {
	t.Helper()
	msg, err := protocol.New(msgType, "test-id", time.Now().UnixMilli(), payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", msgType, err)
	}
	msg.From = from
	msg.To = to
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("send %s: %v", msgType, err)
	}
}

func sendEncrypted(t *testing.T, conn *websocket.Conn, key [32]byte, from, msgType string, payload any) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	env, err := pairing.Seal(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	msg := protocol.Message{
		Type:      msgType,
		ID:        "test-id",
		Timestamp: time.Now().UnixMilli(),
		From:      from,
		To:        "host",
		Payload:   env,
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("send %s: %v", msgType, err)
	}
}

func readEnvelope(t *testing.T, conn *websocket.Conn, timeout time.Duration) protocol.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var msg protocol.Message
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return msg
}

// readUntil skips envelopes until one of the wanted type arrives.
func readUntil(t *testing.T, conn *websocket.Conn, timeout time.Duration, want string) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for %s", want)
		}
		msg := readEnvelope(t, conn, remaining)
		if msg.Type == want {
			return msg
		}
	}
}

// expectNone fails if an envelope arrives within timeout. A read timeout
// permanently poisons a gorilla websocket conn for further reads, so this
// must be the last read on conn in a test.
func expectNone(t *testing.T, conn *websocket.Conn, timeout time.Duration, what string) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var msg protocol.Message
	if err := conn.ReadJSON(&msg); err == nil {
		t.Fatalf("expected no %s, got %s", what, msg.Type)
	}
	_ = conn.SetReadDeadline(time.Time{})
}

func openPayload(t *testing.T, msg protocol.Message, key [32]byte, out any) {
	t.Helper()
	raw, err := pairing.Open(key, msg.Payload)
	if err != nil {
		t.Fatalf("decrypt %s: %v", msg.Type, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode %s: %v", msg.Type, err)
	}
}

// enrollExpert joins and completes the HMAC enrollment as a fake expert.
func enrollExpert(t *testing.T, wsURL, sessionID, name string, secret [32]byte) (*websocket.Conn, pairing.Keys) {
	t.Helper()
	conn := dialWS(t, wsURL)
	sendEnvelope(t, conn, protocol.TypeRoomJoin, name, "", protocol.RoomJoin{
		SessionID:  sessionID,
		ExpertName: name,
	})
	first := readEnvelope(t, conn, 5*time.Second)
	var pe protocol.PairingEnroll
	if first.Type != protocol.TypePairingEnroll || first.Decode(&pe) != nil || pe.Phase != 1 {
		t.Fatalf("expected pairing_enroll phase 1, got %s", first.Type)
	}
	chRaw, err := base64.StdEncoding.DecodeString(pe.Challenge)
	if err != nil || len(chRaw) != pairing.SecretLen {
		t.Fatalf("bad challenge: %v", err)
	}
	var challenge [pairing.SecretLen]byte
	copy(challenge[:], chRaw)
	resp := pairing.EnrollmentResponse(secret, challenge)
	keys, err := pairing.DeriveKeys(secret, challenge)
	if err != nil {
		t.Fatal(err)
	}
	sendEnvelope(t, conn, protocol.TypePairingEnroll, name, "host", protocol.PairingEnroll{
		SessionID: sessionID,
		Phase:     2,
		Response:  base64.StdEncoding.EncodeToString(resp[:]),
	})
	readUntil(t, conn, 5*time.Second, protocol.TypePairingEnroll) // phase 3
	annMsg := readUntil(t, conn, 5*time.Second, protocol.TypeSessionAnnounce)
	var ann protocol.SessionAnnounce
	openPayload(t, annMsg, keys.HostToExpert, &ann)
	if ann.SessionID != sessionID {
		t.Fatalf("bad announce: %+v", ann)
	}
	return conn, keys
}

func newTestSession(t *testing.T, wsURL string, mutate func(*Config)) (*Session, [32]byte) {
	t.Helper()
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		RelayURL: wsURL,
		UIBase:   "http://localhost:8081",
		HostName: "testhost",
		Harness:  "test",
		WorkDir:  t.TempDir(),
		Secret:   secret,
		OnEvent:  func(s string) { t.Log("event:", s) },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.End("test done") })
	return s, secret
}

// grantControl enrolls one expert and hands it control via the novice path.
func grantControl(t *testing.T, wsURL string, s *Session, secret [32]byte, name string) (*websocket.Conn, pairing.Keys) {
	t.Helper()
	conn, keys := enrollExpert(t, wsURL, s.SessionID(), name, secret)
	sendEncrypted(t, conn, keys.ExpertToHost, name, protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  s.SessionID(),
		ExpertName: name,
	})
	deadline := time.Now().Add(5 * time.Second)
	for s.PendingControl() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.Grant(); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	readUntil(t, conn, 5*time.Second, protocol.TypeControlGrant)
	return conn, keys
}

func TestInviteBurnOnEnroll(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	connA, _ := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer connA.Close()
	if got := s.EnrolledNames(); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("enrolled = %v, want [alice]", got)
	}
	if !s.Status().InviteBurned {
		t.Fatalf("invite not burned after first enrollment")
	}

	// A second expert with the same secret must be refused: the invite is
	// single-use. The relay admits the room_join on freshness, the host
	// kicks.
	connB := dialWS(t, wsURL)
	sendEnvelope(t, connB, protocol.TypeRoomJoin, "bob", "", protocol.RoomJoin{
		SessionID:  s.SessionID(),
		ExpertName: "bob",
	})
	kick := readUntil(t, connB, 5*time.Second, protocol.TypeError)
	var kerr protocol.Error
	if kick.Decode(&kerr) != nil || kerr.Code != "kicked" {
		t.Fatalf("expected kicked error for bob, got %s %+v", kick.Type, kerr)
	}
	if s.link.Enrolled("bob") {
		t.Fatalf("bob enrolled despite burned invite")
	}
	if got := s.EnrolledNames(); len(got) != 1 {
		t.Fatalf("enrolled = %v, want exactly one expert", got)
	}
}

func TestApprovalTTLFailsClosed(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, func(c *Config) { c.ApprovalTTL = 300 * time.Millisecond })

	// An enrolled expert that never answers: the request must fail closed.
	conn, keys := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer conn.Close()
	_ = keys

	start := time.Now()
	decision, err := s.RequestApproval(context.Background(), "run the migration?", nil, 0)
	elapsed := time.Since(start)
	if decision != DecisionDeny {
		t.Errorf("decision = %q, want deny (fail closed)", decision)
	}
	if !errors.Is(err, ErrApprovalExpired) {
		t.Errorf("err = %v, want ErrApprovalExpired", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("fail-closed took too long: %v", elapsed)
	}

	// The expert saw the request, then a dismissal broadcast.
	reqMsg := readUntil(t, conn, 5*time.Second, protocol.TypeApprovalRequest)
	var req protocol.ApprovalRequest
	openPayload(t, reqMsg, keys.HostToExpert, &req)
	if req.TimeoutSec <= 0 || req.TimeoutSec > 120 {
		t.Errorf("TimeoutSec = %d, want within (0,120]", req.TimeoutSec)
	}
	dismiss := readUntil(t, conn, 5*time.Second, protocol.TypeApprovalResponse)
	var resp protocol.ApprovalResponse
	openPayload(t, dismiss, keys.HostToExpert, &resp)
	if !resp.Broadcast || resp.ApprovalID != req.ApprovalID {
		t.Errorf("bad dismissal broadcast: %+v", resp)
	}
}

func TestApprovalDecisionResolves(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := grantControl(t, wsURL, s, secret, "alice")

	done := make(chan struct{})
	var decision string
	var reqErr error
	go func() {
		defer close(done)
		decision, reqErr = s.RequestApproval(context.Background(),
			"delete the staging bucket?", []string{"yes, delete it", "no, keep it"}, time.Minute)
	}()
	reqMsg := readUntil(t, conn, 5*time.Second, protocol.TypeApprovalRequest)
	var req protocol.ApprovalRequest
	openPayload(t, reqMsg, keys.HostToExpert, &req)
	if len(req.Options) != 2 {
		t.Fatalf("options = %v, want the two choices", req.Options)
	}
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeApprovalDecision, protocol.ApprovalDecision{
		SessionID:  s.SessionID(),
		ApprovalID: req.ApprovalID,
		Decision:   "yes, delete it",
		DecidedBy:  "alice",
		DecidedAt:  time.Now().Unix(),
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RequestApproval did not resolve")
	}
	if reqErr != nil || decision != "yes, delete it" {
		t.Errorf("decision = %q, err = %v", decision, reqErr)
	}
	// Card dismissed on every client.
	dismiss := readUntil(t, conn, 5*time.Second, protocol.TypeApprovalResponse)
	var resp protocol.ApprovalResponse
	openPayload(t, dismiss, keys.HostToExpert, &resp)
	if !resp.Broadcast {
		t.Errorf("expected broadcast dismissal, got %+v", resp)
	}
}

func TestApprovalNoExpertFailsClosed(t *testing.T) {
	wsURL := startTestRelay(t)
	s, _ := newTestSession(t, wsURL, nil)
	decision, err := s.RequestApproval(context.Background(), "anything?", nil, time.Minute)
	if decision != DecisionDeny || !errors.Is(err, ErrNoExpertConnected) {
		t.Errorf("decision = %q, err = %v; want deny + ErrNoExpertConnected", decision, err)
	}
}

func TestSingleControllerGrantRules(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer conn.Close()

	// No grant without a pending request.
	if err := s.Grant(); err == nil {
		t.Fatal("Grant without pending request should fail")
	}

	// Request -> pending; poll surfaces it for the agent.
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  s.SessionID(),
		ExpertName: "alice",
		Note:       "let me drive",
	})
	deadline := time.Now().Add(3 * time.Second)
	for s.PendingControl() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.PendingControl() != "alice" {
		t.Fatalf("pending = %q, want alice", s.PendingControl())
	}
	items := s.Poll()
	found := false
	for _, it := range items {
		if it.Type == "control_request" {
			found = true
		}
	}
	if !found {
		t.Errorf("control_request missing from poll inbox: %+v", items)
	}

	// Novice grant -> controller set, expert notified.
	if err := s.Grant(); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if s.Controller() != "alice" {
		t.Errorf("controller = %q, want alice", s.Controller())
	}
	readUntil(t, conn, 5*time.Second, protocol.TypeControlGrant)

	// A request from the controller while driving is ignored, not queued.
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  s.SessionID(),
		ExpertName: "alice",
	})
	time.Sleep(200 * time.Millisecond)
	if s.PendingControl() != "" {
		t.Errorf("pending = %q after controller re-request, want empty", s.PendingControl())
	}

	// Yield returns control to the novice.
	s.Yield()
	if s.Controller() != "" {
		t.Errorf("controller = %q after yield, want empty", s.Controller())
	}
	readUntil(t, conn, 5*time.Second, protocol.TypeControlYield)

	// Deny path: request again, then deny.
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  s.SessionID(),
		ExpertName: "alice",
	})
	deadline = time.Now().Add(3 * time.Second)
	for s.PendingControl() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.Deny("not now"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if s.Controller() != "" {
		t.Errorf("controller = %q after deny, want empty", s.Controller())
	}
	denyMsg := readUntil(t, conn, 5*time.Second, protocol.TypeControlDeny)
	var cd protocol.ControlDeny
	openPayload(t, denyMsg, keys.HostToExpert, &cd)
	if cd.Reason != "not now" {
		t.Errorf("deny reason = %q", cd.Reason)
	}
}

func TestPublishEventMasksSecrets(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer conn.Close()

	s.PublishEvent("tool_result", "deployed with api_key=sk-abcdef1234567890, all good",
		map[string]any{"token": "ghp_abcDEF1234567890", "ok": true})

	msg := readUntil(t, conn, 5*time.Second, protocol.TypeTranscriptEvent)
	var ev protocol.TranscriptEvent
	openPayload(t, msg, keys.HostToExpert, &ev)
	if strings.Contains(ev.Text, "sk-abcdef") {
		t.Errorf("secret leaked in text: %q", ev.Text)
	}
	if !strings.Contains(ev.Text, "[REDACTED]") {
		t.Errorf("text not masked: %q", ev.Text)
	}
	if ev.Fields["token"] != "[REDACTED]" {
		t.Errorf("meta token not masked: %v", ev.Fields)
	}
	if ev.Kind != "tool_result" || ev.Harness != "test" {
		t.Errorf("bad event: %+v", ev)
	}
}

func TestExpertChatReachesInbox(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer conn.Close()

	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeExpertChat, protocol.ExpertChat{
		SessionID:  s.SessionID(),
		ExpertName: "alice",
		Text:       "try checking the migration order first",
	})
	deadline := time.Now().Add(3 * time.Second)
	var chat *InboxItem
	for time.Now().Before(deadline) && chat == nil {
		for _, it := range s.Poll() {
			it := it
			if it.Type == "expert_chat" {
				chat = &it
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if chat == nil || chat.Text != "try checking the migration order first" || chat.From != "alice" {
		t.Fatalf("expert_chat missing from inbox: %+v", chat)
	}
	// Poll drains.
	if rest := s.Poll(); len(rest) != 0 {
		t.Fatalf("poll did not drain: %+v", rest)
	}
}

func TestExecControllerOnlyAndNoviceVisible(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := enrollExpert(t, wsURL, s.SessionID(), "alice", secret)
	defer conn.Close()

	// Grant control, then exec runs bounded.
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  s.SessionID(),
		ExpertName: "alice",
	})
	deadline := time.Now().Add(3 * time.Second)
	for s.PendingControl() == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.Grant(); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	readUntil(t, conn, 5*time.Second, protocol.TypeControlGrant)

	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeExecRequest, protocol.ExecRequest{
		SessionID: s.SessionID(),
		ID:        "e1",
		Command:   "echo hello-exec",
	})
	outMsg := readUntil(t, conn, 5*time.Second, protocol.TypeExecOutput)
	var out protocol.ExecOutput
	openPayload(t, outMsg, keys.HostToExpert, &out)
	if out.ID != "e1" || out.Stdout != "hello-exec\n" || out.ExitCode != 0 {
		t.Errorf("bad exec output: %+v", out)
	}

	// Novice-visible: the run lands in the agent inbox.
	deadline = time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		for _, it := range s.Poll() {
			if it.Type == "exec" {
				found = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Errorf("exec run missing from novice inbox")
	}

	// Not the controller anymore: the request is dropped, no output comes
	// back. The expect-none read is last: a read timeout permanently poisons
	// a gorilla websocket conn for further reads.
	s.Yield()
	readUntil(t, conn, 5*time.Second, protocol.TypeControlYield)
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeExecRequest, protocol.ExecRequest{
		SessionID: s.SessionID(),
		ID:        "e2",
		Command:   "echo should-not-run",
	})
	expectNone(t, conn, 500*time.Millisecond, "exec_output for non-controller")
}

func TestCheckpointAndRestoreFlow(t *testing.T) {
	wsURL := startTestRelay(t)
	s, secret := newTestSession(t, wsURL, nil)

	conn, keys := grantControl(t, wsURL, s, secret, "alice")
	defer conn.Close()

	cp, err := s.Checkpoint("before-risky")
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if cp.Label != "before-risky" {
		t.Errorf("label = %q", cp.Label)
	}
	evMsg := readUntil(t, conn, 5*time.Second, protocol.TypeCheckpointEvent)
	var ev protocol.CheckpointEvent
	openPayload(t, evMsg, keys.HostToExpert, &ev)
	if ev.Action != "created" || ev.Label != "before-risky" {
		t.Errorf("bad checkpoint event: %+v", ev)
	}
	if len(s.Status().Checkpoints) != 1 {
		t.Errorf("status checkpoints = %v", s.Status().Checkpoints)
	}

	// Controller requests a rewind: parked for novice confirm, surfaced in
	// the inbox.
	sendEncrypted(t, conn, keys.ExpertToHost, "alice", protocol.TypeCheckpointRestore, protocol.CheckpointRestore{
		SessionID: s.SessionID(),
		Label:     "before-risky",
	})
	deadline := time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		for _, it := range s.Poll() {
			if it.Type == "restore_requested" {
				found = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatal("restore_requested missing from inbox")
	}
	if err := s.ConfirmRestore(); err != nil {
		t.Fatalf("ConfirmRestore: %v", err)
	}
	// The restore_requested broadcast is still queued ahead of restored.
	deadline = time.Now().Add(5 * time.Second)
	restoredOK := false
	for time.Now().Before(deadline) && !restoredOK {
		restored := readUntil(t, conn, time.Until(deadline), protocol.TypeCheckpointEvent)
		var rev protocol.CheckpointEvent
		openPayload(t, restored, keys.HostToExpert, &rev)
		if rev.Action == "restored" && rev.Label == "before-risky" {
			restoredOK = true
		}
	}
	if !restoredOK {
		t.Error("restored event never arrived")
	}
}
