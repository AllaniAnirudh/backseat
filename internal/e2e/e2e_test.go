// Package e2e runs a full backseat session against an in-process relay:
// host with a fake agent, experts completing the HMAC enrollment, encrypted
// control handoff, driven input echoed back through per-expert encryption,
// input gating (non-controller and post-yield input dropped), enrollment
// failure kicking, pending-enrollment timeout, and clean teardown.
package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/AllaniAnirudh/backseat/internal/relay"
)

const sessionID = "e2e-test-session"

func dialWS(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", url, err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendEnvelope writes one plaintext envelope.
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

// sendEncrypted seals the payload with key and writes the envelope.
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

// openPayload decrypts a host->expert envelope with the HostToExpert key.
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

func decodeOutput(t *testing.T, msg protocol.Message, key [32]byte) string {
	t.Helper()
	var out protocol.TermOutput
	openPayload(t, msg, key, &out)
	raw, err := base64.StdEncoding.DecodeString(out.Data)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return string(raw)
}

// readEnvelope reads one envelope, failing the test on timeout.
func readEnvelope(t *testing.T, conn *websocket.Conn, timeout time.Duration) protocol.Message {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	var msg protocol.Message
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read: %v", err)
	}
	return msg
}

// readUntil skips envelopes until one of the wanted type arrives.
func readUntil(t *testing.T, conn *websocket.Conn, timeout time.Duration, wantType string) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("timed out waiting for %s", wantType)
		}
		msg := readEnvelope(t, conn, remaining)
		if msg.Type == wantType {
			return msg
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// joinUntilAccepted dials, sends a secretless room_join, and returns the
// connection plus the first accepted message, retrying while the host's
// announcement hasn't reached the relay yet.
func joinUntilAccepted(t *testing.T, wsURL, session, name string) (*websocket.Conn, protocol.Message) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		sendEnvelope(t, conn, protocol.TypeRoomJoin, name, "", protocol.RoomJoin{
			SessionID:  session,
			ExpertName: name,
		})
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_ = conn.SetReadDeadline(time.Time{})
		if msg.Type == protocol.TypeError {
			var e protocol.Error
			if msg.Decode(&e) == nil && e.Code == "no_session" {
				conn.Close()
				time.Sleep(50 * time.Millisecond)
				continue
			}
			conn.Close()
			t.Fatalf("expert join rejected: %+v", e)
		}
		t.Cleanup(func() { conn.Close() })
		return conn, msg
	}
	t.Fatal("join never accepted within 10s")
	return nil, protocol.Message{}
}

// enrollExpert dials, joins with no secret, and runs the HMAC enrollment,
// returning the connection and the derived directional keys.
func enrollExpert(t *testing.T, wsURL, name string, secret [32]byte) (*websocket.Conn, pairing.Keys) {
	return enrollExpertHarness(t, wsURL, name, secret, "echo")
}

// enrollExpertHarness is enrollExpert with the expected harness banner
// parameterized, for sessions whose host is not the echo harness.
func enrollExpertHarness(t *testing.T, wsURL, name string, secret [32]byte, harness string) (*websocket.Conn, pairing.Keys) {
	t.Helper()
	conn, first := joinUntilAccepted(t, wsURL, sessionID, name)
	{
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
		// Phase 3 ack, then the encrypted session announcement.
		readUntil(t, conn, 5*time.Second, protocol.TypePairingEnroll)
		annMsg := readUntil(t, conn, 5*time.Second, protocol.TypeSessionAnnounce)
		var ann protocol.SessionAnnounce
		openPayload(t, annMsg, keys.HostToExpert, &ann)
		if ann.Harness != harness {
			t.Fatalf("bad announce: %+v", ann)
		}
		return conn, keys
	}
}

func TestBackseatFlow(t *testing.T) {
	// Relay in-process on an ephemeral port.
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

	// Host with a fake agent: an echo loop over stdin.
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		AgentCmd:  []string{"sh", "-c", `while IFS= read -r line; do printf 'echo:%s\n' "$line"; done`},
		Decide:    func(protocol.ControlRequest) bool { return true }, // auto-grant
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	// 1. Expert enrolls through the HMAC ceremony and gets the encrypted
	// session announcement.
	expert1, keys1 := enrollExpert(t, wsURL, "expert1", secret)
	waitFor(t, 5*time.Second, func() bool { return h.Enrolled("expert1") }, "host enrollment state")

	// 2. Duplicate names are rejected by the relay.
	dup := dialWS(t, wsURL)
	sendEnvelope(t, dup, protocol.TypeRoomJoin, "expert1", "", protocol.RoomJoin{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	rej := readUntil(t, dup, 5*time.Second, protocol.TypeError)
	var rejErr protocol.Error
	if err := rej.Decode(&rejErr); err != nil || rejErr.Code != "name_taken" {
		t.Fatalf("expected name_taken rejection, got %+v (err %v)", rejErr, err)
	}

	// 3. Control request (encrypted): host auto-grants, expert sees the
	// decrypted grant.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	grantMsg := readUntil(t, expert1, 5*time.Second, protocol.TypeControlGrant)
	var gotGrant protocol.ControlGrant
	openPayload(t, grantMsg, keys1.HostToExpert, &gotGrant)
	if gotGrant.ExpertName != "expert1" {
		t.Fatalf("bad grant: %+v", gotGrant)
	}
	waitFor(t, 5*time.Second, func() bool { return h.Controller() == "expert1" }, "host controller state")

	// 4. Expert drives: encrypted input reaches the PTY, encrypted output
	// comes back.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("hello\n")),
	})
	deadline := time.Now().Add(5 * time.Second)
	sawEcho := false
	for time.Now().Before(deadline) && !sawEcho {
		msg := readEnvelope(t, expert1, time.Until(deadline))
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:hello") {
			sawEcho = true
		}
	}
	if !sawEcho {
		t.Fatal("expert never received the echoed input")
	}

	// 5. A second expert enrolls, but its input is dropped while expert1
	// holds control. Proven by driving a marker through expert1 and
	// asserting the intruder's text never echoes before it.
	expert2, keys2 := enrollExpert(t, wsURL, "expert2", secret)
	sendEncrypted(t, expert2, keys2.ExpertToHost, "expert2", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("intruder\n")),
	})
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("marker\n")),
	})
	deadline = time.Now().Add(5 * time.Second)
	sawMarker := false
	for time.Now().Before(deadline) && !sawMarker {
		msg := readEnvelope(t, expert2, time.Until(deadline))
		if msg.Type != protocol.TypeTermOutput {
			continue
		}
		out := decodeOutput(t, msg, keys2.HostToExpert)
		if strings.Contains(out, "echo:intruder") {
			t.Fatal("non-controller input reached the PTY")
		}
		if strings.Contains(out, "echo:marker") {
			sawMarker = true
		}
	}
	if !sawMarker {
		t.Fatal("expert2 never received the marker echo")
	}

	// 6. Yield: control returns to the host, so further input is dropped.
	// Proven by scanning everything up to session_end for the dropped text.
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeControlYield, protocol.ControlYield{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	waitFor(t, 5*time.Second, func() bool { return h.Controller() == "" }, "host controller release")
	sendEncrypted(t, expert1, keys1.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("dropped\n")),
	})

	// 7. Bad HMAC response: host fails the enrollment and the relay kicks.
	impostor := dialWS(t, wsURL)
	sendEnvelope(t, impostor, protocol.TypeRoomJoin, "impostor", "", protocol.RoomJoin{
		SessionID:  sessionID,
		ExpertName: "impostor",
	})
	readUntil(t, impostor, 5*time.Second, protocol.TypePairingEnroll) // phase 1
	bad := make([]byte, 32)
	if _, err := rand.Read(bad); err != nil {
		t.Fatal(err)
	}
	sendEnvelope(t, impostor, protocol.TypePairingEnroll, "impostor", "host", protocol.PairingEnroll{
		SessionID: sessionID,
		Phase:     2,
		Response:  base64.StdEncoding.EncodeToString(bad),
	})
	kick := readUntil(t, impostor, 5*time.Second, protocol.TypeError)
	var kickErr protocol.Error
	if err := kick.Decode(&kickErr); err != nil || kickErr.Code != "kicked" {
		t.Fatalf("expected kicked error, got %+v (err %v)", kickErr, err)
	}
	_ = impostor.SetReadDeadline(time.Now().Add(2 * time.Second))
	var after protocol.Message
	if err := impostor.ReadJSON(&after); err == nil {
		t.Fatalf("expected impostor connection to close, got %s", after.Type)
	}

	// 8. Host ends the session: expert1 gets session_end with no echo of
	// the post-yield input anywhere before it.
	h.End("test done")
	deadline = time.Now().Add(5 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("timed out waiting for session_end")
		}
		msg := readEnvelope(t, expert1, remaining)
		switch msg.Type {
		case protocol.TypeTermOutput:
			if strings.Contains(decodeOutput(t, msg, keys1.HostToExpert), "echo:dropped") {
				t.Fatal("post-yield input was not gated: got echo of dropped input")
			}
		case protocol.TypeSessionEnd:
			var gotEnd protocol.SessionEnd
			if err := msg.Decode(&gotEnd); err != nil || gotEnd.Reason != "test done" {
				t.Fatalf("bad session_end: %v", err)
			}
			return
		}
	}
}

func TestPendingEnrollmentTimeout(t *testing.T) {
	old := relay.PendingTimeout
	relay.PendingTimeout = 300 * time.Millisecond
	defer func() { relay.PendingTimeout = old }()

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
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: "timeout-session",
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "echo",
		AgentCmd:  []string{"sh", "-c", `while IFS= read -r line; do printf 'echo:%s\n' "$line"; done`},
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("test cleanup")

	// Join but never answer the challenge: the relay must drop the peer.
	// (The host announces async, so retry the join on no_session.)
	conn, _ := joinUntilAccepted(t, wsURL, "timeout-session", "slowpoke")
	_ = conn.SetReadDeadline(time.Time{})
	timeoutMsg := readUntil(t, conn, 5*time.Second, protocol.TypeError)
	var terr protocol.Error
	if err := timeoutMsg.Decode(&terr); err != nil || terr.Code != "enrollment_timeout" {
		t.Fatalf("expected enrollment_timeout, got %+v (err %v)", terr, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var after protocol.Message
	if err := conn.ReadJSON(&after); err == nil {
		t.Fatalf("expected timed-out connection to close, got %s", after.Type)
	}
	if h.Enrolled("slowpoke") {
		t.Fatal("timed-out peer is marked enrolled on the host")
	}
}
