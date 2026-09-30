// Package e2e runs a full backseat session against an in-process relay:
// host with a fake agent, one expert joining with the right secret, one
// rejected with the wrong secret, control handoff, driven input echoed
// back, input gating after yield, and clean teardown.
package e2e

import (
	"crypto/rand"
	"encoding/base64"
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

func sendEnvelope(t *testing.T, conn *websocket.Conn, msgType string, payload any) {
	t.Helper()
	msg, err := protocol.New(msgType, "test-id", time.Now().UnixMilli(), payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", msgType, err)
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("send %s: %v", msgType, err)
	}
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

func decodeOutput(t *testing.T, msg protocol.Message) string {
	t.Helper()
	var out protocol.TermOutput
	if err := msg.Decode(&out); err != nil {
		t.Fatalf("decode term_output: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(out.Data)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	return string(raw)
}

// joinExpert dials and joins, retrying while the host's announce is still
// propagating to the relay (the announce is sent async, so an instant join
// can legitimately hit no_session).
func joinExpert(t *testing.T, wsURL, name, secretB64 string) *websocket.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		join, err := protocol.New(protocol.TypeRoomJoin, "test-id", time.Now().UnixMilli(), protocol.RoomJoin{
			SessionID:  sessionID,
			ExpertName: name,
			Secret:     secretB64,
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err := conn.WriteJSON(join); err != nil {
			conn.Close()
			continue
		}
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if msg.Type == protocol.TypeSessionAnnounce {
			t.Cleanup(func() { conn.Close() })
			return conn
		}
		var e protocol.Error
		if derr := msg.Decode(&e); derr == nil && e.Code == "no_session" {
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf("expert join rejected: %+v", e)
	}
	t.Fatal("expert could not join within 10s")
	return nil
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
	secretB64 := base64.RawURLEncoding.EncodeToString(secret[:])

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

	// 1. Expert joins with the correct secret and gets the session echo.
	expert := joinExpert(t, wsURL, "expert1", secretB64)

	// 2. Wrong secret: relay rejects with bad_secret and closes the conn.
	bad := make([]byte, 32)
	if _, err := rand.Read(bad); err != nil {
		t.Fatal(err)
	}
	impostor := dialWS(t, wsURL)
	sendEnvelope(t, impostor, protocol.TypeRoomJoin, protocol.RoomJoin{
		SessionID:  sessionID,
		ExpertName: "impostor",
		Secret:     base64.RawURLEncoding.EncodeToString(bad),
	})
	rej := readUntil(t, impostor, 5*time.Second, protocol.TypeError)
	var rejErr protocol.Error
	if err := rej.Decode(&rejErr); err != nil || rejErr.Code != "bad_secret" {
		t.Fatalf("expected bad_secret rejection, got %+v (err %v)", rejErr, err)
	}
	_ = impostor.SetReadDeadline(time.Now().Add(2 * time.Second))
	var after protocol.Message
	if err := impostor.ReadJSON(&after); err == nil {
		t.Fatalf("expected impostor connection to close, got %s", after.Type)
	}

	// 3. Control request: host auto-grants, expert sees the grant.
	sendEnvelope(t, expert, protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	grant := readUntil(t, expert, 5*time.Second, protocol.TypeControlGrant)
	var gotGrant protocol.ControlGrant
	if err := grant.Decode(&gotGrant); err != nil || gotGrant.ExpertName != "expert1" {
		t.Fatalf("bad grant: %v", err)
	}
	waitFor(t, 5*time.Second, func() bool { return h.Controller() == "expert1" }, "host controller state")

	// 4. Expert drives: input reaches the PTY, echoed output comes back.
	sendEnvelope(t, expert, protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("hello\n")),
	})
	deadline := time.Now().Add(5 * time.Second)
	sawEcho := false
	for time.Now().Before(deadline) && !sawEcho {
		msg := readEnvelope(t, expert, time.Until(deadline))
		if msg.Type == protocol.TypeTermOutput && strings.Contains(decodeOutput(t, msg), "echo:hello") {
			sawEcho = true
		}
	}
	if !sawEcho {
		t.Fatal("expert never received the echoed input")
	}

	// 5. Yield: control returns to the host, so a further input must be
	// dropped. We prove it by reading everything up to session_end and
	// asserting the dropped marker never appears in any term_output.
	// (Note: gorilla/websocket caches read errors permanently, so a
	// deliberate read-timeout "silence check" would poison this conn.)
	sendEnvelope(t, expert, protocol.TypeControlYield, protocol.ControlYield{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	waitFor(t, 5*time.Second, func() bool { return h.Controller() == "" }, "host controller release")
	sendEnvelope(t, expert, protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("dropped\n")),
	})

	// 6. Host ends the session: expert gets session_end with no echo of the
	// post-yield input anywhere before it.
	h.End("test done")
	deadline = time.Now().Add(5 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("timed out waiting for session_end")
		}
		msg := readEnvelope(t, expert, remaining)
		switch msg.Type {
		case protocol.TypeTermOutput:
			if strings.Contains(decodeOutput(t, msg), "echo:dropped") {
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
