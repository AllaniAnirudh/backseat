package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// fakeHost plays the novice side of the enrollment against the TUI client:
// it issues a challenge, verifies the HMAC response, derives the same keys,
// then exchanges one encrypted message each way.
func runFakeHost(t *testing.T, secret [pairing.SecretLen]byte, gotChat chan protocol.ExpertChat) string {
	t.Helper()
	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		var join protocol.Message
		if err := conn.ReadJSON(&join); err != nil {
			t.Error(err)
			return
		}
		var rj protocol.RoomJoin
		if err := join.Decode(&rj); err != nil || join.Type != protocol.TypeRoomJoin {
			t.Errorf("expected room_join, got %s", join.Type)
			return
		}

		challenge, _ := pairing.NewChallenge()
		mk := func(msgType string, p any) protocol.Message {
			m, err := protocol.New(msgType, "h1", time.Now().UnixMilli(), p)
			if err != nil {
				t.Error(err)
			}
			m.From, m.To = "host", rj.ExpertName
			return m
		}
		if err := conn.WriteJSON(mk(protocol.TypePairingEnroll, protocol.PairingEnroll{
			SessionID: rj.SessionID, Phase: 1,
			Challenge: base64.StdEncoding.EncodeToString(challenge[:]),
		})); err != nil {
			t.Error(err)
			return
		}

		var resp protocol.Message
		if err := conn.ReadJSON(&resp); err != nil {
			t.Error(err)
			return
		}
		var pe protocol.PairingEnroll
		if err := resp.Decode(&pe); err != nil || pe.Phase != 2 {
			t.Errorf("expected phase 2, got %+v", pe)
			return
		}
		raw, _ := base64.StdEncoding.DecodeString(pe.Response)
		var want [pairing.SecretLen]byte
		copy(want[:], raw)
		if !pairing.VerifyEnrollment(secret, challenge, want) {
			t.Error("bad HMAC enrollment response")
			return
		}
		keys, err := pairing.DeriveKeys(secret, challenge)
		if err != nil {
			t.Error(err)
			return
		}
		if err := conn.WriteJSON(mk(protocol.TypePairingEnroll, protocol.PairingEnroll{
			SessionID: rj.SessionID, Phase: 3,
		})); err != nil {
			t.Error(err)
			return
		}

		// Send one encrypted event host -> expert.
		rawEv, _ := json.Marshal(protocol.TranscriptEvent{
			SessionID: rj.SessionID, Harness: "claude", Kind: "text", Text: "hello expert",
		})
		env, _ := pairing.Seal(keys.HostToExpert, rawEv)
		em := mk(protocol.TypeTranscriptEvent, json.RawMessage("{}"))
		em.Payload = env
		if err := conn.WriteJSON(em); err != nil {
			t.Error(err)
			return
		}

		// Read the client's encrypted expert_chat.
		var chatMsg protocol.Message
		if err := conn.ReadJSON(&chatMsg); err != nil {
			t.Error(err)
			return
		}
		plain, err := pairing.Open(keys.ExpertToHost, chatMsg.Payload)
		if err != nil {
			t.Errorf("open expert_chat: %v", err)
			return
		}
		var chat protocol.ExpertChat
		if err := json.Unmarshal(plain, &chat); err != nil {
			t.Error(err)
			return
		}
		gotChat <- chat
	}))
	t.Cleanup(srv.Close)
	return "ws" + srv.URL[4:] + "/ws"
}

func TestClientEnrollmentAndCrypto(t *testing.T) {
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	gotChat := make(chan protocol.ExpertChat, 1)
	relayURL := runFakeHost(t, secret, gotChat)

	events := make(chan clientEvent, 16)
	c := newClient(joinTarget{relayURL: relayURL, sessionID: "test-session", secret: secret},
		"tester", func(ev clientEvent) { events <- ev })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.run(ctx) }()

	// Wait for enrollment, then the encrypted transcript event.
	var sawEnrolled, sawEvent bool
	timeout := time.After(8 * time.Second)
	for !(sawEnrolled && sawEvent) {
		select {
		case ev := <-events:
			switch e := ev.(type) {
			case evEnrolled:
				sawEnrolled = true
			case evMessage:
				if e.msg.Type != protocol.TypeTranscriptEvent {
					t.Fatalf("unexpected message type %s", e.msg.Type)
				}
				var te protocol.TranscriptEvent
				if err := json.Unmarshal(e.plain, &te); err != nil {
					t.Fatal(err)
				}
				if te.Text != "hello expert" || te.Harness != "claude" {
					t.Fatalf("bad event: %+v", te)
				}
				sawEvent = true
			case evError:
				t.Fatalf("client error: %+v", e)
			}
		case <-timeout:
			t.Fatalf("timeout: enrolled=%v event=%v", sawEnrolled, sawEvent)
		}
	}

	// Expert -> host direction: the fake host decrypts and checks it.
	c.chat("try the migration order first")
	select {
	case chat := <-gotChat:
		if chat.Text != "try the migration order first" || chat.ExpertName != "tester" {
			t.Fatalf("bad chat: %+v", chat)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake host never got the expert_chat")
	}

	cancel()
	<-done
}

func TestClientBadRelay(t *testing.T) {
	secret, _ := pairing.GenerateSecret()
	events := make(chan clientEvent, 4)
	c := newClient(joinTarget{relayURL: "ws://127.0.0.1:1/ws", sessionID: "s", secret: secret},
		"tester", func(ev clientEvent) { events <- ev })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.run(ctx); err == nil {
		t.Fatal("expected dial error")
	}
}
