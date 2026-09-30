package link

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestReadLimitRejectsOversized verifies the link refuses inbound frames
// over the 1 MiB read limit instead of buffering them.
func TestReadLimitRejectsOversized(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Send a 2 MiB text frame: over the 1 MiB link read limit.
		big := make([]byte, 2<<20)
		for i := range big {
			big[i] = 'x'
		}
		_ = conn.WriteMessage(websocket.TextMessage, big)
		time.Sleep(2 * time.Second)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, mux)

	l, err := Dial(Config{RelayURL: "ws://" + ln.Addr().String() + "/ws"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer l.Close()
	if _, err := l.Read(); err == nil {
		t.Fatal("Read of a 2 MiB frame should fail under the 1 MiB read limit")
	}
}
