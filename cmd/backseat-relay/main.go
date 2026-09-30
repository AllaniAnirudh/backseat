// Command backseat-relay is a self-hostable WebSocket relay. It routes
// opaque protocol envelopes between a host and attached experts, keyed by
// session id. It keeps no state beyond live rooms and never sees plaintext:
// payloads are end-to-end encrypted between host and expert after pairing.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type peer struct {
	conn *websocket.Conn
	send chan protocol.Message
}

type room struct {
	mu    sync.Mutex
	peers map[*peer]struct{}
}

type relay struct {
	mu    sync.Mutex
	rooms map[string]*room
}

func newRelay() *relay {
	return &relay{rooms: make(map[string]*room)}
}

func (r *relay) getOrCreate(sessionID string) *room {
	r.mu.Lock()
	defer r.mu.Unlock()
	rm, ok := r.rooms[sessionID]
	if !ok {
		rm = &room{peers: make(map[*peer]struct{})}
		r.rooms[sessionID] = rm
	}
	return rm
}

func (r *relay) get(sessionID string) *room {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rooms[sessionID]
}

func (r *relay) drop(sessionID string, p *peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rm, ok := r.rooms[sessionID]
	if !ok {
		return
	}
	rm.mu.Lock()
	delete(rm.peers, p)
	empty := len(rm.peers) == 0
	rm.mu.Unlock()
	if empty {
		delete(r.rooms, sessionID)
	}
}

// sessionIDOf extracts the routing key present on every payload.
func sessionIDOf(msg protocol.Message) string {
	var probe struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(msg.Payload, &probe); err != nil {
		return ""
	}
	return probe.SessionID
}

func (r *relay) serveWS(w http.ResponseWriter, req *http.Request) {
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Printf("upgrade: %v", err)
		return
	}
	p := &peer{conn: conn, send: make(chan protocol.Message, 128)}

	go func() {
		for msg := range p.send {
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
		}
	}()

	var joined string
	defer func() {
		if joined != "" {
			r.drop(joined, p)
		}
		close(p.send)
		conn.Close()
	}()

	for {
		var msg protocol.Message
		if err := conn.ReadJSON(&msg); err != nil {
			return
		}
		sessionID := sessionIDOf(msg)
		if sessionID == "" {
			continue
		}
		rm := r.get(sessionID)
		if msg.Type == protocol.TypeSessionAnnounce {
			rm = r.getOrCreate(sessionID)
		}
		if rm == nil {
			continue // no live session; drop
		}
		if joined == "" {
			rm.mu.Lock()
			rm.peers[p] = struct{}{}
			rm.mu.Unlock()
			joined = sessionID
		}
		if msg.Type == protocol.TypeSessionEnd {
			r.drop(sessionID, p)
			joined = ""
		}
		// Fan out to every other peer in the room. Payload stays opaque.
		rm.mu.Lock()
		for other := range rm.peers {
			if other == p {
				continue
			}
			select {
			case other.send <- msg:
			default:
			}
		}
		rm.mu.Unlock()
	}
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	r := newRelay()
	http.HandleFunc("/ws", r.serveWS)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("backseat relay listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
