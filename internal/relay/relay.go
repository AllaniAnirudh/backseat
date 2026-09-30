// Package relay routes opaque protocol envelopes between a backseat host
// and attached experts. Rooms are keyed by session id.
//
// Trust notes for v0.1 (localhost demo): the relay sees envelope payloads
// in cleartext, including the invite secret inside room_join. That is
// acceptable on loopback; end-to-end payload encryption from the pairing
// keys arrives in v0.3 per the roadmap. The relay never logs secrets.
package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

// InviteTTL bounds how long after the announcement an expert may join.
const InviteTTL = pairing.InviteTTL

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type peer struct {
	conn   *websocket.Conn
	send   chan protocol.Message
	name   string
	isHost bool
	roomID string
	once   sync.Once
}

func (p *peer) enqueue(msg protocol.Message) {
	defer func() {
		// The peer may have been closed concurrently; drop the message.
		_ = recover()
	}()
	select {
	case p.send <- msg:
	default:
		// Slow peer: drop rather than stall the room.
	}
}

func (p *peer) close() {
	// Closing send lets the write pump flush queued envelopes before the
	// deferred conn.Close runs, so no message is lost on teardown.
	p.once.Do(func() {
		close(p.send)
	})
}

type room struct {
	mu         sync.Mutex
	sessionID  string
	verifier   string // hex SHA-256 of the invite secret
	createdAt  time.Time
	announce   protocol.SessionAnnounce
	host       *peer
	experts    map[*peer]string // peer -> expert name
	controller string           // "" means the host holds control
}

// Server routes envelopes between hosts and experts.
type Server struct {
	mu    sync.Mutex
	rooms map[string]*room
}

// New returns an empty relay server.
func New() *Server {
	return &Server{rooms: make(map[string]*room)}
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func newMsg(msgType string, payload any) protocol.Message {
	msg, err := protocol.New(msgType, newID(), time.Now().UnixMilli(), payload)
	if err != nil {
		// Payloads are fixed structs; marshal cannot fail in practice.
		panic(err)
	}
	return msg
}

func sessionIDOf(msg protocol.Message) string {
	var probe struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(msg.Payload, &probe); err != nil {
		return ""
	}
	return probe.SessionID
}

// ServeHTTP only serves the WebSocket endpoint; everything else 404s.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ws" {
		http.NotFound(w, r)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("relay: websocket upgrade: %v", err)
		return
	}
	p := &peer{conn: conn, send: make(chan protocol.Message, 128)}
	go p.writePump()
	s.servePeer(p)
}

func (p *peer) writePump() {
	defer p.conn.Close()
	for msg := range p.send {
		p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := p.conn.WriteJSON(msg); err != nil {
			return
		}
	}
}

// reject sends an error envelope and closes the connection. The secret is
// never logged.
func (s *Server) reject(p *peer, sessionID, code, message string) {
	p.enqueue(newMsg(protocol.TypeError, protocol.Error{
		SessionID: sessionID,
		Code:      code,
		Message:   message,
	}))
	// The write pump flushes the queued error before the socket closes.
	p.close()
	log.Printf("relay: rejected join for session %q: %s", sessionID, code)
}

func (s *Server) getRoom(sessionID string) *room {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rooms[sessionID]
}

func (s *Server) putRoom(rm *room) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rooms[rm.sessionID] = rm
}

func (s *Server) dropRoom(sessionID string) {
	s.mu.Lock()
	rm, ok := s.rooms[sessionID]
	if ok {
		delete(s.rooms, sessionID)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	rm.mu.Lock()
	peers := make([]*peer, 0, len(rm.experts)+1)
	if rm.host != nil {
		peers = append(peers, rm.host)
		rm.host = nil
	}
	for e := range rm.experts {
		peers = append(peers, e)
	}
	rm.experts = make(map[*peer]string)
	rm.mu.Unlock()
	for _, p := range peers {
		p.close()
	}
}

// servePeer handles one connection: the first envelope must be
// session_announce (host) or room_join (expert).
func (s *Server) servePeer(p *peer) {
	defer p.close()

	p.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var first protocol.Message
	if err := p.conn.ReadJSON(&first); err != nil {
		return
	}
	p.conn.SetReadDeadline(time.Time{}) // no deadline after handshake

	sessionID := sessionIDOf(first)
	if sessionID == "" {
		s.reject(p, "", "bad_envelope", "first message must carry a session_id")
		return
	}

	switch first.Type {
	case protocol.TypeSessionAnnounce:
		s.serveHost(p, sessionID, first)
	case protocol.TypeRoomJoin:
		s.serveExpert(p, sessionID, first)
	default:
		s.reject(p, sessionID, "bad_envelope", "first message must be session_announce or room_join")
	}
}

func (s *Server) serveHost(p *peer, sessionID string, msg protocol.Message) {
	var ann protocol.SessionAnnounce
	if err := msg.Decode(&ann); err != nil || ann.SecretHash == "" {
		s.reject(p, sessionID, "bad_envelope", "invalid session_announce")
		return
	}
	if existing := s.getRoom(sessionID); existing != nil {
		s.reject(p, sessionID, "busy", "session id already live")
		return
	}
	rm := &room{
		sessionID: sessionID,
		verifier:  ann.SecretHash,
		createdAt: time.Now(),
		announce:  ann,
		host:      p,
		experts:   make(map[*peer]string),
	}
	p.isHost = true
	p.name = ann.HostName
	p.roomID = sessionID
	s.putRoom(rm)
	log.Printf("relay: session %q announced by %q (%s)", sessionID, ann.HostName, ann.Harness)

	defer func() {
		// Host left: tell the experts and drop the room.
		rm.mu.Lock()
		rm.host = nil
		for e := range rm.experts {
			e.enqueue(newMsg(protocol.TypeSessionEnd, protocol.SessionEnd{
				SessionID: sessionID,
				Reason:    "host disconnected",
			}))
		}
		rm.mu.Unlock()
		s.dropRoom(sessionID)
		log.Printf("relay: session %q ended (host left)", sessionID)
	}()

	s.pumpHost(p, rm)
}

func (s *Server) serveExpert(p *peer, sessionID string, msg protocol.Message) {
	var join protocol.RoomJoin
	if err := msg.Decode(&join); err != nil {
		s.reject(p, sessionID, "bad_envelope", "invalid room_join")
		return
	}
	rm := s.getRoom(sessionID)
	if rm == nil {
		s.reject(p, sessionID, "no_session", "no live session with that id")
		return
	}
	rm.mu.Lock()
	expired := time.Since(rm.createdAt) > InviteTTL
	rm.mu.Unlock()
	if expired {
		s.reject(p, sessionID, "expired", "invite expired")
		return
	}
	if !pairing.CheckSecret(join.Secret, rm.verifier) {
		s.reject(p, sessionID, "bad_secret", "wrong invite secret")
		return
	}
	name := join.ExpertName
	if name == "" {
		name = "expert"
	}
	p.name = name
	p.roomID = sessionID
	rm.mu.Lock()
	rm.experts[p] = name
	ann := rm.announce
	rm.mu.Unlock()
	log.Printf("relay: expert %q joined session %q", name, sessionID)

	// Tell the newcomer what the session is.
	p.enqueue(newMsg(protocol.TypeSessionAnnounce, ann))

	defer func() {
		rm.mu.Lock()
		delete(rm.experts, p)
		if rm.controller == name {
			rm.controller = ""
		}
		empty := len(rm.experts) == 0 && rm.host == nil
		rm.mu.Unlock()
		if empty {
			s.dropRoom(sessionID)
		}
		log.Printf("relay: expert %q left session %q", name, sessionID)
	}()

	s.pumpExpert(p, rm, name)
}

// pumpHost routes host envelopes: broadcasts go to experts, control state
// is tracked so term_input can be gated on the way back.
func (s *Server) pumpHost(p *peer, rm *room) {
	for {
		var msg protocol.Message
		if err := p.conn.ReadJSON(&msg); err != nil {
			return
		}
		switch msg.Type {
		case protocol.TypeTermOutput:
			s.broadcastExperts(rm, msg)
		case protocol.TypeControlGrant:
			var g protocol.ControlGrant
			if msg.Decode(&g) == nil {
				rm.mu.Lock()
				rm.controller = g.ExpertName
				rm.mu.Unlock()
				log.Printf("relay: session %q control -> %q", rm.sessionID, g.ExpertName)
			}
			s.broadcastExperts(rm, msg)
		case protocol.TypeControlDeny:
			s.broadcastExperts(rm, msg)
		case protocol.TypeControlYield:
			rm.mu.Lock()
			rm.controller = ""
			rm.mu.Unlock()
			log.Printf("relay: session %q control -> host", rm.sessionID)
			s.broadcastExperts(rm, msg)
		case protocol.TypePeerKick:
			var k protocol.PeerKick
			if msg.Decode(&k) != nil {
				continue
			}
			s.kickExpert(rm, k.ExpertName, k.Reason)
		case protocol.TypeSessionEnd:
			s.broadcastExperts(rm, msg)
			log.Printf("relay: session %q ended by host", rm.sessionID)
			s.dropRoom(rm.sessionID)
			return
		default:
			// v0.1 ignores anything else from the host.
		}
	}
}

// pumpExpert routes expert envelopes. term_input only reaches the host when
// it comes from the active controller; everything else is dropped.
func (s *Server) pumpExpert(p *peer, rm *room, name string) {
	for {
		var msg protocol.Message
		if err := p.conn.ReadJSON(&msg); err != nil {
			return
		}
		switch msg.Type {
		case protocol.TypeTermInput:
			rm.mu.Lock()
			allowed := rm.controller == name
			host := rm.host
			rm.mu.Unlock()
			if !allowed || host == nil {
				continue
			}
			host.enqueue(msg)
		case protocol.TypeControlRequest:
			rm.mu.Lock()
			host := rm.host
			rm.mu.Unlock()
			if host != nil {
				host.enqueue(msg)
			}
		case protocol.TypeControlYield:
			rm.mu.Lock()
			rm.controller = ""
			host := rm.host
			rm.mu.Unlock()
			log.Printf("relay: session %q control -> host", rm.sessionID)
			if host != nil {
				host.enqueue(msg)
			}
		case protocol.TypeSessionEnd:
			// Expert leaving voluntarily.
			return
		default:
			// v0.1 ignores anything else from experts.
		}
	}
}

func (s *Server) broadcastExperts(rm *room, msg protocol.Message) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for e := range rm.experts {
		e.enqueue(msg)
	}
}

func (s *Server) kickExpert(rm *room, name, reason string) {
	rm.mu.Lock()
	var target *peer
	for e, n := range rm.experts {
		if n == name {
			target = e
			break
		}
	}
	if rm.controller == name {
		rm.controller = ""
	}
	rm.mu.Unlock()
	if target == nil {
		return
	}
	target.enqueue(newMsg(protocol.TypeError, protocol.Error{
		SessionID: rm.sessionID,
		Code:      "kicked",
		Message:   reason,
	}))
	rm.mu.Lock()
	delete(rm.experts, target)
	rm.mu.Unlock()
	target.close()
	log.Printf("relay: expert %q kicked from session %q", name, rm.sessionID)
}
