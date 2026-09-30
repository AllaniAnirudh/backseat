// Package relay routes opaque protocol envelopes between a backseat host
// and attached experts. Rooms are keyed by session id.
//
// Trust notes: the relay is untrusted by design. Host/expert payloads are
// end-to-end encrypted with keys the relay never sees — derived locally on
// both ends from the invite secret via the pairing ceremony — so the relay
// only ever handles opaque envelopes plus the plaintext routing metadata
// it needs: message type, session id, the to/from fields, and timing. The
// one plaintext control type it acts on is peer_kick; everything else is
// routed, never inspected. Experts join without presenting the secret; the
// host verifies possession through the HMAC enrollment before any content
// flows, and the relay drops peers that never complete it.
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

// PendingTimeout bounds how long a joined-but-unenrolled peer may linger.
// It is a var so tests can shrink it.
var PendingTimeout = 60 * time.Second

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type peer struct {
	conn    *websocket.Conn
	send    chan protocol.Message
	name    string
	isHost  bool
	roomID  string
	pending bool // joined but not yet through the HMAC enrollment
	once    sync.Once
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
	mu        sync.Mutex
	sessionID string
	createdAt time.Time
	host      *peer
	experts   map[*peer]string // peer -> expert name
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

// sessionIDOf reads the session id out of a plaintext payload. It only
// works on unencrypted first envelopes (session_announce, room_join);
// later traffic is routed per-connection, so the relay never needs to
// look inside encrypted payloads.
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

// reject sends an error envelope and closes the connection.
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
	if err := msg.Decode(&ann); err != nil || ann.SessionID == "" {
		s.reject(p, sessionID, "bad_envelope", "invalid session_announce")
		return
	}
	if existing := s.getRoom(sessionID); existing != nil {
		s.reject(p, sessionID, "busy", "session id already live")
		return
	}
	rm := &room{
		sessionID: sessionID,
		createdAt: time.Now(),
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
	if err := msg.Decode(&join); err != nil || join.ExpertName == "" {
		s.reject(p, sessionID, "bad_envelope", "invalid room_join")
		return
	}
	rm := s.getRoom(sessionID)
	if rm == nil {
		s.reject(p, sessionID, "no_session", "no live session with that id")
		return
	}
	name := join.ExpertName
	rm.mu.Lock()
	expired := time.Since(rm.createdAt) > InviteTTL
	duplicate := false
	for _, n := range rm.experts {
		if n == name {
			duplicate = true
			break
		}
	}
	rm.mu.Unlock()
	if expired {
		s.reject(p, sessionID, "expired", "invite expired")
		return
	}
	if duplicate {
		s.reject(p, sessionID, "name_taken", "that expert name is already in the session")
		return
	}
	p.name = name
	p.roomID = sessionID
	p.pending = true
	rm.mu.Lock()
	rm.experts[p] = name
	host := rm.host
	rm.mu.Unlock()
	log.Printf("relay: expert %q joined session %q (pending enrollment)", name, sessionID)

	// The host starts the HMAC enrollment; the newcomer gets nothing yet.
	msg.From = name
	if host != nil {
		host.enqueue(msg)
	}

	// Peers that never complete enrollment are dropped.
	timer := time.AfterFunc(PendingTimeout, func() {
		rm.mu.Lock()
		_, stillThere := rm.experts[p]
		rm.mu.Unlock()
		if stillThere && p.pending {
			p.enqueue(newMsg(protocol.TypeError, protocol.Error{
				SessionID: sessionID,
				Code:      "enrollment_timeout",
				Message:   "enrollment not completed in time",
			}))
			p.close()
			log.Printf("relay: expert %q dropped from session %q: enrollment timed out", name, sessionID)
		}
	})
	defer timer.Stop()

	defer func() {
		rm.mu.Lock()
		delete(rm.experts, p)
		empty := len(rm.experts) == 0 && rm.host == nil
		rm.mu.Unlock()
		if empty {
			s.dropRoom(sessionID)
		}
		log.Printf("relay: expert %q left session %q", name, sessionID)
	}()

	s.pumpExpert(p, rm, name)
}

// markEnrolled clears the pending flag once the host confirms the
// enrollment (phase 3 ack routed to the expert).
func (s *Server) markEnrolled(rm *room, name string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for e, n := range rm.experts {
		if n == name {
			e.pending = false
			return
		}
	}
}

// pumpHost routes host envelopes. peer_kick is the one plaintext control
// type the relay acts on; everything else is routed by `to` and never
// inspected.
func (s *Server) pumpHost(p *peer, rm *room) {
	for {
		var msg protocol.Message
		if err := p.conn.ReadJSON(&msg); err != nil {
			return
		}
		switch msg.Type {
		case protocol.TypePairingEnroll:
			var pe protocol.PairingEnroll
			if err := msg.Decode(&pe); err == nil && pe.Phase == 3 {
				s.markEnrolled(rm, msg.To)
			}
			s.routeToExpert(rm, msg)
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
			s.routeToExpert(rm, msg)
		}
	}
}

// pumpExpert forwards expert envelopes to the host, stamped with the
// authoritative sender name. Control gating lives on the host now: the
// relay cannot read encrypted payloads, so it enforces nothing beyond
// routing.
func (s *Server) pumpExpert(p *peer, rm *room, name string) {
	for {
		var msg protocol.Message
		if err := p.conn.ReadJSON(&msg); err != nil {
			return
		}
		if msg.Type == protocol.TypeSessionEnd {
			return // expert leaving voluntarily
		}
		msg.From = name
		rm.mu.Lock()
		host := rm.host
		rm.mu.Unlock()
		if host == nil {
			return
		}
		host.enqueue(msg)
	}
}

// routeToExpert delivers one host envelope: `to` names the recipient,
// "" or "*" broadcasts. Unknown recipients are dropped.
func (s *Server) routeToExpert(rm *room, msg protocol.Message) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if msg.To == "" || msg.To == "*" {
		for e := range rm.experts {
			e.enqueue(msg)
		}
		return
	}
	for e, n := range rm.experts {
		if n == msg.To {
			e.enqueue(msg)
			return
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
