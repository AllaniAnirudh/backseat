package relay

import (
	"testing"

	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

func chanPeer(name string) *peer {
	return &peer{send: make(chan protocol.Message, 4), name: name}
}

func tryRecv(p *peer) (protocol.Message, bool) {
	select {
	case m := <-p.send:
		return m, true
	default:
		return protocol.Message{}, false
	}
}

func TestRouteToExpert(t *testing.T) {
	s := New()
	rm := &room{experts: make(map[*peer]string)}
	a, b := chanPeer("a"), chanPeer("b")
	rm.experts[a] = "a"
	rm.experts[b] = "b"

	// Directed delivery reaches only the named peer.
	s.routeToExpert(rm, protocol.Message{Type: "x", To: "b", ID: "1"})
	if _, ok := tryRecv(a); ok {
		t.Fatal("peer a received a message addressed to b")
	}
	m, ok := tryRecv(b)
	if !ok || m.To != "b" {
		t.Fatal("peer b did not receive its message")
	}

	// Broadcast reaches everyone.
	s.routeToExpert(rm, protocol.Message{Type: "x", To: "*", ID: "2"})
	if _, ok := tryRecv(a); !ok {
		t.Fatal("peer a missed the broadcast")
	}
	if _, ok := tryRecv(b); !ok {
		t.Fatal("peer b missed the broadcast")
	}

	// Empty To also broadcasts (host->expert default).
	s.routeToExpert(rm, protocol.Message{Type: "x", ID: "3"})
	if _, ok := tryRecv(a); !ok {
		t.Fatal("peer a missed the empty-To broadcast")
	}
	if _, ok := tryRecv(b); !ok {
		t.Fatal("peer b missed the empty-To broadcast")
	}

	// Unknown recipient is dropped, not broadcast.
	s.routeToExpert(rm, protocol.Message{Type: "x", To: "ghost", ID: "4"})
	if _, ok := tryRecv(a); ok {
		t.Fatal("message to unknown recipient leaked to a")
	}
	if _, ok := tryRecv(b); ok {
		t.Fatal("message to unknown recipient leaked to b")
	}
}

func TestMarkEnrolled(t *testing.T) {
	s := New()
	rm := &room{experts: make(map[*peer]string)}
	a := chanPeer("a")
	a.pending = true
	rm.experts[a] = "a"
	s.markEnrolled(rm, "a")
	if a.pending {
		t.Fatal("peer still pending after phase 3 ack")
	}
	// Unknown name: no panic, no change.
	s.markEnrolled(rm, "ghost")
}
