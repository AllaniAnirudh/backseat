// Command backseat-relay is a self-hostable WebSocket relay. It routes
// opaque protocol envelopes between a host and attached experts, keyed by
// session id. See internal/relay for the routing logic.
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/AllaniAnirudh/backseat/internal/relay"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	srv := relay.New()
	mux := http.NewServeMux()
	mux.Handle("/ws", srv)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("backseat relay listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
