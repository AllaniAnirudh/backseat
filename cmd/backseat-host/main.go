// Command backseat-host runs on the novice's machine. It wraps an agent
// command in a PTY, announces the session to the relay, prints a one-time
// invite link, and lets the novice approve or deny expert control requests.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	bpty "github.com/AllaniAnirudh/backseat/internal/pty"
)

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func send(conn *websocket.Conn, msgType string, payload any) error {
	msg, err := protocol.New(msgType, newID(), time.Now().UnixMilli(), payload)
	if err != nil {
		return err
	}
	return conn.WriteJSON(msg)
}

func main() {
	agentCmd := flag.String("agent", "claude", "agent command to run, e.g. \"claude\" or \"copilot --allow-all\"")
	relay := flag.String("relay", "ws://localhost:8080/ws", "relay WebSocket URL")
	name := flag.String("name", "", "display name shown to the expert")
	base := flag.String("url", "http://localhost:8081", "public base URL used to build the invite link")
	flag.Parse()

	parts := strings.Fields(*agentCmd)
	if len(parts) == 0 {
		log.Fatal("empty agent command")
	}

	sessionID := newID()
	secret, err := pairing.GenerateSecret()
	if err != nil {
		log.Fatalf("secret: %v", err)
	}
	invite := pairing.InviteURL(*base, sessionID, secret)

	fmt.Println("Backseat session starting.")
	fmt.Println("Agent:", *agentCmd)
	fmt.Println()
	fmt.Println("Share this one-time link with your expert (expires in 10 minutes):")
	fmt.Println("  " + invite)
	fmt.Println()
	fmt.Println("Type 'grant' to approve a control request, 'deny' to refuse, 'end' to stop.")

	sess, err := bpty.Start(parts[0], parts[1:]...)
	if err != nil {
		log.Fatalf("pty: %v", err)
	}
	defer sess.Close()

	u, err := url.Parse(*relay)
	if err != nil {
		log.Fatalf("relay url: %v", err)
	}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("dial relay: %v", err)
	}
	defer conn.Close()

	hostName := *name
	if hostName == "" {
		hostName = "novice"
	}
	harness := parts[0]
	if err := send(conn, protocol.TypeSessionAnnounce, protocol.SessionAnnounce{
		SessionID: sessionID,
		HostName:  hostName,
		Harness:   harness,
		AgentCmd:  *agentCmd,
	}); err != nil {
		log.Fatalf("announce: %v", err)
	}

	controller := "host" // "host" or expert name
	pendingExpert := ""

	// PTY output -> relay broadcast.
	go func() {
		ch := sess.Subscribe()
		defer sess.Unsubscribe(ch)
		for b := range ch {
			_ = send(conn, protocol.TypeTermOutput, protocol.TermOutput{
				SessionID: sessionID,
				Data:      base64.StdEncoding.EncodeToString(b),
			})
		}
	}()

	// Relay -> local: route input and control messages.
	go func() {
		for {
			var msg protocol.Message
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			switch msg.Type {
			case protocol.TypeControlRequest:
				var p protocol.ControlRequest
				if err := msg.Decode(&p); err != nil {
					continue
				}
				pendingExpert = p.ExpertName
				fmt.Printf("\n[backseat] %s requests control", p.ExpertName)
				if p.Note != "" {
					fmt.Printf(" (%s)", p.Note)
				}
				fmt.Print(". Type 'grant' or 'deny': ")
			case protocol.TypeControlYield:
				controller = "host"
				fmt.Println("\n[backseat] control returned to you.")
			case protocol.TypeTermInput:
				if controller == "host" {
					continue // nobody else may drive while we hold control
				}
				var p protocol.TermInput
				if err := msg.Decode(&p); err != nil {
					continue
				}
				raw, err := base64.StdEncoding.DecodeString(p.Data)
				if err != nil {
					continue
				}
				sess.Write(raw)
			case protocol.TypeSessionEnd:
				fmt.Println("\n[backseat] session ended by peer.")
				sess.Close()
				os.Exit(0)
			}
		}
	}()

	// Novice console: grant, deny, end.
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
		case "grant":
			if pendingExpert == "" {
				fmt.Println("[backseat] no pending request.")
				continue
			}
			controller = pendingExpert
			_ = send(conn, protocol.TypeControlGrant, protocol.ControlGrant{
				SessionID: sessionID, ExpertName: pendingExpert,
			})
			fmt.Printf("[backseat] control handed to %s. Type 'end' to stop the session.\n", pendingExpert)
			pendingExpert = ""
		case "deny":
			if pendingExpert == "" {
				fmt.Println("[backseat] no pending request.")
				continue
			}
			_ = send(conn, protocol.TypeControlDeny, protocol.ControlDeny{
				SessionID: sessionID, ExpertName: pendingExpert,
			})
			pendingExpert = ""
		case "end":
			_ = send(conn, protocol.TypeSessionEnd, protocol.SessionEnd{SessionID: sessionID})
			sess.Close()
			return
		}
	}

	sess.Wait()
	_ = send(conn, protocol.TypeSessionEnd, protocol.SessionEnd{SessionID: sessionID, Reason: "agent exited"})
}
