// Command backseat-host runs on the novice's machine. It wraps an agent
// command in a PTY, announces the session to the relay, prints a one-time
// invite link, and lets the novice approve or deny expert control requests
// from the console: grant, deny, yield, kick, end.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
)

func newSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	relayURL := flag.String("relay", "ws://localhost:8080", "relay WebSocket URL (path /ws is added when missing)")
	uiBase := flag.String("ui", "http://localhost:8081", "public base URL of the expert web UI, used to build the invite link")
	name := flag.String("name", "novice", "display name shown to the expert")
	harness := flag.String("harness", "", "harness label shown to the expert (defaults to the agent command name)")
	flag.Parse()

	agentCmd := flag.Args()
	if len(agentCmd) == 0 {
		log.Fatal("usage: backseat-host [--relay URL] [--ui URL] -- <agent command...>")
	}
	if *harness == "" {
		*harness = agentCmd[0]
	}

	u, err := url.Parse(*relayURL)
	if err != nil {
		log.Fatalf("relay url: %v", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/ws"
	}

	sessionID := newSessionID()
	secret, err := pairing.GenerateSecret()
	if err != nil {
		log.Fatalf("secret: %v", err)
	}
	invite := pairing.InviteURL(*uiBase, sessionID, secret)

	fmt.Println("Backseat session starting.")
	fmt.Println("Agent:", strings.Join(agentCmd, " "))
	fmt.Println()
	fmt.Println("Share this one-time link with your expert (expires in 10 minutes):")
	fmt.Println("  " + invite)
	fmt.Println()
	fmt.Println("Commands: grant | deny [reason] | yield | kick <name> [reason] | end")
	fmt.Println("          checkpoint <label> | checkpoints | rewind <label> | confirm-rewind | deny-rewind [reason]")

	h, err := host.New(host.Config{
		RelayURL:  u.String(),
		SessionID: sessionID,
		Secret:    secret,
		HostName:  *name,
		Harness:   *harness,
		AgentCmd:  agentCmd,
		// Decide nil: control requests wait for a console grant/deny.
		OnOutput: func(b []byte) { os.Stdout.Write(b) },
		OnEvent:  func(s string) { fmt.Println("\n[backseat] " + s) },
	})
	if err != nil {
		log.Fatalf("host: %v", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		cmd, rest, _ := strings.Cut(line, " ")
		rest = strings.TrimSpace(rest)
		switch strings.ToLower(cmd) {
		case "grant":
			if err := h.Grant(); err != nil {
				fmt.Println("[backseat]", err)
			}
		case "deny":
			if err := h.Deny(rest); err != nil {
				fmt.Println("[backseat]", err)
			} else {
				fmt.Println("[backseat] request denied.")
			}
		case "yield":
			h.Yield()
		case "kick":
			who, reason, _ := strings.Cut(rest, " ")
			if who == "" {
				fmt.Println("[backseat] usage: kick <name> [reason]")
				continue
			}
			h.Kick(who, strings.TrimSpace(reason))
		case "end":
			h.End("novice ended the session")
			fmt.Println("[backseat] session ended.")
			return
		case "checkpoint":
			if rest == "" {
				fmt.Println("[backseat] usage: checkpoint <label>")
				continue
			}
			if _, err := h.Checkpoint(rest); err != nil {
				fmt.Println("[backseat]", err)
			} else {
				fmt.Println("[backseat] checkpoint", rest, "created.")
			}
		case "checkpoints":
			cps := h.ListCheckpoints()
			if len(cps) == 0 {
				fmt.Println("[backseat] no checkpoints yet.")
				continue
			}
			for _, cp := range cps {
				fmt.Printf("[backseat] %-24s %s (%s)\n", cp.Label, cp.CreatedAt.Format("15:04:05"), cp.Kind)
			}
		case "rewind":
			if rest == "" {
				fmt.Println("[backseat] usage: rewind <label>")
				continue
			}
			if err := h.RestoreCheckpoint(rest); err != nil {
				fmt.Println("[backseat]", err)
			} else {
				fmt.Println("[backseat] rewound to", rest)
			}
		case "confirm-rewind":
			if err := h.ConfirmRewind(); err != nil {
				fmt.Println("[backseat]", err)
			} else {
				fmt.Println("[backseat] rewind confirmed and executed.")
			}
		case "deny-rewind":
			if err := h.DenyRewind(rest); err != nil {
				fmt.Println("[backseat]", err)
			} else {
				fmt.Println("[backseat] rewind denied.")
			}
		case "help":
			fmt.Println("[backseat] commands: grant | deny [reason] | yield | kick <name> [reason] | end")
			fmt.Println("[backseat]           checkpoint <label> | checkpoints | rewind <label> | confirm-rewind | deny-rewind [reason]")
		default:
			fmt.Println("[backseat] unknown command. Type 'help'.")
		}
	}
	// Stdin closed: keep the session alive until the agent exits or the
	// relay drops it.
	<-h.Done()
	h.Wait()
	fmt.Println("[backseat] session over.")
}
