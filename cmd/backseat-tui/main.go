// Command backseat-tui is the terminal expert client for in-harness
// backseat sessions. It speaks the same encrypted relay protocol as the
// browser expert page: secretless room_join, two-phase HMAC enrollment
// with the invite secret, then sealed envelopes in both directions.
//
// Usage:
//
//	backseat-tui join <code> [--relay-ws ws://host:8080/ws] [--name NAME] [--secret SECRET]
//
// The code is the short code from the session link (<session>#<secret>);
// the full invite link works too. The relay never sees the secret.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const defaultRelayWS = "ws://localhost:8080/ws"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "backseat-tui: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] != "join" {
		return errors.New("usage: backseat-tui join <code> [--relay-ws URL] [--name NAME] [--secret SECRET]")
	}
	fs := flag.NewFlagSet("join", flag.ContinueOnError)
	relayWS := fs.String("relay-ws", defaultRelayWS, "relay WebSocket URL")
	name := fs.String("name", "", "expert display name")
	secretFlag := fs.String("secret", "", "invite secret (base64url); prompted if the code has none")
	flagArgs, posArgs := splitFlags(args[1:])
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	rest := append(fs.Args(), posArgs...)
	if len(rest) != 1 {
		return errors.New("usage: backseat-tui join <code> [--relay-ws URL] [--name NAME] [--secret SECRET]")
	}

	expertName := strings.TrimSpace(*name)
	if expertName == "" {
		n, err := promptLine("Your name: ")
		if err != nil {
			return err
		}
		expertName = strings.TrimSpace(n)
		if expertName == "" {
			expertName = "expert"
		}
	}

	target, err := parseJoinArg(rest[0], *relayWS)
	if errors.Is(err, errNeedSecret) {
		sec := strings.TrimSpace(*secretFlag)
		if sec == "" {
			sec, err = promptSecret("Invite secret: ")
			if err != nil {
				return err
			}
		}
		s, perr := secretFromFragment(sec)
		if perr != nil {
			return perr
		}
		target.secret = s
	} else if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := newModel(nil, target.sessionID, expertName) // out wired below
	prog := tea.NewProgram(m, tea.WithAltScreen())
	client := newClient(target, expertName, func(ev clientEvent) {
		prog.Send(clientEventMsg{ev: ev})
	})
	m.out = client

	fmt.Fprintf(os.Stderr, "joining session %s as %s…\n", target.sessionID, expertName)
	runErr := make(chan error, 1)
	go func() { runErr <- client.run(ctx) }()
	if _, err := prog.Run(); err != nil {
		return err
	}
	cancel()
	client.Close()
	<-runErr
	return nil
}

// promptLine reads one line from the controlling terminal (not stdin: the
// TUI owns stdin once it starts).
func promptLine(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal for prompt: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := tty.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	fmt.Fprintln(tty)
	return sb.String(), nil
}

// promptSecret reads the invite secret without echoing it.
func promptSecret(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal for prompt: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	raw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// splitFlags partitions argv into flag-like args (and their values) and
// positional args, so `join <code> [--flags]` works the way the usage
// string reads. All join flags take values: a bare `-flag` consumes the
// next arg unless it looks like another flag or uses `-flag=value`.
func splitFlags(argv []string) (flagArgs, posArgs []string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flagArgs = append(flagArgs, a)
			if !strings.Contains(a, "=") && i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
				i++
				flagArgs = append(flagArgs, argv[i])
			}
			continue
		}
		posArgs = append(posArgs, a)
	}
	return flagArgs, posArgs
}
