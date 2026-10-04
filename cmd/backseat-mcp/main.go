// Command backseat-mcp is the stdio MCP server for the backseat in-harness
// v0.3 expert-collaboration flow.
//
// As an MCP server (default mode) it exposes exactly seven tools, one
// session per process:
//
//	backseat__create_session, backseat__publish_event, backseat__poll,
//	backseat__request_approval, backseat__checkpoint, backseat__session_status,
//	backseat__end_session
//
// Control decisions (grant/deny/yield/kick/rewind confirm) are deliberately
// NOT tools: the novice human confirms them out-of-band via
// `backseat-mcp ctl`, which talks to the session over a filesystem-gated
// unix socket. Session creation is human-gated too: backseat-mcp prompts
// the human on /dev/tty (which the agent has no access to) before minting
// a session, so a prompt-injected agent can never create one on its own.
// BACKSEAT_ASSUME_YES=1 bypasses that prompt (trusts the local console
// user; for tests and headless runs).
//
// Usage:
//
//	backseat-mcp                       # stdio MCP server
//	backseat-mcp ctl [--sock PATH] <grant [name]|deny|yield|kick|end|confirm-restore|deny-restore|status> [args...]
//
// Environment:
//
//	BACKSEAT_RELAY_URL   relay websocket URL (default ws://127.0.0.1:8080/ws)
//	BACKSEAT_UI_BASE     public base URL of the expert web UI, for the invite link
//	BACKSEAT_WORKDIR     exec/checkpoint directory (default: current directory)
//	BACKSEAT_HOST_NAME   display name shown to the expert (default: agent)
//	BACKSEAT_CTL_SOCK    control socket path (default: $TMPDIR/backseat-mcp-<32 random hex>.sock)
//	BACKSEAT_ASSUME_YES  "1" answers the human-confirm prompts with yes (trusts
//	                     whoever set the launch env; for tests/headless only,
//	                     never in agent-writable config)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/mcphost"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var sess *mcphost.Session

// humanConfirmer asks the human to confirm session creation. It defaults
// to humanConfirmTTY; tests may swap it.
var humanConfirmer = humanConfirmTTY

// humanConfirmTimeout bounds how long the server waits on the human.
const humanConfirmTimeout = 60 * time.Second

// humanConfirmTTY prompts the human on /dev/tty and reads the answer
// there. The agent has no TTY, so a prompt-injected agent cannot forge the
// answer; only the human at the console can. It fails closed: no TTY, a
// denied answer, or a timeout all refuse.
//
// BACKSEAT_ASSUME_YES=1 bypasses the prompt. It trusts whoever controls the
// server's launch environment (the human's harness config, normally) to have
// set it deliberately; meant for tests and headless runs. Never put it in a
// config the agent itself can write: the agent could then mint sessions and
// confirm grants without the human.
func humanConfirmTTY(prompt string) (bool, error) {
	if os.Getenv("BACKSEAT_ASSUME_YES") == "1" {
		return true, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, fmt.Errorf("backseat: no controlling terminal for human confirmation: %w", err)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s ", prompt)
	lineCh := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(tty).ReadString('\n')
		lineCh <- line
	}()
	select {
	case line := <-lineCh:
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true, nil
		default:
			return false, nil
		}
	case <-time.After(humanConfirmTimeout):
		return false, errors.New("backseat: human confirmation timed out after 60s")
	}
}

// confirmSessionCreation gates session creation on the human. It runs
// before anything is minted: a denial means no session exists.
func confirmSessionCreation(label string) error {
	if label == "" {
		label = "untitled"
	}
	ok, err := humanConfirmer(fmt.Sprintf(
		"Backseat: create session '%s'? The invite link and code will be shown to the agent. [y/N]", label))
	if err != nil {
		return fmt.Errorf("human confirmation: %w", err)
	}
	if !ok {
		return errors.New("backseat: session creation denied by the human")
	}
	return nil
}

// defaultCtlSock builds an unpredictable socket name: 32 random hex
// chars, never the PID, so a local peer cannot guess it.
func defaultCtlSock() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return filepath.Join(os.TempDir(), fmt.Sprintf("backseat-mcp-%d.sock", os.Getpid()))
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("backseat-mcp-%x.sock", b))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func toolError(err error) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError("backseat: " + err.Error()), nil
}

func toolJSON(v any) (*mcp.CallToolResult, error) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError(err)
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func requireSession() (*mcphost.Session, error) {
	if sess == nil {
		return nil, fmt.Errorf("no session: call backseat__create_session first")
	}
	return sess, nil
}

// strMap converts a tool argument object into string fields.
func strMap(v any) map[string]string {
	out := map[string]string{}
	if m, ok := v.(map[string]any); ok {
		for k, val := range m {
			out[k] = fmt.Sprintf("%v", val)
		}
	}
	return out
}

func handleCreateSession(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if sess != nil {
		return toolError(fmt.Errorf("session already created in this process"))
	}
	label := req.GetString("label", "")
	// Human gate first: no confirmation means no session is minted.
	if err := confirmSessionCreation(label); err != nil {
		return toolError(err)
	}
	workDir := env("BACKSEAT_WORKDIR", "")
	if workDir == "" {
		var err error
		workDir, err = os.Getwd()
		if err != nil {
			return toolError(err)
		}
	}
	s, err := mcphost.New(mcphost.Config{
		RelayURL:     env("BACKSEAT_RELAY_URL", "ws://127.0.0.1:8080/ws"),
		UIBase:       env("BACKSEAT_UI_BASE", "http://localhost:8081"),
		HostName:     env("BACKSEAT_HOST_NAME", "agent"),
		Harness:      "mcp",
		WorkDir:      workDir,
		HumanConfirm: humanConfirmer,
		OnEvent: func(ev string) {
			fmt.Fprintf(os.Stderr, "backseat: %s\n", ev)
		},
	})
	if err != nil {
		return toolError(err)
	}
	sockPath := env("BACKSEAT_CTL_SOCK", "")
	if sockPath == "" {
		sockPath = defaultCtlSock()
	}
	go func() {
		if err := s.ServeControl(sockPath); err != nil {
			fmt.Fprintf(os.Stderr, "backseat: control socket: %v\n", err)
		}
	}()
	sess = s
	// The control socket path is deliberately NOT in the tool result: the
	// human reads it from the server's stderr. Printing it here would hand
	// it to the agent.
	return toolJSON(map[string]any{
		"session_id":  s.SessionID(),
		"expert_url":  s.InviteURL(),
		"expert_code": s.InviteCode(),
		"label":       label,
		"note": "Share expert_url with the human expert. Control requests and " +
			"rewind requests need the novice's confirmation via " +
			"`backseat-mcp ctl --sock <socket> <command>`; the socket path is " +
			"printed on the server's stderr at startup.",
	})
}

func handlePublishEvent(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	kind, err := req.RequireString("type")
	if err != nil {
		return toolError(fmt.Errorf("type: %w", err))
	}
	text, err := req.RequireString("text")
	if err != nil {
		return toolError(fmt.Errorf("text: %w", err))
	}
	fields := map[string]any{}
	// Mask structurally BEFORE stringifying: nested maps stay maps for
	// the masker, and secret-looking keys redact wholesale.
	if m, ok := req.GetArguments()["meta"].(map[string]any); ok && len(m) > 0 {
		for k, v := range strMap(mcphost.MaskSecretFields(m)) {
			fields[k] = v
		}
	}
	s.PublishEvent(kind, text, fields)
	return toolJSON(map[string]any{"published": true, "type": kind})
}

func handlePoll(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	items := s.Poll()
	if items == nil {
		items = []mcphost.InboxItem{}
	}
	return toolJSON(map[string]any{"items": items})
}

func handleRequestApproval(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	prompt, err := req.RequireString("prompt")
	if err != nil {
		return toolError(fmt.Errorf("prompt: %w", err))
	}
	options := req.GetStringSlice("options", nil)
	timeout := time.Duration(req.GetInt("timeout", 120)) * time.Second
	// Blocking: resolves when the expert decides, or fail-closed on timeout.
	choice, err := s.RequestApproval(ctx, prompt, options, timeout)
	if err != nil {
		return toolError(err)
	}
	return toolJSON(map[string]any{"decision": choice})
}

func handleCheckpoint(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	label, err := req.RequireString("label")
	if err != nil {
		return toolError(fmt.Errorf("label: %w", err))
	}
	cp, err := s.Checkpoint(label)
	if err != nil {
		return toolError(err)
	}
	return toolJSON(map[string]any{
		"label":      cp.Label,
		"created_at": cp.CreatedAt.Unix(),
	})
}

func handleSessionStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	return toolJSON(s.Status())
}

func handleEndSession(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := requireSession()
	if err != nil {
		return toolError(err)
	}
	s.End(req.GetString("reason", ""))
	return toolJSON(map[string]any{"ended": true})
}

// buildMCPServer registers all seven backseat tools with their annotations.
// Kept separate from runMCPServer so tests can inspect the tool list.
func buildMCPServer() *server.MCPServer {
	srv := server.NewMCPServer("backseat", "0.3.0")

	srv.AddTool(mcp.NewTool("backseat__create_session",
		mcp.WithDescription("Create one expert-collaboration session. Asks the human for confirmation first; returns the expert invite URL and code. One session per process."),
		mcp.WithString("label", mcp.Description("Human-readable label for the session")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	), handleCreateSession)

	srv.AddTool(mcp.NewTool("backseat__publish_event",
		mcp.WithDescription("Publish a progress event to the expert (secrets are masked before sending)."),
		mcp.WithString("type", mcp.Required(), mcp.Description("Event type, e.g. progress, blocked, done")),
		mcp.WithString("text", mcp.Required(), mcp.Description("Human-readable event text")),
		mcp.WithObject("meta", mcp.Description("Extra string fields attached to the event")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	), handlePublishEvent)

	srv.AddTool(mcp.NewTool("backseat__poll",
		mcp.WithDescription("Drain the novice inbox: expert chat, control state changes, exec runs, checkpoint notices. Returns items oldest-first and clears them."),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
	), handlePoll)

	srv.AddTool(mcp.NewTool("backseat__request_approval",
		mcp.WithDescription("Ask the expert to approve or deny something. BLOCKS until the expert decides or the timeout elapses (fail-closed: timeout means denied)."),
		mcp.WithString("prompt", mcp.Required(), mcp.Description("What the expert is being asked to decide")),
		mcp.WithArray("options", mcp.Description("Allowed choices shown as one-tap cards"), mcp.WithStringItems()),
		mcp.WithNumber("timeout", mcp.Description("Seconds to wait before failing closed (default 120, max 120)")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	), handleRequestApproval)

	srv.AddTool(mcp.NewTool("backseat__checkpoint",
		mcp.WithDescription("Snapshot the working directory so the expert can rewind to it later."),
		mcp.WithString("label", mcp.Required(), mcp.Description("Checkpoint label, e.g. before-risky-change")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
	), handleCheckpoint)

	srv.AddTool(mcp.NewTool("backseat__session_status",
		mcp.WithDescription("Session state: controller, pending requests, enrolled experts, checkpoints, invite state."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	), handleSessionStatus)

	srv.AddTool(mcp.NewTool("backseat__end_session",
		mcp.WithDescription("End the session for everyone. The invite is invalidated and enrolled experts are disconnected."),
		mcp.WithString("reason", mcp.Description("Why the session is ending")),
		mcp.WithReadOnlyHintAnnotation(false),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	), handleEndSession)

	return srv
}

func runMCPServer() error {
	if os.Getenv("BACKSEAT_ASSUME_YES") == "1" {
		fmt.Fprintln(os.Stderr, "backseat: WARNING: BACKSEAT_ASSUME_YES=1 is set: human confirmation prompts are DISABLED. "+
			"Only set this for trusted automation or tests; never in a config the agent can write, "+
			"or a prompt-injected agent could create sessions and approve grants on its own.")
	}
	return server.ServeStdio(buildMCPServer())
}

// runCtl speaks to a running session's control socket: the novice human's
// confirm path for control and rewind decisions.
func runCtl(args []string) error {
	sockPath := env("BACKSEAT_CTL_SOCK", "")
	rest := args
	if len(rest) >= 2 && rest[0] == "--sock" {
		sockPath = rest[1]
		rest = rest[2:]
	}
	if sockPath == "" {
		return fmt.Errorf("control socket unknown: pass --sock PATH or set BACKSEAT_CTL_SOCK")
	}
	if len(rest) == 0 {
		return fmt.Errorf("usage: backseat-mcp ctl [--sock PATH] <grant [name]|deny|yield|kick|end|confirm-restore|deny-restore|status> [args...]")
	}
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("dial control socket: %w", err)
	}
	defer conn.Close()
	raw, _ := json.Marshal(map[string]any{"cmd": rest[0], "args": rest[1:]})
	if _, err := fmt.Fprintf(conn, "%s\n", raw); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	var resp struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Result string `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &resp); err != nil {
		return fmt.Errorf("bad control response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("ctl: %s", resp.Error)
	}
	if resp.Result != "" {
		fmt.Println(resp.Result)
	} else {
		fmt.Println("ok")
	}
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "ctl" {
		if err := runCtl(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "backseat-mcp:", err)
			os.Exit(1)
		}
		return
	}
	if err := runMCPServer(); err != nil {
		fmt.Fprintln(os.Stderr, "backseat-mcp:", err)
		os.Exit(1)
	}
}
