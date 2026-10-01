// Live-agent test: drives a REAL opencode CLI agent through the full
// Backseat flow (enroll -> request control -> auto-grant -> driven input ->
// agent output streams back). This is the closest thing to a novice/expert
// session with a genuine coding agent in the PTY.
//
// It needs the opencode binary, network access, and a working model
// credential (OpenCode Zen in this repo's case), so it is skipped unless
// BACKSEAT_LIVE_AGENT_TEST=1 is set. Keep it out of the default suite:
// free-tier model latency makes it far too slow for CI.
package e2e

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
	"github.com/gorilla/websocket"
)

// stage narrates the test's progress to stdout so a human watching the run
// (or a recording of it) can follow along in real time. t.Log would buffer
// until the test ends; fmt goes straight to the terminal.
func stage(format string, args ...any) {
	fmt.Printf("[live-agent] "+format+"\n", args...)
}

// findOpenCode locates the real opencode CLI the test drives.
func findOpenCode(t *testing.T) string {
	t.Helper()
	agentBin, err := exec.LookPath("opencode")
	if err != nil {
		t.Skip("live agent test: opencode not on PATH")
	}
	return agentBin
}

// awaitTuiReady waits until the live opencode TUI has rendered its prompt
// box ("Ask anything" placeholder) on the given expert's stream.
func awaitTuiReady(t *testing.T, conn *websocket.Conn, keys pairing.Keys, timeout time.Duration) {
	t.Helper()
	liveAwaitText(t, conn, keys, "Ask anything", "", timeout)
}

func TestLiveOpenCodeAgent(t *testing.T) {
	if os.Getenv("BACKSEAT_LIVE_AGENT_TEST") == "" {
		t.Skip("set BACKSEAT_LIVE_AGENT_TEST=1 to run against the real opencode CLI")
	}
	agentBin := findOpenCode(t)
	workDir := "/tmp/bs-agent-test"
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	wsURL := startTestRelay(t)
	stage("1/6 relay up at %s", wsURL)
	secret, err := pairing.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	h, err := host.New(host.Config{
		RelayURL:  wsURL,
		SessionID: sessionID,
		Secret:    secret,
		HostName:  "testhost",
		Harness:   "opencode",
		AgentCmd:  []string{agentBin},
		WorkDir:   workDir,
		Decide:    func(protocol.ControlRequest) bool { return true }, // auto-grant
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("live agent test cleanup")
	stage("2/6 host started: real `opencode` agent booting in the PTY")

	// Enroll, request control, expect the auto-grant.
	conn, keys := enrollExpertHarness(t, wsURL, "expert1", secret, "opencode")
	sendEncrypted(t, conn, keys.ExpertToHost, "expert1", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID:  sessionID,
		ExpertName: "expert1",
	})
	readUntil(t, conn, 10*time.Second, protocol.TypeControlGrant)
	waitFor(t, 10*time.Second, func() bool { return h.Controller() == "expert1" }, "controller expert1")
	stage("3/6 expert enrolled (HMAC) and granted control")

	// Wait for the opencode TUI to finish rendering before typing, so the
	// keystrokes land in its prompt box and not in a startup dialog.
	awaitTuiReady(t, conn, keys, 60*time.Second)
	stage("4/6 live opencode TUI rendered in the PTY; driving a prompt through the encrypted channel")

	// Drive a prompt through the expert channel and expect the live model
	// to answer with the marker.
	sendEncrypted(t, conn, keys.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString([]byte("Reply with exactly: DRIVEN_OK\n")),
	})
	deadline := time.Now().Add(150 * time.Second)
	for time.Now().Before(deadline) {
		msg := readEnvelope(t, conn, time.Until(deadline))
		if msg.Type == protocol.TypeTermOutput &&
			strings.Contains(decodeOutput(t, msg, keys.HostToExpert), "DRIVEN_OK") {
			stage("5/6 live model answered DRIVEN_OK through the encrypted output channel")
			stage("6/6 PASS: view + enroll + grant + drive + answer, all with a real coding agent")
			return // live agent answered through the Backseat channel
		}
	}
	t.Fatal("timed out waiting for the live agent to answer DRIVEN_OK")
}
