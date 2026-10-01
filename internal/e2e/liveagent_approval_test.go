// Live approval probe: asks the real model to run a shell command through
// the opencode TUI and observes whether Backseat's heuristic approval
// matcher catches the prompt, forwards it, and applies the expert's answer.
//
// This is a probe, not a hard gate: whether opencode asks for approval at
// all depends on the model's permission behavior, which Backseat does not
// control. Outcomes:
//   - approval_request arrives -> answer approve -> command output streams
//     back: full forward-and-answer proven against the live agent.
//   - command output arrives with no approval prompt: t.Skip, the model ran
//     it unasked and there was nothing to forward.
//   - neither within the budget: t.Fatal, the agent went silent.
package e2e

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/backseat/internal/host"
	"github.com/AllaniAnirudh/backseat/internal/pairing"
	"github.com/AllaniAnirudh/backseat/internal/protocol"
)

func TestLiveOpenCodeApprovalProbe(t *testing.T) {
	if os.Getenv("BACKSEAT_LIVE_AGENT_TEST") == "" {
		t.Skip("live agent test: set BACKSEAT_LIVE_AGENT_TEST=1")
	}
	agentBin := findOpenCode(t)
	workDir := t.TempDir()

	wsURL := startTestRelay(t)
	stage("A0 relay up; booting live opencode for the approval probe")
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
		Decide:    func(protocol.ControlRequest) bool { return true },
	})
	if err != nil {
		t.Fatalf("host.New: %v", err)
	}
	defer h.End("approval probe cleanup")

	conn, keys := enrollExpertHarness(t, wsURL, "expert1", secret, "opencode")
	sendEncrypted(t, conn, keys.ExpertToHost, "expert1", protocol.TypeControlRequest, protocol.ControlRequest{
		SessionID: sessionID, ExpertName: "expert1",
	})
	readUntil(t, conn, 10*time.Second, protocol.TypeControlGrant)
	awaitTuiReady(t, conn, keys, 60*time.Second)
	stage("A1 expert in control; asking the live model to write a file")

	sendEncrypted(t, conn, keys.ExpertToHost, "expert1", protocol.TypeTermInput, protocol.TermInput{
		SessionID: sessionID,
		Data: base64.StdEncoding.EncodeToString([]byte(
			"Create a file named approval-probe.txt in the current directory containing exactly the text PROBE_WRITE_OK and nothing else.\n")),
	})

	deadline := time.Now().Add(150 * time.Second)
	sawApproval := false
	for time.Now().Before(deadline) {
		msg := readEnvelope(t, conn, time.Until(deadline))
		switch msg.Type {
		case protocol.TypeApprovalRequest:
			var req protocol.ApprovalRequest
			openPayload(t, msg, keys.HostToExpert, &req)
			sawApproval = true
			stage("A2 approval prompt caught by the matcher (tool=%s); answering approve", req.Tool)
			sendEncrypted(t, conn, keys.ExpertToHost, "expert1", protocol.TypeApprovalResponse, protocol.ApprovalResponse{
				SessionID: sessionID, ApprovalID: req.ApprovalID, Approved: true,
			})
		case protocol.TypeTermOutput:
			out := decodeOutput(t, msg, keys.HostToExpert)
			if strings.Contains(out, "PROBE_WRITE_OK") {
				if !sawApproval {
					t.Skip("model wrote the file without an approval prompt; nothing to forward")
				}
				stage("A3 file written after approval; live approval path verified")
				return
			}
		}
	}
	t.Fatal("probe timed out: the live agent never answered and no approval prompt was forwarded")
}
