# Backseat

![status](https://img.shields.io/badge/status-early%20MVP-orange)

![Expert driving a session in the browser](docs/images/expert-driving.png)

*Verified with a real headless-Chromium click-through: join as viewer, request control, host grants, typed input echoed back through the PTY, yield. Zero JS errors.*

Backseat lets an expert take over someone else's live AI coding agent session. The novice runs one command, shares a one-time link, and the expert opens it in a browser: they see the terminal, request control, and once the novice approves, they drive the agent directly on the novice's machine. It works with any CLI harness (Copilot CLI, Claude Code, OpenCode, Aider) because it captures the terminal, not each agent's private protocol.

## Status: v0.1

Works end to end on localhost: three terminals, one browser. `go build ./...`, `go vet ./...`, and `go test ./...` are green, including an in-process end-to-end test covering HMAC enrollment, encrypted control grant, driven input echoed back through per-expert encryption, input gating (non-controller and post-yield input dropped), enrollment-failure kick, pending-enrollment timeout, and clean teardown.

### What v0.1 does

- Captures any agent command in a PTY and streams the output to the host's own terminal and to connected viewers.
- One-time invite links (`{ui}/?session={id}#secret={...}`): 10-minute expiry, the secret stays in the URL fragment so it never hits a server log. Joining experts prove they hold the secret with an HMAC-SHA256 challenge-response; a wrong answer gets them kicked, and the secret itself never crosses the wire.
- End-to-end payload encryption: after enrollment, every host<->expert payload is AES-256-GCM encrypted with directional keys derived locally from the invite secret (HKDF-SHA256). The relay routes opaque envelopes and never sees session content.
- Control handoff with novice consent: request, grant, deny, yield from either side, plus kick and end. Exactly one controller at a time, enforced by the host daemon.
- Host console commands: `grant`, `deny [reason]`, `yield`, `kick <name> [reason]`, `end`, `help`.
- Self-contained expert UI: xterm.js is vendored into the `backseat-expert` binary, so the page works with no CDN or internet access.

### Security posture

The relay is untrusted by design: payloads are end-to-end encrypted and it only ever sees message types, the `to`/`from` routing fields, session ids, and timing. Honest limitations: no forward secrecy yet (a leaked invite secret decrypts that session's recorded traffic; each session gets a fresh secret), and no audit log yet. See SECURITY.md for the full scope.

### Deferred (see ARCHITECTURE.md roadmap)

- Approval forwarding with one-tap Approve/Deny buttons and checkpoints with novice-confirmed rewind (landed after v0.1). Transcript adapters and the audit log are still ahead (v0.2/v0.3).
- Novice typing directly into the PTY: in v0.1 the host stdin is a command console only.
- NAT traversal / direct transport (v0.4).

## How it works

```
 novice machine                              relay                      expert browser
┌─────────────────────────┐                ┌──────────────┐                ┌──────────────────┐
│ backseat host           │ E2E-encrypted│ backseat     │ E2E-encrypted│ backseat expert  │
│ ┌─────────────────────┐ │ envelopes    │ relay        │ envelopes    │ ┌──────────────┐ │
│ │ agent in a PTY      │─┼──────────────► routes      ├──────────────► │ terminal via │ │
│ │ (claude, copilot…)  │ │              │ opaque       │              │ │ xterm.js     │ │
│ └─────────────────────┘ │                │ envelopes    │              │ └──────────────┘ │
│  ▲                      │                │              │                │  ▲               │
│  │ invite link          │                │              │                │  │ control       │
│  │ #secret=…            │                │              │                │  │ request/grant │
│  └──────────────────────┼────────────────┤              ├────────────────┼──┘               │
│  novice approves in     │  out of band   │              │                │                  │
│  terminal: grant/deny   │  (chat, DM)    │              │                │                  │
└─────────────────────────┘                └──────────────┘                └──────────────────┘
```

1. Novice runs `backseat-host -- <agent command>` and sends the printed invite link to the expert.
2. Expert opens the link, watches the live terminal, and clicks Request control.
3. Novice types `grant` in their terminal. The expert now drives the session.
4. Either side can end it: the novice types `end`, the expert clicks Yield control.

Payloads are end-to-end encrypted from the pairing keys, so the relay never sees session content — only message types, routing fields, and timing.

## Quickstart

Prerequisites: Go 1.25+.

```bash
# terminal 1: relay (WebSocket on :8080, /ws and /healthz)
go run ./cmd/backseat-relay --addr :8080

# terminal 2: expert web UI (serves invite links on :8081)
go run ./cmd/backseat-expert --port :8081 --relay-ws ws://localhost:8080/ws

# terminal 3: novice host (prints the one-time invite link)
go run ./cmd/backseat-host --relay ws://localhost:8080 --ui http://localhost:8081 \
  --name novice -- claude
```

Any command works after `--`: `claude`, `copilot`, `opencode`, `aider`, or for a dry run with no agent installed:

```bash
go run ./cmd/backseat-host --relay ws://localhost:8080 --ui http://localhost:8081 -- \
  sh -c 'while IFS= read -r line; do printf "echo:%s\n" "$line"; done'
```

Open the printed link in a browser. The secret stays in the URL fragment, so it never hits a server log. Click Request control, type `grant` in the host terminal, and type into the browser terminal: your keystrokes drive the agent. Host console commands: `grant`, `deny [reason]`, `yield`, `kick <name> [reason]`, `end`, `help`.

## Contributing

See CONTRIBUTING.md. Issues and PRs welcome. Keep changes small and focused, add tests for protocol and pairing changes, and do not add per-harness private protocol integrations: the PTY plus transcript adapters is the whole strategy.

## License

MIT. See LICENSE.
