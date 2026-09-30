# Backseat

![status](https://img.shields.io/badge/status-early%20MVP-orange)

![Expert driving a session in the browser](docs/images/expert-driving.png)

*Verified with a real headless-Chromium click-through: join as viewer, request control, host grants, typed input echoed back through the PTY, yield. Zero JS errors.*

Backseat lets an expert take over someone else's live AI coding agent session. The novice runs one command, shares a one-time link, and the expert opens it in a browser: they see the terminal, request control, and once the novice approves, they drive the agent directly on the novice's machine. It works with any CLI harness (Copilot CLI, Claude Code, OpenCode, Aider) because it captures the terminal, not each agent's private protocol.

## Status: v0.1

Works end to end on localhost: three terminals, one browser. `go build ./...`, `go vet ./...`, and `go test ./...` are green, including an in-process end-to-end test covering join, bad-secret rejection, control grant, driven input echoed back, input gating after yield, and clean teardown.

### What v0.1 does

- Captures any agent command in a PTY and streams the output to the host's own terminal and to connected viewers.
- One-time invite links (`{ui}/?session={id}#secret={...}`): 10-minute expiry, the secret stays in the URL fragment so it never hits a server log, verified in constant time against a stored hash. A wrong secret gets an error and a closed connection; the secret is never logged.
- Control handoff with novice consent: request, grant, deny, yield from either side, plus kick and end. Exactly one controller at a time, enforced by the host daemon and double-checked by the relay.
- Host console commands: `grant`, `deny [reason]`, `yield`, `kick <name> [reason]`, `end`, `help`.
- Self-contained expert UI: xterm.js is vendored into the `backseat-expert` binary, so the page works with no CDN or internet access.

### Honest limitation

The v0.1 relay routes plaintext envelopes, so run your own relay or one you trust. End-to-end payload encryption is on the v0.3 roadmap. See SECURITY.md for the full scope.

### Deferred (see ARCHITECTURE.md roadmap)

- End-to-end payload encryption from pairing keys (v0.3).
- Transcript adapters, approval forwarding with one-tap buttons, checkpoints and rewind (v0.2/v0.3).
- Novice typing directly into the PTY: in v0.1 the host stdin is a command console only.
- NAT traversal / direct transport (v0.4).

## How it works

```
 novice machine                              relay                      expert browser
┌─────────────────────────┐                ┌──────────────┐                ┌──────────────────┐
│ backseat host           │   WS envelopes │ backseat     │   WS envelopes │ backseat expert  │
│ ┌─────────────────────┐ │                │ relay        │                │ ┌──────────────┐ │
│ │ agent in a PTY      │─┼───────────────►│ routes by    ├───────────────►│ │ terminal via │ │
│ │ (claude, copilot…)  │ │                │ session id   │                │ │ xterm.js     │ │
│ └─────────────────────┘ │                │              │                │ └──────────────┘ │
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

Note: v0.1 does not yet do end-to-end encryption, so run your own relay or one you trust. E2E from pairing keys is on the v0.3 roadmap.

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
