# Backseat

![status](https://img.shields.io/badge/status-early%20MVP-orange)

Backseat lets an expert take over someone else's live AI coding agent session. The novice runs one command, shares a one-time link, and the expert opens it in a browser: they see the terminal, request control, and once the novice approves, they drive the agent directly on the novice's machine, including one-tap approval of the agent's tool calls. It works with any CLI harness (Copilot CLI, Claude Code, OpenCode, Aider) because it captures the terminal, not each agent's private protocol.

## How it works

```
 novice machine                              relay (untrusted)                expert browser
┌─────────────────────────┐                ┌──────────────┐                ┌──────────────────┐
│ backseat host           │   opaque WS    │ backseat     │   opaque WS    │ backseat expert  │
│ ┌─────────────────────┐ │   envelopes    │ relay        │   envelopes    │ ┌──────────────┐ │
│ │ agent in a PTY      │─┼───────────────►│ routes by    ├───────────────►│ │ terminal via │ │
│ │ (claude, copilot…)  │ │                │ session id   │                │ │ xterm.js     │ │
│ └─────────────────────┘ │                │ never sees   │                │ └──────────────┘ │
│  ▲                      │                │ plaintext    │                │  ▲               │
│  │ invite link          │                │ (E2E keys    │                │  │ control       │
│  │ #secret=…            │                │ from pairing)│                │  │ request/grant │
│  └──────────────────────┼────────────────┤              ├────────────────┼──┘               │
│  novice approves in     │  out of band   │              │                │                  │
│  terminal: grant/deny   │  (chat, DM)    │              │                │                  │
└─────────────────────────┘                └──────────────┘                └──────────────────┘
```

1. Novice runs `backseat host -- claude` and sends the printed invite link to the expert.
2. Expert opens the link, watches the live terminal, and clicks Request control.
3. Novice types `grant` in their terminal. The expert now drives the session.
4. Agent tool approvals surface as one-tap Approve/Deny buttons for the expert.
5. Either side can end it instantly. The relay only routes encrypted envelopes.

## Quickstart

Prerequisites: Go 1.25+, a running relay, one CLI agent installed.

```bash
# terminal 1: relay
go run ./cmd/backseat-relay

# terminal 2: expert UI (serves invite links)
go run ./cmd/backseat-expert

# terminal 3: novice host (prints the invite link)
go run ./cmd/backseat-host --agent "claude" --relay ws://localhost:8080/ws --url http://localhost:8081
```

Open the printed link in a browser, request control, type `grant` in the host terminal. You are driving the session.

## Status

Early MVP. PTY capture, control handoff with novice consent, and the WebSocket relay work. Transcript adapters, approval forwarding crypto, and checkpoints are specified in ARCHITECTURE.md but not built yet. See the roadmap there.

## Contributing

Issues and PRs welcome. Keep changes small and focused, add tests for protocol and pairing changes, and do not add per-harness private protocol integrations: the PTY plus transcript adapters is the whole strategy.

## License

MIT. See LICENSE.
