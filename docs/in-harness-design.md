# Backseat in-harness: design (v0.3 milestone)

Locked 2026-09-30. Supersedes the PTY-wrap model as the primary path; the PTY
host remains as a fallback and is not removed.

## Vision

The novice installs a Backseat skill in their coding-agent harness and types
`/backseat`. The harness calls the Backseat MCP server, which mints a session
link. The novice shares the link; the expert opens it (browser) or pastes the
code into a terminal (`backseat-tui join <code>`) and watches/controls the
novice's agent session to fix things.

## What "control" means in-harness (locked)

Raw keystrokes made sense for a PTY. In-harness, control is three capabilities,
gated by the existing single-controller grant model:

1. **Chat-to-agent.** The expert sends a message; the novice's agent receives it
   as an instruction ("try checking the migration order first"). This is the
   primary "fix anything" loop.
2. **Approve/deny.** Structured permission prompts from the agent surface as
   cards to the expert, same 2-minute TTL and answer semantics as v0.2. The
   agent calls `backseat__request_approval` (blocking tool call) instead of
   asking the novice.
3. **Shell side-channel (controller-only).** The expert can run shell commands
   as the novice's user (unconfined: not limited to the working directory)
   via the relay. Explicitly granted, logged, novice-visible, and the output
   is secret-masked.

What control is NOT: the expert never drives the harness UI directly. Chat
and approve/deny work with no control grant at all; only the exec
side-channel is controller-gated. And the exec privilege is real shell, not
a sandbox: the expert's commands run as the novice's own user, unconfined to
the session directory, so grants are for trusted experts only. Every
grant/deny/yield/kick/end stays enforced by the host side (now the
MCP server), never the relay.

## Architecture

```
novice harness (Claude Code / OpenCode / ...)
  └─ backseat-mcp (stdio MCP server, local subprocess)
       ├─ stdio side: tools the novice's AGENT calls
       └─ relay side: WebSocket client to backseat-relay, same E2E
           envelopes as v0.2 (HMAC enrollment, HKDF AES-256-GCM)
backseat-relay: UNCHANGED (dumb encrypted router)
expert: browser page (guest joins) OR backseat-tui (recurring expert)
```

The MCP server has two faces: it is a tool provider to the novice's agent over
stdio, and the trusted host endpoint to the expert over the relay. The relay
protocol is extended, not replaced.

## Watch plane: agent-published structured events

The MCP server cannot see the agent's transcript (it is a tool provider, not
the harness). So the skill instructs the cooperating agent to publish
significant events via `backseat__publish_event`:

- agent messages (assistant text)
- tool calls (name, summary of args, never raw secrets)
- tool results (summarized)
- permission prompts the harness itself raises (as structured data when the
  harness exposes it; the v0.2 PTY regex matcher remains the fallback)

This is honest about its trust property: the novice is cooperating, and the
expert is there to help. It is not a surveillance feed. The PTY host
(`backseat-host`) stays available for full-fidelity mirroring where wanted.

Secret hygiene: the MCP server masks common secret patterns (API keys, tokens)
in published events before forwarding to the expert, and the skill warns the
novice at share time that a viewer sees everything the agent publishes.

## MCP tool surface (called by the novice's agent)

| Tool | Purpose |
|---|---|
| `backseat__create_session(label)` | Mint invite secret, register with relay, return link + code. The skill requires explicit human confirmation before the agent calls this. |
| `backseat__publish_event(type, text, meta)` | Append a structured transcript event for the expert. |
| `backseat__poll()` | Inbox: expert chat messages, control state changes, pending items. The skill instructs the agent to call this each turn while a session is active. |
| `backseat__request_approval(prompt, options, timeout)` | Blocking: forward a structured approval to the expert, return decision. 2-min TTL, fails closed. |
| `backseat__checkpoint(label)` | Semantic checkpoint: file snapshot (reuse v0.2 code) + transcript marker. |
| `backseat__session_status()` | Who is connected, who holds control, session TTL. |
| `backseat__end_session()` | Tear down the session. |

What is deliberately NOT a tool: anything the expert invokes. The expert talks
to the MCP server over the relay WebSocket (encrypted), never through MCP.

## Relay protocol additions (v0.2 messages keep working)

- `transcript_event` (server -> expert): structured event from publish_event.
- `expert_chat` (expert -> server): message for the agent inbox.
- `approval_request` / `approval_decision` (both directions): structured form of
  the v0.2 approval flow; the PTY-matcher path is kept as fallback.
- `exec_request` / `exec_output` (expert -> server -> expert): shell
  side-channel, controller-only, novice-visible, size/time bounded.
- `checkpoint_event`: semantic checkpoint announcements (label, file snapshot
  id, transcript marker).

All new messages ride the existing encrypted envelopes. Routing metadata stays
plaintext (known v0.2 limit).

## Trust rules (carried over and extended)

- Session creation is human-gated: the MCP server prompts the human on their
  own terminal (`/dev/tty`, which the agent cannot forge) when
  `backseat__create_session` is called, on top of human-only skill flags
  (Claude Code, Cursor; Codex support is future, it has no human-only flag
  yet) and human-only command mechanisms (OpenCode, Windsurf), plus the
  skill's informed-consent question. `BACKSEAT_ASSUME_YES=1` skips the prompt
  for trusted automation. A prompt-injected agent must never mint sessions.
- Every grant is human-confirmed by the novice on their own terminal
  (`/dev/tty`) when the expert requests control, out-of-band of the model's
  tool calls (same rule as v0.2). No `ctl grant` needed in the common case.
- The MCP server is minimal and audited: it bridges to the network, so its
  tool surface is exactly the table above, nothing more.
- Invite: 10-minute expiry (v0.2), single-use (burn on first enrollment).
- Expert sees only what the agent publishes plus exec output (secret masking
  on the publish path and on exec output); granting control gives the expert
  a shell with the novice's user privileges, so grants are for trusted
  experts only.

## Per-harness shims (thin by design)

- Claude Code: skill in `~/.claude/skills/backseat/` with
  `disable-model-invocation: true`.
- OpenCode: command in `.opencode/commands/backseat.md` (human-only by
  construction) + `mcp` block docs.
- Cursor: skill with `disable-model-invocation: true`.
- Copilot CLI: skill + `/mcp add` docs.
- Each shim: install steps, the `/backseat` flow, the per-turn poll
  instruction, the publish_event narration guidance, the human-confirmation
  requirement. Shared core stays in the MCP server; shims are markdown.

## Expert TUI (`backseat-tui`, new binary)

Bubble Tea + Bubbles, same protocol and Go crypto as the browser client:

- Transcript pane (scrollable viewport): structured events, tool calls inline.
- Approval cards as keyboard-focusable widgets: `y` approve, `n` deny,
  `?` details, visible TTL countdown.
- Keys: `c` checkpoint, `r` rewind picker, `/` chat input, `?` help overlay.
- Status bar: connection, WATCHING/DRIVING, presence, relay latency.
- Join: `backseat-tui join <code>` (short code from the link).

The browser page remains for zero-install guest joins and now speaks the
in-harness protocol too: it branches on `announce.harness === "mcp"` into a
transcript pane, a chat input, approval cards with a visible TTL countdown,
and a controller-gated exec panel, while PTY sessions keep the terminal UI
unchanged. Approval semantics are identical across both clients.

## Out of scope for v0.3

- ECDH forward secrecy (protocol redesign, queued after).
- TLS-by-default relay (deployer concern, queued after).
- Audit log (easier now with structured events; still queued).
- Removing `backseat-host` (stays as the full-fidelity fallback).
- Removing the browser page or `crypto.js` (stays for guest joins).
