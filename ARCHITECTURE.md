# Backseat architecture (MVP)

## Components

**Host daemon** (`cmd/backseat-host`, `internal/pty`). Runs on the novice's machine. Wraps the agent command in a PTY via creack/pty, announces the session to the relay, prints the one-time invite link, and enforces control state locally: only the current controller's input reaches the PTY. The novice approves or denies control requests by typing `grant` or `deny` in the host terminal, and can kill the session at any time with `end`.

**Relay server** (`cmd/backseat-relay`). Self-hostable WebSocket relay. Rooms are keyed by session id; the relay forwards opaque JSON envelopes between host and experts and keeps no other state. It never sees plaintext: after pairing completes, payloads are end-to-end encrypted between host and expert, so a hostile or curious relay operator learns nothing about the session contents.

**Expert client** (`cmd/backseat-expert`). Web UI served over HTTP. Shows the live terminal via xterm.js, a transcript pane (planned), a Request control button, and Approve/Deny buttons for forwarded agent tool calls. The invite secret stays in the URL fragment, so it never reaches any server in an HTTP request.

## Protocol messages

All messages are JSON over WebSocket inside the `Message` envelope (`type`, `id`, `ts`, `payload`). See `internal/protocol` for the structs.

| Message | Purpose | Key fields |
|---|---|---|
| `session_announce` | Host declares a live session to the relay | `session_id`, `host_name`, `harness`, `agent_cmd` |
| `pairing_invite` | Host issues a one-time invitation | `session_id`, `invite_id`, `expires_at` |
| `pairing_enroll` | One step of the two-phase HMAC enrollment | `session_id`, `invite_id`, `phase`, `challenge`, `response` |
| `control_request` | Expert asks the novice for control | `session_id`, `expert_name`, `note` |
| `control_grant` | Novice hands control to the expert | `session_id`, `expert_name` |
| `control_deny` | Novice refuses the request | `session_id`, `expert_name`, `reason` |
| `control_yield` | Controller releases control back to the novice | `session_id`, `expert_name` |
| `control_force` | Seize control without a handshake | `session_id`, `expert_name`, `pre_authorized` |
| `term_input` | Keystrokes from the current controller to the PTY | `session_id`, `data` (base64) |
| `term_output` | PTY output broadcast to all attached viewers | `session_id`, `data` (base64) |
| `transcript_event` | Parsed harness event from a transcript adapter | `session_id`, `harness`, `kind`, `text`, `fields` |
| `approval_request` | Agent tool approval forwarded to the expert | `session_id`, `approval_id`, `tool`, `summary`, `command` |
| `approval_response` | Expert's one-tap decision | `session_id`, `approval_id`, `approved` |
| `checkpoint_create` | Snapshot the working tree before risky work | `session_id`, `label` |
| `checkpoint_restore` | Rewind the working tree to a checkpoint | `session_id`, `label` |
| `session_end` | Terminate the session, drop all attachments | `session_id`, `reason` |

## Pairing ceremony

Stolen from copilot-agent-mesh's design, reimplemented CLI-first with no editor dependency.

1. The host generates a random 32-byte secret and builds a one-time invite URL: `{base}/join/{session_id}#secret={base64url}`. The secret lives only in the URL fragment, so it is never sent to any server.
2. The invite expires after 10 minutes and is single use. Expired or reused invites fail closed.
3. Two-phase enrollment over the relay:
   - Phase 1: the host sends a fresh random 32-byte challenge (`pairing_enroll`, `phase: 1`).
   - Phase 2: the expert replies with HMAC-SHA256(secret, challenge) (`phase: 2`). The host verifies in constant time. The secret itself never crosses the wire.
4. Both sides run HKDF-SHA256(secret, salt=challenge, info="backseat-v1-pairing") locally and split the 64-byte output into two directional keys: host-to-expert and expert-to-host. Keys are never transmitted.
5. Enrollment commit is idempotent: replaying a completed enrollment returns the existing session keys instead of creating a second pairing.

## Control model

Stolen from AgentDeck's single-controller plus multi-viewer protocol, with the missing piece added.

- Exactly one controller drives the PTY at a time. Everyone else attached is view-only and receives `term_output`.
- `control_request` triggers an explicit accept/deny handshake on the novice's side. The novice types `grant` or `deny` in the host terminal. There is no silent takeover by default.
- `control_yield` returns control to the novice at any time, from either side.
- `control_force` exists for trusted setups (for example a teammate pair-programming daily), but it only works when the novice enabled a pre-authorization toggle for that session. Without it, the host rejects the message.
- Control state is enforced by the host daemon, not by the relay: even a compromised relay cannot grant itself input rights.

## Harness-agnostic strategy

The universal layer is PTY capture. Every CLI agent (Copilot CLI, Claude Code, OpenCode, Aider) renders to a terminal, so backseat drives all of them through `internal/pty` without knowing anything about their internals.

The structured side channel is a set of thin transcript adapters (`adapters/`). Each adapter implements `TranscriptAdapter` (`Name`, `ParseEvent`) and parses that harness's transcript or session files into typed events: prompts, tool calls, tool results, approvals, plain text. Adapters are best effort: unknown lines become plain text or are skipped, never fatal.

Hard rule: never integrate with a harness's private agent protocol. That is how Copilot-specific tools get trapped by one vendor's closed API. The PTY plus transcript adapters is the whole strategy, and it is what keeps backseat working when the next harness appears.

## Differentiator: structured mid-turn intervention

Raw terminal sharing already exists (tmate). Backseat earns its place with three things neither tmate nor the current open-source attempts have:

1. **Approval forwarding.** When the agent asks "run this command?", the prompt is parsed by the transcript adapter and forwarded as `approval_request`. The expert answers with one tap instead of watching the terminal and typing.
2. **Parsed transcript streaming.** The expert sees a structured event feed (tool calls, results, prompts) next to the raw terminal, so they can follow a fast agent without reading scrolling bytes.
3. **Checkpoints and rewind.** `checkpoint_create` snapshots the working tree before risky expert-driven work; `checkpoint_restore` rewinds it. The expert can undo, which is what makes handing control to someone else safe to try.

## Security model

- **Default deny.** Nothing is shared until the novice runs the host and hands out a link. No open ports on the novice's machine; the host dials out to the relay.
- **Scoped grants.** Invites are session-scoped, single use, and expire in 10 minutes. Control grants cover one session and end with it.
- **Novice kill switch.** Typing `end` in the host terminal (or killing the process) terminates the session, drops all relay attachments, and closes the PTY.
- **Untrusted relay.** Payloads are end-to-end encrypted with the paired keys. The relay routes opaque envelopes and cannot read session contents.
- **Audit log.** The host records every expert action (control grants, inputs while controlling, approval decisions, checkpoint restores) to a local append-only log for later review. Planned for v0.3.
- **No private protocol integrations.** Fewer secrets, fewer vendor handshakes, smaller attack surface.

## MVP demo definition

Run on one machine with two terminals (or two machines on a LAN):

1. Terminal 1: `go run ./cmd/backseat-relay` (listens on :8080).
2. Terminal 2: `go run ./cmd/backseat-expert` (listens on :8081).
3. Terminal 3: `go run ./cmd/backseat-host --agent "claude" --relay ws://localhost:8080/ws --url http://localhost:8081`. Copy the printed invite link.
4. Open the link in a browser. Confirm the live terminal mirrors the agent.
5. Click Request control. In the host terminal, type `grant`.
6. Type into the browser terminal. Confirm the keystrokes drive the agent on the host.
7. Trigger an agent tool call that needs approval. Confirm the Approve/Deny buttons appear and the decision takes effect.
8. In the host terminal, type `end`. Confirm the browser shows the session ended.

Demo complete checklist: invite link works, terminal mirrors, control request plus novice grant, expert drives the agent, approval forwarding works, clean teardown.

## Roadmap

- **v0.1** PTY sharing plus control handoff with novice consent (this repo's skeleton).
- **v0.2** Transcript adapters for claude, copilot, opencode, aider; transcript pane in the expert UI.
- **v0.3** Approval forwarding, E2E payload encryption from pairing keys, checkpoints and rewind, audit log.
- **v0.4** NAT traversal and direct transport (WireGuard-style peer link) so the relay becomes optional; hosted relay stays as fallback.
