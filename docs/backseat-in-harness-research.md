# Backseat-in-harness research: the `/backseat` MCP/skill vision

**Question:** Can Backseat live *inside* the coding-agent harness as an MCP server + skill, where the novice types `/backseat`, gets a session link, shares it, and an expert watches/controls the session from a browser?

**Verdict up front:** Technically feasible on every major harness, with real UX wins (structured approval events kill the regex matcher; novice input multiplexing comes free). But the landscape has shifted under it: Claude Code, OpenCode, and Copilot CLI all now ship first-party "share my session" features. Backseat's wedge is **cross-user expert control** (first-party tools are same-user remote control) plus **harness-agnosticism** — and that wedge only holds if the per-harness shim stays thin.

---

## 1. Per-harness plugin story (verified from official docs)

| | Claude Code | OpenCode | Cursor | Copilot CLI | Codex CLI | Windsurf/Cascade |
|---|---|---|---|---|---|---|
| MCP install | `claude mcp add --transport stdio --scope user\|project\|local`; `/mcp` panel | Config file only (`opencode.json`, `mcp.<name>`); no CLI | Customize page UI or `.cursor/mcp.json` / `~/.cursor/mcp.json` | `/mcp add` wizard, `copilot mcp add`, or config files (`~/.copilot/mcp-config.json`) | `~/.codex/config.toml` `[mcp_servers.<name>]`; `codex mcp add` | `~/.codeium/windsurf/mcp_config.json` (global only); Cascade panel menu |
| Human-invoked command | Skill with `disable-model-invocation: true` (human-only, documented) | **Command** (`.opencode/commands/<name>.md`), inherently human-only | Skill with `disable-model-invocation: true` (human-only) | Built-in slash commands are human-only CLI ops; skills are agent-decided | Skill with `allow_implicit_invocation: false` in `agents/openai.yaml` | **Workflow** (`.devin/workflows/*.md`), human-invoked `/name` |
| MCP tool consent | Prompts on first use of each tool; allow/ask/deny rules; `mcp__*` globs; deny-first | No documented first-use prompt; servers "connect automatically unless disabled"; permissive defaults | Approval prompt by default; Run Modes (Auto-review/Allowlist/Run Everything); team MCP allowlist | Destructive tools (shell, writes, MCP) need explicit approval per-use or per-session | Per-server `default_tools_approval_mode` + per-tool overrides (tightest granularity) | No per-tool MCP approval documented |
| MCP server outbound network | No documented sandbox; stdio = local process with user authority → **WebSocket to relay works** | No documented sandbox → **works** | Per-server network mode: Allow all / Allowlist / Deny all / No sandbox → **works unless restricted** | "A shell command can do anything your user account can do" → **works** | No MCP-specific sandbox documented → **works** | No statement found → presumably works |

Key sources: `docs.anthropic.com/en/docs/claude-code/mcp`, `code.claude.com/docs/en/skills`, `code.claude.com/docs/en/permissions`, `opencode.ai/docs/mcp-servers`, `opencode.ai/docs/commands`, `opencode.ai/docs/permissions`, `cursor.com/docs/context/mcp`, `cursor.com/docs/skills`, `docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers`, `developers.openai.com/codex/extend/mcp`, `docs.windsurf.com/windsurf/cascade/mcp`.

**What this means:** the distribution primitive exists everywhere. The cleanest human-only trigger differs per harness (Claude Code/Cursor/Codex: skill flag; OpenCode/Windsurf: separate command/workflow mechanism). The MCP server's own outbound WebSocket is unblocked by default on all six — no harness sandboxes the server's socket I/O, only the *agent's* tool calls.

---

## 2. Novice journey (concrete: Claude Code)

**One-time setup (~2 min):** `claude mcp add --transport stdio backseat --scope user -- backseat-mcp` (or drop a skill folder into `~/.claude/skills/`). First run: Claude Code prompts "allow MCP tool `backseat__create_session`?" once; novice approves. (OpenCode equivalent: paste a `mcp` block into `~/.config/opencode/opencode.json` — no CLI, no first-use prompt; it just connects.)

**The `/backseat` moment:**
1. Novice is stuck, types `/backseat` in the harness. (Claude Code: skill pinned human-only so the agent can't self-trigger it.)
2. Skill instructs the agent to call `backseat__create_session` with a label. The MCP server (local subprocess) mints an invite secret, registers with the relay over its own WebSocket, and returns the link.
3. Agent prints: "Share this link with your expert: `https://relay.example/s/abc#k=SECRET` — it expires in 10 min and is single-use."
4. Novice copies the link (terminal copy; Claude Code's TUI and the web UIs make this one click/drag) and pastes it into Slack/Discord/iMessage.
5. Expert joins → novice sees "expert connected" and a grant prompt; novice approves once.

**Friction count:** one-time ~2-min install; per-session: type 9 chars, one approval click, copy-paste a link. This is the tmate-grade flow ("one command, get a link") that users consistently call the thing they love.

**Caveat (OpenCode):** skills are agent-invoked only there, so `/backseat` must be a *command*, and there's no documented consent gate on MCP tools — the server is silently always-on. Fine for UX, weaker for the trust story (see §5).

---

## 3. Expert journey (what the link should open)

The expert opens a URL in any browser — no account, no install (this "no accounts" property is the single most praised attribute across every tool in §4). To feel in control they need, in priority order:

1. **Live structured transcript** — the agent's messages, tool calls, and diffs rendered readably (not a raw terminal; this is where in-harness beats PTY capture).
2. **Approve/Deny cards** — permission prompts arrive as tappable buttons (Claude Code's own Remote Control already does this for the same-user case; Backseat's existing 2-min-TTL card design ports directly).
3. **Chat-to-agent** — "try fixing it by checking the migration order" as a message the novice's agent receives. This is the actual "fix anything" loop; raw keystroke driving matters less in-harness.
4. **Terminal mirror as fallback** — for watching long builds/logs; keep the existing PTY page.
5. **Presence + control state** — who else is watching, who holds control, one-tap handoff.

Inference, but grounded: every beloved tool converged on watch → participate → approve as the core loop (Live Share's PM: "seamlessly transition from watching to participating").

---

## 4. Comparable UX evidence (real users)

- **tmate** — loved: "instant SSH session... no registration required." Hated: all-or-nothing trust (read-only vs read-write links, nothing in between), corp security vetoes ("bypassing network controls" — [HN](https://news.ycombinator.com/item?id=31080409)), and a stalled project.
- **VS Code Live Share** — loved: "much leaner, much alike watching somebody changing a Google Doc" ([HN](https://news.ycombinator.com/item?id=15704376)); voice+chat built in. Hated: sign-in friction ("required me to sign in before sharing each session... quite annoying"), flaky connects, lag, and ecosystem fragmentation (Cursor users forced back to VS Code mid-session — [dev.to](https://dev.to/pullflow/forked-by-cursor-the-hidden-cost-of-vs-code-fragmentation-4p1)).
- **Tuple/Screenhero** — the mourned gold standard ("I absolutely loved the software" — [HN](https://news.ycombinator.com/item?id=29641907)); killed by pricing psychology (free→paid whiplash), not tech. Lesson: keep the core loop free; charge for teams/retention, not seats on a non-core workflow.
- **Direct prior art — `all-code` (`alc --share`)**: mirrors any agent session (Claude, Codex, OpenCode, Copilot…) to a web page; link-as-credential in the URL fragment (`#k=…`, same as Backseat's design); masks API keys in every view; **requires a human at the physical terminal to confirm permission escalations** (`alc confirm` refuses without a TTY). Admits its limits honestly: "approval prompts arrive as terminal text, not dialogs" — exactly the gap in-harness Backseat would close. ([docs](https://github.com/treeleaves30760/all-code/blob/HEAD/website/docs/remote-control.md))
- **Niche attempts**: `oar` (self-hosted web relay driving Copilot CLI/Claude/Cursor agents from a browser, read-only share links); `clanker-share` (AES-256-GCM-encrypted session upload, key never leaves clipboard); Herdr (phone approvals for Claude Code — now partially superseded by native Remote Control).

**First-party "share my session" features (the competitive reality):**
- **OpenCode**: `/share` → public `opncd.ai/s/<id>` link; manual/auto/disabled modes; `/unshare`. ([opencode.ai/docs/share](https://opencode.ai/docs/share/))
- **Claude Code**: **Remote Control** — `/remote-control` → session URL + QR; view transcript, send messages, **approve/deny prompts** from phone/browser; code stays local. Same-user only, needs Pro/Max+ (Team/Enterprise gated by admin), no API-key users. ([code.claude.com/docs/en/remote-control](https://code.claude.com/docs/en/remote-control))
- **Copilot CLI**: `/share` → link on GitHub.com; `/share off`; gist/file/html export. ([docs.github.com](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/chronicle))
- **Windsurf**: Conversation Sharing (Wave 8), admin-toggleable. **Cursor**: shareable links for cloud background agents only; nothing for in-IDE threads. **Codex CLI**: nothing found.

---

## 5. Friction and trust

- **The confused-deputy risk is real and documented.** A prompt-injected agent must never mint sessions or approve its own control: the human-only skill flag exists precisely for this (Claude Code/Cursor/Codex all document one). Session creation and every grant must be human-confirmed, out-of-band of the model's tool calls — `all-code`'s "confirmation must come from a person at the machine" is the pattern to copy.
- **MCP is an active attack surface.** Tool-poisoning (malicious tool descriptions steering the model) is documented by Trail of Bits and Invariant Labs; a backdoored Postmark MCP server exfiltrated emails from an estimated ~300 orgs (Koi Security, Sep 2026); prompt-injection bugs were found in Anthropic's own official git MCP server (Cyata, Dec 2025). A Backseat MCP server is high-value precisely because it bridges to the network — it must be minimal, audited, and ideally have its tool surface split (session-mint tools vs stream tools).
- **Agents leak.** PromptPwnd (Dec 2025): a hidden instruction in a GitHub issue made Gemini CLI write `GEMINI_API_KEY`/`GITHUB_TOKEN` into a public issue title — "the first confirmed real-world case" of prompt injection compromising CI/CD (Aikido). OpenClaw auto-pushed a user's full vault (37 passwords, 12 API keys) to a public repo. An expert watching a novice's session *will* see secrets on screen — `all-code` masks keys it injected; Backseat should mask common secret patterns in the expert view and warn the novice at share time ("a viewer sees everything the agent prints").
- **Corp-network veto is the tmate lesson.** Anything that tunnels around network controls gets banned by security teams ([HN](https://news.ycombinator.com/item?id=31080409)). Backseat's relay model (outbound WebSocket, no inbound ports) is actually the corp-friendly shape — lead with that.

## 6. Open questions

1. **What is "control" in-harness?** Raw keystrokes (current DRIVING model) map poorly to a chat-oriented agent. Likely: chat-to-agent + approve/deny + optional shell side-channel. Needs a product call before code.
2. **Transcript events vs PTY:** does the MCP server get structured harness events, or does it keep scraping a PTY? The former kills the matcher problem; the latter keeps harness-agnosticism. Probably both: structured where the harness offers it, PTY fallback.
3. **Shim maintenance surface:** six harnesses × (skill/command format + MCP config path + consent quirks). The core (relay protocol, E2E, grant logic) stays shared; budget real time for per-harness paper cuts (e.g. Windsurf's mid-rebrand docs, OpenCode's config-only install).
4. **Does Claude Code's Remote Control expand to third-party sharing?** Today it's same-user + subscription-gated — that's the moat Backseat rows in. If Anthropic opens it to guests, the Claude Code wedge shrinks to cross-harness support.
5. **Relay economics:** who runs the relay, and is there an always-on hosted default? tmate's hosted default is why anyone used it; self-host-only is why corps *could* use it. Both options need to exist.
6. **Unresolved from docs:** whether MCP servers run outside Claude Code's opt-in `/sandbox` (third-party claims yes, official page silent); OpenCode `/share` link semantics (official page not directly verified); exact plan gating of Claude Artifacts public links (sources conflict).

---

## 7. The expert side as a TUI (instead of / in addition to a browser page)

Buppy's question: he likes the browser's command-line-like interface — why not run that in the terminal itself, OpenCode-style?

### (a) How OpenCode's TUI is built, and why it feels good

- **Stack (verified):** OpenCode's interactive TUI is built with [Charm Bubble Tea](https://github.com/charmbracelet/bubbletea) (~45k GitHub stars, MIT). Bubble Tea is a Go framework on the Elm architecture (model + Init/Update/View); it ships a high-performance cell-based renderer, color downsampling, high-fidelity keyboard *and* mouse handling, and native clipboard support, with [Bubbles](https://github.com/charmbracelet/bubbles) as its standard component library (text inputs, viewports, spinners, lists). OpenCode's own docs describe the TUI as "built with Bubble Tea."
- **Why it lands:** it's full-window, keyboard-driven, and never leaves the terminal — the same properties users praise in every beloved TUI. Real sentiment: *"The opencode TUI is the only AI coding interface that didn't annoy me"* (Reddit user, via [medevel.com](https://medevel.com/field-notes-on-coding-agents-opencode-local-models-and-production-workflows-does-opencode-costs-more-yes-and-in-quality-too/)); *"a good TUI beats a mediocre GUI for agent interaction"* ([Medium](https://medium.com/@meipark/ai-didnt-kill-the-terminal-it-made-it-the-default-interface-671d33c112c5)). One project spec framed the choice explicitly: *"Form factor: Terminal TUI — Stays in the terminal, works over ssh, ~30ms start. Browser UI was the alternative — rejected as a context switch"* ([peel SPEC.md](https://github.com/ziadalzarka/peel/blob/HEAD/SPEC.md)).

### (b) Developer preference: TUI vs browser (real quotes)

- **lazygit:** *"fast, doesn't need much ram, I don't have to leave my terminal"* ([HN](https://news.ycombinator.com/item?id=36782018)); *"I do prefer TUI based Git clients to full blown GUI apps because of the keyboard movement. So I can quickly enter do something and exit, while staying in the terminal"* ([LibHunt](https://www.libhunt.com/compare-gitui-vs-lazygit)); *"The philosophy is home-row efficiency. Every mouse reach is a context switch, and context switches are where focused work goes to die"* ([blog](https://aayushbharti.in/blog/terminal-first-dev-setup)).
- **lazydocker:** *"Having a couple different panes always-onscreen with some dedicated different bits of context in them feels sharp/smart!"* ([HN](https://news.ycombinator.com/item?id=36778905)).
- **k9s:** *"far superior to octant"* (Octant is a **web** dashboard) — *"I'm more of a cli junky though"* ([HN](https://news.ycombinator.com/item?id=23364208)); *"Makes daily debugging so much easier"* ([HN](https://news.ycombinator.com/item?id=27737064)).
- **Counter-side:** no "I wish lazygit/k9s had a web UI" quotes surfaced. Documented TUI weaknesses: zero screen-reader accessibility, inconsistent keybindings across apps, color-rendering quirks ([HN](https://news.ycombinator.com/item?id=32331367)); and vs web/Electron, TUIs lose rich charts, images, native notifications, and easy onboarding ([autonomos spec](https://github.com/aterrylu/autonomos/blob/HEAD/docs/research/desktop-shells/terminal-tui.md)). Mouse-in-terminal is actively disliked by some: *"Anything involving overriding the default mouse semantics in a terminal window can go straight to hell"* ([HN](https://news.ycombinator.com/item?id=32331367)) — keyboard-first is the expectation.

### (c) What an expert TUI for Backseat would need

Layout (lazygit-style panels + OpenCode-style chat):
- **Transcript pane** (scrollable viewport): novice agent's messages, tool calls, diffs — the structured stream from §3, rendered as text, not a raw PTY.
- **Approval cards as keyboard-focusable widgets**: focused card shows `y` approve / `n` deny / `?` details; TTL countdown visible. Keyboard focus is *more* reliable than browser notification permission here.
- **Checkpoint/rewind keys**: `c` checkpoint, `r` rewind → checkpoint picker list, single-key confirm.
- **Chat input** at the bottom (Bubbles textinput): message-to-agent, `/` commands.
- **Status bar**: connection, control state (WATCHING/DRIVING), who's present, relay latency.
- Borrowed patterns: lazygit's number-key panel jumps + `?` context help overlay (every panel lists its own bindings); k9s's live-updating views and `:` command mode; OpenCode's tool-call rendering inline in chat.

### (d) Trade-offs: TUI-first vs browser-first for the expert

**TUI wins:**
- **SSH-native.** The expert SSHes into any box and runs `backseat-expert join <code>` — works over the connection they already live in, no local browser needed. (This mirrors tmate's read-only SSH links.)
- **Keyboard-driven speed** for the recurring expert: approve/deny/checkpoint/rewind as single keys.
- **No browser crypto-interop.** Backseat's stack is Go; a TUI reuses `internal/pairing/crypto.go` directly and deletes the entire WebCrypto interop surface (`crypto.js` + the interop test).
- **Single-binary distribution** via `go install` — same story as the relay and host.
- **Audience fit:** the expert is by definition a terminal-native developer — exactly the demographic that loves lazygit/k9s.

**Browser wins:**
- **Link-sharing is the handoff.** "Click this link" works for any expert, zero install — the tmate lesson (§4). A TUI cannot be link-shared; the share flow would need a short code pasted into a terminal (`backseat-expert join <code>`), which is one step more friction.
- **Onboarding/discoverability**, phone/tablet access, richer rendering (syntax-highlighted diffs, images).

**Synthesis (inference):** it's not either/or — the protocol is identical, so ship the TUI as a **second client** on the same relay + E2E envelopes. Browser page = zero-friction guest join (first session with a new expert). TUI = the power tool for the recurring expert (SSH in, keyboard speed, no browser). Build the browser page first because the share flow depends on it; the TUI reuses everything except the renderer. One design note: keep approval semantics identical across both clients (same TTLs, same answer-bytes-only rule) so the trust story doesn't fork.

---

**Caveats on method:** per-harness claims were verified against official doc pages by the research agents (URLs cited inline); user quotes are real with source links; the novice/expert journey walkthroughs, the "wedge" framing, and the TUI synthesis are inference grounded in those facts. No code was written; no live-browser interaction was performed.
