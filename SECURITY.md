# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | Yes                |

## Reporting a vulnerability

Email allanianirudh05@gmail.com with a description of the issue and steps to reproduce it. You will get a reply within 7 days. Do not open a public issue for a suspected vulnerability.

> NOTE FOR THE REPO OWNER: the address above is a placeholder contact. Change it if you want reports to go somewhere else.

## Scope and honest limitations

Payloads are end-to-end encrypted (AES-256-GCM, directional keys derived at enrollment via HKDF-SHA256), so the relay is untrusted by design: it routes opaque envelopes and only ever sees message types, the plaintext `to`/`from` routing fields, session ids, and timing. It holds no content keys.

- Invite secrets live in the URL fragment and never cross the wire: joining experts prove possession with an HMAC-SHA256 challenge-response, verified by the host in constant time. A wrong answer gets them kicked. Invites expire after 10 minutes.
- Exactly one controller at a time, enforced by the host daemon: expert `term_input` is applied only when the sender is the specific controller. The novice must explicitly grant control; there is no silent takeover path.
- Honest limitations: no forward secrecy yet (a leaked invite secret decrypts that session's recorded traffic; each session mints a fresh secret, bounding exposure to one session); no audit log yet (on the v0.3 roadmap).
- The relay still trusts the host for control decisions: `control_grant` and `peer_kick` from the host are forwarded as received. A compromised host binary can do anything its process can do; end-to-end encryption does not protect the novice from their own host.
- Approval answers and rewinds are novice-gated: an expert's approval answer injects at most the prompt's own answer bytes (never free-form input), stale approvals expire after 2 minutes and can never fire, and a rewind only executes after the novice confirms it (or the novice runs it directly). Ending or kicking clears every pending approval and rewind request.

## In-harness MCP server (v0.3)

`cmd/backseat-mcp` runs on the novice's machine as the novice's own user. It is a trusted host endpoint, exactly like `backseat-host`: anyone who can influence its tool calls can already act as the novice.

- **Human-gated creation.** Starting a session (and therefore generating an invite link) must be confirmed by the human novice. That gate lives in the skill, not the server: the server cannot tell a model-initiated `create_session` from a human-approved one.
- **No grant tool.** The seven MCP tools cannot grant control, approve rewinds, or kick. Those decisions go through `backseat-mcp ctl` over a unix socket in the novice's temp directory, gated by filesystem permissions. A remote expert has no path to self-grant.
- **Secret masking is heuristic.** `publish_event` text is scrubbed for assignment-style secrets, known token prefixes, bearer tokens, and PEM blocks before sending. It catches the common shapes, not every secret: treat published text as potentially visible to the expert and keep real credentials out of it.
- **Exec is arbitrary shell as the novice user.** `exec_request` is restricted to the current controller, bounded (2-minute kill, 64 KB shared output cap, max two concurrent), and every run is mirrored into the novice inbox. Still, a controller the novice granted can run anything the novice's account can run. Grant control only to experts you trust with shell access.
- **Approvals fail closed.** `request_approval` resolves to denied on timeout (max 2 minutes), when no expert is connected, and when the session ends. A stale or forged decision cannot resolve an approval: the decision must come from the current controller, name a valid option, and arrive before expiry.

If you deploy a relay for other people, treat it as infrastructure you are responsible for: TLS on the WebSocket endpoint and restricted network access.
