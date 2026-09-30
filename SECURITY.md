# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| v0.1.x  | Yes                |

## Reporting a vulnerability

Email allanianirudh05@gmail.com with a description of the issue and steps to reproduce it. You will get a reply within 7 days. Do not open a public issue for a suspected vulnerability.

> NOTE FOR THE REPO OWNER: the address above is a placeholder contact. Change it if you want reports to go somewhere else.

## Scope and honest limitations

v0.1 is built for trusted, self-hosted use:

- The relay routes plaintext envelopes. Anyone who can observe traffic between the host, relay, and expert can read the session. Run your own relay or one you trust. End-to-end payload encryption is on the v0.3 roadmap.
- Invite secrets live in the URL fragment and are verified against a stored hash in constant time. A wrong secret is rejected and never logged. Invites expire after 10 minutes.
- Exactly one controller at a time is enforced by the host daemon and double-checked by the relay. The novice must explicitly grant control; there is no silent takeover path in v0.1.
- v0.1 has no audit log yet. That is also on the roadmap.

If you deploy a relay for other people, treat it as infrastructure you are responsible for: TLS on the WebSocket endpoint, restricted network access, and log handling that never records invite secrets.
