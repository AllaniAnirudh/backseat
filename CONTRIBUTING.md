# Contributing to Backseat

## Build and test

Prerequisites: Go 1.25 or newer.

```bash
go build ./...        # build everything
go vet ./...          # static checks, must be clean
gofmt -l .            # must print nothing
go test ./... -count=1
```

All four must pass before you open a PR.

## Running the demo

Three terminals plus a browser, all on localhost:

```bash
# terminal 1: relay
go run ./cmd/backseat-relay --addr :8080

# terminal 2: expert web UI
go run ./cmd/backseat-expert --port :8081 --relay-ws ws://localhost:8080/ws

# terminal 3: host (prints the one-time invite link)
go run ./cmd/backseat-host --relay ws://localhost:8080 --ui http://localhost:8081 \
  --name novice -- sh -c 'while IFS= read -r line; do printf "echo:%s\n" "$line"; done'
```

Open the printed link, click Request control, type `grant` in the host terminal, then type in the browser terminal. Replace the `sh` command with `claude`, `copilot`, `opencode`, or `aider` to drive a real agent.

## Code style

- `gofmt` clean, `go vet` clean. No exceptions.
- Keep functions small and names plain. Comments explain why, not what.
- No em-dashes or filler in docs, comments, or commit messages.

## Design constraints

Backseat is harness-agnostic by design: the PTY plus transcript adapters is the whole strategy. Do not add integrations with any agent's private protocol. If a change only works with one harness, it does not belong here.

## Pull requests

- Keep them small and focused. One change per PR.
- Protocol, pairing, and relay changes must come with tests in `internal/e2e` or a package-level test.
- Update README.md or ARCHITECTURE.md when behavior changes.
- Describe what you tested and how: commands run, output seen.
- Bug fixes: include a failing test first if you can reproduce it.

## Reporting bugs

Use the bug report template in `.github/ISSUE_TEMPLATE`. Include the exact commands you ran, what happened, and what you expected. Paste the relay and host logs if you have them.
