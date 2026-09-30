# Backseat for Claude Code

Thin shim. Shared skill content lives in `SKILL.md` in this directory; the
Backseat logic lives in the `backseat-mcp` server.

## Install

1. Install the MCP server:

   ```
   claude mcp add --transport stdio backseat --scope user -- backseat-mcp
   ```

   On first use Claude Code prompts to allow each `backseat__*` tool once.
   The human approves; allow rules can pin this per project with
   `mcp__backseat__*` globs.

2. Install the skill:

   ```
   mkdir -p ~/.claude/skills/backseat
   cp SKILL.md ~/.claude/skills/backseat/SKILL.md
   ```

   `SKILL.md` already carries `disable-model-invocation: true`, so the skill
   is human-only: the agent cannot trigger it on its own. This plus the
   explicit-confirmation rule in the skill is what keeps a prompt-injected
   agent from minting sessions.

## /backseat flow

The human types `/backseat`. The skill (SKILL.md) takes over: it makes the
agent ask for explicit confirmation, call `backseat__create_session`, print
the share link, then poll and publish events each turn while the session is
active. See SKILL.md for the exact tool table, per-turn poll instruction,
`publish_event` narration guidance, and the hard rules.
