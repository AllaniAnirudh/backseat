# Backseat for Cursor

Thin shim. Shared skill content lives in `SKILL.md` in this directory; the
Backseat logic lives in the `backseat-mcp` server.

## Install

1. Add the MCP server. Either use the Cursor Customize page UI, or add to
   `.cursor/mcp.json` (project) / `~/.cursor/mcp.json` (global):

   ```json
   {
     "mcpServers": {
       "backseat": {
         "command": "backseat-mcp",
         "args": []
       }
     }
   }
   ```

   Cursor prompts for approval by default on first use; per-server Run Modes
   (Auto-review, Allowlist, Run Everything) and team MCP allowlists can pin
   the policy. Note the per-server network mode setting: the server needs
   outbound network for its relay WebSocket, so do not set it to Deny all.

2. Install the skill:

   ```
   mkdir -p ~/.cursor/skills/backseat
   cp SKILL.md ~/.cursor/skills/backseat/SKILL.md
   ```

   `SKILL.md` already carries `disable-model-invocation: true`, so the skill
   is human-only: the agent cannot trigger it on its own. This plus the
   explicit-confirmation rule in the skill is what keeps a prompt-injected
   agent from minting sessions.

## /backseat flow

The human invokes the skill. The skill (SKILL.md) takes over: it makes the
agent ask for explicit confirmation, call `backseat__create_session`, print
the share link, then poll and publish events each turn while the session is
active. See SKILL.md for the exact tool table, per-turn poll instruction,
`publish_event` narration guidance, and the hard rules.
