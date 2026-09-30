# Backseat for Copilot CLI

Thin shim. Shared skill content lives in `SKILL.md` in this directory; the
Backseat logic lives in the `backseat-mcp` server.

## Install

1. Add the MCP server. Either run the wizard:

   ```
   copilot mcp add
   ```

   and point it at the `backseat-mcp` binary over stdio, or add to
   `~/.copilot/mcp-config.json`:

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

   Copilot CLI treats MCP tool use like other destructive operations: it asks
   for explicit approval per use or per session. The human approves the
   Backseat tools when prompted.

2. Install the skill (skills are agent-decided in Copilot CLI; the built-in
   slash commands are the human-only CLI ops). Save the shared skill where
   Copilot CLI reads custom skills:

   ```
   cp SKILL.md <copilot-skills-dir>/backseat/SKILL.md
   ```

   Check the Copilot CLI docs for the current custom-skills path on this
   machine. Until the skill is wired to a human-only trigger, the
   explicit-confirmation rule in the skill is the backstop: the agent must get
   a clear yes from the human before calling `backseat__create_session`.

## /backseat flow

The human asks for a Backseat session. The skill (SKILL.md) takes over: it
makes the agent ask for explicit confirmation, call
`backseat__create_session`, print the share link, then poll and publish events
each turn while the session is active. See SKILL.md for the exact tool table,
per-turn poll instruction, `publish_event` narration guidance, and the hard
rules.
