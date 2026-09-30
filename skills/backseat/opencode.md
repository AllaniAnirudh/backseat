# Backseat for OpenCode

Thin shim. Shared skill content lives in `SKILL.md` in this directory; the
Backseat logic lives in the `backseat-mcp` server.

OpenCode invokes skills on the agent's decision, not the human's, so the
human-only trigger here is a command, not a skill. Commands are inherently
human-only: they run only when the human types `/backseat`.

## Install

1. Add the MCP server to the OpenCode config (`~/.config/opencode/opencode.json`
   or project-local `opencode.json`):

   ```json
   {
     "mcp": {
       "backseat": {
         "type": "local",
         "command": ["backseat-mcp"],
         "enabled": true
       }
     }
   }
   ```

   OpenCode connects automatically; there is no first-use consent prompt, so
   the human-confirmation rule in the skill carries the trust story here.

2. Create the command file `.opencode/commands/backseat.md` (project-local)
   or `~/.config/opencode/commands/backseat.md` (global) with this content:

   ```markdown
   ---
   description: Start a Backseat session so a remote expert can watch and help.
   ---

   Start a Backseat session following the Backseat skill. The skill content is:

   <paste the full contents of skills/backseat/SKILL.md here>
   ```

   The skill's `disable-model-invocation` flag is not honored by OpenCode;
   human-only-ness comes from the command mechanism itself.

## /backseat flow

The human types `/backseat`. The command injects the skill instructions into
the session: the agent asks for explicit confirmation, calls
`backseat__create_session`, prints the share link, then polls and publishes
events each turn while the session is active. See SKILL.md for the exact tool
table, per-turn poll instruction, `publish_event` narration guidance, and the
hard rules.
