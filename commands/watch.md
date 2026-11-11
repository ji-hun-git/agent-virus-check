---
description: Show changes to AI-agent and shell configuration since the baseline (hooks, MCP servers, API URLs, approval modes, startup items)
argument-hint: "[init | check | accept]"
---

Run `pah watch ${ARGUMENTS:-check}` if `pah` is installed; otherwise `python3 -I "${CLAUDE_PLUGIN_ROOT}/pah_entry.py" watch ${ARGUMENTS:-check}`.

For `check`: list each change with its severity and explain what it would do (a new hook runs a command, a new MCP server starts a program, a base URL change routes traffic elsewhere). Ask the user whether they made each high-severity change. Only suggest `pah watch accept` for changes the user confirms they made; never run `accept` on your own.
