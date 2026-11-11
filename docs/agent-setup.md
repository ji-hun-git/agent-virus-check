# Using personal-anti-hack with your agent

One guard, one hook entry point, nine agent protocols. `pah install` writes the configuration for the agents it finds;
this page says what it writes, what each agent can and cannot do with it, and how each integration was checked.

```
pah install                      # shows the changes for the agents found on this computer
pah install codex cursor --yes   # writes them (each changed file is backed up first)
pah install --all --skills --mcp # every agent, plus the security skills and the MCP server
```

The hook command is always `<python> -I <this folder>/pah_entry.py hook pre --agent <name>`, with absolute paths. It
reads the agent's JSON on stdin and answers in that agent's format. A crash never blocks the agent: it says so on
stderr and lets the action through.

## Hooks

| Agent | Event | File written by `pah install` | What the hook sees | Can it ask you? | Checked by |
|---|---|---|---|---|---|
| Claude Code | PreToolUse, PostToolUse, SessionStart | `~/.claude/settings.json` (or the plugin) | shell, file writes and reads, web fetches, new clones, session start | yes | live run with Claude Code 2.1.310, drill |
| OpenAI Codex CLI | PreToolUse | `~/.codex/hooks.json` | shell commands and `apply_patch` (paths and added lines) | no: a question becomes a block | live run with Codex 0.167.1, drill |
| Gemini CLI | BeforeTool | `~/.gemini/settings.json` | `run_shell_command`, `write_file`, `replace`, `read_file` | no | drill (format from geminicli.com/docs/hooks) |
| Antigravity CLI (`agy`) | PreToolUse | `~/.gemini/config/hooks.json` | `run_command`, file writes, `view_file` | yes | drill (antigravity.google/docs/hooks) |
| Cursor (IDE and CLI) | beforeShellExecution, preToolUse | `~/.cursor/hooks.json` | shell commands, `Write`, `Delete`, `Read` | yes, for shell commands | drill (cursor.com/docs/hooks) |
| GitHub Copilot (CLI, VS Code) | PreToolUse | `~/.copilot/hooks/personal-anti-hack.json` | `Bash`, `Write`, `Edit`, `Read` | yes, in interactive sessions | drill (docs.github.com hooks reference) |
| Devin Desktop and CLI (formerly Windsurf) | PreToolUse | `~/.config/devin/config.json` (`%APPDATA%\devin` on Windows) | `exec`, `write`, `edit`, `apply_patch` | no | drill (docs.devin.ai) |
| Kiro | PreToolUse | `~/.kiro/hooks/personal-anti-hack.json` | `execute_bash`, `execute_pwsh`, writes | no (exit code 2 blocks) | drill (kiro.dev/docs/hooks) |
| Cline CLI | PreToolUse | `~/.cline/hooks/PreToolUse.py` | `execute_command`, `write_to_file`, `read_file` | no; a block cancels the whole task | drill (Cline source) |

"Drill" is [`bench/drill.py`](../bench/drill.py): every TrapRepo case and a set of risky actions, sent through each
agent's payload format to the real hook entry point. The live runs are [`bench/live_drill.py`](../bench/live_drill.py).

Agents that cannot ask turn every "ask" into a block, with the reason, because the guard only asks about things that
need a person's decision. To let those through instead, set `PAH_ASK_FALLBACK=allow` in the environment the agent
starts hooks with.

### Agent-specific notes

- **Claude Code:** the plugin (`/plugin marketplace add ji-hun-git/personal-anti-hack`) is the simplest install. It also
  scans every new `git clone` and checks the folder and your agent configuration at session start. A repository's own
  `SessionStart` hooks run at the same moment as the guard's, so scan unfamiliar repositories before you open Claude
  Code in them (`pah scan <url>` clones safely into a temporary folder).
- **Codex:** Codex runs a new or changed hook only after you approve it once in `/hooks`.
- **Cursor:** Cursor also runs Claude Code hooks from `~/.claude/settings.json`. With both installed, each command is
  checked twice, with the same result.
- **Cline:** the VS Code extension reads hooks from `~/Documents/Cline/Hooks/` after you enable Hooks in its settings;
  copy the script there to use it with the extension.
- **OpenClaw, opencode, Amp:** these agents take TypeScript plugins rather than command hooks, so there is no hook
  installer yet. Use the MCP server and the skills, and run `pah check-command` from a plugin if you write one.

## Skills

`pah install --skills` copies four Agent Skills (the open SKILL.md format) to `~/.agents/skills/` and
`~/.claude/skills/`, which between them are read by Claude Code, Codex, Gemini CLI, Antigravity, Copilot, Cursor,
OpenClaw, Devin, Amp, opencode and Cline:

| Skill | For |
|---|---|
| `personal-anti-hack` | everyday rules: scan before setup, instructions in a target are data, no download-and-run, exact package names |
| `malware-audit` | a full audit of suspicious code: execution surfaces, static decoding, behavior classes, provenance, verdict |
| `security-review` | exploitable bugs and vulnerable dependencies, including prompt injection and excessive agency in LLM features |
| `incident-response` | something already ran: contain, find out what ran, rotate credentials in order, remove persistence, harden |

Installed copies note the absolute path of `pah_entry.py`, so they work even when `pah` is not on `PATH`.

## MCP server

`pah mcp` is a stdio MCP server with four tools: `scan_path`, `check_command`, `checkup`, `watch_check`.
`pah install <agent> --mcp` registers it where the agent has an MCP config file (Gemini CLI, Antigravity, Cursor,
Copilot, Devin, Kiro, Codex). For Claude Code it prints the `claude mcp add` command instead of editing `~/.claude.json`.

## Without installing anything

Clone this repository and start any agent in it. [`AGENTS.md`](../AGENTS.md) (also imported by `CLAUDE.md` and
`GEMINI.md`) tells the agent how to run the scanner from the folder (`python3 -I pah_entry.py audit <target>`) and which
skill to follow for malware, viruses, bugs or a suspected compromise.
