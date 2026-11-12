"""Install the guard into AI agents: pre-tool hooks, the security skills, and the MCP server.

`pah install <agent>` shows every change first and writes only with --yes, after backing up each file it changes.
Hook commands use absolute paths to this Python and this installation, so files in the project being worked on can
never shadow the guard's modules, and a Microsoft Store "python" stub on Windows cannot get in the way.

Supported agents and where their settings live:

  claude-code   ~/.claude/settings.json            PreToolUse, PostToolUse, SessionStart (or install the plugin)
  codex         ~/.codex/hooks.json                PreToolUse (Bash, apply_patch); approve it once in Codex's /hooks
  gemini        ~/.gemini/settings.json            BeforeTool
  antigravity   ~/.gemini/config/hooks.json        PreToolUse
  cursor        ~/.cursor/hooks.json               beforeShellExecution, preToolUse
  copilot       ~/.copilot/hooks/personal-anti-hack.json   PreToolUse (CLI and VS Code)
  devin         ~/.config/devin/config.json        PreToolUse (Devin Desktop and CLI; %APPDATA%\\devin on Windows)
  kiro          ~/.kiro/hooks/personal-anti-hack.json      PreToolUse
  cline         ~/.cline/hooks/PreToolUse.py       PreToolUse (Cline CLI; the extension: see docs/agent-setup.md)

Skills go to ~/.agents/skills (read by Codex, Gemini CLI, Copilot, Cursor, OpenClaw, Devin, Amp and opencode) and
~/.claude/skills (Claude Code, also read by Cursor, Copilot, Cline and opencode).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .surfaces import load_jsonc

ROOT = Path(__file__).resolve().parent.parent
ENTRY = ROOT / "pah_entry.py"
SKILLS = ROOT / "skills"
MARK = "personal-anti-hack"
AGENT_NAMES = ("claude-code", "codex", "gemini", "antigravity", "cursor", "copilot", "devin", "kiro", "cline")
ADAPTER = {"claude-code": "claude"}


# ---------------------------------------------------------------------------------------------- commands


def _python() -> str:
    return sys.executable or shutil.which("python3") or shutil.which("python") or "python3"


def _base_args() -> list[str]:
    if ENTRY.exists():
        return [_python(), "-I", str(ENTRY)]
    exe = shutil.which("pah")
    if exe:
        return [exe]
    return [_python(), "-m", "pah"]


def posix_command(*args: str) -> str:
    """For agents that run hooks through sh/bash (also Git Bash on Windows): quoted, forward slashes."""
    parts = [p.replace("\\", "/") for p in _base_args()] + list(args)
    return " ".join(f'"{p}"' if (" " in p or "\\" in p or p.endswith((".exe", ".py"))) else p for p in parts)


def windows_command(*args: str) -> str:
    """For agents that run hooks through PowerShell or cmd on Windows."""
    parts = _base_args() + list(args)
    if not any(" " in p for p in parts):
        return " ".join(parts)  # valid in both cmd.exe and PowerShell
    quoted = " ".join(f"'{p}'" if " " in p or "\\" in p else p for p in parts)
    return "& " + quoted  # PowerShell call operator


def hook_command(agent: str, event: str = "pre", shell: str = "auto") -> str:
    args = ["hook", event] + (["--agent", ADAPTER.get(agent, agent)] if ADAPTER.get(agent, agent) != "claude" else [])
    if shell == "posix" or (shell == "auto" and os.name != "nt"):
        return posix_command(*args)
    return windows_command(*args)


# ---------------------------------------------------------------------------------------------- plans


@dataclass
class Change:
    path: Path
    content: str
    summary: str
    created: bool = False


@dataclass
class Plan:
    agent: str
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _home() -> Path:
    return Path(os.environ.get("PAH_INSTALL_HOME") or Path.home())


_PENDING: dict[Path, Change] = {}  # changes planned in this run, so two changes to one file build on each other


def _load_json(path: Path) -> dict | None:
    if path in _PENDING:
        return json.loads(_PENDING[path].content)
    if not path.exists():
        return {}
    data = load_jsonc(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def _has_mark(obj) -> bool:
    return MARK in json.dumps(obj) or "pah_entry.py" in json.dumps(obj)


def _merge_json(plan: Plan, path: Path, mutate, summary: str) -> None:
    data = _load_json(path)
    if data is None:
        plan.skipped.append(f"{path} is not valid JSON; fix it, then run the install again")
        return
    before = json.dumps(data, sort_keys=True)
    mutate(data)
    if json.dumps(data, sort_keys=True) == before:
        plan.skipped.append(f"{path}: already installed")
        return
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if path in _PENDING:  # fold into the earlier change to the same file
        earlier = _PENDING[path]
        earlier.content, earlier.summary = content, f"{earlier.summary}; {summary}"
        return
    change = Change(path, content, summary, not path.exists())
    _PENDING[path] = change
    plan.changes.append(change)


def _append_event(container: dict, event: str, entry: dict) -> None:
    entries = container.setdefault(event, [])
    if not _has_mark(entries):
        entries.append(entry)


# -------------------------------------------------------------------------------------------- per agent


def plan_claude(plan: Plan, home: Path) -> None:
    path = home / ".claude" / "settings.json"
    cmd = {e: hook_command("claude-code", e, "posix") for e in ("pre", "post", "session-start")}

    def mutate(data: dict) -> None:
        hooks = data.setdefault("hooks", {})
        _append_event(hooks, "PreToolUse", {"matcher": "Bash|PowerShell|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch",
                                            "hooks": [{"type": "command", "command": cmd["pre"], "timeout": 60}]})
        _append_event(hooks, "PostToolUse", {"matcher": "Bash|PowerShell", "hooks": [{"type": "command", "command": cmd["post"],
                                                                         "timeout": 120}]})
        _append_event(hooks, "SessionStart", {"hooks": [{"type": "command", "command": cmd["session-start"], "timeout": 60}]})

    _merge_json(plan, path, mutate, "PreToolUse, PostToolUse and SessionStart hooks")
    plan.notes.append("Or install the plugin instead: /plugin marketplace add ji-hun-git/agent-white-hat, then "
                      "/plugin install personal-anti-hack.")


def plan_codex(plan: Plan, home: Path) -> None:
    base = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
    entry = {"matcher": "^(Bash|apply_patch)$", "hooks": [{"type": "command", "command": hook_command("codex", shell="posix"),
                                                           "commandWindows": hook_command("codex", shell="windows"),
                                                           "timeout": 60, "statusMessage": "agent-white-hat check"}]}
    _merge_json(plan, base / "hooks.json", lambda d: _append_event(d.setdefault("hooks", {}), "PreToolUse", entry),
                "PreToolUse hook for shell commands and patches")
    plan.notes.append("Codex runs a new hook only after you approve it: start Codex and open /hooks once. Codex hooks "
                      "cannot ask, so anything agent-white-hat would ask about is blocked with the reason.")


def plan_gemini(plan: Plan, home: Path) -> None:
    entry = {"matcher": "run_shell_command|write_file|replace|read_file",
             "hooks": [{"name": MARK, "type": "command", "command": hook_command("gemini"), "timeout": 60000}]}
    _merge_json(plan, home / ".gemini" / "settings.json",
                lambda d: _append_event(d.setdefault("hooks", {}), "BeforeTool", entry), "BeforeTool hook")
    plan.notes.append("Gemini CLI hooks cannot ask; anything agent-white-hat would ask about is blocked with the reason.")


def plan_antigravity(plan: Plan, home: Path) -> None:
    entry = {"matcher": "run_command|write_to_file|replace_file_content|multi_replace_file_content|view_file",
             "hooks": [{"type": "command", "command": hook_command("antigravity"), "timeout": 60}]}

    def mutate(data: dict) -> None:
        if not _has_mark(data):
            data[MARK] = {"PreToolUse": [entry]}

    _merge_json(plan, home / ".gemini" / "config" / "hooks.json", mutate, "PreToolUse hook")


def plan_cursor(plan: Plan, home: Path) -> None:
    cmd = hook_command("cursor")

    def mutate(data: dict) -> None:
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        _append_event(hooks, "beforeShellExecution", {"command": cmd, "timeout": 60})
        _append_event(hooks, "preToolUse", {"command": cmd, "matcher": "Write|Delete|Read", "timeout": 60})

    _merge_json(plan, home / ".cursor" / "hooks.json", mutate, "beforeShellExecution and preToolUse hooks")
    plan.notes.append("Cursor also runs Claude Code hooks from ~/.claude/settings.json; if both are installed, each "
                      "command is checked twice (same result).")


def plan_copilot(plan: Plan, home: Path) -> None:
    base = Path(os.environ["COPILOT_HOME"]) if os.environ.get("COPILOT_HOME") else home / ".copilot"
    path = base / "hooks" / f"{MARK}.json"
    data = {"version": 1, "hooks": {"PreToolUse": [{"type": "command", "bash": hook_command("copilot", shell="posix"),
                                                    "powershell": hook_command("copilot", shell="windows"),
                                                    "timeoutSec": 60}]}}
    if path.exists():
        plan.skipped.append(f"{path}: already installed")
    else:
        plan.changes.append(Change(path, json.dumps(data, indent=2) + "\n", "PreToolUse hook (CLI and VS Code)", True))


def plan_devin(plan: Plan, home: Path) -> None:
    if os.name == "nt" and os.environ.get("APPDATA") and not os.environ.get("PAH_INSTALL_HOME"):
        path = Path(os.environ["APPDATA"]) / "devin" / "config.json"
    else:
        path = home / ".config" / "devin" / "config.json"
    entry = {"matcher": "^(exec|write|edit|apply_patch)$",
             "hooks": [{"type": "command", "command": hook_command("devin"), "timeout": 60}]}
    _merge_json(plan, path, lambda d: _append_event(d.setdefault("hooks", {}), "PreToolUse", entry), "PreToolUse hook")
    plan.notes.append("Devin hooks cannot ask; anything agent-white-hat would ask about is blocked with the reason.")


def plan_kiro(plan: Plan, home: Path) -> None:
    path = home / ".kiro" / "hooks" / f"{MARK}.json"
    data = {"version": "v1", "hooks": [{"name": MARK, "trigger": "PreToolUse",
                                        "action": {"type": "command", "command": hook_command("kiro")}, "timeout": 60}]}
    if path.exists():
        plan.skipped.append(f"{path}: already installed")
    else:
        plan.changes.append(Change(path, json.dumps(data, indent=2) + "\n", "PreToolUse hook (Kiro CLI; the IDE reads "
                                   "project .kiro/hooks)", True))


def plan_cline(plan: Plan, home: Path) -> None:
    path = home / ".cline" / "hooks" / "PreToolUse.py"
    args = _base_args() + ["hook", "pre", "--agent", "cline"]
    script = ("#!/usr/bin/env python3\n"
              f"# {MARK}: Cline PreToolUse hook, written by `pah install cline`.\n"
              "import subprocess\nimport sys\n\n"
              f"sys.exit(subprocess.run({args!r}, input=sys.stdin.buffer.read()).returncode)\n")
    if path.exists():
        plan.skipped.append(f"{path}: already exists; remove it first to replace it")
    else:
        plan.changes.append(Change(path, script, "PreToolUse hook script (Cline CLI)", True))
    plan.notes.append("The Cline VS Code extension reads hooks from ~/Documents/Cline/Hooks after you enable Hooks in its "
                      "settings; copy the script there if you use the extension. A Cline hook can only cancel the whole "
                      "task, so only clear blocks cancel; questions are blocked with the reason.")


PLANNERS = {"claude-code": plan_claude, "codex": plan_codex, "gemini": plan_gemini, "antigravity": plan_antigravity,
            "cursor": plan_cursor, "copilot": plan_copilot, "devin": plan_devin, "kiro": plan_kiro, "cline": plan_cline}
DETECT = {"claude-code": ".claude", "codex": ".codex", "gemini": ".gemini", "antigravity": ".gemini/config",
          "cursor": ".cursor", "copilot": ".copilot", "devin": ".config/devin", "kiro": ".kiro", "cline": ".cline"}


# ------------------------------------------------------------------------------------------------ skills


def plan_skills(plan: Plan, home: Path, targets: tuple[str, ...] = (".agents/skills", ".claude/skills")) -> None:
    if not SKILLS.is_dir():
        plan.notes.append("The skills ship with the repository, not with the Python package: clone "
                          "https://github.com/ji-hun-git/agent-white-hat and run `python -I pah_entry.py install "
                          "--skills` from the clone.")
        return
    note = (f"\n\n---\nInstalled by agent-white-hat from {ROOT}. If `pah` is not on PATH, run "
            f"`{posix_command()}` (macOS, Linux, Git Bash) or `{windows_command()}` (PowerShell) in its place.\n")
    for target in targets:
        for skill in sorted(p for p in SKILLS.iterdir() if (p / "SKILL.md").is_file()):
            dest = home / target / skill.name
            if dest.exists() and not (dest / f".{MARK}").exists():
                plan.skipped.append(f"{dest}: a different skill with this name exists; left alone")
                continue
            for src in sorted(skill.rglob("*")):
                if src.is_file():
                    text = src.read_text(encoding="utf-8")
                    if src.name == "SKILL.md":
                        text = text.rstrip("\n") + note
                    out = dest / src.relative_to(skill)
                    if not out.exists() or out.read_text(encoding="utf-8") != text:
                        plan.changes.append(Change(out, text, f"skill {skill.name}", not out.exists()))
            marker = dest / f".{MARK}"
            if not marker.exists():
                plan.changes.append(Change(marker, "installed by personal-anti-hack\n", f"skill {skill.name}", True))


# --------------------------------------------------------------------------------------------- MCP server


def plan_mcp(plan: Plan, agent: str, home: Path) -> None:
    args = _base_args()
    server = {"command": args[0], "args": args[1:] + ["mcp"]}
    json_targets = {"gemini": (home / ".gemini" / "settings.json", "mcpServers", server),
                    "antigravity": (home / ".gemini" / "config" / "mcp_config.json", "mcpServers", server),
                    "cursor": (home / ".cursor" / "mcp.json", "mcpServers", {"type": "stdio", **server}),
                    "copilot": (home / ".copilot" / "mcp-config.json", "mcpServers", {"type": "local", **server, "tools": ["*"]}),
                    "devin": (home / ".config" / "devin" / "mcp_config.json", "mcpServers", server),
                    "kiro": (home / ".kiro" / "settings" / "mcp.json", "mcpServers", server)}
    if agent in json_targets:
        path, key, value = json_targets[agent]

        def mutate(data: dict) -> None:
            servers = data.setdefault(key, {})
            if MARK not in servers:
                servers[MARK] = value

        _merge_json(plan, path, mutate, "MCP server (scan_path, check_command, checkup, watch_check)")
    elif agent == "codex":
        base = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else home / ".codex"
        path = base / "config.toml"
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        if f"[mcp_servers.{MARK}]" in text:
            plan.skipped.append(f"{path}: MCP server already configured")
        else:
            toml_args = ", ".join(f"'{a}'" for a in server["args"])
            block = f"\n[mcp_servers.{MARK}]\ncommand = '{server['command']}'\nargs = [{toml_args}]\n"
            plan.changes.append(Change(path, text.rstrip("\n") + "\n" + block, "MCP server", not path.exists()))
    elif agent == "claude-code":
        cmd = " ".join(f'"{a}"' if " " in a else a for a in [server["command"], *server["args"]])
        plan.notes.append(f"Add the MCP server with Claude Code's own command: claude mcp add --scope user {MARK} -- {cmd}")
    else:
        plan.notes.append(f"Add the MCP server in {agent}'s MCP settings: command {server['command']}, "
                          f"arguments {' '.join(server['args'])}")


# ---------------------------------------------------------------------------------------------- apply


def build(agents: list[str], skills: bool, mcp: bool, hooks: bool = True) -> list[Plan]:
    home = _home()
    _PENDING.clear()
    plans = []
    for agent in agents:
        plan = Plan(agent)
        if hooks:
            PLANNERS[agent](plan, home)
        if mcp:
            plan_mcp(plan, agent, home)
        plans.append(plan)
    if skills:
        plan = Plan("skills")
        plan_skills(plan, home)
        plans.append(plan)
    return plans


def detected() -> list[str]:
    home = _home()
    return [a for a, rel in DETECT.items() if (home / rel).exists()]


def apply(plans: list[Plan], write: bool) -> int:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    any_change = False
    for plan in plans:
        print(f"\n== {plan.agent}")
        for change in plan.changes:
            any_change = True
            print(f"  {'create' if change.created else 'update'} {change.path}  ({change.summary})")
        for item in plan.skipped:
            print(f"  skip   {item}")
        for note in plan.notes:
            print(f"  note   {note}")
    if not any_change:
        print("\nNothing to change.")
        return 0
    if not write:
        print("\nNothing written. Run the same command with --yes to make these changes (changed files are backed up "
              "first).")
        return 0
    for plan in plans:
        for change in plan.changes:
            change.path.parent.mkdir(parents=True, exist_ok=True)
            if change.path.exists():
                backup = change.path.with_name(f"{change.path.name}.pah-backup-{stamp}")
                shutil.copy2(change.path, backup)
            change.path.write_text(change.content, encoding="utf-8")
            if change.path.name == "PreToolUse.py" and os.name != "nt":
                change.path.chmod(0o755)
    print("\nWritten. Restart the agents you changed. Then run `pah watch accept` so these changes become part of your "
          "baseline.")
    return 0


def install_claude_code(dry_run: bool = True) -> int:
    """Kept for callers of the first version."""
    return apply(build(["claude-code"], skills=False, mcp=False), write=not dry_run)
