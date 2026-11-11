"""Watch AI-agent configuration for changes you did not make.

Worms and planted instruction files persist by editing agent settings: Shai-Hulud variants wrote
.claude/settings.json hooks, and a planted AGENTS.md made Codex rewrite its own machine-wide settings. `pah watch init`
records a baseline; `pah watch check` reports security-relevant differences (new hooks, MCP servers, API base URLs,
approval modes, startup entries); `pah watch accept` takes the current state as the new baseline.
Secret values are never stored, only hashes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

from .guard import HOME
from .surfaces import load_jsonc, load_toml, walk_commands

BASELINE = HOME / "baseline.json"
SECRET_KEY = re.compile(r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)", re.I)
RC_LINE = re.compile(r"curl|wget|iwr|irm|Invoke-|\beval\b|base64|\bsource\b|\balias\b|NODE_OPTIONS|_BASE_URL|PATH=|"
                     r"export\s|\$env:|python\s+-c|node\s+-e|nohup|&\s*$|\.claude|\.codex|\.gemini|openclaw|LD_PRELOAD", re.I)


def locations() -> list[tuple[str, Path]]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    support = home / "Library" / "Application Support"
    if sys.platform == "win32":
        app_dirs = [appdata]
    elif sys.platform == "darwin":
        app_dirs = [support]
    else:
        app_dirs = [xdg]
    items = [
        ("Claude Code settings", home / ".claude" / "settings.json"),
        ("Claude Code local settings", home / ".claude" / "settings.local.json"),
        ("Claude Code state and MCP servers", home / ".claude.json"),
        ("Claude Code memory", home / ".claude" / "CLAUDE.md"),
        ("Codex config", home / ".codex" / "config.toml"),
        ("Codex instructions", home / ".codex" / "AGENTS.md"),
        ("Gemini CLI settings", home / ".gemini" / "settings.json"),
        ("Gemini CLI instructions", home / ".gemini" / "GEMINI.md"),
        ("Cursor MCP servers", home / ".cursor" / "mcp.json"),
        ("Cursor hooks", home / ".cursor" / "hooks.json"),
        ("Codex hooks", home / ".codex" / "hooks.json"),
        ("Antigravity hooks", home / ".gemini" / "config" / "hooks.json"),
        ("Antigravity MCP servers", home / ".gemini" / "config" / "mcp_config.json"),
        ("Copilot MCP servers", home / ".copilot" / "mcp-config.json"),
        ("Copilot settings", home / ".copilot" / "settings.json"),
        ("Devin config", (appdata if sys.platform == "win32" else xdg) / "devin" / "config.json"),
        ("Kiro MCP servers", home / ".kiro" / "settings" / "mcp.json"),
        ("Cline hook", home / ".cline" / "hooks" / "PreToolUse.py"),
        ("OpenClaw config", home / ".openclaw" / "openclaw.json"),
        ("Windsurf MCP servers", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ("git config", home / ".gitconfig"),
        ("npm config", home / ".npmrc"),
        ("bash", home / ".bashrc"), ("bash profile", home / ".bash_profile"), ("profile", home / ".profile"),
        ("zsh", home / ".zshrc"), ("zsh profile", home / ".zprofile"), ("zsh env", home / ".zshenv"),
        ("PowerShell profile", home / "Documents" / "PowerShell" / "Microsoft.PowerShell_profile.ps1"),
        ("Windows PowerShell profile", home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"),
    ]
    for base in app_dirs:
        items += [
            ("Claude Desktop config", base / "Claude" / "claude_desktop_config.json"),
            ("VS Code settings", base / "Code" / "User" / "settings.json"),
            ("VS Code MCP servers", base / "Code" / "User" / "mcp.json"),
            ("VS Code tasks", base / "Code" / "User" / "tasks.json"),
            ("Cursor settings", base / "Cursor" / "User" / "settings.json"),
            ("pip config", base / "pip" / ("pip.ini" if sys.platform == "win32" else "pip.conf")),
        ]
    return items


def watched_dirs() -> list[tuple[str, Path]]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    return [
        ("Claude Code hooks", home / ".claude" / "hooks"), ("Claude Code agents", home / ".claude" / "agents"),
        ("Claude Code commands", home / ".claude" / "commands"), ("Claude Code skills", home / ".claude" / "skills"),
        ("Codex skills", home / ".codex" / "skills"), ("OpenClaw skills", home / ".openclaw" / "skills"),
        ("Shared agent skills", home / ".agents" / "skills"), ("Copilot hooks", home / ".copilot" / "hooks"),
        ("Kiro hooks", home / ".kiro" / "hooks"), ("Cline hooks", home / ".cline" / "hooks"),
        ("Gemini CLI skills", home / ".gemini" / "skills"),
        ("OpenClaw extensions", home / ".openclaw" / "extensions"),
        ("Windows Startup folder", appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"),
        ("macOS LaunchAgents", home / "Library" / "LaunchAgents"),
        ("Linux autostart", xdg / "autostart"), ("systemd user units", xdg / "systemd" / "user"),
    ]


def _redact_env(env: dict) -> dict:
    out = {}
    for k, v in env.items():
        v = str(v)
        out[k] = ("sha256:" + hashlib.sha256(v.encode()).hexdigest()[:12]) if SECRET_KEY.search(k) else v
    return out


def security_summary(path: Path, text: str) -> dict:
    """The parts of a config file that decide what runs and where traffic goes."""
    name = path.name.lower()
    summary: dict = {}
    if name.endswith(".json"):
        data = load_jsonc(text)
        if isinstance(data, dict):
            summary["commands"] = sorted({cmd for _, cmd in walk_commands(data)})
            for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"):
                if key in data:
                    summary[key] = str(data[key])
            if isinstance(data.get("statusLine"), dict):
                summary["statusLine"] = str(data["statusLine"].get("command", ""))
            env = data.get("env")
            if isinstance(env, dict):
                summary["env"] = _redact_env(env)
            perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
            if perms.get("defaultMode"):
                summary["defaultMode"] = perms["defaultMode"]
            for key in ("enableAllProjectMcpServers", "chat.tools.autoApprove", "task.allowAutomaticTasks",
                        "security.workspace.trust.enabled", "yolo"):
                if key in data:
                    summary[key] = data[key]
            servers = data.get("mcpServers") or data.get("servers") or {}
            if isinstance(servers, dict):
                summary["mcp_servers"] = sorted(servers)
            projects = data.get("projects")
            if isinstance(projects, dict):  # ~/.claude.json keeps per-project MCP servers
                names = set()
                for proj in projects.values():
                    if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                        names.update(proj["mcpServers"])
                summary["project_mcp_servers"] = sorted(names)
    elif name.endswith(".toml"):
        data = load_toml(text) or {}
        summary["mcp_servers"] = sorted((data.get("mcp_servers") or {}).keys())
        summary["commands"] = sorted({" ".join([str(v.get("command", ""))] + [str(a) for a in v.get("args", [])])
                                      for v in (data.get("mcp_servers") or {}).values() if isinstance(v, dict)})
        for key in ("approval_policy", "sandbox_mode", "notify", "model_provider"):
            if key in data:
                summary[key] = str(data[key])
    else:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", "//"))]
        summary["lines"] = sorted({ln[:300] for ln in lines if RC_LINE.search(ln)})[:400]
        if re.search("[\U000E0000-\U000E007F\u202a-\u202e\u2066-\u2069]", text):
            summary["hidden_characters"] = True
    return summary


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dir_listing(path: Path, limit: int = 2000) -> dict:
    out = {}
    if not path.is_dir():
        return out
    for i, p in enumerate(sorted(path.rglob("*"))):
        if i >= limit:
            break
        if p.is_file() and len(p.relative_to(path).parts) <= 3:
            try:
                out[str(p.relative_to(path))] = _hash(p.read_bytes()[:5_000_000])
            except OSError:
                continue
    return out


def _run_keys() -> dict:
    if sys.platform != "win32":
        return {}
    import winreg

    out = {}
    for sub in (r"Software\Microsoft\Windows\CurrentVersion\Run", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    out[f"HKCU\\{sub}\\{name}"] = str(value)[:500]
                    i += 1
        except OSError:
            continue
    return out


def snapshot() -> dict:
    files = {}
    for label, path in locations():
        entry = {"label": label, "exists": path.is_file()}
        if entry["exists"]:
            try:
                data = path.read_bytes()[:20_000_000]
            except OSError:
                continue
            entry.update(sha256=_hash(data), size=len(data),
                         security=security_summary(path, data.decode("utf-8", "replace")))
        files[str(path)] = entry
    dirs = {str(path): {"label": label, "files": _dir_listing(path)} for label, path in watched_dirs()}
    return {"version": 1, "time": time.time(), "files": files, "dirs": dirs, "run_keys": _run_keys()}


def init() -> dict:
    snap = snapshot()
    HOME.mkdir(parents=True, exist_ok=True)
    BASELINE.write_text(json.dumps(snap, indent=1), encoding="utf-8")
    return snap


accept = init

HIGH_KEYS = ("commands", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "statusLine", "env",
             "defaultMode", "enableAllProjectMcpServers", "mcp_servers", "project_mcp_servers", "approval_policy",
             "sandbox_mode", "notify", "chat.tools.autoApprove", "task.allowAutomaticTasks", "security.workspace.trust.enabled",
             "yolo", "model_provider", "hidden_characters")


def _diff_summary(old: dict, new: dict) -> list[tuple[str, str]]:
    changes = []
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        if a == b:
            continue
        if isinstance(a, list) or isinstance(b, list):
            added = sorted(set(b or []) - set(a or []))
            removed = sorted(set(a or []) - set(b or []))
            if added:
                changes.append((key, f"{key} added: " + "; ".join(str(x)[:160] for x in added[:5])))
            if removed:
                changes.append((key, f"{key} removed: " + "; ".join(str(x)[:160] for x in removed[:5])))
        elif isinstance(a, dict) or isinstance(b, dict):
            for k in sorted(set(a or {}) | set(b or {})):
                if (a or {}).get(k) != (b or {}).get(k):
                    changes.append((key, f"{key}.{k}: {(a or {}).get(k)!r} -> {(b or {}).get(k)!r}"))
        else:
            changes.append((key, f"{key}: {a!r} -> {b!r}"))
    return changes


def compare(base: dict, now: dict) -> list[dict]:
    out = []
    for path, entry in now["files"].items():
        old = base["files"].get(path, {"exists": False})
        if entry.get("sha256") == old.get("sha256") and entry.get("exists") == old.get("exists"):
            continue
        label = entry.get("label", path)
        if entry.get("exists") and not old.get("exists"):
            sec = entry.get("security") or {}
            risky = any(sec.get(k) for k in ("commands", "apiKeyHelper", "env", "mcp_servers", "lines"))
            out.append({"path": path, "label": label, "change": "created", "severity": "high" if risky else "medium",
                        "detail": json.dumps(sec)[:300]})
            continue
        if not entry.get("exists"):
            out.append({"path": path, "label": label, "change": "deleted", "severity": "info", "detail": ""})
            continue
        diffs = _diff_summary(old.get("security") or {}, entry.get("security") or {})
        if not diffs:
            out.append({"path": path, "label": label, "change": "content changed (no security-relevant field)",
                        "severity": "info", "detail": ""})
        for key, text in diffs:
            sev = "high" if key in HIGH_KEYS else "medium"
            if key == "lines" and re.search(r"curl|wget|iwr|irm|base64|eval|NODE_OPTIONS|LD_PRELOAD|_BASE_URL", text, re.I):
                sev = "high"
            out.append({"path": path, "label": label, "change": text, "severity": sev, "detail": ""})
    for path, entry in now["dirs"].items():
        old = (base.get("dirs") or {}).get(path, {"files": {}})
        added = sorted(set(entry["files"]) - set(old["files"]))
        changed = sorted(k for k in set(entry["files"]) & set(old["files"]) if entry["files"][k] != old["files"][k])
        if added:
            out.append({"path": path, "label": entry["label"], "change": "new files: " + ", ".join(added[:8]),
                        "severity": "high", "detail": ""})
        if changed:
            out.append({"path": path, "label": entry["label"], "change": "changed files: " + ", ".join(changed[:8]),
                        "severity": "medium", "detail": ""})
    for key, value in now.get("run_keys", {}).items():
        if (base.get("run_keys") or {}).get(key) != value:
            out.append({"path": key, "label": "Windows Run key", "change": f"new or changed: {value}", "severity": "high",
                        "detail": ""})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(out, key=lambda c: order[c["severity"]])


def check(quiet: bool = False) -> list[dict]:
    if not BASELINE.exists():
        return []
    base = json.loads(BASELINE.read_text(encoding="utf-8"))
    return compare(base, snapshot())
