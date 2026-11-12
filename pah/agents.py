"""One guard for many agents: read each agent's pre-tool hook payload, ask the guard, answer in that agent's protocol.

Formats were taken from each agent's documentation (November 2026):

  claude       Claude Code             PreToolUse; tool_name/tool_input; hookSpecificOutput.permissionDecision
  codex        OpenAI Codex CLI        PreToolUse; Bash and apply_patch (patch text in tool_input.command);
                                       Claude-style output; "ask" is not supported, so ask becomes deny
  gemini       Gemini CLI              BeforeTool; run_shell_command/write_file/replace/read_file; {"decision": "deny"}
  antigravity  Antigravity CLI (agy)   PreToolUse; toolCall.name/args (CommandLine, Cwd, TargetFile); {"decision": ...}
  cursor       Cursor (IDE and CLI)    beforeShellExecution (command, cwd), preToolUse; {"permission": ...}
  copilot      GitHub Copilot          PreToolUse with Claude-style tool names, or camelCase preToolUse
                                       (toolName/toolArgs); {"permissionDecision": ...}
  devin        Devin Desktop/CLI       PreToolUse; exec/write/edit; {"decision": "block"}
  kiro         Kiro                    PreToolUse; execute_bash/execute_pwsh; exit 2 with the reason on stderr
  cline        Cline                   PreToolUse; preToolUse.toolName/parameters or tool_call.name/input;
                                       {"cancel": true} (cancels the whole task, so only deny cancels)

Agents that cannot ask the user get deny for "ask" by default: the guard only asks about things that need a person's
decision. PAH_ASK_FALLBACK=allow lets them through instead (with the reason printed where the agent shows it).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

AGENTS = ("claude", "codex", "gemini", "antigravity", "cursor", "copilot", "devin", "kiro", "cline")
NO_ASK = {"codex", "gemini", "devin", "kiro", "cline"}


@dataclass
class ToolEvent:
    kind: str = "other"  # shell | write | read | fetch | other
    command: str = ""
    paths: tuple[str, ...] = ()
    content: str = ""
    url: str = ""
    cwd: str = ""


SHELL_TOOLS = {"bash", "shell", "run_shell_command", "run_command", "execute_command", "exec", "execute_bash",
               "execute_pwsh", "powershell", "terminal", "run_in_terminal", "command"}
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "write_file", "replace", "write_to_file",
               "replace_file_content", "multi_replace_file_content", "create", "str_replace", "create_file",
               "apply_patch", "replace_in_file", "fs_write", "delete", "insert_edit_into_file"}
READ_TOOLS = {"read", "read_file", "view_file", "view", "fs_read", "open_file"}
FETCH_TOOLS = {"webfetch", "web_fetch", "fetch", "read_url_content", "url_fetch"}
_PATH_KEYS = ("file_path", "path", "TargetFile", "target_file", "absolute_path", "notebook_path", "filePath", "file",
              "AbsolutePath")
_CONTENT_KEYS = ("content", "new_string", "new_source", "CodeContent", "ReplacementContent", "file_text", "text", "diff",
                 "newContent", "code")
_PATCH_FILE = re.compile(r"(?m)^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\+\+\+ (?:b/)?(.+)$")


def _as_dict(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _first(d: dict, keys) -> str:
    for key in keys:
        value = d.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _from_tool(name: str, args: dict, cwd: str) -> ToolEvent:
    low = name.lower()
    if low.startswith(("mcp__", "mcp:", "mcp_")):
        return ToolEvent("other", cwd=cwd)
    if low == "apply_patch":  # Codex: the patch text is the command
        patch = _first(args, ("command", "patch", "input"))
        paths = tuple(p.strip() for m in _PATCH_FILE.finditer(patch) for p in m.groups() if p)
        added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
        return ToolEvent("write", paths=paths, content=added, cwd=cwd)
    if low in SHELL_TOOLS:
        return ToolEvent("shell", command=_first(args, ("command", "CommandLine", "cmd", "script")),
                         cwd=_first(args, ("cwd", "Cwd", "workdir")) or cwd)
    if low in WRITE_TOOLS:
        content = _first(args, _CONTENT_KEYS)
        if not content and isinstance(args.get("edits"), list):
            content = "\n".join(str(e.get("new_string", "")) for e in args["edits"] if isinstance(e, dict))
        if not content and isinstance(args.get("ReplacementChunks"), list):
            content = "\n".join(str(c.get("ReplacementContent", "")) for c in args["ReplacementChunks"] if isinstance(c, dict))
        path = _first(args, _PATH_KEYS)
        return ToolEvent("write", paths=(path,) if path else (), content=content, cwd=cwd)
    if low in READ_TOOLS:
        path = _first(args, _PATH_KEYS)
        return ToolEvent("read", paths=(path,) if path else (), cwd=cwd)
    if low in FETCH_TOOLS:
        return ToolEvent("fetch", url=_first(args, ("url", "Url", "uri")), cwd=cwd)
    return ToolEvent("other", cwd=cwd)


def normalize(agent: str, data: dict) -> ToolEvent:
    """The tool call an agent is about to make, whatever the agent's payload looks like."""
    cwd = str(data.get("cwd") or data.get("Cwd") or "")
    if not cwd:
        roots = data.get("workspace_roots") or data.get("workspaceRoots") or data.get("workspacePaths") or []
        cwd = str(roots[0]) if isinstance(roots, list) and roots else os.getcwd()
    if agent == "cursor" and isinstance(data.get("command"), str) and "tool_name" not in data:
        return ToolEvent("shell", command=data["command"], cwd=cwd)  # beforeShellExecution
    if agent == "antigravity" or isinstance(data.get("toolCall"), dict):
        call = data.get("toolCall") or {}
        return _from_tool(str(call.get("name", "")), _as_dict(call.get("args")), cwd)
    if isinstance(data.get("preToolUse"), dict):  # Cline extension
        pre = data["preToolUse"]
        return _from_tool(str(pre.get("toolName", "")), _as_dict(pre.get("parameters")), cwd)
    if isinstance(data.get("tool_call"), dict):  # Cline SDK
        call = data["tool_call"]
        return _from_tool(str(call.get("name", "")), _as_dict(call.get("input")), cwd)
    if "toolName" in data:  # Copilot camelCase events
        return _from_tool(str(data.get("toolName", "")), _as_dict(data.get("toolArgs")), cwd)
    return _from_tool(str(data.get("tool_name", "")), _as_dict(data.get("tool_input")), cwd)


def decide(event: ToolEvent):
    from .guard import Decision, check_command, check_fetch, check_read, check_write

    if event.kind == "shell" and event.command:
        return check_command(event.command, event.cwd)
    if event.kind == "write":
        worst = Decision()
        for path in event.paths or ("",):
            found = check_write(path, event.content, event.cwd)
            worst.stricter(found.action, found.reason)
        return worst
    if event.kind == "read" and event.paths:
        return check_read(event.paths[0], event.cwd)
    if event.kind == "fetch" and event.url:
        return check_fetch(event.url)
    return Decision()


def respond(agent: str, action: str, reason: str) -> tuple[str, int, str]:
    """(stdout, exit code, stderr) for a decision: deny, ask or defer (no objection)."""
    if action == "ask" and agent in NO_ASK:
        if os.environ.get("PAH_ASK_FALLBACK", "deny").lower() == "allow":
            action, reason = "defer", reason
        else:
            action = "deny"
            reason += (" (agent-white-hat would have asked you; this agent cannot ask from a hook, so it was blocked. "
                       "Review it and run it yourself if you agree.)")
    reason = reason[:2000]
    if action == "defer":
        return {"antigravity": (json.dumps({"decision": "allow"}), 0, ""),
                "cursor": ("{}", 0, ""),
                "cline": (json.dumps({"cancel": False}), 0, "")}.get(agent, ("", 0, ""))
    if agent in ("claude", "codex"):
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": action,
                                                  "permissionDecisionReason": reason}}), 0, ""
    if agent == "copilot":
        return json.dumps({"permissionDecision": action, "permissionDecisionReason": reason}), 0, ""
    if agent == "gemini":
        return json.dumps({"decision": "deny", "reason": reason}), 0, ""
    if agent == "antigravity":
        return json.dumps({"decision": action, "reason": reason}), 0, ""
    if agent == "cursor":
        return json.dumps({"permission": action, "user_message": reason, "agent_message": reason}), 0, ""
    if agent == "devin":
        return json.dumps({"decision": "block", "reason": reason}), 0, ""
    if agent == "kiro":
        return "", 2, reason
    if agent == "cline":
        return json.dumps({"cancel": True, "errorMessage": reason}), 0, ""
    return json.dumps({"decision": action, "reason": reason}), 0, ""


def run_pre(agent: str, raw: str) -> tuple[str, int, str]:
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        return respond(agent, "defer", "")
    if not isinstance(data, dict):
        return respond(agent, "defer", "")
    decision = decide(normalize(agent, data))
    return respond(agent, decision.action, decision.reason)
