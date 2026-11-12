"""agent-virus-check as an MCP server over stdio, for any MCP host (Codex, Cursor, Gemini CLI, VS Code, Claude).

Tools: scan_path, check_command, checkup, watch_check. All are read-only and local.
Protocol: JSON-RPC 2.0, one message per line; speaks the 2026-07-28 revision and the earlier handshake revisions.
"""
from __future__ import annotations

import json
import sys

from . import __version__

MODERN = ("2026-07-28",)
VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
META_VERSION = "io.modelcontextprotocol/protocolVersion"
CAPABILITIES = {"tools": {}}
INSTRUCTIONS = ("Local, read-only security checks for code an agent is about to open, install or run. Call scan_path "
                "before running setup, install, build or test commands in a repository you did not write, and "
                "check_command before running a command copied from a README, issue or web page.")

TOOLS = [
    {"name": "scan_path", "description": "Scan a local folder, file, archive or git URL for things that run on their own "
     "(agent hooks, install scripts, folder-open tasks, MCP servers) and for hidden or malicious code. Returns a verdict "
     "(pass, warn, block, incomplete) and the evidence.",
     "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "description": "folder, file or git URL"}},
                     "required": ["path"]}, "annotations": {"readOnlyHint": True}},
    {"name": "check_command", "description": "Judge a shell command before running it: download-and-run, decode-and-run, "
     "credential access, persistence, look-alike packages, registry redirection, and whether the project it would set "
     "up passes a scan. Returns defer, ask or deny with reasons.",
     "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}, "cwd": {"type": "string"}},
                     "required": ["command"]}, "annotations": {"readOnlyHint": True}},
    {"name": "checkup", "description": "Check this computer for API keys in plain files, risky agent settings, planted "
     "instruction files, ClickFix traces, known malware traces and outdated agents. Secret values are never shown.",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
    {"name": "watch_check", "description": "Report changes to AI-agent and shell configuration since the user's baseline.",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
]


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def call_tool(name: str, args: dict) -> tuple[str, bool]:
    from . import report as render

    if name == "scan_path":
        from .scan import scan

        rep = scan(str(args.get("path") or "."), max_seconds=120)
        return render.text(rep, color=False, limit=40), False
    if name == "check_command":
        from .guard import check_command

        d = check_command(str(args.get("command", "")), str(args.get("cwd") or ""))
        return json.dumps({"action": d.action, "reason": d.reason}, ensure_ascii=False), False
    if name == "checkup":
        from .checkup import run

        return render.text(run(), color=False, limit=40, subject="computer"), False
    if name == "watch_check":
        from .watch import BASELINE, check

        if not BASELINE.exists():
            return "No baseline yet: the user should run `pah watch init`.", False
        return json.dumps(check(), indent=1, ensure_ascii=False), False
    raise RpcError(-32602, f"Unknown tool: {name}")


def server_info() -> dict:
    return {"name": "personal-anti-hack", "title": "agent-virus-check", "version": __version__}


def handle(method: str, params: dict) -> dict:
    if method == "initialize":
        asked = str(params.get("protocolVersion", ""))
        return {"protocolVersion": asked if asked in VERSIONS else VERSIONS[0], "capabilities": CAPABILITIES,
                "serverInfo": server_info(), "instructions": INSTRUCTIONS}
    if method == "server/discover":
        return {"supportedVersions": [*MODERN, *VERSIONS], "capabilities": CAPABILITIES,
                "_meta": {"io.modelcontextprotocol/serverInfo": server_info()}, "instructions": INSTRUCTIONS}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        try:
            text, failed = call_tool(str(params.get("name", "")), params.get("arguments") or {})
        except (OSError, RuntimeError, ValueError) as err:
            text, failed = f"{err.__class__.__name__}: {err}", True
        return {"content": [{"type": "text", "text": text}], "isError": failed}
    raise RpcError(-32601, f"Method not found: {method}")


def respond(message: dict) -> dict | None:
    if "id" not in message:
        return None
    params = message.get("params") or {}
    asked = (params.get("_meta") or {}).get(META_VERSION) if isinstance(params, dict) else None
    try:
        if not isinstance(message.get("method"), str):
            raise RpcError(-32600, "Invalid request")
        if asked is not None and asked not in MODERN:
            return {"jsonrpc": "2.0", "id": message["id"], "error": {
                "code": -32022, "message": "Unsupported protocol version",
                "data": {"supported": [*MODERN, *VERSIONS], "requested": asked}}}
        result = handle(message["method"], params)
        if asked is not None or message["method"] == "server/discover":
            result = {"resultType": "complete", **result}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}
    except RpcError as err:
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": err.code, "message": str(err)}}
    except Exception as err:  # a fault must not end the session
        return {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32603, "message": f"{type(err).__name__}: {err}"}}


def reply_to(body: str) -> dict | None:
    try:
        message = json.loads(body)
    except json.JSONDecodeError:
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    if not isinstance(message, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
    return respond(message)


def serve() -> int:
    stdin = open(sys.stdin.fileno(), encoding="utf-8", errors="replace", newline="\n", closefd=False)
    stdout = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False)
    for line in stdin:
        if not line.strip():
            continue
        reply = reply_to(line)
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0
