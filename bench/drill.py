#!/usr/bin/env python3
"""Attack drill: replay what an agent does when asked to "set up this project", for every TrapRepo case and every
supported agent, through each agent's real hook protocol. No model is called and nothing from the cases runs.

    python bench/drill.py [--name NAME] [--agents claude codex ...] [--only case-id ...] [--subprocess]

For each case the drill materializes the repository, picks the command an agent would run to set it up (npm install,
pip install -e ., pytest, cargo build, make, ...), sends it to `pah hook pre --agent <agent>` in that agent's payload
format, and reads the answer in that agent's response format. It then replays a fixed set of risky actions that do not
depend on a repository (a download piped into a shell, a write to the agent's global settings, a read of an SSH key, a
look-alike package install) and a few harmless ones.

Expected: malicious cases are denied (or asked about, where the agent can ask and the case is a WARN); benign cases go
through untouched. With --subprocess every payload goes through `python -I pah_entry.py hook pre --agent X`, exactly as
the agents call it; without it the same code runs in-process (much faster, same decisions).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

AGENTS = ("claude", "codex", "gemini", "antigravity", "cursor", "copilot", "devin", "kiro", "cline")


def shell_payload(agent: str, command: str, cwd: str) -> dict:
    """The JSON each agent sends to a pre-tool hook before running a shell command."""
    return {
        "claude": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd},
        "codex": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd},
        "gemini": {"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": {"command": command},
                   "cwd": cwd},
        "antigravity": {"toolCall": {"name": "run_command", "args": {"CommandLine": command, "Cwd": cwd}}},
        "cursor": {"hook_event_name": "beforeShellExecution", "command": command, "cwd": cwd},
        "copilot": {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd},
        "devin": {"hook_event_name": "PreToolUse", "tool_name": "exec", "tool_input": {"command": command, "cwd": cwd}},
        "kiro": {"hook_event_name": "PreToolUse", "tool_name": "execute_bash", "tool_input": {"command": command}, "cwd": cwd},
        "cline": {"hookName": "PreToolUse", "preToolUse": {"toolName": "execute_command",
                                                            "parameters": {"command": command, "cwd": cwd}}},
    }[agent]


def write_payload(agent: str, path: str, content: str, cwd: str) -> dict:
    return {
        "claude": {"tool_name": "Write", "tool_input": {"file_path": path, "content": content}, "cwd": cwd},
        "codex": {"tool_name": "apply_patch", "tool_input": {
            "command": f"*** Begin Patch\n*** Add File: {path}\n+{content}\n*** End Patch"}, "cwd": cwd},
        "gemini": {"tool_name": "write_file", "tool_input": {"file_path": path, "content": content}, "cwd": cwd},
        "antigravity": {"toolCall": {"name": "write_to_file", "args": {"TargetFile": path, "CodeContent": content}}},
        "cursor": {"hook_event_name": "preToolUse", "tool_name": "Write", "tool_input": {"file_path": path,
                                                                                         "content": content}, "cwd": cwd},
        "copilot": {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": path,
                                                                                          "content": content}, "cwd": cwd},
        "devin": {"tool_name": "write", "tool_input": {"file_path": path, "content": content}},
        "kiro": {"tool_name": "fs_write", "tool_input": {"path": path, "file_text": content}, "cwd": cwd},
        "cline": {"preToolUse": {"toolName": "write_to_file", "parameters": {"path": path, "content": content}}},
    }[agent]


def read_payload(agent: str, path: str, cwd: str) -> dict:
    return {
        "claude": {"tool_name": "Read", "tool_input": {"file_path": path}, "cwd": cwd},
        "codex": None,  # Codex hooks see shell commands and patches only
        "gemini": {"tool_name": "read_file", "tool_input": {"absolute_path": path}, "cwd": cwd},
        "antigravity": {"toolCall": {"name": "view_file", "args": {"AbsolutePath": path}}},
        "cursor": {"hook_event_name": "preToolUse", "tool_name": "Read", "tool_input": {"file_path": path}, "cwd": cwd},
        "copilot": {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": path}, "cwd": cwd},
        "devin": None,
        "kiro": None,
        "cline": {"preToolUse": {"toolName": "read_file", "parameters": {"path": path}}},
    }[agent]


def parse(agent: str, out: str, code: int, err: str) -> str:
    """deny | ask | allow, from the agent's response format."""
    if agent == "kiro":
        return "deny" if code == 2 else "allow"
    if not out.strip():
        return "allow"
    data = json.loads(out)
    if agent in ("claude", "codex"):
        return (data.get("hookSpecificOutput") or {}).get("permissionDecision", "allow")
    if agent == "copilot":
        return data.get("permissionDecision", "allow")
    if agent in ("gemini", "antigravity"):
        return {"deny": "deny", "block": "deny", "ask": "ask"}.get(data.get("decision", "allow"), "allow")
    if agent == "cursor":
        return data.get("permission", "allow")
    if agent == "devin":
        return "deny" if data.get("decision") == "block" else "allow"
    if agent == "cline":
        return "deny" if data.get("cancel") else "allow"
    return "allow"


def call(agent: str, payload: dict, use_subprocess: bool, env: dict) -> str:
    raw = json.dumps(payload)
    if use_subprocess:
        done = subprocess.run([sys.executable, "-I", str(ROOT / "pah_entry.py"), "hook", "pre", "--agent", agent],
                              input=raw, capture_output=True, text=True, env=env, timeout=180)
        return parse(agent, done.stdout, done.returncode, done.stderr)
    from pah.agents import run_pre

    out, code, err = run_pre(agent, raw)
    return parse(agent, out, code, err)


def setup_command(repo: Path) -> str:
    """The command an agent typically runs first when asked to set up or test this repository."""
    files = {p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_file()}
    names = {Path(f).name.lower() for f in files}
    if ".yarnrc.yml" in names:
        return "yarn install"
    if any(n.startswith(".pnpmfile") for n in names):
        return "pnpm install"
    if "package.json" in names or "binding.gyp" in names:
        return "npm install"
    if any(n.startswith("requirements") and n.endswith(".txt") for n in names):
        return "pip install -r requirements.txt"
    if "setup.py" in names or "pyproject.toml" in names:
        return "pip install -e ."
    if "conftest.py" in names or any(n.endswith(".pth") for n in names):
        return "pytest"
    if "cargo.toml" in names or "build.rs" in names:
        return "cargo build"
    if "makefile" in names or "cmakelists.txt" in names:
        return "make"
    if any(n in names for n in ("gradlew", "build.gradle", "build.gradle.kts")) or any("gradle-wrapper" in f for f in files):
        return "./gradlew build"
    if any(f.startswith(".devcontainer/") for f in files):
        return "devcontainer up --workspace-folder ."
    if ".envrc" in names:
        return "direnv allow"
    if ".gitmodules" in names:
        return "git submodule update --init && make"
    if any(f.startswith(".git/") for f in files):
        return "git pull"
    return "npm test"


def generic_actions() -> list[tuple[str, str, str, set[str]]]:
    """(label, kind, target, accepted decisions): risky and harmless actions that do not depend on a repository. They
    live with the other inert attack data in bench/fixtures/."""
    data = json.loads((HERE / "fixtures" / "drill-actions.json").read_text(encoding="utf-8"))
    return [(a["label"], a["kind"], a["target"], set(a["accept"])) for a in data["actions"]]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default=time.strftime("%Y-%m-%d"))
    ap.add_argument("--agents", nargs="*", default=list(AGENTS))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--subprocess", action="store_true", help="call the real hook entry point for every payload")
    args = ap.parse_args(argv)

    from materialize import CASES_DIR, _materialize

    home = Path(tempfile.mkdtemp(prefix="pah-drill-home-"))
    os.environ["PAH_HOME"] = str(home)  # the guard's cache and trust list, isolated from the user's
    env = dict(os.environ)
    cases = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(CASES_DIR.glob("*.json"))]
    if args.only:
        cases = [c for c in cases if c["id"] in args.only]
    rows, skipped = [], []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pah-drill-") as tmp:
        for case in cases:
            try:
                repo, problems = _materialize(case, Path(tmp) / case["id"])
            except OSError as err:
                problems = [f"{err.__class__.__name__}: {err}"]
            if problems:  # for example symlinks, which need privileges on Windows
                reason = "; ".join(problems)
                for form in (tmp.replace(os.sep, os.sep * 2), tmp, Path(tmp).as_posix()):
                    reason = reason.replace(form, "<tmp>")  # results carry no local paths
                skipped.append({"id": case["id"], "reason": reason})
                continue
            command = setup_command(repo)
            for agent in args.agents:
                decision = call(agent, shell_payload(agent, command, str(repo)), args.subprocess, env)
                rows.append({"case": case["id"], "kind": case["kind"], "expected": case["expected"], "agent": agent,
                             "action": command, "decision": decision})
        workspace = Path(tmp) / "workspace"
        workspace.mkdir()
        for label, kind, target, accept in generic_actions():
            for agent in args.agents:
                if kind == "shell":
                    payload = shell_payload(agent, target, str(workspace))
                elif kind == "write":
                    path = str(Path(target).expanduser()) if target.startswith("~") else str(workspace / target)
                    payload = write_payload(agent, path, "{}", str(workspace))
                else:
                    payload = read_payload(agent, str(Path(target).expanduser()), str(workspace))
                if payload is None:
                    continue  # this agent's hooks do not see this kind of tool call
                decision = call(agent, payload, args.subprocess, env)
                rows.append({"case": label, "kind": "generic", "expected": "/".join(sorted(accept)), "agent": agent,
                             "action": target, "decision": decision, "ok": decision in accept})

    def ok(row: dict) -> bool:
        if row["kind"] == "generic":
            return row["ok"]
        if row["kind"] == "benign":
            return row["decision"] == "allow"
        return row["decision"] in ("deny", "ask")

    summary = {}
    for agent in args.agents:
        mine = [r for r in rows if r["agent"] == agent]
        mal = [r for r in mine if r["kind"] == "malicious"]
        ben = [r for r in mine if r["kind"] == "benign"]
        gen = [r for r in mine if r["kind"] == "generic"]
        summary[agent] = {
            "malicious_stopped": sum(r["decision"] in ("deny", "ask") for r in mal), "malicious": len(mal),
            "malicious_denied": sum(r["decision"] == "deny" for r in mal),
            "benign_untouched": sum(r["decision"] == "allow" for r in ben), "benign": len(ben),
            "generic_ok": sum(r["ok"] for r in gen), "generic": len(gen),
        }
    failures = [r for r in rows if not ok(r)]
    out = HERE / "results" / f"{args.name}-drill.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"date": time.strftime("%Y-%m-%d"), "platform": sys.platform,
                               "mode": "subprocess" if args.subprocess else "in-process",
                               "seconds": round(time.monotonic() - started, 1), "summary": summary,
                               "skipped": skipped, "failures": failures, "rows": rows}, indent=1) + "\n",
                   encoding="utf-8")
    print(f"{'agent':12} {'malicious stopped':>18} {'(denied)':>9} {'benign untouched':>17} {'risky actions':>14}")
    for agent, s in summary.items():
        print(f"{agent:12} {s['malicious_stopped']:>11}/{s['malicious']:<6} {s['malicious_denied']:>9} "
              f"{s['benign_untouched']:>10}/{s['benign']:<6} {s['generic_ok']:>8}/{s['generic']:<5}")
    for item in skipped:
        print(f"  skipped {item['id']}: {item['reason'][:120]}")
    for row in failures[:40]:
        print(f"  FAIL {row['agent']:11} {row['case']:40} {row['action'][:40]:40} -> {row['decision']} "
              f"(expected {row['expected'] if row['kind'] != 'malicious' else 'deny/ask'})")
    print(f"\n{len(rows)} decisions, {len(failures)} unexpected  ->  {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
