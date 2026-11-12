"""Command line: pah scan | audit | sweep | protect | quarantine | check-command | hook | watch | checkup | install |
mcp | rules."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .agents import AGENTS as AGENT_CHOICES
from .model import EXIT_CODES

FAIL_ORDER = {"block": 2, "warn": 1, "incomplete": 1, "pass": 0}


def _stdio() -> None:
    """Consoles get Unicode through the console API; pipes and files get UTF-8, whatever the locale's code page."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            if hasattr(stream, "isatty") and not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")


def cmd_scan(args) -> int:
    from . import report as render
    from .scan import scan

    if args.deep and not Path(args.target).exists():
        raise RuntimeError("--deep reviews files on disk: clone the repository first (`git clone --no-recurse-submodules "
                           "<url>`), then run `pah scan <folder> --deep`")
    rep = scan(args.target, max_seconds=args.max_seconds, online=args.online, av=getattr(args, "av", False))
    if args.deep:
        from .review import review

        rep.review = review(rep, args.target, provider=args.provider, model=args.model)
    if args.format == "json":
        out = render.as_json(rep)
    elif args.format == "sarif":
        out = render.sarif(rep)
    else:
        out = render.text(rep, lang=args.lang, verbose=args.verbose)
        if getattr(args, "audit", False):
            out += "\n\n" + render.next_steps(rep, lang=args.lang)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    prefix = None
    if getattr(args, "github", False):
        from .ci import github, workspace_prefix

        prefix = workspace_prefix(args.target)
        github(rep, prefix=prefix)
    if getattr(args, "sarif_out", None):
        Path(args.sarif_out).write_text(render.sarif(rep, base=prefix or "") + "\n", encoding="utf-8")
    verdict = rep.verdict
    if args.fail_on:
        return EXIT_CODES[verdict] if FAIL_ORDER[verdict] >= FAIL_ORDER[args.fail_on] else 0
    return EXIT_CODES[verdict]


def cmd_check_command(args) -> int:
    from .guard import check_command

    d = check_command(args.command, args.cwd or os.getcwd(), scan_repos=not args.no_scan)
    if args.json:
        print(json.dumps({"action": d.action, "reason": d.reason,
                          "findings": [f.to_dict() for f in d.findings]}, indent=2, ensure_ascii=False))
    else:
        print(f"{d.action.upper()}: {d.reason or 'no objection from agent-white-hat'}")
    return {"defer": 0, "ask": 1, "deny": 2}[d.action]


def cmd_hook(args) -> int:
    from .hooks import main as hook_main

    return hook_main(args.event, args.agent)


def cmd_watch(args) -> int:
    from . import watch

    if args.action in ("init", "accept"):
        snap = watch.init()
        n = sum(1 for e in snap["files"].values() if e.get("exists"))
        print(f"Baseline saved to {watch.BASELINE}: {n} agent and shell configuration files, "
              f"{len(snap['dirs'])} folders, {len(snap.get('run_keys', {}))} Run keys.")
        return 0
    if not watch.BASELINE.exists():
        print("No baseline yet. Run `pah watch init` once your agent setup is the way you want it.")
        return 3
    changes = watch.check()
    if args.json:
        print(json.dumps(changes, indent=2, ensure_ascii=False))
    elif not changes:
        print("No changes to agent or shell configuration since the baseline.")
    else:
        for c in changes:
            print(f"{c['severity'].upper():8} {c['label']}  ({c['path']})\n         {c['change']}")
        print("\nIf you made these changes, run `pah watch accept`. If not, find out what did before using your agents.")
    return 2 if any(c["severity"] in ("high", "critical") for c in changes) else (1 if changes else 0)


def cmd_checkup(args) -> int:
    from . import report as render
    from .checkup import run

    rep = run()
    if args.format == "json":
        print(render.as_json(rep))
    else:
        print(render.text(rep, lang=args.lang, subject="computer"))
        if any(f.rule == "PAH-H001" for f in rep.findings):
            print("\nKeys in plain files: revoke and recreate them in each provider's console, then store the new ones "
                  "in your OS credential store or password manager. Changing a password does not cancel stolen tokens.")
    return EXIT_CODES[rep.verdict]


SWEEP_WORDS = {
    "en": {"title": "agent-white-hat sweep", "items": "items", "places": "places", "cached": "unchanged since the last "
           "sweep", "engine": "Antivirus engine", "none": "none found", "computer": "This computer (pah checkup)",
           "quarantined": "Quarantined", "verdict": "Verdict", "next_block": "Blocked items stay where they are unless you "
           "add --quarantine; `pah quarantine list` shows what was moved and `pah quarantine restore ID` puts it back.",
           "no_engine": "none on this computer, so binaries were not checked against signatures"},
    "ko": {"title": "agent-white-hat 전체 검사", "items": "개 항목", "places": "곳", "cached": "지난 검사 이후 바뀌지 않음",
           "engine": "백신 엔진", "none": "발견 없음", "computer": "이 컴퓨터 (pah checkup)", "quarantined": "격리됨",
           "verdict": "판정", "next_block": "--quarantine을 붙이지 않으면 차단 항목은 그대로 둡니다. 옮긴 항목은 "
           "`pah quarantine list`로 보고 `pah quarantine restore ID`로 되돌립니다.", "no_engine": "이 컴퓨터에 없어서 실행 파일은 시그니처로 검사하지 못했습니다"},
}


def render_sweep(rep: dict, lang: str = "en") -> str:
    w = SWEEP_WORDS.get(lang, SWEEP_WORDS["en"])
    items = rep["items"]
    places = sum(len(v) for v in rep["places"].values())
    out = [f"{w['title']}  ·  {len(items)} {w['items']}, {places} {w['places']}  ·  {rep['seconds']}s", ""]
    for it in items:
        if it["verdict"] == "pass":
            continue
        out.append(f" {it['verdict'].upper():10} {it['kind']:10} {it['path']}")
        for f in it["findings"][:3]:
            where = f"{f['path']}:{f['line']}" if f.get("line") else f["path"]
            out.append(f"            {f['severity']:8} {f['rule']}  {where}  {f['message'][:110]}")
        if it.get("note"):
            out.append(f"            {it['note'][:140]}")
        if it.get("quarantined"):
            out.append(f"            {w['quarantined']}: {', '.join(it['quarantined'])}")
    passed = [it for it in items if it["verdict"] == "pass"]
    cached = sum(1 for it in passed if it.get("cached"))
    out.append(f" {'PASS':10} {len(passed)} {w['items']}" + (f" ({cached} {w['cached']})" if cached else ""))
    engine = rep.get("engine") or {}
    if engine and not engine.get("engines"):
        out += ["", f"{w['engine']}: {w['no_engine']}"]
    elif engine:
        hits = engine.get("detections") or []
        out += ["", f"{w['engine']} ({', '.join(engine['engines'])}): " + (w["none"] if not hits else "")]
        out += [f"   {h['severity']:8} {h['path']}  {h['message'][:110]}" for h in hits[:20]]
    host = rep.get("computer")
    if host:
        out += ["", f"{w['computer']}: {host['verdict'].upper()}"]
        out += [f"   {f['severity']:8} {f['rule']}  {f['message'][:120]}" for f in host["findings"][:10]]
    out += ["", f"{w['verdict']}: {rep['verdict'].upper()}"]
    if rep["verdict"] == "block":
        out.append(w["next_block"])
    return "\n".join(out)


def cmd_sweep(args) -> int:
    from . import protect

    def progress(i, n, item):
        if item.verdict in ("block", "warn"):
            print(f"[{i}/{n}] {item.verdict.upper():5} {item.path}", file=sys.stderr, flush=True)

    rep = protect.sweep(tuple(args.only) if args.only else None, engine=not args.no_engine, checkup=not args.no_checkup,
                        fresh=args.fresh, quarantine=args.quarantine, max_seconds=args.max_seconds,
                        progress=None if args.format == "json" else progress)
    print(json.dumps(rep, indent=2, ensure_ascii=False) if args.format == "json" else render_sweep(rep, args.lang))
    return {"block": 2, "warn": 1, "incomplete": 3, "pass": 0}[rep["verdict"]]


def cmd_protect(args) -> int:
    from . import protect

    if args.install or args.uninstall:
        from .install import _base_args

        command = _base_args() + ["protect"] + (["--quarantine"] if args.quarantine else [])
        plan = protect.login_plan(command, remove=args.uninstall)
        print("Real-time protection " + ("will stop starting at login:" if args.uninstall else "will start at login:"))
        for step in plan:
            print("  " + (f"write {step['write']}" if "write" in step else f"delete {step['delete']}" if "delete" in step
                          else "run " + subprocess_line(step["run"])))
        if not args.yes:
            print("Nothing changed. Run the same command with --yes to apply it.")
            return 0
        for line in protect.apply_plan(plan):
            print("  " + line)
        return 0
    try:
        protect.protect(args.interval, do_quarantine=args.quarantine)
    except KeyboardInterrupt:
        print("Real-time protection stopped.")
    return 0


def subprocess_line(argv: list[str]) -> str:
    import subprocess

    return subprocess.list2cmdline(argv)


def cmd_quarantine(args) -> int:
    from . import protect

    if args.action == "list":
        entries = protect.quarantined()
        if not entries:
            print("Quarantine is empty.")
        for m in entries:
            print(f"{m['id']}  {m['when']}  {m['kind']:6} {m['original']}\n              {m['reason'][:140]}")
        return 0
    if not args.target:
        print(f"pah quarantine {args.action} needs {'a path' if args.action == 'add' else 'an ID from `pah quarantine list`'}.")
        return 3
    try:
        if args.action == "add":
            m = protect.quarantine(args.target, "moved by hand")
            print(f"Quarantined {m['original']} as {m['id']}.")
        elif args.action == "restore":
            m = protect.restore(args.target)
            print(f"Restored {m['original']}.")
        else:
            if not args.yes:
                print("Deleting cannot be undone. Run the same command with --yes to delete it.")
                return 0
            m = protect.delete(args.target)
            print(f"Deleted {m['original']} from quarantine for good.")
    except (OSError, ValueError, KeyError) as e:
        print(f"Could not {args.action}: {e}")
        return 3
    return 0


def cmd_trust(args) -> int:
    from .guard import is_trusted, set_trust, trusted_projects

    if args.list:
        for p in sorted(trusted_projects()):
            print(p)
        return 0
    path = Path(args.path or ".")
    if not path.is_dir():
        print(f"pah: not a folder: {path}", file=sys.stderr)
        return 64
    if args.remove:
        print(f"No longer trusted: {set_trust(path, False)}")
        return 0
    if is_trusted(path):
        print(f"Already trusted: {path.resolve()}")
        return 0
    print(f"Trusted: {set_trust(path, True)}\nThe guard still judges commands here but no longer scans this project before "
          "setup. Trust only projects you wrote or have reviewed; undo with `pah trust --remove`.")
    return 0


def cmd_install(args) -> int:
    from .install import AGENT_NAMES, apply, build, detected

    names = ["claude-code" if a == "claude" else a for a in args.agents]
    if args.all:
        names = list(AGENT_NAMES)
    elif args.detected or not names:
        names = detected()
        print("Agents found on this computer: " + (", ".join(names) or "none"))
    unknown = [a for a in names if a not in AGENT_NAMES]
    if unknown:
        print(f"Unknown agent(s): {', '.join(unknown)}. Choose from: {', '.join(AGENT_NAMES)}", file=sys.stderr)
        return 64
    return apply(build(names, skills=args.skills, mcp=args.mcp, hooks=not args.no_hooks), write=args.yes)


def cmd_mcp(args) -> int:
    from .mcp_server import serve

    return serve()


def cmd_rules(args) -> int:
    from . import av, checkup, guard, intel, packages, review, scan, surfaces, watch  # noqa: F401  (registers every rule)
    from .model import RULES
    from .report import rules_markdown

    if args.markdown:
        print(rules_markdown())
    else:
        for rid in sorted(RULES):
            print(f"{rid}  {RULES[rid].title}")
    return 0


def _ci_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--sarif-out", metavar="FILE", help="also write a SARIF report to FILE (for GitHub code scanning), "
                   "whatever --format prints")
    p.add_argument("--github", action="store_true", help="GitHub Actions: annotate findings on their lines, set the "
                   "verdict as a step output and write a job summary")


def main(argv: list[str] | None = None) -> int:
    _stdio()
    parser = argparse.ArgumentParser(prog="pah", description="A local shield for people who let AI agents open, install and "
                                     "run code. Nothing is executed and nothing leaves your machine unless you ask.")
    parser.add_argument("--version", action="version", version=f"agent-white-hat {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan a repository, skill, MCP server, package, archive or git URL before using it")
    p.add_argument("target")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--sarif", dest="format", action="store_const", const="sarif")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"), help="exit non-zero only at or above this verdict")
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--online", action="store_true", help="also check that packages exist, are not brand new and are not "
                   "listed as malicious (sends package names only, to registry.npmjs.org, pypi.org and api.osv.dev)")
    p.add_argument("--deep", action="store_true", help="add a model review of the evidence (needs a provider key)")
    p.add_argument("--provider", choices=("anthropic", "openai", "meta", "ollama"), default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true", help="also show info-level findings")
    p.add_argument("--av", action="store_true", help="also scan with the antivirus engine on this computer "
                   "(Microsoft Defender or ClamAV; local only)")
    _ci_options(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("audit", help="everything for one target: the scan, the local antivirus engine, and (with "
                       "--online) malicious-package and known-vulnerability checks; ends with next steps")
    p.add_argument("target")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--fail-on", choices=("block", "warn", "incomplete"))
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--online", action="store_true", help="send package names and versions to the public registries "
                   "and OSV (malicious packages, brand-new packages, known vulnerabilities)")
    p.add_argument("--no-av", dest="av", action="store_false", help="skip the antivirus engine")
    p.add_argument("--deep", action="store_true", help="add a model review of the evidence (needs a provider key)")
    p.add_argument("--provider", choices=("anthropic", "openai", "meta", "ollama"), default=None)
    p.add_argument("--model", default=None)
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.add_argument("-v", "--verbose", action="store_true")
    _ci_options(p)
    p.set_defaults(func=cmd_scan, av=True, audit=True)

    p = sub.add_parser("check-command", help="judge a shell command an agent (or you) is about to run")
    p.add_argument("command")
    p.add_argument("--cwd")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-scan", action="store_true", help="do not scan the project the command would set up")
    p.set_defaults(func=cmd_check_command)

    p = sub.add_parser("hook", help="agent hook entry point (reads the agent's JSON on stdin)")
    p.add_argument("event", choices=("pre", "post", "session-start"))
    p.add_argument("--agent", default="claude", choices=AGENT_CHOICES,
                   help="which agent's hook protocol to speak (default: claude)")
    p.set_defaults(func=cmd_hook)

    p = sub.add_parser("watch", help="baseline and diff of AI-agent and shell configuration")
    p.add_argument("action", choices=("init", "check", "accept"))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("checkup", help="check this computer for exposed keys, risky agent settings and known traces")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.set_defaults(func=cmd_checkup)

    p = sub.add_parser("sweep", help="full scan of this computer: downloads, code folders, agent skills and plugins, "
                       "editor extensions, the checkup and the built-in antivirus engine")
    p.add_argument("--only", nargs="*", choices=("downloads", "code", "agent", "extensions"), help="scan only these places")
    p.add_argument("--quarantine", action="store_true", help="move blocked items into quarantine (restorable)")
    p.add_argument("--fresh", action="store_true", help="ignore the results remembered from the last sweep")
    p.add_argument("--no-engine", action="store_true", help="skip the antivirus engine (Microsoft Defender or ClamAV)")
    p.add_argument("--no-checkup", action="store_true", help="skip the checks of this computer's settings and traces")
    p.add_argument("--max-seconds", type=float, default=60.0, help="time limit per item")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", dest="format", action="store_const", const="json")
    p.add_argument("--lang", choices=("en", "ko"), default=os.environ.get("PAH_LANG", "en"))
    p.set_defaults(func=cmd_sweep)

    p = sub.add_parser("protect", help="real-time protection: scan new downloads, clones, extensions, skills and startup "
                       "items as they arrive")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between checks")
    p.add_argument("--quarantine", action="store_true", help="move blocked items into quarantine (restorable)")
    p.add_argument("--install", action="store_true", help="start real-time protection at login (shows the change first)")
    p.add_argument("--uninstall", action="store_true", help="stop starting it at login")
    p.add_argument("--yes", action="store_true", help="apply --install or --uninstall")
    p.set_defaults(func=cmd_protect)

    p = sub.add_parser("quarantine", help="list, restore, delete or add quarantined files and folders")
    p.add_argument("action", choices=("list", "restore", "delete", "add"))
    p.add_argument("target", nargs="?", help="an ID from `pah quarantine list`, or a path for `add`")
    p.add_argument("--yes", action="store_true", help="confirm delete")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("trust", help="mark a project you wrote or reviewed as trusted, so the guard stops scanning it "
                       "before setup")
    p.add_argument("path", nargs="?")
    p.add_argument("--remove", action="store_true")
    p.add_argument("--list", action="store_true")
    p.set_defaults(func=cmd_trust)

    p = sub.add_parser("install", help="add the guard to AI agents: hooks, skills, MCP server (shows changes first)")
    p.add_argument("agents", nargs="*", help="claude-code codex gemini antigravity cursor copilot devin kiro cline "
                   "(default: the agents found on this computer)")
    p.add_argument("--all", action="store_true", help="every supported agent")
    p.add_argument("--detected", action="store_true", help="the agents whose settings folders exist")
    p.add_argument("--skills", action="store_true", help="also copy the security skills to ~/.agents/skills and "
                   "~/.claude/skills")
    p.add_argument("--mcp", action="store_true", help="also register the MCP server where the agent has a config file")
    p.add_argument("--no-hooks", action="store_true", help="skip the hooks (for example with --skills only)")
    p.add_argument("--yes", action="store_true", help="write the changes (default: only show them)")
    p.set_defaults(func=cmd_install)

    p = sub.add_parser("mcp", help="run as an MCP server over stdio (scan, check_command, checkup, watch_check)")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("rules", help="list every rule")
    p.add_argument("--markdown", action="store_true")
    p.set_defaults(func=cmd_rules)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as err:
        print(f"pah: not found: {err}", file=sys.stderr)
        return 64
    except RuntimeError as err:
        print(f"pah: {err}", file=sys.stderr)
        return 65
