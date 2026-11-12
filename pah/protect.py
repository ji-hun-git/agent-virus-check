"""Antivirus duties for people who use AI agents: a full sweep of this computer, real-time protection and quarantine.

    pah sweep        scans the places where malware for AI-tool users lands, one item at a time: Downloads and
                     Desktop, code folders (every project in them), installed agent skills, plugins and extensions,
                     and editor extensions; adds the checkup (exposed keys, known traces, outdated agents) and the
                     engine built into the operating system (Microsoft Defender) or ClamAV for binaries.
    pah protect      does the same as things arrive: new downloads, clones, extensions, skills and startup items are
                     scanned within seconds; --quarantine moves blocked ones away. --install starts it at login.
    pah quarantine   list | restore ID | delete ID

Nothing is executed. Quarantine moves a file or folder into the agent-virus-check folder, renamed so that nothing
loads or runs it, and records where it came from so that `pah quarantine restore` can put it back.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .guard import HOME
from .model import Finding, rank

QUARANTINE = HOME / "quarantine"
SWEEP_CACHE = HOME / "sweep-cache.json"
PROTECT_LOG = HOME / "protect.log"

CODE_DIRS = ("code", "Code", "src", "dev", "projects", "Projects", "repos", "workspace", "git", "GitHub", "work",
             "Documents/GitHub", "Documents/Projects", "source/repos")
PROJECT_MARKERS = (".git", "package.json", "pyproject.toml", "setup.py", "Cargo.toml", "go.mod", "SKILL.md", ".mcp.json",
                   ".claude", "AGENTS.md", "CLAUDE.md", "Makefile", "requirements.txt", ".vscode", ".cursor")
IGNORED_NAMES = {"desktop.ini", ".ds_store", ".localized", "thumbs.db", ".obsolete", ".init-default-profile-extensions",
                 "extensions.json"}
PARTIAL_DOWNLOAD = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload")
BIG_FILE = 200 * 1024 * 1024  # larger downloads go to the engine only
NOT_FOR_DOWNLOADS = {"PAH-F004"}  # a downloaded installer is a binary by design; the engine judges it


def _home() -> Path:
    return Path(os.environ.get("PAH_SWEEP_HOME") or Path.home())


def locations(home: Path | None = None) -> dict[str, list[Path]]:
    """Folders whose entries are scanned one by one, grouped by kind. Only folders that exist are returned."""
    home = home or _home()
    profile = Path(os.environ.get("USERPROFILE") or home) if not os.environ.get("PAH_SWEEP_HOME") else home
    kinds = {
        "downloads": [home / "Downloads", home / "Desktop", profile / "OneDrive" / "Desktop"],
        "code": [home / c for c in CODE_DIRS],
        "agent": [home / ".claude" / "skills", home / ".claude" / "plugins" / "marketplaces",
                  home / ".claude" / "plugins" / "cache", home / ".agents" / "skills", home / ".codex" / "skills",
                  home / ".gemini" / "extensions", home / ".openclaw" / "extensions", home / ".cursor" / "skills",
                  home / ".kiro" / "skills", home / ".config" / "opencode" / "plugin", home / ".config" / "opencode" / "plugins"],
        "extensions": [home / ".vscode" / "extensions", home / ".vscode-insiders" / "extensions",
                       home / ".cursor" / "extensions", home / ".windsurf" / "extensions", home / ".vscode-oss" / "extensions",
                       home / ".kiro" / "extensions", home / ".antigravity" / "extensions", home / ".trae" / "extensions"],
    }
    out = {}
    for kind, paths in kinds.items():
        seen, keep = set(), []
        for p in paths:
            try:
                key = p.resolve()
            except OSError:
                continue
            if p.is_dir() and key not in seen:
                seen.add(key)
                keep.append(p)
        out[kind] = keep
    return out


def _is_project(path: Path) -> bool:
    return any((path / m).exists() for m in PROJECT_MARKERS)


def items(locs: dict[str, list[Path]]) -> list[tuple[str, Path]]:
    """(kind, path) for every entry a sweep scans."""
    out = []
    for kind, roots in locs.items():
        for root in roots:
            try:
                entries = sorted(root.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                continue
            for entry in entries:
                name = entry.name.lower()
                if name in IGNORED_NAMES or name.endswith(PARTIAL_DOWNLOAD) or entry.is_symlink():
                    continue
                if kind == "code":
                    if entry.is_dir() and _is_project(entry):
                        out.append((kind, entry))
                    elif entry.is_dir():  # an owner or group folder: code/org/repo
                        try:
                            out += [(kind, sub) for sub in sorted(entry.iterdir()) if sub.is_dir() and _is_project(sub)]
                        except OSError:
                            pass
                elif kind in ("agent", "extensions") and not entry.is_dir():
                    continue
                else:
                    out.append((kind, entry))
    return out


def signature(path: Path) -> str:
    """What has to change for a cached result to be stale: size and times of the entry and of its key files."""
    parts = []
    for p in (path, path / ".git" / "HEAD", path / ".git" / "index", path / "package.json", path / ".claude" / "settings.json",
              path / ".vscode" / "tasks.json", path / "SKILL.md"):
        try:
            st = p.stat()
            parts.append(f"{p.name}:{st.st_size}:{st.st_mtime_ns}")
        except OSError:
            continue
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


@dataclass
class Item:
    kind: str
    path: str
    verdict: str
    findings: list[dict] = field(default_factory=list)
    seconds: float = 0.0
    note: str = ""
    cached: bool = False
    quarantined: list[str] = field(default_factory=list)


def _top(findings: list[Finding], limit: int = 5) -> list[dict]:
    keep = sorted((f for f in findings if rank(f.severity) >= rank("medium")), key=lambda f: -rank(f.severity))
    return [{"rule": f.rule, "severity": f.severity, "path": f.path, "line": f.line, "message": f.message} for f in keep[:limit]]


def _verdict(findings: list[Finding], incomplete: bool) -> str:
    top = max((rank(f.severity) for f in findings), default=0)
    if top >= rank("high"):
        return "block"
    if top >= rank("medium"):
        return "warn"
    return "incomplete" if incomplete else "pass"


def scan_item(kind: str, path: Path, max_seconds: float = 60.0) -> Item:
    """Scan one entry and judge it. Downloads that are binaries are left to the engine, not to the repository rules."""
    from .scan import scan

    started = time.monotonic()
    try:
        if path.is_file() and path.stat().st_size > BIG_FILE:
            return Item(kind, str(path), "pass", note="large file: left to the antivirus engine")
        rep = scan(path, max_seconds=max_seconds)
    except (OSError, ValueError) as e:
        return Item(kind, str(path), "incomplete", note=f"could not be read: {e.__class__.__name__}")
    findings = [f for f in rep.findings if not (kind == "downloads" and path.is_file() and f.rule in NOT_FOR_DOWNLOADS)]
    return Item(kind, str(path), _verdict(findings, bool(rep.incomplete)), _top(findings),
                round(time.monotonic() - started, 2), note="; ".join(rep.incomplete)[:200])


def _load_cache() -> dict:
    try:
        return json.loads(SWEEP_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        SWEEP_CACHE.parent.mkdir(parents=True, exist_ok=True)
        SWEEP_CACHE.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass


def sweep(kinds: tuple[str, ...] | None = None, *, engine: bool = True, checkup: bool = True, fresh: bool = False,
          quarantine: bool = False, max_seconds: float = 60.0, progress=None) -> dict:
    """A full scan of this computer's risky places. Returns a JSON-ready report."""
    started = time.monotonic()
    locs = {k: v for k, v in locations().items() if not kinds or k in kinds}
    todo = items(locs)
    cache = {} if fresh else _load_cache()
    results: list[Item] = []
    for i, (kind, path) in enumerate(todo):
        key, sig = str(path), signature(path)
        hit = cache.get(key)
        if hit and hit.get("sig") == sig and hit.get("verdict") in ("pass", "warn"):
            item = Item(kind, key, hit["verdict"], hit.get("findings", []), 0.0, hit.get("note", ""), cached=True)
        else:
            item = scan_item(kind, path, max_seconds)
            cache[key] = {"sig": sig, "verdict": item.verdict, "findings": item.findings, "note": item.note}
        if quarantine and item.verdict == "block":
            item.quarantined = disarm(kind, path, item)
        results.append(item)
        if progress:
            progress(i + 1, len(todo), item)
    _save_cache(cache)
    engine_report = {}
    if engine and (not kinds or "downloads" in kinds):
        from . import av

        detections, used, problems = [], [], []
        for root in locs.get("downloads", []):
            found, engines_used, errs = av.scan(root.resolve(), timeout=1800)
            detections += [{"rule": f.rule, "severity": f.severity, "path": str(root / f.path), "message": f.message}
                           for f in found]
            used, problems = sorted(set(used) | set(engines_used)), problems + errs
        engine_report = {"engines": used, "problems": problems, "detections": detections}
    host = None
    if checkup:
        from .checkup import run

        rep = run()
        host = {"verdict": rep.verdict, "findings": [
            {"rule": f.rule, "severity": f.severity, "path": f.path, "message": f.message} for f in rep.findings
            if rank(f.severity) >= rank("medium")]}
    order = {"block": 0, "incomplete": 1, "warn": 2, "pass": 3}
    results.sort(key=lambda it: (order[it.verdict], it.kind, it.path.lower()))
    worst = min((order[it.verdict] for it in results), default=3)
    if engine_report.get("detections"):
        worst = 0
    if host and host["verdict"] == "block":
        worst = 0
    elif host and host["verdict"] == "warn":
        worst = min(worst, 2)
    return {
        "verdict": [k for k, v in order.items() if v == worst][0],
        "places": {k: [str(p) for p in v] for k, v in locs.items()},
        "items": [it.__dict__ for it in results],
        "counts": {v: sum(it.verdict == v for it in results) for v in order},
        "engine": engine_report, "computer": host, "seconds": round(time.monotonic() - started, 1),
    }


# ------------------------------------------------------------------------------------------------ quarantine


def _entry_dir(qid: str) -> Path:
    if not qid.isalnum():
        raise ValueError("not a quarantine id")
    return QUARANTINE / qid


def _digest(path: Path) -> str:
    if path.is_dir():
        return ""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _defang(path: Path) -> None:
    """Take execute permission away from everything in the quarantined copy."""
    targets = [path] + (list(path.rglob("*")) if path.is_dir() else [])
    for p in targets:
        try:
            if p.is_file():
                p.chmod(p.stat().st_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except OSError:
            pass


def quarantine(path: str | Path, reason: str) -> dict:
    """Move a file or folder into quarantine and record where it came from."""
    src = Path(path)
    if not src.exists() and not src.is_symlink():
        raise FileNotFoundError(str(src))
    qid = uuid.uuid4().hex[:12]
    entry = _entry_dir(qid)
    entry.mkdir(parents=True, exist_ok=False)
    meta = {"id": qid, "original": str(src.resolve()), "name": src.name, "kind": "folder" if src.is_dir() else "file",
            "sha256": _digest(src) if src.is_file() else "", "reason": reason,
            "when": time.strftime("%Y-%m-%d %H:%M:%S")}
    payload = entry / (src.name + ".quarantined")
    shutil.move(str(src), str(payload))
    _defang(payload)
    (entry / "meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
    return meta


def quarantined() -> list[dict]:
    out = []
    for meta in sorted(QUARANTINE.glob("*/meta.json")) if QUARANTINE.is_dir() else []:
        try:
            out.append(json.loads(meta.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            continue
    return sorted(out, key=lambda m: m.get("when", ""))


def restore(qid: str) -> dict:
    entry = _entry_dir(qid)
    meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
    dest = Path(meta["original"])
    if dest.exists():
        raise FileExistsError(f"{dest} exists; move it away first")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(entry / (meta["name"] + ".quarantined")), str(dest))
    shutil.rmtree(entry, ignore_errors=True)
    return meta


def delete(qid: str) -> dict:
    entry = _entry_dir(qid)
    meta = json.loads((entry / "meta.json").read_text(encoding="utf-8"))
    shutil.rmtree(entry)
    return meta


def disarm(kind: str, path: Path, item: Item) -> list[str]:
    """Quarantine what a blocked item needs to stop working: a downloaded file, an extension or skill folder as a
    whole, and in a project only the files that carry high or critical findings (the hook, the payload), so the
    rest of the work stays where it is."""
    reason = "; ".join(f"{f['rule']} {f['message']}" for f in item.findings[:3])[:400]
    moved = []
    try:
        if kind in ("downloads", "agent", "extensions") or path.is_file():
            moved.append(quarantine(path, reason)["id"])
            return moved
        root = path.resolve()
        files = sorted({f["path"] for f in item.findings if f["severity"] in ("high", "critical") and f.get("path")})
        for rel in files:
            target = (root / rel).resolve()
            if target.is_file() and root in target.parents:
                moved.append(quarantine(target, reason)["id"])
    except OSError:
        pass
    return moved


# ------------------------------------------------------------------------------------------- real-time protect


def startup_dirs(home: Path | None = None) -> list[Path]:
    home = home or _home()
    dirs = [home / "Library" / "LaunchAgents", home / ".config" / "autostart", home / ".config" / "systemd" / "user"]
    if os.environ.get("APPDATA"):
        dirs.append(Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    return [d for d in dirs if d.is_dir()]


def _snapshot(locs: dict[str, list[Path]], extra: list[Path]) -> dict[str, tuple[str, str]]:
    snap = {}
    for kind, path in items(locs) + [("startup", p) for d in extra for p in (d.iterdir() if d.is_dir() else [])]:
        try:
            st = path.stat()
            snap[str(path)] = (kind, f"{st.st_size}:{st.st_mtime_ns}:{signature(path)}")
        except OSError:
            continue
    return snap


def notify(title: str, message: str) -> None:
    """Best-effort desktop notification; the log and the console always get the message."""
    try:
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title "
                            "(item 1 of argv)", "-e", "end run", title, message], timeout=10, check=False,
                           capture_output=True)
        elif sys.platform == "win32":
            script = ("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = "
                      "WindowsRuntime] > $null; $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
                      "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); $x = $t.GetElementsByTagName('text'); "
                      "$x[0].AppendChild($t.CreateTextNode($env:PAH_TITLE)) > $null; "
                      "$x[1].AppendChild($t.CreateTextNode($env:PAH_MESSAGE)) > $null; "
                      "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
                      "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show("
                      "[Windows.UI.Notifications.ToastNotification]::new($t))")
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=15, check=False,
                           capture_output=True, env={**os.environ, "PAH_TITLE": title, "PAH_MESSAGE": message})
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], timeout=10, check=False, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


def _log(line: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"{stamp}  {line}", flush=True)
    try:
        PROTECT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with PROTECT_LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"{stamp}  {line}\n")
    except OSError:
        pass


def check_new(before: dict, after: dict, pending: dict, *, do_quarantine: bool, alert=notify) -> list[Item]:
    """Scan entries that are new or changed and have stopped changing (a download still being written waits)."""
    out = []
    for key, (kind, sig) in after.items():
        if before.get(key, (None, None))[1] == sig:
            pending.pop(key, None)
            continue
        if pending.get(key) != sig:  # changed since the last poll: wait for it to settle
            pending[key] = sig
            continue
        pending.pop(key, None)
        path = Path(key)
        item = scan_item("startup" if kind == "startup" else kind, path)
        if kind == "startup" and item.verdict == "pass":
            item.verdict, item.note = "warn", "new startup item"
        if item.verdict in ("block", "warn"):
            if do_quarantine and item.verdict == "block":
                item.quarantined = disarm(kind, path, item)
            reason = item.findings[0]["message"] if item.findings else item.note
            _log(f"{item.verdict.upper():5} {kind:10} {key}  {reason}" + (f"  (quarantined: {', '.join(item.quarantined)})"
                                                                            if item.quarantined else ""))
            alert("agent-virus-check: " + ("blocked" if item.verdict == "block" else "check this"),
                  f"{path.name}: {reason}"[:200])
        out.append(item)
    return out


def protect(interval: float = 5.0, *, do_quarantine: bool = False, cycles: int | None = None, alert=notify) -> None:
    """Poll the risky places and scan what arrives. cycles=None runs until interrupted."""
    locs = locations()
    extra = startup_dirs()
    watched = [str(p) for v in locs.values() for p in v] + [str(d) for d in extra]
    _log(f"protecting {len(watched)} places: " + ", ".join(watched))
    before = after = _snapshot(locs, extra)
    pending: dict = {}
    n = 0
    while cycles is None or n < cycles:
        time.sleep(interval)
        n += 1
        after = _snapshot(locs, extra)
        check_new(before, after, pending, do_quarantine=do_quarantine, alert=alert)
        before = {k: v for k, v in after.items() if k not in pending}
        if n % 120 == 0:
            from . import watch

            if watch.BASELINE.exists():
                for change in watch.check():
                    if change["severity"] in ("high", "critical"):
                        _log(f"WATCH {change['label']}: {change['change']}")
                        alert("agent-virus-check: agent settings changed", f"{change['label']}: {change['change']}"[:200])


# --------------------------------------------------------------------------------------------- start at login

TASK_NAME = "agent-virus-check protect"
PLIST = "dev.agent-virus-check.protect"


def login_plan(command: list[str], remove: bool = False) -> list[dict]:
    """What starting real-time protection at login takes on this system: files to write and commands to run."""
    home = Path.home()
    if sys.platform == "win32":
        exe = Path(command[0])
        quiet = exe.with_name("pythonw.exe") if exe.with_name("pythonw.exe").exists() else exe
        run = subprocess.list2cmdline([str(quiet)] + command[1:])
        return [{"run": ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]}] if remove else \
            [{"run": ["schtasks", "/Create", "/TN", TASK_NAME, "/SC", "ONLOGON", "/RL", "LIMITED", "/F", "/TR", run]}]
    if sys.platform == "darwin":
        plist = home / "Library" / "LaunchAgents" / f"{PLIST}.plist"
        if remove:
            return [{"run": ["launchctl", "unload", str(plist)]}, {"delete": str(plist)}]
        args = "".join(f"<string>{a}</string>" for a in command)
        text = ('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                f"<key>Label</key><string>{PLIST}</string><key>ProgramArguments</key><array>{args}</array>"
                "<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>"
                f"<key>StandardOutPath</key><string>{PROTECT_LOG}</string></dict></plist>\n")
        return [{"write": str(plist), "text": text}, {"run": ["launchctl", "load", "-w", str(plist)]}]
    unit = home / ".config" / "systemd" / "user" / "agent-virus-check-protect.service"
    if remove:
        return [{"run": ["systemctl", "--user", "disable", "--now", unit.name]}, {"delete": str(unit)}]
    text = ("[Unit]\nDescription=agent-virus-check real-time protection\n\n[Service]\n"
            f"ExecStart={subprocess.list2cmdline(command)}\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n")
    return [{"write": str(unit), "text": text}, {"run": ["systemctl", "--user", "daemon-reload"]},
            {"run": ["systemctl", "--user", "enable", "--now", unit.name]}]


def apply_plan(plan: list[dict]) -> list[str]:
    done = []
    for step in plan:
        if "write" in step:
            Path(step["write"]).parent.mkdir(parents=True, exist_ok=True)
            Path(step["write"]).write_text(step["text"], encoding="utf-8")
            done.append(f"wrote {step['write']}")
        elif "delete" in step:
            Path(step["delete"]).unlink(missing_ok=True)
            done.append(f"removed {step['delete']}")
        else:
            res = subprocess.run(step["run"], capture_output=True, text=True, check=False)
            done.append(f"ran {' '.join(step['run'][:3])}: exit {res.returncode}")
    return done
