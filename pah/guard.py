"""Decide whether an agent may run a command, write a file, read a file or fetch a URL.

The guard only ever makes things stricter: it answers "deny" or "ask", or stays silent and leaves the decision to
the agent's own permission system. It never answers "allow".
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from .indicators import EXFIL_HOSTS, RAW_IP_URL, SECRET_PATHS, is_private_ip

# The rule engine loads only when a command or file content has to be judged: a hook that checks a file read or a
# fetch stays fast.

HOME = Path(os.environ.get("PAH_HOME") or Path.home() / ".personal-anti-hack")
SCAN_CACHE = HOME / "scans.json"
TRUSTED = HOME / "trusted.json"


def trusted_projects() -> set[str]:
    try:
        return set(json.loads(TRUSTED.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        return set()


def set_trust(path: Path, trusted: bool = True) -> Path:
    """Projects the user has reviewed and trusts: the guard still judges commands there, but no longer scans them."""
    key = str(path.resolve())
    items = trusted_projects()
    (items.add if trusted else items.discard)(key)
    HOME.mkdir(parents=True, exist_ok=True)
    TRUSTED.write_text(json.dumps(sorted(items), indent=1), encoding="utf-8")
    return path.resolve()


def is_trusted(root: Path) -> bool:
    key = str(root.resolve())
    return any(key == t or key.startswith(t.rstrip("\\/") + os.sep) for t in trusted_projects())
SKIP_DIRS = {"node_modules", ".venv", "venv", ".tox", "target", "__pycache__", ".gradle", ".next", "dist", "build", ".cache"}


class Decision:
    def __init__(self, action: str = "defer", reason: str = "", findings: list | None = None):
        self.action = action  # defer | ask | deny
        self.reason = reason
        self.findings = findings if findings is not None else []

    def stricter(self, action: str, reason: str) -> None:
        order = {"defer": 0, "ask": 1, "deny": 2}
        if order[action] > order[self.action]:
            self.action = action
            self.reason = reason
        elif order[action] == order[self.action] and reason and reason not in self.reason:
            self.reason = (self.reason + "; " + reason).strip("; ")


def _summary(findings: list, limit: int = 3) -> str:
    from .model import RULES, rank

    top = sorted(findings, key=lambda f: -rank(f.severity))[:limit]
    return "; ".join(f"{f.severity.upper()} {RULES[f.rule].title}: {f.message}" for f in top)


def _action_for(findings: list) -> str:
    from .model import rank, worst

    sev = worst((f.severity for f in findings), "info")
    return "deny" if rank(sev) >= rank("high") else ("ask" if rank(sev) >= rank("medium") else "defer")


# ------------------------------------------------------------------------------------------- repo scans

SETUP = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|ci|add|run|run-script|test|t|start|exec|rebuild|link|dlx|x)\b|\b(?:npm|pnpm|yarn|bun)\s*(?:$|&&|;|\|)"
    r"|\bpip[0-9.]*\s+(?:install\s+(?:-e\s+|--editable\s+)?(?:\.|-r\b|--requirement)|download\b)|\bpython[0-9.]*\s+(?:-m\s+(?:pytest|pip\s+install)|setup\.py)"
    r"|\buv\s+(?:sync|run|pip\s+install|build)\b|\bpoetry\s+(?:install|run|build)\b|\bpipenv\s+(?:install|run)\b|\bpdm\s+install\b"
    r"|\bhatch\s+(?:run|env)\b|\btox\b|\bnox\b|\bpytest\b|\bcargo\s+(?:build|run|test|check|clippy|bench|install\s+--path)\b"
    r"|(?:^|[;&|]\s*)make\b|\bcmake\b|\bmeson\b|\bninja\b|(?:^|[;&|\s])\./[\w.-]+|\b(?:ba|z)?sh\s+[\w./-]+\.sh\b|\bgo\s+(?:run|generate|test|build)\b"
    r"|\bgradlew?\b|\bmvnw?\b|\bdocker\s+compose\s+up\b|\bdevcontainer\s+up\b|\bdirenv\s+allow\b|\bgit\s+(?:commit|checkout|switch|merge|rebase|pull)\b"
    r"|\bdeno\s+(?:task|run)\b|\bbundle\s+(?:install|exec)\b|\bcomposer\s+install\b|\bdotnet\s+(?:build|run|restore)\b", re.I)
SELF_CONTROL = re.compile(
    r"\b(?:pah|pah_entry\.py)\b[^\n|;&]{0,80}\b(?:trust|untrust|install)\b|\b(?:pah|pah_entry\.py)\b[^\n|;&]{0,40}\bwatch\s+(?:accept|init)\b"
    r"|\.personal-anti-hack(?![\w.-])|\bPAH_HOME\s*=|\bclaude\s+plugin\s+(?:disable|uninstall|remove)\b[^\n]{0,80}(?:personal-anti-hack|agent-virus-check|agent-white-hat)", re.I)
CD_PREFIX = re.compile(r"^\s*(?:cd|pushd|Set-Location)\s+(\"[^\"]+\"|'[^']+'|\S+)\s*(?:&&|;)")


def target_dir(command: str, cwd: str) -> Path:
    path = Path(cwd or os.getcwd())
    rest = command
    while True:
        m = CD_PREFIX.match(rest)
        if not m:
            break
        path = (path / os.path.expanduser(m.group(1).strip("\"'"))).resolve()
        rest = rest[m.end():]
    m = re.search(r"(?:--prefix|--cwd|-C|--manifest-path|--dir)[ =](\"[^\"]+\"|'[^']+'|\S+)", rest)
    if m:
        p = (path / os.path.expanduser(m.group(1).strip("\"'"))).resolve()
        path = p.parent if p.suffix else p
    return path


def project_root(path: Path) -> Path | None:
    path = path.resolve()
    home = Path.home().resolve()
    if path == home or path == Path(path.anchor) or not path.is_dir():
        return None
    p = path
    for _ in range(8):
        if (p / ".git").exists():
            return p
        if p.parent == p or p.parent == home:
            break
        p = p.parent
    return path


def fingerprint(root: Path, budget: int = 200_000) -> str:
    h = hashlib.sha256()
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and d != ".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            h.update(f"{os.path.relpath(full, root)}|{st.st_size}|{st.st_mtime_ns}\n".encode("utf-8", "replace"))
            count += 1
            if count > budget:
                return h.hexdigest() + "+"
    for extra in (".git/config", ".git/hooks"):
        p = root / extra
        if p.exists():
            st = os.lstat(p)
            h.update(f"{extra}|{st.st_size}|{st.st_mtime_ns}".encode())
    return h.hexdigest()


def _load_cache() -> dict:
    try:
        return json.loads(SCAN_CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        if len(cache) > 400:
            for key in sorted(cache, key=lambda k: cache[k].get("time", 0))[: len(cache) - 400]:
                cache.pop(key)
        tmp = SCAN_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, indent=1), encoding="utf-8")
        os.replace(tmp, SCAN_CACHE)
    except OSError:
        pass


def repo_verdict(root: Path, max_seconds: float = 25.0) -> dict:
    """Scan a project once per content state; return verdict and the top findings."""
    from .scan import scan

    key = str(root.resolve())
    fp = fingerprint(root)
    cache = _load_cache()
    hit = cache.get(key)
    if hit and hit.get("fingerprint") == fp:
        return hit
    report = scan(root, max_seconds=max_seconds)
    top = report.sorted_findings()[:5]
    entry = {"fingerprint": fp, "verdict": report.verdict, "time": time.time(),
             "summary": _summary(report.findings), "incomplete": report.incomplete[:3],
             "top": [{"rule": f.rule, "severity": f.severity, "path": f.path, "line": f.line, "message": f.message}
                     for f in top]}
    cache[key] = entry
    _save_cache(cache)
    return entry


# ------------------------------------------------------------------------------------------- decisions


def check_command(command: str, cwd: str = "", *, scan_repos: bool = True, max_seconds: float = 25.0) -> Decision:
    from .model import Finding
    from .names import R_LOOKALIKE, lookalike, lookalike_severity, names_in_command
    from .patterns import ENV_DUMP, R_DOWNLOAD_EXEC, analyze_command, classify_host, urls

    decision = Decision()
    findings = analyze_command(command, "(command)", 0, "agent")
    sensitive = bool(SECRET_PATHS.search(command) or EXFIL_HOSTS.search(command) or ENV_DUMP.search(command)
                     or any(not is_private_ip(m.group(1)) for m in RAW_IP_URL.finditer(command))
                     or re.search(r"\$\{?[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*\}?", command))
    for f in findings:
        if f.rule == R_DOWNLOAD_EXEC:
            kinds = {classify_host(u) for u in urls(command)}
            if kinds == {"official"}:
                f.severity = "medium"
                f.message += " (official installer; confirm it is the one you meant)"
        if f.message.endswith("sends data to a remote host") and not sensitive:
            f.severity = "low"  # an agent posting to an API is ordinary; posting secrets or to capture services is not
    for eco, name in names_in_command(command):
        hit = lookalike(name, eco)
        if hit:
            findings.append(Finding(R_LOOKALIKE, lookalike_severity(hit[1], "command"), "(command)", 0,
                                    f"{name} ({eco}) {hit[1]} from {hit[0]}", command[:200], "agent"))
    if os.environ.get("PAH_ONLINE") == "1":
        from .intel import check_packages

        named = [(eco, name, "(command)", 0, "agent") for eco, name in names_in_command(command)]
        findings.extend(check_packages(named))
    decision.findings = findings
    action = _action_for(findings)
    if action != "defer":
        decision.stricter(action, "agent-white-hat: " + _summary(findings))
    if re.search(r"\bgit\s+clone\b[^\n]*--(?:recurse-submodules|recursive)\b", command):
        decision.stricter("ask", "agent-white-hat: clone without submodules first and scan the repository "
                                 "(submodule tricks have run code on clone: CVE-2024-32002, CVE-2025-48384)")
    if SELF_CONTROL.search(command):
        decision.stricter("ask", "agent-white-hat: trusting a project, accepting configuration changes, changing the "
                                 "guard's state or disabling it is the user's decision, not the agent's")
    if scan_repos and SETUP.search(command) and not re.match(r"\s*git\s+clone\b", command):
        root = project_root(target_dir(command, cwd))
        if root is not None and is_trusted(root):
            root = None
        if root is not None:
            try:
                entry = repo_verdict(root, max_seconds=max_seconds)
            except (OSError, RuntimeError) as err:
                entry = {"verdict": "incomplete", "summary": f"scan failed: {err}"}
            verdict = entry.get("verdict")
            where = str(root)
            if verdict == "block":
                decision.stricter("deny", f"agent-white-hat scanned {where} and blocked running its setup: "
                                          f"{entry.get('summary')}. Show the user these findings; they can review them with "
                                          f"`pah scan \"{where}\"` and, only if it is their own project, run "
                                          f"`pah trust \"{where}\"` themselves.")
            elif verdict == "warn":
                decision.stricter("ask", f"agent-white-hat found things to review in {where} before running it: "
                                         f"{entry.get('summary')}")
            elif verdict == "incomplete":
                decision.stricter("ask", f"agent-white-hat could not scan all of {where} "
                                         f"({'; '.join(entry.get('incomplete') or [])}); review before running it")
    return decision


GLOBAL_AGENT_FILES = re.compile(
    r"[\\/]\.claude[\\/](?:settings(?:\.local)?\.json|CLAUDE\.md|hooks[\\/]|agents[\\/]|commands[\\/]|skills[\\/]|plugins[\\/])"
    r"|[\\/]\.claude\.json$|[\\/]\.codex[\\/](?:config\.toml|AGENTS\.md)|[\\/]\.gemini[\\/](?:settings\.json|GEMINI\.md)"
    r"|[\\/]\.cursor[\\/](?:mcp\.json|hooks\.json|rules)|[\\/]\.openclaw[\\/]|claude_desktop_config\.json$"
    r"|[\\/]\.codex[\\/]hooks\.json$|[\\/]\.gemini[\\/]config[\\/]|[\\/]\.copilot[\\/]|[\\/]devin[\\/](?:config|mcp_config)\.json$"
    r"|[\\/]\.kiro[\\/](?:hooks|settings|steering)[\\/]|[\\/]\.cline[\\/]|[\\/]Cline[\\/](?:Hooks|Rules)[\\/]"
    r"|[\\/]\.agents[\\/]skills[\\/]|[\\/]\.config[\\/](?:amp|opencode)[\\/]"
    r"|[\\/]Code[\\/]User[\\/](?:settings|tasks|mcp)\.json$|[\\/]\.codeium[\\/]", re.I)
PERSISTENCE_FILES = re.compile(
    r"[\\/]\.(?:bashrc|zshrc|bash_profile|zprofile|zshenv|profile|bash_login)$|PowerShell_profile\.ps1$|[\\/]LaunchAgents[\\/]"
    r"|[\\/]LaunchDaemons[\\/]|[\\/]Start Menu[\\/]Programs[\\/]Startup[\\/]|[\\/]\.config[\\/](?:autostart|systemd[\\/]user)[\\/]"
    r"|[\\/]\.git[\\/]hooks[\\/]|[\\/]\.git[\\/]config$|[\\/]\.npmrc$|[\\/](?:pip\.conf|pip\.ini)$|[\\/]\.ssh[\\/]", re.I)
PROJECT_AGENT_FILES = re.compile(
    r"(?:^|[\\/])\.claude[\\/]settings(?:\.local)?\.json$|(?:^|[\\/])\.mcp\.json$|(?:^|[\\/])\.cursor[\\/](?:mcp|hooks)\.json$"
    r"|(?:^|[\\/])\.codex[\\/]config\.toml$|(?:^|[\\/])\.gemini[\\/]settings\.json$|(?:^|[\\/])\.vscode[\\/](?:tasks|settings)\.json$"
    r"|(?:^|[\\/])\.devcontainer[\\/]|(?:^|[\\/])\.envrc$|(?:^|[\\/])\.codex[\\/]hooks\.json$|(?:^|[\\/])\.agents[\\/]hooks\.json$"
    r"|(?:^|[\\/])\.github[\\/]hooks[\\/]|(?:^|[\\/])\.kiro[\\/]hooks[\\/]|(?:^|[\\/])\.devin[\\/](?:hooks\.v1|config)\.json$"
    r"|(?:^|[\\/])\.clinerules[\\/]hooks[\\/]|(?:^|[\\/])\.(?:opencode|amp)[\\/]plugins[\\/]", re.I)


def check_write(path: str, content: str | None = None, cwd: str = "") -> Decision:
    decision = Decision()
    norm = str(Path(path).expanduser())
    try:
        own_state = Path(norm).resolve().is_relative_to(HOME.resolve())
    except (OSError, ValueError):
        own_state = False
    if own_state or re.search(r"[\\/]\.personal-anti-hack[\\/]", norm):
        decision.stricter("deny", "agent-white-hat: the agent may not edit the guard's own state (scan cache, trusted "
                                  "projects, configuration baseline)")
    elif GLOBAL_AGENT_FILES.search(norm):
        decision.stricter("ask", f"agent-white-hat: the agent is changing machine-wide agent configuration ({norm}). "
                                 "A planted instruction file made Codex rewrite its own settings this way.")
    elif PERSISTENCE_FILES.search(norm):
        decision.stricter("ask", f"agent-white-hat: writing {norm} changes what runs at login, on git commands or on "
                                 "package installs")
    elif PROJECT_AGENT_FILES.search(norm):
        decision.stricter("ask", f"agent-white-hat: {norm} makes commands run automatically for agents or editors")
    if content:
        from .model import rank
        from .patterns import scan_text

        found = [f for f in scan_text(content[:2_000_000], Path(norm).name, "doc" if norm.lower().endswith((".md", ".mdc"))
                                      else "code", decode=False)
                 if f.rule in ("PAH-T001", "PAH-T002", "PAH-T003", "PAH-T005", "PAH-T006") and rank(f.severity) >= rank("high")]
        if found:
            decision.findings = found
            decision.stricter("deny", "agent-white-hat: the content hides text or code: " + _summary(found))
    return decision


def check_read(path: str, cwd: str = "") -> Decision:
    decision = Decision()
    norm = str(Path(path).expanduser())
    if SECRET_PATHS.search(norm.replace("\\", "/")) or re.search(r"[\\/]\.ssh[\\/]|[\\/]\.gnupg[\\/]|[\\/]\.aws[\\/]", norm):
        decision.stricter("ask", f"agent-white-hat: the agent wants to read a credential store ({norm})")
    return decision


def check_fetch(url: str) -> Decision:
    decision = Decision()
    if EXFIL_HOSTS.search(url):
        decision.stricter("ask", f"agent-white-hat: {url[:120]} is a request-capture or tunnel service")
    m = RAW_IP_URL.search(url)
    if m and not is_private_ip(m.group(1)):
        decision.stricter("ask", f"agent-white-hat: fetching a raw IP address ({m.group(1)})")
    if re.search(r"[?&#/=][A-Za-z0-9+/_=-]{120,}", url):
        decision.stricter("ask", "agent-white-hat: the URL carries a long encoded value, a common way to leak data "
                                 "through a fetch")
    return decision


CLONE = re.compile(r"\b(?:git\s+clone|gh\s+repo\s+clone)\s+(.+)")


def clone_destination(command: str, cwd: str) -> Path | None:
    m = CLONE.search(command)
    if not m:
        return None
    args = [a.strip("\"'") for a in re.split(r"\s+", m.group(1).split("&&")[0].split(";")[0].strip()) if a]
    positional = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in ("-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference", "--filter",
                     "--separate-git-dir", "-j", "--jobs", "--template", "-u", "--upload-pack"):
                skip = True
            continue
        positional.append(a)
    if not positional:
        return None
    base = target_dir(command, cwd)
    if len(positional) >= 2:
        return (base / positional[1]).resolve()
    name = re.sub(r"\.git$", "", positional[0].rstrip("/").split("/")[-1].split(":")[-1])
    return (base / name).resolve() if name else None
