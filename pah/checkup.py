"""Check this computer for the traces and exposures that matter to people who use AI coding agents.

Read-only and local: nothing is sent anywhere, nothing is changed, and secret values are never printed.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .model import Report, rule
from .patterns import COMMAND_PATTERNS, R_DOWNLOAD_EXEC, classify_host, host_of, urls
from .surfaces import load_jsonc, load_toml

R_KEYS_ON_DISK = rule(
    "PAH-H001", "API keys saved in plain files",
    "Infostealers collect text files from Desktop, Documents and Downloads and now look for AI keys specifically "
    "(WardenStealer: 130,000+ infections since August 2026, taking Claude Code and Codex tokens). A stolen key keeps "
    "working until you revoke it.", "Move keys into your OS credential store or a password manager, delete the files, and "
    "rotate any key that has been in a plain file, a chat or a screenshot.", attack=("T1552.001",),
    refs=("https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/",))
R_CRED_PERMS = rule(
    "PAH-H002", "AI-tool credential file readable by other users",
    "Token files such as ~/.claude/.credentials.json and ~/.codex/auth.json should be readable only by you.",
    "chmod 600 the file.", attack=("T1552.001",))
R_RISKY_SETTINGS = rule(
    "PAH-H003", "Agent runs with approvals or protections turned off",
    "With approvals off, any instruction an agent reads (in a repo, web page, issue or tool output) runs without "
    "asking you. Agents changed their own settings this way in 2026 research.",
    "Turn approvals back on; use sandboxed or allow-listed modes for unattended work.", owasp=("ASI02",))
R_PLANTED = rule(
    "PAH-H004", "Agent instruction file outside a project",
    "An AGENTS.md or CLAUDE.md in Downloads, Desktop or your home folder is loaded by any agent started there. A website "
    "can save one to Downloads without a click; a planted one made Codex install malware in over 90% of attempts.",
    "Read it, then delete it unless you put it there. Don't run coding agents from Downloads.",
    attack=("T1204",), refs=("https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/",))
R_HISTORY = rule(
    "PAH-H005", "Shell history shows a downloaded script piped into a shell",
    "Fake Claude Code install pages (InstallFix) and ClickFix lures get people to paste exactly this; the result is "
    "an infostealer.", "If the host was not the vendor's official one, treat the machine as compromised: rotate "
    "credentials and sessions, and check for the persistence traces this checkup lists.", attack=("T1204.004", "T1059"),
    refs=("https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/",))
R_RUNMRU = rule(
    "PAH-H006", "Win+R history shows a ClickFix-style command",
    "ClickFix pages tell you to press Win+R and paste a command (mshta, PowerShell, curl). It was the most common "
    "initial access method in 2025 reports.", "Treat the machine as compromised; rotate credentials from another device.",
    attack=("T1204.004",), refs=("https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/",))
R_IOC = rule(
    "PAH-H007", "Known malware trace",
    "This file or folder matches a published indicator of a campaign that targets AI-tool users.",
    "Disconnect the machine from your accounts, rotate credentials from another device, and clean or reinstall.",
    attack=("T1036",))
R_OUTDATED = rule(
    "PAH-H008", "Agent or git version with a known code-execution fix missing",
    "These versions run code or leak credentials from a cloned repository's files; the fixed versions close that path.",
    "Update the tool.", attack=("T1203",))
R_EXPOSED_MODEL = rule(
    "PAH-H009", "Local model server open to the network",
    "175,000+ Ollama servers were reachable from the internet in January 2026; anyone on the network can use or abuse "
    "them.", "Bind Ollama to 127.0.0.1.", refs=("https://thehackernews.com/2026/01/researchers-find-175000-publicly.html",))
R_GLOBAL_REGISTRY = rule(
    "PAH-H010", "Every install on this machine goes through a non-default registry",
    "A global registry or index redirect applies to every project and every agent.",
    "Remove it unless it is your organization's registry.", attack=("T1195.001",))
R_PLAIN_GIT_CREDS = rule(
    "PAH-H011", "Git stores credentials in plain text",
    "credential.helper=store writes tokens to ~/.git-credentials in plain text, a standard stealer target.",
    "Use the OS credential manager (manager, osxkeychain, libsecret).", attack=("T1552.001",))
R_SECRETS_IN_AGENT_CFG = rule(
    "PAH-H013", "API keys written into agent configuration",
    "MCP server entries in ~/.claude.json, Claude Desktop, Cursor and Codex configs often carry API keys in plain "
    "text; stealers list these exact files (Check Point, 2026).", "Reference environment variables or a secret store "
    "instead of literal keys.", attack=("T1552.001",),
    refs=("https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/",))
R_CHECKUP_WATCH = rule(
    "PAH-H012", "Agent configuration changed since the last accepted baseline",
    "New hooks, MCP servers, API URLs or startup entries you did not add are how worms and planted instructions persist.",
    "Review with `pah watch check`; accept with `pah watch accept` only if you made the change.", attack=("T1546",))

KEY_PATTERNS = [
    ("Anthropic", re.compile(r"\bsk-ant-[a-z]{2,8}\d{0,2}-[A-Za-z0-9_-]{24,}")),
    ("OpenAI", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{24,}|\bsk-[A-Za-z0-9]{40,}\b")),
    ("Meta / Llama", re.compile(r"\bLLM[_|]\d{10,}[_|][A-Za-z0-9_-]{16,}")),
    ("Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("GitHub", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Hugging Face", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("npm", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("xAI", re.compile(r"\bxai-[A-Za-z0-9]{40,}\b")),
    ("Groq", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("OpenRouter", re.compile(r"\bsk-or-v1-[a-f0-9]{40,}\b")),
    ("Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}")),
    ("Stripe", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
]
TEXT_SUFFIXES = {".txt", ".md", ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".csv", ".log", ".sh",
                 ".ps1", ".bat", ".py", ".js", ".ts", ".rtf", ""}
SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "AppData", "Library", ".cache", "site-packages"}
INSTRUCTION_NAMES = {"agents.md", "agents.override.md", "claude.md", "claude.local.md", "gemini.md", ".cursorrules",
                     ".windsurfrules", ".clinerules", "soul.md"}
MIN_VERSIONS = {  # tool: (minimum safe version, reason, source)
    "claude": ("2.1.179", "project-file trust bypasses fixed up to 2.1.84 (CVE-2025-59536, CVE-2026-21852, CVE-2026-33068, "
               "CVE-2026-40068), a worktree named .git running core.fsmonitor (CVE-2026-55607) and plugin SHA pins "
               "resolved to a branch (CVE-2026-86063, fixed 2.1.179)", "https://www.air.security/blog-posts/plugin4shell"),
    "goose": ("1.44.0", "git run before trust executed a repository's core.fsmonitor (CVE-2026-72718)",
              "https://github.com/block/goose/security/advisories/GHSA-r5pp-p5r8-466r"),
    "kiro-cli": ("2.10.0", "a planted executable in the workspace ran at start (CVE-2026-18657)",
                 "https://aws.amazon.com/security/security-bulletins/2026-074-aws/"),
    "code": ("1.145.3", "a __proto__ key in workspace files started an MCP server in Restricted Mode (CVE-2026-121662)",
             "https://github.com/microsoft/vscode/security/advisories"),
    "codex": ("0.149.0", "project config command injection (CVE-2025-61260, fixed 0.23.0) and sandbox escapes fixed up to "
              "0.149.0", "https://labs.cloudsecurityalliance.org/research/csa-research-note-openai-codex-sandbox-escapes-20260922-csa/"),
    "gemini": ("0.39.1", "headless mode auto-trusted workspaces (CVE-2026-12537)", "https://github.com/advisories/GHSA-wpqr-6v78-jr5g"),
    "openclaw": ("2026.3.12", "workspace extensions loaded before trust (CVE-2026-32920); one-click RCE CVE-2026-25253 "
                 "fixed in 2026.1.29", "https://advisories.gitlab.com/npm/openclaw/GHSA-99qw-6mr3-36qr/"),
}
GIT_FIXED = {(2, 43): 7, (2, 44): 4, (2, 45): 4, (2, 46): 4, (2, 47): 3, (2, 48): 2, (2, 49): 1, (2, 50): 1}


def _mask(kind: str, value: str) -> str:
    return f"{kind} key ({value[:7]}…, {len(value)} characters)"


def _candidate_files(roots: list[Path], depth: int = 2, limit: int = 6000):
    count = 0
    for root in roots:
        if not root.is_dir():
            continue
        stack = [(root, 0)]
        while stack:
            directory, level = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for e in entries:
                if e.is_dir(follow_symlinks=False):
                    if level < depth and e.name not in SKIP_DIRS and not e.name.startswith("."):
                        stack.append((Path(e.path), level + 1))
                    continue
                if not e.is_file(follow_symlinks=False):
                    continue
                count += 1
                if count > limit:
                    return
                yield Path(e.path)


def keys_on_disk(report: Report, roots: list[Path]) -> None:
    for path in _candidate_files(roots):
        if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.lower().startswith(".env"):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found = []
        for kind, pattern in KEY_PATTERNS:
            for m in pattern.finditer(text):
                found.append(_mask(kind, m.group(0)))
        if found:
            report.findings.append(_finding(R_KEYS_ON_DISK, "high", str(path), "; ".join(sorted(set(found))[:4])))


def _finding(rule_id, severity, path, message, evidence="", line=0):
    from .model import Finding
    return Finding(rule_id, severity, path, line, message, evidence, "host")


def credential_permissions(report: Report) -> None:
    if os.name == "nt":
        return
    home = Path.home()
    for p in (home / ".claude" / ".credentials.json", home / ".codex" / "auth.json", home / ".gemini" / "oauth_creds.json",
              home / ".openclaw" / "openclaw.json", home / ".git-credentials", home / ".netrc", home / ".npmrc",
              home / ".config" / "gh" / "hosts.yml"):
        try:
            mode = p.stat().st_mode
        except OSError:
            continue
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            report.findings.append(_finding(R_CRED_PERMS, "medium", str(p), f"mode {oct(mode & 0o777)}"))


def risky_settings(report: Report) -> None:
    from .watch import locations

    for label, path in locations():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        data = load_toml(text) if path.suffix == ".toml" else (load_jsonc(text) if path.suffix == ".json" else None)
        if not isinstance(data, dict):
            continue
        perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
        problems = []
        if perms.get("defaultMode") == "bypassPermissions":
            problems.append("defaultMode is bypassPermissions")
        if data.get("approval_policy") == "never" and data.get("sandbox_mode") == "danger-full-access":
            problems.append("approval_policy=never with danger-full-access")
        for key, bad in (("chat.tools.autoApprove", True), ("chat.tools.global.autoApprove", True),
                         ("task.allowAutomaticTasks", "on"), ("security.workspace.trust.enabled", False)):
            if data.get(key) == bad:
                problems.append(f"{key} = {json.dumps(bad)}")
        env = data.get("env") if isinstance(data.get("env"), dict) else {}
        for k, v in env.items():
            if k.upper().endswith("_BASE_URL") and classify_host(str(v)) not in ("official",) and "localhost" not in str(v):
                problems.append(f"{k} = {v}")
        secrets = []
        for k, v in _walk_env(data):
            if any(p.search(str(v)) for _, p in KEY_PATTERNS):
                secrets.append(k)
        if problems:
            report.findings.append(_finding(R_RISKY_SETTINGS, "high" if any("BASE_URL" in p for p in problems) else "medium",
                                            str(path), f"{label}: " + "; ".join(problems)))
        if secrets:
            report.findings.append(_finding(R_SECRETS_IN_AGENT_CFG, "medium", str(path),
                                            f"{label}: literal keys in {', '.join(sorted(set(secrets))[:5])}"))
    host_env = os.environ.get("ANTHROPIC_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
    if host_env and classify_host(host_env) != "official" and "localhost" not in host_env:
        report.findings.append(_finding(R_RISKY_SETTINGS, "high", "environment", f"API base URL set to {host_env}"))
    ollama = os.environ.get("OLLAMA_HOST", "")
    if ollama.startswith(("0.0.0.0", "::", "[::]")):
        report.findings.append(_finding(R_EXPOSED_MODEL, "medium", "environment", f"OLLAMA_HOST={ollama}"))


def _walk_env(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "env" and isinstance(v, dict):
                for ek, ev in v.items():
                    yield f"{prefix}{ek}", ev
            else:
                yield from _walk_env(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_env(item, prefix)


def planted_instructions(report: Report) -> None:
    home = Path.home()
    for folder in (home, home / "Downloads", home / "Desktop", home / "Documents", home / "OneDrive" / "Desktop",
                   home / "OneDrive" / "Documents"):
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            if e.is_file() and e.name.lower() in INSTRUCTION_NAMES:
                sev = "high" if folder.name in ("Downloads", "Desktop") or folder == home else "medium"
                report.findings.append(_finding(R_PLANTED, sev, e.path, f"{e.name} in {folder}"))


def _history_files() -> list[Path]:
    home = Path.home()
    files = [home / ".bash_history", home / ".zsh_history", home / ".local" / "share" / "fish" / "fish_history"]
    appdata = os.environ.get("APPDATA")
    if appdata:
        files.append(Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
    return files


def shell_history(report: Report) -> None:
    for path in _history_files():
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[-5_000_000:]
        except OSError:
            continue
        seen = set()
        for i, line in enumerate(text.splitlines(), 1):
            for pat in COMMAND_PATTERNS:
                if pat.rule not in (R_DOWNLOAD_EXEC, "PAH-C013", "PAH-C014") or not pat.regex.search(line):
                    continue
                hosts = {host_of(u) for u in urls(line)} - {""}
                kinds = {classify_host(u) for u in urls(line)}
                if kinds and kinds <= {"official"}:
                    continue
                key = tuple(sorted(hosts)) or (pat.message,)
                if key in seen:
                    continue
                seen.add(key)
                sev = "high" if "lookalike" in kinds or pat.rule != R_DOWNLOAD_EXEC else "medium"
                report.findings.append(_finding(R_HISTORY, sev, str(path), f"{pat.message} from "
                                                f"{', '.join(sorted(hosts)) or 'an unknown source'}", "", i))


def runmru(report: Report) -> None:
    if sys.platform != "win32":
        return
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                v = str(value)
                if re.search(r"mshta|powershell|pwsh|curl|wget|iwr|irm|iex|bitsadmin|certutil|rundll32\s+\\\\|cmd\s+/c\s+start", v, re.I):
                    report.findings.append(_finding(R_RUNMRU, "high", r"HKCU\...\Explorer\RunMRU", f"entry {name}: "
                                                    f"{v[:40]}…"))
    except OSError:
        return


def iocs(report: Report) -> None:
    local = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    temp = Path(tempfile.gettempdir())
    checks = [
        (local / "Microsoft" / "EdgeUpdate" / "MicrosoftEdgeUpdateCore.dll", "fake Edge Update task payload (ACRStealer/Amatera)",
         "https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign"),
        (temp / "thinking_robot_log.txt", "PROMPTFLUX log file", "https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools"),
        (Path("C:/ProgramData/info/info.txt"), "PROMPTSTEAL/LAMEHUG output file",
         "https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools"),
        (Path("/tmp/helper"), "fake Claude Code installer dropper (macOS)", "https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware"),
        (Path("/tmp/osalogging.zip"), "MacSync staging archive", "https://www.huntress.com/blog/fake-claude-macsync"),
    ]
    home = Path.home()
    polinrider = "https://blog.gitguardian.com/ghostaction-x-polinrider/"
    testmetest = "https://research.jfrog.com/post/beyond-testmetest-42-hijacked-github-repos/"
    sleepyduck = "https://pluto.security/blog/sleepyduck-malware-open-vsx-extensions/"
    trojan_ext = "https://www.stepsecurity.io/blog/claude-code-extension-trojanized"
    apex = "https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages"
    checks += [
        (home / ".node_modules" / ".npm-ws-runner.js", "PolinRider loader (Oct 2026)", polinrider),
        (home / ".node_modules" / ".npm-ws.json", "PolinRider loader state", polinrider),
        (home / ".local" / "bin" / "net-health-checker.sh", "testmetest worm persistence (Oct 2026)", testmetest),
        (home / ".local" / "share" / "runtimes" / "sync.py", "testmetest worm persistence", testmetest),
        (Path("/var/tmp/.fontconfig_state"), "testmetest worm state file", testmetest),
        (local / "ScopeSmart Technologies Inc", "MALFEX payload folder (Oct 2026)",
         "https://checkmarx.com/zero-post/malfex-npm-malware-campaign-three-payloads-and-an-adversary-that-signs-their-work/"),
        (home / ".solidity", "SleepyDuck backdoor folder (Sep 2026)", sleepyduck),
        (home / "Library" / "LaunchAgents" / "com.solidity.langsupport.runner.plist", "SleepyDuck LaunchAgent", sleepyduck),
        (home / ".config" / "systemd" / "user" / "solidity-langsupport-runner.service", "SleepyDuck service", sleepyduck),
        (home / "Library" / "LaunchAgents" / "com.apple.sysmond.plist", "LaunchAgent of the trojanized Claude Code "
         "extension (Oct 2026; Apple's own agents live in /System)", trojan_ext),
        (Path(os.environ.get("APPDATA") or home) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "sysmon.cmd",
         "startup script of the trojanized Claude Code extension", trojan_ext),
        (home / ".apex" / "agent" / "mcp.json", "Apex Accelerator MCP configuration (Oct 2026)", apex),
        (temp / "_apex_run.ps1", "Apex Accelerator dropper script", apex),
    ]
    for path, what, src in checks:
        if sys.platform != "win32" and str(path).startswith("C:"):
            continue
        if sys.platform == "win32" and str(path).startswith("/tmp"):
            continue
        if path.exists():
            report.findings.append(_finding(R_IOC, "critical", str(path), f"{what} ({src})"))
    try:
        for e in os.scandir(home / ".config"):
            if e.name.startswith(".smt"):
                report.findings.append(_finding(R_IOC, "high", e.path, f"hidden .smt file of the trojanized Claude Code "
                                                f"extension ({trojan_ext})"))
                break
    except OSError:
        pass
    try:
        keys = (home / ".ssh" / "authorized_keys").read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?m)\ssvc-telemetry\s*$", keys):
            report.findings.append(_finding(R_IOC, "critical", str(home / ".ssh" / "authorized_keys"), "SSH key with the "
                                            f"comment svc-telemetry, planted by the trojanized Claude Code extension ({trojan_ext})"))
    except OSError:
        pass
    try:
        for e in os.scandir(temp):
            if e.name.startswith("akg_"):
                report.findings.append(_finding(R_IOC, "critical", e.path, "WardenStealer staging file "
                                                "(https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/)"))
                break
    except OSError:
        pass
    startup = Path(os.environ.get("APPDATA") or "") / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if sys.platform == "win32" and startup.is_dir():
        for e in os.scandir(startup):
            if e.name.lower().endswith((".vbs", ".js", ".jse", ".wsf", ".hta", ".bat", ".cmd", ".ps1")):
                report.findings.append(_finding(R_IOC, "high", e.path, "script in the Startup folder (PROMPTFLUX and "
                                                "many stealers persist this way)"))


def _version(tool: str) -> str | None:
    exe = shutil.which(tool)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15, check=False,
                             cwd=tempfile.gettempdir())
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+(?:\.\d+){1,3})", (out.stdout or "") + (out.stderr or ""))
    return m.group(1) if m else None


def _older(version: str, minimum: str) -> bool:
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)][:4]
    return parts(version) < parts(minimum)


def versions(report: Report) -> None:
    for tool, (minimum, why, src) in MIN_VERSIONS.items():
        v = _version(tool)
        if v and _older(v, minimum):
            report.findings.append(_finding(R_OUTDATED, "high", tool, f"{tool} {v} is older than {minimum}: {why} ({src})"))
    if sys.platform != "win32":
        v = _version("git")
        if v:
            major, minor, patch = ([int(x) for x in v.split(".")[:3]] + [0, 0, 0])[:3]
            fixed = GIT_FIXED.get((major, minor))
            if (major, minor) < (2, 43) or (fixed is not None and patch < fixed):
                report.findings.append(_finding(R_OUTDATED, "high", "git", f"git {v} predates the CVE-2025-48384 fix "
                                                "(code execution on clone --recursive)"))


def global_package_config(report: Report) -> None:
    home = Path.home()
    npmrc = home / ".npmrc"
    if npmrc.is_file():
        for m in re.finditer(r"(?m)^\s*registry\s*=\s*(\S+)", npmrc.read_text(encoding="utf-8", errors="replace")):
            if classify_host(m.group(1)) != "official":
                report.findings.append(_finding(R_GLOBAL_REGISTRY, "medium", str(npmrc), f"registry = {m.group(1)}"))
    gitconfig = home / ".gitconfig"
    if gitconfig.is_file():
        text = gitconfig.read_text(encoding="utf-8", errors="replace")
        if re.search(r"(?m)^\s*helper\s*=\s*store\b", text):
            report.findings.append(_finding(R_PLAIN_GIT_CREDS, "medium", str(gitconfig), "credential.helper = store"))
        m = re.search(r"(?m)^\s*fsmonitor\s*=\s*(?!true|false)(\S.*)$", text)
        if m:
            report.findings.append(_finding(R_RISKY_SETTINGS, "medium", str(gitconfig), f"core.fsmonitor runs {m.group(1)}"))


def watch_changes(report: Report) -> None:
    from .watch import BASELINE, check

    if not BASELINE.exists():
        return
    for c in check(quiet=True):
        if c["severity"] in ("high", "critical", "medium"):
            report.findings.append(_finding(R_CHECKUP_WATCH, c["severity"], c["path"], f"{c['label']}: {c['change']}"))


def run(*, key_roots: list[Path] | None = None) -> Report:
    started = time.monotonic()
    report = Report(target="this computer")
    home = Path.home()
    roots = key_roots if key_roots is not None else [home / "Desktop", home / "Documents", home / "Downloads",
                                                       home / "OneDrive" / "Desktop", home / "OneDrive" / "Documents"]
    for check in (lambda r: keys_on_disk(r, roots), credential_permissions, risky_settings, planted_instructions,
                  shell_history, runmru, iocs, versions, global_package_config, watch_changes):
        try:
            check(report)
        except (OSError, ValueError) as err:
            report.incomplete.append(f"{getattr(check, '__name__', 'check')}: {err}")
    report.stats = {"seconds": round(time.monotonic() - started, 2), "files": 0}
    return report
