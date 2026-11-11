"""Execution surfaces: everything in a repo that runs, or changes what an agent does, without being read first.

Each handler parses one kind of file, records the surface (what runs and what triggers it), analyzes every command
it finds, and marks files those commands reference as "autoexec" so their content is judged as code that runs on
its own.
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path

from .model import Finding, Surface, bump, clip, rank, rule
from .names import R_LOOKALIKE, lookalike, lookalike_severity, names_in_command, normalize, popular
from .policy import inert_path
from .patterns import (AI_ADDRESSED, HOST_NOTE, R_DOWNLOAD_EXEC, SECRET_PATHS, analyze_command, classify_host,
                       host_kind, host_of)
from .text import Lines

R_HOOKS = rule(
    "PAH-A001", "Repository ships agent hooks",
    "Hooks in a repository's .claude/settings.json (or Gemini/Cursor equivalents) run shell commands with your "
    "permissions: after you trust the folder in an interactive session, and with no prompt at all under `claude -p` or "
    "the Agent SDK. The Miasma worm (June 2026) spread through SessionStart hooks; 73 repositories were disabled.",
    "Read every hook command and the files it runs before trusting the folder. Run headless agents on repos you did "
    "not write with hooks disabled.", attack=("T1546", "T1059"), owasp=("ASI04", "ASI05"),
    refs=("https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents",
          "https://code.claude.com/docs/en/hooks"))
R_CMD_SETTING = rule(
    "PAH-A002", "Agent setting that runs a command",
    "apiKeyHelper, statusLine, awsAuthRefresh, awsCredentialExport, otelHeadersHelper (Claude Code) and Codex's notify "
    "run programs; a repository has no reason to supply the program that produces your API key.",
    "Remove the setting or point it at a program you installed yourself.", attack=("T1059", "T1552"), owasp=("ASI03",),
    refs=("https://code.claude.com/docs/en/settings",))
R_BASE_URL = rule(
    "PAH-A003", "Redirects the agent's API traffic",
    "A repository that sets ANTHROPIC_BASE_URL, OPENAI_BASE_URL, a proxy, NODE_OPTIONS or extra CA certificates routes "
    "your prompts, code and API key through someone else's server (CVE-2026-21852 leaked API keys this way; a planted "
    "CLAUDE.md captured login tokens in about half of attempts).",
    "Delete the setting. If an agent already ran here, rotate the API key or log out and back in.",
    attack=("T1557", "T1552"), owasp=("ASI03", "LLM02"),
    refs=("https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/",
          "https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/"))
R_APPROVALS = rule(
    "PAH-A004", "Turns off the agent's approvals or sandbox",
    "Project settings that set bypassPermissions, allow every shell command, approval_policy=never or full disk "
    "access let any instruction the agent reads run without asking you.",
    "Remove the setting from the repository; decide approval modes yourself.", owasp=("ASI02",),
    refs=("https://code.claude.com/docs/en/permissions",))
R_MCP_SERVER = rule(
    "PAH-A005", "Repository defines an MCP server the agent will start",
    "A project MCP server is a program the agent launches with your permissions (CurXecute, MCPoison, CVE-2025-59536). "
    "Interactive Claude Code asks first; `claude -p` and the SDK connect without asking.",
    "Check the command and pin the package version before approving the server.", attack=("T1059",), owasp=("ASI04",),
    refs=("https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison",))
R_MCP_AUTO = rule(
    "PAH-A006", "Approves the repository's MCP servers automatically",
    "enableAllProjectMcpServers / enabledMcpjsonServers in a repository's own settings pre-approve its servers, so "
    "they start without the prompt that would have shown you the command (CVE-2025-59536).",
    "Remove the setting and approve servers one by one.", owasp=("ASI04",),
    refs=("https://www.wiz.io/vulnerability-database/cve/cve-2025-59536",))
R_CURSOR_HOOKS = rule(
    "PAH-A007", "Repository ships Cursor hooks",
    "Commands in .cursor/hooks.json run on agent events; workspace hooks ran before trust until Cursor 3.0.0 "
    "(CVE-2026-48124).", "Read the commands; update Cursor.", attack=("T1546",),
    refs=("https://www.pillar.security/blog/the-hook-was-already-in-the-workspace",))
R_CODEX_HOME = rule(
    "PAH-A008", "Redirects Codex's configuration into the repository",
    "A .env that sets CODEX_HOME makes Codex load config.toml from the repository, whose MCP servers then run "
    "(CVE-2025-61260, fixed in 0.23.0).", "Delete the variable; update Codex.", attack=("T1574",),
    refs=("https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/",))
R_AGENT_EXTENSION = rule(
    "PAH-A010", "Agent extension loaded with the workspace",
    "OpenClaw loaded .openclaw/extensions from an opened workspace before trust (CVE-2026-32920, fixed 2026.3.12).",
    "Remove the extension or review its code; update OpenClaw.", attack=("T1546",),
    refs=("https://advisories.gitlab.com/npm/openclaw/GHSA-99qw-6mr3-36qr/",))
R_INSTRUCTION = rule(
    "PAH-A011", "Instruction file tells the agent to do something risky",
    "Agents load AGENTS.md, CLAUDE.md, GEMINI.md, rules and skills automatically and follow them. A 13 KB AGENTS.md "
    "disguised as engineering guidelines made Codex install malware in over 90% of attempts; the researchers' "
    "conclusion was that users have to defend themselves.",
    "Read the instruction. Agents should not change their own settings, hide actions from you or install packages "
    "an instruction file names.", attack=("T1204",), owasp=("ASI01", "LLM01"),
    refs=("https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/",
          "https://arxiv.org/abs/2607.15143"))
R_UNPINNED_MCP = rule(
    "PAH-A013", "MCP server runs an unpinned package",
    "`npx -y package` or `@latest` fetches whatever version is newest at each start, so a later malicious release "
    "(a rug pull, like postmark-mcp) runs without any change in the repository.",
    "Pin an exact version.", attack=("T1195.002",), owasp=("ASI04",),
    refs=("https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html",))
R_TOOL_POISON = rule(
    "PAH-A014", "MCP tool description gives the model hidden orders",
    "Tool descriptions go straight into the model's context. Poisoned descriptions tell it to read ~/.ssh or config "
    "files and pass them as arguments; no model in MCPTox refused more than 3% of the time.",
    "Do not connect the server. Report it.", attack=("T1059",), owasp=("LLM01", "ASI04"),
    refs=("https://arxiv.org/abs/2508.14925",))
R_OTHER_AGENT = rule(
    "PAH-A015", "Other agent configuration that runs commands",
    "Aider test/lint commands, Zed context servers and tasks, Continue and Cline MCP servers in a repository run "
    "programs on the agent's behalf.", "Read the commands before using the agent here.", attack=("T1059",))
R_UNPINNED_RUN = rule(
    "PAH-A017", "Instructions run an unpinned package from the registry",
    "`npx pkg@latest`, `uvx pkg` or `pipx run pkg` in instructions an agent follows runs whatever the registry serves "
    "under that name today. LLM-written skills spread invented names (react-codeshift was copied into 237 repositories), "
    "and whoever registers such a name gets code execution.",
    "Pin an exact version of a package you have checked; run `pah scan --online` to confirm the package exists.",
    attack=("T1195.002",), owasp=("LLM03", "ASI04"),
    refs=("https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands",))
R_SKILL_FETCH = rule(
    "PAH-A016", "Skill fetches or runs remote code",
    "Skills are instructions plus scripts the agent runs. ClawHavoc's 341+ malicious ClawHub skills told the agent to "
    "run a setup step that downloaded the AMOS stealer.", "Do not install the skill.", attack=("T1204", "T1105"),
    refs=("https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting",))

R_FOLDER_OPEN = rule(
    "PAH-I001", "Task runs when the folder is opened",
    "VS Code and Cursor tasks with runOn: folderOpen run a command as soon as the folder opens (Cursor shipped with "
    "Workspace Trust off). Fake job-interview repositories deliver StoatWaffle this way.",
    "Do not open the folder in an editor that trusts it until you have read the task.", attack=("T1204.002", "T1059"),
    refs=("https://www.infoworld.com/article/4149285/new-stoatwaffle-malware-auto%E2%80%91executes-attacks-on-developers-2.html",
          "https://www.oasis.security/blog/cursor-security-flaw"))
R_WEAK_SETTINGS = rule(
    "PAH-I002", "Workspace settings weaken the editor's protections",
    "chat.tools.autoApprove, task.allowAutomaticTasks and turning Workspace Trust off in a repository let tasks and "
    "agent tools run without asking (CVE-2025-53773).", "Remove the settings from the repository.",
    attack=("T1562",), refs=("https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection",))
R_EXEC_SETTING = rule(
    "PAH-I003", "Workspace settings point an executable into the repository",
    "Settings like git.path, terminal profiles or language-server paths that name a file in the repository make the "
    "editor run it.", "Remove the setting.", attack=("T1574",))
R_DEVCONTAINER_HOST = rule(
    "PAH-I004", "Dev container runs a command on your machine",
    "initializeCommand runs on the host, not in the container, before the container exists.",
    "Read the command before opening the folder in a container.", attack=("T1059",),
    refs=("https://containers.dev/implementors/json_reference/",))
R_DEVCONTAINER_MOUNT = rule(
    "PAH-I005", "Dev container exposes host secrets or privileges",
    "Mounting ~/.ssh, ~/.aws, the Docker socket or the host root, or running privileged, gives code in the "
    "container your credentials or the host.", "Remove the mount or flag.", attack=("T1611", "T1552"))
R_ENVRC = rule(
    "PAH-I006", "Shell code runs when you enter the directory",
    "direnv runs .envrc on cd once it is allowed.", "Read it before `direnv allow`.", attack=("T1546",))
R_CI_PRT = rule(
    "PAH-I008", "Workflow runs pull-request code with repository secrets",
    "pull_request_target with a checkout of the pull request's head lets a fork run code with the repository's "
    "secrets and caches (TanStack / Mini Shai-Hulud).", "Do not check out untrusted code in pull_request_target.",
    attack=("T1195",), refs=("https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem",))

R_GITMODULES = rule(
    "PAH-G001", "Dangerous submodule definition",
    "ext:: transports, option-like URLs, custom update commands and paths with control characters or pointing into "
    ".git have been used for code execution on `git clone --recursive` (CVE-2024-32002, CVE-2025-48384).",
    "Clone without --recursive and update git.", attack=("T1203",),
    refs=("https://github.blog/open-source/git/git-security-vulnerabilities-announced-6/",))
R_GIT_CONFIG = rule(
    "PAH-G002", "Git configuration that runs commands",
    "core.fsmonitor, core.hooksPath, sshCommand, pager, credential helpers, diff/filter drivers and ! aliases run "
    "programs on everyday git commands, which agents run constantly. A cloned repository never ships these; an archive "
    "or a tampered checkout can.", "Remove the setting from .git/config.", attack=("T1546",))
R_GIT_HOOKS = rule(
    "PAH-G003", "Git hooks are already installed",
    "A fresh clone has only *.sample hooks. Real hook files mean the repository came as an archive or something "
    "installed them; they run on commit, checkout or push.", "Read them; delete what you did not install.",
    attack=("T1546",))
R_WORKTREE = rule(
    "PAH-G004", "Git directory indirection",
    "commondir/gitdir files that point elsewhere can make tools trust or run things from another location "
    "(Claude Code CVE-2026-40068).", "Inspect where they point.", attack=("T1574",),
    refs=("https://advisories.gitlab.com/npm/@anthropic-ai/claude-code/CVE-2026-40068/",))

# ---------------------------------------------------------------------------------------------- state


@dataclass
class File:
    rel: str
    size: int
    data: bytes
    text: str | None
    link_target: str | None = None

    @property
    def name(self) -> str:
        return posixpath.basename(self.rel)

    @property
    def dir(self) -> str:
        return posixpath.dirname(self.rel)


@dataclass
class State:
    root: Path
    files: dict[str, File] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    autoexec: dict[str, str] = field(default_factory=dict)
    doc_auto: set[str] = field(default_factory=set)
    incomplete: list[str] = field(default_factory=list)
    packages: list[tuple[str, str, str, int, str]] = field(default_factory=list)  # ecosystem, name, path, line, context
    extra: dict = field(default_factory=dict)  # stats from optional checks (dependencies, antivirus)

    def add(self, rule_id: str, severity: str | None, path: str, line: int = 0, message: str = "", evidence: str = "",
            context: str = "config") -> None:
        if severity:
            self.findings.append(Finding(rule_id, severity, path, line, message, clip(evidence), context))

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def surface(self, kind: str, path: str, trigger: str, command: str = "", line: int = 0) -> None:
        if inert_path(path):
            return  # a hook config inside a test fixture or an archive is not a surface of this repository
        self.surfaces.append(Surface(kind, path, trigger, clip(command, 300), line))

    def mark_autoexec(self, rel: str, reason: str, source: str | None = None) -> None:
        """Mark a file as running on its own. Fixtures and archive members only count when something outside them
        (an install script, a hook) runs them: a setup.py inside tests/fixtures/ is test data."""
        if rel not in self.files or rel in self.autoexec:
            return
        if inert_path(rel) and inert_path(source or rel):
            return
        self.autoexec[rel] = reason

    def command(self, cmd: str, path: str, line: int, kind: str, trigger: str, base_dir: str = "",
                floor: tuple[str, str] | None = None) -> list[Finding]:
        """Record a command surface, analyze it, mark the files it runs, and check the packages it installs."""
        cmd = cmd.strip()
        if not cmd:
            return []
        self.surface(kind, path, trigger, cmd, line)
        found = analyze_command(cmd, path, line, "autoexec")
        self.extend(found)
        for ref in exec_refs_in_command(cmd, base_dir or posixpath.dirname(path), self.files):
            self.mark_autoexec(ref, f"run by {kind} in {path}", source=path)
        for eco, name in names_in_command(cmd):
            self.packages.append((eco, name, path, line, "autoexec"))
            hit = lookalike(name, eco)
            if hit:
                self.add(R_LOOKALIKE, lookalike_severity(hit[1], "command"), path, line,
                         f"{name} ({eco}) {hit[1]} from {hit[0]}", cmd, "autoexec")
        if floor:
            self.add(floor[0], floor[1], path, line, kind, cmd, "autoexec")
        return found


# --------------------------------------------------------------------------------------------- helpers

_TOKEN = re.compile(r"\"([^\"]*)\"|'([^']*)'|(\S+)")
_PLACEHOLDERS = re.compile(r"^(?:\$\{?(?:workspaceFolder|workspaceRoot|CLAUDE_PROJECT_DIR|PWD|fileDirname|localWorkspaceFolder|"
                           r"containerWorkspaceFolder|CLAUDE_PLUGIN_ROOT)\}?|%CD%|\$\(pwd\))[\\/]")


_QUOTED_PLACEHOLDER = re.compile(r"[\"']?(?:\$\{?(?:workspaceFolder|workspaceRoot|CLAUDE_PROJECT_DIR|PWD|localWorkspaceFolder|"
                                 r"containerWorkspaceFolder|fileDirname)\}?|%CD%|\$\(pwd\))[\"']?[\\/]")


def refs_in_command(cmd: str, base_dir: str, files: dict) -> list[str]:
    """Repository files a command would run or read."""
    out = []
    cmd = _QUOTED_PLACEHOLDER.sub("", cmd)
    for m in _TOKEN.finditer(cmd):
        tok = next(g for g in m.groups() if g is not None)
        tok = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
        tok = _PLACEHOLDERS.sub("", tok).replace("\\", "/")
        if not tok or tok.startswith(("-", "http:", "https:", "$")) or len(tok) > 300:
            continue
        for cand in (posixpath.normpath(posixpath.join(base_dir, tok)), posixpath.normpath(tok)):
            if cand in files and cand not in out:
                out.append(cand)
                break
    return out


_SIMPLE_SPLIT = re.compile(r"&&|\|\||;|\||\n|(?<![<>&0-9])&(?![>&])")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = {"sudo", "env", "exec", "time", "nohup", "nice", "command", "builtin", "call", "start", "doas"}
_RUNNERS = re.compile(r"^(?:(?:ba|z|da|k|fi|c|tc)?sh|python[0-9.]*|py|pypy[0-9.]*|node|nodejs|deno|bun|bunx|tsx|ts-node|"
                      r"ruby|perl|php|pwsh|powershell|osascript|cscript|wscript|source|\.|lua|rscript|julia|java|go|"
                      r"npx|pnpx|uv|uvx|pipx|poetry|pdm|hatch|rye|pnpm|yarn|npm|dotnet|cmd)(?:\.exe)?$", re.I)
NOT_CODE = (".md", ".markdown", ".rst", ".txt", ".adoc", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".lock", ".csv",
            ".tsv", ".html", ".htm", ".xml", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".css", ".scss",
            ".map", ".d.ts", ".ini", ".cfg", ".conf", ".env", ".log")


def exec_refs_in_command(cmd: str, base_dir: str, files: dict) -> list[str]:
    """Repository files a command would execute: the program itself (./setup.sh, bin/tool) or a script handed to an
    interpreter or runner (bash x.sh, node x.js, npx tsx x.ts, uv run x.py). Files a command only reads
    (cat README.md, docker build -f Dockerfile, git add x.sh) are not executed by it."""
    out: list[str] = []
    cmd = _QUOTED_PLACEHOLDER.sub("", cmd)
    for part in _SIMPLE_SPLIT.split(cmd):
        toks = []
        for m in _TOKEN.finditer(part):
            tok = next(g for g in m.groups() if g is not None)
            tok = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
            toks.append(_PLACEHOLDERS.sub("", tok).replace("\\", "/"))
        i = 0
        while i < len(toks) and (_ENV_ASSIGN.match(toks[i]) or toks[i].lower() in _WRAPPERS):
            i += 1
        if i >= len(toks):
            continue
        toks = [t.strip("\"'") for t in toks]
        head = toks[i]
        program = posixpath.basename(head.lower())
        if _RUNNERS.match(program):
            candidates = toks[i + 1:]
        elif "/" in head or head.lower().endswith((".bat", ".cmd", ".exe", ".com")):
            candidates = [head]  # a path is run as given; cmd.exe also runs batch files from the current folder
        else:
            continue
        for tok in candidates:
            if not tok or tok.startswith(("-", "/", "http:", "https:", "$")) or len(tok) > 300:
                continue
            if tok.lower().endswith(NOT_CODE):
                continue
            for cand in (posixpath.normpath(posixpath.join(base_dir, tok)), posixpath.normpath(tok)):
                if cand in files and cand not in out:
                    out.append(cand)
                    break
    return out


def load_jsonc(text: str):
    """JSON with comments and trailing commas (VS Code, devcontainer, Claude settings)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    if len(text) > 2_000_000:
        return None
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    try:
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))
    except ValueError:
        return None


def load_toml(text: str):
    try:
        import tomllib
    except ImportError:  # Python 3.10: handlers fall back to line patterns
        return None
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return None


def line_of(text: str, needle: str) -> int:
    pos = text.find(needle) if needle else -1
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 0


def as_command(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    if isinstance(value, dict):
        if "command" in value:
            return as_command(value.get("command")) + (" " + as_command(value.get("args")) if value.get("args") else "")
        return " ; ".join(as_command(v) for v in value.values())
    return ""


def walk_commands(obj, path: tuple = ()):
    """(json path, command) for every object with a string "command" (hooks, MCP servers, tasks)."""
    if isinstance(obj, dict):
        if isinstance(obj.get("command"), str):
            yield path, as_command(obj)
        for k, v in obj.items():
            if k not in ("command", "args"):
                yield from walk_commands(v, path + (str(k),))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_commands(v, path + (str(i),))


OFFICIAL_API_HOSTS = ("api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.meta.ai",
                      "localhost", "127.0.0.1")
REDIRECT_ENV = re.compile(r"^(?:ANTHROPIC_(?:BASE_URL|API_URL|BEDROCK_BASE_URL|VERTEX_BASE_URL|FOUNDRY_BASE_URL)|"
                          r"OPENAI_(?:BASE_URL|API_BASE)|GOOGLE_GEMINI_BASE_URL|GEMINI_BASE_URL|CODEX_BASE_URL|OLLAMA_HOST|"
                          r"(?:AZURE_OPENAI|OPENROUTER|GROQ|MISTRAL|DEEPSEEK|XAI|TOGETHER|FIREWORKS|PERPLEXITY|COHERE|"
                          r"LITELLM|CLAUDE_CODE|COPILOT|CURSOR|AIDER|LLM)_(?:BASE_URL|API_BASE|API_URL|ENDPOINT|HOST))$", re.I)
SECRET_ENV = re.compile(r"^(?:ANTHROPIC_(?:API_KEY|AUTH_TOKEN)|OPENAI_API_KEY|GEMINI_API_KEY|CLAUDE_CODE_OAUTH_TOKEN)$", re.I)
INJECT_ENV = re.compile(r"^(?:NODE_OPTIONS|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|REQUESTS_CA_BUNDLE|HTTPS?_PROXY|ALL_PROXY|"
                        r"PYTHONSTARTUP|PYTHONPATH|LD_PRELOAD|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|PROMPT_COMMAND|"
                        r"GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|CODEX_HOME|CLAUDE_CONFIG_DIR)$", re.I)


def check_env(state: State, env: dict, f: File, origin: str, cap: str | None = None) -> None:
    """Variables that redirect an agent's API traffic, hand it someone else's key, or inject code into its process.
    cap limits the severity (a .env below the repository root is read only by tools started in that folder)."""
    add = state.add if cap is None else (lambda rule_id, sev, *a, **k: state.add(rule_id, sev if rank(sev) <= rank(cap)
                                                                                 else cap, *a, **k))
    for key, value in env.items():
        value = str(value)
        line = line_of(f.text or "", key)
        if REDIRECT_ENV.match(key):
            host = host_of(value) if "://" in value else value.split(":")[0]
            if host and host not in OFFICIAL_API_HOSTS and not host.endswith((".anthropic.com", ".openai.com")) \
                    and not value.startswith("$"):
                add(R_BASE_URL, "critical", f.rel, line, f"{origin} sets {key}={value}", f"{key}={value}")
        elif SECRET_ENV.match(key):
            add(R_BASE_URL, "high", f.rel, line, f"{origin} supplies its own {key} (your session would run "
                "under someone else's account, which can read it)", key)
        elif INJECT_ENV.match(key):
            sev = "critical" if key.upper() in ("CODEX_HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "CLAUDE_CONFIG_DIR") \
                or (key.upper() == "NODE_OPTIONS" and re.search(r"(?:--require|-r|--import|--loader)\b", value)) else "high"
            add(R_BASE_URL, sev, f.rel, line, f"{origin} sets {key}={value}", f"{key}={value}")


# ------------------------------------------------------------------------------------------ agent configs

CLAUDE_TRIGGER = "Claude Code session in this folder (after trust; without a prompt under claude -p / SDK)"
EARLY_EVENTS = {"SessionStart", "Setup", "UserPromptSubmit", "InstructionsLoaded", "ConfigChange"}


def claude_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, entries in hooks.items():
        for _path, cmd in walk_commands(entries):
            line = line_of(f.text, cmd.split()[0]) if cmd else 0
            state.command(cmd, f.rel, line, f"Claude Code hook ({event})", CLAUDE_TRIGGER, base_dir="",
                          floor=(R_HOOKS, "medium" if event in EARLY_EVENTS else "low"))
    for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "statusLine"):
        if key in data:
            cmd = as_command(data[key])
            state.command(cmd, f.rel, line_of(f.text, key), f"Claude Code {key}", CLAUDE_TRIGGER,
                          floor=(R_CMD_SETTING, "low" if key == "statusLine" else "high"))
    if isinstance(data.get("env"), dict):
        check_env(state, data["env"], f, "Claude Code settings")
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "bypassPermissions"), "defaultMode: bypassPermissions",
                  "bypassPermissions")
    for entry in perms.get("allow") or []:
        if isinstance(entry, str) and re.fullmatch(r"\s*(?:\*|Bash|Bash\(\s*\*\s*\)|Bash\(:\*\)|Bash\(\*:\*\))\s*", entry):
            state.add(R_APPROVALS, "high", f.rel, line_of(f.text, entry), f"allows every shell command: {entry}", entry)
    if data.get("enableAllProjectMcpServers") is True:
        state.add(R_MCP_AUTO, "high", f.rel, line_of(f.text, "enableAllProjectMcpServers"), "enableAllProjectMcpServers",
                  "enableAllProjectMcpServers: true")
    if data.get("enabledMcpjsonServers"):
        state.add(R_MCP_AUTO, "high", f.rel, line_of(f.text, "enabledMcpjsonServers"),
                  f"pre-approves {data['enabledMcpjsonServers']}", "enabledMcpjsonServers")


def mcp_config(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "") if not f.rel.endswith(".toml") else load_toml(f.text or "")
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or data.get("mcp_servers") or data.get("context_servers") or {}
    if not isinstance(servers, dict):
        return
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        line = line_of(f.text, f'"{name}"') or line_of(f.text, name)
        if spec.get("command"):
            cmd = as_command(spec)
            state.command(cmd, f.rel, line, f"{agent} MCP server '{name}'", trigger, floor=(R_MCP_SERVER, "low"))
            unpinned = unpinned_runner(cmd)
            if unpinned:
                state.add(R_UNPINNED_MCP, "low" if well_known(*unpinned) else "medium", f.rel, line,
                          f"'{name}' runs {unpinned[1]} without a pinned version", cmd)
        url = spec.get("url") or spec.get("serverUrl") or ""
        if url:
            kind = classify_host(url)
            state.surface(f"{agent} remote MCP server '{name}'", f.rel, trigger, url, line)
            if kind in ("raw-ip", "plain-http", "lookalike"):
                state.add(R_MCP_SERVER, "high", f.rel, line, f"remote server '{name}' at {url} ({kind})", url)
        if isinstance(spec.get("env"), dict):
            check_env(state, spec["env"], f, f"MCP server '{name}'")


def cursor_hooks(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    for path, cmd in walk_commands(data or {}):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Cursor hook ({'/'.join(path[1:2]) or 'hook'})",
                      "Cursor agent events in this workspace", floor=(R_CURSOR_HOOKS, "medium"))


def codex_config(state: State, f: File) -> None:
    mcp_config(state, f, "Codex", "Codex session (when CODEX_HOME or a trusted project points here)")
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*approval_policy\s*=\s*[\"']never[\"']|^\s*sandbox_mode\s*=\s*[\"']danger-full-access[\"']", text):
        state.add(R_APPROVALS, "high", f.rel, text.count("\n", 0, m.start()) + 1, m.group().strip(), m.group())
    m = re.search(r"(?m)^\s*notify\s*=\s*(\[.*?\])", text, re.S)
    if m:
        state.command(m.group(1), f.rel, text.count("\n", 0, m.start()) + 1, "Codex notify program",
                      "every Codex turn", floor=(R_CMD_SETTING, "high"))


def dotenv(state: State, f: File) -> None:
    text = f.text or ""
    env = {}
    for m in re.finditer(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[\"']?([^\"'\n#]*)", text):
        env[m.group(1)] = m.group(2).strip()
    if "CODEX_HOME" in env:
        state.add(R_CODEX_HOME, "critical" if not f.dir else "high", f.rel, line_of(text, "CODEX_HOME"),
                  f"CODEX_HOME={env['CODEX_HOME']}", f"CODEX_HOME={env['CODEX_HOME']}")
        env.pop("CODEX_HOME")
    check_env(state, {k: v for k, v in env.items() if REDIRECT_ENV.match(k) or INJECT_ENV.match(k)}, f, ".env",
              cap=None if not f.dir else "medium")


def gemini_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    for event, entries in (data.get("hooks") or {}).items() if isinstance(data.get("hooks"), dict) else []:
        for _path, cmd in walk_commands(entries):
            state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Gemini CLI hook ({event})",
                          "Gemini CLI session in this folder", floor=(R_HOOKS, "medium" if event in EARLY_EVENTS else "low"))
    mcp_config(state, f, "Gemini CLI", "Gemini CLI session in this folder")
    tools = data.get("tools") if isinstance(data.get("tools"), dict) else {}
    if data.get("yolo") or tools.get("autoAccept") or (data.get("security") or {}).get("approvalMode") == "yolo":
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "yolo") or line_of(f.text, "autoAccept"),
                  "auto-accepts tool calls", "yolo/autoAccept")
    if isinstance(data.get("env"), dict):
        check_env(state, data["env"], f, "Gemini CLI settings")


def openclaw_extension(state: State, f: File) -> None:
    state.mark_autoexec(f.rel, "OpenClaw workspace extension")
    if f.name in ("package.json", "openclaw.plugin.json", "index.js", "index.ts", "index.mjs"):
        state.surface("OpenClaw workspace extension", f.rel, "opening the workspace in OpenClaw")
        state.add(R_AGENT_EXTENSION, "high", f.rel, 1, "extension loads with the workspace", f.rel)


def aider_conf(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(test-cmd|lint-cmd|lint|test)\s*:\s*(.+)$", text):
        state.command(m.group(2).strip().strip("'\""), f.rel, text.count("\n", 0, m.start()) + 1,
                      f"Aider {m.group(1)}", "Aider runs it after edits", floor=(R_OTHER_AGENT, "medium"))


def generic_agent_json(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "")
    for path, cmd in walk_commands(data or {}):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"{agent} ({'/'.join(path[:2])})", trigger,
                      floor=(R_OTHER_AGENT, "medium"))


# ------------------------------------------------------------------------------------- instruction files

AUTO_LOADED = re.compile(
    r"(?:^|/)(?:AGENTS(?:\.override)?\.md|CLAUDE(?:\.local)?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|"
    r"\.roorules|CONVENTIONS\.md|SKILL\.md|SOUL\.md|copilot-instructions\.md)$"
    r"|(?:^|/)\.cursor/rules/.*\.mdc?$|(?:^|/)\.github/(?:instructions|prompts)/.*\.md$|(?:^|/)\.claude/(?:agents|commands|skills)/.*\.md$"
    r"|(?:^|/)\.gemini/commands/.*\.toml$|(?:^|/)\.windsurf/rules/.*\.md$|(?:^|/)\.clinerules/.*$|(?:^|/)\.roo/rules[^/]*/.*\.md$"
    r"|(?:^|/)\.amazonq/rules/.*\.md$|(?:^|/)\.kiro/steering/.*\.md$|(?:^|/)\.junie/guidelines\.md$", re.I)
SETUP_DOC = re.compile(r"(?:^|/)(?:README|INSTALL|SETUP|CONTRIBUTING|GETTING[-_]STARTED|QUICKSTART|DEVELOPMENT|BUILDING)"
                       r"(?:\.[a-z]+)?$|(?:^|/)docs?/.*(?:install|setup|getting[-_]started|quickstart).*\.md$", re.I)

IMPERATIVES = [
    (re.compile(r"\b(?:update|change|modify|edit|overwrite|rewrite|add\s+(?:the\s+following\s+|this\s+|these\s+lines\s+)?to)\s+"
                r"(?:your|the\s+agent'?s?|its)\s+(?:own\s+)?(?:global\s+|user\s+)?(?:settings|config(?:uration)?|settings\.json|"
                r"config\.toml|preferences|mcp\s+servers?|hooks)", re.I), "high", "tells the agent to change its own settings"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|\$CODEX_HOME)[\\/](?:\.(?:claude|codex|gemini|cursor|openclaw|copilot|kiro)[\\/])?"
                r"(?:settings(?:\.local)?\.json|config\.toml|hooks\.json|mcp(?:_config)?\.json|auth\.json|\.credentials\.json|"
                r"openclaw\.json)\b|\.claude\.json\b"), "high", "points the agent at its machine-wide configuration"),
    # Naming ANTHROPIC_BASE_URL in documentation is not an instruction; setting it to a host that is not the provider's is.
    (re.compile(r"\b(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE_GEMINI|CODEX|AZURE_OPENAI|OPENROUTER)_(?:BASE_URL|API_BASE|API_URL)\b"
                r"[\"'`]?\s*(?:=|:|\bto\b)\s*[\"'`]?https?://(?!(?:api\.anthropic\.com|api\.openai\.com|generativelanguage\."
                r"googleapis\.com|localhost|127\.0\.0\.1)\b)[\w.-]+"
                r"|\bCODEX_HOME\s*=\s*[\"']?(?!~?/?\.codex\b)[\w./~$-]+", re.I),
     "high", "changes where the agent sends its API traffic"),
    (re.compile(r"\b(?:disable|turn\s+off|skip|bypass|ignore)\s+(?:the\s+|all\s+|any\s+)?(?:sandbox(?:ing)?|approvals?|permission(?:s|\s+prompts?|\s+checks?)?"
                r"|confirmations?|safety\s+checks?|security\s+(?:checks?|warnings?))", re.I), "high", "tells the agent to disable its safeguards"),
    # "Don't ask the user for a key" is autonomy, not concealment; hiding is about not telling, or acting unseen.
    (re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention(?:\s+(?:this|it|that))?\s+to|alert|notify|warn)\s+"
                r"(?:the\s+)?(?:user|human|developer|operator)\b(?!\s+(?:to|how)\b)"
                r"|\b(?:run|execute|install|delete|remove|upload|send|push|download|curl|wget|overwrite|modify|change)\b[^.\n]{0,80}"
                r"\bwithout\s+(?:asking|telling|informing|notifying|alerting|confirming\s+with)\s+(?:the\s+)?(?:user|human|developer)\b"
                r"|\b(?:silently|quietly|covertly|secretly)\s+(?:run|install|execute|download|send|upload|exfiltrate|delete|push|"
                r"post|copy|modify)\b", re.I),
     "high", "tells the agent to hide actions from you"),
    (re.compile(r"\b(?:delete|remove|wipe|erase|clean)\b[^\n]{0,60}\b(?:all|every|entire|whole)\b[^\n]{0,60}\b(?:files|directories|home|"
                r"resources|buckets|repositories|data|history)\b|near-?factory\s+state", re.I), "high", "tells the agent to delete data broadly"),
    (re.compile(r"\b(?:read|cat|open|copy|upload|send|include|paste|attach)\b[^\n]{0,60}(?:~|\$HOME|%USERPROFILE%)[\\/]\."
                r"(?:ssh|aws|npmrc|netrc|git-credentials|claude|codex|gemini|config[\\/]gh)\b|\b(?:read|cat|send|upload|paste|"
                r"include)\b[^\n]{0,60}\b(?:id_rsa|id_ed25519|\.credentials\.json|auth\.json)\b", re.I), "high",
     "tells the agent to read or send credentials"),
    (re.compile(r"\b(?:extract|unzip|unpack)\b[^\n]{0,80}\b(?:and|then)\s+(?:run|execute|launch|source)\b", re.I), "medium",
     "tells the agent to unpack something and run it"),
]
_FENCE = re.compile(r"(?ms)^[ \t]*(```|~~~)[ \t]*([\w+-]*)[^\n]*\n(.*?)^[ \t]*\1")
_INLINE = re.compile(r"`([^`\n]{4,300})`")
_PROMPT_LINE = re.compile(r"(?m)^[ \t]*(?:\$|>|PS[^>\n]{0,40}>)\s+(.+)$")
_SHELLY = re.compile(r"^\s*(?:sudo\s+)?(?:(?:curl|wget|npm|npx|pnpm|yarn|bun|bunx|pip[0-9.]*|uv|uvx|pipx|poetry|cargo|go|gem|brew|"
                     r"apt|powershell|pwsh|iwr|irm|iex|mshta|bash|sh|zsh|python[0-9.]*|node|deno|docker|git|chmod|xattr|export|"
                     r"set|setx|claude|codex|gemini|cursor-agent|openclaw|make)(?=\s|$)|\./)", re.I)


def commands_in_markdown(text: str) -> list[tuple[int, str]]:
    """(line, command) for shell-like commands in fenced blocks, prompt lines and inline code."""
    out = []
    for m in _FENCE.finditer(text):
        lang = m.group(2).lower()
        if lang and lang not in ("sh", "bash", "shell", "zsh", "console", "terminal", "powershell", "ps1", "pwsh", "cmd",
                                 "bat", "shellsession", "text", "txt"):
            continue
        start = text.count("\n", 0, m.start(3)) + 1
        body = re.sub(r"\\\n\s*", " ", m.group(3))
        for i, line in enumerate(body.splitlines()):
            line = re.sub(r"^\s*(?:\$|>|PS[^>]{0,40}>)\s+", "", line)
            if line.strip() and not line.lstrip().startswith("#"):
                out.append((start + i, line.strip()))
    for m in _PROMPT_LINE.finditer(text):
        out.append((text.count("\n", 0, m.start()) + 1, m.group(1).strip()))
    for m in _INLINE.finditer(text):
        if _SHELLY.match(m.group(1)):
            out.append((text.count("\n", 0, m.start()) + 1, m.group(1).strip()))
    return out


_NEGATION = re.compile(r"\b(?:never|not|don'?t|doesn'?t|won'?t|cannot|can'?t|mustn'?t|shouldn'?t|avoid|refuse\s+to|no\s+longer"
                       r"|rather\s+than|instead\s+of)\b", re.I)
_AFFIRMATIVE = re.compile(r"\b(?:never|don'?t|do\s+not)\s+(?:forget|fail|hesitate|neglect|omit)\b", re.I)
_RESUMES = re.compile(r"\b(?:always|then|but|instead|however|must|should|please|now|first|and\s+also)\b", re.I)


def _negated(text: str, pos: int) -> bool:
    """True when the matched instruction is forbidden in its own sentence ("Never A, B or disable the sandbox"), but not
    for "never forget to disable the sandbox" or "never run untrusted code, then disable the sandbox", which are orders."""
    start = max(text.rfind(c, 0, pos) for c in ".!?\n:;")
    before = text[start + 1:pos]
    negations = list(_NEGATION.finditer(before))
    if not negations or _AFFIRMATIVE.search(before):
        return False
    return not _RESUMES.search(before[negations[-1].end():])


def instructions(state: State, f: File, auto_loaded: bool) -> None:
    """Instruction files agents load automatically, and setup docs people and agents follow."""
    text = f.text or ""
    lines = Lines(text)
    if auto_loaded:
        state.doc_auto.add(f.rel)
    seen = set()
    for line, cmd in commands_in_markdown(text):
        if (line, cmd) in seen:
            continue
        seen.add((line, cmd))
        for ref in exec_refs_in_command(cmd, f.dir, state.files) + exec_refs_in_command(cmd, "", state.files):
            state.mark_autoexec(ref, f"run by the instructions in {f.rel}", source=f.rel)
        unpinned = unpinned_runner(cmd)
        if unpinned:
            # A name nobody has registered yet is a slopsquat waiting to happen; a well-known package is a pinning nit.
            sev = "medium" if auto_loaded and not well_known(*unpinned) else "low"
            state.add(R_UNPINNED_RUN, sev, f.rel, line, f"runs {unpinned[1]} without a pinned version", cmd, "doc")
        for finding in analyze_command(cmd, f.rel, line, "doc"):
            if auto_loaded and rank(finding.severity) >= rank("medium"):
                finding.severity = bump(finding.severity)
                finding.message += " (in a file agents load automatically)"
            elif auto_loaded and finding.rule == R_DOWNLOAD_EXEC and finding.severity == "low":
                finding.severity = "medium"
                finding.message += " (in a file agents load automatically)"
            state.findings.append(finding)
        for eco, name in names_in_command(cmd):
            state.packages.append((eco, name, f.rel, line, "doc"))
            hit = lookalike(name, eco)
            if hit:
                state.add(R_LOOKALIKE, lookalike_severity(hit[1], "auto-doc" if auto_loaded else "doc"), f.rel, line,
                          f"{name} ({eco}) {hit[1]} from {hit[0]}", cmd, "doc")
    for pattern, sev, message in IMPERATIVES:
        for m in pattern.finditer(text):
            if _negated(text, m.start()):
                continue
            state.add(R_INSTRUCTION, sev if auto_loaded else "low", f.rel, lines.line(m.start()),
                      message + ("" if auto_loaded else " (setup document)"), text[max(0, m.start() - 60):m.end() + 80], "doc")
            break
    if f.name.upper() == "SKILL.MD":
        skill(state, f)


_UNPINNED = re.compile(r"\b(?P<npm>npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx)\s+(?P<npmargs>[^|;&\n]*)|\buvx\s+(?P<uvargs>[^|;&\n]*)"
                       r"|\bpipx\s+run\s+(?P<pipxargs>[^|;&\n]*)")
_RUNNER_FLAGS_WITH_VALUE = {"-p", "--package", "--from", "--with", "--python", "-c", "--call", "--spec", "--index-url"}
KNOWN_SCOPES = ("@anthropic-ai/", "@modelcontextprotocol/", "@openai/", "@google/", "@google-cloud/", "@microsoft/",
                "@azure/", "@aws-sdk/", "@playwright/", "@vercel/", "@cloudflare/", "@github/", "@octokit/", "@angular/",
                "@vue/", "@nestjs/", "@babel/", "@types/", "@eslint/", "@typescript-eslint/", "@biomejs/", "@sentry/",
                "@supabase/", "@stripe/", "@shopify/", "@nx/", "@storybook/", "@tanstack/", "@prisma/", "@redis/")


def unpinned_runner(cmd: str) -> tuple[str, str] | None:
    """(ecosystem, package) for npx/uvx/pipx runs of a package with no exact version, or None."""
    m = _UNPINNED.search(cmd)
    if not m:
        return None
    eco = "npm" if m.group("npm") else "pypi"
    args = (m.group("npmargs") or m.group("uvargs") or m.group("pipxargs") or "").split()
    skip = False
    for tok in args:
        tok = tok.strip("\"'`")
        if skip:
            skip = False
            if re.match(r"(?:\.{0,2}/|~|[A-Za-z]:[\\/]|https?:|git\+|file:)", tok):
                return None  # --from ./src/tool, --package git+https://...: not a bare registry name
            continue
        if tok.startswith("-"):
            skip = tok in _RUNNER_FLAGS_WITH_VALUE
            continue
        if re.match(r"(?:\.{0,2}/|~|[A-Za-z]:[\\/]|https?:|git\+|file:)", tok) or "$" in tok:
            return None  # a local path or a URL, not a registry package
        name, _, version = tok[1:].partition("@") if tok.startswith("@") else tok.partition("@")
        name = ("@" + name) if tok.startswith("@") else name
        if eco == "pypi":
            name, _, version = tok.partition("==")
        if version and re.match(r"\d", version):
            return None
        return (eco, name) if re.fullmatch(r"@?[\w.-]+(?:/[\w.-]+)?", name) else None
    return None


def well_known(eco: str, name: str) -> bool:
    """A popular package or one under a vendor's npm scope: it exists, so it cannot be a slopsquat."""
    return name.startswith(KNOWN_SCOPES) or normalize(name, eco) in popular(eco)


SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".rb", ".pl")


def skill(state: State, f: File) -> None:
    base = f.dir
    state.surface("Agent Skill", f.rel, "loaded by the agent when the skill applies")
    prefix = base + "/" if base else ""
    for rel in state.files:
        if rel.startswith(prefix) and rel.count("/") - prefix.count("/") <= 2 and rel.lower().endswith(SCRIPT_SUFFIXES):
            state.mark_autoexec(rel, f"script bundled with the skill {f.rel}")
    text = f.text or ""
    for m in re.finditer(r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest)\b[^\n]{0,200}?https?://\S+[^\n]{0,120}?"
                         r"(?:\.(?:zip|dmg|pkg|exe|bin|tar\.gz|tgz|sh|ps1)\b|[|]\s*(?:ba|z)?sh\b)", text, re.I):
        kind = host_kind(m.group(0))
        if kind == "official":
            continue
        # A skill is followed by the agent without a second look; a vendor's own installer is fine, a script from
        # someone's GitHub account is worth asking about, a look-alike domain or plain HTTP is not acceptable.
        sev = "high" if kind in ("risky", "plain-http") else "medium"
        state.add(R_SKILL_FETCH, sev, f.rel, text.count("\n", 0, m.start()) + 1, "skill downloads and runs a file"
                  + HOST_NOTE[kind], m.group(0), "doc")
        break


# ----------------------------------------------------------------------------------------- MCP servers

MCP_IMPORT = re.compile(r"@modelcontextprotocol/sdk|\bfrom\s+mcp(?:\.server)?\b|\bimport\s+mcp\b|\bfastmcp\b|\bFastMCP\b|McpServer\b")
DESCRIPTIONS = re.compile(r"(?s)(?:description\s*[:=]\s*|\.tool\(\s*['\"][\w-]+['\"]\s*,\s*)(?P<q>\"\"\"|'''|`|\"|')(?P<body>.{20,6000}?)(?P=q)"
                          r"|@(?:mcp|server|app)\.tool\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\([^)]*\)[^:]*:\s*(?P<dq>\"\"\"|''')(?P<doc>.{20,6000}?)(?P=dq)")
POISON = re.compile(r"<\s*/?\s*(?:IMPORTANT|instructions?|system|secret|hidden)\s*>|before\s+(?:using|calling)\s+this\s+tool|"
                    r"(?:pass|include|send|provide)\s+(?:its|the|their)?\s*(?:contents?|text|data)\s+(?:as|in)\s+(?:the\s+)?[\w\"'`]+\s*(?:parameter|argument|field)"
                    r"|do\s+not\s+(?:mention|tell|show|reveal)", re.I)


def mcp_server_code(state: State, f: File) -> None:
    text = f.text or ""
    if not MCP_IMPORT.search(text):
        return
    for m in DESCRIPTIONS.finditer(text):
        body = m.group("body") or m.group("doc") or ""
        reasons = []
        if POISON.search(body):
            reasons.append("hidden directives")
        if SECRET_PATHS.search(body):
            reasons.append("names credential files")
        if AI_ADDRESSED.search(body):
            reasons.append("addresses the model")
        if len(reasons) >= 1 and (SECRET_PATHS.search(body) or POISON.search(body)):
            state.add(R_TOOL_POISON, "critical" if len(reasons) >= 2 else "high", f.rel, text.count("\n", 0, m.start()) + 1,
                      "tool description " + ", ".join(reasons), body[:300], "code")


# ------------------------------------------------------------------------------------------ IDE and shell

TASK_TRIGGER = "opening the folder in VS Code or Cursor"
EXEC_SETTING = re.compile(r"(?:^|\.)(?:path|executablePath|serverPath|interpreterPath|defaultInterpreterPath|runtime|"
                          r"command|exePath|binPath|shellPath)$|^terminal\.integrated\.(?:profiles|shell|automationProfile)", re.I)


def vscode_tasks(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    for task in data.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = ((task.get("runOptions") or {}).get("runOn") or "").lower()
        cmds = [as_command(task)] + [as_command(task[os_]) for os_ in ("windows", "osx", "linux")
                                     if isinstance(task.get(os_), dict) and task[os_].get("command")]
        label = task.get("label") or task.get("taskName") or "task"
        for cmd in filter(None, cmds):
            line = line_of(f.text, str(task.get("command"))[:40]) if task.get("command") else 0
            if run_on == "folderopen":
                state.command(cmd, f.rel, line, f"folder-open task '{label}'", TASK_TRIGGER,
                              base_dir=posixpath.dirname(f.dir), floor=(R_FOLDER_OPEN, "high"))
            else:
                state.surface(f"task '{label}'", f.rel, "when you run the task", cmd, line)


def vscode_settings(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    checks = (("chat.tools.autoApprove", True), ("chat.tools.global.autoApprove", True),
              ("task.allowAutomaticTasks", "on"), ("security.workspace.trust.enabled", False),
              ("chat.agent.autoApprove", True), ("github.copilot.chat.agent.autoApprove", True))
    for key, bad in checks:
        if key in data and data[key] == bad:
            state.add(R_WEAK_SETTINGS, "high", f.rel, line_of(text, key), f"{key}: {json.dumps(bad)}", key)
    for key, value in data.items():
        if isinstance(value, str) and EXEC_SETTING.search(key):
            ref = refs_in_command(value, posixpath.dirname(f.dir), state.files)
            if ref:
                state.add(R_EXEC_SETTING, "high", f.rel, line_of(text, key), f"{key} runs {ref[0]}", f"{key}: {value}")
                state.mark_autoexec(ref[0], f"executable named in {f.rel}")
        elif isinstance(value, dict) and key.startswith("terminal.integrated.profiles"):
            for name, prof in value.items():
                if isinstance(prof, dict) and isinstance(prof.get("path"), str):
                    ref = refs_in_command(prof["path"], posixpath.dirname(f.dir), state.files)
                    if ref:
                        state.add(R_EXEC_SETTING, "high", f.rel, line_of(text, prof["path"]), f"terminal profile {name} runs {ref[0]}",
                                  prof["path"])
    mcp_config(state, f, "VS Code", "VS Code agent in this workspace")


DEV_LIFECYCLE = ("onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand")
SENSITIVE_MOUNT = re.compile(r"\.ssh|\.aws|\.config[\\/]gcloud|\.kube|\.docker|docker\.sock|^/,|^\$\{localEnv:(?:HOME|USERPROFILE)\}/?,"
                             r"|^~/?,|\.claude|\.codex|\.gemini|\.gnupg|\.netrc|\.npmrc|\.git-credentials", re.I)


def _host_mount_sources(data: dict) -> list[str]:
    """Host paths bind-mounted into the container. Named volumes (type=volume) live in Docker, not on the host."""
    out = []
    for mount in data.get("mounts") or []:
        if isinstance(mount, dict):
            if str(mount.get("type", "bind")).lower() != "volume" and mount.get("source"):
                out.append(str(mount["source"]))
        elif isinstance(mount, str):
            fields = dict(part.split("=", 1) for part in mount.split(",") if "=" in part)
            if fields.get("type", "bind").lower() != "volume" and (fields.get("source") or fields.get("src")):
                out.append(fields.get("source") or fields.get("src"))
    args = [str(a) for a in data.get("runArgs") or []]
    for i, arg in enumerate(args):
        value = None
        if arg in ("-v", "--volume", "--mount") and i + 1 < len(args):
            value = args[i + 1]
        elif arg.startswith(("-v=", "--volume=", "--mount=")):
            value = arg.split("=", 1)[1]
        if value is None:
            continue
        if "source=" in value or "src=" in value:
            fields = dict(part.split("=", 1) for part in value.split(",") if "=" in part)
            if fields.get("type", "bind").lower() != "volume":
                out.append(fields.get("source") or fields.get("src") or "")
        elif ":" in value and value.split(":", 1)[0].startswith(("/", "~", "$", ".")):
            out.append(value.split(":", 1)[0])
    return [src for src in out if src]


def devcontainer(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    if data.get("initializeCommand"):
        state.command(as_command(data["initializeCommand"]), f.rel, line_of(text, "initializeCommand"),
                      "dev container initializeCommand (host)", "opening the folder in a dev container",
                      base_dir=posixpath.dirname(f.dir) if f.dir.endswith(".devcontainer") else f.dir,
                      floor=(R_DEVCONTAINER_HOST, "high"))
    for key in DEV_LIFECYCLE:  # these run inside the container
        if data.get(key):
            cmd = as_command(data[key])
            state.surface(f"dev container {key} (inside the container)", f.rel, "dev container start", cmd, line_of(text, key))
            state.extend([x for x in analyze_command(cmd, f.rel, line_of(text, key), "autoexec")
                          if rank(x.severity) >= rank("high")])
    mounts = json.dumps(data.get("mounts") or []) + " " + json.dumps(data.get("runArgs") or [])
    host_sources = _host_mount_sources(data)
    sensitive = [src for src in host_sources if SENSITIVE_MOUNT.search(src + ",")]
    if sensitive:
        state.add(R_DEVCONTAINER_MOUNT, "high", f.rel, line_of(text, "mounts") or line_of(text, "runArgs"),
                  "mounts host credentials or the Docker socket: " + ", ".join(sensitive[:3]), mounts[:200])
    if re.search(r"--privileged|--pid=host|--net=host|--cap-add[= ](?:ALL|SYS_ADMIN)", mounts) or data.get("privileged"):
        state.add(R_DEVCONTAINER_MOUNT, "medium", f.rel, line_of(text, "privileged") or line_of(text, "runArgs"),
                  "privileged container", mounts[:200])


def envrc(state: State, f: File) -> None:
    state.surface(".envrc", f.rel, "entering the directory after `direnv allow`", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "direnv .envrc")
    state.add(R_ENVRC, "low", f.rel, 1, "runs on cd once allowed", (f.text or "")[:120])


def workflow(state: State, f: File) -> None:
    text = f.text or ""
    if re.search(r"(?m)^\s*(?:on:\s*\[?[^\n]*\bpull_request_target\b|pull_request_target\s*:)", text) and \
            re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/", text):
        # A risk to the repository's CI secrets, not to the machine of someone who clones it.
        state.add(R_CI_PRT, "low", f.rel, line_of(text, "pull_request_target"),
                  "pull_request_target checks out pull-request code", "pull_request_target", "config")


# ---------------------------------------------------------------------------------------------------- git


def gitmodules(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(url|path|update|branch)\s*=\s*(.*)$", text):
        key, value = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        if key == "url" and (value.startswith(("ext::", "-", "fd::")) or "--upload-pack" in value or "ProxyCommand" in value):
            state.add(R_GITMODULES, "critical", f.rel, line, f"submodule URL can run commands: {value}", value)
        elif key == "update" and value.strip().startswith("!"):
            state.add(R_GITMODULES, "critical", f.rel, line, f"custom submodule update command {value}", value)
        elif key == "path" and (re.search(r"[\r\x00-\x1f]", value) or value.startswith(("/", "..")) or "/.git" in value
                                or value.startswith(".git") or "\\" in value):
            state.add(R_GITMODULES, "high", f.rel, line, f"submodule path {value!r} escapes or targets .git", repr(value))
    if "[submodule" in text:
        state.surface("git submodules", f.rel, "git clone --recursive / git submodule update")


GIT_DANGEROUS = re.compile(r"(?mi)^\s*(fsmonitor|hookspath|sshcommand|pager|editor|askpass|helper|external|textconv|"
                           r"clean|smudge|process|packobjectshook|program|uploadpack|receivepack)\s*=\s*(.+)$")


def git_config(state: State, f: File) -> None:
    text = f.text or ""
    for m in GIT_DANGEROUS.finditer(text):
        key, value = m.group(1).lower(), m.group(2).strip()
        if key == "fsmonitor" and value.lower() in ("true", "false"):
            continue
        if value.startswith(("git-lfs ", "git lfs ")) or (key == "helper" and value in ("manager", "manager-core", "store",
                                                                                         "cache", "osxkeychain", "wincred")):
            continue
        sev = "high" if key in ("fsmonitor", "sshcommand", "packobjectshook", "uploadpack") else "medium"
        if key == "hookspath" and re.search(r"\.husky", value):
            sev = "low"
        state.add(R_GIT_CONFIG, sev, f.rel, text.count("\n", 0, m.start()) + 1, f"{key} = {value}", m.group(0))
    for m in re.finditer(r"(?m)^\s*(\w[\w-]*)\s*=\s*!(.+)$", text):
        state.add(R_GIT_CONFIG, "medium", f.rel, text.count("\n", 0, m.start()) + 1, f"alias {m.group(1)} runs a shell "
                  "command", m.group(0))


def git_hook(state: State, f: File) -> None:
    if f.name.endswith(".sample"):
        return
    state.surface("git hook", f.rel, "git commit / checkout / push in this repository", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "git hook")
    state.add(R_GIT_HOOKS, "high", f.rel, 1, "hook file present in .git/hooks", f.rel)


def git_indirection(state: State, f: File) -> None:
    target = (f.text or "").strip().removeprefix("gitdir:").strip()
    state.add(R_WORKTREE, "high", f.rel, 1, f"{f.name} points to {target}", target)


# ---------------------------------------------------------------------------------------------- dispatch


def dispatch(state: State, f: File) -> None:
    """Run every handler that applies to this file."""
    rel, low, name = f.rel, f.rel.lower(), f.name.lower()
    if f.text is None:
        return
    if re.search(r"(?:^|/)\.claude/settings(?:\.local)?\.json$", low):
        claude_settings(state, f)
    elif low.endswith(".mcp.json") or re.search(r"(?:^|/)(?:\.cursor|\.roo|\.amazonq|\.kiro/settings)/mcp\.json$", low) \
            or name in ("claude_desktop_config.json", "cline_mcp_settings.json", "mcp_config.json"):
        mcp_config(state, f, "MCP", "agent session in this folder (approval prompt in interactive mode)")
    elif re.search(r"(?:^|/)\.cursor/hooks\.json$", low):
        cursor_hooks(state, f)
    elif re.search(r"(?:^|/)\.codex/config\.toml$", low):
        codex_config(state, f)
    elif re.search(r"(?:^|/)\.gemini/settings\.json$", low):
        gemini_settings(state, f)
    elif re.search(r"(?:^|/)\.vscode/tasks\.json$", low):
        vscode_tasks(state, f)
    elif re.search(r"(?:^|/)\.vscode/settings\.json$", low):
        vscode_settings(state, f)
    elif re.search(r"(?:^|/)\.vscode/mcp\.json$", low):
        mcp_config(state, f, "VS Code", "VS Code agent in this workspace")
    elif re.search(r"(?:^|/)\.zed/(?:settings|tasks)\.json$", low):
        generic_agent_json(state, f, "Zed", "Zed in this workspace")
    elif re.search(r"(?:^|/)\.continue/(?:config|mcpServers/).*\.(?:json|ya?ml)$", low):
        generic_agent_json(state, f, "Continue", "Continue in this workspace")
    elif re.search(r"(?:^|/)\.devcontainer(?:/[^/]+)?/devcontainer\.json$|(?:^|/)\.devcontainer\.json$", low):
        devcontainer(state, f)
    elif re.search(r"(?:^|/)\.aider\.conf\.ya?ml$", low):
        aider_conf(state, f)
    elif name == ".envrc":
        envrc(state, f)
    elif re.fullmatch(r"\.env(?:\.[\w.-]+)?", name) and not name.endswith((".example", ".sample", ".template", ".dist")):
        dotenv(state, f)
    elif re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", low):
        workflow(state, f)
    elif name == ".gitmodules":
        gitmodules(state, f)
    elif re.search(r"(?:^|/)\.git/config$", low) or name == ".lfsconfig":
        git_config(state, f)
    elif re.search(r"(?:^|/)\.git/hooks/[^/]+$", low):
        git_hook(state, f)
    elif re.search(r"(?:^|/)\.git/(?:commondir|gitdir)$|(?:^|/)\.git/worktrees/[^/]+/gitdir$", low) or \
            (name == ".git" and (f.text or "").startswith("gitdir:") and ".." in (f.text or "")):
        git_indirection(state, f)
    if re.search(r"(?:^|/)\.openclaw/extensions/", low):
        openclaw_extension(state, f)
    if AUTO_LOADED.search(rel):
        instructions(state, f, auto_loaded=True)
    elif SETUP_DOC.search(rel) and low.endswith((".md", ".rst", ".txt", ".markdown")) or re.fullmatch(r"readme(?:\.[a-z]+)?", name):
        instructions(state, f, auto_loaded=False)
    if low.endswith((".js", ".ts", ".mjs", ".cjs", ".py")) and "node_modules/" not in low:
        mcp_server_code(state, f)
