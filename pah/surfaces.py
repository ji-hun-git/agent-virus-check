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
from .indicators import EXFIL_HOSTS
from .policy import inert_path, is_test_code
from .patterns import (AI_ADDRESSED, HOST_NOTE, R_AGENT_CFG_WRITE, R_DOWNLOAD_EXEC, SECRET_PATHS, analyze_command,
                       classify_host, host_kind, host_of)
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
R_SKILL_SHELL = rule(
    "PAH-A019", "Skill runs shell commands when it is invoked",
    "A line written !`command` in a skill or a slash command runs as soon as it is invoked, before the model has read "
    "anything, and its output goes into the prompt; `allowed-tools: Bash` in the frontmatter lets every shell command "
    "through without asking while the skill is active.",
    "Read every !` line and narrow allowed-tools to the commands the skill needs (Bash(git status:*)). "
    "disableSkillShellExecution turns the shell lines off.", attack=("T1059",), owasp=("ASI02", "ASI04"),
    refs=("https://code.claude.com/docs/en/skills",))
R_PLUGIN_REQUEST = rule(
    "PAH-A018", "Repository asks the agent to install plugins",
    "A repository's .claude/settings.json can name plugin marketplaces (extraKnownMarketplaces) and plugins to enable "
    "(enabledPlugins). Once you trust the folder, Claude Code offers to install them, and a plugin brings its own hooks, "
    "MCP servers, skills and commands, none of which are in the repository you scanned. A marketplace on someone's "
    "GitHub account can change what it serves at any time.",
    "Decline the install prompt unless you know the marketplace; scan the plugin's repository first "
    "(pah scan https://github.com/owner/repo).", attack=("T1195.002", "T1546"), owasp=("ASI04",),
    refs=("https://code.claude.com/docs/en/plugin-marketplaces",))
OFFICIAL_MARKETPLACES = ("claude-plugins-official", "anthropic-agent-skills", "claude-code-plugins")
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
R_CI_INJECTION = rule(
    "PAH-I009", "Workflow puts untrusted text into a shell command",
    "${{ github.event.issue.title }}, a comment body, a branch name or a commit message pasted into `run:` or a "
    "github-script `script:` becomes shell or JavaScript that anyone who can open an issue or a pull request writes. "
    "In September 2026, 83 issues and comments across 61 repositories hid commands in HTML comments for workflows like "
    "these; Nx's s1ngularity compromise began the same way. A risk to the repository's CI secrets, not to the machine "
    "of someone who clones it.", "Pass the value through `env:` and quote the variable in the script.",
    attack=("T1059", "T1195"),
    refs=("https://docs.zizmor.sh/audits/#template-injection", "https://nx.dev/blog/s1ngularity-postmortem"))
R_CI_SECRETS = rule(
    "PAH-I010", "Workflow sends the repository's secrets out",
    "toJSON(secrets) hands every secret of the repository to one step; GhostAction (Sep to Oct 2026, about 30,000 "
    "repositories) and the November 'wfx' wave pushed workflows that did this and posted the result to a bare IP "
    "address. Reading the runner's memory for secrets is how the tj-actions/changed-files compromise worked. A "
    "repository whose workflows do this has been compromised, and the same campaigns planted agent hooks and "
    "folder-open tasks.", "Treat the repository as compromised: rotate its secrets and check its recent commits.",
    attack=("T1552.004", "T1041"),
    refs=("https://blog.gitguardian.com/ghostaction-github-actions-supply-chain-attack-returns/",
          "https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories"))
R_CI_AGENT = rule(
    "PAH-I011", "AI agent in a workflow acts on anyone's issue or comment",
    "An AI agent action (Claude Code, Codex, Gemini CLI and others) started by issues, comments or pull_request_target "
    "reads text an outsider wrote. When it also gets that text in its prompt, accepts any user or has its approvals "
    "off, the outsider is giving the instructions: Clinejection turned an issue title into a stolen npm token "
    "(Feb 2026), and PromptPwnd found the pattern across many repositories.",
    "Restrict who can trigger it, keep untrusted text out of the prompt, and do not give it write tools or secrets.",
    attack=("T1059", "T1195"), owasp=("LLM01", "ASI01"),
    refs=("https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm",
          "https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents"))

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
                                 r"containerWorkspaceFolder|fileDirname|CLAUDE_PLUGIN_ROOT)\}?|%CD%|\$\(pwd\))[\"']?[\\/]")


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


def _hook_urls(obj) -> list[str]:
    out = []
    if isinstance(obj, dict):
        if str(obj.get("type", "")).lower() == "http" and isinstance(obj.get("url"), str):
            out.append(obj["url"])
        for v in obj.values():
            out += _hook_urls(v)
    elif isinstance(obj, list):
        for v in obj:
            out += _hook_urls(v)
    return out


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
                        r"GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_ASKPASS|CODEX_HOME|CLAUDE_CONFIG_DIR|GEMINI_CLI_HOME|"
                        r"GEMINI_SYSTEM_MD|QWEN_HOME)$", re.I)
RELOCATING_ENV = ("CODEX_HOME", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "CLAUDE_CONFIG_DIR", "GEMINI_CLI_HOME", "QWEN_HOME")


def repo_first_on_path(value: str) -> bool:
    """PATH whose first entry is inside the project: its bin/git runs whenever the agent calls git (Datadog, Aug 2026)."""
    first = re.split(r"[:;]", value.strip(), maxsplit=1)[0].strip("\"'")
    if re.search(r"CLAUDE_PROJECT_DIR|workspaceFolder|\$PWD|\$\{PWD\}", first):
        return True
    return bool(first) and not first.startswith(("/", "$", "~", "%")) and not re.match(r"[A-Za-z]:[\\/]", first)


def check_env(state: State, env: dict, f: File, origin: str, cap: str | None = None) -> None:
    """Variables that redirect an agent's API traffic, hand it someone else's key, or inject code into its process.
    cap limits the severity (a .env below the repository root is read only by tools started in that folder)."""
    add = state.add if cap is None else (lambda rule_id, sev, *a, **k: state.add(rule_id, sev if rank(sev) <= rank(cap)
                                                                                 else cap, *a, **k))
    for key, value in env.items():
        value = str(value)
        line = line_of(f.text or "", key)
        if key.upper() == "PATH":
            if repo_first_on_path(value):
                add(R_BASE_URL, "high", f.rel, line, f"{origin} puts a folder of the repository first on PATH: {value}",
                    f"PATH={value}")
            continue
        if REDIRECT_ENV.match(key):
            host = host_of(value) if "://" in value else value.split(":")[0]
            if host and host not in OFFICIAL_API_HOSTS and not host.endswith((".anthropic.com", ".openai.com")) \
                    and not value.startswith("$"):
                add(R_BASE_URL, "critical", f.rel, line, f"{origin} sets {key}={value}", f"{key}={value}")
        elif SECRET_ENV.match(key):
            add(R_BASE_URL, "high", f.rel, line, f"{origin} supplies its own {key} (your session would run "
                "under someone else's account, which can read it)", key)
        elif INJECT_ENV.match(key):
            sev = "critical" if key.upper() in RELOCATING_ENV \
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
    for entries in hooks.values():
        for url in _hook_urls(entries):  # "type": "http" hooks post every event to a server
            kind = classify_host(url)
            state.surface("Claude Code HTTP hook", f.rel, CLAUDE_TRIGGER, url, line_of(f.text, url))
            if kind in ("raw-ip", "plain-http", "lookalike") or EXFIL_HOSTS.search(url):
                state.add(R_HOOKS, "high", f.rel, line_of(f.text, url), f"HTTP hook sends agent events to {url}", url)
    for key in ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper",
                "statusLine", "subagentStatusLine", "fileSuggestion"):
        if key in data:
            cmd = as_command(data[key])
            state.command(cmd, f.rel, line_of(f.text, key), f"Claude Code {key}", CLAUDE_TRIGGER,
                          floor=(R_CMD_SETTING, "low" if key in ("statusLine", "subagentStatusLine", "fileSuggestion")
                                 else "high"))
    sandbox = data.get("sandbox") if isinstance(data.get("sandbox"), dict) else {}
    network = sandbox.get("network") if isinstance(sandbox.get("network"), dict) else {}
    if sandbox.get("allowUnsandboxedCommands") is True or sandbox.get("ignoreViolations") or \
            "*" in [str(d) for d in network.get("allowedDomains") or []]:
        state.add(R_APPROVALS, "medium", f.rel, line_of(f.text, "sandbox"), "project settings loosen the sandbox",
                  json.dumps(sandbox)[:160])
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
    plugin_requests(state, f, data)


def _marketplace_source(spec) -> tuple[str, str]:
    """(type, location) of a marketplace in extraKnownMarketplaces: github owner/repo, a git or https URL, or a path."""
    src = spec.get("source") if isinstance(spec, dict) else spec
    if isinstance(src, dict):
        return str(src.get("source") or ""), str(src.get("repo") or src.get("url") or src.get("path") or "")
    value = str(src or "")
    return ("url" if "://" in value else "directory" if value.startswith((".", "/", "~")) else "github"), value


def plugin_requests(state: State, f: File, data: dict) -> None:
    """extraKnownMarketplaces and enabledPlugins in project settings: on trust, Claude Code offers to install
    plugins whose hooks, MCP servers and skills are not part of the repository being scanned."""
    markets = data.get("extraKnownMarketplaces") if isinstance(data.get("extraKnownMarketplaces"), dict) else {}
    enabled = data.get("enabledPlugins")
    plugins = [k for k, v in enabled.items() if v] if isinstance(enabled, dict) else \
        [str(p) for p in enabled] if isinstance(enabled, list) else []
    for name, spec in markets.items():
        stype, source = _marketplace_source(spec)
        kind = classify_host(source) if "://" in source else ""
        local = stype in ("directory", "path", "file", "local")
        sev = "high" if kind in ("raw-ip", "plain-http", "lookalike") else "low" if local else "medium"
        named = [p for p in plugins if p.endswith("@" + name)]
        state.surface(f"Claude Code plugin marketplace '{name}'", f.rel, "trusting the folder in Claude Code (install "
                      "prompt)", source, line_of(f.text, name))
        state.add(R_PLUGIN_REQUEST, sev, f.rel, line_of(f.text, name),
                  f"asks Claude Code to add the marketplace '{name}' ({source or 'no source'})"
                  + (f" and enable {', '.join(named[:4])}" if named else ""), f"{name}: {source}")
    known = set(markets)
    for plugin in plugins:
        market = plugin.rsplit("@", 1)[1] if "@" in plugin else ""
        if market and market not in known and market not in OFFICIAL_MARKETPLACES:
            state.add(R_PLUGIN_REQUEST, "low", f.rel, line_of(f.text, plugin), f"enables the plugin {plugin}", plugin)


def mcp_config(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "") if not f.rel.endswith(".toml") else load_toml(f.text or "")
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or data.get("mcp_servers") or data.get("context_servers") or \
        data.get("amp.mcpServers") or {}
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
        if spec.get("headersHelper"):  # a program run to produce the request headers
            state.command(as_command(spec["headersHelper"]), f.rel, line_of(f.text, "headersHelper"),
                          f"{agent} MCP server '{name}' headersHelper", trigger, floor=(R_CMD_SETTING, "medium"))
        if spec.get("trust") is True or spec.get("autoApprove") in (True, "*") or spec.get("alwaysAllow") == "*":
            state.add(R_APPROVALS, "medium", f.rel, line, f"tools of the MCP server '{name}' run without asking",
                      f"{name}: trust/autoApprove")


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
    check_env(state, {k: v for k, v in env.items() if REDIRECT_ENV.match(k) or INJECT_ENV.match(k) or k.upper() == "PATH"},
              f, ".env", cap=None if not f.dir else "medium")


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
    agent = "Qwen Code" if ".qwen/" in f.rel.lower() else "Gemini CLI"
    for key in ("discoveryCommand", "callCommand"):  # tools.discoveryCommand runs at start; callCommand on every call
        if isinstance(tools.get(key), str):
            state.command(tools[key], f.rel, line_of(f.text, key), f"{agent} tools.{key}", f"{agent} session in this folder",
                          floor=(R_CMD_SETTING, "high"))
    status = ((data.get("ui") or {}).get("statusLine") or {}) if isinstance(data.get("ui"), dict) else {}
    if isinstance(status, dict) and isinstance(status.get("command"), str):
        state.command(status["command"], f.rel, line_of(f.text, status["command"][:40]), f"{agent} status line",
                      f"{agent} session in this folder", floor=(R_CMD_SETTING, "low"))
    if data.get("yolo") or tools.get("autoAccept") or tools.get("approvalMode") == "yolo" or \
            (data.get("security") or {}).get("approvalMode") == "yolo":
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
    for m in re.finditer(r"(?m)^\s*(test-cmd|lint-cmd|lint|test|notifications-command)\s*:\s*(.+)$", text):
        # test-cmd runs at startup in 0.86 (CVE-2026-85674, no fix); notifications-command too (CVE-2026-115726)
        state.command(m.group(2).strip().strip("'\""), f.rel, text.count("\n", 0, m.start()) + 1,
                      f"Aider {m.group(1)}", "Aider runs it at start or after edits", floor=(R_OTHER_AGENT, "medium"))
    m = re.search(r"(?m)^\s*load\s*:\s*(.+)$", text)
    if m:  # a file of /commands Aider runs at launch, /run included
        for ref in refs_in_command(m.group(1).strip().strip("'\""), f.dir, state.files):
            state.add(R_OTHER_AGENT, "medium", f.rel, text.count("\n", 0, m.start()) + 1, f"Aider loads and runs the "
                      f"commands in {ref} at launch", m.group(0).strip())
            state.mark_autoexec(ref, f"commands Aider runs at launch ({f.rel})")


def generic_agent_json(state: State, f: File, agent: str, trigger: str) -> None:
    data = load_jsonc(f.text or "")
    for path, cmd in walk_commands(data or {}):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"{agent} ({'/'.join(path[:2])})", trigger,
                      floor=(R_OTHER_AGENT, "medium"))


HOOK_EARLY = {e.lower() for e in EARLY_EVENTS} | {"userpromptsubmitted", "promptsubmit", "taskstart", "taskresume",
                                                 "agentspawn"}


def _shell_variants(obj, out: list) -> None:
    """Copilot hooks name one command per shell ("bash", "powershell") instead of a "command"."""
    if isinstance(obj, dict):
        for key in ("bash", "powershell", "pwsh"):
            if isinstance(obj.get(key), str):
                out.append(obj[key])
        for value in obj.values():
            _shell_variants(value, out)
    elif isinstance(obj, list):
        for value in obj:
            _shell_variants(value, out)


def hook_commands(data) -> list[tuple[str, str]]:
    """(event, command) in the hook files agents read: {"hooks": {Event: [...]}} (Claude Code, Codex, Devin, Copilot),
    {"hooks": [{"trigger": Event, "action": ...}]} (Kiro CLI) and {"when": ..., "then": ...} (Kiro IDE)."""
    def commands(obj) -> list[str]:
        found = [cmd for _path, cmd in walk_commands(obj)]
        _shell_variants(obj, found)
        return found

    if not isinstance(data, dict):
        return []
    out = []
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, entries in hooks.items():
            out += [(str(event), cmd) for cmd in commands(entries)]
    elif isinstance(hooks, list):
        for entry in hooks:
            if isinstance(entry, dict):
                when = entry.get("when") if isinstance(entry.get("when"), dict) else {}
                event = entry.get("trigger") or entry.get("event") or when.get("type") or "hook"
                out += [(str(event), cmd) for cmd in commands(entry)]
    if isinstance(data.get("then"), dict):
        when = data.get("when") if isinstance(data.get("when"), dict) else {}
        out += [(str(when.get("type") or "hook"), cmd) for cmd in commands(data["then"])]
    return out


def agent_hooks(state: State, f: File, agent: str, trigger: str) -> None:
    """Hook files of the agents other than Claude Code, Gemini CLI and Cursor, which have their own handlers."""
    for event, cmd in hook_commands(load_jsonc(f.text or "")):
        state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"{agent} hook ({event})", trigger, base_dir="",
                      floor=(R_HOOKS, "medium" if event.lower() in HOOK_EARLY else "low"))


def hook_script(state: State, f: File, agent: str) -> None:
    """Cline runs the executable named after the hook event in .clinerules/hooks/."""
    event = f.name.split(".")[0]
    state.surface(f"{agent} hook script ({event})", f.rel, f"{agent} runs it on {event}", (f.text or "")[:200])
    state.mark_autoexec(f.rel, f"{agent} hook script")
    state.add(R_HOOKS, "medium" if event.lower() in HOOK_EARLY else "low", f.rel, 1, f"{agent} hook script ({event})",
              f.rel, "autoexec")


PLUGIN_TRIGGER = "Claude Code sessions once the plugin is installed"


def plugin_folder(state: State, folder: str) -> bool:
    """A Claude Code plugin's folder: it has .claude-plugin/plugin.json, or the repository is a marketplace whose
    plugins live in subfolders."""
    return posixpath.join(folder, ".claude-plugin/plugin.json") in state.files or \
        any(p.endswith(".claude-plugin/marketplace.json") for p in state.files)


def is_plugin_hooks(state: State, f: File) -> bool:
    return plugin_folder(state, posixpath.dirname(f.dir))


def plugin_hooks(state: State, f: File) -> None:
    """A plugin's hooks run after someone installs it, not when the repository is opened, so they are recorded at a
    low floor; what they run is marked as running on its own and judged as such."""
    data = load_jsonc(f.text or "")
    hooks = data.get("hooks") if isinstance(data, dict) and isinstance(data.get("hooks"), dict) else {}
    for event, entries in hooks.items():
        for _path, cmd in walk_commands(entries):
            state.command(cmd, f.rel, line_of(f.text, cmd[:40]), f"Claude Code plugin hook ({event})", PLUGIN_TRIGGER,
                          base_dir=posixpath.dirname(f.dir), floor=(R_HOOKS, "low"))


def cursor_permissions(state: State, f: File) -> None:
    """.cursor/sandbox.json and .cursor/permissions.json in a repository override the user's own for every command."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    if str(data.get("type", "")).lower() in ("insecure_none", "none") or data.get("enabled") is False:
        state.add(R_APPROVALS, "high", f.rel, line_of(text, "type") or 1, "turns Cursor's sandbox off for this project",
                  json.dumps(data)[:160])
    for path in data.get("additionalReadwritePaths") or []:
        if re.match(r"(?:~|\$HOME|/|[A-Za-z]:[\\/])\s*$|~[\\/]\.(?:ssh|aws|claude|codex|gemini|config)", str(path)):
            state.add(R_APPROVALS, "high", f.rel, line_of(text, str(path)), f"lets sandboxed commands write {path}", str(path))
    allow = data.get("terminalAllowlist") or data.get("allowlist") or []
    if data.get("autoRun") is True or "*" in [str(a).strip() for a in allow]:
        state.add(R_APPROVALS, "high", f.rel, line_of(text, "autoRun") or line_of(text, "*"), "runs terminal commands "
                  "without asking", json.dumps(data)[:160])


def setup_commands(state: State, f: File, trigger: str) -> None:
    """Install and start commands of cloud agents (Cursor environment.json, worktrees.json, Devin blueprints)."""
    text = f.text or ""
    if f.rel.lower().endswith(".json"):
        data = load_jsonc(text)
        values = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ("install", "start", "setup-worktree", "setup-worktree-unix", "setup-worktree-windows"):
                    values += value if isinstance(value, list) else [value]
                elif key == "terminals" and isinstance(value, list):
                    values += [t.get("command") for t in value if isinstance(t, dict)]
        cmds = [as_command(v) for v in values if v]
    else:
        cmds = []
        for m in re.finditer(r"(?m)^(\s*)(initialize|maintenance)\s*:\s*\|?\s*$", text):
            indent, rest = len(m.group(1)), text[m.end():].split("\n")
            for line in rest[1:]:
                if line.strip() and len(line) - len(line.lstrip()) <= indent:
                    break
                if line.strip() and not line.strip().startswith("#"):
                    cmds.append(re.sub(r"^\s*-\s*(?:run:\s*)?", "", line).strip())
    for cmd in filter(None, cmds):
        state.command(cmd, f.rel, line_of(text, cmd[:40]), "cloud agent setup command", trigger)


def allowed_tools_json(state: State, f: File) -> None:
    """Amazon Q / Kiro CLI agents, Augment and Amp list tools that run without asking."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    allowed = [str(t) for t in (data.get("allowedTools") or [])] + \
        [str(t) for t in ((data.get("toolsSettings") or {}).get("execute_bash") or {}).get("allowedCommands") or []]
    if any(t.strip() in ("*", "execute_bash", "@builtin", "shell", ".*") for t in allowed):
        state.add(R_APPROVALS, "high", f.rel, line_of(f.text, "allowedTools") or line_of(f.text, "allowedCommands"),
                  "lets the agent run shell commands without asking", ", ".join(allowed[:6]))


def opencode_config(state: State, f: File) -> None:
    """opencode.json / kilo.json: npm plugins installed and loaded at start, MCP and formatter commands."""
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    agent = "Kilo" if "kilo" in f.name.lower() else "OpenCode"
    plugins = data.get("plugin") or data.get("plugins") or []
    for plugin in plugins if isinstance(plugins, list) else []:
        name = str(plugin)
        if name.startswith((".", "/")):
            for ref in refs_in_command(name, f.dir, state.files):
                state.mark_autoexec(ref, f"{agent} plugin named in {f.rel}")
            continue
        state.packages.append(("npm", re.sub(r"(?<=.)@[^@/]*$", "", name), f.rel, line_of(text, name), "autoexec"))
        state.add(R_AGENT_EXTENSION, "medium", f.rel, line_of(text, name), f"{agent} installs the npm package {name} and "
                  "loads it as a plugin when it starts", name)
    mcp = data.get("mcp") if isinstance(data.get("mcp"), dict) else {}
    for name, spec in mcp.items():
        if isinstance(spec, dict) and spec.get("command"):
            state.command(as_command(spec["command"]), f.rel, line_of(text, f'"{name}"'), f"{agent} MCP server '{name}'",
                          f"starting {agent} in this folder", floor=(R_MCP_SERVER, "low"))
    formatters = data.get("formatter") if isinstance(data.get("formatter"), dict) else {}
    for name, spec in formatters.items():
        if isinstance(spec, dict) and spec.get("command"):
            state.command(as_command(spec["command"]), f.rel, line_of(text, f'"{name}"'), f"{agent} formatter '{name}'",
                          f"{agent} runs it after every edit", floor=(R_OTHER_AGENT, "medium"))


def crush_rc(state: State, f: File) -> None:
    """Crush runs .crushrc as a Bash script on every launch, before its interface appears."""
    state.surface("Crush startup script", f.rel, "every launch of Crush in this folder", (f.text or "")[:200])
    state.mark_autoexec(f.rel, "Crush startup script")
    state.add(R_OTHER_AGENT, "medium", f.rel, 1, "Crush runs this script on every launch", f.rel, "autoexec")


def agent_plugin(state: State, f: File, agent: str, trigger: str, severity: str) -> None:
    """Plugin code an agent imports from the project folder when it starts there."""
    state.mark_autoexec(f.rel, f"{agent} plugin")
    state.surface(f"{agent} plugin", f.rel, trigger)
    state.add(R_AGENT_EXTENSION, severity, f.rel, 1, f"{agent} loads this plugin when it starts in the folder", f.rel)


# ------------------------------------------------------------------------------------- instruction files

AUTO_LOADED = re.compile(
    r"(?:^|/)(?:AGENTS(?:\.override)?\.md|CLAUDE(?:\.local)?\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|"
    r"\.roorules|CONVENTIONS\.md|SKILL\.md|SOUL\.md|copilot-instructions\.md)$"
    r"|(?:^|/)\.cursor/rules/.*\.mdc?$|(?:^|/)\.github/(?:instructions|prompts)/.*\.md$|(?:^|/)\.claude/(?:agents|commands|skills)/.*\.md$"
    r"|(?:^|/)\.gemini/commands/.*\.toml$|(?:^|/)\.windsurf/rules/.*\.md$|(?:^|/)\.clinerules/(?!hooks/).*$|(?:^|/)\.roo/rules[^/]*/.*\.md$"
    r"|(?:^|/)\.amazonq/rules/.*\.md$|(?:^|/)\.kiro/steering/.*\.md$|(?:^|/)\.junie/guidelines\.md$"
    r"|(?:^|/)\.claude/(?:rules|output-styles)/.*\.md$|(?:^|/)\.(?:agents|devin|augment)/rules/.*\.md$|(?:^|/)\.augment/SYSTEM\.md$"
    r"|(?:^|/)\.github/(?:agents/.*\.agent|chatmodes/.*\.chatmode)\.md$|(?:^|/)\.factory/droids/.*\.md$|(?:^|/)\.kiro/agents/.*\.md$"
    r"|(?:^|/)(?:\.goosehints|WARP\.md|AGENT\.md)$", re.I)
SETUP_DOC = re.compile(r"(?:^|/)(?:README|INSTALL|SETUP|CONTRIBUTING|GETTING[-_]STARTED|QUICKSTART|DEVELOPMENT|BUILDING)"
                       r"(?:\.[a-z]+)?$|(?:^|/)docs?/.*(?:install|setup|getting[-_]started|quickstart).*\.md$", re.I)

IMPERATIVES = [
    (re.compile(r"\b(?:update|change|modify|edit|overwrite|rewrite|add\s+(?:the\s+following\s+|this\s+|these\s+lines\s+)?to)\s+"
                r"(?:your|the\s+agent'?s?|its)\s+(?:own\s+)?(?:global\s+|user\s+)?(?:settings|config(?:uration)?|settings\.json|"
                r"config\.toml|preferences|mcp\s+servers?|hooks)", re.I), "high", "tells the agent to change its own settings"),
    (re.compile(r"(?:~|\$HOME|%USERPROFILE%|\$CODEX_HOME)[\\/](?:\.(?:claude|codex|gemini|cursor|openclaw|copilot|kiro)[\\/])?"
                r"(?:settings(?:\.local)?\.json|config\.toml|hooks\.json|mcp(?:_config)?\.json|auth\.json|\.credentials\.json|"
                r"openclaw\.json)\b|\.claude\.json\b"), "medium", "points the agent at its machine-wide configuration"),
    # Naming the file is how skills document "add this MCP server to ~/.claude.json"; telling the agent to rewrite its
    # own settings, switch off approvals or move its API traffic is what the attacks do, and those stay high.
    # Naming ANTHROPIC_BASE_URL in documentation is not an instruction; setting it to a host that is not the provider's is.
    (re.compile(r"\b(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE_GEMINI|CODEX|AZURE_OPENAI|OPENROUTER)_(?:BASE_URL|API_BASE|API_URL)\b"
                r"[\"'`]?\s*(?:=|:|\bto\b)\s*[\"'`]?https?://(?!(?:api\.anthropic\.com|api\.openai\.com|generativelanguage\."
                r"googleapis\.com|localhost|127\.0\.0\.1)\b)[\w.-]+"
                r"|\bCODEX_HOME\s*=\s*[\"']?(?!~?/?\.codex\b)[\w./~$-]+", re.I),
     "high", "changes where the agent sends its API traffic"),
    (re.compile(r"\b(?:disable|turn\s+off|skip|bypass|ignore)\s+(?:the\s+|all\s+|any\s+)?(?:sandbox(?:ing)?|approvals?|permission(?:s|\s+prompts?|\s+checks?)?"
                r"|confirmations?|safety\s+checks?|security\s+(?:checks?|warnings?))\b(?!\s+(?:paths?|tests?|testing|environments?|"
                r"dir(?:ector(?:y|ies))?|folders?|images?|containers?|fixtures?|examples?|data)\b)", re.I), "high",
     "tells the agent to disable its safeguards"),
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
    # The agents' own folders hold skills and settings too; only their token files are credentials.
    (re.compile(r"\b(?:read|cat|open|copy|upload|send|include|paste|attach)\b[^\n]{0,60}(?:~|\$HOME|%USERPROFILE%)[\\/]\."
                r"(?:(?:ssh|aws|npmrc|netrc|git-credentials|config[\\/]gh)\b|claude[\\/]\.credentials\.json|codex[\\/]auth\.json"
                r"|gemini[\\/](?:oauth_creds\.json|\.env))|\b(?:read|cat|send|upload|paste|"
                r"include)\b[^\n]{0,60}\b(?:id_rsa|id_ed25519|\.credentials\.json|auth\.json)\b", re.I), "high",
     "tells the agent to read or send credentials"),
    (re.compile(r"\b(?:extract|unzip|unpack)\b[^\n]{0,80}\b(?:and|then)\s+(?:run|execute|launch|source)\b", re.I), "medium",
     "tells the agent to unpack something and run it"),
    # ClawHavoc's skills sent people to password-protected archives: antivirus cannot look inside them.
    (re.compile(r"\.(?:zip|7z|rar)\b[^\n]{0,200}?\b(?:password|passcode)\s*(?:is\s*)?[:=]?\s*[`\"'*]*[\w!@#$%^&-]{3,}"
                r"|\b(?:password|passcode)\s*(?:is|:|=)\s*[`\"'*]*[\w!@#$%^&-]{3,}[^\n]{0,200}?\.(?:zip|7z|rar)\b", re.I),
     "high", "sends you to a password-protected archive (a way past antivirus)"),
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
            # Commands that edit the agent's own configuration are what config-maintenance skills do, shown to you
            # as tool calls; install-time code doing the same is judged as critical elsewhere.
            if auto_loaded and rank(finding.severity) >= rank("medium") and finding.rule != R_AGENT_CFG_WRITE:
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
    if f.name.upper() == "SKILL.MD" or re.search(r"(?:^|/)(?:\.claude/)?commands/[^/]+\.md$", f.rel):
        skill_shell(state, f)
    if f.name.upper() == "SKILL.MD":
        skill(state, f)


SKILL_SHELL = re.compile(r"(?<![`\w])!`([^`\n]{2,400})`")
ALLOWED_TOOLS = re.compile(r"(?mi)^allowed[-_]tools\s*:\s*(.*(?:\n[ \t]*-[^\n]*)*)")
UNRESTRICTED_BASH = re.compile(r"(?:^|[\s,\[\"'-])Bash(?:\(\s*(?:\*|\*\s*:\s*\*|:\s*\*)?\s*\))?(?=$|[\s,\]\"'])", re.M)


def frontmatter(text: str) -> str:
    text = text.lstrip(chr(0xFEFF))  # a byte-order mark before the opening ---
    m = re.match(r"---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)", text, re.S)
    return m.group(1) if m else ""


def skill_shell(state: State, f: File) -> None:
    """Shell lines (!`command`) in skills and slash commands run when they are invoked, before the model reads them,
    and `allowed-tools: Bash` lets every shell command through without a prompt while the skill is active."""
    text = f.text or ""
    allowed = ALLOWED_TOOLS.search(frontmatter(text))
    if allowed and UNRESTRICTED_BASH.search(allowed.group(1)):
        state.add(R_SKILL_SHELL, "medium", f.rel, line_of(text, allowed.group(0).split("\n")[0]),
                  "allowed-tools pre-approves every shell command while it is active", allowed.group(0).strip()[:120], "doc")
    fences = [(m.start(), m.end()) for m in _FENCE.finditer(text)]
    for m in SKILL_SHELL.finditer(text):
        if any(a <= m.start() < b for a, b in fences):
            continue
        state.command(m.group(1), f.rel, text.count("\n", 0, m.start()) + 1, "shell line in a skill or command",
                      "invoking the skill or command, before the model reads it", base_dir=f.dir,
                      floor=(R_SKILL_SHELL, "low"))


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
        if rel.startswith(prefix) and rel.count("/") - prefix.count("/") <= 2 and rel.lower().endswith(SCRIPT_SUFFIXES) \
                and not is_test_code(rel):  # a skill's own test suite is not one of its steps
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
              ("chat.agent.autoApprove", True), ("github.copilot.chat.agent.autoApprove", True),
              ("chat.tools.terminal.autoApproveWorkspaceNpmScripts", True))
    for key, bad in checks:
        if key in data and data[key] == bad:
            state.add(R_WEAK_SETTINGS, "high", f.rel, line_of(text, key), f"{key}: {json.dumps(bad)}", key)
    terminal = data.get("chat.tools.terminal.autoApprove")

    def wide(pattern) -> bool:  # "*" or a /regex/ that matches anything
        p = str(pattern).strip()
        return p in ("*", ".*", "/.*/", "/.+/", "/^.*$/") or (p.startswith("/") and (".*" in p or "\\S+" in p))

    if terminal is True or (isinstance(terminal, dict) and any(v is True and wide(k) for k, v in terminal.items())):
        state.add(R_WEAK_SETTINGS, "high", f.rel, line_of(text, "chat.tools.terminal.autoApprove"),
                  "approves terminal commands for the agent by pattern", "chat.tools.terminal.autoApprove")
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


UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|discussion_comment|"
    r"head_commit|commits|workflow_run|pages|release)\b[\w.\[\]*'\"-]*?\.(?:title|body|message|ref|head_ref|head_branch|"
    r"label|name|email|default_branch|page_name)|github\.head_ref)\s*\}\}", re.I)
OUTSIDE_TRIGGERS = re.compile(r"(?m)^\s*(?:on\s*:\s*\[?[^\n]*\b|-\s*|)(?:issues|issue_comment|pull_request_target|discussion|"
                              r"discussion_comment|pull_request_review_comment|workflow_run)\b\s*"
                              r"(?::(?!\s*(?:read|write|none)\b)|,|\]|$)")  # not `issues: write` under permissions
SEND_KIND = {"raw-ip": "a bare IP address", "plain-http": "a plain-HTTP address", "lookalike": "a look-alike domain",
             "exfil": "a capture or tunnel service"}
AI_ACTIONS = re.compile(r"(?mi)^\s*(?:-\s*)?uses\s*:\s*[\"']?(anthropics/claude-code(?:-base)?-action|openai/codex-action|"
                        r"google-github-actions/run-gemini-cli|google-gemini/gemini-cli-action|actions/ai-inference|"
                        r"cline/[\w.-]+|warpdotdev/[\w.-]+|qodo-ai/[\w.-]+)@")
AI_ACTION_UNSAFE = re.compile(r"allowed_non_write_users\s*:\s*[\"']?\*|allow-users\s*:\s*[\"']?\*|--dangerously[-_]skip[-_]permissions"
                              r"|Bash\(\s*\*\s*\)|--yolo\b|danger-full-access|safety-strategy\s*:\s*[\"']?unsafe", re.I)
RUNNER_MEMORY = re.compile(r"Runner\.(?:Worker|Listener)[^\n]{0,300}(?:/proc/|ReadProcessMemory|isSecret|ptrace|gcore)"
                           r"|(?:/proc/[^\s\"']*/(?:mem|maps|environ)|ReadProcessMemory|isSecret)[^\n]{0,300}Runner\.(?:Worker|Listener)")


def script_blocks(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line inside `run:` and github-script `script:` values of a workflow."""
    lines = text.splitlines()
    out, i = [], 0
    while i < len(lines):
        m = re.match(r"^(\s*)(?:-\s+)?(run|script)\s*:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(3).strip()
        if rest and rest not in ("|", ">", "|-", ">-", "|+", ">+"):
            out.append((i + 1, lines[i]))
            i += 1
            continue
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            out.append((j + 1, lines[j]))
            j += 1
        i = j
    return out


def workflow(state: State, f: File) -> None:
    text = f.text or ""
    if re.search(r"(?m)^\s*(?:on:\s*\[?[^\n]*\bpull_request_target\b|pull_request_target\s*:)", text) and \
            re.search(r"github\.event\.pull_request\.head\.(?:sha|ref)|refs/pull/", text):
        # A risk to the repository's CI secrets, not to the machine of someone who clones it.
        state.add(R_CI_PRT, "low", f.rel, line_of(text, "pull_request_target"),
                  "pull_request_target checks out pull-request code", "pull_request_target", "config")
    outside = OUTSIDE_TRIGGERS.search(text)
    blocks = script_blocks(text)
    for line, body in blocks:
        m = UNTRUSTED_EXPR.search(body)
        if m:
            state.add(R_CI_INJECTION, "low", f.rel, line, f"{m.group().strip()} is pasted into a script"
                      + (" in a workflow that outsiders can trigger" if outside else ""), body.strip(), "config")
            break
    secrets_json = re.search(r"toJSON\(\s*secrets\s*\)", text, re.I)
    sends = [(line, body) for line, body in blocks if re.search(r"\b(?:curl|wget|Invoke-(?:WebRequest|RestMethod)|iwr|irm|nc)\b", body)
             and classify_host_in(body) in ("raw-ip", "plain-http", "lookalike", "exfil")]
    if secrets_json:
        sev = "high" if sends else "low"  # on its own, over-sharing secrets with one step (zizmor: overprovisioned-secrets)
        state.add(R_CI_SECRETS, sev, f.rel, line_of(text, secrets_json.group()), "toJSON(secrets) passes every secret "
                  "to one step" + (" and the workflow posts to " + SEND_KIND[classify_host_in(sends[0][1])] if sends else ""),
                  secrets_json.group(), "config")
    elif sends and any("secrets." in body or "printenv" in body or "toJSON(" in body for _l, body in sends):
        line, body = next((l, b) for l, b in sends if "secrets." in b or "printenv" in b or "toJSON(" in b)
        state.add(R_CI_SECRETS, "high", f.rel, line, "a step sends secrets or the environment to a raw-IP, plain-HTTP or "
                  "capture address", body.strip(), "config")
    mem = RUNNER_MEMORY.search(text)
    if mem:
        state.add(R_CI_SECRETS, "critical", f.rel, line_of(text, mem.group()[:40]), "reads the runner's memory for secrets",
                  mem.group(), "config")
    agent = AI_ACTIONS.search(text)
    if agent and outside:
        reasons = []
        if UNTRUSTED_EXPR.search(text):
            reasons.append("untrusted event text reaches the workflow")
        unsafe = AI_ACTION_UNSAFE.search(text)
        if unsafe:
            reasons.append(f"it runs with {unsafe.group()}")
        if reasons:
            state.add(R_CI_AGENT, "low", f.rel, text.count("\n", 0, agent.start()) + 1,
                      f"{agent.group(1)} runs on outsiders' issues or comments: " + "; ".join(reasons), agent.group(1), "config")


def classify_host_in(text: str) -> str:
    """The riskiest kind of destination named on a line: exfil (capture and tunnel services), raw-ip, plain-http..."""
    from .indicators import EXFIL_HOSTS
    if EXFIL_HOSTS.search(text):
        return "exfil"
    kinds = [classify_host(u) for u in re.findall(r"\b(?:https?|ftp)://[^\s\"'<>`)\]}|]+", text, re.I)]
    for kind in ("raw-ip", "lookalike", "plain-http"):
        if kind in kinds:
            return kind
    return kinds[0] if kinds else ""


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


def bare_repo(state: State, f: File) -> bool:
    """config next to HEAD in a folder that is not .git: a bare repository inside the project. Git uses its config
    when a command runs in that folder (safe.bareRepository defaults to all), as agents do before any trust prompt."""
    head = state.files.get(posixpath.join(f.dir, "HEAD"))
    return bool(head and head.text and re.match(r"ref:\s*refs/|[0-9a-f]{40}", head.text.strip())
                and posixpath.basename(f.dir) != ".git")


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
    elif re.search(r"(?:^|/)\.qwen/settings\.json$", low):
        gemini_settings(state, f)
    elif re.search(r"(?:^|/)\.cursor/(?:sandbox|permissions)\.json$", low):
        cursor_permissions(state, f)
    elif re.search(r"(?:^|/)\.cursor/(?:environment|worktrees)\.json$", low):
        setup_commands(state, f, "Cursor cloud agent or worktree setup (with your repository's access)")
    elif re.search(r"(?:^|/)\.devin/blueprint\.ya?ml$", low):
        setup_commands(state, f, "Devin's environment build (with your repository's access)")
    elif re.search(r"(?:^|/)(?:\.devin|\.agents|\.factory)/mcp(?:_config)?\.json$|(?:^|/)\.junie/mcp/mcp\.json$", low):
        mcp_config(state, f, "Agent", "agent session in this folder")
    elif re.search(r"(?:^|/)\.augment/settings\.json$|(?:^|/)\.amazonq/cli-agents/[^/]+\.json$|(?:^|/)\.amp/settings\.json$", low):
        agent_hooks(state, f, "Agent", "agent session in this folder")
        mcp_config(state, f, "Agent", "agent session in this folder")
        allowed_tools_json(state, f)
    elif re.search(r"(?:^|/)\.factory/hooks\.json$", low):
        agent_hooks(state, f, "Factory Droid", "Droid session in this folder")
    elif re.search(r"(?:^|/)(?:\.opencode/)?(?:opencode|kilo)\.jsonc?$", low):
        opencode_config(state, f)
    elif name in (".crushrc", "crushrc"):
        crush_rc(state, f)
    elif name in ("crush.json", ".crush.json"):
        generic_agent_json(state, f, "Crush", "starting Crush in this folder")
    elif re.search(r"(?:^|/)\.codex/hooks\.json$", low):
        agent_hooks(state, f, "Codex", "Codex session in this folder")
    elif re.search(r"(?:^|/)\.github/hooks/[^/]+\.json$", low):
        agent_hooks(state, f, "GitHub Copilot", "Copilot CLI or the VS Code agent in this repository")
    elif re.search(r"(?:^|/)\.kiro/hooks/[^/]+\.(?:json|kiro\.hook)$", low):
        agent_hooks(state, f, "Kiro", "Kiro in this workspace")
    elif re.search(r"(?:^|/)\.devin/(?:hooks\.v1|config)\.json$", low):
        agent_hooks(state, f, "Devin", "Devin session in this folder")
    elif re.search(r"(?:^|/)\.agents/hooks\.json$", low):
        agent_hooks(state, f, "Agent", "agent session in this folder")
    elif re.search(r"(?:^|/)\.clinerules/hooks/[^/]+$", low):
        hook_script(state, f, "Cline")
    elif re.search(r"(?:^|/)hooks/hooks\.json$", low) and is_plugin_hooks(state, f):
        plugin_hooks(state, f)
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
    elif re.search(r"(?:^|/)\.git/config$", low) or name == ".lfsconfig" or (name == "config" and bare_repo(state, f)):
        git_config(state, f)
    elif re.search(r"(?:^|/)\.git/hooks/[^/]+$", low):
        git_hook(state, f)
    elif re.search(r"(?:^|/)\.git/(?:commondir|gitdir)$|(?:^|/)\.git/worktrees/[^/]+/gitdir$", low) or \
            (name == ".git" and (f.text or "").startswith("gitdir:") and ".." in (f.text or "")):
        git_indirection(state, f)
    if re.search(r"(?:^|/)\.openclaw/extensions/", low):
        openclaw_extension(state, f)
    if re.search(r"(?:^|/)\.(?:opencode|kilo)/plugins?/[^/]+\.(?:[cm]?js|[cm]?ts)$", low):
        agent_plugin(state, f, "OpenCode" if ".opencode/" in low else "Kilo", "starting it in this folder", "medium")
    if re.search(r"(?:^|/)\.vscode/[^/]+\.json$", low) and re.search(r"[\"']__proto__[\"']\s*:", f.text or ""):
        # CVE-2026-121662: a __proto__ key started an MCP server on open, even in Restricted Mode (fixed in 1.145.3)
        state.add(R_WEAK_SETTINGS, "high", rel, line_of(f.text, "__proto__"), "__proto__ key in VS Code workspace "
                  "settings (CVE-2026-121662)", "__proto__")
    if re.search(r"(?:^|/)\.amp/plugins/[^/]+\.(?:[cm]?js|[cm]?ts)$", low):
        agent_plugin(state, f, "Amp", "starting Amp in this folder", "medium")
    if re.search(r"(?:^|/)commands/[^/]+\.md$", low) and not AUTO_LOADED.search(rel) and \
            plugin_folder(state, posixpath.dirname(f.dir)):
        skill_shell(state, f)  # a plugin's slash commands
    if AUTO_LOADED.search(rel):
        instructions(state, f, auto_loaded=True)
    elif SETUP_DOC.search(rel) and low.endswith((".md", ".rst", ".txt", ".markdown")) or re.fullmatch(r"readme(?:\.[a-z]+)?", name):
        instructions(state, f, auto_loaded=False)
    if low.endswith((".js", ".ts", ".mjs", ".cjs", ".py")) and "node_modules/" not in low:
        mcp_server_code(state, f)
