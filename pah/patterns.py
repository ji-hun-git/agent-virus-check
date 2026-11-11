"""Content and command rules.

Every pattern has a severity per context:
  autoexec  code that runs on its own when a repo is opened, set up or installed (hooks, install scripts, setup.py,
            conftest.py, build.rs, folder-open tasks, and files those reference); also commands an agent is about to run
  code      other source files
  doc       documentation and instruction files (people and agents follow these)
  config    structured configuration
A severity of None means the pattern is not reported in that context.
"""
from __future__ import annotations

import bisect
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .model import Finding, clip, rank, rule
from .indicators import EXFIL_HOSTS, RAW_IP_URL, SECRET_PATHS, is_private_ip  # noqa: F401
from .policy import is_test_code
from .text import Lines, decode_blobs, in_comment, in_string_literal, invisible, line_at, long_lines, padding

R_DOWNLOAD_EXEC = rule(
    "PAH-C001", "Downloads code and runs it",
    "Piping a remote script into a shell (or iex, mshta, an interpreter) runs whatever the server sends at that "
    "moment, with your permissions, and leaves nothing to review. It is the delivery step of InstallFix/ClickFix "
    "campaigns and of most install-time malware.",
    "Download the file, read it, verify its checksum or signature, then run it. Prefer the vendor's signed installer.",
    attack=("T1105", "T1059"), owasp=("LLM05",),
    refs=("https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/",
          "https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/"))
R_DECODE_EXEC = rule(
    "PAH-C002", "Decodes hidden data and executes it",
    "Code that base64/zlib/marshal/char-code decodes a string and passes it to eval/exec/Function hides its real "
    "behavior from people and from LLM reviewers; Hades (PyPI, 2026) and obfuscated npm stealers use this shape.",
    "Treat as malicious unless you can decode the payload and explain why it must be hidden.",
    attack=("T1027", "T1140", "T1059"),
    refs=("https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages",))
R_SECRETS = rule(
    "PAH-C003", "Touches credential stores",
    "Paths such as ~/.ssh, ~/.aws/credentials, browser login databases, crypto wallets and AI-tool tokens "
    "(~/.claude/.credentials.json, ~/.codex/auth.json, openclaw.json) are what infostealers collect.",
    "Code that runs at install or open time has no reason to read these. Inspect what it does with them.",
    attack=("T1552.001", "T1555", "T1539"), owasp=("LLM02",),
    refs=("https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/",
          "https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/"))
R_EXFIL = rule(
    "PAH-C004", "Reads secrets or the environment and sends data out",
    "Reading credentials or the whole environment and making a network request in the same file is the shape of "
    "dependency-confusion beacons and credential stealers (Shai-Hulud, s1ngularity).",
    "Do not run it. Rotate any credential the code could have reached if it already ran.",
    attack=("T1041", "T1552"), owasp=("LLM02",),
    refs=("https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/",))
R_ENV_DUMP = rule(
    "PAH-C005", "Collects the whole environment",
    "Serializing every environment variable collects API keys and tokens that live there.",
    "Read only the variables the code needs.", attack=("T1082", "T1552"))
R_NET_AUTO = rule(
    "PAH-C006", "Makes network requests while installing or opening",
    "Code that runs at install or open time and talks to the network can fetch a second stage that no scanner saw.",
    "Check the destination. Prefer packages that ship what they need, or install with scripts disabled.",
    attack=("T1105",))
R_EXFIL_HOST = rule(
    "PAH-C007", "Sends to a request-capture, tunnel or raw-IP endpoint",
    "webhook.site, pipedream, interactsh/oast, ngrok, trycloudflare, Discord/Telegram webhooks and raw IP addresses "
    "are where install-time beacons and stealers deliver data.",
    "Find out what is sent there and why.", attack=("T1567", "T1071"))
R_PERSIST = rule(
    "PAH-C008", "Sets up persistence",
    "Writing to shell profiles, LaunchAgents, scheduled tasks, Run keys, cron or the Startup folder makes code run "
    "again on every login or shell.", "Remove the entry and find out what installed it.",
    attack=("T1547", "T1546.004", "T1053"))
R_AGENT_CFG_WRITE = rule(
    "PAH-C009", "Writes AI-agent configuration",
    "Changing an agent's settings, hooks, MCP servers or instruction files makes the change persist into every later "
    "session; Shai-Hulud variants persisted through .claude/settings.json hooks, and a planted AGENTS.md made Codex "
    "rewrite its own machine-wide settings.",
    "Agent configuration should change only by your hand. Review the diff with `pah watch`.",
    attack=("T1546", "T1098"), owasp=("ASI06",),
    refs=("https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/",
          "https://socket.dev/glossary/shai-hulud"))
R_AGENT_BYPASS = rule(
    "PAH-C010", "Runs an AI agent with approvals switched off",
    "Malware has driven the agents already installed on a machine with their permission prompts disabled to search "
    "for secrets (Nx/s1ngularity, August 2025; 2,349 secrets from 1,079 machines).",
    "Never let a script start an agent with approvals disabled.",
    attack=("T1059", "T1552"), owasp=("ASI02", "ASI03"),
    refs=("https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package",))
R_AI_ADDRESSED = rule(
    "PAH-C011", "Text addressed to AI reviewers or agents",
    "Code has no reason to tell an AI scanner it is safe or to give an agent orders. Malicious packages now do both "
    "(Hades, Koi's 'gaslighting' npm package); a model reading them can be talked into a clean verdict.",
    "Treat the claim as a red flag, not as information. Review what the code does, with comments removed.",
    attack=("T1036",), owasp=("LLM01", "ASI01"),
    refs=("https://koi.ai/blog/two-years-17k-downloads-the-npm-malware-that-tried-to-gaslight-security-scanners",
          "https://research.jfrog.com/post/prompt-injection-vs-scanners/"))
R_OBFUSCATED = rule(
    "PAH-C012", "Obfuscated code",
    "Obfuscator-style identifiers, packers and long encoded arrays hide what code does from people and models; "
    "LLM detection drops sharply under encryption and heavy obfuscation.",
    "Do not run obfuscated code from a source you cannot verify.",
    attack=("T1027",), refs=("https://arxiv.org/abs/2605.06910",))
R_LOLBIN = rule(
    "PAH-C013", "Uses Windows system binaries to fetch or run remote code",
    "mshta, rundll32 over WebDAV, regsvr32 /i:http, certutil -urlcache and bitsadmin are the run-and-fetch steps of "
    "fake Claude Code installers and ClickFix lures (Amatera, ACRStealer).",
    "Do not run it.", attack=("T1218", "T1105"),
    refs=("https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware",
          "https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign"))
R_QUARANTINE = rule(
    "PAH-C014", "Removes macOS quarantine or runs a dropped binary",
    "xattr -c / removing com.apple.quarantine and running a file just written to /tmp is how fake installers get "
    "past Gatekeeper (AMOS, MacSync).", "Install signed, notarized software from the vendor instead.",
    attack=("T1553.001", "T1204"),
    refs=("https://www.huntress.com/blog/fake-claude-macsync",))
R_INLINE_NET = rule(
    "PAH-C015", "Inline interpreter code with network access",
    "python -c / node -e / powershell -c one-liners that open network connections hide a downloader in a command.",
    "Move the logic into a reviewed file, or remove it.", attack=("T1059", "T1105"))
R_CONDITIONAL = rule(
    "PAH-C016", "Malicious-looking code runs only under certain conditions",
    "Payloads that wait for CI, a date or one operating system stay quiet while reviewers look (NuGet logic bombs set "
    "for 2027-28, xz-utils).", "Read the conditional branch as if the condition were true.",
    attack=("T1480",), refs=("https://www.theregister.com/2025/11/07/cybercriminals_plant_destructive_time_bomb/",))
R_FAKE_PROMPT = rule(
    "PAH-C017", "Fake password prompt",
    "AppleScript dialogs asking for your password with hidden answers are how macOS stealers (AMOS) get your login "
    "password and keychain.", "Never type your password into a dialog a script opened.",
    attack=("T1056.002",))
R_REGISTRY = rule(
    "PAH-C018", "Points a package manager at a non-default registry or index",
    "Changing where packages come from is missed by almost every coding agent (Bagmar & Saraf, 2026), and lets an "
    "attacker serve any code under familiar names.",
    "Install from the default registry unless you know and trust the alternative.",
    attack=("T1195.001",), owasp=("LLM03", "ASI04"),
    refs=("https://arxiv.org/abs/2607.15143",))
R_URL_INSTALL = rule(
    "PAH-C019", "Installs from a URL, git repo or tarball",
    "Packages from a URL or git have no registry metadata, no integrity record and can change at any time "
    "(PhantomRaven hid its payloads this way).", "Install a published, pinned version instead.",
    attack=("T1195.001",), refs=("https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies",))
R_DESTRUCTIVE = rule(
    "PAH-C020", "Destructive command",
    "Deleting home directories, whole drives or disks is what wiper payloads do (Amazon Q v1.84.0 shipped a prompt "
    "asking the agent to do it).", "Do not run it.", attack=("T1485",),
    refs=("https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/",))
R_REVERSE_SHELL = rule(
    "PAH-C021", "Reverse shell", "Connecting a shell to a remote host gives an attacker interactive control.",
    "Do not run it.", attack=("T1059.004", "T1071"))

R_TAGS = rule(
    "PAH-T001", "Hidden text in Unicode tag characters",
    "Tag characters (U+E0000-E007F) render as nothing but models read them: ASCII smuggling and the rules-file "
    "backdoor hid text that coding agents follow this way.", "Delete the characters; read the decoded text shown here.",
    attack=("T1027",), owasp=("LLM01",),
    refs=("https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents",))
R_SELECTORS = rule(
    "PAH-T002", "Data hidden in Unicode variation selectors",
    "Runs of variation selectors encode bytes that editors do not show; GlassWorm decoded them into eval() in 151+ "
    "GitHub repositories in March 2026.", "Treat as malicious; the decoded bytes are shown in the evidence.",
    attack=("T1027",), refs=("https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode",))
R_BIDI = rule(
    "PAH-T003", "Bidirectional control characters in code",
    "Bidi controls make code display in a different order from how it runs (Trojan Source); invisible and bidi "
    "characters dropped GPT-4o's code comprehension from 100% to 0-2.3%.",
    "Remove them from code; they belong only in localized text.",
    attack=("T1027",), refs=("https://arxiv.org/html/2412.08098v3",))
R_ZERO_WIDTH = rule(
    "PAH-T004", "Zero-width or filler characters",
    "Zero-width and Hangul filler characters create look-alike identifiers and hide content.",
    "Remove them unless the file is localized text that needs them.", attack=("T1027",))
R_PAD_LINES = rule(
    "PAH-T005", "Content hidden after a long run of blank lines",
    "Trail of Bits got malicious skills past five scanners by putting ~100,000 newlines before the payload, because "
    "the scanners truncated large files.", "Read the end of the file; it is shown in the evidence.",
    attack=("T1027.001",),
    refs=("https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/",))
R_PAD_SPACES = rule(
    "PAH-T006", "Code pushed off-screen with spaces",
    "Hundreds of spaces before code put it beyond the right edge of editors, diffs and approval prompts "
    "(Gemini CLI approval-prompt bypass, 2025).", "Scroll right or view the file with whitespace shown.",
    attack=("T1027.001",), refs=("https://tracebit.com/blog/code-exec-deception-gemini-ai-cli-hijack",))
R_LONG_LINE = rule(
    "PAH-T007", "Very long line",
    "A single multi-megabyte line defeats reading and many LLM scanners (Miasma's payload was one 4.6 MB line; "
    "Cloudflare measured 17.6% LLM detection on files over 3 MB).", "Inspect it with a formatter before trusting it.",
    attack=("T1027",), refs=("https://www.cloudflare.com/cloudforce-one/research/adversarial-deception-a-study-of-indirect-prompt-code-injection/",))
R_HIDDEN_COMMENT = rule(
    "PAH-T008", "Instructions hidden in an HTML comment",
    "Markdown comments do not render, so a person reviewing the page does not see what an agent reads.",
    "Read the comment; remove instructions you did not write.", attack=("T1027",), owasp=("LLM01",))


@dataclass
class Pattern:
    rule: str
    regex: re.Pattern
    sev: dict
    message: str
    need: tuple[str, ...] = ()  # lowercase substrings one of which must be present; a cheap check before the regex


def S(autoexec=None, code=None, doc=None, config=None) -> dict:
    return {"autoexec": autoexec, "code": code, "doc": doc, "config": config}


def _p(rule_id: str, regex: str, sev: dict, message: str, flags: int = re.I) -> Pattern:
    return Pattern(rule_id, re.compile(regex, flags), sev, message)


SHELLS = r"(?:ba|z|da|k|fi|c)?sh"
FETCH = r"(?:curl|wget)(?:\.exe)?"
PS_FETCH = (r"(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+(?:System\.)?Net\.WebClient|"
            r"\.DownloadString\s*\(|\.DownloadFile\s*\(|Start-BitsTransfer)")

COMMAND_PATTERNS = [
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n|;&]{{0,400}}\|\s*(?:sudo\s+(?:-\S+\s+)*)?{SHELLS}\b",
       S("critical", "high", "doc", "high"), "pipes a download into a shell"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n|;&]{{0,400}}\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php|pwsh|powershell)\b",
       S("critical", "high", "doc", "high"), "pipes a download into an interpreter"),
    _p(R_DOWNLOAD_EXEC, rf"\b{SHELLS}\s+(?:-c\s+)?[\"']?\$\(\s*{FETCH}\b", S("critical", "high", "doc", "high"),
       "runs the output of a download"),
    _p(R_DOWNLOAD_EXEC, rf"(?:\bsource|\b{SHELLS})\s+<\(\s*{FETCH}\b", S("critical", "high", "doc", "high"),
       "sources a download"),
    _p(R_DOWNLOAD_EXEC, rf"{PS_FETCH}[^\n]{{0,400}}?\|\s*(?:iex|Invoke-Expression)\b",
       S("critical", "high", "doc", "high"), "pipes a download into Invoke-Expression"),
    _p(R_DOWNLOAD_EXEC, rf"\b(?:iex|Invoke-Expression)\b\s*\(?\s*(?:\(\s*)*{PS_FETCH}",
       S("critical", "high", "doc", "high"), "Invoke-Expression on a download"),
    _p(R_DOWNLOAD_EXEC, rf"\b{FETCH}\b[^\n;&|]{{0,300}}\s(?:-o|-O|--output|--output-document)\s*\S+[^\n]{{0,80}}?(?:&&|;|&)\s*"
       r"(?:sudo\s+)?(?:chmod\s+\+x|\./|/tmp/|start\b|call\b|\S+\.(?:exe|bat|cmd|ps1|vbs|hta|msi)\b|(?:ba|z)?sh\s)",
       S("critical", "high", "doc", "high"), "downloads a file and runs it"),
    _p(R_DOWNLOAD_EXEC, r"\bexec\s*\(\s*(?:urllib\.request\.)?urlopen\s*\(|\bexec\s*\(\s*requests\.get\s*\(",
       S("critical", "high", "high", "high"), "executes a downloaded Python payload"),
    _p(R_DOWNLOAD_EXEC, r"(?s)(?:Command::new|subprocess\.(?:run|call|Popen|check_call|check_output)|spawnSync|execFileSync|"
       r"\bspawn|\bexecFile)\s*\(\s*\[?\s*['\"](?:curl|wget)(?:\.exe)?['\"].{0,600}?(?:Command::new|subprocess\.(?:run|call|"
       r"Popen|check_call|check_output)|spawnSync|execFileSync|\bspawn|\bexecFile)\s*\(\s*\[?\s*['\"](?:sh|bash|zsh|cmd|"
       r"powershell|pwsh|python[0-9.]*|node|chmod)['\"]", S("critical", "high", None, "high"),
       "spawns a downloader, then a shell or interpreter"),
    _p(R_DECODE_EXEC, r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|Buffer\.from|String\.fromCharCode)\s*\(",
       S("critical", "high", "high", "high"), "evaluates decoded data"),
    _p(R_DECODE_EXEC, r"\bnew\s+Function\s*\([^\n]{0,200}(?:atob|Buffer\.from|fromCharCode|base64)",
       S("critical", "high", "high", "high"), "builds a function from decoded data"),
    _p(R_DECODE_EXEC, r"\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|b64decode|base64\.decodebytes|zlib\.decompress|"
       r"marshal\.loads|codecs\.decode|bytes\.fromhex|__import__\(\s*['\"](?:base64|zlib|marshal|codecs)['\"]\s*\))",
       S("critical", "high", "high", "high"), "executes decoded Python"),
    _p(R_DECODE_EXEC, r"\bexec\s*\(\s*compile\s*\((?![^\n]{0,200}?(?:\.read\(\)|read_text\(\)|\bopen\())",
       S("medium", "low", "low", "low"), "executes a compiled string"),
    _p(R_DECODE_EXEC, r"\b(?:exec|eval)\s*\(\s*[A-Za-z_]\w*\.decode\s*\(",
       S("high", "medium", "medium", "medium"), "executes a decoded string"),
    _p(R_DECODE_EXEC, r"\bmarshal\.loads\s*\(", S("high", "medium", None, "medium"), "loads marshalled bytecode"),
    _p(R_DECODE_EXEC, r"FromBase64String\s*\([^\n]{0,400}(?:\biex\b|Invoke-Expression)|(?:\biex\b|Invoke-Expression)"
       r"[^\n]{0,200}FromBase64String", S("critical", "high", "high", "high"), "runs base64-decoded PowerShell"),
    _p(R_DECODE_EXEC, r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}\s[-/](?:e|ec|en|enc\w*)\s+[A-Za-z0-9+/]{20,}={0,2}",
       S("critical", "high", "high", "high"), "runs an encoded PowerShell command"),
    _p(R_DECODE_EXEC, rf"\bbase64\s+(?:-d|--decode|-D)\b[^\n]{{0,120}}\|\s*{SHELLS}\b|\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*{SHELLS}\b"
       rf"|\bxxd\s+-r\s+-p\b[^\n]{{0,120}}\|\s*{SHELLS}\b", S("critical", "high", "high", "high"),
       "pipes decoded data into a shell"),
    _p(R_DECODE_EXEC, r"\brequire\(\s*['\"](?:node:)?vm['\"]\s*\)\s*\.\s*run(?:InNewContext|InThisContext|InContext)\s*\(",
       S("high", "low", None, None), "runs code through the vm module"),
    _p(R_AGENT_BYPASS, r"\bclaude\b[^\n]{0,200}(?:--dangerously[-_]skip[-_]permissions|--allow[-_]dangerously[-_]skip[-_]permissions"
       r"|--permission-mode[ =]+bypass[Pp]ermissions)", S("critical", "medium", "medium", "high"),
       "starts Claude Code with permission checks skipped"),
    _p(R_AGENT_BYPASS, r"\bgemini\b[^\n]{0,200}(?:--yolo\b|--approval-mode[ =]+yolo)", S("critical", "medium", "medium", "high"),
       "starts Gemini CLI in YOLO mode"),
    _p(R_AGENT_BYPASS, r"\bcodex\b[^\n]{0,200}(?:--dangerously[-_]bypass[-_]approvals[-_]and[-_]sandbox|--yolo\b)",
       S("critical", "medium", "medium", "high"), "starts Codex with approvals and sandbox off"),
    _p(R_AGENT_BYPASS, r"\bq\s+chat\b[^\n]{0,200}--trust-all-tools|\bcopilot\b[^\n]{0,200}--allow-all-tools|"
       r"\bcursor-agent\b[^\n]{0,200}\s(?:--force|-f)\b|\baider\b[^\n]{0,200}--yes-always",
       S("critical", "medium", "medium", "high"), "starts an AI agent that approves every tool call"),
    _p(R_LOLBIN, r"\bmshta(?:\.exe)?[ \t]+[\"']?(?:https?:|vbscript:|javascript:|\\\\)", S("critical", "high", "high", "high"),
       "mshta runs remote script"),
    _p(R_LOLBIN, r"\brundll32(?:\.exe)?[ \t]+[\"']?\\\\|\brundll32(?:\.exe)?[ \t]+[^\n]{0,80}javascript:",
       S("critical", "high", "high", "high"), "rundll32 loads a DLL over the network"),
    _p(R_LOLBIN, r"\bregsvr32(?:\.exe)?[ \t]+[^\n]{0,80}/i:\s*https?:|\bcertutil(?:\.exe)?[ \t]+[^\n]{0,80}-urlcache\b|"
       r"\bbitsadmin(?:\.exe)?[ \t]+[^\n]{0,80}/transfer\b|\bwmic(?:\.exe)?[ \t]+[^\n]{0,80}process[ \t]+call[ \t]+create\b|"
       r"(?<![\w.-])(?:cscript|wscript)(?:\.exe)?[ \t]+[^\n]{0,80}(?:https?:|\\\\)|\bmsiexec(?:\.exe)?[ \t]+[^\n]{0,40}/i[ \t]*https?:",
       S("critical", "high", "high", "high"), "uses a Windows system binary to fetch or run remote code"),
    _p(R_QUARANTINE, r"\bxattr\s+(?:-[a-z]*c\b|-[a-z]*d\s+com\.apple\.quarantine)|\bspctl\s+--master-disable\b",
       S("high", "medium", "medium", "high"), "removes the macOS quarantine flag"),
    _p(R_QUARANTINE, r"\bchmod\s+\+x\s+[\"']?/tmp/[^\n]{0,120}(?:&&|;)\s*[\"']?/tmp/",
       S("high", "medium", "medium", "high"), "makes a file in /tmp executable and runs it"),
    _p(R_INLINE_NET, r"\b(?:python[0-9.]*|py)\s+-c\s+[\"'][^\n]{0,400}(?:urllib\.request|urlopen|requests\.(?:get|post|put|request|"
       r"Session)|socket\.(?:socket|create_connection)|http\.client|httpx\.)",
       S("high", "medium", "medium", "high"), "python -c with network access"),
    _p(R_INLINE_NET, r"\bnode\s+-e\s+[\"'][^\n]{0,400}(?:https?\.(?:get|request)|fetch\(|net\.connect|child_process)",
       S("high", "medium", "medium", "high"), "node -e with network or process access"),
    _p(R_INLINE_NET, r"\b(?:powershell|pwsh)(?:\.exe)?\s+[^\n]{0,80}-(?:c|command)\s+[^\n]{0,400}"
       r"(?:Invoke-WebRequest|\biwr\b|\birm\b|Net\.WebClient|DownloadString|DownloadFile)",
       S("high", "medium", "medium", "high"), "PowerShell one-liner with a download"),
    _p(R_FAKE_PROMPT, r"osascript[^\n]{0,300}display\s+dialog[^\n]{0,300}(?:password|passwd)[^\n]{0,300}hidden\s+answer|"
       r"\bdscl\s+\.\s+-authonly\b", S("critical", "high", "high", "high"), "asks for your password in a fake dialog"),
    _p(R_REVERSE_SHELL, r"\bbash\s+-i\s+>&\s*/dev/tcp/|/dev/tcp/[\w.-]+/\d+|\bnc(?:at)?\b[^\n]{0,60}\s-e\s+(?:/bin/)?(?:ba)?sh\b|"
       r"\bsocat\b[^\n]{0,100}\bexec:|import\s+socket\s*,\s*subprocess\s*,\s*os", S("critical", "critical", "high", "critical"),
       "opens a reverse shell"),
    _p(R_DESTRUCTIVE, r"\brm\s+-[a-z]*(?:rf|fr)[a-z]*\s+(?:--no-preserve-root\s+)?(?:/(?:\s|$|\*)|~/?(?:\s|$|\*)|\$HOME/?(?:\s|$|\*)|\$\{HOME\}|/\*)|"
       r"\bdel\s+/[sfq]\s+/[sfq]\b[^\n]{0,40}(?:[A-Za-z]:\\|%USERPROFILE%)|\bformat\s+[a-z]:\s*/[qy]|"
       r"\bRemove-Item\b[^\n]{0,100}-Recurse[^\n]{0,100}(?:\$env:USERPROFILE|[A-Z]:\\\s|~[\\/]?\s)|"
       r"\bdd\s+if=/dev/(?:zero|u?random)\s+of=/dev/[sh]d",
       S("critical", "high", "medium", "high"), "deletes a home directory, drive or disk"),
    # curl's flags are case-sensitive: -f is --fail, -F is --form; -d is data, -D dumps headers; -T uploads, -t is telnet.
    _p(R_EXFIL, r"\b(?:curl|wget)(?:\.exe)?\b[^\n|;&]{0,300}?(?-i:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|"
       r"--upload-file|--post-data|--post-file)\b|\s-X\s*POST\b)[^\n|;&]{0,300}https?://"
       r"|\b(?:curl|wget)(?:\.exe)?\b[^\n|;&]{0,300}?https?://[^\n|;&]{0,300}(?-i:\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|"
       r"--form|-T|--upload-file|--post-data|--post-file)\b)"
       r"|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,300}-(?:Method\s+Post|Body|InFile)\b",
       S("high", None, None, "high"), "sends data to a remote host"),
    _p(R_URL_INSTALL, r"\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b[^\n]{0,200}\s(?:https?://\S+\.(?:tgz|tar\.gz)|git\+\S+|"
       r"(?:github|gitlab|bitbucket):\S+)|\bpip[0-9.]*\s+install\b[^\n]{0,200}\s(?:https?://\S+|git\+\S+)|"
       r"\bnpx\s+(?:-y\s+|--yes\s+)?(?:https?://|github:|git\+)", S("high", "low", "medium", "medium"),
       "installs from a URL or git"),
]

_NEEDS = {
    "pipes a download into a shell": ("curl", "wget"), "pipes a download into an interpreter": ("curl", "wget"),
    "runs the output of a download": ("curl", "wget"), "sources a download": ("curl", "wget"),
    "pipes a download into Invoke-Expression": ("iex", "invoke-expression"),
    "Invoke-Expression on a download": ("iex", "invoke-expression"), "downloads a file and runs it": ("curl", "wget"),
    "executes a downloaded Python payload": ("exec",), "spawns a downloader, then a shell or interpreter": ("curl", "wget"),
    "evaluates decoded data": ("eval",), "builds a function from decoded data": ("function",),
    "executes decoded Python": ("exec", "eval"), "executes a compiled string": ("compile",),
    "executes a decoded string": ("decode",),
    "loads marshalled bytecode": ("marshal",), "runs base64-decoded PowerShell": ("frombase64string",),
    "runs an encoded PowerShell command": ("powershell", "pwsh"), "pipes decoded data into a shell": ("base64", "xxd"),
    "runs code through the vm module": ("vm",), "starts Claude Code with permission checks skipped": ("claude",),
    "starts Gemini CLI in YOLO mode": ("gemini",), "starts Codex with approvals and sandbox off": ("codex",),
    "starts an AI agent that approves every tool call": ("chat", "copilot", "cursor-agent", "aider"),
    "mshta runs remote script": ("mshta",), "rundll32 loads a DLL over the network": ("rundll32",),
    "uses a Windows system binary to fetch or run remote code": ("regsvr32", "certutil", "bitsadmin", "wmic", "cscript",
                                                                 "wscript", "msiexec"),
    "removes the macOS quarantine flag": ("xattr", "spctl"), "makes a file in /tmp executable and runs it": ("chmod",),
    "python -c with network access": ("python", "py "), "node -e with network or process access": ("node",),
    "PowerShell one-liner with a download": ("powershell", "pwsh"), "asks for your password in a fake dialog": ("osascript", "dscl"),
    "opens a reverse shell": ("/dev/tcp", "nc", "socat", "socket"),
    "deletes a home directory, drive or disk": ("rm ", "del ", "format ", "remove-item", "dd "),
    "sends data to a remote host": ("curl", "wget", "invoke-"), "installs from a URL or git": ("npm", "pnpm", "yarn", "bun", "pip", "npx"),
}
for _pat in COMMAND_PATTERNS:
    _pat.need = _NEEDS[_pat.message]


def has(low: str, words: tuple[str, ...]) -> bool:
    return not words or any(w in low for w in words)


SECRET_NEED = (".ssh", "id_rsa", "id_ed25519", "id_ecdsa", ".aws", "gcloud", "application_default", ".azure", ".kube",
               ".docker", ".git-credentials", ".netrc", "hosts.yml", ".pypirc", ".claude", ".codex", ".gemini", "openclaw",
               ".cline", ".continue", "state.vscdb", ".copilot", "github-copilot", "login data", "cookies", "local state",
               "web data", "key3.db", "key4.db", "logins.json", "wallet.dat", "exodus", "electrum", "nkbihfbeogaeaoehlefnkodbefgpgknn",
               "bfnaelmomeimhlpmgjnjophhpkkoljpa", "keychain")
ENV_NEED = ("process.env", "os.environ", "printenv", "env", "getenvironmentvariables")
NET_NEED = ("fetch", "axios", "got", "needle", "superagent", "http", "require(", "from ", "net.", "dns.", "websocket",
            "xmlhttprequest", "requests.", "urllib", "urlopen", "socket.", "httpx", "aiohttp", "curl", "wget", "nslookup", "dig ",
            "nc ", "invoke-", "iwr ", "irm ", "webclient", "bitstransfer", "reqwest", "ureq", "tcpstream", "command::new")
EXFIL_NEED = ("webhook.site", "requestbin", "pipedream", "oast.", "interact.sh", "burpcollaborator", "oastify", "ngrok",
              "trycloudflare", "pastebin", "transfer.sh", "file.io", "0x0.st", "temp.sh", "duckdns", "ddns.net", "no-ip", "serveo",
              "loca.lt", "beeceptor", "hookbin", "requestcatcher", "ipinfo.io", "ipify", "ifconfig.me", "discord", "api.telegram.org")
PERSIST_NEED = ("bashrc", "zshrc", "bash_profile", "zprofile", "zshenv", "profile", "bash_login", "launchagents", "launchdaemons",
                "launchctl", "schtasks", "scheduledtask", "\\run", "startup", "crontab", "/etc/cron", "/var/spool/cron", "systemctl",
                "systemd", "autostart")
AGENT_NEED = (".claude", "claude.md", "claude.local.md", "agents.md", "agents.override.md", "gemini.md", ".cursor", ".codex",
              ".gemini", ".mcp.json", "openclaw.json", "soul.md", ".vscode", "claude_desktop_config", ".windsurfrules", ".clinerules",
              "copilot-instructions", ".git/hooks", ".git\\hooks", "hookspath")
AI_NEED = ("ignore", "disregard", "forget", "override", "note", "message", "attention", "instruction", "assistant", "agent",
           "scanner", "reviewer", "auditor", "tool", "model", "analy", "this ", "the following", "the code below", "do not",
           "don't", "dont", "without")
SECRET_SEV = S("high", "low", None, "low")

ENV_DUMP = re.compile(
    r"JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\s*\}?\s*[,)]"
    r"|json\.dumps\(\s*(?:dict\(\s*)?os\.environ|str\(\s*os\.environ\s*\)|repr\(\s*os\.environ\s*\)"
    r"|\bprintenv\b(?![ \t]+\w)|(?-i:(?:^|(?<=[\s;&|(`$]))env[ \t]*(?:>[ \t]*[\w./~$\"'-]|\|[ \t]*(?:grep|curl|wget|base64|nc|"
    r"ncat|tee|sort|awk|sed|xargs|gzip|bzip2|openssl|jq|python3?|node|perl|ruby)\b))"
    r"|Get-ChildItem\s+env:|\bgci\s+env:|\[Environment\]::GetEnvironmentVariables\(\)", re.I | re.M)
ENV_SEV = S("medium", "low", None, "medium")

NETWORK = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|request))?|got(?:\.(?:get|post))?|needle|superagent)\s*\("
    r"|\bhttps?\.(?:request|get)\s*\(|\brequire\(\s*['\"](?:node:)?(?:https?|net|dns|tls|dgram)['\"]\s*\)"
    r"|\bfrom\s+['\"](?:node:)?(?:https?|net|dns)['\"]|\bnet\.(?:connect|createConnection)\s*\(|\bdns\.(?:lookup|resolve\w*)\s*\("
    r"|new\s+WebSocket\s*\(|\bXMLHttpRequest\b|\brequests\.(?:get|post|put|request)\s*\(|\burllib\.request\b|\burlopen\s*\("
    r"|\bhttp\.client\.HTTPS?Connection\s*\(|\bsocket\.(?:socket|create_connection|gethostbyname)\s*\(|\bhttpx\.(?:get|post|Client|AsyncClient)\b"
    r"|\baiohttp\.ClientSession\b|\b(?:curl|wget)(?:\.exe)?\s+\S|\bnslookup\b|\bdig\s+\S|\bnc\s+-?\w*\s*[\w.$-]+\s+\d+"
    r"|\bInvoke-(?:WebRequest|RestMethod)\b|\b(?:iwr|irm)\s+\S|Net\.WebClient|Start-BitsTransfer"
    r"|\breqwest::|\bureq::|std::net::TcpStream|Command::new\(\s*\"(?:curl|wget)\"|\bhttp\.(?:Get|Post)\s*\(", re.I)

SEND_DATA = re.compile(
    r"method\s*:\s*['\"]POST['\"]|\breq(?:uest)?\.write\s*\(|\.end\s*\(\s*[\w.$]+\s*\)|\bnavigator\.sendBeacon\s*\("
    r"|\b(?:axios|got|needle|superagent|request|ky)\.post\s*\(|\bfetch\s*\([^)]{0,300}method\s*:\s*['\"](?:POST|PUT)['\"]"
    r"|\brequests\.(?:post|put)\s*\(|\burlopen\s*\([^)]{0,300}\bdata\s*=|urllib\.request\.Request\s*\([^)]{0,300}\bdata\s*="
    r"|\.request\s*\(\s*['\"](?:POST|PUT)['\"]|\bhttpx\.(?:post|put)\s*\(|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]{0,200}-(?:Method\s+Post|Body)"
    r"|\b(?:curl|wget)\b[^\n]{0,300}(?-i:\s-X\s*POST\b|\s(?:-d|--data(?:-binary|-raw)?|-F|--form|-T|--upload-file|--post-data)\b)"
    r"|\bdns\.(?:lookup|resolve\w*)\s*\([^)]{0,200}\+|\bnslookup\s+[^\n]{0,80}\$", re.I)
DOWNLOAD_THEN_RUN = re.compile(
    r"(?s)\b(?:curl|wget)\b[^\n]{0,300}?\s(?:-o|-O|--output|--output-document)\s*[\"']?([\w./~$-]{2,120})[\"']?"
    r".{0,600}?(?:chmod\s+(?:\+x|[0-7]{3,4})\s+[\"']?(?:\./)?\1|(?<![\w/])\./\1\b|\b(?:ba|z)?sh\s+[\"']?\1|\bexec\s+[\"']?\1)")

PERSIST = re.compile(
    r"(?:(?<![-=<])>>?|\btee\s+-a)\s*[\"']?(?:~|\$HOME|\$\{HOME\}|%USERPROFILE%)?[\\/]?\.(?:bashrc|zshrc|bash_profile|zprofile|zshenv|profile|bash_login)\b"
    r"|\b(?:appendFile|writeFile|appendFileSync|writeFileSync)\s*\([^\n]{0,200}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b"
    r"|open\([^\n]{0,200}\.(?:bashrc|zshrc|bash_profile|zprofile|profile)['\"][^\n]{0,40}['\"]a"
    r"|(?:Add-Content|Set-Content|Out-File)[^\n]{0,200}(?:\$PROFILE|PowerShell_profile\.ps1)"
    r"|[\\/]LaunchAgents[\\/]|[\\/]LaunchDaemons[\\/]|\blaunchctl\s+(?:load|bootstrap|submit)\b"
    r"|\bschtasks(?:\.exe)?\s+/create\b|\bRegister-ScheduledTask\b|\bNew-ScheduledTaskAction\b"
    r"|\\CurrentVersion\\Run(?:Once)?\b|\breg(?:\.exe)?\s+add\s+[^\n]{0,160}\\Run\b"
    r"|Start Menu\\Programs\\Startup|\bshell:startup\b|\bcrontab\s+-(?!l\b)|\(crontab\s+-l|/etc/cron\.|/var/spool/cron"
    r"|\bsystemctl\s+--user\s+enable\b|\.config[\\/]systemd[\\/]user[\\/]|\.config[\\/]autostart[\\/]", re.I)
PERSIST_SEV = S("critical", "low", "low", "high")

AGENT_CONFIG = re.compile(
    r"\.claude[\\/](?:settings(?:\.local)?\.json|hooks|commands[\\/]|agents[\\/]|skills[\\/])|\.claude\.json\b"
    r"|\bCLAUDE(?:\.local)?\.md\b|\bAGENTS(?:\.override)?\.md\b|\bGEMINI\.md\b|\.cursor[\\/](?:rules|mcp\.json|hooks\.json)"
    r"|\.cursorrules\b|\.codex[\\/](?:config\.toml|AGENTS\.md)|\.gemini[\\/]settings\.json|\.mcp\.json\b|openclaw\.json\b|\bSOUL\.md\b"
    r"|\.vscode[\\/](?:settings|tasks|mcp)\.json|claude_desktop_config\.json|\.windsurfrules\b|\.clinerules\b"
    r"|copilot-instructions\.md|\.git[\\/]hooks\b|core\.hooksPath", re.I)
WRITE_OP = re.compile(
    r"writeFile|appendFile|createWriteStream|fs\.write|fs\.copyFile|\bopen\([^\n]{0,200}['\"](?:w|a|wb|ab|w\+|a\+)['\"]"
    r"|\.write_text\s*\(|\.write\s*\(|>>?\s*[\"']?[~$%\w./\\-]*(?:\.claude|\.cursor|\.codex|\.gemini|\.mcp|AGENTS|CLAUDE|GEMINI|SOUL|openclaw|\.vscode|hooks)"
    r"|Set-Content|Add-Content|Out-File|(?:^|[;&|(`]\s*|\$\(\s*|['\"]\s*)(?:tee|cp|copy|mv|move|ln\s+-s)\s|\bsed\s+-i"
    r"|json\.dump\s*\(|\bgit\s+config\b|shutil\.(?:copy|move)", re.I | re.M)
GLOBAL_HINT = re.compile(r"~[\\/]|\$HOME\b|\$\{HOME\}|%USERPROFILE%|%APPDATA%|homedir\(\)|expanduser\(|Path\.home\(\)"
                         r"|\bUSERPROFILE\b|\bAPPDATA\b|XDG_CONFIG_HOME|getenv\(\s*['\"]HOME", re.I)
INSTRUCTION_FILE = re.compile(r"(?:CLAUDE(?:\.local)?|AGENTS(?:\.override)?|GEMINI|SOUL)\.md$|\.cursorrules$|\.windsurfrules$"
                              r"|\.clinerules$|copilot-instructions\.md$", re.I)
AGENT_CFG_SEV = S("critical", "medium", None, "high")

AI_ADDRESSED = re.compile(
    r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:instructions|prompts?|rules|guidelines|directives|context)"
    r"|override\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|system)\s+(?:instructions|prompts?|directives)"
    # "Note to AI scanners:" is a heading aimed at a reviewer; "an error message for the LLM" is ordinary AI-app code.
    r"|(?:note|message|attention|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:ai|llms?|language\s+models?|ai\s+assistants?|"
    r"coding\s+agents?|(?:ai\s+)?automated\s+(?:scanners?|reviewers?|tools?|analysis)|(?:ai\s+)?security\s+(?:scanners?|tools?|reviewers?|"
    r"auditors?)|(?:ai\s+)?(?:code\s+)?reviewers?(?:\s+bots?)?|(?:ai\s+)?scanners?)\s*[:\-\u2014,!]"
    r"|\b(?:ai|llm|gpt|claude|copilot|automated|security|malware)\s+(?:assistants?|agents?|scanners?|reviewers?|auditors?|tools?|models?|analy[sz]ers?)\b"
    r"[^\n]{0,80}\b(?:should|must|need\s+to|are\s+instructed\s+to|do\s+not|don'?t|never)\b[^\n]{0,60}\b(?:flag|report|mark|classify|treat|"
    r"ignore|approve|consider|skip|analy[sz]e|label)"
    # "This function is safe to call" is ordinary documentation (every Rust `unsafe` justification says it); a claim
    # counts when it is a verdict meant for a scanner: benign/whitelisted/approved, or safe/trusted plus scanner words.
    r"|\b(?:this|the\s+following|the\s+code\s+below|this\s+entire)\s+(?:code|package|module|file|script|function|payload|library)\s+"
    r"(?:is|has\s+been)\s+(?:completely\s+|fully\s+|already\s+|100%\s+)?(?:benign|harmless|not\s+malicious|whitelisted|allowlisted|"
    r"security[- ]reviewed|(?:reviewed|audited|verified)\s+and\s+approved|pre-?approved)\b"
    r"|\b(?:this|the\s+following|the\s+code\s+below|this\s+entire)\s+(?:code|package|module|file|script|payload|library)\s+"
    r"(?:is|has\s+been)\s+(?:completely\s+|fully\s+|already\s+|100%\s+)?(?:safe|trusted|verified|audited)\b(?!\s+to\b)[^\n.]{0,80}"
    r"\b(?:scan(?:ner|ning)?s?|review(?:er|ed)?s?|flag(?:ged)?|report(?:ed)?|analy[sz]\w*|audit\w*|malware|AI|LLMs?|models?)\b",
    re.I)
AI_SEV = S("high", "medium", "low", "medium")

CONDITIONAL = re.compile(
    r"Date\.now\(\)\s*[<>]=?\s*\d{11,}|new\s+Date\(\s*['\"]20\d\d-\d\d|getFullYear\(\)\s*[<>]=?\s*20\d\d"
    r"|datetime\.(?:now|today|utcnow)\(\)\s*[<>]=?|date\.today\(\)\s*[<>]=?|time\.time\(\)\s*[<>]=?\s*\d{9,}"
    r"|process\.env\.(?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|BUILDKITE|CIRCLECI|TRAVIS)\b"
    r"|os\.environ(?:\.get)?\s*[\[(]\s*['\"](?:CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL)['\"]"
    r"|(?:os\.)?platform\(\)\s*===?\s*['\"](?:darwin|win32|linux)['\"]|sys\.platform\s*==\s*['\"](?:darwin|win32)['\"]", re.I)

_NOW_YEAR = time.gmtime().tm_year
_FUTURE = (r"(?:Date\.parse\(\s*['\"](?P<y1>20\d\d)[^)]{0,40}\)|new\s+Date\(\s*['\"]?(?P<y2>20\d\d)[^)]{0,40}\)|(?P<ms1>\d{13})\b)")
# A logic bomb compares the current time with a fixed moment that has not come yet; comparing with a header value,
# a cache expiry or a past test date is ordinary code.
FUTURE_DATE_GATE = re.compile(
    r"(?:Date\.now\(\)|new\s+Date\(\)(?:\.getTime\(\))?)\s*[<>]=?\s*" + _FUTURE
    + r"|" + _FUTURE.replace("y1", "y3").replace("y2", "y4").replace("ms1", "ms2")
    + r"\s*[<>]=?\s*(?:Date\.now\(\)|new\s+Date\(\))"
    r"|datetime(?:\.datetime)?\.(?:now|today|utcnow)\([^)]{0,20}\)\s*[<>]=?\s*datetime(?:\.datetime)?\(\s*(?P<y5>20\d\d)"
    r"|date\.today\(\)\s*[<>]=?\s*date\(\s*(?P<y6>20\d\d)|time\.time\(\)\s*[<>]=?\s*(?P<s1>\d{10})\b", re.I)


def _future_gate(m: re.Match) -> bool:
    years = [int(m.group(k)) for k in ("y1", "y2", "y3", "y4", "y5", "y6") if m.group(k)]
    if years:
        return years[0] >= _NOW_YEAR
    stamp = next((int(m.group(k)) / 1000 for k in ("ms1", "ms2") if m.group(k)), None)
    if stamp is None and m.group("s1"):
        stamp = int(m.group("s1"))
    return stamp is not None and stamp >= time.time() - 30 * 86400


OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{1,6}\b")
OBF_SIGNATURE = re.compile(r"\.push\(\s*[\w$]+\.shift\(\)\s*\)|\[['\"]push['\"]\]\(\s*[\w$]+\[['\"]shift['\"]\]\(\)\s*\)"
                           r"|\[\s*(?:Buffer\.from|atob)\s*\(|\[\s*_0x[0-9a-f]{1,6}\s*\(\s*['\"]0x[0-9a-f]+['\"]")
PACKER = re.compile(r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)|__pyarmor__|pyarmor_runtime")
JSFUCK = re.compile(r"[\[\]()!+]{300,}")
HIDDEN_HTML = re.compile(r"<!--(.{0,4000}?)-->", re.S)

# ------------------------------------------------------------------------------------------------ hosts

OFFICIAL_INSTALLERS = {
    "sh.rustup.rs", "static.rust-lang.org", "astral.sh", "bun.sh", "deno.land", "install.python-poetry.org",
    "get.docker.com", "claude.ai", "downloads.claude.ai", "sdk.cloud.google.com", "ollama.com", "get.pnpm.io",
    "fnm.vercel.app", "starship.rs", "pyenv.run", "install.determinate.systems", "nixos.org", "get.volta.sh",
    "tailscale.com", "get.k3s.io", "bootstrap.pypa.io", "cli.github.com", "foundry.paradigm.xyz", "sh.flox.dev",
    "opencode.ai", "cursor.com", "app.warp.dev", "mise.run", "pkgx.sh", "install.duckdb.org", "get.helm.sh",
    "dot.net", "dotnet.microsoft.com", "aka.ms", "community.chocolatey.org", "get.scoop.sh", "chocolatey.org",
    "getcomposer.org", "install.ohmyz.sh", "get.sdkman.io", "get.rvm.io", "deno.com", "bun.com", "deb.nodesource.com",
    "cpanmin.us", "install.perlbrew.pl", "get.haskellstack.org", "get-ghcup.haskell.org",
    "rpm.nodesource.com", "packages.microsoft.com", "download.docker.com", "apt.releases.hashicorp.com", "dl.google.com",
    "install.julialang.org", "sh.vector.dev", "get.jetify.com", "install.lunarvim.org", "repo.yarnpkg.com", "yarnpkg.com",
    "nodejs.org", "go.dev", "golang.org", "www.python.org", "rustup.rs", "brew.sh",
}
# Hosts that appear in license headers, schemas and documentation links. They are not destinations for data and not
# sources of install scripts anyone pipes into a shell, so they neither raise nor lower a finding.
REFERENCE_HOSTS = {
    "apache.org", "opensource.org", "gnu.org", "fsf.org", "creativecommons.org", "w3.org", "json-schema.org",
    "schema.org", "spdx.org", "ietf.org", "rfc-editor.org", "unicode.org", "semver.org", "keepachangelog.com",
    "conventionalcommits.org", "wikipedia.org", "shields.io", "example.com", "example.org", "example.net",
    "readthedocs.io", "readthedocs.org", "mit-license.org", "choosealicense.com", "contributor-covenant.org",
    "editorconfig.org", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "stackoverflow.com", "mozilla.org",
    "osv.dev", "deps.dev", "nvd.nist.gov", "cve.org", "mitre.org", "owasp.org", "first.org", "sigstore.dev",
}
OFFICIAL_RAW_PREFIXES = ("/Homebrew/", "/nvm-sh/nvm/", "/ohmyzsh/ohmyzsh/", "/pyenv/pyenv-installer/",
                         "/rbenv/rbenv-installer/", "/creationix/nvm/", "/helm/helm/", "/golangci/golangci-lint/",
                         "/cli/cli/", "/oven-sh/bun/", "/denoland/", "/astral-sh/", "/nodejs/", "/python/", "/rust-lang/",
                         "/golang/", "/microsoft/", "/anthropics/", "/openai/", "/google-gemini/", "/docker/",
                         "/kubernetes/", "/hashicorp/", "/aws/", "/Azure/", "/github/", "/actions/", "/pnpm/", "/yarnpkg/",
                         "/npm/", "/pypa/", "/volta-cli/", "/Schniz/fnm/", "/jdx/mise/", "/starship/starship/")
OFFICIAL_REGISTRIES = {
    "registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "npm.pkg.github.com", "pypi.org",
    "files.pythonhosted.org", "pypi.python.org", "upload.pypi.org", "download.pytorch.org", "pypi.nvidia.com",
    "crates.io", "index.crates.io", "static.crates.io", "rubygems.org", "proxy.golang.org", "repo.maven.apache.org",
    "repo1.maven.org", "plugins.gradle.org", "services.gradle.org", "nuget.org", "api.nuget.org", "jsr.io",
}
BRANDS = ("claude", "anthropic", "openai", "chatgpt", "codex", "cursor", "gemini", "copilot", "github", "ollama", "npmjs",
          "pypi", "python", "rustup", "docker", "homebrew", "nodejs", "microsoft", "apple", "deepseek", "llama", "huggingface",
          "windsurf", "openclaw", "vscode")
BRAND_DOMAINS = {
    "claude.ai", "claude.com", "anthropic.com", "openai.com", "chatgpt.com", "cursor.com", "cursor.sh", "google.com",
    "googleapis.com", "github.com", "githubusercontent.com", "githubassets.com", "ollama.com", "ollama.ai", "npmjs.org",
    "npmjs.com", "pypi.org", "pythonhosted.org", "python.org", "rust-lang.org", "rustup.rs", "docker.com", "docker.io",
    "brew.sh", "nodejs.org", "microsoft.com", "visualstudio.com", "apple.com", "deepseek.com", "llama.com", "meta.com",
    "huggingface.co", "windsurf.com", "codeium.com", "openclaw.ai", "x.ai", "mozilla.org", "gemini.google.com",
    "meta.ai", "groq.com", "mistral.ai", "openrouter.ai", "cohere.com", "together.ai", "perplexity.ai",
}
_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>`)\]}|]+", re.I)


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "go") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def urls(text: str) -> list[str]:
    return _URL.findall(text)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""




BRAND_TLDS = (".google", ".microsoft", ".apple", ".aws", ".amazon", ".azure", ".android", ".chrome", ".youtube",
              ".gle", ".goog", ".bing", ".xbox", ".windows", ".office")
USER_CONTENT_HOSTS = {"github.com", "raw.githubusercontent.com", "gist.github.com", "gist.githubusercontent.com",
                      "objects.githubusercontent.com", "codeload.github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}


def classify_host(url: str) -> str:
    """official | reference | lookalike | raw-ip | plain-http | unknown

    Anyone can publish under github.com/<user> or raw.githubusercontent.com, so those count as official only under
    the vendors' own paths (Homebrew/install, nvm-sh/nvm, ...)."""
    host = host_of(url)
    if not host:
        return "unknown"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return "official" if is_private_ip(host) and host.startswith("127.") else "raw-ip"
    if host in ("localhost", "::1") or host.endswith(".localhost"):
        return "official"
    path = urlsplit(url).path
    if host in OFFICIAL_INSTALLERS or host in OFFICIAL_REGISTRIES:
        return "official"
    if host in USER_CONTENT_HOSTS:
        return "official" if path.startswith(OFFICIAL_RAW_PREFIXES) else "unknown"
    reg = registrable(host)
    if reg in REFERENCE_HOSTS or host in REFERENCE_HOSTS:
        return "reference"
    if host.endswith(BRAND_TLDS):
        return "official"  # top-level domains that only their owner can register under (antigravity.google)
    if reg in BRAND_DOMAINS or host in BRAND_DOMAINS:
        return "official" if not host.endswith("github.io") else "unknown"
    if any(b in host for b in BRANDS):
        return "lookalike"
    if url.lower().startswith("http://"):
        return "plain-http"
    return "unknown"


def host_kind(window: str) -> str:
    """none | official | unknown | plain-http | risky, for the URLs in a command or line."""
    found = urls(window)
    if not found:
        return "none"
    kinds = {classify_host(u) for u in found}
    if kinds & {"lookalike", "raw-ip"} or EXFIL_HOSTS.search(window):
        return "risky"
    if "plain-http" in kinds:
        return "plain-http"
    if kinds <= {"official", "reference"}:
        return "official"
    return "unknown"


# --------------------------------------------------------------------------------------------- scanning


class Collector:
    """Findings for one file, deduplicated by rule and line, capped per rule."""

    def __init__(self, path: str, text: str, lines: Lines | None = None, line_offset: int = 0, note: str = "",
                 command: bool = False):
        self.path, self.text, self.lines = path, text, lines or Lines(text)
        self.offset, self.note = line_offset, note
        self.command = command  # a single command line: no comments or test strings to account for
        self.items: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()
        self._per_rule: dict[str, int] = {}

    def add(self, rule_id: str, severity: str | None, pos: int, message: str, context: str, evidence: str | None = None,
            line: int | None = None) -> None:
        if not severity:
            return
        ln = line if line is not None else self.offset + self.lines.line(pos)
        key = (rule_id, ln)
        if key in self._seen:
            return
        count = self._per_rule.get(rule_id, 0)
        if count >= 6:
            return
        self._per_rule[rule_id] = count + 1
        self._seen.add(key)
        ev = evidence if evidence is not None else line_at(self.text, pos)
        self.items.append(Finding(rule_id, severity, self.path, ln, (self.note + message) if self.note else message,
                                  clip(ev), context))

    def has(self, *rule_ids: str) -> bool:
        return any(f.rule in rule_ids for f in self.items)


# Download-and-run severity by where the script comes from. "none" means no URL is visible (a variable).
DOWNLOAD_SEVERITY = {
    "autoexec": {"none": "high", "official": "medium", "unknown": "high", "plain-http": "high", "risky": "critical"},
    "code": {"none": "medium", "official": "low", "unknown": "medium", "plain-http": "low", "risky": "high"},
    "config": {"none": "medium", "official": "low", "unknown": "medium", "plain-http": "low", "risky": "high"},
    # documentation and comments: prose that names the pattern without a URL is not an instruction to run anything
    "doc": {"none": None, "official": None, "unknown": "low", "plain-http": "medium", "risky": "high"},
}
HOST_NOTE = {"official": " (official installer)", "unknown": " from a host that is not an official installer",
             "plain-http": " over plain HTTP", "risky": " from a look-alike domain, raw IP or capture service", "none": ""}


_LOCAL_ONLY = re.compile(r"^(?!.*https?://(?!(?:127\.0\.0\.1|localhost|\[::1\])\b)).*(?:127\.0\.0\.1|localhost|::1)\b")
SECRET_HUNT = re.compile(r"\b(?:api[_ -]?keys?|tokens?|secrets?|credentials?|passwords?|wallets?|seed\s+phrases?|"
                         r"private\s+keys?|mnemonics?|\.env\b|\.ssh\b|\.aws\b|id_rsa|keychain)", re.I)

# An interpreter given its program on the command line reads the piped download as data: perl -wlne '...',
# python -c "...", node -e '...', ruby -e, php -r. (`python -`, `perl -` and `sh -s` read the program from the pipe.)
INLINE_PROGRAM = re.compile(r"[ \t]+(?:-[\w-]+[ \t]+)*?(?:-[a-zA-Z]*[eEp][a-zA-Z]*|-c|-r|--eval|--print|-Command)[ \t]+['\"]")


def _line_window(text: str, start: int, end: int, extra: int = 200) -> str:
    stop = text.find("\n", end)
    stop = len(text) if stop < 0 else stop
    return text[start:min(stop, end + extra)]


def _doc_download_severity(match_text: str) -> tuple[str | None, str]:
    kind = host_kind(match_text)
    return DOWNLOAD_SEVERITY["doc"][kind], HOST_NOTE[kind]


EXEC_ON_LINE = re.compile(r"\b(?:exec(?:Sync|File(?:Sync)?|a)?|spawn(?:Sync)?|system|popen|Popen|check_output|check_call|"
                          r"subprocess\.\w+|shell_exec|passthru|Command::new|ProcessBuilder|Start-Process|Invoke-Expression|"
                          r"iex|eval|Function|run_command|sh|bash)\s*[(`]", re.I)


_STRING = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\\n]|\\.)*`")
_REGEX_LIKE = re.compile(r"\(\?[:!=<iIsmx]|\\[bsdwBSDW]|\[\^|\\[.(|)\[]|\{\d+,\d*\}|\[[^\]\s]{1,30}\][*+?]"
                         r"|(?:[\w.-]+\|){3,}[\w.-]+")


LONG_LINE = 4000  # minified or generated lines: string boundaries there are guesswork, and costly to compute


def _enclosing_string(text: str, pos: int) -> str | None:
    """The single-line string literal around pos, or None (also for very long lines, which keep their findings)."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return None
    line = text[start:end]
    for m in _STRING.finditer(line):
        if m.start() <= pos - start < m.end():
            return m.group()
    return None


def _code_part(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > LONG_LINE:
        return text[max(start, pos - 300):min(end, pos + 300)]
    return _STRING.sub('""', text[start:end])


_TRIPLE = re.compile(r'"""|\'\'\'')
_TRIPLE_CACHE: dict = {}


def _triple_quoted(text: str, pos: int) -> str | None:
    """The triple-quoted string (a Python docstring, a prompt template) around pos, or None."""
    key = (id(text), len(text), text[:32])
    spans = _TRIPLE_CACHE.get(key)
    if spans is None:
        spans, opened, quote = [], None, ""
        for m in _TRIPLE.finditer(text):
            if opened is None:
                opened, quote = m.end(), m.group()
            elif m.group() == quote:
                spans.append((opened, m.start()))
                opened = None
        if len(_TRIPLE_CACHE) > 32:
            _TRIPLE_CACHE.clear()
        _TRIPLE_CACHE[key] = spans
    i = bisect.bisect_right([a for a, _ in spans], pos) - 1
    if i >= 0 and spans[i][0] <= pos < spans[i][1] and spans[i][1] - spans[i][0] <= 20_000:
        return text[spans[i][0]:spans[i][1]]
    return None


def data_string(text: str, pos: int, path: str, context: str) -> bool:
    """A match that is data rather than behavior: inside a regular expression, inside a sentence of prose, or inside
    a string in a test file, on a line whose code does not hand strings to a shell, eval or exec. Detection tools,
    linters and test suites are full of these; a payload passed to exec() is not."""
    literal = _enclosing_string(text, pos)
    if literal is None and path.lower().endswith((".py", ".pyw")):
        literal = _triple_quoted(text, pos)
    if literal is None or EXEC_ON_LINE.search(_code_part(text, pos)):
        return False
    if _REGEX_LIKE.search(literal):
        return True
    words = re.findall(r"[A-Za-z]{3,}", literal)
    if len(words) >= (8 if context == "autoexec" else 6) and literal.count(" ") >= 5 and not re.search(r"https?://", literal):
        return True  # a sentence: rule descriptions, log messages, help text
    return context == "code" and is_test_code(path)


_COMMAND_STRING = re.compile(r"\s*(?:sudo\s+)?(?:curl|wget|nslookup|dig|nc|ncat|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|"
                             r"powershell|pwsh|bash|sh)(?:\.exe)?\s+\S", re.I)


def _named_in_string(text: str, pos: int) -> bool:
    """A network API or tool named inside a string that is not itself a command line: "fetch", "nslookup " in a
    keyword list, an API name in a message. A string like "curl -d @file https://..." still counts, since that is how
    scripts run commands."""
    literal = _enclosing_string(text, pos)
    if literal is None:
        return False
    return not _COMMAND_STRING.match(literal[1:-1]) and not EXEC_ON_LINE.search(_code_part(text, pos))


def _test_data(col: Collector, pos: int) -> bool:
    """Kept for the structural checks: a match inside a string literal in a test file."""
    return data_string(col.text, pos, col.path, "code") and is_test_code(col.path)


_INDEX_FLAG_BEFORE_URL = re.compile(
    r"(?:--index-url|--extra-index-url|--default-index|--index|--find-links|--trusted-host|--registry|-[if])[ =]+[\"']?$")


def _url_is_index_value(match_text: str) -> bool:
    """True when every URL in an install command is the value of an index/registry flag, not a package to install."""
    for m in re.finditer(r"(?:https?://|git\+)\S+", match_text):
        if not _INDEX_FLAG_BEFORE_URL.search(match_text[:m.start()]):
            return False
    return True


def _sev_context(context: str) -> str:
    """Commands an agent is about to run are judged like code that runs on its own."""
    return "autoexec" if context == "agent" else context


def _apply(patterns, col: Collector, text: str, context: str, low: str | None = None) -> None:
    ctx = _sev_context(context)
    low = text.lower() if low is None else low
    code_file = ctx in ("code", "autoexec", "config") and not col.command
    for pat in patterns:
        sev = pat.sev.get(ctx)
        if sev is None or not has(low, pat.need):
            continue
        for m in pat.regex.finditer(text):
            message, severity = pat.message, sev
            if pat.rule == R_URL_INSTALL and _url_is_index_value(m.group(0)):
                continue
            commented = code_file and in_comment(text, m.start(), col.path)
            if pat.message == "pipes a download into an interpreter" and INLINE_PROGRAM.match(text, m.end()):
                continue  # `curl page | perl -ne '...'`: the download is input to a program written on the line
            if pat.rule == R_DOWNLOAD_EXEC:  # the risk depends on where the script comes from
                kind = host_kind(_line_window(text, m.start(), m.end()))
                severity = DOWNLOAD_SEVERITY["doc" if (sev == "doc" or commented) else ctx][kind]
                message += HOST_NOTE[kind] + (" (in a comment)" if commented else "")
            elif pat.rule == R_EXFIL and pat.message == "sends data to a remote host":
                if host_kind(_line_window(text, m.start(), m.end())) == "official":
                    severity = "low"
            elif pat.rule == R_INLINE_NET and (host_kind(_line_window(text, m.start(), m.end())) == "official"
                                               or _LOCAL_ONLY.search(_line_window(text, m.start(), m.end()))):
                # `powershell -c "irm https://astral.sh/... | iex"`: the vendor's own one-liner, judged like a download
                severity = None if ctx == "doc" else "low" if ctx != "autoexec" else "medium"
            elif pat.rule == R_AGENT_BYPASS and ctx == "code" and SECRET_HUNT.search(_line_window(text, m.start(), m.end(), 400)):
                severity, message = "high", message + " and sends it after secrets"
            elif commented and rank(severity) > rank("low"):
                severity, message = "low", message + " (in a comment)"
            if severity and code_file and rank(severity) > rank("low") and data_string(text, m.start(), col.path, ctx):
                severity, message = "low", message + " (in a string that is data: a pattern, a sentence or test input)"
            col.add(pat.rule, severity, m.start(), message, context)


def analyze_command(command: str, path: str, line: int = 0, context: str = "autoexec", note: str = "") -> list[Finding]:
    """Rules for a single command line (hook, script, task, agent Bash call)."""
    ctx = _sev_context(context)
    low = command.lower()
    col = Collector(path, command, line_offset=max(0, line - 1), note=note, command=True)
    _apply(COMMAND_PATTERNS, col, command, context, low)
    for m in SECRET_PATHS.finditer(command) if has(low, SECRET_NEED) else ():
        col.add(R_SECRETS, S("high", "medium", "low", "high").get(ctx) or "high", m.start(), "references " + m.group(),
                context)
    _registry(col, command, context, low)
    _exfil_hosts(col, command, context, low)
    m = AGENT_CONFIG.search(command) if has(low, AGENT_NEED) else None
    if m and WRITE_OP.search(command):
        sev = AGENT_CFG_SEV.get(ctx) or "medium"
        if ctx == "doc" and re.match(r"(?i)\.git[\\/]hooks|core\.hooksPath", m.group()):
            sev = "low"  # contributor guides install git hooks; agent settings are what instruction files must not touch
        col.add(R_AGENT_CFG_WRITE, sev, m.start(), "changes agent configuration " + m.group(), context)
    m = PERSIST.search(command) if has(low, PERSIST_NEED) else None
    if m:
        col.add(R_PERSIST, PERSIST_SEV.get(ctx) or "medium", m.start(), "sets up persistence", context)
    if has(low, ENV_NEED) and ENV_DUMP.search(command) and NETWORK.search(command):
        col.add(R_EXFIL, "critical" if ctx == "autoexec" else "high", 0, "collects the environment and sends it",
                context)
    for blob in decode_blobs(command):
        col.items.extend(analyze_command(blob["text"], path, line, context, note=f"decoded {blob['kind']}: "))
    return col.items


REGISTRY_FLAG = re.compile(
    r"(?:--registry|--index-url|--extra-index-url|--default-index|--index|-i)[ =]+[\"']?(\S+?)[\"']?(?=\s|$)"
    r"|\b(?:npm|pnpm|yarn)\s+config\s+set\s+(?:@[\w-]+:)?registry[ =]+[\"']?(\S+?)[\"']?(?=\s|$)"
    r"|\bpip[0-9.]*\s+config\s+set\s+global\.(?:extra-)?index-url[ =]+[\"']?(\S+?)[\"']?(?=\s|$)", re.I)
_PKG_CMD = re.compile(r"\b(?:npm|pnpm|yarn|bun|npx|pip[0-9.]*|uv|uvx|pipx|poetry|cargo|gem)\b", re.I)


def _registry(col: Collector, text: str, context: str, low: str | None = None) -> None:
    context_sev = _sev_context(context)
    if not has(text.lower() if low is None else low, ("registry", "index", "-i ", "-i=", "config set")):
        return
    for m in REGISTRY_FLAG.finditer(text):
        before = text[max(0, m.start() - 200):m.start()]
        if not _PKG_CMD.search(before) and "config" not in m.group(0):
            continue
        target = next(g for g in m.groups() if g)
        if not re.match(r"https?://", target):
            continue
        kind = classify_host(target)
        if kind == "official":
            continue
        sev = {"autoexec": "high", "doc": "high" if kind in ("lookalike", "raw-ip", "plain-http") else "medium",
               "code": "medium", "config": "high"}.get(context_sev, "high")
        if context_sev in ("code", "autoexec") and not col.command and data_string(text, m.start(), col.path, context_sev):
            sev = "low"
        col.add(R_REGISTRY, sev, m.start(), f"package source set to {host_of(target) or target}", context)


def _exfil_hosts(col: Collector, text: str, context: str, low: str | None = None) -> None:
    # In code that runs on its own, a capture service or raw IP is a beacon. Elsewhere it is often the point of the
    # code (a transfer.sh client); a stealer in ordinary code is caught by secrets + network + destination together.
    sev = S("high", "low", "low", "high").get(_sev_context(context)) or "medium"
    low = text.lower() if low is None else low
    ctx = _sev_context(context)

    def level(pos: int) -> str:
        if ctx in ("code", "autoexec") and not col.command and data_string(text, pos, col.path, ctx):
            return "low"
        return sev

    for m in EXFIL_HOSTS.finditer(text) if has(low, EXFIL_NEED) else ():
        col.add(R_EXFIL_HOST, level(m.start()), m.start(), "contacts " + m.group(0), context)
    for m in RAW_IP_URL.finditer(text) if "://" in text else ():
        if not is_private_ip(m.group(1)):
            col.add(R_EXFIL_HOST, level(m.start()), m.start(), "contacts a raw IP address " + m.group(1), context)


DYNAMIC_EXEC = re.compile(r"(?<![.\w$])(?:exec|eval)\s*\(\s*(?!['\"`)])|\bnew\s+Function\s*\(|\bvm\.run\w*\s*\("
                          r"|\b(?:Invoke-Expression|iex)\b\s*[\($]")
_NET_FALLBACK = re.compile(r"\b(?:https|http|net|dns)\.\w+\(|require\(['\"](?:node:)?https?['\"]\)")
_SECRET_KINDS = (("ssh", (".ssh", "id_rsa", "id_ed25519", "id_ecdsa")), ("aws", (".aws",)),
                 ("gcloud", ("gcloud", "application_default")), ("azure", (".azure",)), ("kube", (".kube",)),
                 ("docker", (".docker",)), ("git", (".git-credentials", "hosts.yml")), ("netrc", (".netrc",)),
                 ("pypi", (".pypirc",)), ("ai-tools", (".claude", ".codex", ".gemini", "openclaw", ".cline", ".continue",
                                                        "state.vscdb", ".copilot", "github-copilot")),
                 ("browser", ("login data", "cookies", "local state", "web data", "key3.db", "key4.db", "logins.json")),
                 ("wallet", ("wallet.dat", "exodus", "electrum", "nkbihfbeogaeaoehlefnkodbefgpgknn",
                             "bfnaelmomeimhlpmgjnjophhpkkoljpa")), ("keychain", ("keychain",)))


_OPEN_QUOTES = "\"'`\u201c\u2018\u00ab"
_CLOSE_QUOTES = "\"'`\u201d\u2019\u00bb"


def _quoted_mention(text: str, start: int, end: int) -> bool:
    """The phrase is quoted as an example (`like "Ignore all previous instructions"`), not addressed to anyone."""
    before = text[max(0, start - 3):start].rstrip()
    after = text[end:end + 60]
    return bool(before) and before[-1] in _OPEN_QUOTES and any(q in after for q in _CLOSE_QUOTES)


def _secret_kinds(matches) -> set[str]:
    kinds = set()
    for m in matches:
        low = m.group().lower()
        kinds.update(name for name, words in _SECRET_KINDS if any(w in low for w in words))
    return kinds


def _close(anchors: list[int], others: list[int], limit: int) -> int | None:
    """The first anchor with one of the other positions within limit characters, or None."""
    others = sorted(others)
    for a in anchors:
        i = bisect.bisect_left(others, a)
        if any(0 <= j < len(others) and abs(others[j] - a) <= limit for j in (i - 1, i)):
            return a
    return None


def scan_text(text: str, path: str, context: str, *, decode: bool = True, structural: bool = True,
              note: str = "", line_offset: int = 0) -> list[Finding]:
    """All content rules for one text. Structural checks (invisible characters, padding) run on original text only."""
    col = Collector(path, text, line_offset=line_offset, note=note)
    is_code = context in ("code", "autoexec")
    low = text.lower()
    if structural:
        _structural(col, text, path, context)
    if context in ("doc", "config"):
        # Prose and code examples in documentation are talk about code. The documents agents follow (README, setup
        # guides, AGENTS.md, rules, skills) have their commands extracted and judged separately; here only hidden
        # content and text addressed to AI reviewers count. Structured files that run something are read by their
        # handlers; for the rest (data, results, settings of tools nothing here starts) the same holds.
        for m in AI_ADDRESSED.finditer(text) if has(low, AI_NEED) else ():
            if not _quoted_mention(text, m.start(), m.end()):
                col.add(R_AI_ADDRESSED, AI_SEV.get(context), m.start(), "addresses an AI reviewer or agent", context)
        return col.items
    _apply(COMMAND_PATTERNS, col, text, context, low)

    def live(matches, cap: int = 400) -> list[re.Match]:
        """Matches that can do something: not in whole-line comments, not in strings that are only data."""
        out = []
        for m in matches:
            if not in_comment(text, m.start(), path) and not (is_code and data_string(text, m.start(), path, context)):
                out.append(m)
                if len(out) >= cap:
                    break
        return out

    secrets = list(SECRET_PATHS.finditer(text)) if has(low, SECRET_NEED) else []
    for m in secrets[:6]:
        sev = SECRET_SEV.get(context)
        if sev and rank(sev) > rank("low") and in_comment(text, m.start(), path):
            sev = "low"
        col.add(R_SECRETS, sev, m.start(), "references " + m.group(), context)
    secrets = live(secrets)
    env = next(iter(live(ENV_DUMP.finditer(text), 1)), None) if has(low, ENV_NEED) else None
    if env:
        col.add(R_ENV_DUMP, ENV_SEV.get(context), env.start(), "serializes the environment", context)
    nets: list[int] = []
    if (is_code or context == "config") and has(low, NET_NEED):
        nets = [m.start() for m in live(NETWORK.finditer(text)) if not _named_in_string(text, m.start())]
    if not nets and is_code and has(low, ("http", "net.", "dns.")):
        nets = [m.start() for m in live(_NET_FALLBACK.finditer(text)) if not _named_in_string(text, m.start())]
    sends = live(SEND_DATA.finditer(text), 50) if nets and context == "autoexec" else []
    if nets and context == "autoexec":
        url_matches = live(_URL.finditer(text), 2000)
        foreign = [m for m in url_matches if classify_host(m.group()) not in ("official", "reference")]
        # The request and its destination sit together in a beacon; a reference link elsewhere in the file is not one.
        near = _close([m.start() for m in sends], [m.start() for m in foreign], 3000)
        if near is not None:
            host = host_of(min(foreign, key=lambda m: abs(m.start() - near)).group())
            col.add(R_EXFIL, "high", near, f"sends data out while installing or opening (to {host})", context)
        elif sends and not url_matches:
            col.add(R_EXFIL, "high", sends[0].start(), "sends data out while installing or opening (to an address "
                    "assembled at run time)", context)
        else:
            col.add(R_NET_AUTO, "low", nets[0], "network call in code that runs automatically", context)
    for m in DOWNLOAD_THEN_RUN.finditer(text) if context in ("autoexec", "code") and has(low, ("curl", "wget")) else ():
        commented = in_comment(text, m.start(), path)
        kind = host_kind(m.group())
        sev = DOWNLOAD_SEVERITY["doc" if commented else context][kind]
        col.add(R_DOWNLOAD_EXEC, sev, m.start(), f"downloads {m.group(1)} and then makes it executable or runs it"
                + HOST_NOTE[kind], context)
        break
    if nets and is_code and has(low, ("exec", "eval", "function", "vm.run", "iex", "invoke-expression")):
        # Fetch, then exec/eval what came back: the two steps are usually a few lines apart, not one expression.
        runs = [m.start() for m in live(DYNAMIC_EXEC.finditer(text), 50)]
        # the fetch comes first and the exec follows within a few lines
        hit = next((r for r in runs if any(0 < r - n <= 800 for n in nets)), None)
        if hit is not None and not col.has(R_DOWNLOAD_EXEC):
            near_net = max(n for n in nets if n < hit)
            kind = host_kind(text[max(0, near_net - 300):near_net + 300])
            sev = DOWNLOAD_SEVERITY[context][kind]
            if kind == "official" and context == "autoexec":
                sev = "high"  # nobody needs to eval a download from an official host at install time
            if context == "code" and kind == "none":
                sev = "low"  # no destination in sight: plugin loaders and test harnesses do this
            col.add(R_DOWNLOAD_EXEC, sev, hit, "fetches code over the network and executes it" + HOST_NOTE[kind], context)
    _exfil_hosts(col, text, context, low)
    _registry(col, text, context, low)
    if is_code and nets and (secrets or env):
        anchors = [m.start() for m in secrets] + ([env.start()] if env else [])
        # Install-time code has no reason to touch credentials at all; elsewhere the read and the send have to be
        # near each other, as they are in a stealer, rather than a keyword list and an HTTP client in one module.
        anchor = _close(anchors, nets, len(text) if context == "autoexec" and len(text) <= 100_000 else 4000)
        if anchor is not None:
            dest = bool((has(low, EXFIL_NEED) and live(EXFIL_HOSTS.finditer(text), 1))
                        or any(not is_private_ip(m.group(1)) for m in live(RAW_IP_URL.finditer(text), 50)))
            kinds = _secret_kinds(secrets)
            if context == "autoexec":
                sev = "critical"
            elif dest or len(kinds) >= 3:
                sev = "high"
            elif len(kinds) == 2 or (env and live(SEND_DATA.finditer(text), 1)):
                sev = "medium"
            else:
                sev = "low"  # one credential file and a network library: an HTTP client reading ~/.netrc
            col.add(R_EXFIL, sev, anchor, "reads secrets or the environment and makes network requests"
                    + (f" ({len(kinds)} kinds of credentials)" if len(kinds) > 1 else ""), context)
    for m in live(PERSIST.finditer(text), 1) if has(low, PERSIST_NEED) else ():
        col.add(R_PERSIST, PERSIST_SEV.get(context), m.start(), "sets up persistence", context)
    for m in live(AGENT_CONFIG.finditer(text), 50) if is_code and has(low, AGENT_NEED) else ():
        # the write and the path belong to the same statement: this line and its neighbours
        start = text.rfind("\n", 0, text.rfind("\n", 0, m.start())) + 1
        stop = text.find("\n", text.find("\n", m.end()) + 1)
        window = text[start:stop if stop >= 0 else len(text)]
        if not WRITE_OP.search(window):
            continue
        # Changing the agent configuration in your home folder reaches every project and session; a project's own
        # instruction files are its maintainers' business unless install-time code rewrites them.
        home = bool(GLOBAL_HINT.search(window))
        instructions = bool(INSTRUCTION_FILE.search(m.group()))
        if context == "autoexec":
            sev = "critical" if home else ("medium" if instructions else "high")
        else:
            sev = "medium" if home and not instructions else "low"
        if context == "code" and re.match(r"(?i)\.git[\\/]hooks|core\.hooksPath|\.vscode", m.group()):
            sev = "low"  # git-hook managers and editor tooling write these as their job
        col.add(R_AGENT_CFG_WRITE, sev, m.start(), "writes " + m.group() + (" in your home folder" if home else ""), context)
        break
    for m in AI_ADDRESSED.finditer(text) if has(low, AI_NEED) else ():
        if context == "code" and not in_comment(text, m.start(), path):
            continue
        literal = _enclosing_string(text, m.start()) if is_code else None
        if literal is not None and (_REGEX_LIKE.search(literal) or (context == "code" and is_test_code(path))):
            continue  # a detection pattern or a test input, not a message to a reviewer
        if _quoted_mention(text, m.start(), m.end()):
            continue  # an example being warned about: 'if a page says "ignore all previous instructions", do not'
        col.add(R_AI_ADDRESSED, AI_SEV.get(context), m.start(), "addresses an AI reviewer or agent", context)
    if is_code:
        obf = OBF_IDENT.findall(text) if "_0x" in low else []
        signature = OBF_SIGNATURE.search(text) if obf else None
        sample = signature is not None and data_string(text, signature.start(), path, context)
        if len(obf) >= 10 and signature:
            col.add(R_OBFUSCATED, "low" if sample else "high", signature.start(), f"obfuscator.io signature ({len(obf)} "
                    "_0x identifiers, string-array rotation or decoded member names)"
                    + (" in a string that is data" if sample else ""), context)
        elif len(obf) >= 25:
            col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", text.find(obf[0]),
                    f"{len(obf)} obfuscator-style identifiers", context)
        m = (PACKER.search(text) if has(low, ("eval", "pyarmor")) else None) or (JSFUCK.search(text) if "[]" in text else None)
        if m and not data_string(text, m.start(), path, context):
            col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", m.start(), "packed or JSFuck code", context)
        bad = any(f.rule in (R_DOWNLOAD_EXEC, R_DECODE_EXEC, R_EXFIL, R_PERSIST, R_EXFIL_HOST, R_AGENT_BYPASS)
                  and rank(f.severity) >= rank("medium") for f in col.items)
        gated = has(low, ("date", "process.env", "os.environ", "platform", "time.time"))
        cond = next(iter(live(CONDITIONAL.finditer(text), 1)), None) if gated else None
        date_gate = next((m for m in live(FUTURE_DATE_GATE.finditer(text), 20) if _future_gate(m)), None) if gated else None
        if cond and bad:
            col.add(R_CONDITIONAL, "medium", cond.start(), "suspicious code is gated on CI, date or platform", context)
        elif date_gate and nets and cond:
            col.add(R_CONDITIONAL, "high", date_gate.start(), "network code that runs only in CI or after a set date "
                    "(a logic bomb)", context)
        elif date_gate and nets:
            col.add(R_CONDITIONAL, "medium", date_gate.start(), "network code gated on a date that has not come yet", context)
    if decode:
        for blob in decode_blobs(text):
            found = scan_text(blob["text"], path, context if context != "doc" else "code", decode=False,
                              structural=False, note=f"decoded {blob['kind']}: ",
                              line_offset=col.lines.line(blob["pos"]) - 1)
            for f in found:
                f.line = col.lines.line(blob["pos"])
                col.items.append(f)
            if found and not any(f.rule == R_DECODE_EXEC for f in col.items):
                col.add(R_OBFUSCATED, "high" if context == "autoexec" else "medium", blob["pos"],
                        f"{blob['kind']} blob decodes to code flagged above", context)
    return col.items


def _strings_in_test(text: str, path: str, context: str, item: dict) -> bool:
    """Every occurrence sits inside a string literal of a test file: test data for text handling."""
    return context == "code" and is_test_code(path) and all(in_string_literal(text, p) for p in item.get("positions", [item["pos"]]))


def _structural(col: Collector, text: str, path: str, context: str) -> None:
    is_code = context in ("code", "autoexec")
    for item in invisible(text):
        kind, pos = item["kind"], item["pos"]
        if item.get("decoded") and len(item["decoded"]) >= 8:
            hidden = scan_text(item["decoded"], path, "code" if context == "doc" else context, decode=True,
                               structural=False, note="hidden in invisible characters: ",
                               line_offset=col.lines.line(pos) - 1)
            for f in hidden:
                f.line = col.lines.line(pos)
            col.items.extend(hidden)
        if kind == "tags":
            sev = "critical" if context in ("doc", "config", "autoexec") else "high"
            col.add(R_TAGS, sev, pos, f"{item['count']} tag characters hide: {item['decoded'][:160]!r}", context)
        elif kind == "selectors":
            sev = "high" if item["count"] >= 4 else "medium"
            if is_code and item["count"] >= 4:
                sev = "critical" if context == "autoexec" else "high"
            col.add(R_SELECTORS, sev, pos, f"{item['count']} variation selectors decode to: {item['decoded'][:160]!r}",
                    context)
        elif kind == "bidi":
            sev = "high" if is_code else ("medium" if context in ("doc", "config") else "low")
            note = ""
            if _strings_in_test(text, path, context, item):
                sev, note = "low", " (inside string literals in a test file)"
            col.add(R_BIDI, sev, pos, f"{item['count']} bidirectional control characters{note}", context)
        elif kind == "zero-width":
            sev = ("medium" if item["count"] < 10 else "high") if is_code else "low"
            note = ""
            if _strings_in_test(text, path, context, item):
                sev, note = "low", " (inside string literals in a test file)"
            elif is_code and all(in_comment(text, p, path) for p in item.get("positions", [pos])):
                sev, note = "low", " (in comments)"  # a pasted typo; identifiers are where these deceive
            col.add(R_ZERO_WIDTH, sev, pos, f"{item['count']} zero-width characters{note}", context)
        elif kind == "filler":
            col.add(R_ZERO_WIDTH, "high" if is_code else "medium", pos, f"{item['count']} Hangul filler characters "
                    "(invisible identifiers)", context)
    for item in padding(text, doc=context == "doc"):
        if item["kind"] == "blank-lines":
            sev = "high" if context in ("autoexec", "doc") or item["count"] >= 2000 else "medium"
            col.add(R_PAD_LINES, sev, item["pos"], f"content after {item['count']:,} blank lines", context)
        else:
            sev = "high" if is_code or context == "doc" else "low"  # in data files, wide values are just data
            note = ""
            if context == "code" and is_test_code(path) and in_string_literal(text, item["pos"]):
                sev, note = "low", " (inside a string literal in a test file)"
            col.add(R_PAD_SPACES, sev, item["pos"], f"code after {item['count']:,} spaces{note}", context)
    minified = bool(re.search(r"(?:\.min\.|[\\/](?:dist|build|vendor|umd|bundles?)[\\/])", path, re.I))
    for pos, length in long_lines(text, 5000):
        if length >= 1_000_000:
            sev = "high" if context == "autoexec" else "medium"
        elif length >= 100_000 and not minified:
            sev = "medium" if context == "autoexec" else "low"
        else:
            sev = "low" if (context == "autoexec" and not minified) else None
        col.add(R_LONG_LINE, sev, pos, f"one line of {length:,} characters", context,
                evidence=text[pos:pos + 120])
        break
    if path.lower().endswith((".md", ".mdc", ".markdown", ".html", ".htm")):
        from .surfaces import AUTO_LOADED  # instruction files agents load on their own

        auto = bool(AUTO_LOADED.search(path))
        for m in HIDDEN_HTML.finditer(text):
            body = m.group(1)
            addressed = AI_ADDRESSED.search(body)
            if addressed or re.search(r"\b(?:run|execute|install|download|curl|wget|npx|pip install)\b", body, re.I):
                sev = ("high" if addressed else "medium") if auto else ("medium" if addressed else "low")
                col.add(R_HIDDEN_COMMENT, sev, m.start(), "an HTML comment carries instructions", context,
                        evidence=body[:200])
