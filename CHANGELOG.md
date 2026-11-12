# Changelog

## 0.2.0 (2026-11-12)

personal-anti-hack now does an antivirus's job for people who use AI agents, and new checks cover the attacks
reported between September and November 2026, chosen by comparing the rules with the leading scanners (GuardDog,
Socket, Cisco's skill and MCP scanners, Snyk agent-scan, zizmor, malcontent) and with the configuration files each
agent documents. 108 rules, 17 of them new.

**Antivirus duties**
- `pah sweep`: a full scan of this computer, one item at a time: Downloads and Desktop, every project in your code
  folders, installed agent skills, plugins and extensions, editor extensions; plus the checkup and the engine built
  into the operating system (Microsoft Defender) or ClamAV. Unchanged items are remembered between sweeps.
- `pah protect`: real-time protection that scans new downloads, clones, extensions, skills and startup items within
  seconds of arriving, with a desktop notification; `--install` starts it at login (Task Scheduler, a LaunchAgent or a
  systemd user service) after showing the change.
- `pah quarantine`: blocked items move into quarantine (a download, extension or skill as a whole; a project only by
  its payload files) and `restore` puts them back.
- The trojanized Claude Code extension's backdoor shapes: switching on the SSH server and a reverse tunnel to port 22.

**More agents' files**
- Hooks a repository ships for Codex, GitHub Copilot (`.github/hooks`), Kiro, Devin, Cline, Factory, Augment and
  Amazon Q; plugins for OpenCode, Kilo and Amp; Crush's startup script; Gemini CLI and Qwen Code tool commands;
  Cursor's sandbox and permission overrides; cloud-agent setup commands (Cursor, Devin); Aider's startup commands.
- Claude Code plugins: a plugin's `hooks/hooks.json`, marketplaces and plugins a project asks you to install, skill
  shell lines (`` !`cmd` ``) and `allowed-tools: Bash`, HTTP hooks, a loosened sandbox and new command settings.
- `.env` and settings that relocate an agent (`GEMINI_CLI_HOME`, `GEMINI_SYSTEM_MD`) or put the repository first on
  `PATH`; a `git.exe` planted at the top of the repository; bare git repositories inside a project; terminal escape
  codes that hide text; a `__proto__` key in VS Code workspace files.

**Campaign shapes**
- Loaders disguised as fonts and images (PolinRider), dead drops on blockchains and paste sites, worms that republish
  your packages with your token, CI backdoors, wipers that fire when a stolen token is revoked, wallet hijackers,
  hidden processes and secret sweeps at install time, payloads read out of image pixels.
- GitHub workflows: secrets sent out (GhostAction; blocks), untrusted text pasted into scripts, and AI agent actions
  that act on anyone's issue (both reported to maintainers through SARIF).
- Package managers: project settings that undo the install protections of npm 12, pnpm 11, Yarn and Bun; `bin`
  entries named after system commands.
- `pah checkup` knows the traces of PolinRider, the testmetest worm, MALFEX, SleepyDuck, Apex Accelerator and the
  trojanized Claude Code extension.

**Fewer false alarms**
- Detection tables in JavaScript (regular expressions and their labels), a local server's responses, reads of
  `git config core.hooksPath`, git installs pinned to a commit, skills' own test suites, and skills that only mention
  folders under `~/.claude`.

**Measured**
- TrapRepo: 15 new cases; 63 of 63 malicious repositories caught, 0 of 33 benign flagged.
- Attack drill across nine hook protocols: 951 decisions, 0 unexpected.
- 30 widely used repositories, everything-claude-code now among them: 26 pass, 4 warn, none blocked.

## 0.1.0 (2026-11-12)

First release.

**Scanner**
- `pah scan` maps everything in a repository, skill, MCP server, package, archive or git URL that runs without being
  read, reads every file in full (hidden Unicode, padding, encoded blobs, bytecode, archives, disguised binaries) and
  judges each finding by where the file really runs. 91 rules, each tied to an incident, CVE or paper.
- `pah audit` adds the antivirus engine already on the computer (Microsoft Defender or ClamAV) and, with `--online`,
  malicious, missing and brand-new packages and known vulnerabilities in pinned versions (OSV).
- Output as text (English or Korean), JSON or SARIF.

**Guard and agents**
- One guard for Claude Code, Codex, Gemini CLI, Antigravity, Cursor, Copilot, Devin, Kiro and Cline, each through its
  own hook protocol. Setup commands in a project that fails the scan are denied; agent settings, shell profiles and git
  hooks need your approval.
- `pah install` writes each agent's hooks, the skills and the MCP server, and shows every change first.
- Four Agent Skills: everyday rules, malware audit, security review, incident response. `AGENTS.md` lets any agent use
  the repository directly.
- `pah watch` keeps a baseline of agent and shell configuration; `pah checkup` looks for exposed keys and known traces.

**CI**
- A GitHub Action: annotations on the lines in pull requests, a job summary, a verdict output and a SARIF report for
  code scanning. `pah scan --github` and `--sarif-out` do the same from the command line.
- A pre-commit hook.

**Measured**
- TrapRepo: 54 of 54 malicious repositories caught, 0 of 27 benign look-alikes flagged.
- Attack drill across nine hook protocols: 816 decisions, 0 unexpected.
- Live drill with Claude Code and approvals off: the payload ran in 0 of 12 runs.
- 29 widely used repositories scanned in full: none blocked.
