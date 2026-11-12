# Changelog

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
