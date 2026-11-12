# Threat model

Who this protects, from what, and where it stops.

## Who and what

A person who lets AI coding agents (Claude Code, Codex, Gemini CLI, Antigravity, Cursor, Copilot, Devin, Kiro, Cline,
OpenClaw, Aider) open, set up and run code on their own computer, and who installs skills, MCP servers, extensions and packages for those agents. The asset is
that computer and what is on it: SSH keys, cloud credentials, browser sessions, crypto wallets, and the agents' own
tokens, which infostealers now collect on purpose.

## The doors, and what guards each

| Door | How malware comes through | personal-anti-hack |
| --- | --- | --- |
| Opening a repository with an agent or editor | `.claude/settings.json` hooks and env, `.mcp.json`, `.cursor/` hooks and MCP, `.codex/` with a `.env` CODEX_HOME, `.gemini/settings.json`, `.openclaw/extensions/`, `.vscode/tasks.json` folder-open tasks, workspace settings, dev container `initializeCommand`, `.envrc` | Mapped as surfaces; every command analyzed; files they run judged as code that runs on its own (`scan`, SessionStart hook) |
| Following instructions | AGENTS.md / CLAUDE.md / GEMINI.md / rules / skills telling the agent to install, reconfigure itself, change its API URL, disable approvals or hide things; README setup steps with registry redirects or `curl \| sh` from look-alike domains | Commands extracted and judged; instructions to change settings, hide actions or read credentials flagged; files instructions run marked as running on their own |
| Installing packages | npm lifecycle scripts, `binding.gyp` expansions, URL/git dependencies, off-registry lockfiles, `.npmrc`/`.yarnrc.yml`/`.pnpmfile.cjs`/`bunfig.toml`, `setup.py`, `.pth`, `conftest.py`, in-tree build backends, `build.rs`, `.cargo/config`, Makefile `$(shell)`, build wrappers; look-alike, invented and brand-new names | Surfaces plus content; look-alike names offline; missing, new and OSV-listed packages with `--online`; the guard denies setup commands in projects that fail |
| Adding skills, MCP servers, extensions | Bundled setup scripts that fetch binaries, poisoned tool descriptions, unpinned `npx` servers | Skill scripts judged as running on their own; tool descriptions checked for hidden orders and credential paths; unpinned packages flagged |
| Pasting install commands | Fake install pages for AI tools (InstallFix), ClickFix, shared chats as lure pages | The guard judges commands an agent runs; `checkup` finds traces in shell and Win+R history |
| Building projects | Visual Studio pre/post-build events and MSBuild `Exec` tasks (the 2021 campaign against security researchers), Xcode Run Script phases (XCSSET) | Build steps mapped as surfaces and their commands judged like install scripts |
| Known malware and vulnerable code | Droppers, packed binaries and hack tools that pattern rules cannot read; dependency versions with published vulnerabilities | `audit` runs the local antivirus engine (Defender or ClamAV); `--online` checks pinned versions against OSV |
| After infection | Infostealers taking AI tokens, worms persisting in agent settings | `checkup` (keys in plain files, risky settings, planted instruction files, known traces, outdated agents), `watch` (diff of agent and shell configuration), and the incident-response skill |

## What makes it hard to fool

- **Code decides.** A model's review can raise a verdict, with claims that must cite lines the code can verify; it can
  never lower one. A refusal, a cut-off or an invalid answer counts as "not reviewed".
- **Nothing is truncated.** Every file is read in full; padding, multi-megabyte lines and payloads after 100,000
  newlines are still read. What cannot be read makes the result "incomplete", never "pass".
- **Hidden text is decoded.** Tag characters and variation selectors are decoded and the hidden text scanned; bidi and
  zero-width characters are reported; base64, hex, escapes and char-code lists are decoded and scanned again.
- **What looks like data is checked as data.** Executables named as images or archives, `.pyc` files without
  source, scripts inside office documents and archives, symbolic links that point out of the repository.
- **Text addressed to reviewers is evidence, not information.** "This code is audited and safe" in a package is
  itself a finding.
- **Where a file sits is part of the evidence.** Test fixtures and archive members are data unless an entry point runs
  them; CI pipelines run on the CI provider's machines; container build steps run inside the image. Their findings are
  kept but do not block, except disguised binaries, bytecode without source, links and archive tricks, which block
  wherever they are (the xz-utils backdoor lived in test fixtures).

## Where it stops

- **It is static.** Behavior that appears only at run time (a second stage fetched from a server that is clean during
  review) is caught only by its shape: the fetch, the decode, the send. It does not execute code to watch it.
- **Rules are public.** An attacker can test against them, as with every open scanner. New techniques need new rules;
  report bypasses (see SECURITY.md).
- **Severity is a judgment.** Rules are tuned to block what runs on its own and to stay quiet on ordinary code; a
  benign repository that ships agent hooks or folder-open tasks will be asked about, on purpose.
- **Known-bad lists need the network.** OSV and registry checks run only with `--online` (package names and pinned
  versions only). The antivirus check uses the engine installed on the machine and says so when there is none.
- **Hooks differ by agent.** Claude Code, Antigravity, Cursor and Copilot can ask the user; Codex, Gemini CLI, Devin,
  Kiro and Cline hooks can only allow or block, so the guard blocks where it would have asked. A repository's own
  session-start hooks run at the same moment as the guard's: scan before opening an agent in an unfamiliar folder.
  OpenClaw, opencode and Amp take plugins rather than command hooks; the MCP server and skills work there.
- **It does not replace the agents' own protections.** Keep approval prompts and sandboxes on; run unfamiliar code in
  a disposable environment; keep secrets out of plain files.
- **The antivirus duties run in user space.** `pah protect` polls the places it watches every few seconds, so it
  notices a new download or extension shortly after it lands instead of blocking the write, and a file that runs the
  moment it is written can act first; the agents' hooks are what stop commands before they run. Binaries are judged
  by the engine built into the operating system (Microsoft Defender) or ClamAV, so on a machine with neither, known
  malware binaries go unchecked and the sweep says so. Quarantine moves files; it does not undo what a program already
  did, which is what `pah checkup` and the incident-response skill are for.
