# Research behind personal-anti-hack

The evidence this tool is designed from, current to 2026-11-11: how malware reaches people who use AI coding agents (Claude Code, Codex, Cursor, Gemini CLI, OpenClaw, MCP servers, Agent Skills), why language-model review misses it, what existing defenses cover, and what the strongest security projects have in common. Every rule in [rules.md](rules.md) cites the incident or study it comes from; this page collects them.

**Legend.** **[V]** checked against the primary source. **[R]** as reported by the linked source, not independently re-checked. **[?]** unverified or conflicting.

## 1. How malware reaches people who use AI tools

| Door | What happened | Source |
|---|---|---|
| Opening a repo with an agent or IDE | Miasma worm (Jun 2026) planted Claude/Gemini `SessionStart` hooks, a Cursor rule and a VS Code `folderOpen` task; GitHub disabled 73 Microsoft repos [R] | [StepSecurity](https://www.stepsecurity.io/blog/miasma-worm-hits-microsoft-again-azure-functions-action-and-72-other-repositories-disabled-after-supply-chain-attack-targeting-ai-coding-agents), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-agent-instruction-file-poisoning-20261027/) |
| | Fake job-interview repos deliver StoatWaffle through `.vscode/tasks.json` with `"runOn": "folderOpen"` [R] | [InfoWorld](https://www.infoworld.com/article/4149285/new-stoatwaffle-malware-auto%E2%80%91executes-attacks-on-developers-2.html) |
| | Claude Code project files could run code or leak the API key before the trust prompt (CVE-2025-59536, CVE-2026-21852; both patched, no known exploitation) [R] | [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files/) |
| Following instructions in files | A 13 KB `AGENTS.md` posing as engineering guidelines, dropped in `~/Downloads` by a website: Codex first changed its machine-wide settings, then installed the malicious npm package `function-color`, in more than 90% of attempts. A `CLAUDE.md` variant got Claude Code to route its requests to an attacker server about 50% of the time, exposing the login token. The researchers say there is nothing for the vendors to patch, so users must defend themselves. About half of the firm's customers run a coding agent in Downloads [V] | [Help Net Security, 2026-10-26](https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/) |
| | Agents install whatever setup docs list. Registry redirection is missed almost everywhere, near-miss names (azurecore for azure-core) slip through, and whether an attack is caught depends on the harness-model pair. A deterministic pre-install check of names, sources and versions closes most of the gap [V, abstract only; per-agent numbers R] | [Bagmar & Saraf, arXiv 2607.15143](https://arxiv.org/abs/2607.15143) |
| | Clinejection (Feb 2026): text in a GitHub issue title hijacked Cline's triage bot, leading to a stolen npm token; `cline@2.3.0` installed OpenClaw globally from its postinstall script [R] | [Snyk](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions) |
| Installing packages | PhantomRaven: 126 npm packages showing "0 dependencies" that fetch the payload from URL dependencies at install [R]. Phantom Gyp: 57 packages running code through `binding.gyp` [R]. LiteLLM compromise through a `.pth` file [R]. Shai-Hulud: at least seven waves Sep 2025 to Aug 2026; the credential sweep grew from 189 to 469 file paths including Cursor, OpenClaw and Codex configs; Mini Shai-Hulud persisted through `.claude/settings.json` hooks [R] | [Koi](https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies), [Snyk](https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp), [FutureSearch](https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/), [Socket](https://socket.dev/glossary/shai-hulud), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-shai-hulud-ai-credential-expansion-2026090/) |
| | Slopsquatting: the hallucinated name `react-codeshift` appeared in 47 AI-generated skills copied into 237 repos [R]. Across 16 LLMs, 5.2% (commercial) and 21.7% (open) of suggested packages were hallucinated [R] | [Aikido](https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands), [USENIX Security '25](https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen) |
| Adding skills, MCP servers, extensions | ClawHavoc: 341 malicious skills among 2,857 on ClawHub (1 Feb 2026), 824 by 16 Feb, mostly delivering the AMOS stealer [R]. A trojanized Claude Code extension sat on Cursor's marketplace for about 11 hours on 29 Oct 2026, up to 5,000 installs, planting an SSH key [R]. `postmark-mcp` (Sep 2025) BCC'd every email it sent [R] | [Koi](https://koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting), [Sophos](https://www.sophos.com/en-us/blog/malicious-claude-code-extension-distributed-through-cursor-marketplace), [THN](https://thehackernews.com/2025/09/first-malicious-mcp-server-found.html) |
| Pasting install commands | "InstallFix" (Mar 2026): Google ads led to cloned Claude Code install pages whose one-liners (`curl … \| zsh`, `mshta https://…`) installed the Amatera and Cuckoo stealers [R]. Straiker counted 88 lure domains, 30+ for Claude Code [R]. Shared ChatGPT, Grok and claude.ai chats were used as lure pages (AMOS, MacSync) [R]. Fake-CAPTCHA (ClickFix) incidents rose 563% in 2025 [R]. Sophos: of 38 malicious-AI cases (Jul 2025 to Jun 2026), 30 were fake AI software and Claude was the lure in 26 [R] | [Help Net Security](https://www.helpnetsecurity.com/2026/03/09/fake-claude-code-install-pages-installfix-attacks/), [Bitdefender](https://www.bitdefender.com/en-us/blog/labs/fake-claude-code-google-ads-malware), [Straiker](https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign), [Huntress](https://www.huntress.com/blog/fake-claude-macsync), [CrowdStrike](https://www.crowdstrike.com/en-us/blog/how-clickfix-attacks-work-and-how-to-stop-them/), [Sophos](https://www.sophos.com/en-us/blog/fake-ai-real-malware-attackers-impersonating-ai-brands) |
| Turning your own AI CLIs against you | s1ngularity/Nx (Aug 2025) ran Claude Code, Gemini CLI and Amazon Q with their permission checks bypassed; 2,349 secrets from 1,079 machines [R]. QUIETVAULT uses AI CLIs already on the machine to hunt for secrets [R]. Amazon Q v1.84.0 shipped a wiper prompt [R] | [GitGuardian](https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/), [Google GTIG](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), [The Register](https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/) |

### After infection: AI-token theft

- WardenStealer: more than 130,000 infections since 2026-08-03. It takes Claude Code OAuth tokens (including MCP server tokens) and Codex `auth.json` [R] ([SpyCloud](https://spycloud.com/blog/infostealers-now-target-ai-tokens-and-api-keys/)).
- Aokigahara's `aisessions` module reads `.claude.json`, `.codex/auth.json`, Cursor/Windsurf/VS Code `state.vscdb`, `.gemini/.env`, `.copilot/hosts.json` and the Claude/ChatGPT Store-app caches [R] ([Check Point](https://research.checkpoint.com/2026/infostealer-riding-the-ai-train/)).
- A Vidar variant took `openclaw.json` (with the gateway token), `device.json` and `MEMORY.md` [R] ([Hudson Rock](https://www.infostealers.com/article/hudson-rock-identifies-real-world-infostealer-infection-targeting-openclaw-configurations/)). ACRStealer takes Cline and Continue keys [R].
- A password change does not cancel stolen tokens; sessions must be revoked and tokens rotated [R] (SpyCloud, above).

## 2. Why conventional LLMs miss it

- **Size and dilution.** Cloudflare (2026-04-29), 7 models, 18,400 calls, 100 malicious Workers: 67.3% baseline detection. Files over 3 MB: 17.6% (12.3–13.6% with injected comments). Deceptive comments making up under 1% of a file cut detection to 53.3%; very dense comments raised it instead. Their conclusion: structural obfuscation beats linguistic deception. Their advice: strip comments before analysis, keep functional code when truncating, anonymise names, ask attack-specific questions, check safety claims against behavior [V] ([Cloudflare](https://www.cloudflare.com/cloudforce-one/research/adversarial-deception-a-study-of-indirect-prompt-code-injection/)).
- **Scanners bypassed in under an hour.** Trail of Bits (2026-06-03) beat five products (ClawHub's pipeline, Cisco skill-scanner, and Gen, Socket and Snyk on skills.sh) with four skills: about 100,000 leading newlines (the harness truncates large files), a payload in shipped `.pyc` bytecode, scripts hidden inside a DOCX, and a registry-redirecting config framed as a compliance policy that talked the LLM scanner into approving. Three of four took under an hour. Their message: don't outsource trust to a scanner; pin versions, limit permissions, monitor at runtime [V] ([CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/)).
- **LLM-only recall is low.** On 6,420 malicious npm packages, SocketAI (LLM) had 98.2% precision but 44.4% recall; GuardDog (rules) 89.9% recall [R] ([arXiv 2603.27549](https://arxiv.org/html/2603.27549v2)). 13 LLMs on 4,070 PyPI packages located the malicious lines at F1 0.48; code length was the only significant factor [R] ([arXiv 2602.16304](https://arxiv.org/abs/2602.16304)). LLM scanners analysed only 69–86% of large npm files before preprocessing [R] ([CASHEWS, arXiv 2609.18862](https://arxiv.org/abs/2609.18862)). Miasma's payload was a single 4.6 MB line [R].
- **Invisible characters.** GlassWorm hid payloads in Unicode variation selectors decoded into `eval()`, hitting 151+ GitHub repos 3–9 Mar 2026 [R] ([Aikido](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)). GPT-4o's code comprehension fell from 100% to 0–2.3% with invisible, bidi or backspace characters [R] ([arXiv 2412.08098](https://arxiv.org/html/2412.08098v3)). Hidden Unicode in rules files made Copilot and Cursor insert scripts silently [R] ([Pillar](https://pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)).
- **Malware now talks to the scanner.** Hades PyPI (Jun 2026) put a prompt injection before its payload asking LLMs to report it clean [R] ([StepSecurity](https://www.stepsecurity.io/blog/the-hades-campaign-pypi-packages)). A Shai-Hulud wave opened with refusal bait: a scanner must report a refusal as "not scanned", never "clean" [R] ([JFrog](https://research.jfrog.com/post/prompt-injection-vs-scanners/)).
- **Code that isn't there yet or isn't active yet.** URL dependencies (PhantomRaven), NuGet logic bombs set for 2027–28 inside ~99% benign code, xz-utils' payload in test fixtures activated only in specific builds [R]. Environment-checking npm malware is caught 39.5–51.7% of the time [R].
- **Even the winner's models.** Gatekeeper's Muse models block 55–57% of malware on its time-split test [V] (§3).

## 3. Existing defenses and their gaps

### The winning repo: Gatekeeper [V]

Second place, Indie track, Meta Global AI Developer Hackathon 2026 (finals 2026-11-09), and the only security project among the 14 winners, per a third-party recap of the closing announcements; the official gallery had not shown placements yet [R]. Built 26 Oct to 4 Nov 2026.

- **What it does.** npm malware detection on Meta models; never runs package code. An investigator agent reads the package step by step with code tools (read, search, decode, strings, diff against the previous version or the original of a fork). Every claim is checked by code: cited lines must exist, and `reach.py` checks that an install hook can actually reach the cited file. Flags "phantom" dependencies the public registry doesn't have (the fake job-interview Tailwind campaign) and URL dependencies. Campaign memory of endpoints and accounts. Install guard: shims for `npm`/`npx`, live OSV lookup plus an offline list of 222k malicious npm names, a 24-hour cooldown via `--before`, and a local Muse Glimmer judge. Live monitor of every npm release with flag times committed to an OpenTimestamps ledger.
- **Results.** 48 confirmed malicious packages (117 versions) flagged about a minute after publication, a median 14 hours before any public report and 25 hours before the OSV/GitHub/npm listing; 48% of the malware published while it ran.
- **Its own stated gaps.** npm and npx only (pnpm, yarn, bun or a full-path npm bypass the shims). Dependencies are not read by the model. `npm install` with no arguments, which is what you run in a cloned repo, gets no model check. The local classifier is public, so attackers can test against it offline. Models block 55–57%.
- **Out of scope entirely.** Repo auto-execution files, agent configs, README/AGENTS.md lures, skills, MCP servers, extensions, other ecosystems, paste-to-run installers, post-infection checks.
- Sources: [README](https://github.com/lb2002/gatekeeper), [guard threat model](https://github.com/lb2002/gatekeeper/blob/main/docs/guard-threat-model.md), [winners recap](https://dev.to/moruku36/the-meta-ai-hackathon-is-over-what-the-winners-of-5367-projects-built-and-what-i-learned-by-glc).

### Agent, skill and MCP defenses [R]

| Tool | Mechanism | Gap |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) (ex mcp-scan) | Rules plus Snyk-hosted models across 14 clients | Needs `SNYK_TOKEN` and uploads tool descriptions and skill content; starts stdio servers during scans; bypassed by Trail of Bits |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) / mcp-scanner | YARA-X, Python AST dataflow, LLM judge | Rules alone catch 7.7% at HIGH (vendor figure); bypassed by Trail of Bits |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | 71 patterns: regex, AST, taint, YARA, optional LLM | Flagged 48.7% of 67,453 ClawHub skill versions yet caught 6.8% of 206 rated malicious ([arXiv 2606.01494](https://arxiv.org/abs/2606.01494)); cannot analyse binary code |
| [Tencent AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard) | LLM-driven scans | Needs an LLM key; web UI without authentication |
| LlamaFirewall + Prompt Guard 2 | Classifier plus LLM alignment check | AgentDojo attack success 1.75% (vendor); 512-token window reportedly split-bypassed [?] |
| [Pipelock](https://github.com/luckyPipewrench/pipelock) | Local MCP/HTTP proxy, schema hashing for rug pulls | No published rates; misses poisoning present at the first `tools/list` |
| Hook packs: [dcg](https://github.com/Dicklesworthstone/destructive_command_guard), [cc-safety-net](https://github.com/kenryu42/claude-code-safety-net), [lasso claude-hooks](https://github.com/lasso-security/claude-hooks) | Command patterns per agent | No content analysis; one agent each; "not a sandbox" |
| [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime), Codex and Cursor sandboxes | OS sandbox | Escaped by writing config that an unsandboxed tool runs later (7 findings, Jul 2026); Windows support in alpha |
| [ClawSec](https://github.com/prompt-security/clawsec) | Config drift detection | OpenClaw only. No tool watches agent config files across all agents |

### Package-level detectors [R]

| Tool | Notes |
|---|---|
| [GuardDog](https://github.com/DataDog/guarddog) | YARA rules plus metadata, 7 ecosystems, local. npm precision 97.0%, recall 89.9% |
| [malcontent](https://github.com/chainguard-dev/malcontent) | 14,500+ YARA capability rules, diff between versions; many false positives |
| [OpenSSF package-analysis](https://github.com/ossf/package-analysis) | Runs packages in gVisor, records strace and network |
| [Packj](https://github.com/ossillate-inc/packj) | Static plus install tracing; precision about 50–57% |
| [SafeDep vet / pmg](https://github.com/safedep/pmg), [Aikido safe-chain](https://github.com/AikidoSec/safe-chain), [Datadog scfw](https://github.com/DataDog/supply-chain-firewall), Socket Firewall | Package-manager wrappers on vendor feeds; unknown new versions pass |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Offline MAL- records; most malware is classified within 3 days |
| [YARA-X](https://github.com/VirusTotal/yara-x), [capa](https://github.com/mandiant/capa) | Rule engines; quality depends on the rules |

npm 12 (Jul 2026) blocks dependency install scripts, `binding.gyp` and URL/git dependencies by default, but a repo's own scripts still run; pnpm 10 blocks dependency scripts [R].

## 4. What a pre-flight repo scan must map (things that run without being read) [R]

| Surface | Paths | Trigger | Incidents and CVEs |
|---|---|---|---|
| Agent configs | `.claude/settings*.json` (hooks, `env`, `defaultMode`), `.mcp.json`, `.cursor/{mcp.json,hooks.json,rules/}`, `.codex/config.toml` plus a `.env` setting `CODEX_HOME`, `.gemini/settings.json`, `.openclaw/extensions/` | Session start or folder open | Claude Code CVE-2025-59536, CVE-2026-21852, CVE-2026-33068, CVE-2026-40068; Cursor CVE-2025-54135/54136, CVE-2026-48124; Codex CVE-2025-61260; Gemini CLI CVE-2026-12537; OpenClaw CVE-2026-32920; Miasma |
| Instruction files | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, README setup steps | The agent reads them | Forever Security, Bagmar & Saraf, Miasma |
| Redirects | `*_BASE_URL`, `CODEX_HOME`, `.npmrc`/`pip.conf` registries, lockfile `resolved` URLs | First request or install | CVE-2026-21852; Trail of Bits' LLM-scanner bypass |
| IDE | `.vscode/tasks.json` with `runOn: folderOpen`; settings naming executables or auto-approval | Folder open (Cursor shipped with Workspace Trust off [?]) | StoatWaffle; CVE-2025-53773; IDEsaster (30+ flaws) |
| Dev containers | `devcontainer.json` `initializeCommand` (runs on the host) | Container setup | |
| Shell env | `.envrc` | After `direnv allow` | |
| npm | Own lifecycle scripts, husky `prepare`, `binding.gyp` with `<!(`, URL/git dependencies | Install | Phantom Gyp, PhantomRaven |
| Python | `*.pth`, `conftest.py`, `setup.py`, import-time code | Interpreter start, pytest, `pip install` or even `pip download` | LiteLLM, Hades |
| Rust | `build.rs`, proc macros, `.cargo/config*`, `rust-toolchain.toml` | Build, or rust-analyzer on open | proc-macro1 typosquat |
| Make | `$(shell …)` | When the Makefile is read | Bagmar & Saraf |
| Git | Submodule plus symlink, worktree `commondir` | `clone --recursive`, agent start | CVE-2024-32002, CVE-2025-48384, CVE-2026-40068 |
| Symlinks out of the repo | Any file | Agent reads or writes it under a harmless name | GhostApproval (6 assistants) |
| Content tricks | Invisible/bidi/tag Unicode; single lines over 1 MB; padding; decode-then-execute; high-entropy literals; binaries in fixtures; date-, CI- or environment-conditional code; text addressed to AI scanners; scripts launching agent CLIs with permission-bypass flags | Review or scan | GlassWorm, Miasma, xz-utils, Hades, Nx |
| CI | `pull_request_target` checking out PR code or sharing caches | Fork pull request | TanStack / Mini Shai-Hulud |

## 5. Benchmarks and datasets [R]

- **Malicious packages.**
  - [ossf/malicious-packages](https://github.com/ossf/malicious-packages): about 240k OSV reports including spam (Apache-2.0).
  - [Datadog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset): 29,847 samples including IDE extensions and AI skills (Apache-2.0 with attribution; zips use the password "infected"; mostly found by GuardDog, so selection bias).
  - [pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry): 9,503 packages.
  - Backstabber's Knife Collection: 174 packages, available on request.
- **Skills.**
  - MalSkillBench: 3,944 malicious skills verified by execution, plus 4,000 benign ([arXiv 2606.07131](https://arxiv.org/abs/2606.07131)).
  - MaliciousSkillBench: 9,740 skills; the best detector reached 95.6% recall at a 62.4% false-positive rate ([arXiv 2608.19901](https://arxiv.org/abs/2608.19901)).
- **Agent injection.**
  - AgentDojo, AgentDyn, InjecAgent.
  - MCPTox: 1,312 tool-poisoning cases.
  - LLMail-Inject: 208k attacks.
  - b3 and BrowseSafe-Bench.
- **Gap.** No public benchmark measures the end-to-end case: an agent sets up a malicious repo, and is the person compromised? There is also none for MCP rug pulls or for persistence through hooks.

## 6. What winning security repos share [R]

1. **They prove findings instead of raising alerts.** AIxCC's Atlantis re-ran the exploit on every patch, Shannon says "no exploit, no report", and Gatekeeper's lines are checked by code.
2. **They publish a number against a named baseline.**
3. **One command gets a first result.**
4. **They ship inside the agent people already run** (skill, plugin, MCP server).
5. **They pair the LLM with plain code.** The AIxCC review found that LLMs add to fuzzing rather than replace it.
6. **They favor robustness over cleverness.** Stability explained most of AIxCC's score gap.
7. **Their costs are low and stated.**
8. **They plug into CI with machine-readable output** (SARIF, JSON).
9. **They run locally and sandboxed by default.**
10. **They ride a fresh threat with a credible statistic.**

**Two more findings:**
- Open-source personal security is an empty field: the top scam-detection repo created since 2025 has 44 stars.
- Winning a competition does not by itself bring stars: AIxCC repos have 11–1,744; Buttercup, which runs on a laptop, out-starred the winner.

Sources: [AIxCC SoK](https://arxiv.org/html/2602.07666), [Team Atlanta](https://team-atlanta.github.io/blog/post-afc), [Trail of Bits](https://blog.trailofbits.com/2025/08/09/trail-of-bits-buttercup-wins-2nd-place-in-aixcc-challenge/), [ROSS index](https://runacap.com/ross-index/q3-2026/).

## 7. Implications for personal-anti-hack

- Guard every door an AI-tool user opens, not one ecosystem; leave deep npm detection to OSV and tools like Gatekeeper.
- Code decides, the LLM investigates. A model can raise suspicion but cannot clear a rule-based block, and its claims count only when they cite lines that code has verified. A refusal or a truncation is reported as "not scanned".
- Normalize before any model reads: reveal invisible Unicode, cut padding, split minified lines, strip comments for a second pass, decode in code, look inside `.pyc` files and archives.
- Get behavior evidence by running installs in isolation with canary secrets (optional).
- Watch agent config and instruction files across all agents, not one.
- Measure end-to-end with real agents and publish numbers against bare LLMs and named tools, including an adaptive round.

## 8. Code to reuse from the author's repos

- `ai-agent-building-kit/template/kit/guard.py`: tag characters, invisible characters, variation selectors, hidden HTML, secret patterns, exfiltration URLs in images and links.
- `ethical-research/skills/ethical-research/scripts/integrity_scan.py`: zero-width and bidi detection, hidden text in PDF and DOCX.
- `ethical-research/skills/ethical-research/scripts/mcp_server.py`: standard-library MCP server supporting current protocol revisions.
- The `.claude-plugin/` packaging and the benchmark harness pattern (pass^3, multiple vendors, result files tied to the code version).
