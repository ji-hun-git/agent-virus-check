# TrapRepo: the personal-anti-hack benchmark corpus

82 cases (55 malicious, 27 benign) that measure whether a
pre-flight scanner (or a plain LLM review) catches real 2025-2026 supply-chain
and agent-config malware techniques **before** a person or an AI coding agent
opens, installs or runs a repo, Agent Skill, MCP server or package -- without
false alarms on legitimate repositories.

Each case is one JSON file (`<id>.json`). The files it describes are **data**,
never real files in this tree; `materialize.py` writes them into a throwaway
directory on demand. The scanner under test is written by a different engineer;
these fixtures are deliberately *not* tuned to any detector.

## Safety model (non-negotiable)

- **Fixtures are data.** No case materializes a real `.claude/`, `.vscode/`,
  `AGENTS.md`, `package.json`, etc. into the repo tree. Materialization targets a
  temporary directory only.
- **Payloads are inert.** Every payload's only guaranteed effect is to print
  `PAH-CANARY` or create a `PAH_CANARY_TRIGGERED` file. The realistic *shape* of
  each technique surrounds that canary.
- **Reserved domains only.** Every URL inside a malicious fixture uses a reserved
  domain (`*.invalid`, `*.example`, `*.test`, `example.com|net|org`). The sole
  exception is standard, non-dereferenced XML namespace identifiers (e.g.
  `schemas.openxmlformats.org` in a DOCX's `[Content_Types].xml`), which are not
  network endpoints. Benign fixtures may name real official installer/registry
  hosts as text.
- **Credential paths, never real theft.** Code may *reference* credential paths
  (`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.claude/.credentials.json`,
  `~/.codex/auth.json`) to reproduce a technique, but anything "sent" is the
  literal canary marker, to a reserved `.invalid` host.
- **No destructive commands, no working exploits, no real stealer code.**
  Persistence examples only append a `# PAH-CANARY` comment. `materialize.py`
  never executes a payload; `--check` rejects any destructive command or
  non-reserved URL in a malicious fixture.

## Usage

```
python bench/materialize.py --check            # validate the whole corpus
python bench/materialize.py --all  <out_dir>   # write every case to <out_dir>/<id>/repo
python bench/materialize.py <id>   <out_dir>   # write one case
```

`expected` is what a correct scanner should do: `block` or `warn` for malicious
cases (`warn` when the real-world harm still needs a later manual step, e.g. the
user runs an install), `pass` for benign cases.

## Changes after review

The corpus was written separately from the scanner. After the first benchmark run, two cases were corrected because
they did not reproduce their incident; both changes are recorded in the cases' `notes`:

- `lookalike-dep-separator-confusion`: moved from package.json to requirements.txt, because `azure-core` (the name
  `azurecore` imitates) is a PyPI package.
- `rust-build-rs-network-exec`: the build script only held a URL in a variable; it now fetches and runs a second
  stage, as the technique does (still inert: the host is a reserved `.invalid` name).

## Cases

| id | kind | expected | technique | incident |
|---|---|---|---|---|
| `claude-apikeyhelper-command` | malicious | block | apiKeyHelper names a shell command that Claude Code runs to fetch credentials; the comman… | Claude Code project-file abuse class (CVE-2026-21852 family) |
| `claude-settings-env-anthropic-base-url` | malicious | block | The env block sets ANTHROPIC_BASE_URL (and auth token env) to an attacker host, so the ag… | CVE-2026-21852 (Claude Code project files could leak the AP… |
| `claude-settings-pretooluse-hook` | malicious | block | A PreToolUse hook matched to Bash runs an attacker script before each matching tool call,… | Miasma / Mini Shai-Hulud persistence through .claude/settin… |
| `claude-settings-sessionstart-hook` | malicious | block | A SessionStart hook in .claude/settings.json runs a shell script the first time a Claude … | Miasma worm (Jun 2026) planted Claude/Gemini SessionStart h… |
| `claude-statusline-command` | malicious | block | statusLine.command runs a shell command each time the status line renders; pointing it at… | Claude Code project-file abuse class (statusLine command ex… |
| `codex-env-codexhome-config-toml` | malicious | block | A repo .env sets CODEX_HOME to a repo-local .codex directory; the repo's .codex/config.to… | CVE-2025-61260 (Codex CODEX_HOME / config.toml redirection) |
| `cursor-hooks-json` | malicious | block | A .cursor/hooks.json registers a command that Cursor runs around agent actions (e.g. afte… | CVE-2026-48124 (Cursor agent hooks arbitrary command execut… |
| `cursor-mcp-json-command` | malicious | block | A .cursor/mcp.json entry uses command/args to run a shell payload; Cursor starts project … | CurXecute / MCPoison (Cursor MCP auto-execution, CVE-2025-5… |
| `gemini-settings-hook` | malicious | block | A .gemini/settings.json registers a start-up command Gemini CLI runs when the project loa… | Miasma (Gemini SessionStart hooks) / CVE-2026-12537 |
| `mcp-json-enable-all-project` | malicious | block | A project .mcp.json defines a stdio MCP server whose command is attacker-controlled; .cla… | CVE-2025-59536 (auto-enabled project MCP servers execute on… |
| `openclaw-extension-autoload` | malicious | block | An extension dropped under .openclaw/extensions/ is auto-loaded by OpenClaw on launch; it… | CVE-2026-32920 (OpenClaw auto-loaded extensions) / trojaniz… |
| `binary-magic-disguised-fixture` | malicious | warn | A file named like compressed test data actually begins with ELF magic and embeds command … | xz-utils (payload concealed in test fixtures, activated in … |
| `pyc-only-payload` | malicious | block | A package ships a compiled .pyc module with no corresponding .py; Python imports the byte… | Trail of Bits skill-scanner bypass (payload in shipped .pyc… |
| `gradle-wrapper-distributionurl-offhost` | malicious | warn | The Gradle wrapper's distributionUrl is changed to an attacker host, so ./gradlew downloa… | Gradle wrapper distributionUrl redirection (toolchain-downl… |
| `makefile-shell-download-run` | malicious | block | A top-level $(shell ...) assignment is evaluated as soon as make parses the Makefile (inc… | Makefile $(shell ...) execution (Bagmar & Saraf setup-doc e… |
| `date-ci-conditional-trigger` | malicious | block | The beacon runs only when it detects a CI environment or when the date is past a hardcode… | Environment/date-conditional malware (NuGet logic bombs; en… |
| `glassworm-variation-selectors-eval` | malicious | block | A JS string carries an invisible payload encoded as Unicode variation selectors; a decode… | GlassWorm (Oct 2025-Mar 2026): payloads hidden in Unicode v… |
| `js-100k-leading-newlines` | malicious | block | A JS file begins with about 100,000 blank lines so size/line-count truncation drops the r… | Trail of Bits skill-scanner bypass (large files truncated b… |
| `js-multimb-single-line` | malicious | block | A ~3 MB single line of minified filler hides an eval payload near its end, where length-b… | Miasma (a single 4.6 MB line); CASHEWS/Cloudflare on large-… |
| `js-trailing-spaces-hidden` | malicious | block | A single line begins with innocuous code, then hundreds of spaces push the eval payload f… | Trail of Bits / Cloudflare obfuscation class (off-screen pa… |
| `obfuscatorio-js-loader` | malicious | block | Hex _0x identifiers, a shuffled string array and an index-offset decoder hide the real st… | Obfuscator.io-style loaders (common in npm stealers; Cloudf… |
| `docx-hidden-script-skill` | malicious | block | A .docx (a zip) carries a hidden Python entry alongside its document XML; the accompanyin… | Trail of Bits skill-scanner bypass (scripts hidden inside a… |
| `git-dir-hookspath-fsmonitor` | malicious | block | A repo downloaded as an archive carries a prebuilt .git/ whose config sets core.hooksPath… | Git config abuse (core.hooksPath / core.fsmonitor) in archi… |
| `gitmodules-suspicious-submodule` | malicious | warn | A submodule entry uses a crafted path and an attacker-hosted URL; a recursive clone fetch… | CVE-2024-32002 / CVE-2025-48384 (submodule checkout hook/sy… |
| `husky-precommit-payload` | malicious | block | A .husky/pre-commit hook (installed by husky's prepare step) runs attacker code whenever … | Git-hook persistence via husky (lifecycle + commit-time exe… |
| `symlink-to-ssh-key` | malicious | warn | A file named like documentation is actually a symlink escaping the repo to the user's pri… | GhostApproval (symlink escape read/written by AI assistants… |
| `devcontainer-initializecommand` | malicious | block | initializeCommand executes on the host (not in the sandboxed container) during dev contai… | Dev container initializeCommand host execution (pre-flight … |
| `vscode-settings-autoapprove` | malicious | block | Workspace settings enable chat.tools.autoApprove and task.allowAutomaticTasks, so the age… | CVE-2025-53773 (workspace settings silently disable agent g… |
| `vscode-tasks-folderopen` | malicious | block | A task with runOptions.runOn = folderOpen executes a shell command the moment the workspa… | StoatWaffle: fake job-interview repos auto-execute via .vsc… |
| `agents-md-install-and-reconfigure` | malicious | block | A long AGENTS.md framed as mandatory engineering policy instructs the coding agent to npm… | Forever Security / Codex AGENTS.md attack (Oct 2026): a 13 … |
| `claude-md-set-base-url` | malicious | block | CLAUDE.md, which Claude Code reads automatically, tells the agent to route requests throu… | Forever Security CLAUDE.md variant (routed Claude Code thro… |
| `cursor-rules-mdc-tagchars` | malicious | block | An alwaysApply Cursor rule shows innocuous style guidance, but Unicode tag characters smu… | Pillar rules-file backdoor (hidden Unicode in rules files m… |
| `readme-curl-bash-lookalike` | malicious | warn | The README's install step is `curl ... | bash` from a domain crafted to look like an offi… | InstallFix (Mar 2026): cloned Claude Code install pages who… |
| `readme-nondefault-registry` | malicious | warn | The README 'Quick start' tells the reader to run commands that switch the npm registry an… | Bagmar & Saraf: agents install whatever setup docs list; re… |
| `mcp-tool-description-poisoning` | malicious | block | The MCP server's code is benign, but one tool's description embeds hidden instructions te… | MCPTox / tool-poisoning class; first malicious MCP server (… |
| `agent-cli-yolo-secret-hunt` | malicious | block | A script run during install invokes a coding agent already on the machine with its guardr… | Nx / s1ngularity (Aug 2025): used Claude Code, Gemini CLI a… |
| `binding-gyp-command-expansion` | malicious | block | A native addon's binding.gyp embeds a <!(...) command-expansion token, which node-gyp exe… | Phantom Gyp: 57 npm packages ran code through binding.gyp c… |
| `lookalike-dep-separator-confusion` | malicious | warn | requirements.txt depends on 'azurecore', a separator-dropped look-alike of the real PyPI … | Bagmar & Saraf: near-miss names (azurecore for azure-core) … |
| `npm-postinstall-beacon` | malicious | block | An internal-looking package runs a postinstall lifecycle script that executes attacker co… | Dependency-confusion / Shai-Hulud class (install-time beaco… |
| `npm-prepare-script` | malicious | block | The repo's own package.json prepare script runs during `npm install` in the cloned repo; … | Shai-Hulud / Cline postinstall class (a repo's own lifecycl… |
| `npm-url-dependency` | malicious | block | A dependency is specified as an http(s) tarball URL instead of a registry range, so npm f… | PhantomRaven: 126 npm packages fetched payloads from URL de… |
| `npmrc-registry-redirect` | malicious | block | A repo-local .npmrc overrides the registry (and injects an auth token) so every install i… | Registry redirection via .npmrc (Trail of Bits LLM-scanner … |
| `package-lock-offregistry-resolved` | malicious | warn | The lockfile's resolved URL for a common package points at an attacker mirror, so `npm ci… | Lockfile integrity abuse (resolved URL redirection) in the … |
| `pnpmfile-cjs-hook` | malicious | block | A .pnpmfile.cjs readPackage hook runs arbitrary code during dependency resolution and can… | pnpm lifecycle-hook abuse (install-time code execution clas… |
| `yarnrc-yarnpath-repo-script` | malicious | block | yarnPath makes Yarn execute a JavaScript file shipped in the repo instead of a trusted Ya… | Yarn yarnPath redirection (self-hosted binary abuse, regist… |
| `python-conftest-beacon` | malicious | block | Module-level code in conftest.py executes during pytest collection, before any test runs,… | Import-time Python execution class (conftest / sitecustomiz… |
| `python-exec-base64-zlib-loader` | malicious | block | The module decodes a base64+zlib (and, in the wild, marshal) blob and exec()s it, hiding … | Hades PyPI campaign (Jun 2026): base64/zlib/marshal exec lo… |
| `python-exec-loader-ai-reviewer-comment` | malicious | block | A base64 exec loader is preceded by a comment addressed to automated reviewers asserting … | Hades campaign prompt-injection-to-scanner; Cloudflare dilu… |
| `python-pth-exec` | malicious | block | A .pth file whose line begins with 'import' is executed by the site module every time the… | LiteLLM PyPI compromise delivered through a .pth file |
| `python-requirements-index-url` | malicious | warn | A requirements file sets --index-url/--extra-index-url to an attacker-hosted index, so in… | Index redirection / dependency confusion (Bagmar & Saraf: r… |
| `python-setup-py-download-run` | malicious | block | setup.py runs arbitrary Python at install time; here it reaches out to an attacker host a… | PyPI install-time execution class (Hades campaign and prede… |
| `cargo-config-rustc-wrapper` | malicious | block | A repo-local .cargo/config.toml sets build.rustc-wrapper to a script in the repo, so ever… | Cargo config redirection (rustc-wrapper/linker) in the agen… |
| `rust-build-rs-network-exec` | malicious | block | A Cargo build script (build.rs) runs on the host during `cargo build` (and when rust-anal… | Cargo build.rs execution class (proc-macro/build-script sup… |
| `skill-md-fetch-binary` | malicious | block | An Agent Skill's SKILL.md instructs the agent to run a bundled setup script whose job is … | ClawHavoc (341 malicious ClawHub skills, mostly delivering … |
| `skill-npx-nonexistent-slopsquat` | malicious | warn | A skill tells the agent to run npx on a package name that does not exist on the registry,… | react-codeshift slopsquat (a hallucinated name appeared in … |
| `benign-claude-settings-narrow` | benign | pass | A .claude/settings.json that only sets a narrow permission allowlist; no hooks, no env, n… | Legitimate .claude/settings.json (mirrors the malicious hoo… |
| `benign-mcp-json-local-stdio` | benign | pass | A project .mcp.json points at a local stdio MCP server by interpreter + script, and there… | Legitimate .mcp.json (mirrors mcp-json-enable-all-project w… |
| `benign-env-local-dev` | benign | pass | A development .env with a local port, debug flag and a localhost database URL; no CODEX_H… | Legitimate dev .env (mirrors codex-env-codexhome-config-tom… |
| `benign-github-actions-pull-request` | benign | pass | A CI workflow on the safe pull_request event (not pull_request_target), checking out and … | Legitimate CI (hard negative for pull_request_target cache/… |
| `benign-gradle-wrapper-official` | benign | pass | A standard gradle-wrapper.properties whose distributionUrl is the official services.gradl… | Legitimate Gradle wrapper (mirrors gradle-wrapper-distribut… |
| `benign-makefile-shell-gitrev` | benign | pass | A top-level $(shell ...) runs a harmless local git command to embed the commit hash; no d… | Legitimate Makefile (mirrors makefile-shell-download-run wi… |
| `benign-emoji-vs16-locales` | benign | pass | A localization file with legitimate non-ASCII: emoji using the U+FE0F variation selector … | Legitimate Unicode (hard negative for variation-selector an… |
| `benign-minified-dist-no-eval` | benign | pass | A legitimately minified bundle: long single-ish lines and short identifiers, but no eval/… | Legitimate minified output (mirrors js-multimb-single-line … |
| `benign-gitmodules-normal` | benign | pass | A standard submodule under a sensible path pointing at a github.com HTTPS URL. | Legitimate submodule (mirrors gitmodules-suspicious-submodu… |
| `benign-husky-lint-staged` | benign | pass | A standard husky pre-commit hook runs lint-staged to lint staged files; no network, no pa… | Legitimate husky + lint-staged setup (mirrors husky-precomm… |
| `benign-devcontainer-postcreate` | benign | pass | postCreateCommand runs inside the container after it is built (sandboxed), and there is n… | Legitimate devcontainer.json (mirrors devcontainer-initiali… |
| `benign-vscode-build-task` | benign | pass | A normal build task invoked manually (Ctrl+Shift+B); no runOptions.runOn, so nothing runs… | Legitimate .vscode/tasks.json (mirrors vscode-tasks-foldero… |
| `benign-agents-md-conventions` | benign | pass | AGENTS.md documents build/test/style conventions and asks the agent to run tests before c… | Legitimate AGENTS.md (mirrors agents-md-install-and-reconfi… |
| `benign-claude-md-conventions` | benign | pass | CLAUDE.md lists how to build, test and where key modules live; no routing changes, no bas… | Legitimate CLAUDE.md (mirrors claude-md-set-base-url withou… |
| `benign-cursor-style-rules` | benign | pass | A .cursor/rules/*.mdc with plain, visible style guidance and no hidden Unicode and no alw… | Legitimate Cursor rules (mirrors cursor-rules-mdc-tagchars … |
| `benign-readme-official-installers` | benign | pass | The README's setup references the real official installers (rustup, uv, bun) over https; … | Legitimate install docs (mirrors readme-curl-bash-lookalike… |
| `benign-mcp-server-normal` | benign | pass | An MCP server whose tool descriptions plainly describe their function and whose code does… | Legitimate MCP server (mirrors mcp-tool-description-poisoni… |
| `benign-native-addon-binding-gyp` | benign | pass | A normal N-API addon: binding.gyp lists sources only (no command expansion), built with n… | Legitimate node-gyp native addon (mirrors binding-gyp-comma… |
| `benign-npmrc-save-exact` | benign | pass | A repo .npmrc that sets save-exact and engine-strict and keeps the default public registr… | Legitimate .npmrc (mirrors npmrc-registry-redirect without … |
| `benign-package-lock-registry` | benign | pass | A normal lockfile whose resolved URLs and integrity hashes point at registry.npmjs.org. | Legitimate lockfile (mirrors package-lock-offregistry-resol… |
| `benign-pytest-conftest-fixtures` | benign | pass | conftest.py defines fixtures and has no module-level code that does work at collection ti… | Legitimate conftest.py (mirrors python-conftest-beacon with… |
| `benign-requirements-hashes` | benign | pass | A hash-pinned requirements file from the default PyPI index; no index redirection. | Legitimate hashed requirements (mirrors python-requirements… |
| `benign-setup-py-pyproject` | benign | pass | A conventional setup.py that only calls setup() plus a pyproject with metadata; no networ… | Legitimate packaging (mirrors python-setup-py-download-run … |
| `benign-build-rs-out-dir` | benign | pass | A normal build script writes a generated .rs file into the Cargo OUT_DIR; no network, no … | Legitimate build.rs codegen (mirrors rust-build-rs-network-… |
| `benign-cargo-config-target-flags` | benign | pass | A .cargo/config.toml that sets rustflags/target settings only; no rustc-wrapper and no li… | Legitimate Cargo config (mirrors cargo-config-rustc-wrapper… |
| `benign-rust-proc-macro` | benign | pass | A proc-macro crate that derives code at compile time using syn/quote; proc-macro = true, … | Legitimate proc-macro (hard negative for build-time-executi… |
| `benign-skill-md-normal` | benign | pass | An Agent Skill whose SKILL.md documents what it does and how to call it; no fetch-and-run… | Legitimate skill (mirrors skill-md-fetch-binary / slopsquat… |
