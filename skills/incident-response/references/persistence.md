# Where malware stays behind

List these, compare with what the user knows they set up, and note modification times near the incident. `pah watch check` covers many of them automatically once a baseline exists.

## All platforms

- Shell profiles: `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.profile`, fish `config.fish`, PowerShell `$PROFILE` files.
- Git: `git config --global --list` (look for `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, `credential.helper`, aliases starting with `!`), global hooks folder.
- AI agents:
  - Claude Code: `~/.claude/settings.json` (`hooks`, `env`, `apiKeyHelper`, `statusLine`), `~/.claude.json` (MCP servers), `~/.claude/CLAUDE.md`, `~/.claude/skills`, `~/.claude/agents`, plugins.
  - Codex: `~/.codex/config.toml` (`mcp_servers`, `notify`, hooks), `~/.codex/hooks.json`, `~/.codex/AGENTS.md`.
  - Gemini CLI / Antigravity: `~/.gemini/settings.json`, `~/.gemini/config/hooks.json`, `~/.gemini/GEMINI.md`.
  - Cursor: `~/.cursor/mcp.json`, `~/.cursor/hooks.json`; Copilot: `~/.copilot/` (hooks, MCP config, instructions); Devin: `~/.config/devin/`; Kiro: `~/.kiro/`; OpenClaw: `~/.openclaw/openclaw.json` and extensions.
- Package managers: `~/.npmrc` (`script-shell`, `node-options`, registry), `pip.conf`/`pip.ini` (index URL), `~/.cargo/config.toml` (wrappers).
- Editors: VS Code/Cursor user `settings.json`, `tasks.json`, installed extensions (newly added or sideloaded `.vsix`).
- Browser extensions added recently, especially wallet-adjacent ones.

## macOS

- `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/` (new `.plist` files; `launchctl list` for unknown labels).
- Login items (System Settings → General → Login Items), `crontab -l`, `/etc/periodic`.
- Quarantine removal traces in shell history (`xattr -c`, `xattr -d com.apple.quarantine`), password prompts from scripts (`osascript` dialogs).

## Linux

- `~/.config/systemd/user/` and `systemctl --user list-unit-files --state=enabled`; `/etc/systemd/system/`.
- `crontab -l`, `/etc/cron.*`, `/var/spool/cron/`.
- `~/.config/autostart/*.desktop`, `/etc/profile.d/`, `~/.ssh/authorized_keys` (new keys), `/etc/ld.so.preload`.

## Windows

- Run keys: `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and `RunOnce`, and the HKLM equivalents).
- Startup folder: `shell:startup`.
- Scheduled tasks: `schtasks /query /fo LIST /v` or `Get-ScheduledTask | Where-Object State -ne Disabled`.
- Services and WMI subscriptions (`Get-WmiObject -Namespace root\subscription -Class __EventFilter`).
- PowerShell history: `(Get-PSReadLineOption).HistorySavePath`; Run dialog history (RunMRU), where ClickFix commands land.
- Microsoft Defender history: Windows Security → Protection history.
