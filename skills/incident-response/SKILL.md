---
name: incident-response
description: Guide a person through a suspected compromise of their own computer or developer accounts, step by step. Use when they ran an untrusted install script, package, repository, extension, "fix" command or AI-agent setup and now worry it was malware; when an antivirus, GitHub, npm or cloud provider warned them; when keys leaked; or when they ask "was I hacked?" or "what do I do now?".
---

# Incident response for one person's machine and accounts

Order matters: stop the damage, find out what ran, take back the accounts, remove what stayed behind, then make it harder next time. Explain each step in the user's language and let them run anything that touches their accounts.

## Ground rules

- Work with the user, not around them. Credential rotation, account settings, deleting files and reinstalling are their actions; prepare the exact steps and let them confirm each one.
- Do not print secret values. When a check finds a key, report the file, the provider and the first four characters.
- Never run "cleanup" or "removal" scripts from the internet, from the suspicious package or from a message that came with it.
- Assume stolen tokens are already in use. Changing a password does not end existing sessions or revoke API keys.

## 1. Contain (minutes)

1. Stop what is running: close the terminal or agent session that ran it, and end leftover processes the user does not recognise (node, python, powershell, curl, wget started around that time).
2. If it is still sending data, disconnect the network until the rest of step 1 is done.
3. Do not wipe or reinstall yet. The files show what was taken and where it went.

## 2. Find out what ran

- Identify the exact package, version, repository commit, extension or command, and the time. Shell history, the agent's transcript and package-manager logs help.
- Audit it with the malware-audit skill (`pah audit <path or URL>`) to learn what it collects, where it sends data and what it leaves behind.
- Check this computer: `pah checkup` (keys saved in plain files, risky agent settings, planted instruction files, `curl | sh` and ClickFix traces, known malware traces, outdated agents) and `pah watch check` (changes to agent and shell configuration since the baseline). Persistence locations to inspect by hand are in [persistence](references/persistence.md).

## 3. Take back the accounts (highest value first)

Rotate from a device you trust, in this order, and revoke the old credential instead of only creating a new one:

1. AI provider API keys and agent logins (Anthropic, OpenAI, Google, others), then cancel the old keys in each console and check usage for spikes.
2. GitHub: personal access tokens, OAuth app grants, SSH keys and deploy keys; review the security log for new tokens, keys, repositories, workflows or gists.
3. Package registries: npm and PyPI tokens; check whether any of their packages got a new version they did not publish (worms republish with stolen tokens).
4. Cloud accounts: access keys and sessions; review the provider's audit log for new users, keys and resources.
5. Browser sessions: sign out everywhere for email, password manager, code hosting and banking; stealers take cookies, which skip passwords and 2FA.
6. Crypto wallets: move funds from a clean device to a new wallet with a new seed.
7. Password manager: change the master password if a stealer ran while it was unlocked.

The full checklist with where each setting lives is in [rotation](references/rotation.md).

## 4. Remove what stayed behind

- Undo persistence found in step 2 (shell profiles, launch agents, systemd user units, scheduled tasks, Run keys, cron, git hooks, agent hooks and MCP servers, IDE tasks and extensions).
- Reinstall the AI CLIs and editors from the vendor, and recheck their configuration afterwards.
- Remove the malicious package, repository or extension and clear package caches.
- Reinstall the operating system when the code ran with administrator rights, when persistence cannot be fully explained, or when a known stealer family with system-level components ran.

## 5. Harden

- `pah install` for the user's agents (the guard that stops setup commands in repositories that fail a scan), and `pah watch init` once the machine is clean.
- Passkeys or app-based 2FA everywhere; fine-grained, expiring tokens; no long-lived keys in plain files (`pah checkup` lists them).
- Run untrusted code only in a disposable VM, container or cloud dev environment, never with approvals switched off on the main machine.

## Report back

Give the user a short summary: what ran, what it could reach, what was rotated, what was removed, what is still open, and what to watch for in the next weeks (unexpected logins, registry publishes, cloud charges).
