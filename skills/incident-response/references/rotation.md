# Credential rotation checklist

For each item: revoke the old credential (do not only add a new one), then check the account's activity log for use you do not recognise. Do it from a device you trust.

| Credential | Where to revoke | What to check afterwards |
|---|---|---|
| Anthropic API keys | Claude Console → API keys | usage and cost per key; workspace members |
| Claude Code login | `claude` → `/logout`, then sign out other sessions in the account settings | new devices |
| OpenAI API keys, Codex login | OpenAI platform → API keys; `codex logout` | usage; organization members |
| Google AI / Gemini keys | Google AI Studio or Cloud console → credentials | API usage per key |
| Other model providers (Meta, xAI, Groq, OpenRouter, Mistral) | each provider's key page | usage spikes |
| GitHub | Settings → Developer settings → personal access tokens (classic and fine-grained); Applications (OAuth and GitHub Apps); SSH and GPG keys; each repository's deploy keys | Settings → Security log: new tokens, keys, repos, gists, workflow runs; organization audit log |
| npm | npmjs.com → Access Tokens | packages you maintain: versions you did not publish (`npm view <pkg> time`) |
| PyPI | pypi.org → Account settings → API tokens; trusted publishers | release history of your projects |
| AWS / GCP / Azure | IAM access keys and sessions; service account keys; app registrations | CloudTrail / Cloud Audit Logs / Activity log: new users, keys, instances, regions you do not use |
| Docker Hub, other registries | access tokens | pushed images |
| Slack, Discord, Telegram | sign out of all sessions; rotate bot tokens and webhooks | messages sent by the account |
| Email and SSO (Google, Microsoft, Apple) | sign out of all sessions; review app passwords and OAuth grants | forwarding rules and filters (attackers add them) |
| Password manager | change the master password if a stealer ran while it was unlocked; revoke trusted devices | new devices |
| Crypto wallets | move funds from a clean device to a new wallet with a new seed phrase | — |
| SSH keys | remove the old public key from every server and service (`authorized_keys`, GitHub, GitLab) | `last`/auth logs on servers |

Keys found in plain files by `pah checkup` should be moved into the operating system's credential store or the provider's login flow after rotation.
