---
description: Check this computer for exposed API keys, risky agent settings, planted instruction files and malware traces
---

Run `pah checkup` if `pah` is installed; otherwise `python3 -I "${CLAUDE_PLUGIN_ROOT}/pah_entry.py" checkup` (use `python` or `py` if `python3` is missing). Then:

1. Explain each finding in the user's language, most severe first. Secret values are never printed; do not try to open the files to read them.
2. For keys saved in plain files: tell the user to revoke and recreate them in each provider's console and store the new ones in the OS credential store or a password manager.
3. For malware traces or ClickFix entries: advise treating the machine as compromised, rotating credentials and signing out sessions from another device.
4. Suggest `pah watch init` if no baseline exists yet.
