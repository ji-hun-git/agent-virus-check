# Security

## Reporting a problem

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/ji-hun-git/agent-virus-check/security/advisories/new). Include what you
ran, what you expected and what happened. A technique that gets malicious code past the scanner is a vulnerability
here: please report it the same way, ideally with an inert test case in the format of `bench/fixtures/traprepo/`.

## What agent-virus-check does and does not do

- **It never runs code from what it scans.** Repositories, archives, packages and skills are read as bytes. The only
  program it starts while scanning is `git`, with hooks and fsmonitor disabled, to clone a URL or to read symbolic
  links from the index.
- **It keeps scanned code out of its own imports.** The Claude Code hooks and commands run Python in isolated mode
  (`python -I`), so a `json.py` or `pah/` folder in the project being worked on cannot replace its modules.
- **It sends nothing unless you ask.** `--online` sends package names (and pinned versions) to registry.npmjs.org,
  pypi.org and api.osv.dev. `--deep` sends prepared evidence (excerpts of the scanned files) to the model provider whose
  key you set. Nothing else leaves the machine.
- **The guard only tightens.** Hook decisions are `deny`, `ask` or no answer; it never answers `allow`, so it cannot
  approve something your own permission settings would have stopped.
- **It is not a sandbox.** A scan lowers the chance that you run something malicious; it cannot prove that code is
  safe. Rules are public, so a determined attacker can test against them, as with every open scanner. Keep approval
  prompts on, keep secrets out of plain files, and run unfamiliar code in a disposable environment.
