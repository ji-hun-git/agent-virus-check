# CI and pre-commit

Run the same scan in pull requests, before commits, or in any CI. Nothing in the scanned code is executed, nothing
leaves the runner unless you turn on `online`, and there is nothing to install besides Python 3.10 or newer, which
GitHub's runners already have.

## GitHub Actions

### Gate pull requests

```yaml
name: personal-anti-hack
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: ji-hun-git/agent-white-hat@v0.3.0
```

The step fails when the verdict is BLOCK (a high or critical finding). High and critical findings appear as errors and
medium ones as warnings on their lines in the pull request, and the job summary lists everything that runs without
being read and every finding of medium or worse. A SARIF report is written to `personal-anti-hack.sarif`.

Pin the action to a full commit SHA if your organization requires it; the tag works the same way.

### Show findings in the Security tab

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: ji-hun-git/agent-white-hat@v0.3.0
    with:
      fail-on: none
  - uses: github/codeql-action/upload-sarif@v4
    if: always()
    with:
      sarif_file: personal-anti-hack.sarif
      category: agent-white-hat
```

### Check something before a workflow runs it

A workflow that installs a third-party tool, builds a submodule or opens a downloaded archive can scan it first:

```yaml
- uses: ji-hun-git/agent-white-hat@v0.3.0
  with:
    path: vendor/some-tool          # or an archive, or https://github.com/owner/repo
    sarif: ""
```

### What it reads in your own workflows

| Rule | What it means for you |
| --- | --- |
| [PAH-I010](rules.md#pah-i010) | A workflow sends `toJSON(secrets)` or other secrets to a bare IP, plain HTTP or a capture service, or reads the runner's memory. This is how GhostAction and the 'wfx' wave (Sep to Nov 2026) looked; it blocks, because the repository has been compromised. |
| [PAH-I009](rules.md#pah-i009) | `${{ github.event.issue.title }}` or a similar value is pasted into `run:` or `script:`. Pass it through `env:` instead. |
| [PAH-I011](rules.md#pah-i011) | An AI agent action runs on issues or comments and also gets untrusted text in its prompt, accepts any user or has its approvals off (Clinejection). |
| [PAH-I008](rules.md#pah-i008) | `pull_request_target` checks out the pull request's code. |

PAH-I009, PAH-I011 and PAH-I008 are risks to the repository's CI, not to the machine of someone who clones it, so they
are reported at low severity: they appear in the Security tab through the SARIF upload and do not change the verdict.

### Inputs

| Input | Default | |
| --- | --- | --- |
| `path` | `.` | Folder, file, archive or git URL to scan. |
| `fail-on` | `block` | Fail at or above this verdict: `block`, `warn`, `incomplete`, or `none` to only report. |
| `sarif` | `personal-anti-hack.sarif` | Where to write the SARIF report; empty to skip. |
| `annotations` | `true` | Put medium-or-worse findings on their lines; `false` to keep them in the summary only. |
| `online` | `false` | Also check packages against the public registries and OSV. Sends package names and versions. |
| `python` | | Interpreter to use; by default the runner's `python3` or `python` (3.10 or newer). |

### Outputs

| Output | |
| --- | --- |
| `verdict` | `block`, `warn`, `pass` or `incomplete`. |
| `sarif` | Path of the SARIF report, when one was written. |

The scan step also sets `critical`, `high`, `medium` and `low` counts.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ji-hun-git/agent-white-hat
    rev: v0.3.0
    hooks:
      - id: agent-white-hat
        # stages: [pre-push]   # in a large repository, scan before each push instead of each commit
```

The hook scans the whole repository and stops the commit on BLOCK, printing the findings.

## Any other CI

```sh
python -m pip install https://github.com/ji-hun-git/agent-white-hat/archive/refs/tags/v0.3.0.tar.gz
pah scan . --fail-on block --sarif-out personal-anti-hack.sarif
```

| Exit code | Verdict |
| --- | --- |
| 0 | pass, or below the `--fail-on` threshold |
| 1 | warn |
| 2 | block |
| 3 | incomplete: something could not be read in full, which is never reported as clean |
| 64, 65 | the command was wrong, or the target could not be read |

`--github` adds the annotations, step outputs and job summary described above when the scan runs inside GitHub
Actions; `--format sarif` prints SARIF instead of text, and `--sarif-out FILE` writes it alongside whatever is printed.
