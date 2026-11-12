# Contributing

The most useful contributions, in order:

1. **False positives.** Use the [false positive form](https://github.com/ji-hun-git/agent-virus-check/issues/new?template=false-positive.yml):
   what you scanned (a public URL and commit is best), the rule and the line, and why it is harmless. A legitimate
   pattern the scanner gets wrong becomes a benign TrapRepo case, so it stays fixed.
2. **Missed malware and bypasses.** Report them privately through a
   [security advisory](https://github.com/ji-hun-git/agent-virus-check/security/advisories/new), not in a public
   issue. The best report is an inert TrapRepo case (see below).
3. **Code**, for one of the above or an issue marked as ready.

## Development

Python 3.10 or newer and the standard library; there are no dependencies, and that is deliberate. A scanner that
pulls in packages adds the very supply-chain risk it checks for.

```sh
python -m unittest discover -s tests          # unit tests and the TrapRepo corpus
python bench/materialize.py --check           # every case inert, every URL on a reserved domain
python bench/run.py --name dev                # benchmark, rules only (seconds, offline)
python bench/drill.py --name dev              # every agent hook protocol against every case
python -I pah_entry.py scan . --fail-on block # the repository passes its own scan
```

Lint the way CI does: `ruff check --select F,E9,B,UP --ignore UP007,B904 --target-version py310 .`

## Adding or changing a rule

- Tie it to something real: the incident, CVE or paper goes in the rule's `refs`.
- Add a malicious TrapRepo case and a benign twin that uses the same mechanism legitimately, in
  `bench/fixtures/_build_cases.py`. Payloads only print `PAH-CANARY` and every URL is on a reserved domain such as
  `.invalid`; `bench/materialize.py --check` enforces both.
- Keep the benchmark at 0 benign flagged. If the rule could fire on ordinary projects, also run
  `python bench/real_repos.py` (it downloads widely used repositories and scans them).
- Regenerate the rule list with `python -I pah_entry.py rules --markdown > docs/rules.md`, and the README figures with
  `python scripts/make_figures.py` when headline numbers change.

## Pull requests

One change per pull request, with tests, and say what you ran: test results, and benchmark numbers before and after
if detection changed. Never commit real credentials, personal data or live payloads, including in fixtures.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE), and to follow the
[code of conduct](CODE_OF_CONDUCT.md).
