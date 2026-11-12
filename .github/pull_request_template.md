## What and why



## Checks

- [ ] `python -m unittest discover -s tests` passes
- [ ] For new or changed rules: a malicious TrapRepo case and its benign twin, and `python bench/run.py` still flags 0 benign cases
- [ ] `docs/rules.md` regenerated if rules changed
- [ ] No real credentials, personal data or live payloads anywhere, fixtures included (reserved domains such as `.invalid` only)
