# Notices

agent-white-hat is released under the MIT License (see `LICENSE`). It includes the following data from others.

- **`pah/data/popular-npm.txt`**: the names of the 5,000 most-downloaded npm packages, taken from
  [npm-high-impact](https://github.com/wooorm/npm-high-impact) 1.13.0 by Titus Wormer, MIT License, sorted by name.
  Used to recognize look-alike package names.
- **`pah/data/popular-pypi.txt`**: the names of 5,000 of the most-downloaded PyPI projects, from public PyPI download
  statistics (the ClickHouse PyPI dataset) as published by [top-pypi-packages](https://github.com/hugovk/top-pypi-packages)
  on 2026-11-01. Only the names are kept, normalized and sorted; download counts and ranks are not included.
- **`pah/data/known-npm.txt`** and **`pah/data/known-pypi.txt`**: the rest of the same two lists (all 17,338 names in
  npm-high-impact 1.13.0, and the 15,000 PyPI projects in top-pypi-packages of 2026-11-01), used only so that
  established packages are not reported as look-alikes of more popular ones.

Rule descriptions cite the public research and incident reports they are based on; the links are in `docs/rules.md`
and `docs/research.md`.
