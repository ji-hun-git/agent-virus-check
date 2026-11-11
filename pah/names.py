"""Look-alike package names (typosquats, separator confusion, homoglyphs) against the most-downloaded packages.

Coding agents catch blatant typosquats but install plausible near-misses: Cursor installed `azurecore` for
`azure-core` in 28 of 30 runs (Bagmar & Saraf, 2026). LLMs also invent package names that attackers then register
(slopsquatting; 5.2% of packages suggested by commercial models, 21.7% by open models).
"""
from __future__ import annotations

import re
from functools import cache
from pathlib import Path

from .model import rule

R_LOOKALIKE = rule(
    "PAH-P007", "Package name looks like a popular package",
    "One character or one separator away from a popular package is how typosquats and slopsquats catch people and "
    "agents; agents install plausible near-misses (azurecore for azure-core) almost every time.",
    "Check the exact name on the registry. Install the popular package if that is what you meant.",
    attack=("T1195.002",), owasp=("LLM03", "ASI04"),
    refs=("https://arxiv.org/abs/2607.15143",
          "https://www.usenix.org/conference/usenixsecurity25/presentation/spracklen"))

DATA = Path(__file__).with_name("data")
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_."
HOMOGLYPHS = (("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"), ("0", "o"), ("o", "0"), ("1", "l"),
              ("l", "1"), ("i", "l"), ("l", "i"), ("5", "s"), ("s", "5"))


def _names(path: Path) -> frozenset[str]:
    if not path.exists():
        return frozenset()
    return frozenset(line.strip() for line in path.read_text(encoding="utf-8").splitlines()
                     if line.strip() and not line.startswith("#"))


@cache
def popular(ecosystem: str) -> frozenset[str]:
    """The most-downloaded packages: the names squatters imitate."""
    return _names(DATA / f"popular-{ecosystem}.txt")


@cache
def known(ecosystem: str) -> frozenset[str]:
    """A wider list of established packages. A name on it is real and widely used, so it is not reported as a
    look-alike even when it is one character away from a more popular name (stylus and stylis, eclint and eslint)."""
    return popular(ecosystem) | _names(DATA / f"known-{ecosystem}.txt")


def normalize(name: str, ecosystem: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "pypi" else name


def _squash(name: str) -> str:
    """The name with scope marks and separators removed: @types/node, types-node and typesnode all become typesnode."""
    return re.sub(r"[@/._-]", "", name)


@cache
def _squashed(ecosystem: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in sorted(popular(ecosystem)):
        out.setdefault(_squash(name), name)
    return out


def _edits1(word: str):
    for i in range(len(word) + 1):
        for c in ALPHABET:
            yield word[:i] + c + word[i:]
        if i < len(word):
            yield word[:i] + word[i + 1:]
            for c in ALPHABET:
                if c != word[i]:
                    yield word[:i] + c + word[i + 1:]
        if i < len(word) - 1:
            yield word[:i] + word[i + 1] + word[i] + word[i + 2:]


def _edit_kind(name: str, target: str) -> str:
    if len(name) == len(target) - 1:
        return "one character missing"
    if len(name) == len(target) + 1:
        return "one character added"
    diffs = [i for i, (a, b) in enumerate(zip(name, target, strict=True)) if a != b]
    if len(diffs) == 2 and diffs[1] == diffs[0] + 1 and name[diffs[0]] == target[diffs[1]] and name[diffs[1]] == target[diffs[0]]:
        return "two characters swapped"
    return "one character changed"


# Separator and scope confusion, homoglyphs, a dropped or swapped letter: how typosquats are made. An added or changed
# character is just as often a different, legitimate package (npm-run-all2, stylus), so it counts for less.
STRONG = ("differs only in separators", "look-alike characters", "one character missing", "two characters swapped")


def lookalike_severity(how: str, where: str) -> str:
    """where: manifest (a declared dependency), command (an install an agent or hook runs), auto-doc (instructions
    agents load on their own) or doc (a README)."""
    strong = how.startswith(STRONG)
    return {"manifest": ("medium", "low"), "command": ("high", "medium"), "auto-doc": ("high", "medium"),
            "doc": ("medium", "low")}[where][0 if strong else 1]


def lookalike(name: str, ecosystem: str) -> tuple[str, str] | None:
    """(popular package it imitates, how) or None."""
    targets = popular(ecosystem)
    if not targets:
        return None
    norm = normalize(name, ecosystem)
    if not norm or norm in known(ecosystem) or len(norm) < 4:
        return None
    scope, _, bare = norm.rpartition("/") if norm.startswith("@") else ("", "", norm)
    target = _squashed(ecosystem).get(_squash(norm))
    if target and target != norm:
        return target, "differs only in separators" + (" or scope" if target.startswith("@") != norm.startswith("@") else "")
    if len(bare) >= 5:
        for variant in _edits1(bare):
            candidate = f"{scope}/{variant}" if scope else variant
            candidate = normalize(candidate, ecosystem)
            if candidate != norm and candidate in targets and len(variant) >= 5:
                return candidate, _edit_kind(norm, candidate)
        for a, b in HOMOGLYPHS:
            if a in bare:
                variant = normalize(bare.replace(a, b), ecosystem)
                candidate = f"{scope}/{variant}" if scope else variant
                if candidate != norm and candidate in targets:
                    return candidate, f"look-alike characters ({a} for {b})"
    return None


# ------------------------------------------------------------------------- names from manifests and commands

_SPEC_SPLIT = re.compile(r"[\s\[<>=!~;@(]")
NPM_INSTALL = re.compile(r"\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|global\s+add)\b([^\n|;&]*)|\b(?:npx|bunx|pnpx)\s+([^\n|;&]*)"
                         r"|\b(?:pnpm|yarn)\s+dlx\s+([^\n|;&]*)", re.I)
PY_INSTALL = re.compile(r"\b(?:pip[0-9.]*|uv\s+pip|pipx)\s+(?:install|run)\b([^\n|;&]*)|\buv\s+add\b([^\n|;&]*)"
                        r"|\buvx\s+([^\n|;&]*)|\bpoetry\s+add\b([^\n|;&]*)", re.I)
_FLAGS_WITH_VALUE = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url", "--extra-index-url", "-f",
                     "--find-links", "--trusted-host", "--registry", "--prefix", "-t", "--target", "-e", "--editable",
                     "--python", "-p", "--package", "--from", "--with", "--cache", "--tag", "--workspace", "-w",
                     "--filter", "--dir", "-C", "--index", "--default-index", "--group", "--extra"}


def _names_from_args(args: str, npm: bool) -> list[str]:
    names = []
    tokens = args.split()
    skip = False
    for tok in tokens:
        tok = tok.strip("\"'`,")
        if skip:
            skip = False
            continue
        if not tok or tok in ("&&", "||"):
            break
        if tok.startswith("-"):
            if tok in _FLAGS_WITH_VALUE:
                skip = True
            continue
        if re.match(r"(?:https?:|git\+|file:|\.|/|~|[A-Za-z]:\\)", tok) or tok.endswith((".tgz", ".whl", ".txt", ".tar.gz")):
            continue
        if npm:
            base = tok[1:].split("@")[0] if tok.startswith("@") else tok.split("@")[0]
            name = ("@" + base) if tok.startswith("@") else base
        else:
            name = _SPEC_SPLIT.split(tok)[0]
        if re.fullmatch(r"@?[A-Za-z0-9][\w.\-/]*", name or ""):
            names.append(name)
    return names


def names_in_command(command: str) -> list[tuple[str, str]]:
    """(ecosystem, package name) for packages a command would install or run."""
    out = []
    for m in NPM_INSTALL.finditer(command):
        args = next((g for g in m.groups() if g is not None), "")
        names = _names_from_args(args, npm=True)
        if m.group(2) is not None or m.group(3) is not None:  # npx / dlx run one package
            names = names[:1]
        out += [("npm", n) for n in names]
    for m in PY_INSTALL.finditer(command):
        args = next((g for g in m.groups() if g is not None), "")
        names = _names_from_args(args, npm=False)
        if m.group(3) is not None:  # uvx runs one tool
            names = names[:1]
        out += [("pypi", n) for n in names]
    return out


def requirement_names(text: str) -> list[tuple[int, str]]:
    """(line, name) from a requirements file."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-") or "://" in line or line.startswith((".", "/")):
            continue
        name = _SPEC_SPLIT.split(line)[0].strip()
        if re.fullmatch(r"[A-Za-z0-9][\w.\-]*", name):
            out.append((i, name))
    return out
