#!/usr/bin/env python3
"""TrapRepo materializer and validator (agent-virus-check benchmark).

The benchmark cases live as JSON DATA under ``bench/fixtures/traprepo/``. No fixture file is
ever a real file in the repo tree; this module turns one case into a throwaway
directory tree on demand so a scanner can look at it, and validates the corpus.

Safety: nothing in this module ever *executes* a fixture payload. It only writes
bytes, builds zip/pyc/binary blobs, and creates symlinks. Payloads are inert
(they only print ``PAH-CANARY`` or create ``PAH_CANARY_TRIGGERED``) and every URL
inside a malicious fixture points at a reserved domain (*.invalid / *.example /
*.test / example.com|net|org).

stdlib only; targets Python 3.12.

CLI:
    python bench/materialize.py --check            validate every case (exit!=0 on any problem)
    python bench/materialize.py --all  <out_dir>   materialize all into <out_dir>/<id>/repo
    python bench/materialize.py <id>   <out_dir>   materialize one into <out_dir>/<id>/repo
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
import py_compile
from pathlib import Path

CASES_DIR = Path(__file__).resolve().parent / "fixtures" / "traprepo"

VALID_KINDS = {"malicious", "benign"}
VALID_EXPECTED = {"block", "warn", "pass"}
VALID_CATEGORIES = {
    "agent-config", "instruction-file", "ide", "package-install", "python",
    "rust", "build", "git", "skill", "mcp", "content-obfuscation", "binary",
    "docs", "ci",
}
KNOWN_GENERATORS = {
    "repeat_text", "pyc", "zip", "binary", "git_dir",
    "variation_selectors", "tag_chars",
}
REQUIRED_FIELDS = [
    "id", "title", "kind", "expected", "category", "technique", "trigger",
    "incident", "sources", "files", "notes",
]


# --------------------------------------------------------------------------- #
# Generators. Each single-file generator takes a params dict and returns bytes.
# "git_dir" is handled separately because it writes a small directory tree.
# --------------------------------------------------------------------------- #
def gen_repeat_text(params: dict) -> bytes:
    head = params.get("head", "")
    repeat = params.get("repeat", "")
    count = int(params.get("count", 0))
    tail = params.get("tail", "")
    return (head + repeat * count + tail).encode("utf-8")


def gen_pyc(params: dict) -> bytes:
    """Compile params['source'] for the running interpreter; return .pyc bytes."""
    source = params["source"]
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "_pah_src.py"
        src.write_text(source, encoding="utf-8")
        cfile = Path(td) / "_pah_src.pyc"
        py_compile.compile(str(src), cfile=str(cfile), doraise=True)
        return cfile.read_bytes()


def gen_zip(params: dict) -> bytes:
    """Build a zip from params['entries'] = {archive_name: text}."""
    entries = params["entries"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, text in entries.items():
            z.writestr(name, text)
    return buf.getvalue()


_MAGIC = {"elf": b"\x7fELF", "pe": b"MZ", "macho": b"\xcf\xfa\xed\xfe", "ttf": b"\x00\x01\x00\x00", "woff2": b"wOF2"}


def gen_binary(params: dict) -> bytes:
    """Magic header + deterministic filler + embedded ASCII strings. Not code."""
    magic = _MAGIC[params["magic"]]
    size = int(params.get("size", 256))
    strings = params.get("strings", [])
    body = bytearray()
    body += magic
    body += bytes((i * 7) % 256 for i in range(64))  # deterministic filler
    strblob = b"\x00".join(s.encode("ascii", "replace") for s in strings)
    body += b"\x00" + strblob + b"\x00"
    if len(body) < size:
        body += bytes(size - len(body))  # zero pad to requested size
    return bytes(body)


def gen_variation_selectors(params: dict) -> bytes:
    """GlassWorm encoding: hidden UTF-8 bytes -> variation selectors after `visible`."""
    prefix = params.get("prefix", "")
    visible = params.get("visible", "")
    hidden = params.get("hidden", "")
    suffix = params.get("suffix", "")
    out = [prefix, visible]
    for b in hidden.encode("utf-8"):
        out.append(chr(0xFE00 + b) if b < 16 else chr(0xE0100 + (b - 16)))
    out.append(suffix)
    return "".join(out).encode("utf-8")


def gen_tag_chars(params: dict) -> bytes:
    """ASCII smuggling: hidden ASCII -> Unicode tag characters (U+E0000 + ord)."""
    prefix = params.get("prefix", "")
    hidden = params.get("hidden", "")
    suffix = params.get("suffix", "")
    out = [prefix]
    out.extend(chr(0xE0000 + ord(c)) for c in hidden)
    out.append(suffix)
    return "".join(out).encode("utf-8")


_FILE_GENERATORS = {
    "repeat_text": gen_repeat_text,
    "pyc": gen_pyc,
    "zip": gen_zip,
    "binary": gen_binary,
    "variation_selectors": gen_variation_selectors,
    "tag_chars": gen_tag_chars,
}


def _materialize_git_dir(gitpath: Path, params: dict) -> None:
    gitpath.mkdir(parents=True, exist_ok=True)
    (gitpath / "config").write_text(params.get("config", ""), encoding="utf-8")
    (gitpath / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    hooks = params.get("hooks", {})
    if hooks:
        hdir = gitpath / "hooks"
        hdir.mkdir(parents=True, exist_ok=True)
        for name, text in hooks.items():
            hp = hdir / name
            hp.write_text(text, encoding="utf-8")
            try:
                hp.chmod(hp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            except OSError:
                pass  # executable bit is moot on some filesystems


# --------------------------------------------------------------------------- #
# Materialization
# --------------------------------------------------------------------------- #
def _safe_join(repo: Path, rel: str) -> Path:
    repo_r = repo.resolve()
    dest = (repo / rel).resolve()
    if dest != repo_r and repo_r not in dest.parents:
        raise ValueError(f"path escapes repo: {rel!r}")
    return dest


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def _materialize(case: dict, out_dir) -> tuple[Path, list[str]]:
    repo = Path(out_dir)
    repo.mkdir(parents=True, exist_ok=True)
    skips: list[str] = []

    for rel, content in case.get("files", {}).items():
        _write_bytes(_safe_join(repo, rel), content.encode("utf-8"))

    for g in case.get("generated", []):
        name = g["generator"]
        dest = _safe_join(repo, g["path"])
        params = g.get("params", {})
        if name == "git_dir":
            _materialize_git_dir(dest, params)
            continue
        if name not in _FILE_GENERATORS:
            raise ValueError(f"unknown generator: {name!r}")
        _write_bytes(dest, _FILE_GENERATORS[name](params))

    for s in case.get("symlinks", []):
        link = _safe_join(repo, s["path"])
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(s["target"], link)
        except (OSError, NotImplementedError) as e:
            skips.append(
                f"symlink {s['path']} -> {s['target']}: "
                f"{e.__class__.__name__}: {e} (recorded as skipped, not fatal)"
            )
    return repo, skips


def materialize(case, out_dir) -> Path:
    """Write a case (dict or path to a JSON file) into out_dir. Returns the repo root.

    Symlink failures (e.g. Windows without privilege) are recorded and printed,
    not raised, so a case is skipped rather than crashing the run.
    """
    if not isinstance(case, dict):
        case = json.loads(Path(case).read_text(encoding="utf-8"))
    repo, skips = _materialize(case, out_dir)
    for s in skips:
        print(f"  [skip] {s}", file=sys.stderr)
    return repo


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
URL_RE = re.compile(r'https?://[^\s"\'`<>)\]}\\]+', re.IGNORECASE)

DESTRUCTIVE_RE = [re.compile(p, re.IGNORECASE) for p in [
    r'\brm\s+-[a-z]*r[a-z]*f\b', r'\brm\s+-[a-z]*f[a-z]*r\b',
    r'\brmdir\s+/s\b', r'\bdel\s+/[sq]\b',
    r'\bformat\s+[a-z]:', r'\bformat\s+/[a-z]',
    r'\bmkfs\b', r'\bwipefs\b', r'\bshred\b', r'\bcipher\s+/w\b',
    r'\bdd\s+if=\S+\s+of=/dev/', r'>\s*/dev/sd[a-z]',
    r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:',
    r'\btaskkill\s+/f', r'\bkillall\b', r'\bpkill\b', r'\bkill\s+-9\b',
    r'Remove-Item\b[^\n]*-Recurse[^\n]*-Force[^\n]*[A-Za-z]:\\',
]]


# Standard, non-dereferenced XML / document-format namespace hosts. These appear
# as identifiers (e.g. in a DOCX's [Content_Types].xml), never as network
# endpoints, so they are permitted even inside a malicious fixture. Any
# attacker-controlled URL must still use a reserved domain.
NS_ALLOW = {
    "schemas.openxmlformats.org", "schemas.microsoft.com", "www.w3.org",
    "purl.org", "ns.adobe.com", "schemas.android.com",
}


def is_reserved_host(host: str) -> bool:
    host = host.lower().rstrip(".").split(":")[0]
    if host.endswith(".invalid") or host == "invalid":
        return True
    if host.endswith(".example") or host == "example":
        return True
    if host.endswith(".test") or host == "test":
        return True
    for d in ("example.com", "example.net", "example.org"):
        if host == d or host.endswith("." + d):
            return True
    return False


def _host_of(url: str) -> str:
    m = re.match(r'https?://([^/:?#]+)', url, re.IGNORECASE)
    return m.group(1) if m else ""


def _iter_fixture_text(case: dict):
    """Strings that become materialized fixture content (not case metadata)."""
    yield from case.get("files", {}).values()
    for g in case.get("generated", []):
        yield json.dumps(g.get("params", {}), ensure_ascii=False)
    for s in case.get("symlinks", []):
        yield s.get("target", "")
        yield s.get("path", "")


def _check_case(path: Path, c: dict) -> list[str]:
    errs: list[str] = []
    for f in REQUIRED_FIELDS:
        if f not in c:
            errs.append(f"missing field '{f}'")
    if errs:
        return errs

    if c["id"] != path.stem:
        errs.append(f"id '{c['id']}' != filename stem '{path.stem}'")
    if c["kind"] not in VALID_KINDS:
        errs.append(f"bad kind '{c['kind']}'")
    if c["expected"] not in VALID_EXPECTED:
        errs.append(f"bad expected '{c['expected']}'")
    if c["category"] not in VALID_CATEGORIES:
        errs.append(f"bad category '{c['category']}'")
    if not isinstance(c.get("sources"), list):
        errs.append("sources must be a list")
    if not isinstance(c.get("files"), dict):
        errs.append("files must be a dict")

    if c.get("kind") == "benign" and c.get("expected") != "pass":
        errs.append("benign case must expect 'pass'")
    if c.get("kind") == "malicious" and c.get("expected") not in ("block", "warn"):
        errs.append("malicious case must expect 'block' or 'warn'")
    if c.get("kind") == "malicious" and not c.get("sources"):
        errs.append("malicious case needs at least one source")

    for g in c.get("generated", []):
        if g.get("generator") not in KNOWN_GENERATORS:
            errs.append(f"unknown generator '{g.get('generator')}'")
        if "path" not in g:
            errs.append("generated entry missing 'path'")
    for s in c.get("symlinks", []):
        if "path" not in s or "target" not in s:
            errs.append("symlink entry needs 'path' and 'target'")

    texts = list(_iter_fixture_text(c))
    blob = "\n".join(texts)
    for rx in DESTRUCTIVE_RE:
        m = rx.search(blob)
        if m:
            errs.append(f"forbidden destructive command: {m.group(0)!r}")
    if c.get("kind") == "malicious":
        for t in texts:
            for u in URL_RE.findall(t):
                h = _host_of(u.rstrip('.,);"\''))
                if not is_reserved_host(h) and h.lower() not in NS_ALLOW:
                    errs.append(f"non-reserved URL in malicious fixture: {u}")
    return errs


def check() -> int:
    paths = sorted(CASES_DIR.glob("*.json"))
    if not paths:
        print(f"no cases found in {CASES_DIR}", file=sys.stderr)
        return 1
    problems: list[str] = []
    seen: dict[str, str] = {}
    n_mal = n_ben = 0
    for p in paths:
        try:
            c = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            problems.append(f"{p.name}: invalid JSON: {e}")
            continue
        cid = c.get("id")
        if cid in seen:
            problems.append(f"{p.name}: duplicate id '{cid}' (also {seen[cid]})")
        elif cid:
            seen[cid] = p.name
        if c.get("kind") == "malicious":
            n_mal += 1
        elif c.get("kind") == "benign":
            n_ben += 1
        problems += [f"{p.name}: {e}" for e in _check_case(p, c)]

    if problems:
        print("CHECK FAILED:", file=sys.stderr)
        for pr in problems:
            print("  - " + pr, file=sys.stderr)
        print(f"\n{len(problems)} problem(s) across {len(paths)} case file(s)",
              file=sys.stderr)
        return 1
    print(f"OK: {len(paths)} cases valid  ({n_mal} malicious, {n_ben} benign)")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _materialize_one(c: dict, out_root: Path) -> list[str]:
    repo = out_root / c["id"] / "repo"
    if repo.exists():
        shutil.rmtree(repo)
    _, skips = _materialize(c, repo)
    return skips


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TrapRepo materializer / validator")
    ap.add_argument("--check", action="store_true", help="validate the corpus")
    ap.add_argument("--all", metavar="OUT_DIR", help="materialize every case")
    ap.add_argument("pos", nargs="*", help="<id> <out_dir> to materialize one case")
    args = ap.parse_args(argv)

    if args.check:
        return check()

    if args.all:
        out_root = Path(args.all)
        paths = sorted(CASES_DIR.glob("*.json"))
        if not paths:
            print(f"no cases found in {CASES_DIR}", file=sys.stderr)
            return 1
        all_skips: list[str] = []
        for p in paths:
            c = json.loads(p.read_text(encoding="utf-8"))
            all_skips += [f"{c['id']}: {s}" for s in _materialize_one(c, out_root)]
        print(f"materialized {len(paths)} cases into {out_root}")
        if all_skips:
            print("skipped (non-fatal):")
            for s in all_skips:
                print("  - " + s)
        return 0

    if len(args.pos) == 2:
        cid, out = args.pos
        p = CASES_DIR / f"{cid}.json"
        if not p.exists():
            print(f"no such case: {cid}", file=sys.stderr)
            return 2
        c = json.loads(p.read_text(encoding="utf-8"))
        skips = _materialize_one(c, Path(out))
        print(f"materialized {cid} into {Path(out) / cid / 'repo'}")
        for s in skips:
            print("  [skip] " + s)
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
