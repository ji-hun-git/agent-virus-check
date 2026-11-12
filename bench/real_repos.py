#!/usr/bin/env python3
"""False-positive check on popular, legitimate repositories.

    python bench/real_repos.py [--name NAME] [--only owner/repo ...] [--cache DIR] [--top N]

Each repository is cloned with the scanner's safe clone (depth 1, no hooks, no submodules, no templates), scanned,
and deleted. The commit scanned is recorded so the run can be repeated. Results: bench/results/<name>-real-repos.json.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from pah.scan import scan  # noqa: E402

REPOS = [
    # npm: install scripts, native builds, downloads at install, git hooks
    "expressjs/express", "sindresorhus/got", "typicode/husky", "lovell/sharp", "nodejs/node-addon-examples",
    "puppeteer/puppeteer", "evanw/esbuild", "prettier/prettier",
    # Python: setup/pyproject builds, conftest.py, requirements
    "psf/requests", "pallets/flask", "fastapi/fastapi", "pytest-dev/pytest", "python-poetry/poetry", "astral-sh/ruff",
    # Rust: build.rs and procedural macros
    "BurntSushi/ripgrep", "serde-rs/serde", "tokio-rs/tokio",
    # AI agents, skills and MCP servers: agent configs, hooks, instruction files
    "anthropics/claude-code", "openai/codex", "google-gemini/gemini-cli", "modelcontextprotocol/servers",
    "anthropics/skills", "affaan-m/everything-claude-code",
    # installers and tooling with curl | sh in their docs, devcontainers, build wrappers
    "ohmyzsh/ohmyzsh", "nvm-sh/nvm", "Homebrew/install", "cli/cli", "spring-projects/spring-petclinic",
    "microsoft/vscode-remote-try-node", "vitejs/vite",
]


def remove_tree(path: Path) -> None:
    """rmtree that also removes read-only files (git marks pack files read-only on Windows)."""
    def retry(func, target, _info):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    shutil.rmtree(path, onerror=retry)  # onexc replaces onerror only from Python 3.12


def clone(slug: str, dest: Path, attempts: int = 3) -> str:
    """Safe shallow clone, retried: large packs over flaky connections fail part way more often than not."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    error = ""
    for attempt in range(attempts):
        if dest.exists():
            remove_tree(dest)
        cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "protocol.ext.allow=never",
               "-c", "core.longpaths=true"] + (["-c", "http.version=HTTP/1.1"] if attempt else []) + [
               "clone", "--depth", "1", "--no-recurse-submodules", "--template=", "--quiet", "--",
               f"https://github.com/{slug}", str(dest)]
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=900, env=env, check=False)
        except subprocess.TimeoutExpired:
            error = "clone timed out"
            continue
        if done.returncode == 0:
            return subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True,
                                  check=False).stdout.strip()
        error = done.stderr.strip()[:300]
    try:
        return download_tarball(slug, dest)
    except (OSError, ValueError, tarfile.TarError) as err:
        raise RuntimeError(f"{error}; tarball fallback failed: {err}") from err


def download_tarball(slug: str, dest: Path) -> str:
    """Fallback for repositories whose git pack keeps failing part way: GitHub's tarball of the default branch, unpacked
    member by member with tarfile's "data" filter (no absolute paths, no links out of the folder)."""
    if dest.exists():
        remove_tree(dest)
    req = urllib.request.Request(f"https://api.github.com/repos/{slug}/tarball",
                                 headers={"User-Agent": "agent-white-hat-benchmark", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=900) as resp:
        data = resp.read()
    dest.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        top = members[0].name.split("/")[0]  # owner-repo-<short sha>
        for member in members:
            rel = member.name[len(top) + 1:]
            if not rel:
                continue
            member.name = rel
            try:
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, dest, filter="data")
                elif member.isfile() or member.isdir():
                    tar.extract(member, dest)
            except (tarfile.TarError, OSError):
                continue
    sha = top.rsplit("-", 1)[-1]
    (dest / ".pah-commit").write_text(sha + "\n", encoding="utf-8")
    return sha


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default=time.strftime("%Y-%m-%d"))
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--top", type=int, default=12, help="findings of medium or higher to keep per repository")
    ap.add_argument("--cache", type=Path, help="keep clones in this folder and reuse them on the next run")
    args = ap.parse_args(argv)
    rows = []
    for slug in args.only or REPOS:
        tmp = Path(tempfile.mkdtemp(prefix="pah-real-"))
        repo = (args.cache / slug.replace("/", "__")) if args.cache else tmp / "repo"
        try:
            sha = ""
            if args.cache and (repo / ".pah-commit").is_file():
                sha = (repo / ".pah-commit").read_text(encoding="utf-8").strip()
            elif args.cache and (repo / ".git").is_dir():
                sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True,
                                     check=False).stdout.strip()
                tracked = subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True,
                                         check=False).stdout.split("\n", 1)[0]
                if not sha or not tracked or not (repo / tracked).exists():
                    sha = ""  # a clone that failed part way: fetch it again
            if not sha:
                sha = clone(slug, repo)
            started = time.monotonic()
            rep = scan(repo)
            top = [{"rule": f.rule, "severity": f.severity, "path": f.path, "line": f.line, "message": f.message[:160]}
                   for f in rep.sorted_findings() if f.severity in ("medium", "high", "critical")][:args.top]
            rows.append({"repo": slug, "commit": sha, "verdict": rep.verdict, "files": rep.stats.get("files"),
                         "seconds": round(time.monotonic() - started, 1), "surfaces": len(rep.surfaces),
                         "incomplete": rep.incomplete[:3], "top": top})
            print(f"{rep.verdict:10} {slug:40} {rep.stats.get('files', 0):>6} files {rows[-1]['seconds']:>6}s  "
                  + "; ".join(f"{t['severity']} {t['rule']} {t['path']}:{t['line']}" for t in top[:3]), flush=True)
        except (RuntimeError, OSError, subprocess.SubprocessError) as err:
            rows.append({"repo": slug, "error": str(err)})
            print(f"error      {slug}: {err}", flush=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    out = HERE / "results" / f"{args.name}-real-repos.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"date": time.strftime("%Y-%m-%d"), "platform": sys.platform, "repos": rows}, indent=1)
                   + "\n", encoding="utf-8")
    counts = {}
    for r in rows:
        counts[r.get("verdict", "error")] = counts.get(r.get("verdict", "error"), 0) + 1
    print(f"\n{len(rows)} repositories: {counts}  ->  {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
