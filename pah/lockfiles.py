"""Exact dependency versions from lockfiles and pinned manifests, for known-vulnerability lookups.

Only what the files say is read; nothing is resolved or installed. Ecosystem names are OSV's.
"""
from __future__ import annotations

import json
import posixpath
import re

NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")
_YARN_BLOCK = re.compile(r'(?m)^"?((?:@[^@\s",/]+/)?[^@\s",/]+)@[^\n]*:\s*\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?[ \t]+"?([^"\s]+)"?')
_PNPM_KEY = re.compile(r"(?m)^[ \t]{2}['\"]?/?((?:@[^@\s'\"/]+/)?[^@\s'\"(/]+)@(\d[^\s('\":]*)")
_TOML_PACKAGE = re.compile(r'(?ms)^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')
_REQ_PIN = re.compile(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*==\s*([\w.!+\-]+)")
_GEM_SPEC = re.compile(r"(?m)^ {4}([A-Za-z0-9][\w.\-]*) \(([\d][^)\s,]*)\)$")
_GO_SUM = re.compile(r"(?m)^(\S+) v([^\s/]+) h1:")


def _line(text: str, needle: str) -> int:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else 0


def pins_in(path: str, text: str) -> list[tuple[str, str, str, int]]:
    """(ecosystem, name, version, line) pinned by one file."""
    name = posixpath.basename(path).lower()
    out: list[tuple[str, str, str, int]] = []
    if name in NPM_LOCKS:
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for key, info in (data.get("packages") or {}).items():
            if key and isinstance(info, dict) and info.get("version") and not info.get("link"):
                out.append(("npm", key.rsplit("node_modules/", 1)[-1], str(info["version"]), 0))

        def walk(deps: dict) -> None:
            for dep, info in (deps or {}).items():
                if isinstance(info, dict) and info.get("version"):
                    out.append(("npm", dep, str(info["version"]), 0))
                    walk(info.get("dependencies") or {})

        if not data.get("packages"):
            walk(data.get("dependencies") or {})
    elif name == "yarn.lock":
        out += [("npm", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1) for m in _YARN_BLOCK.finditer(text)]
    elif name == "pnpm-lock.yaml":
        out += [("npm", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1) for m in _PNPM_KEY.finditer(text)]
    elif name in ("poetry.lock", "uv.lock", "pdm.lock"):
        out += [("PyPI", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1) for m in _TOML_PACKAGE.finditer(text)]
    elif name == "cargo.lock":
        out += [("crates.io", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1)
                for m in _TOML_PACKAGE.finditer(text)]
    elif name == "pipfile.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for section in ("default", "develop"):
            for dep, info in (data.get(section) or {}).items():
                version = str((info or {}).get("version", "")).lstrip("=")
                if version:
                    out.append(("PyPI", dep, version, _line(text, f'"{dep}"')))
    elif re.fullmatch(r"(?:requirements|constraints)[\w.-]*\.(?:txt|in)", name):
        out += [("PyPI", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1) for m in _REQ_PIN.finditer(text)]
    elif name == "gemfile.lock":
        out += [("RubyGems", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1) for m in _GEM_SPEC.finditer(text)]
    elif name == "composer.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section) or []:
                if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                    out.append(("Packagist", pkg["name"], str(pkg["version"]).lstrip("v"), _line(text, pkg["name"])))
    elif name == "go.sum":
        seen = set()
        for m in _GO_SUM.finditer(text):
            if (m.group(1), m.group(2)) not in seen:
                seen.add((m.group(1), m.group(2)))
                out.append(("Go", m.group(1), m.group(2), text.count("\n", 0, m.start()) + 1))
    return out


def pinned(files: dict) -> list[tuple[str, str, str, str, int]]:
    """(ecosystem, name, version, path, line) across a scanned tree, one entry per package and version."""
    seen: dict[tuple[str, str, str], tuple[str, str, str, str, int]] = {}
    for rel, f in files.items():
        if f.text is None or "node_modules/" in rel or "!/" in rel:
            continue
        for eco, name, version, line in pins_in(rel, f.text):
            seen.setdefault((eco, name, version), (eco, name, version, rel, line))
    return list(seen.values())
