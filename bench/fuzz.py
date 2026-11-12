#!/usr/bin/env python3
"""Evasion fuzzer: rewrite every malicious TrapRepo case the way an attacker would to get past the rules, and count
what gets through.

    python bench/fuzz.py                      # all cases, all operators; results in bench/results/<date>-fuzz.json
    python bench/fuzz.py --only npm-postinstall-beacon --ops js_split js_char_codes
    python bench/fuzz.py --check              # exit 1 if any mutant gets past (for CI)

Each operator rewrites the code files of a case (JavaScript, Python, shell) without changing what they do: names
split into pieces, strings built from character codes or hex escapes, members reached through brackets and aliases,
the whole file wrapped in a base64 loader, the payload delayed, shell commands assembled from variables. A mutant
that a case's expected verdict no longer catches is a bypass. Neutral operators (renaming, comments) also run over
the benign cases, where any flag is a false alarm the rewrite caused.

Nothing is executed: cases are written to a temporary folder, scanned and deleted, and their payloads are inert.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import hashlib
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from materialize import materialize  # noqa: E402
from pah import __version__  # noqa: E402
from pah.scan import scan  # noqa: E402

CASES = HERE / "fixtures" / "traprepo"
# The base64 loader shapes are test data, kept with the other fixtures so this script is not itself a loader.
LOADERS = json.loads((HERE / "fixtures" / "fuzz-loaders.json").read_text(encoding="utf-8"))
RESULTS = HERE / "results"
JS = (".js", ".mjs", ".cjs", ".ts", ".ttf")
PY = (".py",)
SH = (".sh",)
STRING = re.compile(r"(?<![\w$`])(['\"])((?:\\.|(?!\1)[^\\\n])*)\1")
JS_MEMBERS = r"request|write|end|get|post|exec|execSync|spawn|readFileSync|writeFileSync|env|homedir|stringify|on"
PY_MEMBERS = r"urlopen|Request|system|popen|expanduser|request|post|get|b64decode|run|check_output"
SH_TOOLS = ("curl", "wget", "bash", "sh", "base64")


def _outside_strings(code: str, fn) -> str:
    """Apply fn to the parts of code that are not string literals."""
    out, last = [], 0
    for m in STRING.finditer(code):
        out.append(fn(code[last:m.start()]))
        out.append(m.group())
        last = m.end()
    out.append(fn(code[last:]))
    return "".join(out)


def _strings(code: str, fn, min_len: int = 3) -> str:
    """Replace each string literal (content of min_len characters or more, no escapes) with fn(quote, content)."""
    def repl(m: re.Match) -> str:
        content = m.group(2)
        if len(content) < min_len or "\\" in content or m.group(0).startswith(("'use strict'", '"use strict"')):
            return m.group()
        return fn(m.group(1), content)
    return STRING.sub(repl, code)


def _halves(s: str) -> tuple[str, str]:
    mid = max(1, len(s) // 2)
    return s[:mid], s[mid:]


# ------------------------------------------------------------------------------------------------ operators


def js_split(code: str) -> str:
    return _strings(code, lambda q, s: "({0}{1}{0} + {0}{2}{0})".format(q, *_halves(s)))


def js_array_join(code: str) -> str:
    return _strings(code, lambda q, s: "[" + ", ".join(f"{q}{c}{q}" for c in _halves(s)) + "].join('')")


def js_char_codes(code: str) -> str:
    return _strings(code, lambda q, s: "String.fromCharCode(" + ",".join(str(ord(c)) for c in s) + ")")


def js_hex_escape(code: str) -> str:
    return _strings(code, lambda q, s: q + "".join(f"\\x{ord(c):02x}" if ord(c) < 256 else c for c in s) + q)


def js_rot13(code: str) -> str:
    decoder = "const __d = s => s.replace(/[a-z]/gi, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= " \
              "(c = c.charCodeAt(0) + 13) ? c : c - 26));\n"
    out = _strings(code, lambda q, s: f"__d({q}{codecs.encode(s, 'rot13')}{q})")
    return decoder + out if out != code else code


def js_brackets(code: str) -> str:
    return _outside_strings(code, lambda part: re.sub(rf"\.({JS_MEMBERS})\b", r"['\1']", part))


def js_alias_require(code: str) -> str:
    if "require(" not in code:
        return code
    return "const __r = module.constructor.prototype.require.bind(module);\n" + _outside_strings(
        code, lambda part: re.sub(r"(?<![\w.$])require\(", "__r(", part))


def _b64(code: str) -> str:
    return base64.b64encode(code.encode()).decode()


def js_eval_base64(code: str) -> str:
    return LOADERS["js_eval"].format(blob=_b64(code))


def js_function_base64(code: str) -> str:
    return LOADERS["js_function"].format(blob=_b64(code))


def js_delay(code: str) -> str:
    return "setTimeout(() => {\n" + code + "\n}, 1500);\n"


def py_split(code: str) -> str:
    return _strings(code, lambda q, s: "({0}{1}{0} + {0}{2}{0})".format(q, *_halves(s)))


def py_join(code: str) -> str:
    return _strings(code, lambda q, s: "''.join([" + ", ".join(f"{q}{c}{q}" for c in _halves(s)) + "])")


def py_chr(code: str) -> str:
    return _strings(code, lambda q, s: "''.join(map(chr, [" + ", ".join(str(ord(c)) for c in s) + "]))")


def py_hex_escape(code: str) -> str:
    return _strings(code, lambda q, s: q + "".join(f"\\x{ord(c):02x}" if ord(c) < 256 else c for c in s) + q)


def py_rot13(code: str) -> str:
    out = _strings(code, lambda q, s: f"__import__('codecs').decode({q}{codecs.encode(s, 'rot13')}{q}, 'rot13')")
    return out


def py_getattr(code: str) -> str:
    return _outside_strings(code, lambda part: re.sub(rf"\b([A-Za-z_][\w.]*)\.({PY_MEMBERS})\(",
                                                      r"getattr(\1, '\2')(", part))


def py_exec_base64(code: str) -> str:
    return LOADERS["py_exec"].format(blob=_b64(code))


def sh_split_tools(code: str) -> str:
    lines, header = code.split("\n"), []
    shebang = [lines.pop(0)] if lines and lines[0].startswith("#!") else []
    body = "\n".join(lines)
    for i, tool in enumerate(SH_TOOLS):
        if re.search(rf"(?<![\w./-]){tool}(?![\w.-])", body):
            a, b = _halves(tool)
            header.append(f"_t{i}a={a}; _t{i}b={b}")
            body = re.sub(rf"(?<![\w./-]){tool}(?![\w.-])", f"${{_t{i}a}}${{_t{i}b}}", body)
    return "\n".join(shebang + header + [body]) if header else code


def sh_printf_url(code: str) -> str:
    def url(m: re.Match) -> str:
        return '"$(printf \'' + "".join(f"\\x{ord(c):02x}" for c in m.group()) + '\')"'
    return re.sub(r"https?://[^\s\"'>|)]+", url, code)


def sh_base64(code: str) -> str:
    lines = code.split("\n")
    shebang = lines.pop(0) + "\n" if lines and lines[0].startswith("#!") else ""
    return LOADERS["sh_pipe"].format(shebang=shebang, blob=_b64("\n".join(lines)))


def rename_identifiers(code: str) -> str:
    """Neutral: rename variables declared with const/let/var (JS) or assigned at the start of a line (Python)."""
    names = set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_]\w{2,})\b", code)) | \
        set(re.findall(r"(?m)^([a-z_][a-z0-9_]{2,})\s*=(?!=)", code))
    for i, name in enumerate(sorted(names, key=len, reverse=True)):
        code = _outside_strings(code, lambda part, n=name, k=i: re.sub(rf"(?<![\w.$]){n}\b", f"v{k}x", part))
    return code


def add_comments(code: str) -> str:
    """Neutral: a comment line after every line of code."""
    return "\n".join(line + ("\n# note" if line.strip() and not line.rstrip().endswith(("\\", ",", "(", "[", "{"))
                             else "") for line in code.split("\n"))


OPERATORS = {
    "js_split": (JS, js_split), "js_array_join": (JS, js_array_join), "js_char_codes": (JS, js_char_codes),
    "js_hex_escape": (JS, js_hex_escape), "js_rot13": (JS, js_rot13), "js_brackets": (JS, js_brackets),
    "js_alias_require": (JS, js_alias_require), "js_eval_base64": (JS, js_eval_base64),
    "js_function_base64": (JS, js_function_base64), "js_delay": (JS, js_delay),
    "py_split": (PY, py_split), "py_join": (PY, py_join), "py_chr": (PY, py_chr), "py_hex_escape": (PY, py_hex_escape),
    "py_rot13": (PY, py_rot13), "py_getattr": (PY, py_getattr), "py_exec_base64": (PY, py_exec_base64),
    "sh_split_tools": (SH, sh_split_tools), "sh_printf_url": (SH, sh_printf_url), "sh_base64": (SH, sh_base64),
}
NEUTRAL = {"rename": (JS + PY, rename_identifiers), "py_comments": (PY + SH, add_comments)}


def _cases(only: list[str] | None) -> list[dict]:
    out = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(CASES.glob("*.json"))]
    return [c for c in out if not only or c["id"] in only]


def _mutate(case: dict, suffixes: tuple, fn) -> dict | None:
    """The case with fn applied to its code files (test files left alone), or None when nothing changed."""
    files, changed = dict(case.get("files", {})), False
    for rel, text in files.items():
        if not rel.lower().endswith(suffixes) or re.search(r"(?:^|/)(?:tests?|__tests__)/|\.test\.", rel):
            continue
        new = fn(text)
        if new != text:
            files[rel], changed = new, True
    return {**case, "files": files} if changed else None


def _verdict(case: dict) -> tuple[str, list[str]]:
    tmp = Path(tempfile.mkdtemp(prefix="pah-fuzz-"))
    try:
        root = materialize(case, tmp)
        rep = scan(root)
        return rep.verdict, sorted({f.rule for f in rep.findings if f.severity in ("medium", "high", "critical")})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run(only: list[str] | None = None, ops: list[str] | None = None, progress=None) -> dict:
    rows, untestable = [], []
    for case in _cases(only):
        baseline, _rules = _verdict(case)
        if (case["kind"] == "malicious" and baseline not in ("block", "warn")) or \
                (case["kind"] == "benign" and baseline != "pass"):
            untestable.append(case["id"])  # e.g. a symlink case on a system that cannot create symlinks
            continue
        pool = OPERATORS if case["kind"] == "malicious" else NEUTRAL
        for name, (suffixes, fn) in pool.items():
            if ops and name not in ops:
                continue
            mutant = _mutate(case, suffixes, fn)
            if mutant is None:
                continue
            verdict, rules = _verdict(mutant)
            expected = case["expected"]
            if case["kind"] == "malicious":
                bypass = verdict not in ("block", "warn") or (expected == "block" and verdict != "block")
            else:
                bypass = verdict != "pass"  # a false alarm caused by the rewrite
            rows.append({"case": case["id"], "kind": case["kind"], "operator": name, "expected": expected,
                         "verdict": verdict, "rules": rules, "bypass": bypass})
            if progress:
                progress(rows[-1])
    return {"rows": rows, "untestable": untestable}


def summarize(rows: list[dict]) -> list[str]:
    lines = []
    for name in list(OPERATORS) + list(NEUTRAL):
        mine = [r for r in rows if r["operator"] == name]
        if mine:
            bad = [r for r in mine if r["bypass"]]
            lines.append(f"{name:20} {len(mine):4} mutants  {len(mine) - len(bad):4} held  {len(bad):3} "
                         + ("false alarms" if name in NEUTRAL else "got past"))
    mal = [r for r in rows if r["kind"] == "malicious"]
    ben = [r for r in rows if r["kind"] == "benign"]
    lines.append(f"\n{len(mal)} malicious mutants: {sum(not r['bypass'] for r in mal)} held "
                 f"({sum(r['verdict'] in ('block', 'warn') for r in mal)} still caught); "
                 f"{len(ben)} benign rewrites: {sum(r['bypass'] for r in ben)} false alarms")
    return lines


def code_hash() -> str:
    """The same hash bench/run.py records: the scanner's code that produced the results."""
    h = hashlib.sha256()
    for p in sorted((HERE.parent / "pah").rglob("*.py")):
        h.update(p.read_bytes())
    return h.hexdigest()[:12]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", nargs="*", help="case ids")
    ap.add_argument("--ops", nargs="*", choices=list(OPERATORS) + list(NEUTRAL))
    ap.add_argument("--name", default=time.strftime("%Y-%m-%d"))
    ap.add_argument("--check", action="store_true", help="exit 1 when any mutant gets past or a rewrite causes a flag")
    args = ap.parse_args(argv)
    started = time.monotonic()
    data = run(args.only, args.ops)
    data.update({"name": args.name, "date": time.strftime("%Y-%m-%d"), "version": __version__, "code": code_hash(),
                 "seconds": round(time.monotonic() - started, 1), "operators": list(OPERATORS),
                 "neutral": list(NEUTRAL)})
    print("\n".join(summarize(data["rows"])))
    for r in data["rows"]:
        if r["bypass"]:
            print(f"  {r['operator']:20} {r['case']:42} {r['verdict']:6} (expected {r['expected']}) {r['rules']}")
    if not args.check:
        RESULTS.mkdir(exist_ok=True)
        path = RESULTS / f"{args.name}-fuzz.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"-> {path}")
    return 1 if args.check and any(r["bypass"] for r in data["rows"]) else 0


if __name__ == "__main__":
    sys.exit(main())
