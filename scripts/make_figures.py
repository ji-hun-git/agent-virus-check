#!/usr/bin/env python3
"""Draw the README figures from the benchmark results, in light and dark, English and Korean. Standard library only.

    python scripts/make_figures.py          # every SVG into docs/figures/
    python scripts/make_figures.py --png    # also docs/figures/social-preview.png (needs Chrome or Edge)

hero      the banner: what the guard does, a recorded agent run, the headline numbers
pipeline  how a tool call reaches the guard, and what the scan does
results   malicious repositories caught by the rules and by models reading the repository
scan      what `pah scan` prints for one TrapRepo case (made by running the scanner, colors as in a terminal)
repos     the widely used repositories scanned in full for false alarms
social    the 1280 x 640 card for the repository's social preview

Every number comes from bench/results/; nothing is typed in by hand except the words around it.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench" / "results"
OUT = ROOT / "docs" / "figures"
DATE = "2026-11-11"

SANS = ('-apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, "Apple SD Gothic Neo", '
        '"Malgun Gothic", "Noto Sans KR", sans-serif')
MONO = ('ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", "D2Coding", "Malgun Gothic", '
        'monospace')

# GitHub's own palette, so the figures sit naturally on the page in either theme. Outcome colors were checked for
# color-blind separation (adjacent pairs, protan/deutan/tritan) against the card surface of each theme.
THEMES = {
    "light": {
        "card": "#ffffff", "card2": "#f6f8fa", "border": "#d1d9e0", "line": "#e1e6eb",
        "fg": "#1f2328", "muted": "#59636e", "subtle": "#818b98",
        "accent": "#2f6fde", "accent_fg": "#1f5bc6", "accent_bg": "#ebf2fe",
        "good": "#1a7f37", "good_bg": "#dafbe1", "good_line": "#9fe0b0",
        "warn": "#9a6700", "warn_bg": "#fff8c5", "warn_line": "#e8d27a",
        "bad": "#cf222e", "bad_bg": "#ffebe9", "bad_line": "#ffb8b1",
        "bar_all": "#2f6fde", "bar_some": "#e0a526", "bar_missed": "#cf222e", "bar_refused": "#8c959f",
        "ink_all": "#ffffff", "ink_some": "#1f2328", "ink_missed": "#ffffff", "ink_refused": "#ffffff",
        "hero_a": "#eef4ff", "hero_b": "#ffffff", "dots": "#2f6fde", "dots_op": "0.13", "glow_op": "0.16",
        "band": "#f6f8fa",
        "term": {"bg": "#f6f8fa", "border": "#d1d9e0", "bar": "#eaeef2", "fg": "#1f2328", "muted": "#59636e",
                 "red": "#cf222e", "orange": "#bc4c00", "yellow": "#9a6700", "cyan": "#1b7c83", "blue": "#0550ae",
                 "green": "#116329", "badge_fg": "#ffffff", "warn_badge_fg": "#1f2328",
                 "badge_red": "#cf222e", "badge_yellow": "#d4a72c", "badge_green": "#2da44e", "badge_gray": "#818b98"},
    },
    "dark": {
        "card": "#0d1117", "card2": "#151b23", "border": "#3d444d", "line": "#262c36",
        "fg": "#f0f6fc", "muted": "#9198a1", "subtle": "#6e7681",
        "accent": "#4c8df6", "accent_fg": "#79b0ff", "accent_bg": "#152338",
        "good": "#3fb950", "good_bg": "#12261a", "good_line": "#2a5a35",
        "warn": "#d29922", "warn_bg": "#2a2111", "warn_line": "#6b5212",
        "bad": "#f85149", "bad_bg": "#2d1214", "bad_line": "#7a2a2a",
        "bar_all": "#4c8df6", "bar_some": "#d4a232", "bar_missed": "#da3633", "bar_refused": "#6e7681",
        "ink_all": "#ffffff", "ink_some": "#0d1117", "ink_missed": "#ffffff", "ink_refused": "#ffffff",
        "hero_a": "#0f1a2e", "hero_b": "#0d1117", "dots": "#8fb4ff", "dots_op": "0.10", "glow_op": "0.22",
        "band": "#151b23",
        "term": {"bg": "#151b23", "border": "#3d444d", "bar": "#1c232c", "fg": "#e6edf3", "muted": "#8b949e",
                 "red": "#ff7b72", "orange": "#ffa657", "yellow": "#e3b341", "cyan": "#56d4dd", "blue": "#79c0ff",
                 "green": "#7ee787", "badge_fg": "#ffffff", "warn_badge_fg": "#0d1117",
                 "badge_red": "#da3633", "badge_yellow": "#d29922", "badge_green": "#2ea043", "badge_gray": "#6e7681"},
    },
}
# The recorded agent run in the hero is shown in a dark terminal in both themes.
HERO_TERM = {"bg": "#0b1020", "border": "#26304a", "bar": "#121a2e", "fg": "#e6edf3", "muted": "#8b949e",
             "dim": "#c4cdd8", "prompt": "#79c0ff", "tool": "#3fb950", "red": "#ff7b72", "high": "#ffa657",
             "low": "#8b949e", "reply": "#e6edf3"}
AGENTS = ["Claude Code", "Codex", "Gemini CLI", "Antigravity", "Cursor", "Copilot", "Devin", "Kiro", "Cline"]

# ---------------------------------------------------------------------------------------------------------------------
# Words. Numbers are filled in from the results.

STR = {
    "en": {
        "hero_alt": "personal-anti-hack: a shield in front of everything your AI agent opens, installs and runs",
        "tagline": [[("A shield in front of", "fg")], [("everything your AI agent", "fg")],
                    [("opens, installs and runs.", "accent")]],
        "tag_size": 31,
        "hero_sub": "Reads repositories, skills, MCP servers and packages before they run, denies the setup commands "
                    "of the ones that fail, and watches your agents' settings. The checks run in code, on your machine.",
        "one_guard": "ONE GUARD FOR",
        "term_title": "agent session · approvals off",
        "caption": "Recorded run: Claude Code {cc}, approvals off · bench/live_drill.py",
        "stats": [("malicious test repositories", "caught, rules only, offline"),
                  ("benign look-alikes", "flagged"),
                  ("widely used repositories", "blocked"),
                  ("live agent runs in which", "the payload ran")],
        "pipe_title": "How it works",
        "pipe_sub": "Every command your agent runs passes the guard first. A setup command gets the whole project scanned "
                    "before it may run.",
        "touch_h": "What your agent touches",
        "touch": ["Git repositories", "Packages: npm, PyPI, …", "Agent Skills", "MCP servers", "Archives, downloads",
                  "AGENTS.md, CLAUDE.md"],
        "agent_h": "Your AI agent",
        "guard_h": "The guard",
        "guard_sub": "a pre-tool hook",
        "guard_body": "Checks each command for download-and-run, decode-and-run, credential reads, persistence, "
                      "approvals turned off, look-alike packages and registry redirects.",
        "guard_setup": "Setup commands (npm install, pip install -e ., make, pytest) scan the project first.",
        "out_h": "Outcome",
        "outcomes": [("BLOCK", "bad", "Denied. Nothing runs."), ("WARN", "warn", "You are asked."),
                     ("PASS", "good", "Your agent's own rules apply.")],
        "out_note": "The guard never answers \u201callow\u201d.",
        "a_ab": ["clones,", "reads"],
        "a_bc": ["every", "tool call"],
        "a_cd": ["command", "checks"],
        "a_scan": "setup: scan the project",
        "a_verdict": "verdict",
        "scan_h": "Inside the scan",
        "stages": [(["Map what runs", "on its own"],
                    "Agent hooks, npm and pip lifecycle scripts, IDE tasks, dev containers, build scripts, git hooks, "
                    "instruction files, and the files they run."),
                   (["Read everything"],
                    "Whole files, never truncated. Base64, hex and escapes decoded; hidden Unicode, padding, archives, "
                    "and binaries found by what they are."),
                   (["Judge by context"],
                    "The same line is critical in a hook, high in code and quiet in docs. Downloads judged by host; "
                    "combinations escalate."),
                   (["Verdict"], "High or critical blocks, medium warns. Anything not read in full is never called "
                                 "clean.")],
        "addons": ["+ local antivirus: Microsoft Defender, ClamAV", "+ known vulnerabilities: OSV (--online)",
                   "+ config watch: pah watch"],
        "res_title": "Malicious repositories caught, out of {n}",
        "res_sub1": "TrapRepo: {n} malicious and {b} benign repositories built from real 2025-26 techniques, with inert payloads.",
        "res_sub2": "Each model read the repository (up to 100,000 characters) and answered \u201csafe\u201d or "
                    "\u201cunsafe\u201d, {k} runs per case.",
        "legend": ["Caught in every run", "Caught in some runs", "Missed in every run", "Refused in every run (no answer)"],
        "res_rules": "rules only, offline",
        "res_model": "the model alone",
        "res_benign": "Benign flagged",
        "res_every": "every run",
        "res_any": "any run",
        "res_of": "{a} of {b}",
        "res_foot": "A refused review is not a clean result: personal-anti-hack reports it as \u201cnot reviewed\u201d. "
                    "Every case, run and answer is in bench/results/.",
        "repo_title": "{n} widely used repositories, scanned in full",
        "repo_big": "0 blocked",
        "repo_sub": "{p} pass and {w} warn, across {f} files. Each warning is worth knowing before an agent sets the "
                    "project up.",
        "groups": ["JavaScript", "Python", "Rust", "AI agents, MCP", "Shell, installers", "Go, Java, containers"],
        "repo_notes": ["ruff and the MCP servers ship Claude Code SessionStart hooks.",
                       "A gemini-cli skill pipes a third-party install script into sh."],
        "repo_legend": ["pass", "warn", "block"],
        "scan_cmd": "pah scan ./acme-utils",
        "scan_title": "Terminal",
        "scan_note": "Trimmed: each high or critical finding also prints why it matters and what to do.",
        "social_tag": ["A shield in front of everything your", "AI agent opens, installs and runs."],
    },
    "ko": {
        "hero_alt": "personal-anti-hack: AI 에이전트가 여는 모든 문 앞의 방어막",
        "tagline": [[("AI 에이전트가 여는", "fg")], [("모든 문 앞의 ", "fg"), ("방어막.", "accent")]],
        "tag_size": 34,
        "hero_sub": "레포지토리·스킬·MCP 서버·패키지를 실행 전에 읽고, 검사에 걸리면 설치·설정 명령을 막고, 에이전트 "
                    "설정 변경을 감시합니다. 판정은 코드가, 내 컴퓨터에서 합니다.",
        "one_guard": "하나의 가드로",
        "term_title": "에이전트 세션 · 승인 끔",
        "caption": "실제 실행 기록: Claude Code {cc}, 승인 끔 · bench/live_drill.py",
        "stats": [("악성 테스트 레포지토리", "탐지 (규칙만, 오프라인)"),
                  ("비슷한 정상 레포지토리", "오탐"),
                  ("널리 쓰이는 레포지토리", "차단"),
                  ("실제 에이전트 실행 중", "페이로드가 실행된 횟수")],
        "pipe_title": "작동 방식",
        "pipe_sub": "에이전트가 실행하는 모든 명령은 먼저 가드를 거칩니다. 설치·설정 명령이면 프로젝트 전체를 검사한 뒤에만 "
                    "실행됩니다.",
        "touch_h": "에이전트가 다루는 것",
        "touch": ["Git 레포지토리", "패키지: npm, PyPI …", "에이전트 스킬", "MCP 서버", "압축 파일·다운로드",
                  "AGENTS.md·CLAUDE.md"],
        "agent_h": "내 AI 에이전트",
        "guard_h": "가드",
        "guard_sub": "도구 실행 전 훅",
        "guard_body": "명령마다 확인합니다: 내려받아 실행, 디코딩해 실행, 자격 증명 읽기, 지속성, 승인 끄기, 비슷한 이름의 "
                      "패키지, 레지스트리 변경.",
        "guard_setup": "설치·설정 명령(npm install, pip install -e ., make, pytest)은 프로젝트를 먼저 검사합니다.",
        "out_h": "결과",
        "outcomes": [("BLOCK", "bad", "거부. 아무것도 실행되지 않습니다."), ("WARN", "warn", "나에게 묻습니다."),
                     ("PASS", "good", "에이전트 자체 규칙대로.")],
        "out_note": "가드는 \u2018허용\u2019이라고 답하지 않습니다.",
        "a_ab": ["클론,", "읽기"],
        "a_bc": ["모든", "도구 호출"],
        "a_cd": ["명령", "검사"],
        "a_scan": "설치·설정: 프로젝트 검사",
        "a_verdict": "판정",
        "scan_h": "검사 안에서 일어나는 일",
        "stages": [(["스스로 실행되는 것", "찾기"],
                    "에이전트 훅, npm·pip 라이프사이클 스크립트, IDE 작업, 개발 컨테이너, 빌드 스크립트, git 훅, "
                    "지시 파일과 그것들이 실행하는 파일."),
                   (["전부 읽기"],
                    "파일을 자르지 않고 끝까지. Base64·hex·이스케이프를 풀고, 숨은 유니코드, 패딩, 압축 파일, 이름을 속인 "
                    "바이너리를 찾습니다."),
                   (["맥락으로 판단"],
                    "같은 줄도 훅에서는 critical, 코드에서는 high, 문서에서는 조용히. 다운로드는 호스트로 판단하고, 조합은 "
                    "심각도를 올립니다."),
                   (["판정"], "high·critical은 차단, medium은 경고. 끝까지 읽지 못한 것은 깨끗하다고 하지 않습니다.")],
        "addons": ["+ 로컬 백신: Microsoft Defender, ClamAV", "+ 알려진 취약점: OSV (--online)",
                   "+ 설정 감시: pah watch"],
        "res_title": "악성 레포지토리 {n}개 중 탐지 수",
        "res_sub1": "TrapRepo: 2025–26년 실제 기법으로 만든 악성 {n}개와 정상 {b}개, 페이로드는 무해합니다.",
        "res_sub2": "모델은 레포지토리를 읽고(최대 10만 자) \u2018안전\u2019 또는 \u2018위험\u2019으로 답했고, 사례마다 {k}번 "
                    "실행했습니다.",
        "legend": ["매 실행 탐지", "일부 실행만 탐지", "매번 놓침", "매번 거절 (답 없음)"],
        "res_rules": "규칙만, 오프라인",
        "res_model": "모델 단독",
        "res_benign": "정상 레포 오탐",
        "res_every": "매 실행",
        "res_any": "한 번이라도",
        "res_of": "{b}개 중 {a}",
        "res_foot": "거절은 깨끗하다는 뜻이 아닙니다: personal-anti-hack은 \u2018검토 안 됨\u2019으로 보고합니다. "
                    "모든 사례·실행·답변은 bench/results/에 있습니다.",
        "repo_title": "널리 쓰이는 레포지토리 {n}개, 통째로 검사",
        "repo_big": "차단 0",
        "repo_sub": "파일 {f}개, 통과 {p} · 경고 {w}. 경고는 모두 에이전트에게 설치를 맡기기 전에 알아 둘 만한 것입니다.",
        "groups": ["JavaScript", "Python", "Rust", "AI 에이전트·MCP", "셸·설치 스크립트", "Go·Java·컨테이너"],
        "repo_notes": ["ruff와 MCP 서버 모음은 Claude Code SessionStart 훅을 넣어 두었습니다.",
                       "gemini-cli의 스킬 하나는 제3자 설치 스크립트를 sh로 바로 실행시킵니다."],
        "repo_legend": ["통과", "경고", "차단"],
        "scan_cmd": "pah scan ./acme-utils --lang ko",
        "scan_title": "터미널",
        "scan_note": "일부 생략: high·critical 항목은 위험한 이유와 조치도 함께 출력합니다.",
        "social_tag": ["AI 에이전트가 여는", "모든 문 앞의 방어막."],
    },
}

# ---------------------------------------------------------------------------------------------------------------------
# Text measurement. SVG text is drawn by the viewer's fonts, so layout uses Helvetica's metrics (as wide as or wider
# than the system fonts in the stack) and leaves slack.

_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
       [278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556,
        278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334,
        260, 334, 584]
_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
        [333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556,
         333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389,
         280, 389, 584]
_OTHER = {"·": 278, "—": 1000, "–": 556, "…": 1000, "→": 1000, "↓": 600, "\u2018": 222, "\u2019": 222,
          "\u201c": 333, "\u201d": 333, "✕": 800, "●": 600, "›": 333, "×": 584}


def _wide(ch: str) -> bool:
    o = ord(ch)
    return 0x1100 <= o <= 0x11FF or 0x3000 <= o <= 0x9FFF or 0xAC00 <= o <= 0xD7A3 or 0xFF00 <= o <= 0xFFEF


def tw(s: str, size: float, weight: int = 400, mono: bool = False) -> float:
    """Approximate rendered width in px."""
    if mono:
        return sum(1.0 if _wide(c) else 0.61 for c in s) * size
    k = min(1.0, max(0.0, (weight - 400) / 300))
    total = 0.0
    for c in s:
        o = ord(c)
        if _wide(c):
            total += 950 + 30 * k
        elif 32 <= o <= 126:
            total += _REG[o - 32] + (_BOLD[o - 32] - _REG[o - 32]) * k
        else:
            total += _OTHER.get(c, 600)
    return total / 1000 * size * 1.04


def wrap(s: str, size: float, width: float, weight: int = 400, mono: bool = False) -> list[str]:
    lines: list[str] = []
    cur = ""
    for word in s.split(" "):
        trial = f"{cur} {word}" if cur else word
        if cur and tw(trial, size, weight, mono) > width:
            lines.append(cur)
            cur = word
        else:
            cur = trial
    if cur:
        lines.append(cur)
    return lines


# ---------------------------------------------------------------------------------------------------------------------
# SVG pieces

def f(v: float) -> str:
    return f"{v:.1f}".rstrip("0").rstrip(".")


def svg_open(w: int, h: int, title: str, desc: str) -> list[str]:
    return [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" '
            f'aria-labelledby="title desc" font-family={quoteattr(SANS)}>',
            f'<title id="title">{escape(title)}</title><desc id="desc">{escape(desc)}</desc>']


def text(x: float, y: float, s: str, size: float, fill: str, weight: int = 400, anchor: str = "start",
         mono: bool = False, extra: str = "") -> str:
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    w = f' font-weight="{weight}"' if weight != 400 else ""
    fam = f" font-family={quoteattr(MONO)}" if mono else ""
    return f'<text x="{f(x)}" y="{f(y)}" font-size="{f(size)}"{w} fill="{fill}"{a}{fam}{extra}>{escape(s)}</text>'


def runs(x: float, y: float, parts: list[tuple[str, str, int]], size: float, mono: bool = False,
         anchor: str = "start") -> str:
    """One line of text in several colors: parts are (text, color, weight)."""
    fam = f" font-family={quoteattr(MONO)}" if mono else ""
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    spans = "".join(f'<tspan fill="{c}"' + (f' font-weight="{wt}"' if wt != 400 else "") + f">{escape(s)}</tspan>"
                    for s, c, wt in parts if s)
    return f'<text x="{f(x)}" y="{f(y)}" font-size="{f(size)}"{fam}{a} xml:space="preserve">{spans}</text>'


def rect(x: float, y: float, w: float, h: float, rx: float, fill: str, stroke: str | None = None,
         extra: str = "") -> str:
    s = f' stroke="{stroke}"' if stroke else ""
    return f'<rect x="{f(x)}" y="{f(y)}" width="{f(w)}" height="{f(h)}" rx="{f(rx)}" fill="{fill}"{s}{extra}/>'


def pill(x: float, y: float, label: str, size: float, fg: str, bg: str, stroke: str | None = None, weight: int = 600,
         pad: float = 9, h: float | None = None, mono: bool = False) -> tuple[str, float]:
    h = h or size + 11
    w = tw(label, size, weight, mono) + 2 * pad
    return (rect(x, y, w, h, h / 2, bg, stroke) +
            text(x + w / 2, y + h / 2 + size * 0.36, label, size, fg, weight, "middle", mono)), w


def logo(x: float, y: float, size: float, color: str) -> str:
    """The shield from the plugin icon (scripts/make_icon.py), as vectors."""
    k = size / 100
    return (f'<g transform="translate({f(x)} {f(y)}) scale({k:.4f})">'
            f'<rect width="100" height="100" rx="18" fill="{color}"/>'
            '<path d="M50 17 L76 26 L76 50 Q74 72 50 84 Q26 72 24 50 L24 26 Z" fill="#ffffff"/>'
            f'<path d="M36 50 L43 43 L48 49 L60 35 L67 42 L48 62 Z" fill="{color}"/></g>')


def arrow(x1: float, y1: float, x2: float, y2: float, color: str, label: str | list[str] = "", lsize: float = 12,
          lcolor: str = "") -> str:
    """A straight arrow; a horizontal one carries its label (one or more short lines) above the shaft."""
    out = [f'<line x1="{f(x1)}" y1="{f(y1)}" x2="{f(x2)}" y2="{f(y2)}" stroke="{color}" stroke-width="1.6"/>']
    head = f'fill="none" stroke="{color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"'
    if x1 == x2:  # vertical: label to the right
        s = 1 if y2 > y1 else -1
        out.append(f'<path d="M{f(x2 - 5)} {f(y2 - 7 * s)} L{f(x2)} {f(y2)} L{f(x2 + 5)} {f(y2 - 7 * s)}" {head}/>')
        if label:
            out.append(text(x1 + 9, (y1 + y2) / 2 + 4, str(label), lsize, lcolor or color, 500))
    else:
        s = 1 if x2 > x1 else -1
        out.append(f'<path d="M{f(x2 - 7 * s)} {f(y2 - 5)} L{f(x2)} {f(y2)} L{f(x2 - 7 * s)} {f(y2 + 5)}" {head}/>')
        lines = [label] if isinstance(label, str) else label
        for i, line in enumerate(lines):
            if line:
                ly = y1 - 9 - (len(lines) - 1 - i) * (lsize + 2)
                out.append(text((x1 + x2) / 2, ly, line, lsize, lcolor or color, 500, "middle"))
    return "".join(out)


def flow(items: list[str], x0: float, y0: float, width: float, size: float, gap: float, row_h: float,
         pad: float = 9, weight: int = 500) -> list[tuple[str, float, float, float]]:
    """Lay chips out left to right, wrapping at width: returns (label, x, y, w)."""
    placed = []
    x, y = x0, y0
    for label in items:
        w = tw(label, size, weight) + 2 * pad
        if x > x0 and x + w > x0 + width:
            x, y = x0, y + row_h
        placed.append((label, x, y, w))
        x += w + gap
    return placed


# ---------------------------------------------------------------------------------------------------------------------
# Data

def load(name: str) -> dict:
    return json.loads((RESULTS / f"{DATE}-{name}.json").read_text(encoding="utf-8"))


def headline() -> dict:
    rules = load("rules")["rows"]
    mal = [r for r in rules if r["kind"] == "malicious"]
    ben = [r for r in rules if r["kind"] == "benign"]
    repos = load("real-repos")["repos"]
    live = [r for name in ("live-drill", "live-drill-nested", "live-drill-pretool") for r in load(name)["runs"]]
    return {
        "caught": sum(r["pah"] in ("block", "warn") for r in mal), "malicious": len(mal),
        "flagged": sum(r["pah"] in ("block", "warn") for r in ben), "benign": len(ben),
        "repos": len(repos), "repos_blocked": sum(r["verdict"] == "block" for r in repos),
        "live": len(live), "live_ran": sum(bool(r.get("payload_ran")) for r in live),
    }


def recorded_run() -> dict:
    """The hero's terminal: the first trap run of the pre-command-hook live drill, as recorded."""
    data = load("live-drill-pretool")
    run = next(r for r in data["runs"] if r["kind"] == "malicious" and r["blocked"])
    blocked = run["blocked"][0]
    tool, _, command = blocked["action"].partition(": ")
    reason = blocked["reason"].split(" and blocked running its setup: ", 1)[-1]
    reason = reason.split(". Show the user", 1)[0]
    findings = []
    for part in reason.split("; "):
        m = re.match(r"(CRITICAL|HIGH|MEDIUM|LOW) (.+)", part.strip())
        if not m:
            continue
        title, _, detail = m.group(2).partition(": ")
        host = re.search(r"\(to [^)]+\)", detail)
        findings.append((m.group(1), title, host.group(0) if host else detail))
    sentences = re.split(r"(?<=\.) ", run["final"].strip().split("\n")[0])
    prompt = re.split(r"(?<=\.) ", data["prompt"])
    return {"cc": data["claude_code"].rsplit("@", 1)[-1], "prompt": " ".join(prompt[:1]) + " " +
            prompt[1].split(" (")[0] + " \u2026", "tool": tool, "command": command, "findings": findings,
            "reply": " ".join(sentences[:2])}


# ---------------------------------------------------------------------------------------------------------------------
# Figures

def hero(lang: str, theme: str) -> str:
    t, s, h, rec = THEMES[theme], STR[lang], headline(), recorded_run()
    W, H = 960, 520
    out = svg_open(W, H, s["hero_alt"], s["hero_sub"])
    out.append(
        '<defs>'
        f'<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{t["hero_a"]}"/>'
        f'<stop offset="0.65" stop-color="{t["hero_b"]}"/></linearGradient>'
        f'<pattern id="dots" width="18" height="18" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1.1" '
        f'fill="{t["dots"]}" fill-opacity="{t["dots_op"]}"/></pattern>'
        f'<radialGradient id="glow" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="{t["accent"]}" '
        f'stop-opacity="{t["glow_op"]}"/><stop offset="1" stop-color="{t["accent"]}" stop-opacity="0"/></radialGradient>'
        f'<clipPath id="card"><rect x="0" y="0" width="{W}" height="{H}" rx="16"/></clipPath>'
        '</defs>')
    out.append('<g clip-path="url(#card)">')
    out.append(rect(0, 0, W, H, 0, "url(#bg)"))
    out.append(f'<rect x="440" y="0" width="{W - 440}" height="{H - 96}" fill="url(#dots)"/>')
    out.append('<ellipse cx="700" cy="215" rx="330" ry="210" fill="url(#glow)"/>')
    band_y = H - 96
    out.append(rect(0, band_y, W, 96, 0, t["band"]))
    out.append(f'<line x1="0" y1="{band_y}" x2="{W}" y2="{band_y}" stroke="{t["border"]}"/>')
    out.append('</g>')
    out.append(rect(0.5, 0.5, W - 1, H - 1, 15.5, "none", t["border"]))

    # left column
    x = 44
    out.append(logo(x, 38, 38, t["accent"]))
    out.append(text(x + 50, 64, "personal-anti-hack", 21, t["fg"], 700))
    size = s["tag_size"]
    y = 128 if len(s["tagline"]) == 3 else 150
    for line in s["tagline"]:
        spans = "".join(f'<tspan fill="{t[key]}">{escape(part)}</tspan>' for part, key in line)
        out.append(f'<text x="{x}" y="{f(y)}" font-size="{size}" font-weight="700" letter-spacing="-0.4" '
                   f'xml:space="preserve">{spans}</text>')
        y += size * 1.27
    y += 6
    for line in wrap(s["hero_sub"], 14.5, 384):
        out.append(text(x, y, line, 14.5, t["muted"]))
        y += 21.5
    y += 14
    out.append(text(x, y, s["one_guard"], 10.5, t["subtle"], 700, extra=' letter-spacing="1.2"'))
    for label, cx, cy, cw in flow(AGENTS, x, y + 10, 384, 12, 6, 30):
        out.append(rect(cx, cy, cw, 24, 12, t["card"], t["border"]))
        out.append(text(cx + cw / 2, cy + 16.2, label, 12, t["fg"], 500, "middle"))

    # the recorded run
    T = HERO_TERM
    tx, ty, tw_, th = 458, 36, 466, 352
    out.append(f'<rect x="{tx + 4}" y="{ty + 10}" width="{tw_}" height="{th}" rx="14" fill="#000" fill-opacity="'
               f'{"0.16" if theme == "light" else "0.45"}"/>')
    out.append(rect(tx, ty, tw_, th, 12, T["bg"], T["border"]))
    out.append(f'<path d="M{tx + 12} {ty + 0.5} H{tx + tw_ - 12} A11.5 11.5 0 0 1 {tx + tw_ - 0.5} {ty + 12} V{ty + 34} '
               f'H{tx + 0.5} V{ty + 12} A11.5 11.5 0 0 1 {tx + 12} {ty + 0.5} Z" fill="{T["bar"]}"/>')
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(f'<circle cx="{tx + 18 + i * 16}" cy="{ty + 17}" r="5" fill="{c}"/>')
    out.append(text(tx + tw_ / 2, ty + 21.5, s["term_title"], 11.5, T["muted"], 500, "middle"))
    out.append(f'<line x1="{tx}" y1="{ty + 34.5}" x2="{tx + tw_}" y2="{ty + 34.5}" stroke="{T["border"]}"/>')
    ms, lh = 11.8, 19.6
    cols = int((tw_ - 32) / (ms * 0.61))
    lx, ly = tx + 16, ty + 60

    def fit(s: str, n: int) -> list[str]:
        return wrap(s, ms, n * ms * 0.61, mono=True)

    lines: list[list[tuple[str, str, int]]] = []
    for i, part in enumerate(fit(rec["prompt"], cols - 2)):
        lines.append([("› " if i == 0 else "  ", T["prompt"], 700), (part, T["fg"], 400)])
    lines.append([])
    lines.append([("● ", T["tool"], 400), (rec["tool"], T["fg"], 700), (f"({rec['command']})", T["dim"], 400)])
    lines.append([("  ✕ ", T["red"], 700), ("Blocked by personal-anti-hack before it ran:", T["red"], 400)])
    for sev, title, detail in rec["findings"]:
        color = T["high"] if sev in ("HIGH", "CRITICAL") else T["low"]
        tag = "    " + sev.ljust(4) + " "
        one = f"{title} {detail}" if detail.startswith("(") else f"{title}: {detail}"
        body = [one] if len(tag) + len(one) <= cols else fit(title, cols - len(tag)) + fit(detail, cols - len(tag))
        for i, part in enumerate(body):
            lines.append([(tag if i == 0 else " " * len(tag), color, 700), (part, T["dim"], 400)])
    lines.append([])
    for i, part in enumerate(fit(rec["reply"], cols - 2)):
        lines.append([("● " if i == 0 else "  ", T["reply"], 400), (part, T["reply"], 400)])
    for parts in lines:
        if parts:
            out.append(runs(lx, ly, parts, ms, mono=True))
        ly += lh
    out.append(text(tx + 16, ty + th - 14, s["caption"].format(cc=rec["cc"]), 11, T["muted"]))

    # headline numbers
    cells = [(h["caught"], h["malicious"]), (h["flagged"], h["benign"]), (h["repos_blocked"], h["repos"]),
             (h["live_ran"], h["live"])]
    cw = W / 4
    for i, ((a, b), (l1, l2)) in enumerate(zip(cells, s["stats"], strict=True)):
        cx = i * cw + 44 if i == 0 else i * cw + 30
        if i:
            out.append(f'<line x1="{f(i * cw)}" y1="{band_y + 20}" x2="{f(i * cw)}" y2="{H - 20}" stroke="{t["border"]}"/>')
        out.append(runs(cx, band_y + 41, [(str(a), t["accent"] if i == 0 else t["fg"], 700),
                                          (f" / {b}", t["subtle"], 600)], 26))
        out.append(text(cx, band_y + 62, l1, 12.5, t["muted"]))
        out.append(text(cx, band_y + 79, l2, 12.5, t["muted"]))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def pipeline(lang: str, theme: str) -> str:
    t, s = THEMES[theme], STR[lang]
    top = 104
    A, B, C, D = (28, 184), (268, 188), (512, 208), (776, 156)
    # the outcome column sets the height of the top row
    oy, outcome_rows = top + 44, []
    for label, kind, desc in s["outcomes"]:
        lines = wrap(desc, 12, D[1] - 28)
        outcome_rows.append((oy, label, kind, lines))
        oy += 20 + 14 + len(lines) * 16 + 8
    note = wrap(s["out_note"], 11.5, D[1] - 28)
    bh = max(236, oy - top + len(note) * 15 + 8)
    # the scan stages set the height of the bottom panel
    W, n = 960, len(s["stages"])
    sw = (W - 56 - 32 - (n - 1) * 26) / n
    title_lines = max(len(title) for title, _ in s["stages"])
    bodies = [wrap(body, 12.4, sw - 28) for _, body in s["stages"]]
    body_top = 50 + (title_lines - 1) * 16
    sh = max(body_top + (18 if i == n - 1 else 0) + (len(b) - 1) * 17 + 16 for i, b in enumerate(bodies))
    ph = 44 + sh + 16 + 24 + 16
    H = int(top + bh + 52 + ph + 26)
    out = svg_open(W, H, s["pipe_title"], s["pipe_sub"])
    out.append(rect(0.5, 0.5, W - 1, H - 1, 15.5, t["card"], t["border"]))
    out.append(text(28, 42, s["pipe_title"], 20, t["fg"], 700))
    y = 66
    for line in wrap(s["pipe_sub"], 13.5, 900):
        out.append(text(28, y, line, 13.5, t["muted"]))
        y += 20

    def box(col, title, sub=""):
        x, w = col
        parts = [rect(x, top, w, bh, 12, t["card2"], t["border"]), text(x + 14, top + 26, title, 13.5, t["fg"], 700)]
        if sub:
            parts.append(text(x + 14, top + 44, sub, 11.5, t["muted"]))
        return "".join(parts)

    # A: inputs
    out.append(box(A, s["touch_h"]))
    for i, item in enumerate(s["touch"]):
        iy = top + 52 + i * 29
        out.append(rect(A[0] + 14, iy, A[1] - 28, 23, 6, t["card"], t["border"]))
        out.append(rect(A[0] + 22, iy + 8, 7, 7, 2, t["subtle"]))
        out.append(text(A[0] + 36, iy + 15.8, item, 12, t["fg"]))
    # B: agents
    out.append(box(B, s["agent_h"]))
    cw2 = (B[1] - 28 - 8) / 2
    for i, name in enumerate(AGENTS):
        cx = B[0] + 14 + (i % 2) * (cw2 + 8)
        cy = top + 52 + (i // 2) * 30
        if i == len(AGENTS) - 1 and i % 2 == 0:
            cx = B[0] + 14 + (cw2 + 8) / 2
        out.append(rect(cx, cy, cw2, 23, 11.5, t["card"], t["border"]))
        out.append(text(cx + cw2 / 2, cy + 15.8, name, 11.5, t["fg"], 500, "middle"))
    # C: the guard
    x, w = C
    out.append(rect(x, top, w, bh, 12, t["accent_bg"], t["accent"]))
    out.append(logo(x + 14, top + 13, 22, t["accent"]))
    out.append(text(x + 44, top + 29, s["guard_h"], 14, t["fg"], 700))
    out.append(text(x + 44 + tw(s["guard_h"], 14, 700) + 8, top + 29, s["guard_sub"], 11.5, t["accent_fg"], 500))
    yy = top + 56
    for line in wrap(s["guard_body"], 12.2, w - 28):
        out.append(text(x + 14, yy, line, 12.2, t["fg"]))
        yy += 17.5
    yy += 8
    out.append(f'<line x1="{x + 14}" y1="{yy - 9}" x2="{x + w - 14}" y2="{yy - 9}" stroke="{t["accent"]}" '
               f'stroke-opacity="0.35"/>')
    yy += 6
    for line in wrap(s["guard_setup"], 12.2, w - 28):
        out.append(text(x + 14, yy, line, 12.2, t["accent_fg"], 600))
        yy += 17.5
    # D: outcome
    out.append(box(D, s["out_h"]))
    for oy, label, kind, lines in outcome_rows:
        p, pw = pill(D[0] + 14, oy, label, 11, t["card"] if theme == "dark" else "#ffffff", t[kind], pad=8, h=20)
        out.append(p)
        for j, line in enumerate(lines):
            out.append(text(D[0] + 14, oy + 36 + j * 16, line, 12, t["fg"]))
    for j, line in enumerate(note):
        out.append(text(D[0] + 14, top + bh - 14 - (len(note) - 1 - j) * 15, line, 11.5, t["muted"]))
    # arrows between the boxes
    ay = top + 118
    out.append(arrow(A[0] + A[1] + 6, ay, B[0] - 6, ay, t["subtle"], s["a_ab"], lcolor=t["muted"]))
    out.append(arrow(B[0] + B[1] + 6, ay, C[0] - 6, ay, t["accent"], s["a_bc"], lcolor=t["accent_fg"]))
    out.append(arrow(C[0] + C[1] + 6, ay, D[0] - 6, ay, t["accent"], s["a_cd"], lcolor=t["accent_fg"]))

    # the scan
    py = top + bh + 52
    out.append(rect(28, py, W - 56, ph, 12, t["card2"], t["border"]))
    out.append(arrow(C[0] + C[1] / 2, top + bh + 2, C[0] + C[1] / 2, py - 3, t["accent"], s["a_scan"],
                     lcolor=t["accent_fg"]))
    out.append(text(44, py + 28, s["scan_h"], 13.5, t["fg"], 700))
    sy = py + 44
    for i, (title, body_lines) in enumerate(zip((st[0] for st in s["stages"]), bodies, strict=True)):
        sx = 44 + i * (sw + 26)
        last = i == n - 1
        out.append(rect(sx, sy, sw, sh, 10, t["card"], t["accent"] if last else t["border"]))
        out.append(f'<circle cx="{f(sx + 22)}" cy="{f(sy + 22)}" r="11" fill="{t["accent"]}"/>')
        out.append(text(sx + 22, sy + 26.2, str(i + 1), 12, "#ffffff", 700, "middle"))
        for j, line in enumerate(title):
            out.append(text(sx + 40, sy + 26.5 + j * 16, line, 13, t["fg"], 700))
        by = sy + body_top
        if last:
            bx = sx + 14
            for label, kind in (("BLOCK", "bad"), ("WARN", "warn"), ("PASS", "good")):
                p, pw = pill(bx, by - 13, label, 10.5, "#ffffff" if theme == "light" else t["card"], t[kind], pad=7,
                             h=19)
                out.append(p)
                bx += pw + 5
            by += 18
        for line in body_lines:
            out.append(text(sx + 14, by, line, 12.4, t["muted"]))
            by += 17
        if not last:
            out.append(arrow(sx + sw + 4, sy + sh / 2, sx + sw + 22, sy + sh / 2, t["subtle"]))
    # the verdict feeds the outcome
    vx = 44 + (n - 1) * (sw + 26) + sw / 2
    vx = min(max(vx, D[0] + 30), D[0] + D[1] - 30)
    out.append(arrow(vx, sy - 2, vx, top + bh + 3, t["accent"], s["a_verdict"], lcolor=t["accent_fg"]))
    ax = 44
    for label in s["addons"]:
        p, pw = pill(ax, py + ph - 38, label, 11.5, t["fg"], t["card"], t["border"], weight=500, pad=11, h=24)
        out.append(p)
        ax += pw + 10
    out.append("</svg>")
    return "\n".join(out) + "\n"


def results_rows(lang: str) -> tuple[list[dict], int]:
    s = STR[lang]
    models = load("models")
    rules = load("rules")
    mal = [r for r in rules["rows"] if r["kind"] == "malicious"]
    ben = [r for r in rules["rows"] if r["kind"] == "benign"]
    rows = [{"name": "personal-anti-hack", "note": s["res_rules"], "all": sum(r["pah"] in ("block", "warn") for r in mal),
             "some": 0, "missed": sum(r["pah"] not in ("block", "warn") for r in mal), "refused": 0,
             "false": sum(r["pah"] in ("block", "warn") for r in ben), "benign": len(ben), "total": len(mal)}]
    mal = [r for r in models["rows"] if r["kind"] == "malicious"]
    ben = [r for r in models["rows"] if r["kind"] == "benign"]
    names = {"openai:gpt-6-astra": "GPT-6 Astra", "meta:muse-spark-1.3": "Muse Spark 1.3",
             "anthropic:claude-opus-5-5": "Claude Opus 5.5"}
    for spec, name in names.items():
        row = {"name": name, "note": s["res_model"], "all": 0, "some": 0, "missed": 0, "refused": 0,
               "total": len(mal), "benign": len(ben)}
        for r in mal:
            ts = r["models"][spec]
            k = sum(x["verdict"] == "unsafe" for x in ts)
            key = "all" if k == len(ts) else "some" if k else ("missed" if any(x["verdict"] == "safe" for x in ts)
                                                               else "refused")
            row[key] += 1
        row["false"] = sum(any(x["verdict"] == "unsafe" for x in r["models"][spec]) for r in ben)
        rows.append(row)
    return rows, models.get("trials", 3)


def results(lang: str, theme: str) -> str:
    t, s = THEMES[theme], STR[lang]
    rows, trials = results_rows(lang)
    total, benign = rows[0]["total"], rows[0]["benign"]
    W = 960
    left, bar_w = 228, 486
    top, row_h, bar_h = 168, 60, 30
    H = top + row_h * len(rows) + 58
    summary = "; ".join(f"{r['name']}: {r['all']} of {total} caught in every run, {r['some']} in some runs, "
                        f"{r['missed']} missed, {r['refused']} refused; {r['false']} of {r['benign']} benign flagged"
                        for r in rows)
    out = svg_open(W, H, s["res_title"].format(n=total), summary)
    out.append(rect(0.5, 0.5, W - 1, H - 1, 15.5, t["card"], t["border"]))
    out.append(text(28, 42, s["res_title"].format(n=total), 20, t["fg"], 700))
    out.append(text(28, 66, s["res_sub1"].format(n=total, b=benign), 13.5, t["muted"]))
    out.append(text(28, 86, s["res_sub2"].format(k=trials), 13.5, t["muted"]))
    keys = [("all", "bar_all"), ("some", "bar_some"), ("missed", "bar_missed"), ("refused", "bar_refused")]
    x = 28
    for (_key, color), label in zip(keys, s["legend"], strict=True):
        out.append(rect(x, 110, 12, 12, 3, t[color]))
        out.append(text(x + 18, 120.5, label, 13, t["muted"]))
        x += 18 + tw(label, 13) + 24
    rx = left + bar_w + 30
    out.append(text(rx, top - 14, s["res_benign"], 12.5, t["muted"], 600))
    unit = bar_w / total
    for i, row in enumerate(rows):
        y = top + i * row_h
        if i == 0:
            out.append(rect(16, y - 13, W - 32, row_h - 4, 10, t["accent_bg"]))
        out.append(text(28, y + 13, row["name"], 14.5, t["fg"], 700 if i == 0 else 600))
        out.append(text(28, y + 32, row["note"], 12.5, t["muted"]))
        out.append(rect(left, y, bar_w, bar_h, 5, t["line"]))
        bx = left
        for key, color in keys:
            n = row[key]
            if not n:
                continue
            w = n * unit
            gap = 2 if bx + w < left + bar_w - 0.5 else 0
            out.append(f'<rect x="{f(bx)}" y="{y}" width="{f(max(w - gap, 1.5))}" height="{bar_h}" rx="5" '
                       f'fill="{t[color]}"><title>{escape(row["name"])}: {n} of {total}</title></rect>')
            if w >= 26:
                out.append(text(bx + 9, y + 19.5, str(n), 13, t[f"ink_{key}"], 700))
            bx += w
        frac = row["false"] / row["benign"]
        out.append(runs(rx, y + 20, [(s["res_of"].format(a=row["false"], b=row["benign"]), t["fg"], 700)], 14.5))
        out.append(text(rx, y + 38, s["res_every"] if i == 0 else s["res_any"], 12, t["muted"]))
        mx = rx + 92
        out.append(rect(mx, y + 9, 96, 8, 4, t["line"]))
        if frac:
            out.append(rect(mx, y + 9, max(96 * frac, 4), 8, 4, t["bar_missed"]))
    foot = top + row_h * len(rows) + 4
    out.append(f'<line x1="28" y1="{foot}" x2="{W - 28}" y2="{foot}" stroke="{t["line"]}"/>')
    out.append(text(28, foot + 28, s["res_foot"], 12.5, t["muted"]))
    out.append("</svg>")
    return "\n".join(out) + "\n"


# The scan figure is made by running the scanner on a TrapRepo case and keeping its own colors.
ANSI = re.compile(r"\033\[([\d;]*)m")


def _scan_text(lang: str) -> str:
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "bench"))
    import materialize  # bench/materialize.py
    from pah import report
    from pah.scan import scan

    case = json.loads((ROOT / "bench" / "fixtures" / "traprepo" / "claude-settings-sessionstart-hook.json")
                      .read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        target = materialize.materialize(case, Path(tmp) / "acme-utils")
        rep = scan(target)
        rep.target = "./acme-utils"
        rep.stats["seconds"] = round(rep.stats.get("seconds", 0), 1)  # as measured, rounded so the figure is stable
        return report.text(rep, lang=lang, color=True)


def _segments(line: str, pal: dict) -> list[tuple[str, str, int, str | None]]:
    """Split one ANSI-colored line into (text, color, weight, background)."""
    out, pos = [], 0
    color, weight, bg = pal["fg"], 400, None
    codes = {"31": pal["red"], "33": pal["yellow"], "36": pal["cyan"], "97": pal["badge_fg"], "30": pal["warn_badge_fg"]}
    backs = {"41": pal["badge_red"], "43": pal["badge_yellow"], "42": pal["badge_green"], "47": pal["badge_gray"]}
    for m in ANSI.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], color, weight, bg))
        for code in (m.group(1) or "0").split(";"):
            if code in ("0", ""):
                color, weight, bg = pal["fg"], 400, None
            elif code == "1":
                weight = 700
            elif code == "2":
                color = pal["muted"]
            elif code in codes:
                color = codes[code]
            elif code in backs:
                bg = backs[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], color, weight, bg))
    return out


def scan_figure(lang: str, theme: str, raw: str) -> str:
    t, s = THEMES[theme], STR[lang]
    pal = t["term"]
    cols, ms, lh = 112, 12.4, 19.5
    lines: list[str] = []
    for line in raw.split("\n"):
        plain = ANSI.sub("", line)
        if re.match(r"\s+(Why|Fix|이유|조치): ", plain):
            continue
        lines.append(line)
    # wrap long plain lines (no color codes inside the wrapped ones) with a hanging indent
    wrapped: list[str] = []
    for line in lines:
        plain = ANSI.sub("", line)
        if len(plain) <= cols or ANSI.search(line):
            wrapped.append(line)
            continue
        indent = len(plain) - len(plain.lstrip(" "))
        hang = indent + (2 if plain.lstrip().startswith(("•", ">")) else 0)
        width = cols - hang
        first = True
        rest = plain
        while rest:
            if len(rest) <= (cols if first else width):
                wrapped.append(rest if first else " " * hang + rest)
                break
            limit = cols if first else width
            cut = rest.rfind(" ", 0, limit)
            cut = cut if cut > limit // 2 else limit
            wrapped.append(rest[:cut] if first else " " * hang + rest[:cut])
            rest = rest[cut:].lstrip(" ")
            first = False
    W = 960
    head = 46
    H = int(head + 24 + (len(wrapped) + 2) * lh + 40)
    desc = ANSI.sub("", raw)
    out = svg_open(W, H, f"$ {s['scan_cmd']}", desc[:1800])
    out.append(rect(0.5, 0.5, W - 1, H - 1, 12, pal["bg"], pal["border"]))
    out.append(f'<path d="M12 0.5 H{W - 12} A11.5 11.5 0 0 1 {W - 0.5} 12 V{head - 10} H0.5 V12 A11.5 11.5 0 0 1 12 0.5 Z" '
               f'fill="{pal["bar"]}"/>')
    out.append(f'<line x1="0" y1="{head - 9.5}" x2="{W}" y2="{head - 9.5}" stroke="{pal["border"]}"/>')
    for i, c in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        out.append(f'<circle cx="{20 + i * 17}" cy="18.5" r="5.5" fill="{c}"/>')
    out.append(text(W / 2, 23, s["scan_title"], 12, pal["muted"], 500, "middle"))
    x0, y = 22, head + 18
    out.append(runs(x0, y, [("$ ", pal["green"], 700), (s["scan_cmd"], pal["fg"], 400)], ms, mono=True))
    y += lh * 1.5
    # Colored pieces are placed on a fixed character grid, so badges line up whatever monospace font draws them.
    cw = ms * 0.6
    for line in wrapped:
        segs = _segments(line, pal)
        col = 0
        for seg, color, wt, bg in segs:
            x = x0 + col * cw
            if bg:
                label = seg.strip()
                out.append(rect(x, y - ms + 0.5, len(seg) * cw, ms + 5.5, 3, bg))
                out.append(runs(x + len(seg) * cw / 2, y, [(label, color, wt)], ms, mono=True, anchor="middle"))
            else:
                out.append(runs(x, y, [(seg, color, wt)], ms, mono=True))
            col += len(seg)
        y += lh
    out.append(text(x0, H - 16, s["scan_note"], 11.5, pal["muted"]))
    out.append("</svg>")
    return "\n".join(out) + "\n"


REPO_GROUPS = [
    ["expressjs/express", "sindresorhus/got", "typicode/husky", "lovell/sharp", "nodejs/node-addon-examples",
     "puppeteer/puppeteer", "evanw/esbuild", "prettier/prettier", "vitejs/vite"],
    ["psf/requests", "pallets/flask", "fastapi/fastapi", "pytest-dev/pytest", "python-poetry/poetry", "astral-sh/ruff"],
    ["BurntSushi/ripgrep", "serde-rs/serde", "tokio-rs/tokio"],
    ["anthropics/claude-code", "openai/codex", "google-gemini/gemini-cli", "modelcontextprotocol/servers",
     "anthropics/skills"],
    ["ohmyzsh/ohmyzsh", "nvm-sh/nvm", "Homebrew/install"],
    ["cli/cli", "spring-projects/spring-petclinic", "microsoft/vscode-remote-try-node"],
]
REPO_NAMES = {"modelcontextprotocol/servers": "MCP servers", "anthropics/skills": "Anthropic skills",
              "Homebrew/install": "Homebrew install", "cli/cli": "GitHub CLI"}


def _k(n: int) -> str:
    return f"{n / 1000:.1f}k".replace(".0k", "k") if n >= 1000 else str(n)


def repos_figure(lang: str, theme: str) -> str:
    t, s = THEMES[theme], STR[lang]
    data = {r["repo"]: r for r in load("real-repos")["repos"]}
    listed = [r for g in REPO_GROUPS for r in g]
    missing = sorted(set(data) - set(listed))
    if missing:
        raise SystemExit(f"repos figure: add {missing} to REPO_GROUPS")
    n, files = len(data), sum(r["files"] for r in data.values())
    counts = {v: sum(r["verdict"] == v for r in data.values()) for v in ("pass", "warn", "block")}
    W = 960
    gx, chip_h, gap, row_h = 196, 26, 7, 34
    rows_y = 104
    layout, y = [], rows_y
    for gi, group in enumerate(REPO_GROUPS):
        labels = [REPO_NAMES.get(r, r.split("/", 1)[1]) for r in group]
        items = [f"{lab}  {_k(data[r]['files'])}" for lab, r in zip(labels, group, strict=True)]
        placed = flow(items, gx, y, W - 28 - gx, 12.2, gap, row_h, pad=11, weight=500)
        layout.append((gi, group, labels, placed))
        y = placed[-1][2] + row_h + 8
    H = int(y + 82)
    desc = "; ".join(f"{r}: {data[r]['verdict']} ({data[r]['files']} files)" for r in listed)
    out = svg_open(W, H, s["repo_title"].format(n=n), desc)
    out.append(rect(0.5, 0.5, W - 1, H - 1, 15.5, t["card"], t["border"]))
    out.append(text(28, 42, s["repo_title"].format(n=n), 20, t["fg"], 700))
    big = s["repo_big"]
    p, pw = pill(W - 28 - (tw(big, 15, 700) + 32), 22, big, 15, t["good"], t["good_bg"], t["good_line"], pad=16, h=32)
    out.append(p)
    sub = s["repo_sub"].format(p=counts["pass"], w=counts["warn"], f=f"{files:,}")
    yy = 68
    for line in wrap(sub, 13.5, 760):
        out.append(text(28, yy, line, 13.5, t["muted"]))
        yy += 19
    for gi, group, _labels, placed in layout:
        out.append(text(28, placed[0][2] + 17.8, s["groups"][gi], 13, t["muted"], 600))
        for (item, cx, cy, cw), repo in zip(placed, group, strict=True):
            verdict = data[repo]["verdict"]
            kind = {"pass": "good", "warn": "warn", "block": "bad"}[verdict]
            name, _, size = item.partition("  ")
            out.append(f'<g><title>{escape(repo)}: {verdict}, {data[repo]["files"]} files</title>' +
                       rect(cx, cy, cw, chip_h, 13, t[f"{kind}_bg"], t[f"{kind}_line"]) +
                       runs(cx + 11, cy + 17.3, [(name, t["fg"], 600), ("  " + size, t[kind], 500)], 12.2) + "</g>")
    fy = H - 66
    out.append(f'<line x1="28" y1="{fy}" x2="{W - 28}" y2="{fy}" stroke="{t["line"]}"/>')
    lx = 28
    for label, kind in zip(s["repo_legend"], ("good", "warn", "bad"), strict=True):
        out.append(rect(lx, fy + 18, 12, 12, 6, t[f"{kind}_bg"], t[f"{kind}_line"]))
        out.append(text(lx + 18, fy + 28.5, label, 12.5, t["muted"]))
        lx += 18 + tw(label, 12.5) + 20
    out.append(text(28, fy + 50, "\u26a0 " + "  ".join(s["repo_notes"]), 12.5, t["warn"]))
    out.append(text(W - 28, fy + 28.5, "bench/real_repos.py", 11.5, t["subtle"], 400, "end", mono=True))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def social() -> str:
    t, s, h = THEMES["dark"], STR["en"], headline()
    W, H = 1280, 640
    out = svg_open(W, H, "personal-anti-hack", s["hero_sub"])
    out.append(
        '<defs>'
        '<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#13213d"/>'
        '<stop offset="0.6" stop-color="#0d1117"/></linearGradient>'
        '<pattern id="dots" width="22" height="22" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.4" '
        'fill="#8fb4ff" fill-opacity="0.12"/></pattern>'
        f'<radialGradient id="glow" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="{t["accent"]}" '
        'stop-opacity="0.35"/><stop offset="1" stop-color="#4c8df6" stop-opacity="0"/></radialGradient>'
        '</defs>')
    out.append(rect(0, 0, W, H, 0, "url(#bg)"))
    out.append(rect(0, 0, W, H, 0, "url(#dots)"))
    out.append('<ellipse cx="1080" cy="150" rx="420" ry="300" fill="url(#glow)"/>')
    out.append('<g transform="translate(842 70) scale(4.6)" opacity="0.13" fill="none" stroke="#8fb4ff" '
               'stroke-width="0.9" stroke-linejoin="round"><path d="M50 17 L76 26 L76 50 Q74 72 50 84 Q26 72 24 50 L24 26 Z"/>'
               '<path d="M36 50 L43 43 L48 49 L60 35 L67 42 L48 62 Z"/></g>')
    out.append(logo(96, 92, 96, t["accent"]))
    out.append(text(96, 300, "personal-anti-hack", 76, "#f0f6fc", 800, extra=' letter-spacing="-1.5"'))
    for i, line in enumerate(s["social_tag"]):
        out.append(text(96, 368 + i * 48, line, 38, "#9fb8e6" if i else "#c9d6ee", 500))
    stats = [(f"{h['caught']}/{h['malicious']}", "malicious repos caught"), (f"{h['flagged']}/{h['benign']}",
             "false alarms"), (f"{h['repos_blocked']}/{h['repos']}", "popular repos blocked"), ("9", "agents, one guard")]
    x = 96
    for value, label in stats:
        out.append(text(x, 534, value, 40, "#f0f6fc", 700))
        out.append(text(x, 566, label, 20, "#8b949e"))
        x += max(tw(value, 40, 700), tw(label, 20)) + 64
    out.append("</svg>")
    return "\n".join(out) + "\n"


def browser() -> str | None:
    for c in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "google-chrome", "chromium", "msedge"):
        if Path(c).exists() or shutil.which(c):
            return c
    return None


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    written = []
    for lang in STR:
        raw = _scan_text(lang)
        for theme in THEMES:
            for name, svg in (("hero", hero(lang, theme)), ("pipeline", pipeline(lang, theme)),
                              ("results", results(lang, theme)), ("scan", scan_figure(lang, theme, raw)),
                              ("repos", repos_figure(lang, theme))):
                path = OUT / f"{name}-{lang}-{theme}.svg"
                path.write_text(svg, encoding="utf-8", newline="\n")
                written.append(path)
    social_svg = OUT / "social-preview.svg"
    social_svg.write_text(social(), encoding="utf-8", newline="\n")
    written.append(social_svg)
    if "--png" in argv:
        exe = browser()
        if not exe:
            print("--png needs Chrome or Edge", file=sys.stderr)
            return 1
        with tempfile.TemporaryDirectory() as profile:
            subprocess.run([exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", f"--user-data-dir={profile}",
                            "--force-device-scale-factor=1", "--window-size=1280,640",
                            f"--screenshot={OUT / 'social-preview.png'}", social_svg.resolve().as_uri()],
                           check=True, capture_output=True, timeout=120)
        written.append(OUT / "social-preview.png")
    for p in written:
        print(p.relative_to(ROOT).as_posix())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
