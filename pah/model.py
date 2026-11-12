"""Rules, findings, execution surfaces and reports.

A finding is one piece of evidence tied to a file and line. A surface is something in the target that runs without
being read first (a hook, an install script, a folder-open task). The verdict comes from the findings, by severity,
and a scan that could not read everything never ends as "pass".
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
_RANK = {name: i for i, name in enumerate(SEVERITIES)}

VERDICTS = ("pass", "warn", "block", "incomplete")
EXIT_CODES = {"pass": 0, "warn": 1, "block": 2, "incomplete": 3}


def rank(severity: str) -> int:
    return _RANK[severity]


def bump(severity: str, steps: int = 1) -> str:
    return SEVERITIES[min(len(SEVERITIES) - 1, max(0, _RANK[severity] + steps))]


def worst(severities, default: str = "info") -> str:
    best = default
    for sev in severities:
        if _RANK[sev] > _RANK[best]:
            best = sev
    return best


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    why: str
    fix: str = ""
    attack: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()


RULES: dict[str, Rule] = {}


def rule(id: str, title: str, why: str, fix: str = "", attack=(), owasp=(), refs=()) -> str:
    """Register a rule once, at import time, and return its id."""
    if id in RULES:
        raise ValueError(f"duplicate rule id {id}")
    RULES[id] = Rule(id, title, why, fix, tuple(attack), tuple(owasp), tuple(refs))
    return id


_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clip(text: str, limit: int = 220) -> str:
    """Make an excerpt safe to print: no control characters, invisible characters shown as code points."""
    from .text import reveal  # local import: text imports nothing from here at module load

    text = reveal(text.replace("\r\n", "\n").replace("\r", "\n"))  # Windows line endings are not hidden content
    text = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)
    text = " ".join(text.split()) if "\n" in text else text.strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int = 0
    message: str = ""
    evidence: str = ""
    context: str = ""

    @property
    def meta(self) -> Rule:
        return RULES[self.rule]

    def to_dict(self) -> dict:
        data = asdict(self)
        meta = self.meta
        data.update(title=meta.title, why=meta.why, fix=meta.fix, attack=list(meta.attack), owasp=list(meta.owasp),
                    refs=list(meta.refs))
        return data


@dataclass
class Surface:
    """Something in the target that runs code or changes behavior without being read first."""

    kind: str
    path: str
    trigger: str
    command: str = ""
    line: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)
    surfaces: list[Surface] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    review: dict | None = None

    @property
    def verdict(self) -> str:
        top = worst((f.severity for f in self.findings), default="info")
        if rank(top) >= rank("high"):
            return "block"
        if self.review and self.review.get("raises") == "block":
            return "block"
        if rank(top) >= rank("medium") or (self.review and self.review.get("raises") == "warn"):
            return "warn"
        if self.incomplete:
            return "incomplete"
        return "pass"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-rank(f.severity), f.path, f.line, f.rule))

    def to_dict(self) -> dict:
        from . import __version__

        counts = {sev: 0 for sev in SEVERITIES}
        for f in self.findings:
            counts[f.severity] += 1
        return {
            "tool": "agent-virus-check",
            "version": __version__,
            "target": self.target,
            "verdict": self.verdict,
            "counts": counts,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "surfaces": [s.to_dict() for s in self.surfaces],
            "incomplete": self.incomplete,
            "stats": self.stats,
            "review": self.review,
        }
