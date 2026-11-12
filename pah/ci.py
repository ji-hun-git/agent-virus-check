"""GitHub Actions output for a scan: workflow annotations, step outputs and a job summary.

Annotations put high and critical findings (errors) and medium ones (warnings) on the lines they are about, in the
pull request's diff. GitHub shows at most ten of each kind per step, so the job summary lists everything else.
"""
from __future__ import annotations

import html
import os
from pathlib import Path

from .model import RULES, Report, rank

PER_KIND = 10  # GitHub keeps ten error and ten warning annotations per step
TABLE_ROWS = 60
LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
LABEL = {"block": "BLOCK", "warn": "WARN", "pass": "PASS", "incomplete": "INCOMPLETE"}
MEANING = {
    "block": "Do not open, install or run this with an agent until the findings below are explained",
    "warn": "Review the findings below before you let an agent set this up",
    "pass": "Nothing that runs on its own looks dangerous",
    "incomplete": "Parts could not be read, so this is not a clean result",
}


def _data(text: str) -> str:
    """Escape a workflow-command message."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _prop(text: str) -> str:
    """Escape a workflow-command property (file, title)."""
    return _data(text).replace(":", "%3A").replace(",", "%2C")


def _cell(text: str) -> str:
    """Text for a Markdown table cell: HTML-escaped, pipes and line breaks neutralized."""
    return html.escape(" ".join(str(text).split())).replace("|", "&#124;")


def workspace_prefix(target: str, workspace: str | None = None) -> str | None:
    """Path of the scanned folder relative to the checkout, so findings point at real files in the diff.

    None when the target is not inside the workspace (a git URL, an archive somewhere else).
    """
    try:
        path = Path(target).resolve()
        root = Path(workspace or os.environ.get("GITHUB_WORKSPACE") or os.getcwd()).resolve()
        if not path.exists():
            return None
        folder = path if path.is_dir() else path.parent
        rel = folder.relative_to(root).as_posix()
    except (OSError, ValueError):
        return None
    return "" if rel == "." else rel


def _where(prefix: str | None, path: str) -> str | None:
    if prefix is None or "!/" in path:  # inside an archive: no file in the checkout to point at
        return None
    return f"{prefix}/{path}" if prefix else path


def annotations(report: Report, prefix: str | None) -> list[str]:
    shown = {"error": 0, "warning": 0}
    out = []
    for f in report.sorted_findings():
        level = LEVEL.get(f.severity)
        if not level or shown[level] >= PER_KIND:
            continue
        shown[level] += 1
        props = [f"title={_prop(f'{f.rule} {RULES[f.rule].title} ({f.severity})')}"]
        where = _where(prefix, f.path)
        if where:
            props.insert(0, f"file={_prop(where)}")
            if f.line:
                props.insert(1, f"line={f.line}")
        message = f.message + (f"\n> {f.evidence}" if f.evidence else "") + f"\n{RULES[f.rule].why}"
        out.append(f"::{level} {','.join(props)}::{_data(message)}")
    return out


def summary(report: Report, prefix: str | None) -> str:
    data = report.to_dict()
    counts = ", ".join(f"{n} {sev}" for sev, n in reversed(list(data["counts"].items())) if n) or "no findings"
    stats = report.stats
    lines = [f"### agent-virus-check: {LABEL[report.verdict]}", "",
             f"{MEANING[report.verdict]}.", "",
             f"<code>{_cell(report.target)}</code> · {counts} · {stats.get('files', 0):,} files · "
             f"{stats.get('seconds', 0)}s", ""]
    if report.surfaces:
        lines += [f"**Runs without being read ({len(report.surfaces)})**", "", "| What | Where | Runs when | Command |",
                  "| --- | --- | --- | --- |"]
        for s in report.surfaces[:TABLE_ROWS]:
            where = _where(prefix, s.path) or s.path
            lines.append(f"| {_cell(s.kind)} | <code>{_cell(where)}{':' + str(s.line) if s.line else ''}</code> | "
                         f"{_cell(s.trigger)} | <code>{_cell(s.command)}</code> |")
        lines.append("")
    shown = [f for f in report.sorted_findings() if rank(f.severity) >= rank("medium")]
    quiet = len(report.findings) - len(shown)
    if shown:
        lines += ["**Findings**", "", "| Severity | Rule | Where | What |", "| --- | --- | --- | --- |"]
        for f in shown[:TABLE_ROWS]:
            where = _where(prefix, f.path) or f.path
            what = _cell(f.message) + (f"<br><code>{_cell(f.evidence)}</code>" if f.evidence else "")
            lines.append(f"| {f.severity} | [{f.rule}](https://github.com/ji-hun-git/agent-virus-check/blob/main/docs/"
                         f"rules.md#{f.rule.lower()}) {_cell(RULES[f.rule].title)} | "
                         f"<code>{_cell(where)}{':' + str(f.line) if f.line else ''}</code> | {what} |")
        if len(shown) > TABLE_ROWS:
            lines.append(f"\n… and {len(shown) - TABLE_ROWS} more medium or worse.")
        lines.append("")
    if quiet:
        lines += [f"{quiet} low or informational finding{'s are' if quiet != 1 else ' is'} in the SARIF report "
                  "and in `pah scan --json`.", ""]
    if report.incomplete:
        lines += ["**Not fully scanned**", ""] + [f"- {_cell(x)}" for x in report.incomplete[:20]] + [""]
    return "\n".join(lines) + "\n"


def github(report: Report, env: dict | None = None, prefix: str | None = None) -> None:
    """Print annotations and write the step outputs and the job summary GitHub Actions provides files for."""
    env = os.environ if env is None else env
    if env.get("PAH_ANNOTATIONS", "true").strip().lower() != "false":
        for line in annotations(report, prefix):
            print(line)
    counts = report.to_dict()["counts"]
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"verdict={report.verdict}\n")
            for sev in ("critical", "high", "medium", "low"):
                fh.write(f"{sev}={counts[sev]}\n")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary(report, prefix))
