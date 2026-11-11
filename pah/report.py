"""Render a Report as text, JSON or SARIF 2.1.0."""
from __future__ import annotations

import json
import os
import sys

from . import __version__
from .model import RULES, SEVERITIES, Report, rank

HOMEPAGE = "https://github.com/ji-hun-git/personal-anti-hack"
VERDICT_TEXT = {
    "block": "BLOCK: do not open, install or run this with an agent until the findings below are explained",
    "warn": "WARN: review the findings below before you let an agent set this up",
    "pass": "PASS: nothing that runs on its own looks dangerous",
    "incomplete": "INCOMPLETE: parts could not be read, so this is not a clean result",
}
VERDICT_KO = {
    "block": "차단: 아래 항목이 설명되기 전에는 에이전트로 열거나 설치하거나 실행하지 마세요",
    "warn": "경고: 에이전트에게 설정을 맡기기 전에 아래 항목을 확인하세요",
    "pass": "통과: 스스로 실행되는 것 중 위험해 보이는 것은 없습니다",
    "incomplete": "불완전: 일부를 읽지 못했으므로 깨끗하다는 결과가 아닙니다",
}
CHECKUP_TEXT = {
    "block": "ACT: fix the high-severity findings below",
    "warn": "REVIEW: look at the findings below",
    "pass": "OK: no problems found",
    "incomplete": "INCOMPLETE: some checks could not run",
}
CHECKUP_KO = {
    "block": "조치 필요: 아래의 심각한 항목을 처리하세요",
    "warn": "확인 필요: 아래 항목을 살펴보세요",
    "pass": "양호: 문제가 발견되지 않았습니다",
    "incomplete": "불완전: 일부 점검을 실행하지 못했습니다",
}
HEADINGS = {
    "en": {"surfaces": "Runs without being read", "findings": "Findings", "incomplete": "Not fully scanned",
           "why": "Why", "fix": "Fix", "none": "No findings.", "review": "Deep review", "antivirus": "Antivirus",
           "dependencies": "Known vulnerabilities"},
    "ko": {"surfaces": "읽지 않아도 실행되는 것", "findings": "발견 사항", "incomplete": "끝까지 검사하지 못한 부분",
           "why": "이유", "fix": "조치", "none": "발견 사항 없음.", "review": "심층 검토", "antivirus": "백신 검사",
           "dependencies": "알려진 취약점"},
}
COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m",
          "block": "\033[1;97;41m", "warn": "\033[1;30;43m", "pass": "\033[1;30;42m", "incomplete": "\033[1;30;47m"}
RESET = "\033[0m"


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def text(report: Report, *, lang: str = "en", color: bool | None = None, limit: int = 60, verbose: bool = False,
         subject: str = "scan") -> str:
    color = _use_color(sys.stdout) if color is None else color
    h = HEADINGS.get(lang, HEADINGS["en"])
    paint = (lambda key, s: f"{COLORS[key]}{s}{RESET}") if color else (lambda key, s: s)
    data = report.to_dict()
    counts = ", ".join(f"{n} {sev}" for sev, n in reversed(list(data["counts"].items())) if n)
    verdict = report.verdict
    if subject == "computer":
        label, sentence = (CHECKUP_KO if lang == "ko" else CHECKUP_TEXT)[verdict].split(": ", 1)
        size = ""
    else:
        label, sentence = verdict.upper(), (VERDICT_KO if lang == "ko" else VERDICT_TEXT)[verdict].split(": ", 1)[1]
        size = f"  ·  {report.stats.get('files', 0):,} files"
    lines = [f"personal-anti-hack {__version__}  ·  {report.target}",
             paint(verdict, f" {label} ") + "  " + sentence,
             f"   {counts or '0 findings'}{size}  ·  {report.stats.get('seconds', 0)}s", ""]
    if report.surfaces:
        lines.append(f"{h['surfaces']} ({len(report.surfaces)}):")
        for s in report.surfaces[:40]:
            where = f"{s.path}:{s.line}" if s.line else s.path
            cmd = f"  →  {s.command}" if s.command else ""
            lines.append(f"  • {s.kind}  [{where}]  ({s.trigger}){cmd}")
        if len(report.surfaces) > 40:
            lines.append(f"  … {len(report.surfaces) - 40} more")
        lines.append("")
    findings = report.sorted_findings()
    if not verbose:
        findings = [f for f in findings if rank(f.severity) >= rank("low")]
    lines.append(f"{h['findings']}:" if findings else h["none"])
    for f in findings[:limit]:
        meta = RULES[f.rule]
        where = f"{f.path}:{f.line}" if f.line else f.path
        lines.append(f"  {paint(f.severity, f.severity.upper().ljust(8))} {f.rule}  {meta.title}")
        lines.append(f"           {where} — {f.message}")
        if f.evidence:
            lines.append(f"           > {f.evidence}")
        if rank(f.severity) >= rank("high"):
            lines.append(f"           {h['why']}: {meta.why}")
            if meta.fix:
                lines.append(f"           {h['fix']}: {meta.fix}")
    if len(findings) > limit:
        lines.append(f"  … {len(findings) - limit} more (use --json for all)")
    if report.review:
        r = report.review
        lines += ["", f"{h['review']} ({r.get('provider')}/{r.get('model')}): {r.get('status')} — {r.get('verdict', '')}"]
        for c in (r.get("claims") or [])[:8]:
            lines.append(f"  - {c.get('file')}:{c.get('line')}  {c.get('claim')}")
        if r.get("summary"):
            lines.append(f"  {r['summary']}")
    av = report.stats.get("antivirus")
    if av:
        engines = ", ".join(av.get("engines") or []) or "none available"
        lines += ["", f"{h['antivirus']}: {engines} — {av.get('detections', 0)} detection(s)"]
        lines += [f"  - {p}" for p in av.get("problems") or []]
    deps = report.stats.get("dependencies")
    if deps:
        lines += ["", f"{h['dependencies']}: {deps.get('pinned_versions', 0)} pinned versions checked with OSV, "
                      f"{deps.get('vulnerable', 0)} with known vulnerabilities"]
        if deps.get("problem"):
            lines.append(f"  - {deps['problem']}")
    if report.incomplete:
        lines += ["", f"{h['incomplete']}:"] + [f"  - {x}" for x in report.incomplete[:20]]
    return "\n".join(lines)


NEXT_STEPS = {
    "en": {
        "title": "Next steps",
        "block": "Do not install, build, test or open this with an agent. Each HIGH or CRITICAL finding above names the "
                 "file and line. To find out what the code does, follow skills/malware-audit. If anything from it already "
                 "ran on this computer, follow skills/incident-response and rotate your credentials.",
        "warn": "Review the MEDIUM findings above before an agent sets this up. Continue only if each one is explained "
                "and you trust the source; otherwise use a disposable VM or container.",
        "incomplete": "Part of the target could not be read (listed above), so this is not a clean result. Check those "
                      "files by hand, or rerun with a longer --max-seconds.",
        "pass": "Nothing known to be malicious, and nothing dangerous that runs on its own. That is not proof of safety.",
        "no_av": "No antivirus engine ran (Microsoft Defender on Windows, ClamAV elsewhere).",
        "no_online": "Packages were not checked online; --online checks for malicious, missing, brand-new and vulnerable "
                     "versions (sends package names and versions).",
        "bugs": "Looking for security bugs rather than malware? Follow skills/security-review.",
    },
    "ko": {
        "title": "다음 단계",
        "block": "설치·빌드·테스트하거나 에이전트로 열지 마세요. 위의 HIGH·CRITICAL 항목마다 파일과 줄이 있습니다. 코드가 실제로 "
                 "무엇을 하는지는 skills/malware-audit 절차로 확인하세요. 이미 이 컴퓨터에서 실행됐다면 "
                 "skills/incident-response를 따르고 키·토큰을 교체하세요.",
        "warn": "에이전트에게 설치를 맡기기 전에 위의 MEDIUM 항목을 확인하세요. 각 항목이 설명되고 출처를 믿을 수 있을 때만 "
                "진행하고, 아니면 일회용 VM이나 컨테이너에서 실행하세요.",
        "incomplete": "대상 일부를 읽지 못했습니다(위 목록). 깨끗하다는 뜻이 아닙니다. 그 파일들을 직접 확인하거나 "
                      "--max-seconds를 늘려 다시 실행하세요.",
        "pass": "알려진 악성 코드도, 스스로 실행되는 위험한 동작도 없습니다. 다만 안전이 증명된 것은 아닙니다.",
        "no_av": "백신 엔진 검사가 실행되지 않았습니다(Windows는 Microsoft Defender, 그 외는 ClamAV).",
        "no_online": "패키지를 온라인으로 확인하지 않았습니다. --online은 악성·존재하지 않는·갓 올라온·취약한 버전을 "
                     "확인합니다(패키지 이름과 버전을 보냅니다).",
        "bugs": "악성 코드가 아니라 보안 버그를 찾는다면 skills/security-review 절차를 따르세요.",
    },
}


def next_steps(report: Report, lang: str = "en") -> str:
    t = NEXT_STEPS.get(lang, NEXT_STEPS["en"])
    lines = [f"{t['title']}:", f"  {t[report.verdict]}"]
    av = report.stats.get("antivirus") or {}
    if not av.get("engines"):
        lines.append(f"  {t['no_av']}")
    if "dependencies" not in report.stats:
        lines.append(f"  {t['no_online']}")
    lines.append(f"  {t['bugs']}")
    return "\n".join(lines)


def as_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)


def sarif(report: Report) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    used = sorted({f.rule for f in report.findings})
    rules = [{
        "id": rid, "name": RULES[rid].title,
        "shortDescription": {"text": RULES[rid].title}, "fullDescription": {"text": RULES[rid].why},
        "help": {"text": RULES[rid].fix or RULES[rid].why}, "helpUri": f"{HOMEPAGE}/blob/main/docs/rules.md#{rid.lower()}",
        "properties": {"tags": list(RULES[rid].attack) + list(RULES[rid].owasp)},
    } for rid in used]
    results = []
    for f in report.sorted_findings():
        loc = {"physicalLocation": {"artifactLocation": {"uri": f.path.split("!/")[0]}}}
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": max(1, f.line)}
        results.append({"ruleId": f.rule, "level": level[f.severity],
                        "message": {"text": f"{f.message}" + (f" — {f.evidence}" if f.evidence else "")},
                        "locations": [loc], "properties": {"severity": f.severity, "context": f.context}})
    doc = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "personal-anti-hack", "version": __version__, "informationUri": HOMEPAGE,
                                         "rules": rules}},
                     "results": results,
                     "properties": {"verdict": report.verdict, "incomplete": report.incomplete}}]}
    return json.dumps(doc, indent=2, ensure_ascii=False)


def rules_markdown() -> str:
    lines = ["# Rules", "", "Every rule personal-anti-hack reports, with the incident or study behind it.", "",
             "| Rule | What it means | ATT&CK | OWASP |", "| --- | --- | --- | --- |"]
    for rid in sorted(RULES):
        r = RULES[rid]
        lines.append(f"| <a id=\"{rid.lower()}\"></a>`{rid}` | **{r.title}.** {r.why} | {', '.join(r.attack)} | {', '.join(r.owasp)} |")
    lines += ["", "Severity depends on where a match is: code that runs on its own (hooks, install scripts, folder-open "
              "tasks and the files they run) is judged most strictly, then other code, configuration and documentation.",
              f"Severities: {', '.join(SEVERITIES)}. High or critical blocks; medium warns."]
    return "\n".join(lines) + "\n"
