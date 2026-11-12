"""Optional online checks: `pah scan --online`, and PAH_ONLINE=1 for the guard.

For each package a target installs or runs: does it exist on the public registry, how new is it, and does OSV list
it as malicious (MAL- records)? Only package names (and versions, when pinned) leave the machine: to registry.npmjs.org,
pypi.org and api.osv.dev. Nothing about the repository itself is sent.

Why: LLMs invent package names and attackers register them (slopsquatting); fake job-interview projects depend on
private packages that no public scanner can read; most malicious releases are reported within days, so very new
versions deserve a wait.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .model import Finding, rule

R_MISSING = rule(
    "PAH-P014", "Package does not exist on the public registry",
    "A name that nothing is published under can be registered by anyone, and the next `npx`/`pip install` runs their "
    "code (slopsquatting). A public project depending on a package nobody can read is also how fake job-interview "
    "repositories hide their payload (Gatekeeper's 'phantom dependency').",
    "Do not run it. Find the package that was meant, or ask the author.", attack=("T1195.002",), owasp=("LLM03",),
    refs=("https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands",
          "https://github.com/lb2002/gatekeeper"))
R_KNOWN_BAD = rule(
    "PAH-P015", "Package is listed as malicious (OSV)",
    "OSV's MAL- records collect confirmed malicious packages from OpenSSF, GitHub and registries.",
    "Do not install it. If it was installed, treat the machine as compromised and rotate credentials.",
    attack=("T1195.002",), refs=("https://github.com/ossf/malicious-packages",))
R_NEW_PACKAGE = rule(
    "PAH-P016", "Package was published in the last few days",
    "Most malicious releases are reported within one to three days; waiting before installing a brand-new package or "
    "version catches much of what scanners miss.", "Wait a few days or read the package before installing it.",
    attack=("T1195.002",), refs=("https://openssf.org/blog/2026/05/12/hack-to-the-future-the-impact-and-legacy-of-the-darpa-aixcc-challenge/",))

R_VULNERABLE = rule(
    "PAH-P018", "Dependency version has known vulnerabilities",
    "The exact version a lockfile or pinned manifest installs has published security advisories (OSV collects GitHub, "
    "PyPA, RustSec, Go and other databases). This is a bug, not malware; it matters when the code reaches the "
    "vulnerable function.",
    "Upgrade to a fixed version (shown) and rerun the tests. If you cannot, check whether the vulnerable code is used.",
    attack=("T1190",), refs=("https://osv.dev/", "https://google.github.io/osv.dev/post-v1-querybatch/"))

UA = {"User-Agent": "agent-virus-check (+https://github.com/ji-hun-git/agent-virus-check)", "Accept": "application/json"}


def _get(url: str, timeout: int = 15):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None, None


def _age_days(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 86400


def registry_info(ecosystem: str, name: str) -> dict:
    """{exists: bool|None, age_days: float|None, latest_age_days: float|None}"""
    if ecosystem == "npm":
        status, data = _get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
        if status == 404:
            return {"exists": False}
        if not data:
            return {"exists": None}
        times = data.get("time") or {}
        latest = (data.get("dist-tags") or {}).get("latest")
        if not latest and data.get("versions") is None and times.get("unpublished"):
            return {"exists": False, "unpublished": True}
        return {"exists": True, "age_days": _age_days(times.get("created")),
                "latest_age_days": _age_days(times.get(latest)) if latest else None}
    if ecosystem == "pypi":
        status, data = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
        if status == 404:
            return {"exists": False}
        if not data:
            return {"exists": None}
        uploads = [f.get("upload_time_iso_8601") for files in (data.get("releases") or {}).values() for f in files or []]
        uploads = sorted(u for u in uploads if u)
        return {"exists": True, "age_days": _age_days(uploads[0]) if uploads else None,
                "latest_age_days": _age_days(uploads[-1]) if uploads else None}
    return {"exists": None}


def osv_malicious(packages: list[tuple[str, str]]) -> set[tuple[str, str]]:
    """The (ecosystem, name) pairs with a MAL- advisory in OSV."""
    if not packages:
        return set()
    eco = {"npm": "npm", "pypi": "PyPI"}
    queries = [{"package": {"name": n, "ecosystem": eco[e]}} for e, n in packages if e in eco]
    body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=body,
                                 headers={**UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            results = json.loads(resp.read().decode("utf-8")).get("results") or []
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return set()
    bad = set()
    for (e, n), res in zip(packages, results, strict=False):
        if any(str(v.get("id", "")).startswith("MAL-") for v in (res or {}).get("vulns") or []):
            bad.add((e, n))
    return bad


def check_packages(packages: list[tuple[str, str, str, int, str]], new_days: float = 7.0) -> list[Finding]:
    """packages: (ecosystem, name, path, line, context). Returns findings; network failures produce none."""
    unique = {}
    for eco, name, path, line, context in packages:
        if eco in ("npm", "pypi") and name and not name.startswith((".", "/")):
            unique.setdefault((eco, name), (path, line, context))
    pairs = list(unique)[:300]
    findings: list[Finding] = []
    bad = osv_malicious(pairs)
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        infos = dict(zip(pairs, pool.map(lambda p: registry_info(*p), pairs), strict=True))
    for key in pairs:
        eco, name = key
        path, line, context = unique[key]
        info = infos.get(key) or {}
        if key in bad:
            findings.append(Finding(R_KNOWN_BAD, "critical", path, line, f"{name} ({eco}) has a MAL- advisory in OSV", name,
                                    context))
        elif info.get("exists") is False:
            sev = "high" if context in ("doc", "autoexec", "agent") else "medium"
            findings.append(Finding(R_MISSING, sev, path, line, f"{name} is not on the public {eco} registry", name, context))
        elif info.get("age_days") is not None and info["age_days"] < new_days:
            findings.append(Finding(R_NEW_PACKAGE, "medium", path, line,
                                    f"{name} ({eco}) first appeared {info['age_days']:.1f} days ago", name, context))
    return findings


def _post(url: str, payload: dict, timeout: int = 60):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={**UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "": 0}


def _advisory(vuln_id: str) -> dict:
    status, data = _get(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vuln_id)}", timeout=20)
    return data if status == 200 and isinstance(data, dict) else {}


def _vkey(version: str) -> tuple:
    """Order versions well enough to pick an upgrade: numbers compare as numbers, pre-releases sort first."""
    parts = re.findall(r"\d+|[A-Za-z]+", version.lstrip("vV"))
    return tuple((1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in parts) + ((2, 0, ""),)


def _first_fix(advisory: dict, name: str, current: str) -> str | None:
    """The lowest released version above `current` that fixes this advisory (semver and ecosystem ranges only)."""
    fixes = []
    for affected in advisory.get("affected") or []:
        if str((affected.get("package") or {}).get("name", "")).lower() != name.lower():
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            fixes += [e["fixed"] for e in rng.get("events") or [] if isinstance(e, dict) and e.get("fixed")]
    later = [f for f in fixes if _vkey(f) > _vkey(current)]
    return min(later, key=_vkey) if later else None


def known_vulnerabilities(pins: list[tuple[str, str, str, str, int]], max_details: int = 120) -> tuple[list[Finding], str | None]:
    """pins: (OSV ecosystem, name, version, path, line). Sends names and versions to api.osv.dev; returns findings
    and a problem note when OSV could not be reached (never a silent pass)."""
    if not pins:
        return [], None
    results: list = []
    for start in range(0, min(len(pins), 5000), 1000):
        chunk = pins[start:start + 1000]
        queries = [{"package": {"name": name, "ecosystem": eco}, "version": version} for eco, name, version, _, _ in chunk]
        data = _post("https://api.osv.dev/v1/querybatch", {"queries": queries})
        if data is None:
            return [], "OSV (api.osv.dev) could not be reached; known vulnerabilities were not checked"
        results += data.get("results") or []
    hits = []
    for pin, res in zip(pins, results, strict=False):
        ids = [v.get("id") for v in (res or {}).get("vulns") or [] if v.get("id") and not str(v["id"]).startswith("MAL-")]
        if ids:
            hits.append((pin, ids))
    wanted = list(dict.fromkeys(i for _, ids in hits for i in ids))[:max_details]
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        details = dict(zip(wanted, pool.map(_advisory, wanted), strict=True))
    findings = []
    for (eco, name, version, path, line), ids in hits:
        labels, worst, fixes, unfixed = [], "", [], 0
        for vid in ids:
            adv = details.get(vid) or {}
            sev = str((adv.get("database_specific") or {}).get("severity") or "").upper()
            if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER.get(worst, 0):
                worst = sev
            cve = next((a for a in adv.get("aliases") or [] if str(a).startswith("CVE-")), None)
            labels.append(f"{vid}{' / ' + cve if cve else ''}")
            fix = _first_fix(adv, name, version) if adv else None
            if fix:
                fixes.append(fix)
            elif adv:
                unfixed += 1
        severity = "medium" if worst in ("CRITICAL", "HIGH") else "low"
        upgrade = ""
        if fixes:
            upgrade = f"; upgrade to {max(fixes, key=_vkey)} or later"
            if unfixed:
                upgrade += f" ({unfixed} without a fixed release)"
        findings.append(Finding(R_VULNERABLE, severity, path, line,
                                f"{name} {version} ({eco}): {len(ids)} known "
                                f"{'vulnerability' if len(ids) == 1 else 'vulnerabilities'}"
                                f"{', worst ' + worst if worst else ''} ({', '.join(labels[:4])}{', ...' if len(labels) > 4 else ''})"
                                f"{upgrade}", f"{name}@{version}", "config"))
    return findings, None


def now() -> float:
    return time.time()
