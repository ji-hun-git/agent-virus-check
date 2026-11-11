"""Antivirus engines already on this computer: Microsoft Defender (Windows) and ClamAV (any system).

Signature engines recognise known malware families, droppers, hack tools and packed binaries; pah's rules recognise
the source-level, install-time and agent-level attacks that signatures have not seen. An audit uses both. The scan is
local: nothing is uploaded, and remediation is switched off so the engine reports instead of deleting files.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .model import Finding, rule

R_AV = rule(
    "PAH-V001", "Antivirus engine detected malware",
    "A signature engine matched a known malware family, hack tool or potentially unwanted program. Signature hits are "
    "rarely wrong about binaries and droppers, which source-level rules cannot read.",
    "Do not run or open the file. If it already ran, follow the incident-response steps and rotate credentials.",
    attack=("T1204",), refs=("https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus",
                             "https://docs.clamav.net/manual/Usage/Scanning.html"))

TEST_SIGNATURES = re.compile(r"EICAR|Test[-_ ]?File|Clamav\.Test", re.I)
PUA = re.compile(r"\b(?:PUA|PUP|HackTool|Adware|RiskWare|Tool|Unwanted|Generic\.Tool)\b", re.I)


def defender_path() -> Path | None:
    if os.name != "nt":
        return None
    candidates = []
    data = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
    if data.is_dir():
        candidates += sorted(data.glob("*/MpCmdRun.exe"), reverse=True)
    candidates.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe")
    return next((c for c in candidates if c.is_file()), None)


def engines() -> list[str]:
    found = []
    if defender_path():
        found.append("Microsoft Defender")
    if shutil.which("clamdscan") or shutil.which("clamscan"):
        found.append("ClamAV")
    return found


def _severity(signature: str) -> str:
    if TEST_SIGNATURES.search(signature):
        return "medium"  # an antivirus test file: harmless by design, but nobody ships one by accident
    if PUA.search(signature):
        return "high"
    return "critical"


def _rel(path: str, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return path


def _defender(exe: Path, target: Path, timeout: int) -> tuple[list[tuple[str, str]], str | None]:
    cmd = [str(exe), "-Scan", "-ScanType", "3", "-File", str(target), "-DisableRemediation"]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return [], f"Microsoft Defender did not finish within {timeout}s"
    except OSError as err:
        return [], f"Microsoft Defender could not start: {err.strerror}"
    out = done.stdout + done.stderr
    hits, threat = [], None
    for line in out.splitlines():
        m = re.match(r"\s*Threat\s*:\s*(.+)$", line)
        if m:
            threat = m.group(1).strip()
            continue
        m = re.match(r"\s*(?:file|containerfile)\s*:\s*(.+)$", line, re.I)
        if m and threat:
            hits.append((threat, m.group(1).strip()))
    if done.returncode not in (0, 2) and not hits:
        return [], f"Microsoft Defender exited with code {done.returncode}: {out.strip()[-200:]}"
    if done.returncode == 2 and not hits:
        hits.append(("threat reported without details", str(target)))
    return hits, None


def _clamav(target: Path, timeout: int) -> tuple[list[tuple[str, str]], str | None]:
    if shutil.which("clamdscan"):
        cmd = ["clamdscan", "--fdpass", "--infected", "--no-summary", "--multiscan", str(target)]
    else:
        cmd = ["clamscan", "--recursive", "--infected", "--no-summary", str(target)]
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return [], f"ClamAV did not finish within {timeout}s"
    except OSError as err:
        return [], f"ClamAV could not start: {err.strerror}"
    hits = [(m.group(2), m.group(1)) for m in re.finditer(r"(?m)^(.+?):\s+(.+?)\s+FOUND$", done.stdout)]
    if done.returncode not in (0, 1):
        return hits, f"ClamAV exited with code {done.returncode}: {(done.stderr or done.stdout).strip()[-200:]}"
    return hits, None


def scan(target: Path, timeout: int = 900) -> tuple[list[Finding], list[str], list[str]]:
    """(findings, engines used, problems). No engine on this computer means no findings and a note, never a pass."""
    findings: list[Finding] = []
    used: list[str] = []
    problems: list[str] = []
    exe = defender_path()
    if exe:
        hits, problem = _defender(exe, target, timeout)
        used.append("Microsoft Defender")
        if problem:
            problems.append(problem)
        for signature, path in hits:
            findings.append(Finding(R_AV, _severity(signature), _rel(path, target), 0,
                                    f"Microsoft Defender: {signature}", path, "code"))
    if shutil.which("clamdscan") or shutil.which("clamscan"):
        hits, problem = _clamav(target, timeout)
        used.append("ClamAV")
        if problem:
            problems.append(problem)
        for signature, path in hits:
            findings.append(Finding(R_AV, _severity(signature), _rel(path, target), 0, f"ClamAV: {signature}", path, "code"))
    if not used:
        problems.append("no antivirus engine found (Microsoft Defender on Windows, or ClamAV: clamscan/clamdscan)")
    return findings, used, problems
