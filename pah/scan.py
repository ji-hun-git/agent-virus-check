"""Scan a directory, a single file, an archive or a git URL, and produce a Report.

Nothing in the target is ever executed. Every file is read in full (no truncation); files that cannot be read in full
make the result "incomplete", never "pass".
"""
from __future__ import annotations

import io
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path

from .model import Report, rule
from .packages import dispatch_packages
from .patterns import scan_text
from .policy import adjust
from .surfaces import AUTO_LOADED, File, State, dispatch
from .text import decode_bytes

R_SYMLINK = rule(
    "PAH-F001", "Symbolic link points outside the repository",
    "A link with a harmless name that resolves to ~/.ssh, a config file or another directory makes an agent read or "
    "write something other than what the approval prompt shows (GhostApproval affected six assistants).",
    "Delete the link or check where it points before letting an agent touch it.", attack=("T1036",),
    refs=("https://wiz.io/blog/ghostapproval-a-trust-boundary-gap-in-ai-coding-assistants",))
R_DISGUISED_BINARY = rule(
    "PAH-F002", "Executable disguised as another file type",
    "An ELF/PE/Mach-O binary named like an image, archive or text file is how xz-utils hid its backdoor in test "
    "fixtures; reviewers and models skip such files.", "Find out what loads the file. Treat it as malicious until "
    "explained.", attack=("T1036.008", "T1027.009"), refs=("https://www.openwall.com/lists/oss-security/2024/03/29/4",))
R_PYC = rule(
    "PAH-F003", "Compiled Python without its source",
    "A .pyc with no matching .py cannot be reviewed; Trail of Bits hid credential theft in bytecode that every "
    "skill scanner missed.", "Delete it, or rebuild it from source you can read.", attack=("T1027.004",),
    refs=("https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/",))
R_NATIVE = rule(
    "PAH-F004", "Native binary shipped in the repository",
    "Prebuilt executables and native modules run without any source to review.",
    "Prefer packages that build from source, or verify the binary's origin.", attack=("T1204.002",))
R_PLANTED = rule(
    "PAH-F006", "Program named after a system tool at the top of the repository",
    "Windows looks in the current folder first, and tools that start git or node from the project folder ran a "
    "planted git.exe as soon as the folder was opened: Cursor 3.2.16 (CVE-2026-63093), Claude Desktop before "
    "1.8089.0 (CVE-2026-88066), Kiro IDE and CLI (CVE-2026-18656).", "Delete the file; update the tool.",
    attack=("T1574.008",), refs=("https://github.com/advisories/GHSA-prfr-jc65-hr23",
                                  "https://aws.amazon.com/security/security-bulletins/2026-074-aws/"))
PLANTED_TOOL = re.compile(r"(?:git|node|npm|npx|pnpm|yarn|python3?|py|pip3?|uv|bun|deno|code|cursor|claude|codex|gemini|kiro|"
                          r"rg|where|cmd|powershell|pwsh|bash|sh|ssh|curl|wget|tar|cargo|rustc|go|java|dotnet|docker|gh)"
                          r"\.(?:exe|com|bat|cmd)", re.I)
R_ARCHIVE_SCRIPT = rule(
    "PAH-F005", "Script hidden inside a document or archive",
    "Office documents are zip files. Trail of Bits hid scripts inside a DOCX and had the skill tell the agent to "
    "extract and run them; pattern scanners never looked inside.", "Do not extract or run it.",
    attack=("T1027.009", "T1204"),
    refs=("https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/",))

SKIP_CONTENT = {"node_modules", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "target", ".gradle",
                ".next", ".nuxt", ".turbo", ".parcel-cache", ".cache", "bower_components", "site-packages"}
NEVER_CONTENT = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock",
                 "uv.lock", "go.sum", "composer.lock", "gemfile.lock", "bun.lock", "pipfile.lock", "flake.lock"}
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 3 * 1024 * 1024 * 1024
MAX_FILES = 300_000
DECODE_BLOBS_UNDER = 6 * 1024 * 1024

DOC_EXT = {".md", ".markdown", ".rst", ".txt", ".adoc", ".mdc", ".html", ".htm", ".org", ".tex", ".svg", ".csv", ".tsv",
           ".rss", ".atom", ".ipynb"}
CONFIG_EXT = {".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties",
              ".plist", ".lock"}
DOC_LIKE_XML = re.compile(r"(?:^|/)(?:feed|rss|atom|sitemap|changelog|news)[^/]*\.xml$", re.I)
CODE_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".tsx", ".py", ".pyw", ".sh", ".bash", ".zsh", ".fish",
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".rb", ".pl", ".php", ".go", ".rs", ".java", ".kt", ".kts",
            ".scala", ".groovy", ".gradle", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".m", ".lua", ".r", ".jl",
            ".dart", ".ex", ".exs", ".erl", ".clj", ".hs", ".ml", ".nim", ".zig", ".v", ".sql", ".gyp", ".mk", ".applescript",
            ".scpt", ".hta", ".wsf", ".jse", ".vbe", ".dockerfile"}
CODE_NAMES = {"makefile", "gnumakefile", "dockerfile", "rakefile", "gemfile", "vagrantfile", "justfile", "procfile", ".envrc",
              ".bashrc", ".zshrc", ".profile", "jenkinsfile", "build", "configure", "gradlew", "mvnw"}
EXEC_EXT = {".exe", ".dll", ".so", ".dylib", ".node", ".bin", ".o", ".a", ".sys", ".scr", ".com", ".elf", ".out", ".app"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".jse", ".wsf",
              ".hta", ".exe", ".dll", ".scr", ".rb", ".pl", ".command", ".applescript", ".scpt", ".lnk", ".jar"}
SENSITIVE_TARGET = re.compile(r"(?:^|[\\/])\.(?:ssh|aws|gnupg|kube|docker|claude|codex|gemini|cursor|openclaw|config[\\/]gcloud)"
                              r"(?:[\\/]|$)|id_rsa|id_ed25519|\.netrc|\.git-credentials|[\\/]etc[\\/]|AppData|Library[\\/]Keychains|"
                              r"\.bash_history|\.zsh_history", re.I)


def _magic(data: bytes) -> str | None:
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:2] == b"MZ" and len(data) > 0x40:
        off = int.from_bytes(data[0x3C:0x40], "little")
        if 0 < off < len(data) - 4 and data[off:off + 4] == b"PE\x00\x00":
            return "PE"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "Mach-O"
    if data[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(data[4:8], "big") < 30:
        return "Mach-O"
    return None


MEDIA_MAGIC = {".ttf": (b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf"), ".otf": (b"OTTO", b"\x00\x01\x00\x00"),
               ".woff": (b"wOFF",), ".woff2": (b"wOF2",), ".png": (b"\x89PNG",), ".jpg": (b"\xff\xd8\xff",),
               ".jpeg": (b"\xff\xd8\xff",), ".gif": (b"GIF8",), ".ico": (b"\x00\x00\x01\x00",), ".bmp": (b"BM",),
               ".webp": (b"RIFF",), ".mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3"), ".wav": (b"RIFF",), ".avi": (b"RIFF",),
               ".mp4": (), ".mov": (), ".m4a": (), ".eot": ()}
CODE_TOKENS = re.compile(r"\b(?:function\s*\w*\s*\(|require\s*\(|import\s+[\w{*]|eval\s*\(|exec\s*\(|const\s+\w+\s*=|"
                         r"var\s+\w+\s*=|let\s+\w+\s*=|def\s+\w+\s*\(|child_process|subprocess|atob\s*\()|=>")


def _disguised_text(state: State, f: File) -> None:
    """A font, image or video that decodes as program text: PolinRider's loader was saved as fa-solid-300.ttf."""
    ext = posixpath.splitext(f.rel.lower())[1]
    magic = MEDIA_MAGIC.get(ext)
    if magic is None or (magic and f.data.startswith(magic)) or (ext in (".mp4", ".mov", ".m4a") and f.data[4:8] == b"ftyp"):
        return
    m = CODE_TOKENS.search(f.text or "")
    if m:
        state.add(R_DISGUISED_BINARY, "high", f.rel, (f.text or "").count("\n", 0, m.start()) + 1,
                  f"program code saved as a {ext} file", (f.text or "")[m.start():m.start() + 120], "code")
        state.mark_autoexec(f.rel, f"code disguised as a {ext} file")


def _is_pyc(f: File) -> bool:
    return f.rel.lower().endswith(".pyc") and f.data[2:4] == b"\r\n"


def _pyc_source(state: State, f: File) -> bool:
    d, name = posixpath.split(f.rel)
    stem = name.split(".")[0]
    candidates = [posixpath.join(d, stem + ".py")]
    if posixpath.basename(d) == "__pycache__":
        candidates.append(posixpath.join(posixpath.dirname(d), stem + ".py"))
    return any(c in state.files for c in candidates)


def _in_skill(state: State, rel: str) -> bool:
    d = posixpath.dirname(rel)
    for _ in range(3):
        if posixpath.join(d, "SKILL.md") in state.files or (not d and "SKILL.md" in state.files):
            return True
        if not d:
            break
        d = posixpath.dirname(d)
    return False


def _binary_checks(state: State, f: File) -> None:
    ext = posixpath.splitext(f.rel.lower())[1]
    kind = _magic(f.data)
    if kind:
        # A Unix executable has no extension; a binary named like an image, archive or text file is disguised.
        versioned_library = re.search(r"\.(?:so|dylib)(?:\.\d+)+$", f.rel.lower())
        if ext and ext not in EXEC_EXT and not f.rel.lower().endswith((".exe", ".dll")) and not versioned_library:
            state.add(R_DISGUISED_BINARY, "high", f.rel, 0, f"{kind} executable named *{ext or ' (no extension)'}", f.rel, "code")
        else:
            sev = "high" if _in_skill(state, f.rel) else ("medium" if f.rel.count("/") <= 1 else "low")
            state.add(R_NATIVE, sev, f.rel, 0, f"{kind} binary", f.rel, "code")
        _strings(state, f, f"strings in the {kind} binary: ")
    if _is_pyc(f):
        if not _pyc_source(state, f):
            state.add(R_PYC, "high", f.rel, 0, "bytecode with no .py source next to it", f.rel, "code")
            _strings(state, f, "strings in compiled bytecode: ")
        else:  # a cache of source that is scanned anyway; committed caches are still worth knowing about
            state.add(R_PYC, "low", f.rel, 0, "compiled Python next to its source (Python may load this instead of the "
                      "source when the header matches)", f.rel, "code")


def _strings(state: State, f: File, note: str) -> None:
    found = re.findall(rb"[\x20-\x7e]{6,}", f.data[:MAX_FILE])
    if not found:
        return
    text = "\n".join(s.decode("ascii") for s in found[:20000])
    for finding in scan_text(text, f.rel, "code", structural=False, decode=True, note=note):
        finding.line = 0
        state.findings.append(finding)


def _archive_members(state: State, f: File, depth: int) -> list[File]:
    out: list[File] = []
    if depth > 3:
        state.incomplete.append(f"{f.rel}: archives nested more than 3 levels deep were not opened")
        return out
    total = 0
    buf = io.BytesIO(f.data)
    office = False
    try:
        if f.data[:4] == b"PK\x03\x04":
            with zipfile.ZipFile(buf) as z:
                names = z.namelist()
                office = "[Content_Types].xml" in names
                for info in z.infolist()[:5000]:
                    if info.is_dir():
                        continue
                    name = info.filename
                    if name.startswith(("/", "\\")) or ".." in re.split(r"[\\/]", name):
                        state.add(R_ARCHIVE_SCRIPT, "high", f.rel, 0, f"member path escapes the archive: {name}", name, "code")
                    if info.flag_bits & 0x1:
                        state.incomplete.append(f"{f.rel}!/{name}: encrypted member not scanned")
                        continue
                    if info.file_size > MAX_FILE or total + info.file_size > 512 * 1024 * 1024 or \
                            (info.compress_size and info.file_size / max(1, info.compress_size) > 250):
                        state.incomplete.append(f"{f.rel}!/{name}: too large or too compressed to unpack safely")
                        continue
                    data = z.read(info)
                    total += len(data)
                    out.append(File(f"{f.rel}!/{name}", len(data), data, decode_bytes(data)))
        elif f.data[:2] == b"\x1f\x8b" or (len(f.data) > 262 and f.data[257:262] == b"ustar"):
            with tarfile.open(fileobj=buf, mode="r:*") as t:
                for member in t.getmembers()[:5000]:
                    if member.issym() or member.islnk():
                        target = member.linkname
                        if target.startswith("/") or ".." in target.split("/"):
                            state.add(R_SYMLINK, "high", f"{f.rel}!/{member.name}", 0, f"link in archive points to {target}",
                                      target, "code")
                        continue
                    if not member.isfile():
                        continue
                    if member.name.startswith("/") or ".." in member.name.split("/"):
                        state.add(R_ARCHIVE_SCRIPT, "high", f.rel, 0, f"member path escapes the archive: {member.name}",
                                  member.name, "code")
                    if member.size > MAX_FILE or total + member.size > 512 * 1024 * 1024:
                        state.incomplete.append(f"{f.rel}!/{member.name}: too large to unpack safely")
                        continue
                    data = t.extractfile(member).read()
                    total += len(data)
                    out.append(File(f"{f.rel}!/{member.name}", len(data), data, decode_bytes(data)))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError) as err:
        state.incomplete.append(f"{f.rel}: could not open archive ({err.__class__.__name__})")
        return []
    if office:
        for m in out:
            ext = posixpath.splitext(m.rel.lower())[1]
            if ext in SCRIPT_EXT or (m.text or "").startswith("#!") or _magic(m.data):
                state.add(R_ARCHIVE_SCRIPT, "high", m.rel, 0, "executable content inside an office document", m.rel, "code")
            if m.rel.endswith(("word/document.xml", "ppt/slides/slide1.xml", "xl/sharedStrings.xml")) and m.text:
                plain = re.sub(r"<[^>]+>", " ", m.text)
                out.append(File(m.rel + "#text", len(plain), plain.encode("utf-8", "replace"), plain))
    return out


ARCHIVE_EXT = (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".vsix", ".whl", ".jar", ".nupkg", ".crx", ".xpi",
               ".tgz", ".tar.gz", ".tar", ".crate", ".skill", ".egg", ".apk", ".aab", ".ipa", ".gem", ".docm", ".xlsm", ".pptm")


def _is_archive(f: File) -> bool:
    low = f.rel.lower()
    return low.endswith(ARCHIVE_EXT) and (f.data[:4] == b"PK\x03\x04" or f.data[:2] == b"\x1f\x8b"
                                          or (len(f.data) > 262 and f.data[257:262] == b"ustar"))


def _git_symlinks(root: Path) -> dict[str, str]:
    """On Windows clones without symlink support, links are plain files; the index still records mode 120000."""
    if not (root / ".git").is_dir() or shutil.which("git") is None:
        return {}
    try:
        out = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(root),
                              "ls-files", "-s", "-z"], capture_output=True, timeout=30, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    links = {}
    for entry in out.split(b"\x00"):
        if entry.startswith(b"120000 "):
            rel = entry.split(b"\t", 1)[-1].decode("utf-8", "replace")
            try:
                links[rel] = (root / rel).read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
    return links


def _check_link(state: State, rel: str, target: str) -> None:
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), target.replace("\\", "/")))
    outside = target.startswith(("/", "\\", "~")) or re.match(r"^[A-Za-z]:", target) or resolved.startswith("..")
    into_git = resolved == ".git" or resolved.startswith(".git/")
    if SENSITIVE_TARGET.search(target):
        state.add(R_SYMLINK, "critical", rel, 0, f"links to {target}", f"{rel} -> {target}", "config")
    elif outside or into_git:
        state.add(R_SYMLINK, "high", rel, 0, f"links outside the repository to {target}", f"{rel} -> {target}", "config")


def _walk(root: Path, state: State, started: float, max_seconds: float | None) -> None:
    total = 0
    count = 0
    stack = [(root, "")]
    links = _git_symlinks(root)
    while stack:
        directory, prefix = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as err:
            state.incomplete.append(f"{prefix or '.'}: could not list ({err.strerror})")
            continue
        for entry in entries:
            rel = f"{prefix}{entry.name}"
            if entry.is_symlink():
                try:
                    _check_link(state, rel, os.readlink(entry.path))
                except OSError:
                    pass
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name == ".git":
                    _walk_git(Path(entry.path), rel + "/", state)
                    continue
                stack.append((Path(entry.path), rel + "/"))
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            count += 1
            if count > MAX_FILES:
                state.incomplete.append(f"more than {MAX_FILES:,} files; the rest were not scanned")
                return
            if max_seconds and time.monotonic() - started > max_seconds:
                state.incomplete.append(f"time limit of {max_seconds:.0f}s reached while reading files")
                return
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            if size > MAX_FILE:
                state.incomplete.append(f"{rel}: {size / 1e6:.0f} MB file not scanned")
                continue
            total += size
            if total > MAX_TOTAL:
                state.incomplete.append("repository larger than 3 GB; the rest was not scanned")
                return
            try:
                data = Path(entry.path).read_bytes()
            except OSError as err:
                state.incomplete.append(f"{rel}: could not read ({err.strerror})")
                continue
            state.files[rel] = File(rel, size, data, decode_bytes(data))
    for rel, target in links.items():
        _check_link(state, rel, target)


def _walk_git(git: Path, prefix: str, state: State) -> None:
    """Inside .git, read only what can run or redirect: config, hooks and indirection files."""
    for name in ("config", "commondir", "gitdir"):
        p = git / name
        if p.is_file():
            data = p.read_bytes()[:1_000_000]
            state.files[prefix + name] = File(prefix + name, len(data), data, decode_bytes(data))
    hooks = git / "hooks"
    if hooks.is_dir():
        for p in hooks.iterdir():
            if p.is_file() and not p.name.endswith(".sample"):
                data = p.read_bytes()[:1_000_000]
                state.files[f"{prefix}hooks/{p.name}"] = File(f"{prefix}hooks/{p.name}", len(data), data, decode_bytes(data))
    worktrees = git / "worktrees"
    if worktrees.is_dir():
        for p in worktrees.glob("*/gitdir"):
            data = p.read_bytes()[:10_000]
            rel = f"{prefix}worktrees/{p.parent.name}/gitdir"
            state.files[rel] = File(rel, len(data), data, decode_bytes(data))


_JS_IMPORT = re.compile(r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|\bimport\s+)['"](\.{1,2}/[^'"]+)['"]""")
_PY_IMPORT = re.compile(r"(?m)^\s*(?:from\s+(\.?[\w.]*)\s+import\s+([\w, ]+)|import\s+([\w.]+))")
_JS_EXTS = ("", ".js", ".cjs", ".mjs", ".ts", ".json", "/index.js", "/index.cjs", "/index.ts")


def _local_imports(state: State, f: File) -> list[str]:
    out = []
    text = f.text or ""
    base = posixpath.dirname(f.rel)
    low = f.rel.lower()
    if low.endswith((".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".mts", ".cts")):
        for m in _JS_IMPORT.finditer(text):
            target = posixpath.normpath(posixpath.join(base, m.group(1)))
            for ext in _JS_EXTS:
                if target + ext in state.files:
                    out.append(target + ext)
                    break
    elif low.endswith(".py"):
        for m in _PY_IMPORT.finditer(text):
            mod = (m.group(1) or m.group(3) or "").lstrip(".")
            names = [mod] if mod else [n.strip() for n in (m.group(2) or "").split(",")]
            for name in names:
                path = posixpath.join(base, name.replace(".", "/")) if name else ""
                for cand in (path + ".py", path + "/__init__.py"):
                    if name and cand in state.files:
                        out.append(cand)
    return out


def _propagate(state: State) -> None:
    """Mark what autoexec files import. Hooks, install scripts and build scripts pull their imports in up to four
    levels deep. A program that documentation tells you to run is followed one level: its entry module is what the
    instructions run, and an application's whole import graph is not install-time code."""
    depth = {rel: 0 for rel in state.autoexec}
    limit = {rel: 1 if reason.startswith("run by the instructions in") else 4 for rel, reason in state.autoexec.items()}
    queue = list(state.autoexec)
    while queue:
        rel = queue.pop()
        f = state.files.get(rel)
        if f is None or f.text is None or depth[rel] >= limit[rel]:
            continue
        for ref in _local_imports(state, f):
            if ref not in state.autoexec:
                state.autoexec[ref] = f"imported by {rel} ({state.autoexec[rel]})"
                depth[ref] = depth[rel] + 1
                limit[ref] = limit[rel]
                queue.append(ref)


def _context(state: State, f: File) -> str:
    if f.rel in state.autoexec:
        return "autoexec"
    low = f.rel.lower()
    name = posixpath.basename(low)
    ext = posixpath.splitext(name)[1]
    if f.rel in state.doc_auto or AUTO_LOADED.search(f.rel) or low.endswith("#text") or DOC_LIKE_XML.search(low):
        return "doc"
    if ext in CODE_EXT or name in CODE_NAMES or (f.text or "").startswith("#!"):
        return "code"
    if ext in CONFIG_EXT or name.startswith(".") and not ext:
        return "config"
    return "doc"


def _skipped_dir(rel: str) -> bool:
    return any(part in SKIP_CONTENT for part in rel.split("/")[:-1])


def scan(target: str | os.PathLike, *, max_seconds: float | None = None, online: bool = False,
         av: bool = False) -> Report:
    """Scan a directory, file, archive or git URL. Nothing in the target is executed.

    online=True also asks the public registries and OSV about the packages the target installs or runs, and about
    known vulnerabilities in pinned versions (package names and versions only). av=True also runs the antivirus
    engines installed on this computer (Microsoft Defender, ClamAV) over the files, locally."""
    started = time.monotonic()
    target_str = str(target)
    if re.match(r"^(?:https?://|git@|ssh://)", target_str):
        return _scan_url(target_str, max_seconds=max_seconds, online=online, av=av)
    path = Path(target_str).expanduser()
    if not path.exists():
        raise FileNotFoundError(target_str)
    if path.is_dir():
        state = State(root=path.resolve())
        _walk(state.root, state, started, max_seconds)
    else:
        state = State(root=path.resolve().parent)
        data = path.read_bytes()
        state.files[path.name] = File(path.name, len(data), data, decode_bytes(data))
    report = _analyze(state, target_str, started, max_seconds, online)
    if av:
        from . import av as antivirus

        found, used, problems = antivirus.scan(path.resolve())
        report.findings.extend(found)
        report.stats["antivirus"] = {"engines": used, "problems": problems, "detections": len(found)}
    return report


def _analyze(state: State, target: str, started: float, max_seconds: float | None, online: bool = False) -> Report:
    archives = [f for f in list(state.files.values()) if _is_archive(f)]
    for f in archives:
        for member in _archive_members(state, f, 1):
            state.files[member.rel] = member
            if _is_archive(member):
                for inner in _archive_members(state, member, 2):
                    state.files[inner.rel] = inner
    for f in list(state.files.values()):
        if _skipped_dir(f.rel) and f.name.lower() not in ("package.json", "binding.gyp") and not f.name.endswith(".pth"):
            continue
        dispatch(state, f)
        dispatch_packages(state, f)
        if "/" not in f.rel and PLANTED_TOOL.fullmatch(f.name):
            state.add(R_PLANTED, "critical", f.rel, 0, f"{f.name} in the project folder runs in place of the real "
                      f"{f.name.split('.')[0]} in tools that start it from there", f.rel, "code")
            state.mark_autoexec(f.rel, "program named after a system tool in the project folder")
        if f.text is None:
            _binary_checks(state, f)
        else:
            _disguised_text(state, f)
    _propagate(state)
    scanned = 0
    for f in state.files.values():
        if f.text is None or posixpath.basename(f.rel.lower()) in NEVER_CONTENT:
            continue
        if _skipped_dir(f.rel) and f.rel not in state.autoexec:
            continue
        if max_seconds and time.monotonic() - started > max_seconds:
            state.incomplete.append(f"time limit of {max_seconds:.0f}s reached; {f.rel} and later files not checked")
            break
        context = _context(state, f)
        decode = f.size <= DECODE_BLOBS_UNDER or context == "autoexec"
        state.findings.extend(scan_text(f.text, f.rel, context, decode=decode))
        scanned += 1
    if online and state.packages:
        from .intel import check_packages

        state.findings.extend(check_packages(state.packages))
    if online:
        from .intel import known_vulnerabilities
        from .lockfiles import pinned

        pins = pinned(state.files)
        vulns, problem = known_vulnerabilities(pins)
        state.findings.extend(vulns)
        state.extra["dependencies"] = {"pinned_versions": len(pins), "vulnerable": len(vulns), "problem": problem}
    adjust(state.findings, state.autoexec, {rel: f.size for rel, f in state.files.items() if f.size >= 1_000_000})
    report = Report(target=target, findings=_dedupe(state.findings), surfaces=state.surfaces, incomplete=state.incomplete)
    report.stats = {
        "files": len(state.files), "text_files_scanned": scanned,
        "bytes": sum(f.size for f in state.files.values()), "archives_opened": len(archives),
        "autoexec_files": dict(sorted(state.autoexec.items())), "seconds": round(time.monotonic() - started, 2),
        **state.extra,
    }
    return report


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.rule, f.path, f.line, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _scan_url(url: str, *, max_seconds: float | None, online: bool = False, av: bool = False) -> Report:
    """Clone without hooks, submodules, LFS smudge or templates into a temporary directory, scan it, delete it."""
    if shutil.which("git") is None:
        raise RuntimeError("git is required to scan a URL")
    tmp = Path(tempfile.mkdtemp(prefix="pah-clone-"))
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_CONFIG_NOSYSTEM="1")
    try:
        cmd = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull, "-c", "protocol.ext.allow=never",
               "-c", "protocol.file.allow=never", "clone", "--depth", "1", "--no-recurse-submodules", "--template=",
               "--quiet", "--", url, str(tmp / "repo")]
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env, check=False)
        if done.returncode != 0:
            raise RuntimeError(f"git clone failed: {done.stderr.strip()[:300]}")
        report = scan(tmp / "repo", max_seconds=max_seconds, online=online, av=av)
        report.target = url
        return report
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
