"""Text handling that does not trust how a file looks when it is rendered.

Everything here works on the whole file: nothing is truncated, padded content is still read, invisible characters
are decoded, and encoded blobs are decoded in code (never by asking a model to decode them).
"""
from __future__ import annotations

import base64
import binascii
import bisect
import gzip
import re
import zlib

# ---------------------------------------------------------------------------------------------- decoding bytes


def decode_bytes(data: bytes) -> str | None:
    """Text content of a file, or None when it is binary."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    text = data.decode("latin-1")
    printable = sum(1 for ch in text[:65536] if ch.isprintable() or ch in "\r\n\t")
    return text if printable >= 0.9 * min(len(text), 65536) else None


class Lines:
    """Position to line number, for files of any size."""

    def __init__(self, text: str):
        self.starts = [0]
        self.starts.extend(m.end() for m in re.finditer("\n", text))

    def line(self, pos: int) -> int:
        return bisect.bisect_right(self.starts, pos)

    def __len__(self) -> int:
        return len(self.starts)


def line_at(text: str, pos: int, width: int = 160) -> str:
    """The text around a position, on one line."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    end = len(text) if end < 0 else end
    if end - start > width:
        left = max(start, pos - width // 2)
        return text[left:left + width].rstrip("\r")
    return text[start:end].rstrip("\r")


# ---------------------------------------------------------------------------------------- invisible characters

TAGS = re.compile("[\U000E0000-\U000E007F]+")
SELECTORS = re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]+")
BIDI = re.compile("[\u202A-\u202E\u2066-\u2069]")
ZERO_WIDTH = re.compile("[\u200B\u200C\u200D\u2060-\u2064\uFEFF\u180E\u034F]")
FILLERS = re.compile("[\u115F\u1160\u3164\uFFA0]")
_ANY_INVISIBLE = re.compile(
    "[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u180E\u034F\u115F\u1160\u3164\uFFA0"
    "\uFE00-\uFE0F\U000E0000-\U000E007F\U000E0100-\U000E01EF]+")


def _emoji_like(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x2300 <= cp <= 0x23FF or 0x2B00 <= cp <= 0x2BFF
            or 0x2190 <= cp <= 0x21FF or 0x25A0 <= cp <= 0x25FF or 0x2900 <= cp <= 0x297F or cp in (0x00A9, 0x00AE,
            0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D, 0x3297, 0x3299, 0x20E3, 0x200D) or ch in "#*0123456789")


def decode_tags(run: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def decode_selectors(run: str) -> str:
    """Bytes hidden in variation selectors (GlassWorm): U+FE00..FE0F = 0..15, U+E0100..E01EF = 16..255."""
    data = bytearray()
    for c in run:
        cp = ord(c)
        data.append(cp - 0xFE00 if cp <= 0xFE0F else cp - 0xE0100 + 16)
    return bytes(data).decode("utf-8", errors="replace")


_FLAG_TAGS = re.compile("[\U000E0030-\U000E0039\U000E0061-\U000E007A]{2,7}\U000E007F")


def invisible(text: str) -> list[dict]:
    """Invisible characters that can hide instructions or code: one entry per run or character class.

    Not reported: emoji subdivision flags (black flag + tag letters + cancel tag, e.g. the flag of England),
    ideographic variation sequences (one or two selectors after a CJK or other non-ASCII character) and the
    text/emoji presentation selectors. Each of these is what the characters are for, and none can carry a payload.
    """
    found: list[dict] = []
    if text.isascii():
        return found
    for m in TAGS.finditer(text):
        if m.start() and text[m.start() - 1] == "\U0001F3F4" and _FLAG_TAGS.fullmatch(m.group()):
            continue
        found.append({"kind": "tags", "pos": m.start(), "count": len(m.group()), "decoded": decode_tags(m.group())})
    scattered = []
    for m in SELECTORS.finditer(text):
        run = m.group()
        if len(run) <= 2 and all(c in "\uFE0E\uFE0F" for c in run):
            continue  # text or emoji presentation of the previous character
        if len(run) <= 2:
            scattered.append(m)  # an ideographic variation sequence, or one or two bytes: no payload on its own
            continue
        found.append({"kind": "selectors", "pos": m.start(), "count": len(run), "decoded": decode_selectors(run)})
    if len(scattered) >= 16 and sum(not text[m.start() - 1].isascii() for m in scattered if m.start()) < len(scattered) / 2:
        # many short runs after ASCII text: a payload spread out to dodge run-length checks
        joined = "".join(m.group() for m in scattered)
        found.append({"kind": "selectors", "pos": scattered[0].start(), "count": len(joined),
                      "decoded": decode_selectors(joined)})
    bidi = [m.start() for m in BIDI.finditer(text)]
    if bidi:
        found.append({"kind": "bidi", "pos": bidi[0], "count": len(bidi), "decoded": "", "positions": bidi[:200]})
    zero = []
    for m in ZERO_WIDTH.finditer(text):
        pos, ch = m.start(), m.group()
        if ch == "\uFEFF" and pos == 0:
            continue
        prev = text[pos - 1] if pos else ""
        nxt = text[pos + 1] if pos + 1 < len(text) else ""
        if ch == "\u200D" and (_emoji_like(prev) or _emoji_like(nxt) or nxt in "\uFE0F"):
            continue
        if ch == "\u200C" and any("\u0600" <= c <= "\u06FF" or "\u0900" <= c <= "\u0DFF" for c in (prev, nxt) if c):
            continue
        zero.append(pos)
    if zero:
        found.append({"kind": "zero-width", "pos": zero[0], "count": len(zero), "decoded": "", "positions": zero[:200]})
    fillers = [m.start() for m in FILLERS.finditer(text)]
    if fillers:
        found.append({"kind": "filler", "pos": fillers[0], "count": len(fillers), "decoded": ""})
    return found


def reveal(text: str) -> str:
    """Show invisible characters as code points, and decode hidden tag or selector text, for display."""

    def sub(m: re.Match) -> str:
        run = m.group()
        if len(run) == 1 and run in "\uFE0E\uFE0F\u200E\u200F":
            return run
        if all(0xE0000 <= ord(c) <= 0xE007F for c in run):
            return f"⟦hidden tag text: {decode_tags(run)!r}⟧"
        if len(run) > 1 and all(0xFE00 <= ord(c) <= 0xFE0F or 0xE0100 <= ord(c) <= 0xE01EF for c in run):
            return f"⟦{len(run)} variation selectors: {decode_selectors(run)[:120]!r}⟧"
        shown = "".join(f"<U+{ord(c):04X}>" for c in run[:6])
        return shown + (f"…(+{len(run) - 6})" if len(run) > 6 else "")

    return _ANY_INVISIBLE.sub(sub, text)


# --------------------------------------------------------------------------------------------- padding and size

BLANK_RUN = re.compile(r"(?:[ \t]*\r?\n){400,}")
SPACE_RUN = re.compile(r"[ \t]{180,}(?=[^\s])")
NON_SPACE = re.compile(r"\S")
_RST_BORDER = re.compile(r"(?m)^[ \t]*=+(?:[ \t]+=+)+[ \t]*\r?$")
_PUSHED_DOC = re.compile(r"^(?:[;&|`$]|\$\()|\b(?:curl|wget|bash|sh|zsh|python[0-9.]*|node|npx|npm|pip[0-9.]*|uvx?|powershell|pwsh|"
                         r"iex|iwr|irm|eval|exec|rm|chmod|base64|sudo|ignore|disregard|instructions?|assistant|agent|system|"
                         r"must|always|never|secret|token|password)\b", re.I)


def _table_cell(text: str, run_start: int, run_end: int) -> bool:
    """A long run of spaces that is column alignment in a Markdown or reStructuredText table."""
    line_start = text.rfind("\n", 0, run_start) + 1
    line_end = text.find("\n", run_end)
    line = text[line_start:line_end if line_end >= 0 else len(text)]
    if text[run_end:run_end + 1] in "|+" or line.lstrip().startswith(("|", "+")):
        return True
    borders = list(_RST_BORDER.finditer(text, max(0, line_start - 20_000), line_start))
    if not borders:
        return False
    border = borders[-1]
    starts = {m.start() - border.start() for m in re.finditer(r"=+", border.group())}
    return (run_end - line_start) in starts


def padding(text: str, doc: bool = False) -> list[dict]:
    """Runs of blank lines or spaces that push content out of sight (and past scanners that truncate).

    Column alignment in tables is not padding. In documentation, the text pushed off-screen must also look like a
    command or an instruction; wide prose tables push ordinary words."""
    found = []
    for m in BLANK_RUN.finditer(text) if text.count("\n") >= 400 else ():
        after = NON_SPACE.search(text, m.end())
        if after:
            found.append({"kind": "blank-lines", "pos": after.start(), "count": m.group().count("\n")})
    for m in SPACE_RUN.finditer(text) if (" " * 180 in text or "\t" in text) else ():
        if _table_cell(text, m.start(), m.end()):
            continue
        if doc:
            end = text.find("\n", m.end())
            if not _PUSHED_DOC.search(text[m.end():end if end >= 0 else len(text)][:400]):
                continue
        found.append({"kind": "spaces", "pos": m.end(), "count": len(m.group())})
    return found


def in_string_literal(text: str, pos: int) -> bool:
    """True when pos is inside a quoted string on its line (single-line strings only; an approximation).
    Lines over 4,000 characters are not parsed: on minified code the answer would be a guess."""
    i = text.rfind("\n", 0, pos) + 1
    if pos - i > 4000:
        return False
    quote = ""
    while i < pos:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        i += 1
    return bool(quote)


_COMMENT_START = {
    "hash": re.compile(r"[ \t]*#(?!!)"),
    "slash": re.compile(r"[ \t]*(?://|/\*|\*(?!/))"),
    "dash": re.compile(r"[ \t]*--"),
    "rem": re.compile(r"[ \t]*(?:@?rem\b|::)", re.I),
    "semi": re.compile(r"[ \t]*;"),
}
_HASH_EXT = {".py", ".pyw", ".sh", ".bash", ".zsh", ".fish", ".ksh", ".rb", ".pl", ".pm", ".ps1", ".psm1", ".psd1", ".r",
             ".yaml", ".yml", ".toml", ".cfg", ".conf", ".mk", ".cmake", ".nim", ".ex", ".exs", ".jl", ".tcl", ".gyp",
             ".gypi", ".properties", ".dockerfile", ".coffee", ".cr", ".awk", ".sed", ".envrc", ".gitignore"}
_HASH_NAMES = {"makefile", "gnumakefile", "dockerfile", "containerfile", "gemfile", "rakefile", "vagrantfile", "podfile",
               "brewfile", "justfile", "procfile", ".envrc", ".bashrc", ".zshrc", ".profile", "build", "configure",
               "mvnw", "gradlew", "pkgbuild", "cmakelists.txt"}
_SLASH_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".java", ".kt", ".kts", ".scala", ".groovy",
              ".gradle", ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".cs", ".go", ".rs", ".swift", ".m", ".mm",
              ".dart", ".zig", ".v", ".json5", ".jsonc", ".proto", ".sol", ".fs", ".fsx", ".vue", ".svelte"}


def _comment_styles(path: str) -> tuple[str, ...]:
    name = path.rsplit("/", 1)[-1].lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name.lstrip(".") else ""
    if ext in _SLASH_EXT:
        return ("slash",)
    if ext == ".php":
        return ("slash", "hash")
    if ext in _HASH_EXT or name in _HASH_NAMES or name.startswith(("dockerfile", "containerfile")):
        return ("hash",)
    if ext in (".sql", ".lua", ".hs", ".elm", ".ada"):
        return ("dash",)
    if ext in (".bat", ".cmd"):
        return ("rem",)
    if ext in (".ini", ".reg", ".asm", ".s"):
        return ("semi", "hash")
    return ("hash", "slash")


def in_comment(text: str, pos: int, path: str) -> bool:
    """True when pos is on a full-line comment, or inside a /* */ block, in the comment syntax of the file's language.

    Only whole-line comments count: a trailing `# ...` may be inside a string, and treating it as a comment would
    let code hide behind a quote."""
    start = text.rfind("\n", 0, pos) + 1
    styles = _comment_styles(path)
    for style in styles:
        m = _COMMENT_START[style].match(text, start)
        if m and m.end() <= pos:
            return True
    if "slash" in styles:
        opened = text.rfind("/*", max(0, pos - 20_000), pos)
        return opened >= 0 and text.rfind("*/", opened, pos) < 0
    return False


def long_lines(text: str, limit: int = 5000) -> list[tuple[int, int]]:
    return [(m.start(), m.end() - m.start()) for m in re.finditer(rf"[^\n]{{{limit},}}", text)]


# --------------------------------------------------------------------------------------------- encoded blobs

B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{40,}={0,2})(?![A-Za-z0-9+/=_-])")
HEX = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){24,})(?![0-9A-Fa-f])")
X_ESC = re.compile(r"((?:\\x[0-9A-Fa-f]{2}){12,})")
U_ESC = re.compile(r"((?:\\u[0-9A-Fa-f]{4}){12,})")
CHARCODES = re.compile(r"(?:fromCharCode\s*\(|\[)\s*((?:\d{1,3}\s*,\s*){11,}\d{1,3})\s*[)\]]")


def _printable(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    for magic, fn in ((b"\x78", zlib.decompress), (b"\x1f\x8b", gzip.decompress)):
        if data.startswith(magic):
            try:
                data = fn(data)
            except (zlib.error, OSError, EOFError):
                pass
            break
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    good = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if good < 0.92 * len(text):
        return None
    if not re.search(r"[\s(){};=.:/\\'\"<>-]", text):
        return None  # a long token that decodes to another token is not code
    return text


def decode_blobs(text: str, limit: int = 400, budget: int = 4_000_000) -> list[dict]:
    """Decode base64, hex, escape sequences and char-code lists in code; return the readable results."""
    found: list[dict] = []
    spent = 0
    attempts = 0

    def add(pos: int, kind: str, decoded: str | None) -> None:
        nonlocal spent
        if decoded and spent < budget:
            found.append({"pos": pos, "kind": kind, "text": decoded[:200_000]})
            spent += len(decoded)

    for m in B64.finditer(text):
        attempts += 1
        if attempts > limit:
            break
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars=b"-_" if ("-" in blob or "_" in blob) else None)
        except (binascii.Error, ValueError):
            continue
        add(m.start(), "base64", _printable(raw))
    for m in HEX.finditer(text):
        attempts += 1
        if attempts > limit * 2:
            break
        try:
            add(m.start(), "hex", _printable(bytes.fromhex(m.group(1))))
        except ValueError:
            continue
    for m in X_ESC.finditer(text):
        add(m.start(), "\\x escapes", _printable(bytes.fromhex(m.group(1).replace("\\x", ""))))
    for m in U_ESC.finditer(text):
        try:
            add(m.start(), "\\u escapes", "".join(chr(int(h, 16)) for h in re.findall(r"\\u([0-9A-Fa-f]{4})", m.group(1))))
        except ValueError:
            continue
    for m in CHARCODES.finditer(text):
        codes = [int(n) for n in re.findall(r"\d+", m.group(1))]
        if all(9 <= c <= 126 for c in codes):
            decoded = "".join(chr(c) for c in codes)
            if re.search(r"[\s(){};=.:/]", decoded):
                add(m.start(), "char codes", decoded)
    return found


# ------------------------------------------------------------------------------------------- comment stripping

_C_COMMENTS = re.compile(r"/\*.*?\*/|(?<![:\"'\\])//[^\n]*", re.S)
_HASH_COMMENTS = re.compile(r"(?m)(?<![\"'])#(?!!)[^\n]*")
_HTML_COMMENTS = re.compile(r"<!--.*?-->", re.S)


def strip_comments(text: str, suffix: str) -> str:
    """Approximate comment removal, so a reviewer reads code rather than the author's claims about it."""
    suffix = suffix.lower()
    if suffix in (".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".java", ".c", ".cc", ".cpp", ".h", ".go", ".rs",
                  ".cs", ".kt", ".swift", ".php", ".gradle", ".kts", ".json5", ".jsonc"):
        return _C_COMMENTS.sub("", text)
    if suffix in (".py", ".sh", ".bash", ".zsh", ".rb", ".pl", ".ps1", ".toml", ".yaml", ".yml", ".cfg", ".ini",
                  ".conf", ".mk", "") or suffix.endswith("makefile"):
        return _HASH_COMMENTS.sub("", text)
    if suffix in (".md", ".mdc", ".html", ".htm", ".xml"):
        return _HTML_COMMENTS.sub("", text)
    return text
