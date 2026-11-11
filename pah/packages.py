"""Package-manager and build surfaces: npm, Python, Rust and build tools.

These are the places where `npm install`, `pip install`, `pytest`, `cargo build`, `make` or opening a project in an
IDE runs code from the repository before anyone reads it.
"""
from __future__ import annotations

import posixpath
import re

from .model import rule
from .names import R_LOOKALIKE, lookalike, lookalike_severity, requirement_names
from .patterns import OFFICIAL_REGISTRIES, USER_CONTENT_HOSTS, analyze_command, classify_host, host_of
from .surfaces import File, State, line_of, load_jsonc, load_toml

R_LIFECYCLE = rule(
    "PAH-P001", "Install-time script",
    "npm runs preinstall/install/postinstall/prepare scripts on `npm install`; most npm malware (dependency confusion "
    "beacons, Shai-Hulud) runs from here. A repository's own scripts still run under npm 12.",
    "Read the script and the files it runs, or install with --ignore-scripts.", attack=("T1059", "T1195.002"),
    refs=("https://docs.npmjs.com/cli/v12/using-npm/scripts",))
R_URL_DEP = rule(
    "PAH-P002", "Dependency fetched from a URL or git",
    "Dependencies from a URL or git bypass the registry, so no scanner saw them; PhantomRaven's 126 packages showed "
    "'0 dependencies' and pulled payloads from HTTP URLs at install.",
    "Depend on a published, pinned version.", attack=("T1195.001",),
    refs=("https://www.koi.ai/blog/phantomraven-npm-malware-hidden-in-invisible-dependencies",))
R_LOCK_OFF_REGISTRY = rule(
    "PAH-P003", "Lockfile installs from outside the registry",
    "npm installs locked dependencies from their recorded `resolved` URL, so a lockfile that points elsewhere swaps "
    "the code behind familiar names.", "Regenerate the lockfile from the official registry.", attack=("T1195.001",))
R_REGISTRY_CFG = rule(
    "PAH-P004", "Project config changes where packages come from",
    "Registry and index settings committed to a repository (.npmrc, .yarnrc.yml, pip.conf, requirements, pyproject, "
    ".cargo/config) redirect every install made in it; agents almost never notice (Bagmar & Saraf, 2026).",
    "Remove the setting unless it points at a registry you control.", attack=("T1195.001",), owasp=("LLM03",),
    refs=("https://arxiv.org/abs/2607.15143",))
R_GYP = rule(
    "PAH-P005", "node-gyp runs a command while building",
    "binding.gyp `<!(...)` expansions run shell commands during `npm install`, with no install script to see; "
    "Phantom Gyp spread through 57 packages this way.", "Read the expanded commands.", attack=("T1059",),
    refs=("https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp",))
R_PM_RUNS_REPO = rule(
    "PAH-P006", "Package manager runs a file from the repository",
    "yarnPath, .pnpmfile.cjs, bunfig preload and .npmrc script-shell/node-options make every install or script in the "
    "repository execute repository code first.", "Read the file it points at.", attack=("T1574",))
R_PTH = rule(
    "PAH-P008", "Python code that runs at interpreter start",
    "Lines starting with `import` in a .pth file, and sitecustomize/usercustomize modules, run whenever Python starts "
    "once installed (the LiteLLM compromise).", "Remove them unless you know why they exist.", attack=("T1546",),
    refs=("https://futuresearch.ai/blog/litellm-pypi-supply-chain-attack/",))
R_PY_BUILD = rule(
    "PAH-P010", "Custom Python build backend in the repository",
    "An in-tree build backend runs repository code on `pip install` and even `pip download`.",
    "Read the backend module.", attack=("T1059",))
R_CARGO = rule(
    "PAH-P011", "Cargo runs repository code",
    "build.rs and proc macros run on `cargo build` and when rust-analyzer opens the project; .cargo/config can swap the "
    "compiler, linker or runner for a repository script.", "Read build.rs and .cargo/config before building or opening.",
    attack=("T1059", "T1574"), refs=("https://rust-analyzer.github.io/book/security.html",))
R_MAKE_SHELL = rule(
    "PAH-P012", "Makefile runs a command when it is read",
    "$(shell ...) outside recipes runs as soon as make reads the Makefile, before any target.",
    "Read the command.", attack=("T1059",))
R_WRAPPER = rule(
    "PAH-P013", "Build wrapper downloads from an unofficial host",
    "gradlew/mvnw download and run the build tool from distributionUrl; pointing it elsewhere runs any code.",
    "Use the official distribution URL and verify the checksum.", attack=("T1195.002",))

LIFECYCLE = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepublish")
KNOWN_SCRIPTS = re.compile(
    r"^\s*(?:node-gyp(?:-build)?(?:\s+rebuild)?|prebuild-install(?:\s*\|\|\s*node-gyp\s+rebuild)?(?:\s+[-\w=]+)*|husky(?:\s+install)?"
    r"|is-ci\s*\|\|\s*husky(?:\s+install)?|patch-package|tsc(?:\s+[-\w./=]+)*|ngcc|opencollective-postinstall|lerna\s+bootstrap"
    r"|electron-builder\s+install-app-deps|npm\s+run\s+[\w:.-]+|pnpm\s+(?:run\s+)?[\w:.-]+|yarn\s+(?:run\s+)?[\w:.-]+"
    r"|playwright\s+install(?:\s+[-\w]+)*|cypress\s+install|simple-git-hooks|lefthook\s+install|svelte-kit\s+sync|nuxi?\s+prepare"
    r"|node\s+-e\s+\"try\{require\('./postinstall'\)\}catch\(e\)\{\}\"|echo\s+[^|;&]*)\s*$", re.I)
TRIGGER_NPM = "npm install / pnpm install / yarn in this folder"


def _dep_spec_risk(spec: str) -> tuple[str, str] | None:
    spec = spec.strip()
    if spec.startswith("http://"):
        return "high", "plain-HTTP URL"
    if re.match(r"https?://", spec):
        trusted = classify_host(spec) == "official" or host_of(spec) in USER_CONTENT_HOSTS
        return ("medium" if trusted else "high"), "tarball URL"
    if spec.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or re.fullmatch(r"[\w.-]+/[\w.-]+(?:#\S+)?", spec):
        if re.search(r"#[0-9a-f]{40}$", spec):
            return "low", "git repository pinned to a commit"  # a full commit hash cannot be swapped out later
        return "medium", "git repository"
    return None


def package_json(state: State, f: File) -> None:
    data = load_jsonc(f.text or "")
    if not isinstance(data, dict):
        return
    text = f.text or ""
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    in_node_modules = "node_modules/" in f.rel
    for name in LIFECYCLE:
        cmd = scripts.get(name)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        line = line_of(text, f'"{name}"')
        known = bool(KNOWN_SCRIPTS.match(cmd))
        state.command(cmd, f.rel, line, f"npm {name} script", TRIGGER_NPM, base_dir=f.dir,
                      floor=None if known else (R_LIFECYCLE, "low"))
        for alias in re.findall(r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?([\w:.-]+)", cmd):
            if alias in scripts and alias not in LIFECYCLE and isinstance(scripts[alias], str):
                state.command(scripts[alias], f.rel, line_of(text, f'"{alias}"'), f"npm script '{alias}' (via {name})",
                              TRIGGER_NPM, base_dir=f.dir)
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for dep, spec in deps.items():
            if not isinstance(spec, str):
                continue
            line = line_of(text, f'"{dep}"')
            risk = _dep_spec_risk(spec)
            if risk and not in_node_modules:
                state.add(R_URL_DEP, risk[0], f.rel, line, f"{dep} comes from a {risk[1]}: {spec}", f'"{dep}": "{spec}"')
            target = spec[4:].rsplit("@", 1)[0] if spec.startswith("npm:") else dep
            if not in_node_modules and not risk and not spec.startswith(("file:", "link:", "workspace:")):
                state.packages.append(("npm", target, f.rel, line, "config"))
            hit = lookalike(target, "npm") if not in_node_modules else None
            if hit:
                state.add(R_LOOKALIKE, lookalike_severity(hit[1], "manifest"), f.rel, line,
                          f"{target} {hit[1]} from {hit[0]}", f'"{dep}": "{spec}"')
    if data.get("gypfile") or "binding.gyp" in (posixpath.basename(r) for r in state.files if posixpath.dirname(r) == f.dir):
        state.surface("node-gyp build", f.rel, TRIGGER_NPM)
    hooks = data.get("simple-git-hooks")
    if isinstance(hooks, dict) and not in_node_modules:
        for name, cmd in hooks.items():
            if isinstance(cmd, str):
                state.command(cmd, f.rel, line_of(text, f'"{name}"'), f"simple-git-hooks {name}",
                              "git commit / push after npm install", base_dir=f.dir)
    if not in_node_modules and any("husky" in str(scripts.get(s, "")) for s in ("prepare", "postinstall")):
        husky_dir = posixpath.join(f.dir, ".husky") if f.dir else ".husky"
        for rel in state.files:
            if rel.startswith(husky_dir + "/") and "/_/" not in rel[len(husky_dir):]:
                state.mark_autoexec(rel, "git hook installed by husky (runs on commit)")
                if rel.count("/") == husky_dir.count("/") + 1:
                    state.surface("husky git hook", rel, "git commit / push after npm install")


ALLOWED_GYP = re.compile(r"<!@?\(\s*node\s+-[pe]\s+\\?[\"']require\(\\?['\"][\w@/.-]+\\?['\"]\)(?:\.\w+)*\\?[\"']\s*\)"
                         r"|<!@?\(\s*pkg-config\s+[-\w\s.]+\)|<!@?\(\s*node\s+-[pe]\s+\\?[\"']process\.\w+(?:\.\w+)*\\?[\"']\s*\)")


NODE_REQUIRE = re.compile(r"<!@?\(\s*node\s+-[pe]\s+\\?[\"']require\(\\?['\"]([\w@/.-]+)\\?['\"]\)"
                          r"(?:\.\w+|\(\)|\[\\?['\"][^'\"\]]{1,120}\\?['\"]\])*\\?[\"']\s*\)")


def binding_gyp(state: State, f: File) -> None:
    text = f.text or ""
    state.surface("node-gyp configuration", f.rel, TRIGGER_NPM)
    for m in re.finditer(r"<!@?\((.{1,600}?)\)(?=[\"'\],\s])", text, re.S):
        if ALLOWED_GYP.match(m.group(0)):
            continue
        line = text.count("\n", 0, m.start()) + 1
        local = NODE_REQUIRE.match(text, m.start())  # from the expansion's start: the lazy match above may stop at ()
        if local:
            # `node -p "require('../dist/helper.cjs').fn()"`: the package's own module runs at install time, so that
            # module is judged as install-time code instead of flagging the expansion itself.
            module = local.group(1)
            if module.startswith("."):
                target = posixpath.normpath(posixpath.join(f.dir, module))
                for cand in (target, target + ".js", target + ".cjs", target + "/index.js"):
                    state.mark_autoexec(cand, f"required by a node-gyp expansion in {f.rel}", source=f.rel)
            state.surface("node-gyp command expansion", f.rel, TRIGGER_NPM, m.group(1), line)
            state.add(R_GYP, "low", f.rel, line, f"node-gyp runs {module} while configuring the build", m.group(1))
            continue
        # What the expansion runs is judged as install-time code (download-and-run, network, secrets, the scripts it
        # starts); the expansion itself is how native addons configure their builds (pkg-config, readelf, node -p).
        state.command(m.group(1), f.rel, line, "node-gyp command expansion", TRIGGER_NPM, base_dir=f.dir,
                      floor=(R_GYP, "low"))
    for m in re.finditer(r"['\"]action['\"]\s*:\s*\[([^\]]{1,600})\]", text):
        cmd = " ".join(re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)))
        state.command(cmd, f.rel, text.count("\n", 0, m.start()) + 1, "node-gyp action", TRIGGER_NPM, base_dir=f.dir,
                      floor=(R_GYP, "low"))


def lockfile(state: State, f: File) -> None:
    text = f.text or ""
    hosts: dict[str, int] = {}
    pinned_hosts: dict[str, bool] = {}
    for m in re.finditer(r"(?:\"resolved\"\s*:\s*\"|resolved\s+\"|tarball:\s*['\"]?)([^\"'\s,}]+)", text):
        url = m.group(1)
        if url.startswith(("file:", "link:", "workspace:")):
            continue
        host = host_of(url) if "://" in url else ("git" if url.startswith("git") else "")
        if not host or host in OFFICIAL_REGISTRIES or host.endswith((".npmjs.org", ".yarnpkg.com")):
            continue
        hosts.setdefault(host, text.count("\n", 0, m.start()) + 1)
        pinned_hosts[host] = pinned_hosts.get(host, True) and bool(re.search(r"[/#][0-9a-f]{40}\b", url))
    for host, line in list(hosts.items())[:5]:
        sev = "medium" if host in ("github.com", "codeload.github.com", "git", "gitlab.com") else "high"
        if host in ("github.com", "codeload.github.com", "gitlab.com") and pinned_hosts.get(host):
            sev = "low"  # every entry from this host names an exact commit
        state.add(R_LOCK_OFF_REGISTRY, sev, f.rel, line, f"locked packages download from {host}", host)


def npmrc(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*([@\w:./-]*registry|script-shell|node-options|onload-script|git|shell|userconfig|globalconfig|"
                         r"ignore-scripts|_authToken|//[^=\s]+:_authToken)\s*=\s*(.+)$", text):
        key, value = m.group(1), m.group(2).strip().strip("\"'")
        line = text.count("\n", 0, m.start()) + 1
        if key.endswith("registry"):
            if classify_host(value) != "official":
                state.add(R_REGISTRY_CFG, "high" if not key.startswith("@") else "medium", f.rel, line,
                          f"{key} = {value}", m.group(0))
        elif key in ("script-shell", "node-options", "onload-script", "git", "shell", "userconfig", "globalconfig"):
            state.add(R_PM_RUNS_REPO, "high", f.rel, line, f"{key} = {value}", m.group(0))
            state.command(value, f.rel, line, f".npmrc {key}", TRIGGER_NPM, base_dir=f.dir)


YARN_RELEASE_MIN = 1_000_000


def yarnrc(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(yarnPath|yarn-path|npmRegistryServer|registry|plugins)\s*[:=\s]\s*[\"']?([^\"'\n]+)", text):
        key, value = m.group(1), m.group(2).strip()
        line = text.count("\n", 0, m.start()) + 1
        if key in ("yarnPath", "yarn-path"):
            target = posixpath.normpath(posixpath.join(f.dir, value))
            standard = re.match(r"\.yarn/releases/yarn-[\d.]+(?:-[\w.]+)?\.c?js$", posixpath.relpath(target, f.dir or "."))
            size = state.files[target].size if target in state.files else 0
            # A checked-in Yarn release is how Yarn 2+ projects pin the package manager. Real releases are bundles of
            # several megabytes; a small file with a release's name is a script dressed up as one.
            if standard and size >= YARN_RELEASE_MIN:
                sev, note = "low", " (the project's pinned Yarn release)"
            elif standard:
                sev, note = "high", f" ({size:,} bytes; real Yarn releases are megabytes, so this is not one)"
            else:
                sev, note = "high", ""
            state.add(R_PM_RUNS_REPO, sev, f.rel, line, f"every yarn command runs {target}{note}", m.group(0))
            state.mark_autoexec(target, "yarnPath")
        elif key in ("npmRegistryServer", "registry") and classify_host(value) != "official":
            state.add(R_REGISTRY_CFG, "high", f.rel, line, f"{key}: {value}", m.group(0))


def pnpmfile(state: State, f: File) -> None:
    state.surface("pnpm hooks file", f.rel, "pnpm install")
    state.mark_autoexec(f.rel, "pnpm runs .pnpmfile.cjs on install")
    state.add(R_PM_RUNS_REPO, "medium", f.rel, 1, ".pnpmfile.cjs runs on every pnpm install", f.rel)


def bunfig(state: State, f: File) -> None:
    text = f.text or ""
    m = re.search(r"(?m)^\s*preload\s*=\s*(.+)$", text)
    if m:
        for ref in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
            target = posixpath.normpath(posixpath.join(f.dir, ref))
            state.mark_autoexec(target, "bunfig preload")
        state.add(R_PM_RUNS_REPO, "medium", f.rel, text.count("\n", 0, m.start()) + 1, "bun preloads repository code",
                  m.group(0))


# ------------------------------------------------------------------------------------------------- python


def setup_py(state: State, f: File) -> None:
    state.surface("setup.py", f.rel, "pip install / pip download / python setup.py")
    state.mark_autoexec(f.rel, "setup.py runs on pip install")


def conftest(state: State, f: File) -> None:
    state.surface("pytest conftest", f.rel, "pytest in this folder")
    state.mark_autoexec(f.rel, "pytest imports conftest.py")


def pth(state: State, f: File) -> None:
    text = f.text or ""
    for i, line in enumerate(text.splitlines(), 1):
        if re.match(r"\s*import[\s;]", line):
            state.surface(".pth import line", f.rel, "every Python start once installed", line, i)
            found = analyze_command(line, f.rel, i, "autoexec")
            state.extend(found)
            state.add(R_PTH, "critical" if found else "high", f.rel, i, "executes code at interpreter start", line)
            break


def sitecustomize(state: State, f: File) -> None:
    state.surface(f.name, f.rel, "every Python start once on the path")
    state.mark_autoexec(f.rel, f.name)
    state.add(R_PTH, "high", f.rel, 1, f"{f.name} runs at interpreter start", f.rel)


def pyproject(state: State, f: File) -> None:
    text = f.text or ""
    data = load_toml(text) or {}
    build = data.get("build-system") or {}
    backend_path = build.get("backend-path")
    if backend_path or re.search(r"(?m)^\s*backend-path\s*=", text):
        backend = build.get("build-backend", "")
        module = backend.split(":")[0].replace(".", "/")
        for base in backend_path or ["."]:
            for cand in (f"{module}.py", f"{module}/__init__.py"):
                target = posixpath.normpath(posixpath.join(f.dir, base, cand))
                state.mark_autoexec(target, "in-tree build backend")
        state.add(R_PY_BUILD, "medium", f.rel, line_of(text, "backend-path"), f"in-tree backend {backend}", "backend-path")
    deps = list((data.get("project") or {}).get("dependencies") or []) + list(build.get("requires") or [])
    for group in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
        deps += list(group or [])
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    deps += list((poetry.get("dependencies") or {}).keys())
    for dep in deps:
        name = re.split(r"[\s\[<>=!~;@(]", str(dep).strip())[0]
        if name and name.lower() != "python":
            state.packages.append(("pypi", name, f.rel, line_of(text, name), "config"))
        hit = lookalike(name, "pypi") if name and name.lower() != "python" else None
        if hit:
            state.add(R_LOOKALIKE, lookalike_severity(hit[1], "manifest"), f.rel, line_of(text, name),
                      f"{name} {hit[1]} from {hit[0]}", str(dep))
    for m in re.finditer(r"(?m)^\s*(?:url|index-url|extra-index-url|default-index)\s*=\s*[\"']([^\"']+)[\"']", text):
        if classify_host(m.group(1)) != "official":
            state.add(R_REGISTRY_CFG, "medium", f.rel, text.count("\n", 0, m.start()) + 1, f"package index {m.group(1)}",
                      m.group(0))


def requirements(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(-i|--index-url|--extra-index-url|--trusted-host|-f|--find-links)[ =]+(\S+)", text):
        flag, value = m.group(1), m.group(2)
        line = text.count("\n", 0, m.start()) + 1
        if flag == "--trusted-host":
            state.add(R_REGISTRY_CFG, "medium", f.rel, line, f"--trusted-host {value} turns off TLS checks", m.group(0))
        elif classify_host(value) != "official":
            kind = classify_host(value)
            state.add(R_REGISTRY_CFG, "high" if flag in ("-i", "--index-url") or kind != "unknown" else "medium", f.rel, line,
                      f"{flag} {value}", m.group(0))
    for m in re.finditer(r"(?m)^\s*(?:[\w.-]+\s*@\s*)?((?:https?|git\+\w+)://\S+)", text):
        url = m.group(1).replace("git+", "", 1)
        trusted = classify_host(url) == "official" or host_of(url) in USER_CONTENT_HOSTS
        state.add(R_URL_DEP, "medium" if trusted else "high", f.rel,
                  text.count("\n", 0, m.start()) + 1, f"requirement from {m.group(1)}", m.group(0))
    for line, name in requirement_names(text):
        state.packages.append(("pypi", name, f.rel, line, "config"))
        hit = lookalike(name, "pypi")
        if hit:
            state.add(R_LOOKALIKE, lookalike_severity(hit[1], "manifest"), f.rel, line,
                      f"{name} {hit[1]} from {hit[0]}", name)


def pip_conf(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?mi)^\s*(index-url|extra-index-url|index_url|url)\s*=\s*(\S+)", text):
        if classify_host(m.group(2)) != "official":
            state.add(R_REGISTRY_CFG, "high", f.rel, text.count("\n", 0, m.start()) + 1, f"{m.group(1)} = {m.group(2)}",
                      m.group(0))


# --------------------------------------------------------------------------------------------- rust/build


def build_rs(state: State, f: File) -> None:
    state.surface("Cargo build script", f.rel, "cargo build / rust-analyzer opening the project")
    state.mark_autoexec(f.rel, "build.rs runs on cargo build and in rust-analyzer")


def cargo_toml(state: State, f: File) -> None:
    text = f.text or ""
    m = re.search(r"(?m)^\s*build\s*=\s*[\"']([^\"']+)[\"']", text)
    if m:
        state.mark_autoexec(posixpath.normpath(posixpath.join(f.dir, m.group(1))), "custom Cargo build script")
    if re.search(r"(?m)^\s*proc-macro\s*=\s*true", text):
        state.surface("Rust procedural macro", f.rel, "compiling dependents / rust-analyzer")
        lib = posixpath.join(f.dir, "src/lib.rs") if f.dir else "src/lib.rs"
        state.mark_autoexec(lib, "proc macro runs at compile time and in rust-analyzer")


def cargo_config(state: State, f: File) -> None:
    text = f.text or ""
    project = posixpath.dirname(f.dir)
    for m in re.finditer(r"(?m)^\s*(rustc-wrapper|rustc-workspace-wrapper|rustc|rustdoc|linker|runner|ar)\s*=\s*(.+)$", text):
        value = m.group(2).strip()
        line = text.count("\n", 0, m.start()) + 1
        state.command(value.strip("[]\"'").replace("\", \"", " "), f.rel, line, f"cargo {m.group(1)}",
                      "cargo build/run/test in this folder", base_dir=project,
                      floor=(R_CARGO, "high" if m.group(1) != "runner" else "medium"))
    for m in re.finditer(r"(?m)^\s*(?:registry|index|replace-with)\s*=\s*[\"']([^\"']+)[\"']", text):
        if "://" in m.group(1) and classify_host(m.group(1).replace("sparse+", "")) != "official":
            state.add(R_REGISTRY_CFG, "high", f.rel, text.count("\n", 0, m.start()) + 1, f"crate source {m.group(1)}",
                      m.group(0))


def rust_toolchain(state: State, f: File) -> None:
    text = f.text or ""
    m = re.search(r"(?m)^\s*path\s*=\s*[\"']([^\"']+)", text)
    if m:
        state.add(R_CARGO, "high", f.rel, text.count("\n", 0, m.start()) + 1, f"custom toolchain path {m.group(1)}",
                  m.group(0))


BENIGN_SHELL = re.compile(r"^\s*(?:git\s+(?:rev-parse|describe|log|config\s+--get|symbolic-ref|branch|tag|ls-files|status)|uname|date|pwd|"
                          r"whoami|id\s|hostname|nproc|getconf|sysctl\s+-n|cat\s+[\w./-]+|head\s|grep\s|sed\s|awk\s|find\s|ls\s|"
                          r"echo\s|printf\s|which\s|command\s+-v|test\s|\[\s|python[0-9.]*\s+-c\s+['\"]import\s+(?:sys|sysconfig|platform)|"
                          r"go\s+(?:env|list|version)|node\s+-p|npm\s+bin|basename|dirname|realpath|wc\s|tr\s|cut\s|sort\s|xargs\s)")


def makefile(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"\$\(shell\s+((?:[^()]|\([^()]*\))+)\)", text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        if text[line_start:line_start + 1] == "\t":
            continue  # inside a recipe: runs only when that target runs
        cmd = m.group(1).strip()
        line = text.count("\n", 0, m.start()) + 1
        if BENIGN_SHELL.match(cmd):
            state.surface("Makefile $(shell) at parse time", f.rel, "running make", cmd, line)
            continue
        state.command(cmd, f.rel, line, "Makefile $(shell) at parse time", "running make", base_dir=f.dir,
                      floor=(R_MAKE_SHELL, "low"))


def cmake(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"execute_process\s*\(\s*COMMAND\s+([^)]{1,500})\)", text, re.I):
        state.command(m.group(1), f.rel, text.count("\n", 0, m.start()) + 1, "CMake execute_process", "cmake configure",
                      base_dir=f.dir)
    for m in re.finditer(r"file\s*\(\s*DOWNLOAD\s+[\"']?(\S+?)[\"']?\s", text, re.I):
        if classify_host(m.group(1)) not in ("official",):
            state.surface("CMake download", f.rel, "cmake configure", m.group(1), text.count("\n", 0, m.start()) + 1)


def wrapper_properties(state: State, f: File) -> None:
    text = f.text or ""
    for m in re.finditer(r"(?m)^\s*(distributionUrl|wrapperUrl)\s*=\s*(\S+)", text):
        url = m.group(2).replace("\\:", ":")
        host = host_of(url)
        if host not in ("services.gradle.org", "repo.maven.apache.org", "repo1.maven.org", "downloads.gradle.org"):
            state.add(R_WRAPPER, "high", f.rel, text.count("\n", 0, m.start()) + 1, f"{m.group(1)} from {host or url}",
                      m.group(0))


R_IDE_BUILD = rule(
    "PAH-P017", "Project file runs commands when the project is built",
    "Visual Studio pre/post-build events and MSBuild Exec tasks, and Xcode Run Script build phases, run with your "
    "permissions on every build. Lazarus used a .vcxproj pre-build event against security researchers (2021); XCSSET "
    "spreads by injecting build-phase scripts into Xcode projects (new variants in 2025).",
    "Read the command before building. Build untrusted projects in a disposable VM or container.",
    attack=("T1127.001", "T1059", "T1195.002"),
    refs=("https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/",
          "https://www.microsoft.com/en-us/security/blog/2025/03/11/new-xcsset-malware-adds-new-obfuscation-persistence-techniques-to-infect-xcode-projects/"))

_MSBUILD_EVENT = re.compile(r"<(PreBuildEvent|PostBuildEvent|PreLinkEvent)>(.*?)</\1>", re.S | re.I)
_MSBUILD_EXEC = re.compile(r"<Exec\b[^>]*?\bCommand\s*=\s*(\"([^\"]*)\"|'([^']*)')", re.S | re.I)
_XML_ENTITIES = {"&quot;": '"', "&apos;": "'", "&lt;": "<", "&gt;": ">", "&#xD;&#xA;": "\n", "&#xA;": "\n", "&#13;&#10;": "\n",
                 "&#10;": "\n", "&amp;": "&"}


def _xml_unescape(value: str) -> str:
    for entity, char in _XML_ENTITIES.items():
        value = value.replace(entity, char)
    return value


def msbuild(state: State, f: File) -> None:
    """.csproj/.vcxproj/.vbproj/.fsproj, Directory.Build.props/.targets (imported by every project below them)."""
    text = f.text or ""
    trigger = "building the project (Visual Studio, Rider, dotnet build, msbuild)"
    for m in _MSBUILD_EVENT.finditer(text):
        cmd = _xml_unescape(m.group(2)).strip()
        if cmd:
            for i, part in enumerate(line for line in cmd.splitlines() if line.strip()):
                state.command(part.strip(), f.rel, text.count("\n", 0, m.start()) + 1 + i, f"MSBuild {m.group(1)}",
                              trigger, base_dir=f.dir, floor=(R_IDE_BUILD, "medium"))
    for m in _MSBUILD_EXEC.finditer(text):
        cmd = _xml_unescape(m.group(2) or m.group(3) or "").strip()
        if cmd:
            state.command(cmd, f.rel, text.count("\n", 0, m.start()) + 1, "MSBuild Exec task", trigger, base_dir=f.dir,
                          floor=(R_IDE_BUILD, "low"))


_PBX_SCRIPT = re.compile(r'shellScript\s*=\s*"((?:[^"\\]|\\.)*)"\s*;')


def xcode_project(state: State, f: File) -> None:
    text = f.text or ""
    project_dir = posixpath.dirname(posixpath.dirname(f.rel))
    for m in _PBX_SCRIPT.finditer(text):
        script = m.group(1).encode("utf-8").decode("unicode_escape", errors="replace")
        line = text.count("\n", 0, m.start()) + 1
        state.surface("Xcode Run Script build phase", f.rel, "building the project in Xcode", script[:300], line)
        for part in script.splitlines():
            if part.strip() and not part.lstrip().startswith("#"):
                state.command(part.strip(), f.rel, line, "Xcode Run Script build phase", "building the project in Xcode",
                              base_dir=project_dir)
        if re.search(r"\b(?:curl|wget|osascript|base64|eval|python3?\s+-c|nc\s|bash\s+-c)\b", script):
            state.add(R_IDE_BUILD, "medium", f.rel, line, "Run Script build phase with network, eval or AppleScript",
                      script[:200])


def gradle_build(state: State, f: File) -> None:
    state.surface("Gradle build script", f.rel, "opening the project in an IDE (Gradle sync) or running gradle")
    state.mark_autoexec(f.rel, "Gradle evaluates build scripts on project import")


def git_hook_managers(state: State, f: File) -> None:
    """pre-commit local hooks and lefthook commands run on git commit, which agents do constantly."""
    text = f.text or ""
    if f.name.lower() == ".pre-commit-config.yaml":
        for m in re.finditer(r"(?m)^\s*-?\s*repo:\s*local\b(.*?)(?=^\s*-\s*repo:|\Z)", text, re.S):
            for e in re.finditer(r"(?m)^\s*entry:\s*['\"]?([^'\"\n]+)", m.group(1)):
                state.command(e.group(1).strip(), f.rel, text.count("\n", 0, m.start() + e.start()) + 1,
                              "pre-commit local hook", "git commit after `pre-commit install`", base_dir=f.dir)
    else:
        for m in re.finditer(r"(?m)^\s*run:\s*['\"]?([^'\"\n]+)", text):
            state.command(m.group(1).strip(), f.rel, text.count("\n", 0, m.start()) + 1, "lefthook command",
                          "git commit / push after `lefthook install`", base_dir=f.dir)


def dispatch_packages(state: State, f: File) -> None:
    low, name = f.rel.lower(), f.name.lower()
    if f.text is None:
        return
    if name in (".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml"):
        git_hook_managers(state, f)
    elif name == "package.json":
        package_json(state, f)
    elif name == "binding.gyp":
        binding_gyp(state, f)
    elif name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"):
        lockfile(state, f)
    elif name == ".npmrc":
        npmrc(state, f)
    elif name in (".yarnrc.yml", ".yarnrc"):
        yarnrc(state, f)
    elif name in (".pnpmfile.cjs", ".pnpmfile.js", ".pnpmfile.mjs"):
        pnpmfile(state, f)
    elif name == "bunfig.toml":
        bunfig(state, f)
    elif name == "setup.py":
        setup_py(state, f)
    elif name == "conftest.py":
        conftest(state, f)
    elif name.endswith(".pth"):
        pth(state, f)
    elif name in ("sitecustomize.py", "usercustomize.py"):
        sitecustomize(state, f)
    elif name == "pyproject.toml":
        pyproject(state, f)
    elif re.fullmatch(r"(?:requirements|constraints)[\w.-]*\.(?:txt|in)", name) or re.search(r"(?:^|/)requirements/[^/]+\.txt$", low):
        requirements(state, f)
    elif name in ("pip.conf", "pip.ini", "uv.toml", ".pypirc") or name == "pipfile":
        pip_conf(state, f)
    elif name == "build.rs":
        build_rs(state, f)
    elif name == "cargo.toml":
        cargo_toml(state, f)
    elif re.search(r"(?:^|/)\.cargo/config(?:\.toml)?$", low):
        cargo_config(state, f)
    elif name in ("rust-toolchain", "rust-toolchain.toml"):
        rust_toolchain(state, f)
    elif name in ("makefile", "gnumakefile") or name.endswith(".mk"):
        makefile(state, f)
    elif name == "cmakelists.txt":
        cmake(state, f)
    elif name in ("gradle-wrapper.properties", "maven-wrapper.properties"):
        wrapper_properties(state, f)
    elif name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "init.gradle"):
        gradle_build(state, f)
    elif name.endswith((".csproj", ".vcxproj", ".vbproj", ".fsproj", ".proj", ".targets")) or name in (
            "directory.build.props", "directory.build.targets"):
        msbuild(state, f)
    elif name == "project.pbxproj":
        xcode_project(state, f)
