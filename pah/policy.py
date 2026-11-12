"""Where a file sits changes what a finding in it means.

Content rules look at one file at a time. This pass looks at where each finding is and adjusts its severity:

  inert data      test fixtures, snapshots and members of archives committed to the repository are data. Nothing
                  runs them unless an entry point refers to them, and then they are marked as autoexec and left alone.
  CI pipelines    workflows run on the CI provider's machines, not on yours. They matter to maintainers (pah still
                  lists them), but they do not change whether cloning, opening or installing is safe for you.
  container build Dockerfile steps run inside the image being built, not on your machine.
  vendored tools  .yarn/releases and similar bundles are whole package managers. File-wide co-occurrence signals
                  (environment plus network somewhere in 3 MB) say nothing there; line-level indicators still count.
  plain config    structured files no handler recognised are not executed; content rules there are capped at low.

Rules about the files themselves (disguised binaries, bytecode without source, links, archive tricks) are never
adjusted: the xz-utils backdoor lived in test fixtures.
"""
from __future__ import annotations

import re

from .model import Finding, rank

FIXTURE = re.compile(
    r"(?:^|/)(?:fixtures?|__fixtures__|test[-_]?fixtures|testdata|test[-_]data|__snapshots__|snapshots?|testcases|"
    r"test[-_]cases|cassettes|goldens?|corpus|corpora|__mocks__)/", re.I)
TEST_CODE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|testing|e2e|evals?)/|(?:^|/)[^/]+[._-](?:tests?|specs?|evals?)\.[a-z]+$"
    r"|(?:^|/)test_[^/]+\.py$"
    r"|(?:^|/)[^/]+_test\.(?:go|py|rs|rb)$", re.I)
CI = re.compile(
    r"(?:^|/)\.github/(?:workflows|actions)/|(?:^|/)\.gitlab-ci\.ya?ml$|(?:^|/)\.gitlab/ci/|(?:^|/)\.circleci/"
    r"|(?:^|/)azure-pipelines[^/]*\.ya?ml$|(?:^|/)\.azure-pipelines/|(?:^|/)\.travis\.ya?ml$|(?:^|/)bitbucket-pipelines\.ya?ml$"
    r"|(?:^|/)\.buildkite/|(?:^|/)\.drone\.ya?ml$|(?:^|/)appveyor\.ya?ml$|(?:^|/)cloudbuild\.ya?ml$|(?:^|/)jenkinsfile$"
    r"|(?:^|/)\.woodpecker(?:\.ya?ml|/)|(?:^|/)\.cirrus\.ya?ml$", re.I)
CONTAINER = re.compile(r"(?:^|/)(?:[^/]*\.)?(?:dockerfile|containerfile)(?:\.[^/]*)?$", re.I)
VENDORED_TOOL = re.compile(r"(?:^|/)\.yarn/(?:releases|plugins|sdks)/|(?:^|/)\.pnp\.c?js$|(?:^|/)\.pnp\.loader\.mjs$", re.I)

NEVER_ADJUSTED = {"PAH-F001", "PAH-F002", "PAH-F003", "PAH-F005"}
CI_COMPROMISE = {"PAH-I010"}
HIDDEN_TEXT = {"PAH-T001", "PAH-T002", "PAH-T003", "PAH-T005", "PAH-T008"}
FILE_WIDE = ("reads secrets or the environment and makes network requests", "sends data out while installing or opening",
             "serializes the environment", "network call in code that runs automatically",
             "suspicious code is gated on CI, date or platform", "network code gated on a date",
             "network code that runs only in CI or after a set date")


def archive_of(rel: str) -> str | None:
    return rel.split("!/", 1)[0] if "!/" in rel else None


def inert_path(rel: str) -> bool:
    """Test fixtures and archive members: data unless an entry point refers to them."""
    return "!/" in rel or bool(FIXTURE.search(rel))


def is_test_code(rel: str) -> bool:
    return bool(TEST_CODE.search(rel)) and not FIXTURE.search(rel)


def category(rel: str, autoexec: dict) -> str | None:
    # Where a pipeline or an image build runs does not change when something on this machine starts it.
    if CI.search(rel):
        return "ci"
    if CONTAINER.search(rel):
        return "container"
    if rel in autoexec:
        return None
    archive = archive_of(rel)
    if archive is not None:
        return None if archive in autoexec else "inert"
    if FIXTURE.search(rel):
        return "inert"
    return None


def _cap(severity: str, limit: str) -> str:
    return limit if rank(severity) > rank(limit) else severity


NOTES = {"inert": "test fixture or archive member: data that nothing here runs",
         "ci": "CI pipeline: runs on the CI provider's machines, not yours",
         "container": "container build step: runs inside the image, not on your machine",
         "vendored": "vendored package-manager release: whole-file signals are expected in a bundle this size",
         "config": "structured file that nothing here executes"}


VENDORED_MIN = 1_000_000  # real Yarn releases and PnP maps are megabytes; a small "release" is just a script


def adjust(findings: list[Finding], autoexec: dict, sizes: dict | None = None) -> None:
    sizes = sizes or {}
    for f in findings:
        if f.rule in NEVER_ADJUSTED:
            continue
        cat = category(f.path, autoexec)
        before = f.severity
        if cat == "inert":
            f.severity = _cap(f.severity, "low")
        elif cat == "ci":
            if f.rule in CI_COMPROMISE and not inert_path(f.path):
                continue  # a workflow that steals the repository's secrets means the repository itself is compromised
            f.severity = _cap(f.severity, "medium" if f.rule in HIDDEN_TEXT else "low")
        elif cat == "container":
            if f.rule not in HIDDEN_TEXT:
                f.severity = _cap(f.severity, "medium" if f.rule == "PAH-C007" else "low")
        elif VENDORED_TOOL.search(f.path) and sizes.get(f.path, 0) >= VENDORED_MIN and f.message.startswith(FILE_WIDE):
            cat = "vendored"
            f.severity = _cap(f.severity, "low")
        elif f.context == "config" and f.rule.startswith("PAH-C"):
            # Configuration that runs something is handled by a handler, whose findings carry the autoexec context.
            # What is left (results, data, settings of tools nothing here starts) only describes commands.
            cat = "config"
            f.severity = _cap(f.severity, "low")
        if f.severity != before:
            f.message += f" ({NOTES[cat]})"
