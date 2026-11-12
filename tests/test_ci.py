"""The GitHub Actions output (pah/ci.py), SARIF paths, and the scan command's --github and --sarif-out options."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "bench"))

import materialize  # noqa: E402
from pah import ci, cli, report  # noqa: E402
from pah import surfaces as _surfaces  # noqa: E402,F401  (registers the rules used below)
from pah.model import Finding, Report, Surface  # noqa: E402


def sample() -> Report:
    return Report(target="proj", findings=[
        Finding("PAH-C004", "high", "scripts/post,install.js", 6, "sends data out: 100% of it", "req.end()"),
        Finding("PAH-A001", "medium", ".claude/settings.json", 8, "Claude Code hook | SessionStart"),
        Finding("PAH-C003", "low", "lib/a.js", 3, "references a credential path"),
    ], surfaces=[Surface("npm postinstall script", "package.json", "npm install", "node scripts/post,install.js", 5)],
        stats={"files": 4, "seconds": 0.1})


class AnnotationTests(unittest.TestCase):
    def test_levels_paths_and_escaping(self):
        lines = ci.annotations(sample(), "sub/dir")
        self.assertEqual(len(lines), 2)  # low findings are not annotated
        error, warning = lines
        self.assertTrue(error.startswith("::error file=sub/dir/scripts/post%2Cinstall.js,line=6,title=PAH-C004 "))
        self.assertIn("100%25 of it", error)  # % escaped in the message
        self.assertNotIn("\n", error)
        self.assertIn("%0A", error)  # evidence and the rule's reason on their own lines
        self.assertTrue(warning.startswith("::warning file=sub/dir/.claude/settings.json,line=8,"))

    def test_no_file_when_the_target_is_not_in_the_checkout(self):
        line = ci.annotations(sample(), None)[0]
        self.assertTrue(line.startswith("::error title="))
        self.assertNotIn("file=", line)

    def test_at_most_ten_of_each_kind(self):
        rep = Report(target=".", findings=[Finding("PAH-C004", "high", f"f{i}.js", 1, "x") for i in range(25)])
        self.assertEqual(len(ci.annotations(rep, "")), ci.PER_KIND)


class OutputTests(unittest.TestCase):
    def test_outputs_summary_and_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, summary = Path(tmp, "out"), Path(tmp, "summary.md")
            env = {"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary), "PAH_ANNOTATIONS": "false"}
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                ci.github(sample(), env, prefix="")
            self.assertEqual(printed.getvalue(), "")  # annotations switched off
            self.assertIn("verdict=block\n", out.read_text(encoding="utf-8"))
            self.assertIn("high=1\n", out.read_text(encoding="utf-8"))
            text = summary.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("### personal-anti-hack: BLOCK"))
            self.assertIn("Claude Code hook &#124; SessionStart", text)  # a pipe cannot break the table
            self.assertIn("1 low or informational finding is in the SARIF report", text)

    def test_workspace_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp, "a", "b")
            sub.mkdir(parents=True)
            self.assertEqual(ci.workspace_prefix(str(sub), tmp), "a/b")
            self.assertEqual(ci.workspace_prefix(tmp, tmp), "")
            with tempfile.TemporaryDirectory() as other:
                self.assertIsNone(ci.workspace_prefix(other, tmp))
            self.assertIsNone(ci.workspace_prefix("https://github.com/o/r", tmp))

    def test_sarif_base(self):
        doc = json.loads(report.sarif(sample(), base="sub/dir"))
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in doc["runs"][0]["results"]]
        self.assertTrue(all(u.startswith("sub/dir/") for u in uris), uris)
        plain = json.loads(report.sarif(sample()))
        self.assertEqual(plain["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "scripts/post,install.js")


class CommandTests(unittest.TestCase):
    def test_scan_with_github_and_sarif_out(self):
        case = json.loads((ROOT / "bench" / "fixtures" / "traprepo" / "npm-postinstall-beacon.json")
                          .read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            repo = materialize.materialize(case, Path(tmp, "trap"))
            out, summary, sarif = Path(tmp, "out"), Path(tmp, "summary.md"), Path(tmp, "r.sarif")
            env = {"GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary), "GITHUB_WORKSPACE": tmp}
            printed = io.StringIO()
            with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(printed):
                code = cli.main(["scan", str(repo), "--github", "--sarif-out", str(sarif), "--fail-on", "block"])
            self.assertEqual(code, 2)
            self.assertIn("::error file=trap/", printed.getvalue())
            self.assertIn("verdict=block", out.read_text(encoding="utf-8"))
            results = json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
            self.assertTrue(results)
            self.assertTrue(all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("trap/")
                                for r in results))


if __name__ == "__main__":
    unittest.main()
