#!/usr/bin/env python3
"""Draw the README figure from the benchmark results (light and dark SVG). Standard library only.

    python scripts/make_figures.py [bench/results/2026-11-11-models.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "figures"

THEMES = {
    "light": {"surface": "#fcfcfb", "border": "rgba(11,11,11,0.10)", "primary": "#0b0b0b", "secondary": "#52514e",
              "muted": "#898781", "grid": "#e1e0d9"},
    "dark": {"surface": "#1a1a19", "border": "rgba(255,255,255,0.10)", "primary": "#f0efec", "secondary": "#c3c2b7",
             "muted": "#898781", "grid": "#2c2c2a"},
}
# Outcome colors: the fixed status palette (good / warning / critical) and a neutral for "no answer".
OUTCOMES = [("all", "Caught in every run", "#0ca30c", "#ffffff"),
            ("some", "Caught in some runs", "#fab219", "#0b0b0b"),
            ("missed", "Missed in every run", "#d03b3b", "#ffffff"),
            ("refused", "Refused in every run (no answer)", "#898781", "#ffffff")]
FONT = 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'


def outcomes(results: dict) -> list[dict]:
    mal = [r for r in results["rows"] if r["kind"] == "malicious"]
    ben = [r for r in results["rows"] if r["kind"] == "benign"]
    rows = [{"name": "personal-anti-hack", "note": "rules only, offline",
             "all": sum(1 for r in mal if r["pah"] in ("block", "warn")), "some": 0,
             "missed": sum(1 for r in mal if r["pah"] not in ("block", "warn")), "refused": 0,
             "false": sum(1 for r in ben if r["pah"] in ("block", "warn")), "benign": len(ben), "total": len(mal)}]
    names = {"openai:gpt-6-astra": "GPT-6 Astra", "meta:muse-spark-1.3": "Muse Spark 1.3",
             "anthropic:claude-opus-5-5": "Claude Opus 5.5"}
    for spec in ("openai:gpt-6-astra", "meta:muse-spark-1.3", "anthropic:claude-opus-5-5"):
        if spec not in mal[0]["models"]:
            continue
        row = {"name": names[spec], "note": "the model alone", "all": 0, "some": 0, "missed": 0,
               "refused": 0, "total": len(mal), "benign": len(ben)}
        for r in mal:
            ts = r["models"][spec]
            k = sum(t["verdict"] == "unsafe" for t in ts)
            key = "all" if k == len(ts) else "some" if k else ("missed" if any(t["verdict"] == "safe" for t in ts)
                                                               else "refused")
            row[key] += 1
        row["false"] = sum(1 for r in ben if any(t["verdict"] == "unsafe" for t in r["models"][spec]))
        rows.append(row)
    return rows


def svg(rows: list[dict], theme: str, trials: int) -> str:
    t = THEMES[theme]
    width, left, bar_w = 920, 214, 470
    top, row_h, bar_h = 158, 58, 28
    height = top + row_h * len(rows) + 64
    total = rows[0]["total"]
    unit = bar_w / total
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
             f'role="img" aria-labelledby="t d" font-family=\'{FONT}\'>']
    summary = "; ".join(f"{r['name']}: caught {r['all']} of {total} in every run, {r['some']} in some runs, missed {r['missed']}, "
                        f"refused {r['refused']}; flagged {r['false']} of {r['benign']} benign" for r in rows)
    parts.append(f'<title id="t">Malicious repositories caught, out of {total}</title><desc id="d">{escape(summary)}</desc>')
    parts.append(f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="12" fill="{t["surface"]}" '
                 f'stroke="{t["border"]}"/>')
    parts.append(f'<text x="28" y="40" font-size="19" font-weight="600" fill="{t["primary"]}">Malicious repositories caught, '
                 f'out of {total}</text>')
    parts.append(f'<text x="28" y="64" font-size="13" fill="{t["secondary"]}">TrapRepo: {total} malicious and '
                 f'{rows[0]["benign"]} benign repositories built from real 2025-26 techniques, with inert payloads.</text>')
    parts.append(f'<text x="28" y="83" font-size="13" fill="{t["secondary"]}">Each model read the repository (up to 100,000 '
                 f'characters) and answered "safe" or "unsafe", {trials} runs per case.</text>')
    x = 28
    for _key, label, color, _ in OUTCOMES:
        parts.append(f'<rect x="{x}" y="108" width="12" height="12" rx="3" fill="{color}"/>')
        parts.append(f'<text x="{x + 18}" y="118.5" font-size="12.5" fill="{t["secondary"]}">{escape(label)}</text>')
        x += 18 + len(label) * 6.9 + 26
    parts.append(f'<text x="{left + bar_w + 24}" y="{top - 14}" font-size="12" fill="{t["muted"]}">Benign repositories flagged</text>')
    for i, row in enumerate(rows):
        y = top + i * row_h
        weight = "600" if i == 0 else "500"
        parts.append(f'<text x="28" y="{y + 13}" font-size="14.5" font-weight="{weight}" fill="{t["primary"]}">{escape(row["name"])}</text>')
        parts.append(f'<text x="28" y="{y + 31}" font-size="11.5" fill="{t["muted"]}">{escape(row["note"])}</text>')
        bx = left
        for key, label, color, ink in OUTCOMES:
            n = row[key]
            if not n:
                continue
            w = n * unit
            gap = 2 if bx + w < left + bar_w - 0.5 else 0
            parts.append(f'<rect x="{bx:.1f}" y="{y}" width="{max(w - gap, 1):.1f}" height="{bar_h}" rx="4" fill="{color}">'
                         f'<title>{escape(row["name"])}: {escape(label.lower())}, {n} of {total}</title></rect>')
            if w >= 24:
                parts.append(f'<text x="{bx + 8:.1f}" y="{y + 18.5}" font-size="12.5" font-weight="600" fill="{ink}">{n}</text>')
            bx += w
        caught = row["all"] + row["some"]
        parts.append(f'<text x="{left + bar_w + 24}" y="{y + 18.5}" font-size="14" font-weight="600" fill="{t["primary"]}">'
                     f'{row["false"]} of {row["benign"]}</text>')
        parts.append(f'<text x="{left + bar_w + 92}" y="{y + 18.5}" font-size="12" fill="{t["muted"]}">'
                     f'{"(every run)" if i == 0 else "(any run)"}</text>')
        parts.append(f'<desc>{escape(row["name"])}: {caught} of {total} caught at least once</desc>')
    foot = top + row_h * len(rows) + 14
    parts.append(f'<line x1="28" y1="{foot}" x2="{width - 28}" y2="{foot}" stroke="{t["grid"]}" stroke-width="1"/>')
    parts.append(f'<text x="28" y="{foot + 24}" font-size="12" fill="{t["secondary"]}">A refused review is not a clean result: '
                 'personal-anti-hack reports it as "not reviewed". Every case, run and answer is in bench/results/.</text>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main(argv: list[str]) -> int:
    path = Path(argv[0]) if argv else ROOT / "bench" / "results" / "2026-11-11-models.json"
    results = json.loads(path.read_text(encoding="utf-8"))
    rules = ROOT / "bench" / "results" / "2026-11-11-rules.json"
    rows = outcomes(results)
    if rules.exists():  # the scanner's row comes from the final rules run, the models' rows from the model run
        final = json.loads(rules.read_text(encoding="utf-8"))
        rows[0] = outcomes(final)[0]
    OUT.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        (OUT / f"results-{theme}.svg").write_text(svg(rows, theme, results.get("trials", 3)), encoding="utf-8")
    for r in rows:
        print(r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
