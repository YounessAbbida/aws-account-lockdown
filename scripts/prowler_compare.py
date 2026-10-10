#!/usr/bin/env python3
"""Compare two Prowler CSV outputs (before and after remediation).

Prints Markdown tables ready to paste into docs/report-template.md:
pass rate, failed checks by severity, what was fixed, what is new, and the
critical/high findings that remain.

Usage:
    python scripts/prowler_compare.py BEFORE.csv AFTER.csv > comparison.md

Works with the CSV that `prowler aws -M csv` writes (semicolon-delimited,
upper-case headers such as STATUS, SEVERITY, CHECK_ID, RESOURCE_UID). Muted
findings are ignored. Pass rate = PASS / (PASS + FAIL).
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "informational"]


def load(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8-sig")
    first_line = text.splitlines()[0] if text else ""
    delimiter = ";" if first_line.count(";") >= first_line.count(",") else ","
    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    rows = []
    for raw in reader:
        row = {(k or "").strip().upper(): (v or "").strip() for k, v in raw.items()}
        if row.get("MUTED", "").lower() == "true":
            continue
        rows.append(row)
    if rows and not {"STATUS", "SEVERITY", "CHECK_ID"} <= rows[0].keys():
        sys.exit(f"{path}: missing STATUS, SEVERITY or CHECK_ID columns; is this a Prowler CSV?")
    return rows


def key(row: dict[str, str]) -> tuple[str, str, str]:
    return (row.get("CHECK_ID", ""), row.get("RESOURCE_UID", ""), row.get("REGION", ""))


def failures(rows: list[dict[str, str]]) -> dict[tuple[str, str, str], dict[str, str]]:
    return {key(r): r for r in rows if r.get("STATUS", "").upper() == "FAIL"}


def pass_rate(rows: list[dict[str, str]]) -> str:
    statuses = Counter(r.get("STATUS", "").upper() for r in rows)
    total = statuses["PASS"] + statuses["FAIL"]
    return "n/a" if total == 0 else f"{100 * statuses['PASS'] / total:.0f}%"


def by_severity(fails: dict) -> Counter:
    return Counter(r.get("SEVERITY", "").lower() for r in fails.values())


def finding_table(fails: dict, limit: int = 50) -> str:
    if not fails:
        return "_None._\n"
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows = sorted(fails.values(), key=lambda r: (order.get(r.get("SEVERITY", "").lower(), 99), r.get("CHECK_ID", "")))
    lines = ["| Severity | Check | Resource | Region |", "|---|---|---|---|"]
    for r in rows[:limit]:
        lines.append(f"| {r.get('SEVERITY', '')} | `{r.get('CHECK_ID', '')}` | {r.get('RESOURCE_UID', '')} | {r.get('REGION', '')} |")
    if len(rows) > limit:
        lines.append(f"| | _{len(rows) - limit} more_ | | |")
    return "\n".join(lines) + "\n"


def compare(before: list[dict[str, str]], after: list[dict[str, str]]) -> str:
    fb, fa = failures(before), failures(after)
    sb, sa = by_severity(fb), by_severity(fa)
    fixed = {k: v for k, v in fb.items() if k not in fa}
    new = {k: v for k, v in fa.items() if k not in fb}
    remaining = {k: v for k, v in fa.items() if v.get("SEVERITY", "").lower() in ("critical", "high")}

    out = ["## Summary\n", "| | Before | After |", "|---|---|---|"]
    out.append(f"| Pass rate | {pass_rate(before)} | {pass_rate(after)} |")
    out.append(f"| Failed checks | {len(fb)} | {len(fa)} |")
    for s in SEVERITIES:
        out.append(f"| {s.capitalize()} | {sb[s]} | {sa[s]} |")
    out.append("")
    out.append(f"## Fixed ({len(fixed)})\n")
    out.append(finding_table(fixed))
    out.append(f"## New since baseline ({len(new)})\n")
    out.append(finding_table(new))
    out.append(f"## Remaining critical and high ({len(remaining)})\n")
    out.append(finding_table(remaining))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    print(compare(load(args.before), load(args.after)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
