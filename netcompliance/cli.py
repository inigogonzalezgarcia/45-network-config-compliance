"""Command line: `demo` writes the fictional Tailspin Logistics backups and exports to sample_data/ and builds the outputs; `review` runs on
your own backups and exports."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import report, simulate
from .checks import CRITICAL, WARNING, overall, pct, review, run_all, summary
from .model import load, parse_dt

OUTPUTS = ("report.html", "compliance-pack.md", "device-status.csv", "rule-results.csv", "backups.csv", "lifecycle.csv", "actions.csv",
           "findings.csv")


def run(data: Path, out: Path, title: str | None = None, as_of: datetime | None = None) -> dict:
    d = load(data, as_of)
    rv = review(d)
    findings = run_all(d, rv)
    title = title or f"{d.settings.organisation} · network configuration compliance, {d.today:%d %B %Y}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(d, rv, findings, title), encoding="utf-8")
    (out / "compliance-pack.md").write_text(report.pack_md(d, rv, findings, title), encoding="utf-8")
    report.write_devices(d, rv, out / "device-status.csv")
    report.write_rules(d, rv, out / "rule-results.csv")
    report.write_backups(d, rv, out / "backups.csv")
    report.write_lifecycle(d, rv, out / "lifecycle.csv")
    report.write_actions(findings, out / "actions.csv")
    report.write_findings(findings, out / "findings.csv")
    sm = summary(d, rv)
    sm.update(overall=overall(rv), critical=sum(f.severity == CRITICAL for f in findings), warning=sum(f.severity == WARNING for f in findings),
              site_status=[(r["name"], r["status"]) for r in rv["sites"]])
    return sm


def _when(value: str) -> datetime:
    d = parse_dt(value)
    if not d:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM'): {value}")
    return d


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netcompliance", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    dm = sub.add_parser("demo", help="write the fictional backups and exports to sample_data/ and build the outputs")
    dm.add_argument("--data", type=Path, default=Path("sample_data"))
    dm.add_argument("--out", type=Path, default=Path("output"))
    rv = sub.add_parser("review", help="build the outputs from your own backups and exports")
    rv.add_argument("data", type=Path, nargs="?", help="folder with inventory.csv, baseline.json and configs/")
    rv.add_argument("--data", dest="data_opt", type=Path, help="same as the positional folder")
    rv.add_argument("--out", type=Path, default=Path("output"))
    rv.add_argument("--title", help="title of the report and the pack")
    rv.add_argument("--as-of", type=_when, help="reference date (default: settings.json, or now)")
    a = p.parse_args(argv)
    if a.cmd == "demo":
        simulate.write(a.data)
        sm = run(a.data, a.out, f"{simulate.ORG} · weekly network configuration compliance (review of 6 November 2026)")
    else:
        folder = a.data or a.data_opt
        if not folder:
            print("error: give the folder with inventory.csv, baseline.json and configs/", file=sys.stderr)
            return 2
        try:
            sm = run(folder, a.out, a.title, a.as_of)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    sites = ", ".join(f"{n} {s.upper()}" for n, s in sm["site_status"])
    print(f"{sm['overall'].upper()} · {sites} · {sm['devices']} devices: {sm['compliant']} compliant, {sm['drift']} drift, "
          f"{sm['noncompliant']} non-compliant · {pct(sm['pass_rate'])} of {sm['checks']} rule checks pass · {sm['missing']} backups missing, "
          f"{sm['stale']} old · {sm['unsaved']} unsaved · {sm['critical']} critical, {sm['warning']} warnings")
    print(f"outputs in {a.out}/: {', '.join(OUTPUTS)}")
    return 0
