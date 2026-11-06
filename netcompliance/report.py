"""Outputs: report.html (verdict, tiles, the sites, status by area, fix first, the devices with their status per area, backups, lifecycle
and all findings), compliance-pack.md (the pack for the change board, with a proposed change window and a decision column per finding),
and the CSVs: device-status, rule-results (device x rule), backups, lifecycle, actions and findings."""
from __future__ import annotations

import csv
import html
from pathlib import Path

from .checks import (AREAS, COMPLIANT, CRITICAL, DRIFT, FAIL, INFO, NA, NONCOMPLIANT, PASS, RULES, WARNING, Finding, _n, area_status,
                     overall, pct, summary, window_for)
from .model import FILES, Data
from .parsers import PLATFORM_LABEL

e = html.escape
TODO = "**[TO COMPLETE]**"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, "": 3}


# ---------------------------------------------------------------- csv

def _w(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _dt(x) -> str:
    return x.strftime("%Y-%m-%d %H:%M") if x else ""


def _worst(results) -> str:
    sev = {r.severity for r in results if r.status == FAIL}
    return CRITICAL if CRITICAL in sev else WARNING if WARNING in sev else INFO if sev else ""


def _res(x: dict, code: str):
    return next(r for r in x["results"] if r.code == code)


def write_findings(findings: list[Finding], path: Path) -> None:
    _w(path, ["severity", "area", "code", "subject", "detail", "next_step", "owner", "sites", "change_window", "devices"],
       [[f.severity, f.area, f.code, f.subject, f.detail, f.fix, f.owner, "; ".join(f.sites), f.window, "; ".join(f.devices)] for f in findings])


def write_actions(findings: list[Finding], path: Path) -> None:
    _w(path, ["ref", "action", "next_step", "owner", "severity", "sites", "devices", "change_window", "change_ticket", "decision", "done"],
       [[f.code, f.subject, f.fix, f.owner, f.severity, "; ".join(f.sites), "; ".join(f.devices), f.window, "", "", ""]
        for f in findings if f.severity != INFO])


def write_devices(d: Data, rv: dict, path: Path) -> None:
    rows = []
    for x in rv["devices"]:
        dev, inv = x["device"], x["device"].inv
        worst = _worst(x["results"])
        rows.append([dev.hostname, dev.site, d.settings.site_name(dev.site) if dev.site else "", inv.room if inv else "", inv.rack if inv else "",
                     inv.role if inv else "", inv.vendor if inv else "", (inv.model if inv else "") or (dev.config.model if dev.config else ""),
                     PLATFORM_LABEL[dev.platform], inv.mgmt_ip if inv else "", x["status"], x["critical"], x["warning"], "; ".join(x["codes"]),
                     window_for(worst, d) if worst in (CRITICAL, WARNING) else ""])
    _w(path, ["hostname", "site", "site_name", "room", "rack", "role", "vendor", "model", "platform", "mgmt_ip", "status", "critical",
              "warnings", "codes", "change_window"], rows)


def write_rules(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["hostname", "site", "code", "area", "rule", "result", "severity", "detail"],
       [[x["device"].hostname, x["device"].site, r.code, r.area, RULES[r.code][0], r.status, r.severity, r.detail]
        for x in rv["devices"] for r in x["results"]])


def backup_rows(d: Data, rv: dict) -> list[dict]:
    out = []
    for x in rv["devices"]:
        dev, c, inv = x["device"], x["device"].config, x["device"].inv
        tickets = []
        if c and c.last_change:
            tickets = [ch.ticket for ch in d.changes if ch.hostname.lower() == dev.hostname.lower() and ch.approved and ch.covers(c.last_change)]
        res = [_res(x, k) for k in ("BKP-01", "BKP-02", "BKP-03", "BKP-04")]
        age = (d.as_of - inv.last_backup).total_seconds() / 86400 if inv and inv.last_backup and c else None
        out.append({"dev": dev, "c": c, "inv": inv, "age": age, "tickets": tickets, "res": res, "worst": _worst(res),
                    "unsaved": bool(c and c.last_change and (not c.last_saved or c.last_saved < c.last_change))})
    return out


def write_backups(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["hostname", "site", "platform", "config_file", "last_backup", "backup_age_days", "last_change", "last_change_by", "last_saved",
              "unsaved_changes", "change_ticket", "severity", "codes", "detail"],
       [[b["dev"].hostname, b["dev"].site, PLATFORM_LABEL[b["dev"].platform], b["dev"].path, _dt(b["inv"].last_backup) if b["inv"] else "",
         "" if b["age"] is None else f"{b['age']:.1f}", _dt(b["c"].last_change) if b["c"] else "", b["c"].last_change_by if b["c"] else "",
         _dt(b["c"].last_saved) if b["c"] else "", "yes" if b["unsaved"] else "no", "; ".join(b["tickets"]), b["worst"],
         "; ".join(r.code for r in b["res"] if r.status == FAIL), "; ".join(r.detail for r in b["res"] if r.status == FAIL)]
        for b in backup_rows(d, rv)])


def lifecycle_rows(d: Data, rv: dict) -> list[dict]:
    out = []
    b = d.baseline
    for x in rv["devices"]:
        dev, inv, c = x["device"], x["device"].inv, x["device"].config
        model = (inv.model if inv else "") or (c.model if c else "")
        fam = b.family(model)
        eos = inv.end_of_support if inv else None
        out.append({"dev": dev, "model": model, "family": fam, "version": (inv.os_version if inv else "") or (c.version if c else ""),
                    "approved": [str(v) for v in b.approved_versions.get(fam, [])], "eos": eos,
                    "days": (eos - d.today).days if eos else None, "v": _res(x, "LCM-01"), "e": _res(x, "LCM-02")})
    return out


def write_lifecycle(d: Data, rv: dict, path: Path) -> None:
    _w(path, ["hostname", "site", "model", "family", "os_version", "approved_versions", "version_result", "end_of_support", "days_to_eos",
              "support_result", "severity", "detail"],
       [[r["dev"].hostname, r["dev"].site, r["model"], r["family"], r["version"], "; ".join(r["approved"]), r["v"].status,
         r["eos"].isoformat() if r["eos"] else "", "" if r["days"] is None else r["days"], r["e"].status, _worst([r["v"], r["e"]]),
         "; ".join(x.detail for x in (r["v"], r["e"]) if x.status == FAIL)] for r in lifecycle_rows(d, rv)])


# ---------------------------------------------------------------- the pack

def _md(x) -> str:
    return str(x).replace("|", "/")


def _word(st: str) -> str:
    return {"ok": "COMPLIANT", CRITICAL: "NON-COMPLIANT", WARNING: "DRIFT"}.get(st, st.upper())


def pack_md(d: Data, rv: dict, findings: list[Finding], title: str) -> str:
    s, sm, st = d.settings, summary(d, rv), area_status(findings)
    wins = s.windows()
    out = [f"# {title}", "",
           f"> Generated by netcompliance on {d.as_of:%a %d %b %Y} from the backups and exports listed under *Scope and evidence*. Read-only: "
           f"nothing was changed on any device. Every fix goes through a change; sections marked {TODO} are for the change board.", "",
           f"**Overall: {overall(rv).upper()}** · {sm['compliant']} compliant, {sm['drift']} drift, {sm['noncompliant']} non-compliant of "
           f"{sm['devices']} devices · {pct(sm['pass_rate'])} of the rule checks pass", "",
           "## Decisions for the change board", "",
           "Critical findings are proposed for the first change window, warnings for the next one. Approve, move to another window, or "
           "record an exception with an owner and an end date.", "",
           "| Ref | Finding | Severity | Devices | Proposed window | Owner | Decision |", "|---|---|---|---|---|---|---|"]
    for f in findings:
        if f.severity == INFO:
            continue
        out.append(f"| {f.code} | {_md(f.subject)} | {f.severity} | {_md(', '.join(f.devices[:6]) + (' …' if len(f.devices) > 6 else ''))} | "
                   f"{_md(f.window or '–')} | {_md(f.owner)} | {TODO if f.severity == CRITICAL else ''} |")
    out += ["", "| Area | Status | Findings to act on |", "|---|---|---|"]
    for a in AREAS:
        out.append(f"| {a} | {_word(st[a])} | {sum(f.area == a and f.severity != INFO for f in findings)} |")
    out += ["", "## Headlines", "",
            f"- {sm['devices']} devices in {sm['sites']} sites: " + ", ".join(f"{sm['platforms'][k]} {PLATFORM_LABEL[k]}"
                                                                                for k in ("ios", "aruba", "fortios") if sm["platforms"][k]) + ".",
            f"- Backups: {sm['missing']} devices with no backup, {sm['stale']} with a backup older than {s.backup_max_days} days; "
            f"{sm['unsaved']} with unsaved changes and {sm['unplanned']} changed with no approved change.",
            f"- Lifecycle: {sm['eos']} out of vendor support; {sum(1 for x in rv['devices'] for r in x['results'] if r.code == 'LCM-01' and r.status == FAIL)} "
            "on a version not approved for the model.",
            f"- Change windows: {', '.join(f'{n} ({w:%a %d %b %H:%M})' for n, w in wins) or 'none in settings.json'}.",
            "", "## Scope and evidence", "", f"- Organisation: {s.organisation}", f"- Reference date: {d.as_of:%a %d %b %Y %H:%M}",
            f"- A backup is old after {s.backup_max_days} days (critical after {s.backup_critical_days}); unsaved changes are critical after "
            f"{s.unsaved_critical_hours} hours; end of support is a warning {s.eos_warning_days} days ahead.", "",
            "| Source | File | Records |", "|---|---|---|"]
    out += [f"| {FILES.get(k, k)} | `{k}` | {v:,} |" for k, v in d.sources.items()]
    out += ["", "## 1. Status by site", "", "| Site | Rooms | Devices | Compliant | Drift | Non-compliant | Status |", "|---|---|---|---|---|---|---|"]
    for r in rv["sites"]:
        out.append(f"| {_md(r['name'])} | {_md(', '.join(r['rooms']) or '–')} | {r['devices']} | {r['counts'][COMPLIANT]} | {r['counts'][DRIFT]} | "
                   f"{r['counts'][NONCOMPLIANT]} | **{r['status'].upper()}** |")
    out += ["", "## 2. Devices not compliant", "", "| Device | Site | Role | Model | Status | Findings |", "|---|---|---|---|---|---|"]
    for x in sorted(rv["devices"], key=lambda x: ({NONCOMPLIANT: 0, DRIFT: 1, COMPLIANT: 2}[x["status"]], x["device"].site, x["device"].hostname)):
        if x["status"] == COMPLIANT:
            continue
        dev, inv = x["device"], x["device"].inv
        out.append(f"| {dev.hostname} | {dev.site or '–'} | {inv.role if inv else '(not in inventory)'} | "
                   f"{_md((inv.model if inv else '') or (dev.config.model if dev.config else ''))} | {x['status'].upper()} | {', '.join(x['codes'])} |")
    out += ["", "## 3. Backups and changes", "", "| Device | Last backup | Age (days) | Last change | Saved | Ticket | Finding |",
            "|---|---|---|---|---|---|---|"]
    for b in backup_rows(d, rv):
        if not b["worst"]:
            continue
        out.append(f"| {b['dev'].hostname} | {_dt(b['inv'].last_backup) if b['inv'] and b['inv'].last_backup else '–'} | "
                   f"{'–' if b['age'] is None else format(b['age'], '.0f')} | {_dt(b['c'].last_change) if b['c'] else '–'} | "
                   f"{'no' if b['unsaved'] else 'yes' if b['c'] and b['c'].last_change else '–'} | {', '.join(b['tickets']) or '–'} | "
                   f"{_md('; '.join(r.detail for r in b['res'] if r.status == FAIL))} |")
    out += ["", "## 4. Lifecycle", "", "| Device | Model | Version | Approved | End of support | Finding |", "|---|---|---|---|---|---|"]
    for r in lifecycle_rows(d, rv):
        if r["v"].status != FAIL and r["e"].status != FAIL:
            continue
        out.append(f"| {r['dev'].hostname} | {_md(r['model'])} | {_md(r['version'])} | {_md(', '.join(r['approved']) or 'none')} | "
                   f"{r['eos'].isoformat() if r['eos'] else '–'} | {_md('; '.join(x.detail for x in (r['v'], r['e']) if x.status == FAIL))} |")
    out += ["", "## Findings", ""]
    for f in findings:
        if f.severity == INFO:
            continue
        out += [f"### {f.code} · {f.subject} ({f.severity})", "", _md(f.detail), "",
                f"Sites: {', '.join(f.sites) or '–'}. Next step: {f.fix} Owner: {f.owner}. Proposed window: {f.window or '–'}.", ""]
    info = [f for f in findings if f.severity == INFO]
    if info:
        out += ["For information:", ""] + [f"- {f.code}: {_md(f.detail)}" for f in info] + [""]
    out += ["## Exceptions", "", "| Device | Rule | Reason | Compensating control | Owner | Until |", "|---|---|---|---|---|---|",
            f"| {TODO} | | | | | |", "",
            "## Notes", "",
            "- A device is NON-COMPLIANT with a critical failure, DRIFT with warnings only, COMPLIANT otherwise; a site and the review take "
            "the worst status of their devices. rule-results.csv has every rule for every device (pass, fail or n/a).",
            "- Unsaved changes and changes without a ticket are read from the `! Last configuration change` and `! NVRAM config last updated` "
            "header lines of Cisco backups; when a backup does not keep them, the rules are n/a.",
            "- Unused ports are ports with no description (or a description in the baseline's unused list): the description is the "
            "record that a port is in use.",
            "- Approved versions are the ones in baseline.json, agreed by this company; they are not vendor recommendations.",
            f"- Decisions of the change board: {TODO}", "",
            "## Sign-off", "", f"- Prepared by (network operations): {TODO}", f"- Reviewed with (network and security engineering): {TODO}",
            f"- Date: {TODO}", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb;--na:#c9ced4}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0;--na:#3a434c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}h3{font-size:15px;margin:18px 0 8px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:24px}
.overall{display:inline-block;margin-top:14px;padding:6px 14px;border-radius:99px;font-weight:700;border:2px solid currentColor}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}
.area .lbl{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px}.area .cnt{display:block;font-size:13px;color:var(--muted);margin-top:4px}
.sites{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}
.site{background:var(--card);border:1px solid var(--line);border-top:5px solid var(--ok);border-radius:10px;padding:12px 16px}
.site.non-compliant{border-top-color:var(--bad)}.site.drift{border-top-color:var(--warn)}.site h3{margin:0 0 2px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}
.area.critical,.area.warning,.area.ok{color:inherit}
.pill.compliant{color:var(--ok)}.pill.drift{color:var(--warn)}.pill.non-compliant{color:var(--bad)}
td.subj{min-width:190px}td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);min-width:200px;max-width:380px}td.sm{font-size:13px}
.brk{overflow-wrap:anywhere;word-break:break-word}
.cell{display:inline-block;width:18px;height:18px;border-radius:4px;background:var(--ok)}.cell.warning{background:var(--warn)}.cell.critical{background:var(--bad)}
.cell.na{background:var(--na)}td.c{text-align:center;padding:8px 4px}th.c{text-align:center;padding:8px 4px;font-size:11px}
footer{margin-top:40px;font-size:13px}
"""
AREA_SHORT = {"Backup": "Backup", "Management plane": "Mgmt", "Logging and time": "Logs", "Switching": "Switch", "FortiGate": "FortiGate",
              "Lifecycle": "Life", "Inventory": "Inv"}


def _pill(cls: str, text: str) -> str:
    return f"<span class='pill {cls}'>{e(text)}</span>"


def _spill(st: str) -> str:
    return _pill(st, st.upper())


def _table(head: list[str], rows: list[str], centre: set | None = None) -> str:
    centre = centre or set()
    return ("<div class='wrap'><table><tr>" + "".join(f"<th{' class=c' if k in centre else ''}>{e(h)}</th>" for k, h in enumerate(head))
            + "</tr>" + "".join(rows) + "</table></div>")


def _area_table(findings: list[Finding], prefix: str) -> str:
    xs = [f for f in findings if f.code.startswith(prefix)]
    if not xs:
        return "<p class='muted'>Nothing to report.</p>"
    return _table(["Severity", "Finding", "Detail", "Next step", "Window"],
                  [f"<tr><td>{_pill(f.severity, f.severity.upper())}</td><td class='subj'><b>{e(f.code)}</b> {e(f.subject)}</td>"
                   f"<td class='sm brk'>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td><td class='sm'>{e(f.window or '–')}</td></tr>" for f in xs])


def _cell(results, area: str) -> str:
    rs = [r for r in results if r.area == area]
    if all(r.status == NA for r in rs):
        return "<span class='cell na' title='n/a'></span>"
    w = _worst(rs)
    w = "" if w == INFO else w
    tip = "; ".join(f"{r.code} {r.detail}" for r in rs if r.status == FAIL and r.severity != INFO) or "pass"
    return f"<span class='cell {w}' title='{e(tip, quote=True)}'></span>"


def render_html(d: Data, rv: dict, findings: list[Finding], title: str) -> str:
    s, sm, st = d.settings, summary(d, rv), area_status(findings)
    ov = overall(rv)
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(s.organisation)} · as of {d.as_of:%a %d %b %Y %H:%M} · {sm['devices']} devices in "
         f"{sm['sites']} comms rooms</p>",
         f"<span class='overall {'critical' if ov == NONCOMPLIANT else 'warning' if ov == DRIFT else 'ok'}'>Overall: {e(ov.upper())}</span>"
         "<div class='tiles'>"]
    wins = s.windows()
    tiles = [("Devices", str(sm["devices"]), f"{sm['sites']} sites · {sm['platforms']['ios']} Cisco, {sm['platforms']['aruba']} Aruba, "
              f"{sm['platforms']['fortios']} FortiGate"),
             ("Compliant", str(sm["compliant"]), f"{sm['drift']} drift · {sm['noncompliant']} non-compliant"),
             ("Rule checks passed", pct(sm["pass_rate"]), f"{sm['passed']} of {sm['checks']}"),
             ("Backups missing", str(sm["missing"]), f"{sm['stale']} older than {s.backup_max_days} days"),
             ("Unsaved / no ticket", f"{sm['unsaved']} / {sm['unplanned']}", "running config changes"),
             ("Out of support", str(sm["eos"]), f"{sm['lifecycle']} lifecycle findings"),
             ("Critical findings", str(sum(f.severity == CRITICAL for f in findings)), f"{sum(f.severity == WARNING for f in findings)} warnings"),
             ("Next window", wins[0][0] if wins else "–", f"{wins[0][1]:%a %d %b %H:%M}" if wins else "none in settings")]
    h += [f"<div class='tile'><span class='muted'>{e(x)}</span><b>{e(y)}</b><span class='muted'>{e(z)}</span></div>" for x, y, z in tiles]
    h.append("</div><h2>Sites</h2><div class='sites'>")
    for r in rv["sites"]:
        bad = [x for x in rv["devices"] if x["device"].site == r["site"] and x["status"] == NONCOMPLIANT]
        h.append(f"<div class='site {r['status']}'><h3>{e(r['name'])} {_spill(r['status'])}</h3><span class='muted'>"
                 f"{e(', '.join(r['rooms']) or 'no room')} · {r['devices']} devices · {r['counts'][COMPLIANT]} compliant, {r['counts'][DRIFT]} drift, "
                 f"{r['counts'][NONCOMPLIANT]} non-compliant</span>"
                 + (f"<p class='critical' style='margin:8px 0 0;font-size:13px'>{e(', '.join(x['device'].hostname for x in bad))}</p>" if bad else "")
                 + "</div>")
    h.append("</div><h2>Status by area</h2><div class='areas'>")
    for a in AREAS:
        n = sum(f.area == a and f.severity != INFO for f in findings)
        cls = {"ok": "compliant", CRITICAL: "non-compliant", WARNING: "drift"}[st[a]]
        h.append(f"<div class='area {st[a]}'><span class='lbl'>{e(a)}</span>{_pill(cls, _word(st[a]))}<span class='cnt'>{n} to act on</span></div>")
    h.append("</div>")
    crit = [f for f in findings if f.severity == CRITICAL]
    if crit:
        h.append("<h2>Fix first</h2>")
        h.append(_table(["Finding", "What", "Next step", "Window", "Owner"],
                        [f"<tr><td class='subj'><b>{e(f.subject)}</b><br><span class='muted'>{e(f.area)} · {e(f.code)} · {e(', '.join(f.sites))}</span></td>"
                         f"<td class='sm brk'>{e(f.detail)}</td><td class='fix'>{e(f.fix)}</td><td class='sm'>{e(f.window or '–')}</td>"
                         f"<td class='sm'>{e(f.owner)}</td></tr>" for f in crit]))
    # 1 devices
    h.append("<h2>1. Devices</h2><p class='muted'>Worst result per area for every device (green pass, amber warning, red critical, grey "
             "not applicable; hover for the detail). rule-results.csv has every rule for every device.</p>")
    rows = []
    for x in rv["devices"]:
        dev, inv = x["device"], x["device"].inv
        where = f"{dev.site or '–'} · {inv.room} · {inv.rack}" if inv else f"{dev.site or '–'} · not in the inventory"
        model = (inv.model if inv else "") or (dev.config.model if dev.config else "")
        rows.append(f"<tr><td class='nw'><b>{e(dev.hostname)}</b><br><span class='muted sm'>{e(where)}</span></td><td class='sm'>"
                    f"{e(inv.role if inv else '–')}<br><span class='muted'>{e(model)}</span></td>"
                    + "".join(f"<td class='c'>{_cell(x['results'], a)}</td>" for a in AREAS)
                    + f"<td>{_spill(x['status'])}</td><td class='sm'>{e(', '.join(x['codes']) or '–')}</td></tr>")
    h.append(_table(["Device", "Role / model"] + [AREA_SHORT[a] for a in AREAS] + ["Status", "Findings"], rows, set(range(2, 2 + len(AREAS)))))
    # 2 backups
    h.append(f"<h2>2. Backups and changes</h2><p class='muted'>Missing backups, backups older than {s.backup_max_days} days, running "
             "configurations changed after the last save, and changes with no approved ticket in changes.csv. backups.csv has every device.</p>")
    br = [b for b in backup_rows(d, rv) if b["worst"]]
    h.append(_table(["Device", "Last backup", "Last change", "Saved", "Ticket", "Finding"],
                    [f"<tr><td class='nw'><b>{e(b['dev'].hostname)}</b></td><td class='sm nw'>"
                     f"{e(_dt(b['inv'].last_backup) if b['inv'] and b['inv'].last_backup else '–')}"
                     f"{'' if b['age'] is None else '<br><span class=muted>' + format(b['age'], '.0f') + ' days</span>'}</td>"
                     f"<td class='sm nw'>{e(_dt(b['c'].last_change) if b['c'] else '–')}</td><td class='sm'>"
                     f"{'no' if b['unsaved'] else ('yes' if b['c'] and b['c'].last_change else '–')}</td><td class='sm'>{e(', '.join(b['tickets']) or '–')}</td>"
                     f"<td class='sm brk {b['worst']}'>{e('; '.join(r.detail for r in b['res'] if r.status == FAIL))}</td></tr>" for b in br])
             if br else "<p class='muted'>None.</p>")
    h.append("<p></p>" + _area_table(findings, "BKP"))
    sections = [("3. Management plane", "MGT", "SSH v2 only, no telnet, hashed passwords, AAA with TACACS+ or RADIUS and a local fallback, a "
                 f"login banner, an idle timeout of {d.baseline.max_idle_minutes} minutes or less, and management access restricted."),
                ("4. Logging and time", "LOG", f"NTP servers ({', '.join(d.baseline.ntp_servers)}), syslog hosts "
                 f"({', '.join(d.baseline.syslog_hosts)}), time zone and SNMP v3 only."),
                ("5. Switching hygiene", "SWI", f"Access switches: unused ports shut down in VLAN {d.baseline.parking_vlan}, PortFast and "
                 f"BPDU guard on user ports, no user ports in VLAN 1, port security at {', '.join(d.baseline.port_security_sites) or 'no site'}; "
                 f"trunks with native VLAN {d.baseline.native_vlan or 'other than 1'}."),
                ("6. FortiGate", "FWL", "Admin access on WAN interfaces, accept policies from all to all with service ALL, accept policies "
                 f"without logging, policies disabled for more than {s.disabled_policy_days} days, and FortiOS against the baseline minimum.")]
    for head, prefix, note in sections:
        h.append(f"<h2>{e(head)}</h2><p class='muted'>{e(note)}</p>" + _area_table(findings, prefix))
    # 7 lifecycle
    h.append(f"<h2>7. Lifecycle and inventory</h2><p class='muted'>OS version against the approved list for the model family, end of "
             f"support passed or within {s.eos_warning_days} days, and the inventory against the configurations. lifecycle.csv has every device.</p>")
    lr = [r for r in lifecycle_rows(d, rv) if r["v"].status == FAIL or r["e"].status == FAIL]
    if lr:
        h.append(_table(["Device", "Model", "Version", "Approved", "End of support", "Finding"],
                        [f"<tr><td class='nw'><b>{e(r['dev'].hostname)}</b></td><td class='sm'>{e(r['model'])}</td><td class='sm nw'>{e(r['version'])}</td>"
                         f"<td class='sm'>{e(', '.join(r['approved']) or 'none')}</td><td class='sm nw'>{e(r['eos'].isoformat() if r['eos'] else '–')}</td>"
                         f"<td class='sm brk {_worst([r['v'], r['e']])}'>{e('; '.join(x.detail for x in (r['v'], r['e']) if x.status == FAIL))}</td></tr>"
                         for r in lr]))
    h.append("<p></p>" + _area_table(findings, "LCM") + "<p></p>" + _area_table(findings, "INV"))
    h.append("<h2>All findings</h2>")
    h.append(_table(["Severity", "Area", "Finding", "Devices", "Window", "Owner"],
                    [f"<tr><td>{_pill(f.severity, f.severity.upper())}</td><td class='nw'>{e(f.area)}</td><td>{e(f.subject)}</td>"
                     f"<td class='sm brk'>{e(', '.join(f.devices))}</td><td class='sm'>{e(f.window or '–')}</td><td class='sm'>{e(f.owner)}</td></tr>"
                     for f in findings]))
    h.append("<footer class='muted'>Generated by netcompliance. Fictional demo data unless you ran it on your own backups. The pack for the "
             "change board is compliance-pack.md.</footer></main></body></html>")
    return "".join(h)


__all__ = ["render_html", "pack_md", "write_devices", "write_rules", "write_backups", "write_lifecycle", "write_actions", "write_findings",
           "_n", "PASS"]
