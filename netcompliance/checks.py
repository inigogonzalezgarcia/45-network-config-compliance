"""The rules of the weekly network configuration compliance review. Seven areas: backup (missing or old backups, running configuration
not saved, changes with no approved ticket), management plane (SSH v2, telnet, password storage, AAA with a local fallback, banner, idle
timeout, restricted management access), logging and time (NTP, syslog, time zone, SNMP communities), switching hygiene (unused ports,
BPDU guard and PortFast, native VLAN, user ports in VLAN 1, port security), FortiGate (admin access on WAN, any-any policies, policies
without logging, old disabled policies, firmware), lifecycle (approved versions, end of support) and inventory (configurations with no
inventory row, model or serial mismatch).

Every rule gives every device a result: pass, fail (with a severity) or n/a. A device is NON-COMPLIANT with a critical failure, DRIFT
with warnings only, COMPLIANT otherwise; a site and the whole review take the worst status of their devices."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .model import Data, Device, _norm, compact, version_key
from .parsers import ARUBA, FORTIOS, IOS

CRITICAL, WARNING, INFO = "critical", "warning", "info"
PASS, FAIL, NA = "pass", "fail", "n/a"
ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ("Backup", "Management plane", "Logging and time", "Switching", "FortiGate", "Lifecycle", "Inventory")
PREFIX = {"BKP": "Backup", "MGT": "Management plane", "LOG": "Logging and time", "SWI": "Switching", "FWL": "FortiGate",
          "LCM": "Lifecycle", "INV": "Inventory"}
NONCOMPLIANT, DRIFT, COMPLIANT = "non-compliant", "drift", "compliant"
STATUS = {CRITICAL: NONCOMPLIANT, WARNING: DRIFT, None: COMPLIANT}
STATUS_ORDER = {NONCOMPLIANT: 0, DRIFT: 1, COMPLIANT: 2}

# code: (rule, owner area, next step)
RULES = {
    "BKP-01": ("Configuration backup exists", "backup", "Fix the backup job for the device (credentials, ACL, Oxidized/RANCID source) and "
               "take a backup today."),
    "BKP-02": ("Backup newer than the limit", "backup", "Check why the backup job stopped for the device or site and run it again."),
    "BKP-03": ("Running configuration saved", "backup", "Compare running and startup configuration, then save (copy running-config "
               "startup-config) or roll back, through a change."),
    "BKP-04": ("Configuration changes have an approved change", "backup", "Find who changed what; raise a retrospective change or roll "
               "back, and review with the engineer."),
    "MGT-01": ("SSH version 2 only", "management", "Set ip ssh version 2."),
    "MGT-02": ("No telnet", "management", "Allow SSH only on the VTY lines (transport input ssh), disable the telnet server on "
               "ArubaOS-Switch (no telnet-server) and remove telnet from FortiGate allowaccess."),
    "MGT-03": ("Passwords stored hashed", "management", "Replace enable password with enable secret and turn on service "
               "password-encryption."),
    "MGT-04": ("AAA with TACACS+ or RADIUS and a local fallback", "management", "Apply the baseline AAA block: the TACACS+/RADIUS group first, "
               "local as fallback."),
    "MGT-05": ("Login banner", "management", "Apply the baseline login banner."),
    "MGT-06": ("Idle timeout", "management", "Set the idle timeout of the baseline on every management line."),
    "MGT-07": ("Management access restricted to the management network", "management", "Apply the VTY access-class, the authorized "
               "managers or the trusted hosts of the baseline."),
    "LOG-01": ("NTP servers as baseline", "logging", "Point NTP to the baseline servers and remove the old ones."),
    "LOG-02": ("Syslog hosts as baseline", "logging", "Add the baseline syslog hosts."),
    "LOG-03": ("Time zone as baseline", "logging", "Apply the baseline clock time zone and summer time."),
    "LOG-04": ("SNMP v3 only, no v2c communities", "logging", "Remove the SNMP community and move the poller (Zabbix, SolarWinds) to "
               "SNMPv3; public and private first."),
    "SWI-01": ("Unused ports shut down in the parking VLAN", "switching", "Shut down unused ports and move them to the parking VLAN."),
    "SWI-02": ("PortFast and BPDU guard on access ports", "switching", "Enable PortFast (admin-edge-port) and BPDU guard "
               "(bpdu-protection) on user ports."),
    "SWI-03": ("Native VLAN of trunks not VLAN 1", "switching", "Set the baseline native VLAN on both ends of the trunk in the same window."),
    "SWI-04": ("No user ports in VLAN 1", "switching", "Move the user ports to their user VLAN."),
    "SWI-05": ("Port security where the baseline requires it", "switching", "Enable port security on user ports at the sites of the "
               "baseline."),
    "FWL-01": ("No admin access on WAN interfaces", "firewall", "Remove HTTPS, HTTP, SSH and telnet from allowaccess on the WAN interfaces; "
               "manage through the management interface or VPN."),
    "FWL-02": ("No any-any accept policies", "firewall", "Replace the policy with specific addresses and services, or disable it, "
               "through a change."),
    "FWL-03": ("Logging on accept policies", "firewall", "Set logtraffic all (or utm) on the accept policies."),
    "FWL-04": ("Disabled policies cleaned up", "firewall", "Delete disabled policies older than the limit after checking with the owner."),
    "FWL-05": ("FortiOS at or above the baseline minimum", "firewall", "Plan the FortiOS upgrade on the upgrade path, HA pair secondary "
               "first."),
    "LCM-01": ("OS version approved for the model", "lifecycle", "Upgrade to an approved version in a change window, or record an exception."),
    "LCM-02": ("Within vendor support", "lifecycle", "Replace the device or record the risk with an end date; order the replacement."),
    "INV-01": ("Device in the inventory", "inventory", "Add the device to Device42 with site, rack, role and serial, or remove the stale "
               "backup."),
    "INV-02": ("Inventory matches the configuration", "inventory", "Correct the model, serial or hostname in Device42 (or on the device)."),
}


@dataclass
class Result:
    hostname: str
    code: str
    status: str
    severity: str = ""
    detail: str = ""

    @property
    def area(self) -> str:
        return PREFIX[self.code.split("-")[0]]


@dataclass
class Finding:
    severity: str
    area: str
    code: str
    subject: str
    detail: str
    fix: str
    owner: str = ""
    devices: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)
    window: str = ""


def _n(k: int, word: str, plural: str | None = None) -> str:
    return f"{k} {word if k == 1 else (plural or word + 's')}"


def _top(items: list[str], k: int = 6, sep: str = ", ") -> str:
    return sep.join(items[:k]) + (f" and {len(items) - k} more" if len(items) > k else "")


def pct(x: float | None, k: int = 0) -> str:
    return "–" if x is None else f"{x:.{k}%}"


SHORT = (("TwentyFiveGigE", "Twe"), ("FortyGigabitEthernet", "Fo"), ("TenGigabitEthernet", "Te"), ("FiveGigabitEthernet", "Fi"),
         ("TwoGigabitEthernet", "Tw"), ("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"), ("HundredGigE", "Hu"))


def short(name: str) -> str:
    for a, b in SHORT:
        if name.startswith(a):
            return b + name[len(a):]
    return name


def _ports(ports) -> str:
    return _top([short(p.name) for p in ports], 6)


def is_unused(p, b) -> bool:
    d = _norm(p.description)
    return not d or any(d.startswith(x) for x in b.unused_descriptions)


def _dt(x: datetime) -> str:
    return f"{x:%a %d %b %H:%M}"


# ---------------------------------------------------------------- one device

def evaluate(d: Data, dev: Device) -> list[Result]:
    s, b = d.settings, d.baseline
    c, inv, plat = dev.config, dev.inv, dev.platform
    out: list[Result] = []

    def add(code, status, severity="", detail=""):
        out.append(Result(dev.hostname, code, status, severity if status == FAIL else "", detail))

    # ------------------------------------------------ backup
    if inv is None:
        add("BKP-01", NA, detail="not in the inventory")
    elif c is None:
        add("BKP-01", FAIL, CRITICAL, f"no configuration backup in configs/ for {dev.hostname}")
    else:
        add("BKP-01", PASS, detail=dev.path)
    if inv is None or c is None:
        add("BKP-02", NA, detail="no backup" if c is None and inv else "not in the inventory")
    elif not inv.last_backup:
        add("BKP-02", NA, detail="no last backup time in the inventory")
    else:
        age = (d.as_of - inv.last_backup).total_seconds() / 86400
        if age > s.backup_critical_days:
            add("BKP-02", FAIL, CRITICAL, f"last backup {inv.last_backup:%d %b %Y}, {int(age)} days old")
        elif age > s.backup_max_days:
            add("BKP-02", FAIL, WARNING, f"last backup {inv.last_backup:%d %b %Y}, {int(age)} days old")
        else:
            add("BKP-02", PASS, detail=f"last backup {inv.last_backup:%d %b %Y %H:%M}")
    if c is None or plat != IOS:
        add("BKP-03", NA)
        add("BKP-04", NA)
    else:
        if not c.last_change:
            add("BKP-03", NA, detail="no 'Last configuration change' header in the backup")
        elif c.last_saved and c.last_saved >= c.last_change:
            add("BKP-03", PASS, detail=f"saved {_dt(c.last_saved)}")
        else:
            hours = (d.as_of - c.last_change).total_seconds() / 3600
            sev = CRITICAL if hours >= s.unsaved_critical_hours else WARNING
            saved = f"last saved {_dt(c.last_saved)}" if c.last_saved else "never saved"
            add("BKP-03", FAIL, sev, f"changed {_dt(c.last_change)}{' by ' + c.last_change_by if c.last_change_by else ''}, {saved}: "
                                     f"unsaved for {int(hours)} hours, lost on the next reload")
        if not c.last_change:
            add("BKP-04", NA, detail="no 'Last configuration change' header in the backup")
        elif "changes.csv" not in d.sources:
            add("BKP-04", NA, detail="no changes.csv")
        elif c.last_change < d.as_of - timedelta(days=s.backup_max_days):
            add("BKP-04", PASS, detail=f"last change {_dt(c.last_change)}, before this review period")
        else:
            ok = [ch for ch in d.changes if ch.hostname.lower() == dev.hostname.lower() and ch.approved and ch.covers(c.last_change)]
            if ok:
                add("BKP-04", PASS, detail=f"changed {_dt(c.last_change)} under {ok[0].ticket}")
            else:
                add("BKP-04", FAIL, WARNING, f"changed {_dt(c.last_change)}{' by ' + c.last_change_by if c.last_change_by else ''} with no "
                                             "approved change for the device at that time")
    if c is None:
        for code in RULES:
            if not code.startswith(("BKP", "LCM", "INV")):
                add(code, NA, detail="no configuration")
    else:
        _mgmt(d, dev, add)
        _logging(d, dev, add)
        _switching(d, dev, add)
        _firewall(d, dev, add)
    _lifecycle(d, dev, add)
    _inventory(d, dev, add)
    order = list(RULES)
    out.sort(key=lambda r: order.index(r.code))
    return out


def _mgmt(d: Data, dev: Device, add) -> None:
    c, b, plat = dev.config, d.baseline, dev.platform
    if plat == IOS:
        add("MGT-01", PASS if c.ssh_v2 else FAIL, WARNING, "" if c.ssh_v2 else "no 'ip ssh version 2' (SSH v1 still accepted)")
    else:
        add("MGT-01", NA, detail="SSH v2 only on this platform")
    if c.telnet:
        add("MGT-02", FAIL, CRITICAL, c.telnet_where)
    elif c.transport_unset:
        add("MGT-02", FAIL, WARNING, f"transport input not set explicitly on {c.transport_unset}")
    else:
        add("MGT-02", PASS)
    if plat == IOS:
        bad = []
        if c.enable_password:
            bad.append("enable password configured")
        if not c.enable_secret:
            bad.append("no enable secret")
        if not c.password_encryption:
            bad.append("no service password-encryption")
        add("MGT-03", FAIL if bad else PASS, WARNING, "; ".join(bad))
    else:
        add("MGT-03", NA)
    if plat in (IOS, ARUBA):
        ok = c.aaa_remote and c.aaa_local
        add("MGT-04", PASS if ok else FAIL, WARNING, c.aaa_detail + ("" if ok else (" (no local fallback)" if c.aaa_remote else
                                                                                    " (no TACACS+/RADIUS group)")))
    else:
        add("MGT-04", NA)
    add("MGT-05", PASS if c.banner else FAIL, WARNING, "" if c.banner else "no login banner")
    bad = [f"{w} {'never' if m == 0 else str(m) + ' min'}" for w, m in c.idle if m == 0 or m > b.max_idle_minutes]
    add("MGT-06", FAIL if bad else PASS, WARNING, ("idle timeout over " + str(b.max_idle_minutes) + " min: " + ", ".join(bad)) if bad else "")
    add("MGT-07", PASS if c.restricted else FAIL, WARNING, c.restricted_detail)


def _logging(d: Data, dev: Device, add) -> None:
    c, b = dev.config, d.baseline
    have, want = list(dict.fromkeys(c.ntp)), b.ntp_servers
    missing, extra = [x for x in want if x not in have], [x for x in have if x not in want]
    if not want:
        add("LOG-01", NA, detail="no NTP servers in the baseline")
    elif missing or extra:
        add("LOG-01", FAIL, WARNING, "; ".join(x for x in (("missing " + ", ".join(missing)) if missing else "",
                                                             ("not in the baseline " + ", ".join(extra)) if extra else "") if x))
    else:
        add("LOG-01", PASS, detail=", ".join(have))
    miss = [x for x in b.syslog_hosts if x not in c.syslog]
    if not b.syslog_hosts:
        add("LOG-02", NA)
    else:
        add("LOG-02", FAIL if miss else PASS, WARNING, ("missing " + ", ".join(miss)) if miss else ", ".join(c.syslog))
    tz = b.timezone.get(dev.platform)
    if not tz:
        add("LOG-03", NA, detail="no time zone in the baseline for this platform")
    elif str(c.timezone or "") != str(tz):
        add("LOG-03", FAIL, WARNING, f"time zone {c.timezone or 'not set'}, baseline {tz}")
    else:
        add("LOG-03", PASS, detail=str(tz))
    bad = [x for x in c.snmp_communities if x.lower() in b.snmp_forbidden]
    if bad:
        add("LOG-04", FAIL, CRITICAL, "SNMP v2c community " + ", ".join(f"'{x}'" for x in bad))
    elif c.snmp_communities:
        add("LOG-04", FAIL, WARNING, f"{_n(len(c.snmp_communities), 'SNMP v2c community', 'SNMP v2c communities')} configured")
    else:
        add("LOG-04", PASS, detail="SNMPv3" if c.snmp_v3 else "no SNMP communities")


def _switching(d: Data, dev: Device, add) -> None:
    c, b = dev.config, d.baseline
    codes = ("SWI-01", "SWI-02", "SWI-03", "SWI-04", "SWI-05")
    if dev.platform == FORTIOS or not dev.is_switch:
        for code in codes:
            add(code, NA, detail="not a switch")
        return
    access_role = dev.role == "access" or (dev.inv is None and dev.platform == ARUBA)
    access = [p for p in c.ports if p.mode != "trunk"]
    trunks = [p for p in c.ports if p.mode == "trunk"]
    if access_role:
        unused = [p for p in access if is_unused(p, b)]
        bad = [p for p in unused if not p.shutdown or p.vlan != b.parking_vlan]
        up1 = [p for p in bad if not p.shutdown and p.vlan in (0, 1)]
        if bad:
            what = f"{_n(len(bad), 'unused port')} not shut down in VLAN {b.parking_vlan}: {_ports(bad)}"
            if up1:
                what += f" ({len(up1)} up in VLAN 1)"
            add("SWI-01", FAIL, WARNING, what)
        else:
            add("SWI-01", PASS, detail=f"{len(unused)} unused ports parked")
        used = [p for p in access if not is_unused(p, b) and not p.shutdown]
        nostp = [p for p in used if not (p.portfast and p.bpduguard)]
        add("SWI-02", FAIL if nostp else PASS, WARNING, f"{_n(len(nostp), 'user port')} without PortFast and BPDU guard: {_ports(nostp)}"
            if nostp else "")
        v1 = [p for p in used if p.vlan in (0, 1)]
        add("SWI-04", FAIL if v1 else PASS, WARNING, f"{_n(len(v1), 'user port')} in VLAN 1: {_ports(v1)}" if v1 else "")
        if dev.site in b.port_security_sites:
            nops = [p for p in used if not p.port_security]
            add("SWI-05", FAIL if nops else PASS, WARNING, f"{_n(len(nops), 'user port')} without port security: {_ports(nops)}" if nops else "")
        else:
            add("SWI-05", NA, detail="not required at this site")
    else:
        for code in ("SWI-01", "SWI-02", "SWI-04", "SWI-05"):
            add(code, NA, detail="core switch")
    want = b.native_vlan
    bad = [p for p in trunks if (p.native == 1 if want is None else p.native not in (want, 0))]
    add("SWI-03", FAIL if bad else (PASS if trunks else NA), WARNING,
        f"{_n(len(bad), 'trunk')} with native VLAN {', '.join(sorted({str(p.native) for p in bad}))}"
        f"{'' if want is None else ' (baseline ' + str(want) + ')'}: {_ports(bad)}" if bad else ("" if trunks else "no trunks"))


DATE_IN_TEXT = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _firewall(d: Data, dev: Device, add) -> None:
    c, b, s = dev.config, d.baseline, d.settings
    codes = ("FWL-01", "FWL-02", "FWL-03", "FWL-04", "FWL-05")
    if dev.platform != FORTIOS:
        for code in codes:
            add(code, NA, detail="not a FortiGate")
        return
    wan = [i for i in c.interfaces if _norm(i.role) == "wan" or i.name.lower().startswith("wan")]
    bad = [f"{i.name} ({' '.join(x for x in i.allowaccess if x in ('https', 'http', 'ssh', 'telnet'))})" for i in wan
           if any(x in i.allowaccess for x in ("https", "http", "ssh", "telnet"))]
    add("FWL-01", FAIL if bad else PASS, CRITICAL, ("admin access on " + ", ".join(bad)) if bad else "")
    on = [p for p in c.policies if p.status == "enable" and p.action == "accept"]
    anyany = [p for p in on if "all" in [x.lower() for x in p.srcaddr] and "all" in [x.lower() for x in p.dstaddr]
              and "all" in [x.lower() for x in p.service]]
    add("FWL-02", FAIL if anyany else PASS, CRITICAL,
        "; ".join(f"policy {p.id} '{p.name}' {'/'.join(p.srcintf)} -> {'/'.join(p.dstintf)} all/all/ALL accept"
                  f"{', logtraffic disable' if p.logtraffic == 'disable' else ''}" for p in anyany))
    nolog = [p for p in on if p.logtraffic == "disable"]
    add("FWL-03", FAIL if nolog else PASS, WARNING, ("logtraffic disable on " + ", ".join(f"policy {p.id} '{p.name}'" for p in nolog))
        if nolog else "")
    off = [p for p in c.policies if p.status == "disable"]
    old, undated = [], []
    for p in off:
        m = DATE_IN_TEXT.search(p.comments)
        if m:
            try:
                age = (d.today - datetime.strptime(m.group(1), "%Y-%m-%d").date()).days
            except ValueError:
                age = None
            if age is not None and age >= s.disabled_policy_days:
                old.append(f"policy {p.id} '{p.name}' disabled {m.group(1)} ({age} days)")
                continue
        else:
            undated.append(f"policy {p.id} '{p.name}'")
    if old:
        add("FWL-04", FAIL, WARNING, "; ".join(old))
    elif undated:
        add("FWL-04", FAIL, INFO, "disabled with no date in the comments: " + ", ".join(undated))
    else:
        add("FWL-04", PASS, detail=f"{len(off)} disabled" if off else "none disabled")
    fam = b.family(c.model or (dev.inv.model if dev.inv else ""), b.min_firmware)
    if not fam or not c.version:
        add("FWL-05", NA, detail="no minimum for the model" if c.version else "no version in the backup header")
    elif version_key(c.version) < version_key(str(b.min_firmware[fam])):
        add("FWL-05", FAIL, WARNING, f"FortiOS {c.version}, baseline minimum {b.min_firmware[fam]} for {fam}")
    else:
        add("FWL-05", PASS, detail=f"FortiOS {c.version}")


def _lifecycle(d: Data, dev: Device, add) -> None:
    b, s, inv, c = d.baseline, d.settings, dev.inv, dev.config
    model = (inv.model if inv else "") or (c.model if c else "")
    version = (inv.os_version if inv else "") or (c.version if c and c.platform != IOS else "")
    fam = b.family(model)
    if not fam:
        add("LCM-01", NA, detail=f"no approved list for {model or 'the model'}")
    elif not version and c and c.platform == IOS and not inv:
        add("LCM-01", NA, detail=f"only the release train ({c.version}) is in the configuration; add the device to the inventory")
    elif not version:
        add("LCM-01", FAIL, WARNING, "no OS version in the inventory or the backup")
    else:
        ok = [str(v) for v in b.approved_versions[fam]]
        if any(version_key(version) == version_key(v) for v in ok):
            add("LCM-01", PASS, detail=version)
        elif not ok:
            add("LCM-01", FAIL, WARNING, f"{version}: no approved version for {fam}, replace")
        else:
            add("LCM-01", FAIL, WARNING, f"{version} not approved for {fam} (approved: {', '.join(ok)})")
    eos = inv.end_of_support if inv else None
    if not eos:
        add("LCM-02", NA, detail="no end of support date")
    else:
        days = (eos - d.today).days
        if days < 0:
            add("LCM-02", FAIL, CRITICAL, f"{model} out of vendor support since {eos:%d %b %Y}")
        elif days <= s.eos_warning_days:
            add("LCM-02", FAIL, WARNING, f"{model} end of support {eos:%d %b %Y}, in {days} days")
        else:
            add("LCM-02", PASS, detail=f"end of support {eos:%d %b %Y}")


def _inventory(d: Data, dev: Device, add) -> None:
    inv, c = dev.inv, dev.config
    if inv is None:
        add("INV-01", FAIL, WARNING, f"{dev.path} has no inventory row" + (f" ({c.model} {c.serial})".rstrip() if c and c.model else ""))
        add("INV-02", NA)
        return
    add("INV-01", PASS)
    if c is None:
        add("INV-02", NA, detail="no configuration")
        return
    bad = []
    if c.hostname and c.hostname.lower() != inv.hostname.lower():
        bad.append(f"hostname {c.hostname} in the configuration")
    if c.model and inv.model and compact(c.model) not in compact(inv.model):
        bad.append(f"model {c.model} in the configuration, {inv.model} in the inventory")
    if c.serial and inv.serial and c.serial.upper() != inv.serial.upper():
        bad.append(f"serial {c.serial} in the configuration, {inv.serial} in the inventory")
    add("INV-02", FAIL if bad else PASS, WARNING, "; ".join(bad))


# ---------------------------------------------------------------- the review

def device_status(results: list[Result]) -> str:
    sev = {r.severity for r in results if r.status == FAIL}
    return STATUS[CRITICAL] if CRITICAL in sev else STATUS[WARNING] if WARNING in sev else STATUS[None]


def review(d: Data) -> dict:
    devices = []
    for dev in d.devices:
        res = evaluate(d, dev)
        fails = [r for r in res if r.status == FAIL]
        devices.append({"device": dev, "results": res, "status": device_status(res),
                        "critical": sum(r.severity == CRITICAL for r in fails), "warning": sum(r.severity == WARNING for r in fails),
                        "codes": [r.code for r in fails if r.severity != INFO]})
    sites = defaultdict(list)
    for x in devices:
        sites[x["device"].site].append(x)
    site_rows = []
    for code in sorted(sites, key=lambda k: (k == "", list(d.settings.sites).index(k) if k in d.settings.sites else 99, k)):
        xs = sites[code]
        st = min((x["status"] for x in xs), key=lambda v: STATUS_ORDER[v])
        site_rows.append({"site": code, "name": d.settings.site_name(code), "devices": len(xs), "status": st,
                          "counts": Counter(x["status"] for x in xs), "critical": sum(x["critical"] for x in xs),
                          "warning": sum(x["warning"] for x in xs),
                          "rooms": sorted({x["device"].inv.room for x in xs if x["device"].inv and x["device"].inv.room})})
    return {"devices": devices, "sites": site_rows}


def window_for(severity: str, d: Data) -> str:
    w = d.settings.windows()
    if severity == INFO or not w:
        return ""
    pick = w[0] if severity == CRITICAL or len(w) == 1 else w[1]
    return f"{pick[0]} ({pick[1]:%a %d %b %H:%M})"


def run_all(d: Data, rv: dict | None = None) -> list[Finding]:
    rv = rv if rv is not None else review(d)
    hits = defaultdict(list)
    for x in rv["devices"]:
        for r in x["results"]:
            if r.status == FAIL:
                hits[(r.code, r.severity)].append((x["device"], r))
    out = []
    for code, (rule, owner, fix) in RULES.items():
        for sev in (CRITICAL, WARNING, INFO):
            xs = hits.get((code, sev), [])
            if not xs:
                continue
            subject = f"{rule}: fails on {_n(len(xs), 'device')}"
            if sev == INFO:
                subject = f"For information ({code}): {subject}"
            detail = _top([f"{dev.hostname}: {r.detail}" for dev, r in xs], 8, "; ")
            out.append(Finding(sev, PREFIX[code.split("-")[0]], code, subject, detail,
                               fix if sev != INFO else "No change needed; review at the next weekly review.", d.settings.owner(owner),
                               [dev.hostname for dev, _ in xs], sorted({dev.site for dev, _ in xs if dev.site}), window_for(sev, d)))
    out.sort(key=lambda f: (ORDER[f.severity], AREAS.index(f.area), f.code))
    return out


def area_status(findings: list[Finding]) -> dict[str, str]:
    st = {}
    for a in AREAS:
        sev = [f.severity for f in findings if f.area == a and f.severity != INFO]
        st[a] = CRITICAL if CRITICAL in sev else WARNING if sev else "ok"
    return st


def overall(rv: dict) -> str:
    sts = [x["status"] for x in rv["devices"]]
    return min(sts, key=lambda v: STATUS_ORDER[v]) if sts else COMPLIANT


def summary(d: Data, rv: dict) -> dict:
    res = [r for x in rv["devices"] for r in x["results"]]
    checked = [r for r in res if r.status in (PASS, FAIL) and not (r.status == FAIL and r.severity == INFO)]
    passed = sum(r.status == PASS for r in checked)
    st = Counter(x["status"] for x in rv["devices"])
    backed = [x for x in rv["devices"] if x["device"].inv]
    return dict(
        devices=len(rv["devices"]), sites=len(rv["sites"]), compliant=st[COMPLIANT], drift=st[DRIFT], noncompliant=st[NONCOMPLIANT],
        checks=len(checked), passed=passed, pass_rate=passed / len(checked) if checked else None,
        missing=sum(1 for x in backed if not x["device"].config),
        stale=sum(1 for x in rv["devices"] for r in x["results"] if r.code == "BKP-02" and r.status == FAIL),
        unsaved=sum(1 for x in rv["devices"] for r in x["results"] if r.code == "BKP-03" and r.status == FAIL),
        unplanned=sum(1 for x in rv["devices"] for r in x["results"] if r.code == "BKP-04" and r.status == FAIL),
        lifecycle=sum(1 for x in rv["devices"] for r in x["results"] if r.code.startswith("LCM") and r.status == FAIL),
        eos=sum(1 for x in rv["devices"] for r in x["results"] if r.code == "LCM-02" and r.status == FAIL and r.severity == CRITICAL),
        platforms=Counter(x["device"].platform for x in rv["devices"]),
    )


__all__ = ["AREAS", "RULES", "CRITICAL", "WARNING", "INFO", "PASS", "FAIL", "NA", "COMPLIANT", "DRIFT", "NONCOMPLIANT", "Result", "Finding",
           "evaluate", "review", "run_all", "summary", "area_status", "overall", "window_for", "short"]
