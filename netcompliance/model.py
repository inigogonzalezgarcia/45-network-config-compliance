"""Loading: the comms-room inventory (a Device42-style export: hostname, site, room, rack, role, vendor, model, OS version, serial, management
IP, last backup and end of support), the configuration backups in configs/ (one file per device, as Oxidized or RANCID store them or as
copied by hand), the baseline (golden rules and approved versions per model family), the optional approved changes, and the settings.
Forgiving column names, into plain dataclasses."""
from __future__ import annotations

import csv
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from .parsers import ARUBA, FORTIOS, IOS, DeviceConfig, detect, parse

INVENTORY_ALIASES = {
    "hostname": ["hostname", "name", "device name", "device"],
    "site": ["site", "building", "location"],
    "room": ["room", "comms room", "room name"],
    "rack": ["rack", "rack name"],
    "role": ["role", "device role", "service level", "tags"],
    "vendor": ["vendor", "manufacturer", "hw vendor"],
    "model": ["model", "hw model", "hardware", "hardware model"],
    "os_version": ["os version", "os_version", "software version", "firmware"],
    "serial": ["serial", "serial no", "serial_no", "serial number"],
    "mgmt_ip": ["mgmt ip", "management ip", "ip address", "ip", "primary ip"],
    "last_backup": ["last backup", "last_backup", "backup time", "last config backup"],
    "end_of_support": ["end of support", "end_of_support", "eos", "last date of support", "ldos"],
}
BACKUP_LOG_ALIASES = {
    "hostname": ["hostname", "node", "name"],
    "last_backup": ["collected at", "collected_at", "last backup", "time", "last success"],
    "result": ["result", "status"],
}
CHANGE_ALIASES = {
    "ticket": ["number", "ticket", "change", "change number"],
    "hostname": ["configuration item", "configuration_item", "cmdb ci", "cmdb_ci", "hostname", "device"],
    "start": ["planned start", "planned_start", "start date", "start_date", "start"],
    "end": ["planned end", "planned_end", "end date", "end_date", "end"],
    "approval": ["approval", "approval status", "state", "status"],
    "summary": ["short description", "short_description", "summary", "description"],
}
APPROVED = {"approved", "scheduled", "implement", "review", "closed", "authorized", "authorised"}
DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M", "%d/%m/%Y")
DEFAULT_OWNERS = {"backup": "Network operations", "management": "Network engineering", "logging": "Network engineering",
                  "switching": "Network engineering", "firewall": "Security engineering", "lifecycle": "Infrastructure manager",
                  "inventory": "CMDB / Device42 owner"}
CONFIG_SUFFIXES = (".cfg", ".conf", ".txt", "")


def _norm(s) -> str:
    s = unicodedata.normalize("NFKD", str(s or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(ch for ch in s if not unicodedata.combining(ch))).strip()


def compact(s) -> str:
    """Model names compared without case, spaces, punctuation or the FortiGate prefixes: 'FortiGate 100F' and 'FG100F' -> '100F'."""
    x = re.sub(r"[^A-Z0-9]", "", str(s or "").upper())
    return re.sub(r"^(FORTIGATE|FGT|FG)", "", x)


def parse_dt(v) -> datetime | None:
    s = str(v or "").strip()
    if not s:
        return None
    s = re.sub(r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})$", "", s)
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            continue
    return None


def parse_d(v) -> date | None:
    x = parse_dt(v)
    return x.date() if x else None


def num(v) -> float | None:
    try:
        return float(str(v).strip()) if str(v or "").strip() else None
    except ValueError:
        return None


def version_key(v: str) -> tuple:
    """'17.09.05a' -> (17, 9, 5, 'a'); 'WC.16.11.0012' -> ('wc', 16, 11, 12); comparable within one family."""
    out = []
    for part in re.findall(r"\d+|[A-Za-z]+", str(v or "")):
        out.append(int(part) if part.isdigit() else part.lower())
    return tuple(out)


def same_version(a: str, b: str) -> bool:
    return bool(a) and bool(b) and version_key(a) == version_key(b)


def _read(path: Path) -> tuple[list[str], list[dict]]:
    with open(path, newline="", encoding="utf-8-sig") as fh:
        header = fh.readline()
        fh.seek(0)
        delim = max(",;\t", key=header.count)
        reader = csv.DictReader(fh, delimiter=delim)
        return list(reader.fieldnames or []), list(reader)


def _map(fields: list[str], aliases: dict[str, list[str]]) -> dict[str, str]:
    heads = {_norm(h): h for h in fields}
    cols = {}
    for k, names in aliases.items():
        for n in names + [k.replace("_", " ")]:
            if _norm(n) in heads and heads[_norm(n)] not in cols.values():
                cols[k] = heads[_norm(n)]
                break
    return cols


def _rows(path: Path, aliases: dict[str, list[str]]) -> list[dict]:
    fields, raw = _read(path)
    cols = _map(fields, aliases)
    return [{k: (r.get(c) or "").strip() for k, c in cols.items()} for r in raw]


def platform_of(vendor: str, model: str) -> str:
    v = _norm(f"{vendor} {model}")
    if "forti" in v:
        return FORTIOS
    if "aruba" in v or v.startswith("hp") or " hp" in f" {v}" or "procurve" in v:
        return ARUBA
    return IOS


@dataclass
class InventoryItem:
    hostname: str
    site: str = ""
    room: str = ""
    rack: str = ""
    role: str = ""
    vendor: str = ""
    model: str = ""
    os_version: str = ""
    serial: str = ""
    mgmt_ip: str = ""
    last_backup: datetime | None = None
    end_of_support: date | None = None

    @property
    def platform(self) -> str:
        return platform_of(self.vendor, self.model)


@dataclass
class Change:
    ticket: str
    hostname: str
    start: datetime | None = None
    end: datetime | None = None
    approval: str = ""
    summary: str = ""

    @property
    def approved(self) -> bool:
        return _norm(self.approval) in APPROVED

    def covers(self, when: datetime) -> bool:
        if not self.start:
            return False
        if self.end and self.end > self.start:
            return self.start <= when <= self.end
        return self.start.date() == when.date()


@dataclass
class Device:
    hostname: str
    inv: InventoryItem | None
    config: DeviceConfig | None
    path: str = ""
    site_hint: str = ""

    @property
    def platform(self) -> str:
        if self.config:
            return self.config.platform
        return self.inv.platform if self.inv else IOS

    @property
    def site(self) -> str:
        return self.inv.site if self.inv else self.site_hint

    @property
    def role(self) -> str:
        return _norm(self.inv.role) if self.inv else ""

    @property
    def is_switch(self) -> bool:
        return self.role in ("core", "access", "distribution") or (self.inv is None and self.platform == ARUBA)


@dataclass
class Baseline:
    ntp_servers: list = field(default_factory=list)
    syslog_hosts: list = field(default_factory=list)
    timezone: dict = field(default_factory=dict)          # platform -> value of clock timezone / time timezone
    max_idle_minutes: int = 15
    parking_vlan: int = 999
    native_vlan: int | None = None
    port_security_sites: list = field(default_factory=list)
    unused_descriptions: list = field(default_factory=lambda: ["unused", "spare", "free", "parking"])
    approved_versions: dict = field(default_factory=dict)  # model family -> [versions]
    min_firmware: dict = field(default_factory=dict)       # FortiGate model family -> minimum FortiOS version
    snmp_forbidden: list = field(default_factory=lambda: ["public", "private"])

    def family(self, model: str, table: dict | None = None) -> str:
        table = self.approved_versions if table is None else table
        m = compact(model)
        hits = [k for k in table if compact(k) and compact(k) in m]
        return max(hits, key=lambda k: (len(compact(k)), k)) if hits else ""


def baseline_from_dict(raw: dict) -> Baseline:
    b = Baseline()
    for k, v in raw.items():
        if k.startswith("_") or not hasattr(b, k) or v is None:
            continue
        if k in ("max_idle_minutes", "parking_vlan"):
            setattr(b, k, int(v))
        elif k == "native_vlan":
            b.native_vlan = int(v)
        elif k in ("approved_versions", "min_firmware", "timezone"):
            setattr(b, k, {str(a): b2 for a, b2 in v.items()})
        elif k in ("unused_descriptions", "snmp_forbidden"):
            setattr(b, k, [str(x).lower() for x in v])
        else:
            setattr(b, k, list(v))
    return b


@dataclass
class Settings:
    organisation: str = "Network configuration compliance"
    as_of: datetime | None = None
    backup_max_days: int = 7
    backup_critical_days: int = 30
    unsaved_critical_hours: int = 24
    eos_warning_days: int = 180
    disabled_policy_days: int = 90
    sites: dict = field(default_factory=dict)              # code -> name
    change_windows: list = field(default_factory=list)     # [{"name": ..., "start": ...}]
    owners: dict = field(default_factory=lambda: dict(DEFAULT_OWNERS))

    def owner(self, area: str) -> str:
        return self.owners.get(area) or DEFAULT_OWNERS.get(area, "Network operations")

    def site_name(self, code: str) -> str:
        return self.sites.get(code, code) if code else "(no site)"

    def windows(self) -> list[tuple[str, datetime]]:
        out = [(str(w.get("name", "")), parse_dt(w.get("start"))) for w in self.change_windows]
        return sorted([(n, d) for n, d in out if d], key=lambda x: x[1])


def settings_from_dict(raw: dict) -> Settings:
    s = Settings()
    for k, v in raw.items():
        if not hasattr(s, k) or v is None:
            continue
        cur = getattr(s, k)
        if k == "as_of":
            s.as_of = parse_dt(v)
        elif k == "change_windows":
            s.change_windows = [dict(x) for x in v]
        elif k == "owners":
            cur.update({str(a): b for a, b in v.items()})
        elif k == "sites":
            s.sites = {str(a): str(b) for a, b in v.items()}
        elif isinstance(cur, int):
            setattr(s, k, int(num(v) or 0))
        else:
            setattr(s, k, v)
    return s


@dataclass
class Data:
    settings: Settings
    baseline: Baseline
    as_of: datetime
    devices: list[Device] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    sources: dict = field(default_factory=dict)

    @property
    def today(self) -> date:
        return self.as_of.date()


def load_inventory(path: Path) -> list[InventoryItem]:
    out = []
    for r in _rows(path, INVENTORY_ALIASES):
        if not r.get("hostname"):
            continue
        out.append(InventoryItem(r["hostname"].strip(), r.get("site", ""), r.get("room", ""), r.get("rack", ""), r.get("role", ""),
                                 r.get("vendor", ""), r.get("model", ""), r.get("os_version", ""), r.get("serial", ""), r.get("mgmt_ip", ""),
                                 parse_dt(r.get("last_backup")), parse_d(r.get("end_of_support"))))
    return out


def load_changes(path: Path) -> list[Change]:
    return [Change(r["ticket"], r.get("hostname", "").strip(), parse_dt(r.get("start")), parse_dt(r.get("end")), r.get("approval", ""),
                   r.get("summary", "")) for r in _rows(path, CHANGE_ALIASES) if r.get("ticket")]


def load_configs(folder: Path) -> dict[str, tuple[DeviceConfig, str]]:
    """configs/<hostname>.cfg (also .conf, .txt or no extension, as Oxidized and RANCID store them). The key is the file name without the
    extension, lower case."""
    out = {}
    if not folder.is_dir():
        return out
    for p in sorted(folder.iterdir()):
        if not p.is_file() or p.name.startswith(".") or p.suffix.lower() not in CONFIG_SUFFIXES:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            continue
        out[p.stem.lower() if p.suffix else p.name.lower()] = (parse(text, detect(text)), f"configs/{p.name}")
    return out


FILES = {
    "inventory.csv": "Comms-room inventory: hostname, site, room, rack, role, vendor, model, OS version, serial, management IP, last backup, "
                     "end of support (Device42 export)",
    "configs/": "Configuration backups, one file per device (Oxidized, RANCID, the collector in scripts/ or copied by hand)",
    "baseline.json": "Golden rules per platform and approved OS versions per model family",
    "changes.csv": "Approved change tickets per device and window (optional)",
    "backup_log.csv": "Collection log of the collector in scripts/ (optional; newer backup times override the inventory)",
}


def load(folder: Path, as_of: datetime | None = None) -> Data:
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"no folder {folder}")
    sp = folder / "settings.json"
    s = settings_from_dict(json.loads(sp.read_text(encoding="utf-8"))) if sp.exists() else Settings()
    bp = folder / "baseline.json"
    if not bp.exists():
        raise FileNotFoundError(f"{folder}: need baseline.json ({FILES['baseline.json']})")
    b = baseline_from_dict(json.loads(bp.read_text(encoding="utf-8")))
    ip = folder / "inventory.csv"
    if not ip.exists():
        raise FileNotFoundError(f"{folder}: need inventory.csv ({FILES['inventory.csv']})")
    inv = load_inventory(ip)
    if not inv:
        raise ValueError(f"{ip}: no devices (check the hostname column)")
    lp = folder / "backup_log.csv"
    if lp.exists():
        by = {i.hostname.lower(): i for i in inv}
        for r in _rows(lp, BACKUP_LOG_ALIASES):
            it, when = by.get(r.get("hostname", "").lower()), parse_dt(r.get("last_backup"))
            if it and when and _norm(r.get("result", "ok")) in ("ok", "success", "") and (not it.last_backup or when > it.last_backup):
                it.last_backup = when
    cfgs = load_configs(folder / "configs")
    when = as_of or s.as_of or datetime.now().replace(second=0, microsecond=0)
    d = Data(s, b, when)
    seen = set()
    for it in inv:
        key = it.hostname.lower()
        seen.add(key)
        cfg = cfgs.get(key)
        d.devices.append(Device(it.hostname, it, cfg[0] if cfg else None, cfg[1] if cfg else ""))
    for key in sorted(set(cfgs) - seen):
        cfg, path = cfgs[key]
        name = cfg.hostname or key
        prefix = name.split("-", 1)[0].upper()
        d.devices.append(Device(name, None, cfg, path, prefix if prefix in s.sites else ""))
    d.devices.sort(key=lambda x: (x.site == "", x.site, x.hostname.lower()))
    cp = folder / "changes.csv"
    if cp.exists():
        d.changes = load_changes(cp)
    d.sources = {"inventory.csv": len(inv), "configs/": len(cfgs), "baseline.json": 1}
    if cp.exists():
        d.sources["changes.csv"] = len(d.changes)
    if lp.exists():
        d.sources["backup_log.csv"] = len(_rows(lp, BACKUP_LOG_ALIASES))
    return d


__all__ = ["Data", "Device", "InventoryItem", "Change", "Baseline", "Settings", "load", "load_inventory", "load_changes", "load_configs",
           "baseline_from_dict", "settings_from_dict", "version_key", "same_version", "compact", "FILES", "IOS", "ARUBA", "FORTIOS"]
