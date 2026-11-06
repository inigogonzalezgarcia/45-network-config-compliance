"""Parsers for the three configuration formats, kept to what the checks read:

- Cisco IOS and IOS-XE `show running-config` (with the `! Last configuration change at ...` and `! NVRAM config last updated at ...`
  header lines when present);
- HPE Aruba ArubaOS-Switch (ProCurve-style) `show running-config`;
- Fortinet FortiOS `show` / `show full-configuration` (`config ... edit ... set ... next ... end` blocks).

Each parser returns a `DeviceConfig` with the same fields, so the checks do not care which platform they look at. A value of None means
"not applicable to this platform" or "not visible in the configuration"; the checks then mark the rule n/a."""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime

IOS, ARUBA, FORTIOS = "ios", "aruba", "fortios"
PLATFORM_LABEL = {IOS: "Cisco IOS / IOS-XE", ARUBA: "ArubaOS-Switch", FORTIOS: "FortiOS"}
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PHYSICAL = re.compile(r"^(FastEthernet|GigabitEthernet|TwoGigabitEthernet|FiveGigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|"
                      r"FortyGigabitEthernet|HundredGigE)\d+/\d+(/\d+)?$")


@dataclass
class Port:
    name: str
    description: str = ""
    mode: str = ""            # access, trunk or "" (not set)
    vlan: int = 1             # access VLAN (untagged VLAN on ArubaOS-Switch)
    native: int = 1           # native VLAN of a trunk (untagged VLAN of a tagged port on ArubaOS-Switch)
    shutdown: bool = False
    portfast: bool = False
    bpduguard: bool = False
    port_security: bool = False


@dataclass
class FgInterface:
    name: str
    role: str = ""
    allowaccess: list = field(default_factory=list)
    ip: str = ""
    dedicated_mgmt: bool = False


@dataclass
class FgAdmin:
    name: str
    trusthosts: list = field(default_factory=list)
    profile: str = ""


@dataclass
class FgPolicy:
    id: str
    name: str = ""
    srcintf: list = field(default_factory=list)
    dstintf: list = field(default_factory=list)
    srcaddr: list = field(default_factory=list)
    dstaddr: list = field(default_factory=list)
    service: list = field(default_factory=list)
    action: str = "deny"
    logtraffic: str = "utm"
    status: str = "enable"
    comments: str = ""


@dataclass
class DeviceConfig:
    platform: str
    hostname: str = ""
    model: str = ""
    serial: str = ""
    version: str = ""
    last_change: datetime | None = None
    last_change_by: str = ""
    last_saved: datetime | None = None
    ssh_v2: bool | None = None
    telnet: bool | None = None
    telnet_where: str = ""
    transport_unset: str = ""                             # IOS: VTY lines without an explicit transport input
    password_encryption: bool | None = None
    enable_secret: bool | None = None
    enable_password: bool | None = None
    aaa_remote: bool | None = None
    aaa_local: bool | None = None
    aaa_detail: str = ""
    banner: bool | None = None
    idle: list = field(default_factory=list)              # (where, minutes or 0 for never)
    restricted: bool | None = None
    restricted_detail: str = ""
    ntp: list = field(default_factory=list)
    syslog: list = field(default_factory=list)
    timezone: str | None = None
    snmp_communities: list = field(default_factory=list)
    snmp_v3: bool = False
    ports: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)        # FortiOS
    admins: list = field(default_factory=list)            # FortiOS
    policies: list = field(default_factory=list)          # FortiOS


def detect(text: str) -> str:
    head = text.lstrip()[:400]
    if head.startswith("#config-version=") or re.search(r"^config system global", text, re.M):
        return FORTIOS
    if re.match(r";\s*\S+ Configuration Editor;", head):
        return ARUBA
    return IOS


def parse(text: str, platform: str | None = None) -> DeviceConfig:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    p = platform or detect(text)
    return {IOS: parse_ios, ARUBA: parse_aruba, FORTIOS: parse_fortios}[p](text)


# ---------------------------------------------------------------- Cisco IOS / IOS-XE

def ios_time(line: str) -> tuple[datetime | None, str]:
    """`! Last configuration change at 02:14:37 CET Wed Nov 4 2026 by netadmin` -> (datetime, user). The time zone is the device's
    `clock timezone` and is kept as local time."""
    m = re.search(r"at (\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)? \S+ \w{3} (\w{3}) +(\d{1,2}) (\d{4})(?: by (\S+))?", line)
    if not m or m.group(4).lower() not in MONTHS:
        return None, ""
    hh, mm, ss, mon, day, year, who = m.groups()
    return datetime(int(year), MONTHS[mon.lower()], int(day), int(hh), int(mm), int(ss)), who or ""


def ios_blocks(text: str) -> tuple[list[str], list[tuple[str, list[str]]], list[str]]:
    """Top-level lines, blocks (a top-level line with its indented children) and the header comment lines."""
    top, blocks, comments = [], [], []
    lines = text.split("\n")
    i = 0
    cur = None
    while i < len(lines):
        raw = lines[i].rstrip()
        i += 1
        if not raw.strip():
            continue
        if raw.startswith("!"):
            comments.append(raw)
            cur = None
            continue
        if raw.startswith("banner "):
            parts = raw.split(None, 2)
            top.append(" ".join(parts[:2]))
            rest = parts[2] if len(parts) > 2 else ""
            delim = rest[:2] if rest.startswith("^") else rest[:1]
            if delim and rest[len(delim):].find(delim) < 0:
                while i < len(lines) and delim not in lines[i]:
                    i += 1
                i += 1
            cur = None
            continue
        if raw[0] == " ":
            if cur is not None:
                cur[1].append(raw.strip())
            continue
        top.append(raw)
        cur = (raw, [])
        blocks.append(cur)
    return top, blocks, comments


def parse_ios(text: str) -> DeviceConfig:
    c = DeviceConfig(IOS)
    top, blocks, comments = ios_blocks(text)
    for line in comments:
        if "Last configuration change at" in line:
            c.last_change, c.last_change_by = ios_time(line)
        elif "NVRAM config last updated at" in line:
            c.last_saved, _ = ios_time(line)
    groups = {"tacacs+": "tacacs+", "radius": "radius"}
    login = ""
    c.ssh_v2 = False
    c.password_encryption = False
    c.enable_secret = c.enable_password = False
    c.banner = False
    aaa_new = False
    pf_default = bpdu_default = False
    for line in top:
        w = line.split()
        if line.startswith("hostname "):
            c.hostname = w[1]
        elif line.startswith("version ") and not c.version:
            c.version = w[1]
        elif line == "ip ssh version 2":
            c.ssh_v2 = True
        elif line == "service password-encryption":
            c.password_encryption = True
        elif line.startswith("enable secret"):
            c.enable_secret = True
        elif line.startswith("enable password"):
            c.enable_password = True
        elif line == "aaa new-model":
            aaa_new = True
        elif line.startswith("aaa group server ") and len(w) >= 5:
            groups[w[4]] = w[3]
        elif line.startswith("aaa authentication login default "):
            login = " ".join(w[4:])
        elif line.startswith("banner login") or line.startswith("banner motd"):
            c.banner = True
        elif line.startswith("ntp server "):
            rest = w[2:]
            if rest[:1] == ["vrf"]:
                rest = rest[2:]
            if rest:
                c.ntp.append(rest[0])
        elif line.startswith("logging host "):
            c.syslog.append(w[2] if w[2] not in ("ipv4", "ipv6") else w[3])
        elif len(w) == 2 and w[0] == "logging" and IP.match(w[1]):
            c.syslog.append(w[1])
        elif line.startswith("clock timezone "):
            c.timezone = w[2]
        elif line.startswith("snmp-server community "):
            c.snmp_communities.append(w[2])
        elif line.startswith("snmp-server group ") and " v3 " in f" {line} ":
            c.snmp_v3 = True
        elif line.startswith("license udi pid "):
            c.model = w[3]
            if len(w) >= 6 and w[4] == "sn":
                c.serial = w[5]
        elif line == "spanning-tree portfast default" or line == "spanning-tree portfast edge default":
            pf_default = True
        elif line in ("spanning-tree portfast bpduguard default", "spanning-tree portfast edge bpduguard default"):
            bpdu_default = True
    # AAA: a remote group (TACACS+ or RADIUS) first, local as the fallback
    methods = login.split()
    remote = []
    k = 0
    while k < len(methods):
        if methods[k] == "group" and k + 1 < len(methods):
            remote.append(groups.get(methods[k + 1], ""))
            k += 2
        else:
            k += 1
    c.aaa_remote = aaa_new and any(g in ("tacacs+", "radius") for g in remote)
    c.aaa_local = aaa_new and "local" in methods
    c.aaa_detail = f"aaa authentication login default {login}" if login else ("aaa new-model without a login method list" if aaa_new
                                                                            else "no aaa new-model")
    # VTY lines: transport, exec-timeout, access-class
    telnet, unset, restricted = [], [], []
    vty = [(h, ch) for h, ch in blocks if h.startswith("line vty ")]
    for head, children in vty:
        where = head.replace("line ", "")
        tr = [x for x in children if x.startswith("transport input ")]
        if not tr:
            unset.append(where)
        elif any(t in tr[-1].split()[2:] for t in ("telnet", "all")):
            telnet.append(where)
        to = [x for x in children if x.startswith("exec-timeout ")]
        if to:
            parts = to[-1].split()
            mins = int(parts[1]) + (1 if len(parts) > 2 and int(parts[2]) > 0 else 0)
            c.idle.append((where, mins))
        else:
            c.idle.append((where, 10))          # IOS default: 10 minutes
        if not any(x.startswith("access-class ") and x.split()[-1] in ("in", "vrf-also") for x in children):
            restricted.append(where)
    c.telnet = bool(telnet)
    c.telnet_where = ("transport input telnet on " + ", ".join(telnet)) if telnet else ""
    c.transport_unset = ", ".join(unset)
    c.restricted = bool(vty) and not restricted
    c.restricted_detail = ("no access-class on " + ", ".join(restricted)) if restricted else ("no line vty" if not vty else "")
    # interfaces
    for head, children in blocks:
        if not head.startswith("interface "):
            continue
        name = head.split(None, 1)[1]
        if not PHYSICAL.match(name) or name == "GigabitEthernet0/0":
            continue
        p = Port(name)
        for x in children:
            w = x.split()
            if x.startswith("description "):
                p.description = x.split(None, 1)[1]
            elif x == "switchport mode access":
                p.mode = "access"
            elif x == "switchport mode trunk":
                p.mode = "trunk"
            elif x.startswith("switchport access vlan ") and w[3].isdigit():
                p.vlan = int(w[3])
            elif x.startswith("switchport trunk native vlan ") and w[4].isdigit():
                p.native = int(w[4])
            elif x == "shutdown":
                p.shutdown = True
            elif x.startswith("spanning-tree portfast") and "disable" not in x and "trunk" not in x:
                p.portfast = True
            elif x == "spanning-tree bpduguard enable":
                p.bpduguard = True
            elif x == "switchport port-security":
                p.port_security = True
        if p.mode == "access":
            p.portfast = p.portfast or pf_default
            p.bpduguard = p.bpduguard or (bpdu_default and p.portfast)
        c.ports.append(p)
    return c


# ---------------------------------------------------------------- ArubaOS-Switch

def aruba_ports(spec: str) -> list[str]:
    """`1-4,10,A1-A2` -> ['1', '2', '3', '4', '10', 'A1', 'A2']."""
    out = []
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ma, mb = re.match(r"([A-Za-z]*)(\d+)$", a), re.match(r"([A-Za-z]*)(\d+)$", b)
            if ma and mb and ma.group(1) == mb.group(1):
                out += [f"{ma.group(1)}{k}" for k in range(int(ma.group(2)), int(mb.group(2)) + 1)]
                continue
        out.append(part)
    return out


def _port_key(p: str):
    m = re.match(r"([A-Za-z]*)(\d+)$", p)
    return (m.group(1), int(m.group(2))) if m else (p, 0)


def parse_aruba(text: str) -> DeviceConfig:
    c = DeviceConfig(ARUBA)
    lines = text.split("\n")
    m = re.match(r";\s*(\S+) Configuration Editor; Created on release #(\S+)", lines[0].strip()) if lines else None
    if m:
        c.model, c.version = m.group(1), m.group(2)
    blocks: list[tuple[str, list[str]]] = []
    top: list[str] = []
    cur = None
    for raw in lines:
        s = raw.strip()
        if not s or s.startswith(";"):
            continue
        if raw.startswith(" ") and cur is not None:
            if s != "exit":
                cur[1].append(s)
            else:
                cur = None
            continue
        top.append(s)
        if re.match(r"^(interface|vlan) \S+$", s):
            cur = (s, [])
            blocks.append(cur)
        else:
            cur = None
    c.telnet = True
    c.telnet_where = "telnet-server enabled (no 'no telnet-server')"
    c.banner = False
    c.restricted = False
    c.restricted_detail = "no ip authorized-managers"
    idle = 0
    remote_servers = False
    login = ""
    edge, bpdu, psec = set(), set(), set()
    for s in top:
        w = s.split()
        if s.startswith("hostname "):
            c.hostname = s.split(None, 1)[1].strip('"')
        elif s == "no telnet-server":
            c.telnet, c.telnet_where = False, ""
        elif s.startswith("console idle-timeout ") and w[2].isdigit():
            idle = int(w[2])
        elif s.startswith("banner motd") or s.startswith("banner exec"):
            c.banner = True
        elif s.startswith("ip authorized-managers "):
            c.restricted, c.restricted_detail = True, ""
        elif s.startswith("tacacs-server host ") or s.startswith("radius-server host "):
            remote_servers = True
        elif s.startswith("aaa authentication ssh login "):
            login = " ".join(w[4:])
        elif s.startswith("ntp server ") and len(w) > 2:
            c.ntp.append(w[2])
        elif s.startswith("sntp server priority ") and len(w) > 4:
            c.ntp.append(w[4])
        elif w[0] == "logging" and len(w) > 1 and IP.match(w[1]):
            c.syslog.append(w[1])
        elif s.startswith("time timezone "):
            c.timezone = w[2]
        elif s.startswith("snmp-server community "):
            c.snmp_communities.append(w[2].strip('"'))
        elif s == "snmpv3 enable":
            c.snmp_v3 = True
        elif w[0] == "spanning-tree" and len(w) == 3 and w[2] == "admin-edge-port":
            edge.update(aruba_ports(w[1]))
        elif w[0] == "spanning-tree" and len(w) == 3 and w[2] == "bpdu-protection":
            bpdu.update(aruba_ports(w[1]))
        elif w[0] == "port-security" and len(w) >= 3 and w[2] == "learn-mode":
            psec.update(aruba_ports(w[1]))
    methods = login.split()
    c.aaa_remote = remote_servers and bool(methods) and methods[0] in ("tacacs", "radius")
    c.aaa_local = "local" in methods[1:]
    c.aaa_detail = f"aaa authentication ssh login {login}" if login else "no aaa authentication ssh login"
    c.idle.append(("console idle-timeout", (idle + 59) // 60 if idle else 0))
    ports: dict[str, Port] = {}
    untagged, tagged = {}, {}
    for head, ch in blocks:
        kind, ident = head.split()
        if kind == "interface":
            p = ports.setdefault(ident, Port(ident))
            for x in ch:
                if x.startswith("name "):
                    p.description = x.split(None, 1)[1].strip('"')
                elif x == "disable":
                    p.shutdown = True
        elif ident.isdigit():
            for x in ch:
                w = x.split()
                if w[0] == "untagged" and len(w) > 1:
                    for q in aruba_ports(w[1]):
                        untagged[q] = int(ident)
                elif w[0] == "tagged" and len(w) > 1:
                    for q in aruba_ports(w[1]):
                        tagged.setdefault(q, []).append(int(ident))
    for q in set(untagged) | set(tagged):
        ports.setdefault(q, Port(q))
    for q, p in ports.items():
        p.vlan = p.native = untagged.get(q, 0)
        p.mode = "trunk" if q in tagged else "access"
        p.portfast, p.bpduguard, p.port_security = q in edge, q in bpdu, q in psec
    c.ports = [ports[k] for k in sorted(ports, key=_port_key)]
    return c


# ---------------------------------------------------------------- FortiOS

def fortios_tree(text: str) -> dict:
    """`config a b` / `edit x` / `set k v` / `unset k` / `next` / `end` into nested dicts. Tables (blocks with `edit`) become
    {name: {...}}; settings become {key: [values]}."""
    root: dict = {}
    stack = [root]
    for raw in text.split("\n"):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            w = shlex.split(s, posix=True)
        except ValueError:
            w = s.split()
        if not w:
            continue
        if w[0] == "config":
            node = stack[-1].setdefault(" ".join(w[1:]), {})
            stack.append(node)
        elif w[0] == "edit" and len(w) > 1:
            node = stack[-1].setdefault("__edit__", {}).setdefault(w[1], {})
            stack.append(node)
        elif w[0] in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif w[0] == "set" and len(w) > 1:
            stack[-1][w[1]] = w[2:]
    return root


def _v(node: dict, key: str, default: str = "") -> str:
    x = node.get(key)
    return " ".join(x) if isinstance(x, list) and x else default


def parse_fortios(text: str) -> DeviceConfig:
    c = DeviceConfig(FORTIOS)
    m = re.search(r"^#config-version=([A-Z0-9]+)-(\d+\.\d+\.\d+)-", text, re.M)
    if m:
        c.model, c.version = m.group(1), m.group(2)
    t = fortios_tree(text)
    g = t.get("system global", {})
    c.hostname = _v(g, "hostname")
    c.banner = _v(g, "pre-login-banner", "disable") == "enable"
    c.idle.append(("admintimeout", int(_v(g, "admintimeout", "5") or 5)))
    for name, x in t.get("system interface", {}).get("__edit__", {}).items():
        c.interfaces.append(FgInterface(name, _v(x, "role"), list(x.get("allowaccess", [])), " ".join(x.get("ip", [])[:1]),
                                        _v(x, "dedicated-to") == "management"))
    tel = [i.name for i in c.interfaces if "telnet" in i.allowaccess]
    c.telnet, c.telnet_where = bool(tel), ("telnet in allowaccess on " + ", ".join(tel)) if tel else ""
    for name, x in t.get("system admin", {}).get("__edit__", {}).items():
        th = [" ".join(v) for k, v in sorted(x.items()) if k.startswith("trusthost") and v and " ".join(v) not in ("0.0.0.0 0.0.0.0",)]
        c.admins.append(FgAdmin(name, th, _v(x, "accprofile")))
    open_admins = [a.name for a in c.admins if not a.trusthosts]
    c.restricted = bool(c.admins) and not open_admins
    c.restricted_detail = ("no trusted hosts on admin " + ", ".join(open_admins)) if open_admins else ""
    ntp = t.get("system ntp", {})
    if _v(ntp, "ntpsync", "enable") == "enable":
        if _v(ntp, "type", "fortiguard") == "custom":
            c.ntp = [_v(x, "server") for _, x in sorted(ntp.get("ntpserver", {}).get("__edit__", {}).items()) if _v(x, "server")]
        else:
            c.ntp = ["fortiguard"]
    for key in ("log syslogd setting", "log syslogd2 setting", "log syslogd3 setting", "log syslogd4 setting"):
        x = t.get(key, {})
        if _v(x, "status") == "enable" and _v(x, "server"):
            c.syslog.append(_v(x, "server"))
    for _, x in sorted(t.get("system snmp community", {}).get("__edit__", {}).items()):
        if _v(x, "status", "enable") == "enable":
            c.snmp_communities.append(_v(x, "name"))
    c.snmp_v3 = bool(t.get("system snmp user", {}).get("__edit__"))
    pols = t.get("firewall policy", {}).get("__edit__", {})
    for pid in sorted(pols, key=lambda k: int(k) if k.isdigit() else 0):
        x = pols[pid]
        c.policies.append(FgPolicy(pid, _v(x, "name"), list(x.get("srcintf", [])), list(x.get("dstintf", [])), list(x.get("srcaddr", [])),
                                   list(x.get("dstaddr", [])), list(x.get("service", [])), _v(x, "action", "deny"),
                                   _v(x, "logtraffic", "utm"), _v(x, "status", "enable"), _v(x, "comments")))
    return c


__all__ = ["DeviceConfig", "Port", "FgInterface", "FgAdmin", "FgPolicy", "parse", "detect", "IOS", "ARUBA", "FORTIOS", "PLATFORM_LABEL"]
