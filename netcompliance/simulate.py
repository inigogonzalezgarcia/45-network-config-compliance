"""Fictional demo: Tailspin Logistics, a made-up logistics company with three comms rooms (Madrid headquarters, the Zaragoza hub and the
Valencia port warehouse) and 33 network devices in the inventory: Cisco Catalyst 9300 and 9200 switches on IOS-XE, an old Catalyst
3750-X, Cisco ISR 4331 routers, HPE Aruba 2930F switches at Zaragoza and FortiGate 100F and 60F firewalls. Reviewed on Friday
6 November 2026. Every hostname, address, serial, ticket and person is made up; the addresses are private (RFC 1918) or documentation
ranges (RFC 5737). The problems are placed on purpose among the everyday ones."""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

ORG = "Tailspin Logistics"
SEED = 45
DOMAIN = "tailspin.example"
NTP = ["10.10.0.10", "10.10.0.11"]
OLD_NTP = "10.30.0.5"
SYSLOG = "10.10.0.20"
TACACS = ["10.10.0.31", "10.10.0.32"]
BANNER = "Authorised access only. Tailspin Logistics network. Activity is logged."
SITES = {"MAD": "Madrid HQ", "ZAZ": "Zaragoza hub", "VLC": "Valencia port warehouse"}
ROOMS = {"MAD": "Comms room B1", "ZAZ": "Comms room 0.12", "VLC": "Comms room GF"}
NET = {"MAD": "10.10", "ZAZ": "10.20", "VLC": "10.30"}
ASN = {"MAD": 65010, "ZAZ": 65020, "VLC": 65030}

SETTINGS = {
    "organisation": ORG,
    "as_of": "2026-11-06 08:00",
    "backup_max_days": 7,
    "backup_critical_days": 30,
    "unsaved_critical_hours": 24,
    "eos_warning_days": 180,
    "disabled_policy_days": 90,
    "sites": SITES,
    "change_windows": [{"name": "CW 2026-46", "start": "2026-11-10 22:00"}, {"name": "CW 2026-47", "start": "2026-11-17 22:00"}],
    "owners": {"backup": "Network operations (Marta Ibáñez)", "management": "Network engineering (Daniel Ferrer)",
               "logging": "Network engineering (Daniel Ferrer)", "switching": "Network engineering (Daniel Ferrer)",
               "firewall": "Security engineering (Lucía Prieto)", "lifecycle": "Infrastructure manager (Carlos Vidal)",
               "inventory": "Device42 owner (Marta Ibáñez)"},
}

BASELINE = {
    "_comment": "Golden rules of Tailspin Logistics (fictional). Versions are the ones this company approved, not vendor recommendations.",
    "ntp_servers": NTP,
    "syslog_hosts": [SYSLOG],
    "timezone": {"ios": "CET", "aruba": "60"},
    "max_idle_minutes": 15,
    "parking_vlan": 999,
    "native_vlan": 998,
    "port_security_sites": ["MAD"],
    "unused_descriptions": ["unused", "spare", "free", "parking"],
    "snmp_forbidden": ["public", "private"],
    "approved_versions": {"C9300": ["17.9.5", "17.12.4"], "C9200": ["17.9.5", "17.12.4"], "ISR4331": ["17.9.5", "17.12.4"],
                          "WS-C3750X": [], "2930F": ["WC.16.11.0012"], "FortiGate 100F": ["7.2.10", "7.4.7"],
                          "FortiGate 60F": ["7.2.10", "7.4.7"]},
    "min_firmware": {"FortiGate 100F": "7.2.10", "FortiGate 60F": "7.2.10"},
}

C9300_48P, C9300_24T, C9200_48P = "C9300-48P", "C9300-24T", "C9200-48P"
C3750X, ISR, ARUBA_M = "WS-C3750X-48P-S", "ISR4331/K9", "Aruba 2930F-48G-PoE+-4SFP+ (JL256A)"
FG100, FG60 = "FortiGate 100F", "FortiGate 60F"

# hostname, site, rack, role, vendor, model, os version, end of support
DEVICES = [
    ("MAD-CS01", "MAD", "R01", "core", "Cisco", C9300_24T, "17.12.4", ""),
    ("MAD-CS02", "MAD", "R01", "core", "Cisco", C9300_24T, "17.12.4", ""),
    ("MAD-RT01", "MAD", "R01", "router", "Cisco", ISR, "17.9.5", ""),
    ("MAD-RT02", "MAD", "R01", "router", "Cisco", ISR, "17.9.5", ""),
    ("MAD-FW01", "MAD", "R01", "firewall", "Fortinet", FG100, "7.2.10", ""),
    ("MAD-FW02", "MAD", "R01", "firewall", "Fortinet", FG100, "7.2.10", ""),
] + [(f"MAD-AS{k:02d}", "MAD", "R02" if k <= 5 else "R03", "access", "Cisco", C9300_48P, "17.9.5", "") for k in range(1, 10)] + [
    ("MAD-AS10", "MAD", "R04", "access", "Cisco", C3750X, "15.2(4)E10", "2021-10-31"),
    ("ZAZ-CS01", "ZAZ", "R01", "core", "HPE Aruba", ARUBA_M, "WC.16.11.0012", ""),
] + [(f"ZAZ-AS{k:02d}", "ZAZ", "R01" if k <= 3 else "R02", "access", "HPE Aruba", ARUBA_M, "WC.16.11.0012", "") for k in range(1, 7)] + [
    ("ZAZ-RT01", "ZAZ", "R01", "router", "Cisco", ISR, "17.9.5", ""),
    ("ZAZ-FW01", "ZAZ", "R01", "firewall", "Fortinet", FG60, "7.2.10", ""),
    ("VLC-CS01", "VLC", "R01", "core", "Cisco", C9300_24T, "17.9.5", ""),
] + [(f"VLC-AS{k:02d}", "VLC", "R01" if k <= 2 else "R02", "access", "Cisco", C9200_48P, "17.9.5", "") for k in range(1, 6)] + [
    ("VLC-RT01", "VLC", "R01", "router", "Cisco", ISR, "17.6.5", ""),
    ("VLC-FW01", "VLC", "R01", "firewall", "Fortinet", FG60, "7.4.7", ""),
]
EXTRA = ("VLC-AS06", "VLC", C9200_48P)          # a switch added during a project, backed up by Oxidized, never put in Device42
NO_BACKUP = {"ZAZ-AS06", "VLC-AS05"}
STALE = "2026-10-27 02:00"                       # Oxidized at Zaragoza stopped after a firewall rule change
NIGHTLY = "2026-11-06 02:00"
# planted problems
TELNET = {"ZAZ-AS03"}
PUBLIC = {"VLC-AS04", "ZAZ-AS05"}
OLD_NTP_ON = {"VLC-CS01", "VLC-AS01", "VLC-AS02", "VLC-AS03", "VLC-AS04"}
UNUSED_UP = {"MAD-AS04": 6}
UNSAVED = {"MAD-AS07": ("02:14:37 CET Wed Nov 4 2026", "netadmin", "18:02:11 CET Wed Oct 21 2026")}
# everyday ones
NO_BPDU = {"MAD-AS08": 2}
NO_PSEC = {"MAD-AS03": 2}
NATIVE1 = {"VLC-AS02"}
NO_SSHV2 = {"MAD-AS10"}
NO_IDLE = {"ZAZ-AS02"}
COMMUNITY = {"MAD-RT02": "tlog-mon"}
SERIAL_SWAP = {"MAD-AS06"}                       # replaced under RMA, Device42 still has the old serial
CHANGED = {"MAD-CS01": ("23:12:05 CET Tue Nov 3 2026", "dferrer", "23:14:40 CET Tue Nov 3 2026"),
           "VLC-RT01": ("22:37:51 CET Thu Nov 5 2026", "dferrer", "22:40:02 CET Thu Nov 5 2026")}
CHANGES = [
    ["CHG0045112", "MAD-CS01", "2026-11-03 22:00", "2026-11-04 00:00", "Approved", "Closed", "Add VLAN 140 for the new handheld scanners"],
    ["CHG0045120", "VLC-RT01", "2026-11-05 22:00", "2026-11-05 23:30", "Approved", "Implement", "QoS policy update on the MPLS uplink"],
    ["CHG0045131", "MAD-AS07", "2026-11-12 22:00", "2026-11-12 23:00", "Requested", "Assess",
     "Move the warehouse office ports to the new voice VLAN"],
    ["CHG0045140", "ZAZ-FW01", "2026-11-10 22:00", "2026-11-10 23:00", "Approved", "Scheduled", "Remove the temporary WMS cutover policy"],
]


def _serial(rnd: random.Random, model: str) -> str:
    al = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    if model.startswith("FortiGate"):
        return ("FG100FTK" if "100F" in model else "FGT60FTK") + str(rnd.randint(21000000, 23999999))
    if "Aruba" in model:
        return "SG" + str(rnd.randint(1, 3)) + "".join(rnd.choice(al) for _ in range(7))
    pre = {ISR: "FDO", C3750X: "FDO"}.get(model, rnd.choice(["FOC", "FCW"]))
    return f"{pre}{rnd.randint(2201, 2533)}X{''.join(rnd.choice(al) for _ in range(3))}"


def _hash(rnd: random.Random, n: int = 40) -> str:
    al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./"
    return "".join(rnd.choice(al) for _ in range(n))


def _ip(dev: dict) -> str:
    return dev["mgmt_ip"]


# ---------------------------------------------------------------- Cisco IOS / IOS-XE

def ios_config(dev: dict, rnd: random.Random, others: list[dict]) -> str:
    h, site, model = dev["hostname"], dev["site"], dev["model"]
    net = NET[site]
    xe = model != C3750X
    ver = {"15.2(4)E10": "15.2", "17.6.5": "17.6"}.get(dev["os_version"], dev["os_version"].rsplit(".", 1)[0])
    change, who, saved = CHANGED.get(h) or UNSAVED.get(h) or ("22:41:09 CET Wed Oct 14 2026", "mibanez", "22:43:51 CET Wed Oct 14 2026")
    saved_by = "netadmin" if h in UNSAVED else who
    L = ["Building configuration...", "", "Current configuration : {size} bytes", "!",
         f"! Last configuration change at {change} by {who}", f"! NVRAM config last updated at {saved} by {saved_by}", "!",
         f"version {ver}", "service timestamps debug datetime msec localtime show-timezone",
         "service timestamps log datetime msec localtime show-timezone", "service password-encryption", "!", f"hostname {h}", "!"]
    if xe and dev["role"] != "router":
        L += ["vrf definition Mgmt-vrf", " !", " address-family ipv4", " exit-address-family", "!"]
    L += ["logging buffered 64000 informational", "no logging console", f"enable secret 9 $9${_hash(rnd, 14)}${_hash(rnd, 43)}", "!",
          "aaa new-model", "!", "aaa group server tacacs+ ISE-TACACS", " server name ISE-01", " server name ISE-02", "!",
          "aaa authentication login default group ISE-TACACS local", "aaa authorization exec default group ISE-TACACS local",
          "aaa accounting exec default start-stop group ISE-TACACS", "!", "aaa session-id common",
          "clock timezone CET 1 0", "clock summer-time CEST recurring last Sun Mar 2:00 last Sun Oct 3:00", "!",
          f"ip domain name {DOMAIN}", "!", "login on-success log", "!"]
    if xe:
        L += [f"license udi pid {model} sn {dev['config_serial']}"]
    L += ["!", f"username netadmin privilege 15 secret 9 $9${_hash(rnd, 14)}${_hash(rnd, 43)}", "!"]
    if dev["role"] != "router":
        L += ["spanning-tree mode rapid-pvst", "spanning-tree extend system-id", "!"]
        vlans = [(10, "MGMT"), (110, "USERS"), (120, "PRINTERS"), (130, "WIFI-AP")] + ([(140, "SCANNERS")] if site == "MAD" else []) + \
                [(250, "TRANSIT")] * (dev["role"] == "core") + [(998, "NATIVE"), (999, "PARKING")]
        for v, n in vlans:
            L += [f"vlan {v}", f" name {n}", "!"]
        L += ports_ios(dev, rnd, others)
        L += ["interface Vlan1", " no ip address", " shutdown", "!", "interface Vlan10", f" ip address {_ip(dev)} 255.255.255.0", "!"]
        if dev["role"] == "core":
            L += ["interface Vlan250", f" ip address {net}.250.{4 + int(h[-1])} 255.255.255.248", "!", "ip routing", "!"]
        L += [f"ip default-gateway {net}.10.1" if dev["role"] == "access" else f"ip route 0.0.0.0 0.0.0.0 {net}.250.4", "!"]
    else:
        wan = {"MAD-RT01": "10.250.1.2", "MAD-RT02": "10.250.2.2", "ZAZ-RT01": "10.250.3.2", "VLC-RT01": "10.250.4.2"}[h]
        L += ["interface GigabitEthernet0/0/0", " description MPLS-WAN-CARRIER", f" ip address {wan} 255.255.255.252",
              " negotiation auto", "!", "interface GigabitEthernet0/0/1", f" description LAN-{site}-CS01",
              f" ip address {_ip(dev)} 255.255.255.248", " negotiation auto", "!", "interface GigabitEthernet0/0/2", " no ip address",
              " shutdown", " negotiation auto", "!",
              f"router bgp {ASN[site]}", " bgp log-neighbor-changes",
              f" neighbor {wan.rsplit('.', 1)[0]}.1 remote-as 65000", " !", " address-family ipv4",
              f"  network {net}.0.0 mask 255.255.0.0", f"  neighbor {wan.rsplit('.', 1)[0]}.1 activate", " exit-address-family", "!",
              f"ip route {net}.0.0 255.255.0.0 {net}.250.4", "!"]
    if h not in NO_SSHV2:
        L += ["ip ssh version 2"]
    L += ["!", "ip access-list standard MGMT-ACL", " 10 permit 10.10.0.0 0.0.0.255", " 20 deny   any log", "!",
          f"logging host {SYSLOG}", "!"]
    if h in PUBLIC:
        L += ["snmp-server community public RO"]
    if h in COMMUNITY:
        L += [f"snmp-server community {COMMUNITY[h]} RO MGMT-ACL"]
    L += ["snmp-server view NETMON-VIEW iso included", "snmp-server group NETMON v3 priv read NETMON-VIEW access MGMT-ACL",
          f"snmp-server location {SITES[site]}, {ROOMS[site]}, {dev['rack']}", "snmp-server contact Network operations", "!"]
    for k, ip in enumerate(TACACS, 1):
        L += [f"tacacs server ISE-0{k}", f" address ipv4 {ip}", f" key 7 {''.join(rnd.choice('0123456789ABCDEF') for _ in range(22))}"]
    L += ["!", "banner login ^C", BANNER, "^C", "!", "line con 0", " exec-timeout 10 0", " stopbits 1"]
    for a, b in (("0", "4"), ("5", "15")):
        L += [f"line vty {a} {b}", " access-class MGMT-ACL in vrf-also" if xe else " access-class MGMT-ACL in", " exec-timeout 10 0",
              " transport input ssh"]
    L += ["!"]
    for ip in ([OLD_NTP] if h in OLD_NTP_ON else NTP):
        L += [f"ntp server {ip}"]
    L += ["!", "!", "end", ""]
    text = "\n".join(L)
    return text.replace("{size}", str(len(text.split("!", 1)[1].encode("utf-8"))))


def ports_ios(dev: dict, rnd: random.Random, others: list[dict]) -> list[str]:
    h, site, model, role = dev["hostname"], dev["site"], dev["model"], dev["role"]
    L = []
    if model != C3750X:
        L += ["interface GigabitEthernet0/0", " vrf forwarding Mgmt-vrf", " no ip address", " shutdown", "!"]
    uplinks = ["TenGigabitEthernet1/1/" + str(k) for k in range(1, 5)]
    if model == C3750X:
        uplinks = uplinks[:2]
    n = 24 if model == C9300_24T else 48
    native = " switchport trunk native vlan 998"
    if role == "core":
        access = [o for o in others if o["site"] == site and o["role"] == "access"]
        edge = [o for o in others if o["site"] == site and o["role"] in ("router", "firewall")]
        for k in range(1, n + 1):
            name = f"GigabitEthernet1/0/{k}"
            if k <= len(access):
                L += [f"interface {name}", f" description DL-{access[k - 1]['hostname']}", native,
                      " switchport trunk allowed vlan 10,110,120,130" + (",140" if site == "MAD" else "") + ",998", " switchport mode trunk", "!"]
            elif k - len(access) <= len(edge):
                L += [f"interface {name}", f" description {edge[k - len(access) - 1]['hostname']}", " switchport access vlan 250",
                      " switchport mode access", "!"]
            else:
                L += [f"interface {name}", " switchport access vlan 999", " switchport mode access", " shutdown", "!"]
        for k, name in enumerate(uplinks, 1):
            if k <= 2 and site == "MAD":
                peer = "MAD-CS02" if h == "MAD-CS01" else "MAD-CS01"
                L += [f"interface {name}", f" description ISL-{peer}", native, " switchport mode trunk", "!"]
            else:
                L += [f"interface {name}", " switchport access vlan 999", " switchport mode access", " shutdown", "!"]
        return L
    used = rnd.randint(26, 42)
    up_unused = UNUSED_UP.get(h, 0)
    no_bpdu = set(rnd.sample(range(1, used + 1), NO_BPDU.get(h, 0)))
    no_psec = set(rnd.sample(range(1, used + 1), NO_PSEC.get(h, 0)))
    floor = 1 + int(h[-2:]) // 4
    for k in range(1, n + 1):
        name = f"GigabitEthernet1/0/{k}"
        L += [f"interface {name}"]
        if k <= used:
            if k % 12 == 0:
                desc, vlan = f"AP-{site}-P{floor}-{k // 12:02d}", 130
            elif k % 17 == 0:
                desc, vlan = f"PRN-{site}-P{floor}-{k // 17:02d}", 120
            else:
                desc, vlan = f"USR-{site}-P{floor}-{k:03d}", 110
            L += [f" description {desc}", f" switchport access vlan {vlan}", " switchport mode access"]
            if site == "MAD" and k not in no_psec:
                L += [" switchport port-security maximum 2", " switchport port-security violation restrict", " switchport port-security"]
            if k not in no_bpdu:
                L += [" spanning-tree portfast", " spanning-tree bpduguard enable"]
        elif k > n - up_unused:
            L += [" switchport mode access"]
        else:
            L += [" switchport access vlan 999", " switchport mode access", " shutdown", " spanning-tree portfast",
                  " spanning-tree bpduguard enable"]
        L += ["!"]
    cores = [o["hostname"] for o in others if o["site"] == site and o["role"] == "core"] or ["CS01"]
    for k, name in enumerate(uplinks, 1):
        L += [f"interface {name}"]
        if k <= 2:
            L += [f" description UPLINK-{cores[(k - 1) % len(cores)]}"]
            if not (h in NATIVE1 and k == 2):
                L += [native]
            L += [" switchport trunk allowed vlan 10,110,120,130" + (",140" if site == "MAD" else "") + ",998", " switchport mode trunk"]
        else:
            L += [" switchport access vlan 999", " switchport mode access", " shutdown"]
        L += ["!"]
    return L


# ---------------------------------------------------------------- ArubaOS-Switch

def _range(ports: list[int]) -> str:
    out, i = [], 0
    while i < len(ports):
        j = i
        while j + 1 < len(ports) and ports[j + 1] == ports[j] + 1:
            j += 1
        out.append(str(ports[i]) if i == j else f"{ports[i]}-{ports[j]}")
        i = j + 1
    return ",".join(out)


def aruba_config(dev: dict, rnd: random.Random, others: list[dict]) -> str:
    h, site = dev["hostname"], dev["site"]
    net = NET[site]
    ver = "".join(rnd.choice("0123456789abcdef") for _ in range(2))
    L = [f"; JL256A Configuration Editor; Created on release #{dev['os_version']}",
         "; Ver #14:01.4f.f8.1d.9b.3f.bf.bb.ef.7c.59.fc.6b.fb.9f.fc.ff.ff.37.ef:" + ver, f'hostname "{h}"', "module 1 type jl256a"]
    if h not in NO_IDLE:
        L += ["console idle-timeout 600", "console idle-timeout serial-usb 600"]
    if h not in TELNET:
        L += ["no telnet-server"]
    L += ["time daylight-time-rule western-europe", "time timezone 60", "timesync ntp", "ntp unicast"]
    L += [f"ntp server {ip} iburst" for ip in NTP]
    L += ["ntp enable", f'banner motd "{BANNER}"', "ip authorized-managers 10.10.0.0 255.255.255.0 access manager",
          f"ip default-gateway {net}.10.1", f"logging {SYSLOG}"]
    if h in PUBLIC:
        L += ['snmp-server community "public" unrestricted']
    L += ["snmpv3 enable"]
    L += [f"tacacs-server host {ip}" for ip in TACACS]
    L += ["aaa authentication ssh login tacacs local", "aaa authentication ssh enable tacacs local"]
    if dev["role"] == "core":
        access = [o["hostname"] for o in others if o["site"] == site and o["role"] == "access"]
        trunks = list(range(1, len(access) + 1))
        names = {k: f"DL-{access[k - 1]}" for k in trunks}
        users, parked = [], [k for k in range(len(access) + 1, 49)] + [51, 52]
        trunks += [49, 50]
        names.update({49: "UPLINK-ZAZ-RT01", 50: "UPLINK-ZAZ-FW01"})
    else:
        used = rnd.randint(24, 40)
        users = list(range(1, used + 1))
        parked = list(range(used + 1, 49)) + [51, 52]
        trunks = [49, 50]
        names = {k: f"USR-{site}-{k:03d}" for k in users}
        names.update({49: "UPLINK-ZAZ-CS01", 50: "UPLINK-ZAZ-CS01-2"})
    for k in sorted(set(names) | set(parked)):
        L += [f"interface {k}"]
        if k in names:
            L += [f'   name "{names[k]}"']
        if k in parked:
            L += ["   disable"]
        L += ["   exit"]
    L += ["vlan 1", '   name "DEFAULT_VLAN"', "   no untagged 1-52", "   no ip address", "   exit",
          "vlan 10", '   name "MGMT"', f"   tagged {_range(trunks)}", f"   ip address {_ip(dev)} 255.255.255.0", "   exit"]
    if users:
        L += ["vlan 110", '   name "USERS"', f"   untagged {_range(users)}", f"   tagged {_range(trunks)}", "   no ip address", "   exit"]
    else:
        L += ["vlan 110", '   name "USERS"', f"   tagged {_range(trunks)}", "   no ip address", "   exit"]
    L += ["vlan 998", '   name "NATIVE"', f"   untagged {_range(trunks)}", "   no ip address", "   exit",
          "vlan 999", '   name "PARKING"', f"   untagged {_range(parked)}", "   no ip address", "   exit", "spanning-tree"]
    if users:
        L += [f"spanning-tree {_range(users)} admin-edge-port", f"spanning-tree {_range(users)} bpdu-protection"]
    L += ["no tftp server", "no autorun", "no dhcp config-file-update", "no dhcp image-file-update", "password manager", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- FortiOS

def fortios_config(dev: dict, rnd: random.Random) -> str:
    h, site, model = dev["hostname"], dev["site"], dev["model"]
    net = NET[site]
    code = "FG100F" if "100F" in model else "FGT60F"
    build = {"7.2.10": "build1706-240918", "7.4.7": "build2731-250123"}[dev["os_version"]]
    wan_ip = {"MAD": "203.0.113.2", "ZAZ": "203.0.113.34", "VLC": "203.0.113.66"}[site]
    L = [f"#config-version={code}-{dev['os_version']}-FW-{build}:opmode=0:vdom=0:user=oxidized", "#conf_file_ver=" +
         str(rnd.randint(10 ** 15, 10 ** 16 - 1)), f"#buildno={build[5:9]}", "#global_vdom=1",
         "config system global", "    set admintimeout 10", f'    set alias "{h}"', f'    set hostname "{h}"',
         "    set pre-login-banner enable", "end", "config system interface"]
    if code == "FG100F":
        L += ['    edit "mgmt"', f"        set ip {_ip(dev)} 255.255.255.0", "        set allowaccess ping https ssh",
              "        set type physical", "        set dedicated-to management", "        set role lan", "    next"]
    wan_access = "ping https ssh" if h == "ZAZ-FW01" else "ping"
    L += ['    edit "wan1"', f"        set ip {wan_ip} 255.255.255.248", f"        set allowaccess {wan_access}", "        set type physical",
          "        set role wan", "    next"]
    lan = "port1" if code == "FG100F" else "internal"
    L += [f'    edit "{lan}"', f"        set ip {net}.250.4 255.255.255.248", "        set allowaccess ping", "        set type " +
          ("physical" if code == "FG100F" else "hard-switch"), "        set role lan", "    next"]
    if code == "FGT60F":
        L += ['    edit "MGMT"', '        set vdom "root"', f"        set ip {_ip(dev)} 255.255.255.0", "        set allowaccess ping https ssh",
              "        set role lan", f'        set interface "{lan}"', "        set vlanid 10", "    next"]
    L += ["end", "config system admin", '    edit "admin"', '        set accprofile "super_admin"', '        set vdom "root"',
          "        set trusthost1 10.10.0.0 255.255.255.0", f"        set password ENC SH2{_hash(rnd, 60)}", "    next",
          '    edit "oxidized"', '        set accprofile "read_only_backup"', '        set vdom "root"',
          "        set trusthost1 10.10.0.40 255.255.255.255", f"        set password ENC SH2{_hash(rnd, 60)}", "    next", "end",
          "config system ntp", "    set ntpsync enable", "    set type custom", "    config ntpserver"]
    for k, ip in enumerate(NTP, 1):
        L += [f"        edit {k}", f'            set server "{ip}"', "        next"]
    L += ["    end", "end", "config system snmp sysinfo", "    set status enable", f'    set location "{SITES[site]}, {ROOMS[site]}"', "end",
          "config system snmp user", '    edit "netmon"', "        set notify-hosts 10.10.0.21", "        set security-level auth-priv",
          "        set auth-proto sha256", f"        set auth-pwd ENC {_hash(rnd, 48)}", "        set priv-proto aes256",
          f"        set priv-pwd ENC {_hash(rnd, 48)}", "    next", "end",
          "config log syslogd setting", "    set status enable", f'    set server "{SYSLOG}"', "end", "config firewall policy"]
    pols = [("LAN-to-Internet", lan, "wan1", "LAN-USERS", "all", '"HTTP" "HTTPS" "DNS"', "utm", "", ""),
            ("Servers-to-Updates", lan, "wan1", "SERVERS", "UPDATE-SERVERS", '"HTTPS"', "all", "", ""),
            ("Scanners-to-WMS", lan, "wan1", "SCANNERS", "WMS-SAAS", '"HTTPS"', "all", "", "")]
    if h == "ZAZ-FW01":
        pols.append(("TEMP-any-out", lan, "wan1", "all", "all", '"ALL"', "disable", "", "Temporary during WMS cutover 2026-09-15"))
    if h == "VLC-FW01":
        pols.append(("OLD-ERP-sync", lan, "wan1", "ERP-OLD", "ERP-HOSTING", '"HTTPS"', "all", "disable",
                     "Disabled 2026-04-02 after the ERP migration, CHG0039876"))
    if h.startswith("MAD-FW"):
        pols.append(("Guest-WiFi-out", lan, "wan1", "GUEST-NET", "all", '"HTTP" "HTTPS" "DNS"', "utm", "disable",
                     "Disabled 2026-09-20, guest Wi-Fi moved to its own circuit"))
    for k, (name, si, di, sa, da, svc, log, status, comment) in enumerate(pols, 1):
        L += [f"    edit {k}", f'        set name "{name}"', f'        set srcintf "{si}"', f'        set dstintf "{di}"',
              "        set action accept", f'        set srcaddr "{sa}"', f'        set dstaddr "{da}"', '        set schedule "always"',
              f"        set service {svc}"]
        if log != "utm":
            L += [f"        set logtraffic {log}"]
        L += ["        set nat enable"]
        if status:
            L += [f"        set status {status}"]
        if comment:
            L += [f'        set comments "{comment}"']
        L += ["    next"]
    L += ["end", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- write

def _csv(path: Path, header: list[str], rows: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def write(folder: Path) -> Path:
    folder = Path(folder)
    (folder / "configs").mkdir(parents=True, exist_ok=True)
    for old in (folder / "configs").glob("*.cfg"):
        old.unlink()
    rnd = random.Random(SEED)
    devs = []
    count = {}
    for host, site, rack, role, vendor, model, ver, eos in DEVICES:
        count[site] = count.get(site, 0) + 1
        net = NET[site]
        if role == "router":
            ip = f"{net}.250.{1 + sum(1 for d in devs if d['site'] == site and d['role'] == 'router')}"
        elif role == "firewall":
            ip = f"{net}.10.{5 + sum(1 for d in devs if d['site'] == site and d['role'] == 'firewall')}"
        elif role == "core":
            ip = f"{net}.10.{2 + sum(1 for d in devs if d['site'] == site and d['role'] == 'core')}"
        else:
            ip = f"{net}.10.{10 + int(host[-2:])}"
        serial = _serial(rnd, model)
        devs.append({"hostname": host, "site": site, "rack": rack, "role": role, "vendor": vendor, "model": model, "os_version": ver,
                     "eos": eos, "mgmt_ip": ip, "serial": serial, "config_serial": _serial(rnd, model) if host in SERIAL_SWAP else serial})
    extra = {"hostname": EXTRA[0], "site": EXTRA[1], "rack": "R02", "role": "access", "vendor": "Cisco", "model": EXTRA[2],
             "os_version": "17.9.5", "eos": "", "mgmt_ip": "10.30.10.16", "serial": "", "config_serial": _serial(rnd, EXTRA[2])}
    for d in devs + [extra]:
        if d["hostname"] in NO_BACKUP:
            continue
        if d["vendor"] == "Fortinet":
            text = fortios_config(d, rnd)
        elif d["vendor"] == "HPE Aruba":
            text = aruba_config(d, rnd, devs)
        else:
            text = ios_config(d, rnd, devs + ([extra] if d is extra else []))
        (folder / "configs" / f"{d['hostname']}.cfg").write_text(text, encoding="utf-8", newline="\n")
    _csv(folder / "inventory.csv", ["hostname", "site", "room", "rack", "role", "vendor", "model", "os_version", "serial", "mgmt_ip",
                                    "last_backup", "end_of_support"],
         [[d["hostname"], d["site"], ROOMS[d["site"]], d["rack"], d["role"], d["vendor"], d["model"], d["os_version"], d["serial"],
           d["mgmt_ip"], "" if d["hostname"] in NO_BACKUP else (STALE if d["site"] == "ZAZ" else NIGHTLY), d["eos"]] for d in devs])
    _csv(folder / "changes.csv", ["number", "configuration_item", "planned_start", "planned_end", "approval", "state", "short_description"],
         CHANGES)
    (folder / "baseline.json").write_text(json.dumps(BASELINE, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (folder / "settings.json").write_text(json.dumps(SETTINGS, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    return folder


__all__ = ["write", "ORG", "SETTINGS", "BASELINE"]
