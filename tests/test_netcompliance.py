import csv
import hashlib
import json
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

from netcompliance import cli
from netcompliance.checks import (RULES, COMPLIANT, CRITICAL, DRIFT, FAIL, INFO, NA, NONCOMPLIANT, PASS, WARNING, area_status, evaluate, overall,
                                  review, run_all, summary, window_for)
from netcompliance.model import (Baseline, Change, Data, Device, InventoryItem, baseline_from_dict, load, load_configs, load_inventory,
                                 settings_from_dict, version_key)
from netcompliance.parsers import ARUBA, FORTIOS, IOS, detect, parse

AS_OF = datetime(2026, 11, 6, 8, 0)
BASE = {"ntp_servers": ["10.10.0.10", "10.10.0.11"], "syslog_hosts": ["10.10.0.20"], "timezone": {"ios": "CET", "aruba": "60"},
        "max_idle_minutes": 15, "parking_vlan": 999, "native_vlan": 998, "port_security_sites": ["MAD"],
        "approved_versions": {"C9300": ["17.9.5", "17.12.4"], "ISR4331": ["17.9.5"], "WS-C3750X": [], "FortiGate 60F": ["7.2.10"]},
        "min_firmware": {"FortiGate 60F": "7.2.10"}}

IOS_OK = """Building configuration...

Current configuration : 4210 bytes
!
! Last configuration change at 23:12:05 CET Tue Nov 3 2026 by dferrer
! NVRAM config last updated at 23:14:40 CET Tue Nov 3 2026 by dferrer
!
version 17.9
service password-encryption
!
hostname SW1
!
enable secret 9 $9$abc$def
!
aaa new-model
!
aaa group server tacacs+ ISE-TACACS
 server name ISE-01
!
aaa authentication login default group ISE-TACACS local
clock timezone CET 1 0
license udi pid C9300-48P sn FOC2412X1AB
!
spanning-tree portfast default
spanning-tree portfast bpduguard default
!
interface GigabitEthernet0/0
 vrf forwarding Mgmt-vrf
 shutdown
!
interface GigabitEthernet1/0/1
 description USR-MAD-P1-001
 switchport access vlan 110
 switchport mode access
 switchport port-security
!
interface GigabitEthernet1/0/2
 switchport access vlan 999
 switchport mode access
 shutdown
!
interface TenGigabitEthernet1/1/1
 description UPLINK-CS01
 switchport trunk native vlan 998
 switchport mode trunk
!
interface Vlan10
 ip address 10.10.10.11 255.255.255.0
!
ip ssh version 2
logging host 10.10.0.20
snmp-server group NETMON v3 priv read NETMON-VIEW
!
banner login ^C
Authorised access only.
line vty 0 4 (inside the banner, not a real line)
^C
!
line vty 0 4
 access-class MGMT-ACL in vrf-also
 exec-timeout 10 0
 transport input ssh
line vty 5 15
 access-class MGMT-ACL in vrf-also
 exec-timeout 10 0
 transport input ssh
!
ntp server vrf Mgmt-vrf 10.10.0.10
ntp server 10.10.0.11
!
end
"""

ARUBA_OK = """; JL256A Configuration Editor; Created on release #WC.16.11.0012
; Ver #14:01.4f.f8.1d.9b.3f.bf.bb.ef.7c.59.fc.6b.fb.9f.fc.ff.ff.37.ef:05
hostname "ZAZ-AS01"
console idle-timeout 600
no telnet-server
time timezone 60
ntp server 10.10.0.10 iburst
ntp server 10.10.0.11 iburst
banner motd "Authorised access only."
ip authorized-managers 10.10.0.0 255.255.255.0 access manager
logging 10.10.0.20
tacacs-server host 10.10.0.31
aaa authentication ssh login tacacs local
interface 1
   name "USR-ZAZ-001"
   exit
interface 2
   name "USR-ZAZ-002"
   exit
interface 3
   disable
   exit
vlan 1
   name "DEFAULT_VLAN"
   no untagged 1-4
   exit
vlan 110
   name "USERS"
   untagged 1-2
   tagged 4
   exit
vlan 998
   untagged 4
   exit
vlan 999
   untagged 3
   exit
spanning-tree 1-2 admin-edge-port
spanning-tree 1-2 bpdu-protection
"""

FORTI = """#config-version=FGT60F-7.2.8-FW-build1639-240313:opmode=0:vdom=0:user=oxidized
#buildno=1639
config system global
    set admintimeout 30
    set hostname "ZAZ-FW01"
end
config system interface
    edit "wan1"
        set ip 203.0.113.34 255.255.255.248
        set allowaccess ping https ssh
        set role wan
    next
    edit "internal"
        set allowaccess ping https telnet
        set role lan
    next
end
config system admin
    edit "admin"
        set accprofile "super_admin"
        set trusthost1 10.10.0.0 255.255.255.0
    next
    edit "vendor"
        set accprofile "super_admin"
    next
end
config system snmp community
    edit 1
        set name "public"
    next
end
config firewall policy
    edit 3
        set name "LAN-out"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "LAN"
        set dstaddr "all"
        set service "HTTPS" "DNS"
    next
    edit 7
        set name "TEMP-any"
        set srcintf "internal"
        set dstintf "wan1"
        set action accept
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set logtraffic disable
    next
    edit 8
        set name "old"
        set action accept
        set srcaddr "A"
        set dstaddr "B"
        set service "HTTPS"
        set status disable
        set comments "Disabled 2026-03-01 CHG0001"
    next
    edit 9
        set name "undated"
        set status disable
    next
end
"""


def inv(host, site="MAD", role="access", vendor="Cisco", model="C9300-48P", ver="17.9.5", serial="FOC2412X1AB",
        backup=datetime(2026, 11, 6, 2, 0), eos=None) -> InventoryItem:
    return InventoryItem(host, site, "Comms room B1", "R02", role, vendor, model, ver, serial, "10.10.10.11", backup, eos)


def data(devices, changes=(), settings=None, base=None) -> Data:
    s = settings_from_dict(settings or {"sites": {"MAD": "Madrid HQ", "ZAZ": "Zaragoza hub"},
                                        "change_windows": [{"name": "CW 46", "start": "2026-11-10 22:00"},
                                                           {"name": "CW 47", "start": "2026-11-17 22:00"}]})
    d = Data(s, baseline_from_dict(base or BASE), AS_OF, list(devices), list(changes))
    d.sources = {"inventory.csv": len(devices), "configs/": len(devices), "baseline.json": 1} | ({"changes.csv": len(changes)} if changes else {})
    return d


def dev(text, host="SW1", **kw) -> Device:
    c = parse(text) if text else None
    return Device(host, inv(host, **kw), c, f"configs/{host}.cfg" if c else "")


def results(d: Data, device: Device) -> dict:
    return {r.code: r for r in evaluate(d, device)}


def rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class TestParsers(unittest.TestCase):
    def test_ios_headers_banner_aaa_vty_and_ports(self):
        c = parse(IOS_OK)
        self.assertEqual(c.platform, IOS)
        self.assertEqual((c.hostname, c.model, c.serial, c.version), ("SW1", "C9300-48P", "FOC2412X1AB", "17.9"))
        self.assertEqual((c.last_change, c.last_change_by, c.last_saved), (datetime(2026, 11, 3, 23, 12, 5), "dferrer", datetime(2026, 11, 3, 23, 14, 40)))
        self.assertTrue(c.ssh_v2 and c.aaa_remote and c.aaa_local and c.banner and c.restricted and c.enable_secret)
        self.assertFalse(c.telnet or c.enable_password)
        self.assertEqual(c.ntp, ["10.10.0.10", "10.10.0.11"])
        self.assertEqual((c.syslog, c.timezone, c.snmp_communities, c.snmp_v3), (["10.10.0.20"], "CET", [], True))
        self.assertEqual([p.name for p in c.ports], ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "TenGigabitEthernet1/1/1"])
        p1, p2, te = c.ports
        self.assertTrue(p1.portfast and p1.bpduguard and p1.port_security)       # from the global defaults
        self.assertEqual((p1.vlan, p2.vlan, p2.shutdown, te.mode, te.native), (110, 999, True, "trunk", 998))
        self.assertEqual(c.idle, [("vty 0 4", 10), ("vty 5 15", 10)])

    def test_aruba_and_fortios(self):
        a = parse(ARUBA_OK)
        self.assertEqual((a.platform, a.hostname, a.model, a.version, a.timezone), (ARUBA, "ZAZ-AS01", "JL256A", "WC.16.11.0012", "60"))
        self.assertFalse(a.telnet)
        self.assertTrue(a.aaa_remote and a.aaa_local and a.banner and a.restricted)
        ports = {p.name: p for p in a.ports}
        self.assertEqual((ports["1"].vlan, ports["1"].portfast, ports["1"].bpduguard), (110, True, True))
        self.assertEqual((ports["3"].shutdown, ports["3"].vlan, ports["4"].mode, ports["4"].native), (True, 999, "trunk", 998))
        self.assertTrue(parse(ARUBA_OK.replace("no telnet-server\n", "")).telnet)
        f = parse(FORTI)
        self.assertEqual((f.platform, f.model, f.version, f.hostname), (FORTIOS, "FGT60F", "7.2.8", "ZAZ-FW01"))
        self.assertEqual([p.id for p in f.policies], ["3", "7", "8", "9"])
        self.assertEqual((f.policies[0].logtraffic, f.policies[1].logtraffic, f.policies[2].status), ("utm", "disable", "disable"))
        self.assertEqual(f.policies[0].service, ["HTTPS", "DNS"])
        self.assertTrue(f.telnet)
        self.assertFalse(f.restricted)
        self.assertEqual((f.snmp_communities, f.idle), (["public"], [("admintimeout", 30)]))
        self.assertEqual([detect(x) for x in (IOS_OK, ARUBA_OK, FORTI)], [IOS, ARUBA, FORTIOS])

    def test_config_folder_as_oxidized_or_rancid_store_it(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / "SW1.cfg").write_bytes(IOS_OK.replace("\n", "\r\n").encode("utf-8"))
            (Path(t) / "zaz-as01").write_text(ARUBA_OK, encoding="utf-8")
            (Path(t) / "ZAZ-FW01.conf").write_text(FORTI, encoding="utf-8")
            (Path(t) / "notes.md").write_text("not a config", encoding="utf-8")
            (Path(t) / "empty.cfg").write_text("", encoding="utf-8")
            got = load_configs(Path(t))
        self.assertEqual({k: v[0].platform for k, v in got.items()}, {"sw1": IOS, "zaz-as01": ARUBA, "zaz-fw01": FORTIOS})
        self.assertEqual(got["sw1"][0].last_saved, datetime(2026, 11, 3, 23, 14, 40))
        self.assertEqual(got["zaz-as01"][1], "configs/zaz-as01")


class TestBackup(unittest.TestCase):
    def test_missing_old_unsaved_and_unticketed_changes(self):
        unsaved = IOS_OK.replace("! NVRAM config last updated at 23:14:40 CET Tue Nov 3 2026", "! NVRAM config last updated at 18:02:11 CET Wed Oct 21 2026")
        ok, gone, old, dirty = dev(IOS_OK, "SW1"), dev("", "SW2"), dev(IOS_OK, "SW3", backup=datetime(2026, 10, 27, 2)), dev(unsaved, "SW4")
        tick = Change("CHG1", "SW1", datetime(2026, 11, 3, 22), datetime(2026, 11, 4, 0), "Approved")
        d = data([ok, gone, old, dirty], [tick, Change("CHG2", "SW4", datetime(2026, 11, 3, 22), None, "Requested")])
        r = {x.hostname: results(d, x) for x in d.devices}
        self.assertEqual(r["SW1"]["BKP-01"].status, PASS)
        self.assertEqual(r["SW1"]["BKP-04"].status, PASS)
        self.assertIn("CHG1", r["SW1"]["BKP-04"].detail)
        self.assertEqual((r["SW2"]["BKP-01"].severity, r["SW2"]["MGT-02"].status), (CRITICAL, NA))
        self.assertEqual((r["SW3"]["BKP-02"].severity, r["SW3"]["BKP-04"].status), (WARNING, FAIL))    # no ticket for SW3
        self.assertEqual(r["SW4"]["BKP-03"].severity, CRITICAL)                                         # 56 hours unsaved
        self.assertEqual(r["SW4"]["BKP-04"].severity, WARNING)                                          # ticket not approved
        d2 = data([dev(unsaved, "SW4")], [], settings={"unsaved_critical_hours": 72})
        self.assertEqual(results(d2, d2.devices[0])["BKP-03"].severity, WARNING)
        d3 = data([dev(IOS_OK.replace("! Last configuration change", "! Something"), "SW5")])
        self.assertEqual(results(d3, d3.devices[0])["BKP-03"].status, NA)


class TestManagementAndLogging(unittest.TestCase):
    def test_management_plane(self):
        bad = (IOS_OK.replace("ip ssh version 2\n", "").replace(" transport input ssh\nline vty 5", " transport input telnet ssh\nline vty 5")
               .replace("enable secret 9 $9$abc$def", "enable password Tailspin1").replace("service password-encryption\n", "")
               .replace("group ISE-TACACS local", "group ISE-TACACS").replace(" exec-timeout 10 0\n transport input telnet", " exec-timeout 0 0\n transport input telnet")
               .replace(" access-class MGMT-ACL in vrf-also\n exec-timeout 10 0\n transport input ssh", " exec-timeout 10 0\n transport input ssh"))
        d = data([dev(bad)])
        r = results(d, d.devices[0])
        self.assertEqual({k: r[k].severity for k in ("MGT-01", "MGT-02", "MGT-03", "MGT-04", "MGT-06", "MGT-07")},
                         {"MGT-01": WARNING, "MGT-02": CRITICAL, "MGT-03": WARNING, "MGT-04": WARNING, "MGT-06": WARNING, "MGT-07": WARNING})
        self.assertIn("enable password", r["MGT-03"].detail)
        self.assertIn("vty 0 4 never", r["MGT-06"].detail)
        self.assertIn("vty 5 15", r["MGT-07"].detail)
        unset = IOS_OK.replace(" transport input ssh\nline vty 5", "line vty 5")
        d = data([dev(unset)])
        self.assertEqual(results(d, d.devices[0])["MGT-02"].severity, WARNING)
        good = data([dev(IOS_OK)])
        self.assertTrue(all(x.status == PASS for k, x in results(good, good.devices[0]).items() if k.startswith("MGT")))

    def test_ntp_syslog_timezone_and_snmp(self):
        txt = (IOS_OK.replace("ntp server vrf Mgmt-vrf 10.10.0.10\nntp server 10.10.0.11", "ntp server 10.30.0.5")
               .replace("logging host 10.10.0.20\n", "").replace("clock timezone CET 1 0", "clock timezone UTC 0 0")
               .replace("ip ssh version 2", "ip ssh version 2\nsnmp-server community public RO"))
        d = data([dev(txt)])
        r = results(d, d.devices[0])
        self.assertIn("not in the baseline 10.30.0.5", r["LOG-01"].detail)
        self.assertEqual((r["LOG-02"].status, r["LOG-03"].detail), (FAIL, "time zone UTC, baseline CET"))
        self.assertEqual(r["LOG-04"].severity, CRITICAL)
        d = data([dev(IOS_OK.replace("ip ssh version 2", "ip ssh version 2\nsnmp-server community tlog-mon RO MGMT-ACL"))])
        self.assertEqual(results(d, d.devices[0])["LOG-04"].severity, WARNING)
        d = data([Device("ZAZ-AS05", inv("ZAZ-AS05", "ZAZ", vendor="HPE Aruba", model="Aruba 2930F (JL256A)"),
                         parse(ARUBA_OK + 'snmp-server community "public" unrestricted\n'))])
        r = results(d, d.devices[0])
        self.assertEqual((r["LOG-04"].severity, r["LOG-03"].status, r["MGT-01"].status), (CRITICAL, PASS, NA))


class TestSwitching(unittest.TestCase):
    def test_unused_ports_bpdu_native_vlan1_and_port_security(self):
        txt = IOS_OK.replace("spanning-tree portfast default\nspanning-tree portfast bpduguard default\n", "").replace(
            "interface TenGigabitEthernet1/1/1", "interface GigabitEthernet1/0/3\n switchport mode access\n!\n"
            "interface GigabitEthernet1/0/4\n description PRN-MAD-01\n switchport mode access\n!\ninterface TenGigabitEthernet1/1/2\n"
            " switchport mode trunk\n!\ninterface TenGigabitEthernet1/1/1")
        d = data([dev(txt)])
        r = results(d, d.devices[0])
        self.assertIn("Gi1/0/3 (1 up in VLAN 1)", r["SWI-01"].detail)
        self.assertIn("2 user ports without PortFast", r["SWI-02"].detail)
        self.assertIn("Te1/1/2", r["SWI-03"].detail)
        self.assertIn("Gi1/0/4", r["SWI-04"].detail)
        self.assertIn("Gi1/0/4", r["SWI-05"].detail)
        d = data([dev(IOS_OK, site="VLC")])
        r = results(d, d.devices[0])
        self.assertEqual([r[k].status for k in ("SWI-01", "SWI-02", "SWI-03", "SWI-04", "SWI-05")], [PASS, PASS, PASS, PASS, NA])
        d = data([dev(IOS_OK, role="core"), dev(IOS_OK, "RT1", role="router", model="ISR4331/K9")])
        rc, rr = results(d, d.devices[0]), results(d, d.devices[1])
        self.assertEqual((rc["SWI-01"].status, rc["SWI-03"].status, rr["SWI-03"].status), (NA, PASS, NA))
        aru = data([Device("ZAZ-AS01", inv("ZAZ-AS01", "ZAZ", vendor="HPE Aruba", model="Aruba 2930F (JL256A)"),
                           parse(ARUBA_OK.replace("interface 3\n   disable\n   exit\n", "")))])
        self.assertEqual(results(aru, aru.devices[0])["SWI-01"].severity, WARNING)


class TestFortiGateLifecycleInventory(unittest.TestCase):
    def test_fortigate_rules(self):
        d = data([Device("ZAZ-FW01", inv("ZAZ-FW01", "ZAZ", "firewall", "Fortinet", "FortiGate 60F", "7.2.8"), parse(FORTI))])
        r = results(d, d.devices[0])
        self.assertEqual((r["FWL-01"].severity, r["FWL-01"].detail), (CRITICAL, "admin access on wan1 (https ssh)"))
        self.assertEqual(r["FWL-02"].severity, CRITICAL)
        self.assertIn("policy 7 'TEMP-any'", r["FWL-02"].detail)
        self.assertEqual(r["FWL-03"].detail, "logtraffic disable on policy 7 'TEMP-any'")
        self.assertIn("policy 8 'old' disabled 2026-03-01", r["FWL-04"].detail)
        self.assertEqual(r["FWL-05"].detail, "FortiOS 7.2.8, baseline minimum 7.2.10 for FortiGate 60F")
        self.assertEqual((r["MGT-02"].severity, r["MGT-06"].status, r["MGT-07"].detail), (CRITICAL, FAIL, "no trusted hosts on admin vendor"))
        self.assertEqual((r["SWI-01"].status, r["MGT-04"].status, r["LCM-01"].status), (NA, NA, FAIL))
        self.assertGreater(version_key("7.2.10"), version_key("7.2.8"))

    def test_lifecycle_and_inventory(self):
        old = dev(IOS_OK.replace("license udi pid C9300-48P sn FOC2412X1AB\n", ""), "SW10", model="WS-C3750X-48P-S", ver="15.2(4)E10",
                  eos=date(2021, 10, 31))
        rt = dev(IOS_OK, "RT1", role="router", model="ISR4331/K9", ver="17.06.05")
        soon = dev(IOS_OK, "SW1", eos=date(2027, 3, 31), serial="FOC9999X999")
        orphan = Device("SW99", None, parse(IOS_OK.replace("hostname SW1", "hostname SW99")), "configs/SW99.cfg", "MAD")
        d = data([old, rt, soon, orphan])
        r = {x.hostname: results(d, x) for x in d.devices}
        self.assertEqual(r["SW10"]["LCM-02"].severity, CRITICAL)
        self.assertIn("no approved version", r["SW10"]["LCM-01"].detail)
        self.assertIn("17.06.05 not approved", r["RT1"]["LCM-01"].detail)
        self.assertEqual(r["SW1"]["LCM-02"].severity, WARNING)
        self.assertIn("serial FOC2412X1AB in the configuration", r["SW1"]["INV-02"].detail)
        self.assertIn("model C9300-48P", r["RT1"]["INV-02"].detail)
        self.assertEqual((r["SW99"]["INV-01"].severity, r["SW99"]["LCM-01"].status, r["SW99"]["BKP-01"].status), (WARNING, NA, NA))
        self.assertEqual(version_key("17.09.05"), version_key("17.9.5"))


class TestVerdict(unittest.TestCase):
    def test_device_site_and_overall_status_with_change_windows(self):
        d = data([dev(IOS_OK, "SW1"), dev(IOS_OK.replace("ntp server 10.10.0.11", "ntp server 10.30.0.5"), "sw1"),
                  dev(IOS_OK.replace("ip ssh version 2", "ip ssh version 2\nsnmp-server community public RO"), "Sw1", site="ZAZ")])
        rv = review(d)
        st = {x["device"].hostname: x["status"] for x in rv["devices"]}
        self.assertEqual(st, {"SW1": COMPLIANT, "sw1": DRIFT, "Sw1": NONCOMPLIANT})      # hostnames compared without case
        self.assertEqual([(r["site"], r["status"]) for r in rv["sites"]], [("MAD", DRIFT), ("ZAZ", NONCOMPLIANT)])
        self.assertEqual(overall(rv), NONCOMPLIANT)
        f = run_all(d, rv)
        self.assertEqual([(x.code, x.severity, x.window) for x in f],
                         [("LOG-04", CRITICAL, "CW 46 (Tue 10 Nov 22:00)"), ("LOG-01", WARNING, "CW 47 (Tue 17 Nov 22:00)")])
        self.assertEqual(area_status(f)["Logging and time"], CRITICAL)
        self.assertEqual(window_for(INFO, d), "")
        info = data([Device("FW", inv("FW", vendor="Fortinet", model="FortiGate 60F", ver="7.2.10", role="firewall"),
                            parse(FORTI.replace("    edit 7", "    edit 70").replace('set name "TEMP-any"', 'set name "x"\n        set status disable')
                                  .replace("ping https ssh\n        set role wan", "ping\n        set role wan")))])
        self.assertEqual(summary(info, review(info))["devices"], 1)

    def test_settings_and_baseline_overrides(self):
        s = settings_from_dict({"backup_max_days": "3", "owners": {"firewall": "SecOps"}, "sites": {"MAD": "Madrid"}})
        self.assertEqual((s.backup_max_days, s.owner("firewall"), s.owner("backup"), s.site_name("MAD"), s.site_name("X")),
                         (3, "SecOps", "Network operations", "Madrid", "X"))
        b = baseline_from_dict({"native_vlan": "900", "unused_descriptions": ["SPARE"], "_comment": "x"})
        self.assertEqual((b.native_vlan, b.unused_descriptions, b.parking_vlan), (900, ["spare"], 999))
        self.assertEqual(Baseline(approved_versions={"C9300": [], "C9300-48P": []}).family("C9300-48P"), "C9300-48P")
        self.assertEqual(Baseline(approved_versions={"FortiGate 100F": []}).family("FG100F"), "FortiGate 100F")
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "inv.csv"
            p.write_text("Name;Building;Rack;Hw Model;Serial No;Last Backup;Last Date of Support\nsw1;MAD;R1;C9300-48P;FOC1;06/11/2026 02:00;"
                         "2030-01-31\n", encoding="utf-8")
            it = load_inventory(p)[0]
        self.assertEqual((it.hostname, it.site, it.model, it.serial, it.last_backup, it.end_of_support),
                         ("sw1", "MAD", "C9300-48P", "FOC1", datetime(2026, 11, 6, 2, 0), date(2030, 1, 31)))


class TestOutputs(unittest.TestCase):
    def test_demo_end_to_end_is_deterministic(self):
        with tempfile.TemporaryDirectory() as t:
            hashes = []
            for k in range(2):
                out, dd = Path(t) / f"out{k}", Path(t) / f"data{k}"
                self.assertEqual(cli.main(["demo", "--data", str(dd), "--out", str(out)]), 0)
                self.assertEqual(sorted(p.name for p in out.iterdir()), sorted(cli.OUTPUTS))
                hashes.append({n: hashlib.sha1((out / n).read_bytes()).hexdigest() for n in cli.OUTPUTS}
                              | {str(p.relative_to(dd)): hashlib.sha1(p.read_bytes()).hexdigest() for p in dd.rglob("*") if p.is_file()})
            self.assertEqual(hashes[0], hashes[1])
            self.assertEqual(json.loads((Path(t) / "data0" / "settings.json").read_text(encoding="utf-8"))["as_of"], "2026-11-06 08:00")
            self.assertLess(sum(p.stat().st_size for p in (Path(t) / "data0").rglob("*") if p.is_file()), 1_000_000)
            d = load(Path(t) / "data0")
        rv = review(d)
        f = run_all(d, rv)
        sm = summary(d, rv)
        self.assertEqual(overall(rv), NONCOMPLIANT)
        self.assertEqual((sm["devices"], sm["compliant"], sm["drift"], sm["noncompliant"], sm["missing"], sm["stale"]), (34, 9, 17, 8, 2, 8))
        self.assertEqual({x.code for x in f if x.severity == CRITICAL}, {"BKP-01", "BKP-03", "MGT-02", "LOG-04", "FWL-01", "FWL-02", "LCM-02"})
        by = {(x.code, x.severity): x for x in f}
        self.assertEqual(by[("MGT-02", CRITICAL)].devices, ["ZAZ-AS03"])
        self.assertEqual(sorted(by[("LOG-04", CRITICAL)].devices), ["VLC-AS04", "ZAZ-AS05"])
        self.assertEqual(sorted(by[("BKP-01", CRITICAL)].devices), ["VLC-AS05", "ZAZ-AS06"])
        self.assertEqual(by[("BKP-03", CRITICAL)].devices, ["MAD-AS07"])
        self.assertEqual(by[("BKP-04", WARNING)].devices, ["MAD-AS07"])
        self.assertIn("6 up in VLAN 1", by[("SWI-01", WARNING)].detail)
        self.assertIn("VLC-RT01: 17.6.5 not approved", by[("LCM-01", WARNING)].detail)
        self.assertEqual(by[("LCM-02", CRITICAL)].devices, ["MAD-AS10"])
        self.assertIn("10.30.0.5", by[("LOG-01", WARNING)].detail)

    def test_pack_and_csv_outputs(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(cli.main(["demo", "--data", str(Path(t) / "d"), "--out", str(Path(t) / "o")]), 0)
            o = Path(t) / "o"
            pack = (o / "compliance-pack.md").read_text(encoding="utf-8")
            html = (o / "report.html").read_text(encoding="utf-8")
            ds, rr, bk, lc, act = (rows(o / n) for n in ("device-status.csv", "rule-results.csv", "backups.csv", "lifecycle.csv", "actions.csv"))
        for h in ("## Decisions for the change board", "## Headlines", "## 1. Status by site", "## 2. Devices not compliant",
                  "## 3. Backups and changes", "## 4. Lifecycle", "## Exceptions", "## Sign-off"):
            self.assertIn(h, pack)
        self.assertEqual(len(ds), 34)
        self.assertEqual(len(rr), 34 * len(RULES))
        self.assertEqual({r["result"] for r in rr}, {PASS, FAIL, NA})
        self.assertEqual([r["unsaved_changes"] for r in bk if r["hostname"] == "MAD-AS07"], ["yes"])
        self.assertEqual([r["change_ticket"] for r in bk if r["hostname"] == "MAD-CS01"], ["CHG0045112"])
        self.assertEqual([r["support_result"] for r in lc if r["hostname"] == "MAD-AS10"], [FAIL])
        self.assertTrue(all(a["change_window"].startswith("CW 2026-4") for a in act))
        self.assertIn("Fix first", html)
        self.assertNotIn("\r", pack)

    def test_review_reports_missing_files(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o")]), 2)
            self.assertEqual(cli.main(["review", "--out", str(Path(t) / "o")]), 2)
            (Path(t) / "baseline.json").write_text(json.dumps(BASE), encoding="utf-8")
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o")]), 2)
            (Path(t) / "inventory.csv").write_text("hostname\n", encoding="utf-8")
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o")]), 2)
            (Path(t) / "inventory.csv").write_text("hostname,site,role,vendor,model\nSW1,MAD,access,Cisco,C9300-48P\n", encoding="utf-8")
            (Path(t) / "configs").mkdir()
            (Path(t) / "configs" / "SW1.cfg").write_text(IOS_OK, encoding="utf-8")
            (Path(t) / "backup_log.csv").write_text("hostname,collected_at,result\nsw1,2026-11-05 23:00,ok\nSW1,2026-11-06 01:00,failed\n",
                                                    encoding="utf-8")
            self.assertEqual(cli.main(["review", t, "--out", str(Path(t) / "o"), "--as-of", "2026-11-06"]), 0)
            self.assertEqual(rows(Path(t) / "o" / "backups.csv")[0]["last_backup"], "2026-11-05 23:00")


if __name__ == "__main__":
    unittest.main()
