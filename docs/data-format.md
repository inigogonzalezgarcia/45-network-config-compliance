# Data format

Put the files in one folder and run `python -m netcompliance review <folder>`. `inventory.csv` and `baseline.json` are required; `configs/` holds the backups; `changes.csv`, `backup_log.csv` and `settings.json` are optional. CSV files can be comma, semicolon or tab separated, UTF-8. Column names are matched loosely (case, accents and punctuation are ignored), and the alternatives below are accepted. Dates as ISO 8601 (`2026-11-06` or `2026-11-06 02:00`) or `dd/mm/yyyy`; a time zone suffix is ignored, so keep every file in the local time of the devices. Hostnames are compared without case.

```
data/
  inventory.csv        required
  baseline.json        required
  configs/             one file per device
  changes.csv          optional
  backup_log.csv       optional, written by scripts/Get-NetworkConfigBackup.ps1
  settings.json        optional
```

## How the review works

| Step | Rule |
|---|---|
| Join | Every inventory row is a device. Its backup is `configs/<hostname>` (`.cfg`, `.conf`, `.txt` or no extension). A backup with no inventory row is a device too, and gets INV-01 |
| Platform | From the backup itself: `#config-version=` is FortiOS, `; <product> Configuration Editor;` is ArubaOS-Switch, anything else is Cisco IOS / IOS-XE. Without a backup, from the vendor and model of the inventory |
| Result | Every rule gives every device *pass*, *fail* (critical, warning or information) or *n/a*. rule-results.csv has all of them |
| Device status | NON-COMPLIANT with a critical failure, DRIFT with warnings only, COMPLIANT otherwise. Information does not change the status |
| Site and overall | The worst status of their devices |
| Change window | Critical findings are proposed for the first window in `change_windows`, warnings for the second |

## inventory.csv

One row per device in the comms rooms, as a Device42 export (or any CMDB) gives it.

| Column | Alternatives | Notes |
|---|---|---|
| hostname | name, device name | Required; must match the backup file name |
| site | building, location | Site code, as in `settings.json` `sites` (`MAD`) |
| room | comms room | |
| rack | rack name | |
| role | device role, service level, tags | `core`, `access`, `distribution`, `router` or `firewall`. Switching rules run on `access` (and native VLAN on every switch) |
| vendor | manufacturer | `Cisco`, `HPE Aruba`, `Fortinet` |
| model | hw model, hardware | `C9300-48P`, `ISR4331/K9`, `Aruba 2930F-48G-PoE+-4SFP+ (JL256A)`, `FortiGate 100F`; compared with the model in the backup and matched to a family of `approved_versions` |
| os_version | software version, firmware | `17.9.5`, `15.2(4)E10`, `WC.16.11.0012`, `7.2.10`. Leading zeros are ignored (`17.09.05` = `17.9.5`) |
| serial | serial no, serial number | Compared with the serial in `license udi pid ... sn ...` of Cisco IOS-XE backups |
| mgmt_ip | management ip, ip address | Used by the collector |
| last_backup | backup time, last config backup | Time of the last successful backup; `backup_log.csv` overrides it when newer |
| end_of_support | eos, last date of support, ldos | The vendor's last date of support; empty when not announced |

## configs/

One text file per device, named after the hostname. The checks read only what they need; everything else is ignored.

- **Cisco IOS and IOS-XE**, `show running-config`. Read: the header lines `! Last configuration change at 02:14:37 CET Wed Nov 4 2026 by netadmin` and `! NVRAM config last updated at ...` (when present), `hostname`, `version`, `license udi pid <model> sn <serial>`, `service password-encryption`, `enable secret` / `enable password`, `aaa new-model`, `aaa group server tacacs+|radius <name>`, `aaa authentication login default ...`, `banner login` / `banner motd`, `ip ssh version 2`, `clock timezone`, `ntp server [vrf <vrf>] <ip>`, `logging host <ip>`, `snmp-server community`, `snmp-server group ... v3`, `spanning-tree portfast [edge] default` and `... bpduguard default`, `line vty` blocks (`transport input`, `exec-timeout`, `access-class`) and physical `interface` blocks (`description`, `switchport mode`, `switchport access vlan`, `switchport trunk native vlan`, `shutdown`, `spanning-tree portfast`, `spanning-tree bpduguard enable`, `switchport port-security`). `GigabitEthernet0/0` (the management port in the Mgmt-vrf) is skipped.
- **ArubaOS-Switch** (ProCurve style), `show running-config`. Read: the first line `; JL256A Configuration Editor; Created on release #WC.16.11.0012` (model and version), `hostname`, `no telnet-server`, `console idle-timeout`, `banner motd` / `banner exec`, `ip authorized-managers`, `tacacs-server host` / `radius-server host`, `aaa authentication ssh login`, `ntp server` (or `sntp server priority`), `logging <ip>`, `time timezone`, `snmp-server community`, `snmpv3 enable`, `interface <port>` blocks (`name`, `disable`), `vlan <id>` blocks (`untagged`, `tagged`), `spanning-tree <ports> admin-edge-port` and `bpdu-protection`, `port-security <ports> learn-mode`. A port tagged in any VLAN is a trunk; its untagged VLAN is the native VLAN.
- **FortiOS**, `show` or `show full-configuration`. Read: the header `#config-version=FG100F-7.2.10-FW-...` (model and version), `config system global` (`hostname`, `admintimeout`, default 5, `pre-login-banner`), `config system interface` (`role`, `allowaccess`, `dedicated-to`), `config system admin` (`trusthost1`…), `config system ntp`, `config log syslogd setting` (and syslogd2–4), `config system snmp community` and `snmp user`, and `config firewall policy` (`srcintf`, `dstintf`, `srcaddr`, `dstaddr`, `service`, `action`, `logtraffic` default `utm`, `status` default `enable`, `comments`). With plain `show`, settings left at their default are not printed; the defaults above are assumed.

Oxidized and RANCID backups work as they are. Copies made by hand work too, as long as the file starts with the show output.

## baseline.json

The golden rules. Example (the demo's):

```json
{
  "ntp_servers": ["10.10.0.10", "10.10.0.11"],
  "syslog_hosts": ["10.10.0.20"],
  "timezone": {"ios": "CET", "aruba": "60"},
  "max_idle_minutes": 15,
  "parking_vlan": 999,
  "native_vlan": 998,
  "port_security_sites": ["MAD"],
  "unused_descriptions": ["unused", "spare", "free", "parking"],
  "snmp_forbidden": ["public", "private"],
  "approved_versions": {"C9300": ["17.9.5", "17.12.4"], "ISR4331": ["17.9.5", "17.12.4"], "WS-C3750X": [],
                        "2930F": ["WC.16.11.0012"], "FortiGate 100F": ["7.2.10", "7.4.7"]},
  "min_firmware": {"FortiGate 100F": "7.2.10"}
}
```

| Key | Meaning |
|---|---|
| ntp_servers | Every device must use exactly these (LOG-01: missing ones and ones not in the list). FortiGate with `set type fortiguard` counts as `fortiguard` |
| syslog_hosts | Every device must send to these (LOG-02) |
| timezone | Per platform: the zone name of `clock timezone` on IOS (`CET`), the minutes of `time timezone` on ArubaOS-Switch (`60`). Not checked on FortiOS |
| max_idle_minutes | VTY `exec-timeout` (IOS default 10), `console idle-timeout` (ArubaOS-Switch, in seconds, 0 is never) and `admintimeout` (FortiOS) must be at most this, and never 0 |
| parking_vlan | Where unused access ports go, shut down |
| native_vlan | The native VLAN of trunks; when not set, anything but VLAN 1 |
| port_security_sites | Sites where user ports must have port security |
| unused_descriptions | A port with no description, or one starting with one of these words, is unused. The description is the record that a port is in use |
| snmp_forbidden | Communities that are critical; any other v2c community is a warning |
| approved_versions | Model family → approved OS versions. A family matches when its name, without spaces, punctuation or the FortiGate prefix, is contained in the model (`C9300` matches `C9300-48P`; `FortiGate 100F` matches `FG100F`); the longest match wins. An empty list means no version is approved: replace |
| min_firmware | FortiGate model family → minimum FortiOS version, checked against the version in the backup header |

## changes.csv (optional)

Approved changes, as exported from the ITSM tool (ServiceNow change_request columns shown).

| Column | Alternatives | Notes |
|---|---|---|
| number | ticket, change | |
| configuration_item | cmdb ci, hostname, device | The hostname of the device |
| planned_start | start date, start | |
| planned_end | end date, end | When empty, the whole day of planned_start |
| approval | approval status, state, status | Approved when one of: approved, scheduled, implement, review, closed, authorized |
| short_description | summary, description | |

BKP-04 looks at Cisco devices changed within the last `backup_max_days`: the time of `! Last configuration change` must fall in the window of an approved change for that device. Without changes.csv the rule is n/a.

## backup_log.csv (optional)

Written by `scripts/Get-NetworkConfigBackup.ps1`: `hostname`, `collected_at`, `result` (`ok` / `failed`), `detail`. A successful collection newer than the inventory's `last_backup` replaces it.

## settings.json (optional)

| Key | Default | Meaning |
|---|---|---|
| organisation | | Shown in the report |
| as_of | now | Reference date and time (`2026-11-06 08:00`); fix it to get the same outputs on every run |
| backup_max_days | 7 | Backup older than this is a warning (BKP-02); also the review period of BKP-04 |
| backup_critical_days | 30 | Backup older than this is critical |
| unsaved_critical_hours | 24 | Running configuration unsaved for longer than this is critical, a warning before |
| eos_warning_days | 180 | End of support within this many days is a warning; passed is critical |
| disabled_policy_days | 90 | Disabled FortiGate policies whose comments carry a date (`YYYY-MM-DD`) older than this are a warning; with no date, information |
| sites | {} | Site code → name |
| change_windows | [] | `[{"name": "CW 2026-46", "start": "2026-11-10 22:00"}, ...]` |
| owners | | Owner per area: backup, management, logging, switching, firewall, lifecycle, inventory |

## The rules

| Code | Rule | Platforms | Severity of a failure |
|---|---|---|---|
| BKP-01 | Configuration backup exists for every inventory device | all | critical |
| BKP-02 | Backup newer than `backup_max_days` | all | warning; critical after `backup_critical_days` |
| BKP-03 | Running configuration saved (last change not after the NVRAM update) | IOS | warning; critical after `unsaved_critical_hours` |
| BKP-04 | Last change inside an approved change | IOS | warning |
| MGT-01 | `ip ssh version 2` | IOS | warning |
| MGT-02 | No telnet: VTY `transport input` without telnet or all; `no telnet-server`; no telnet in `allowaccess` | all | critical; warning when `transport input` is not set |
| MGT-03 | `enable secret`, no `enable password`, `service password-encryption` | IOS | warning |
| MGT-04 | Login through a TACACS+ or RADIUS group with `local` as fallback | IOS, ArubaOS-Switch | warning |
| MGT-05 | Login banner (`banner login`/`motd`, `banner motd`, `pre-login-banner enable`) | all | warning |
| MGT-06 | Idle timeout at most `max_idle_minutes` and not never | all | warning |
| MGT-07 | `access-class` on every VTY line; `ip authorized-managers`; trusted hosts on every FortiGate admin | all | warning |
| LOG-01 | NTP servers exactly as baseline | all | warning |
| LOG-02 | Syslog hosts of the baseline present | all | warning |
| LOG-03 | Time zone as baseline | IOS, ArubaOS-Switch | warning |
| LOG-04 | No SNMP v2c communities | all | critical for `snmp_forbidden`, warning otherwise |
| SWI-01 | Unused access ports shut down in `parking_vlan` | access switches | warning |
| SWI-02 | PortFast and BPDU guard on used access ports | access switches | warning |
| SWI-03 | Native VLAN of trunks as baseline (not VLAN 1) | switches | warning |
| SWI-04 | No used access port in VLAN 1 | access switches | warning |
| SWI-05 | Port security on used access ports at `port_security_sites` | access switches | warning |
| FWL-01 | No HTTPS, HTTP, SSH or telnet in `allowaccess` of a WAN interface (`role wan` or named wan*) | FortiOS | critical |
| FWL-02 | No enabled accept policy with `srcaddr all`, `dstaddr all` and `service ALL` | FortiOS | critical |
| FWL-03 | No enabled accept policy with `logtraffic disable` | FortiOS | warning |
| FWL-04 | Disabled policies not kept beyond `disabled_policy_days` | FortiOS | warning; information when undated |
| FWL-05 | FortiOS at or above `min_firmware` | FortiOS | warning |
| LCM-01 | OS version in `approved_versions` for the model family | all | warning |
| LCM-02 | End of support not passed, not within `eos_warning_days` | all | critical when passed, warning within |
| INV-01 | Every backup has an inventory row | all | warning |
| INV-02 | Hostname, model and serial in the backup match the inventory | all | warning |

## Outputs

| File | Columns |
|---|---|
| device-status.csv | hostname, site, site_name, room, rack, role, vendor, model, platform, mgmt_ip, status, critical, warnings, codes, change_window |
| rule-results.csv | hostname, site, code, area, rule, result (pass, fail, n/a), severity, detail |
| backups.csv | hostname, site, platform, config_file, last_backup, backup_age_days, last_change, last_change_by, last_saved, unsaved_changes, change_ticket, severity, codes, detail |
| lifecycle.csv | hostname, site, model, family, os_version, approved_versions, version_result, end_of_support, days_to_eos, support_result, severity, detail |
| actions.csv | ref, action, next_step, owner, severity, sites, devices, change_window, change_ticket, decision, done |
| findings.csv | severity, area, code, subject, detail, next_step, owner, sites, change_window, devices |
