# Weekly review

How to run the review every week and turn its findings into changes. The tool only reads backups and exports; every fix is made on the devices by the network and security engineers, through the change process.

## Who does what

| Role | In the review |
|---|---|
| Network operations | Runs the collection and the review every Friday morning, checks the backups, sends the pack to the change board and each owner their lines |
| Network engineering | Owns the baseline for switches and routers, raises the changes for management plane, logging and switching findings |
| Security engineering | Owns the FortiGate rules and the baseline for firewalls, raises the changes for FWL findings |
| Infrastructure manager | Lifecycle: upgrades, replacements, budget for end-of-support devices, exceptions |
| Device42 / CMDB owner | Inventory findings (INV), sites, racks, roles, serials and end-of-support dates |
| Change board (CAB) | Approves the proposed windows, accepts or rejects exceptions |

## The weekly cycle

| When | What | Output |
|---|---|---|
| Every night | Oxidized or RANCID (or `scripts/Get-NetworkConfigBackup.ps1`) saves the running configurations | `configs/`, `backup_log.csv` |
| Friday 07:30 | Export the inventory from Device42 and the approved changes of the week from the ITSM tool | `inventory.csv`, `changes.csv` |
| Friday 08:00 | Run the review | `output/` |
| Friday 09:00 | Network operations reads the pack: anything critical that cannot wait goes to the emergency change process | `compliance-pack.md` |
| Before the change board | Each owner raises a change for their lines, with the device list from `actions.csv` | change tickets |
| Change board | Decisions per finding: window, exception or rejection | the pack, *Decisions* |
| After the window | Next week's run shows what was fixed; findings still open come back with the same reference | `findings.csv` |

```powershell
.\scripts\Get-NetworkConfigBackup.ps1 -InventoryCsv .\data\inventory.csv -OutputFolder .\data
```

```bash
python -m netcompliance review data/
```

## How to read the pack

1. **Overall and the decisions table.** The overall status is the worst device. The decisions table has one line per finding and severity, with the devices, the proposed window and the owner. Critical findings are proposed for the next window, warnings for the following one.
2. **Status by area.** Shows where the drift is concentrated: a site with backups 10 days old is a backup job problem, not ten device problems.
3. **Headlines.** Missing and old backups, unsaved and unplanned changes, end of support.
4. **Sections 1 to 4.** Status by site, the devices not compliant, backups and changes, lifecycle.
5. **Findings.** The detail per rule with the next step.

`report.html` shows the same with a grid of devices by area (hover a cell for the detail); `rule-results.csv` has every rule for every device for whoever needs the evidence.

## From finding to change

| Finding | Typical change | Notes |
|---|---|---|
| BKP-01, BKP-02 | Not a device change: fix the backup job (credentials, ACL, the collector's source address in `MGMT-ACL`, Oxidized node list) | Take a manual backup the same day |
| BKP-03 | Compare `show running-config` with `show startup-config`; save or roll back in the window | Until then, a reload or power cut loses the change |
| BKP-04 | Find who changed what (TACACS+ accounting, syslog); raise a retrospective change or roll back | Talk to the engineer; repeated cases go to the change manager |
| MGT-02, LOG-04 critical | Standard change, next window: `transport input ssh`, `no telnet-server`, remove the community after moving the poller to SNMPv3 | Check the monitoring (Zabbix, SolarWinds) still polls after the change |
| FWL-01, FWL-02 | Normal change with security engineering: remove admin access from WAN, replace the any-any policy with specific objects | Look at the traffic log first to see what the policy is really used for |
| LOG-01, LOG-02, LOG-03, MGT-xx warnings | Standard change by site: apply the baseline block to all the devices of the site in one window | One change per site and block is easier to approve and roll back |
| SWI-xx | Standard change per switch: shut down and park unused ports, PortFast/BPDU guard, native VLAN on both ends of the trunk | Native VLAN changes on both ends in the same window, or the trunk drops untagged traffic |
| LCM-01 | Upgrade in a window, HA secondary or stack member first, with the rollback image on flash | Check the upgrade path in the vendor notes |
| LCM-02 | Replacement project; until then, an exception with compensating controls | The replacement is a purchase, not a window |
| INV-xx | Correct Device42; no device change | Serial mismatches usually come from an RMA swap |

When the change is raised, put its number in the `change_ticket` column of `actions.csv` and in `changes.csv` for the window, so the next review sees the change as approved.

## Updating the baseline

- The baseline is a document under change control: the owners propose, the change board approves, and `baseline.json` is updated in the same change.
- New approved versions: add them to `approved_versions` once tested on one device per family, and keep the previous one until the last device is upgraded.
- New NTP or syslog servers: add them before the devices are changed, remove the old ones after; for a week the old ones show as *not in the baseline*.
- New sites: add the site code to `settings.json`, the port security site list if it applies, and the devices to Device42 with the right role.
- Keep `baseline.json` in Git with the history of who changed what and when.

## Exceptions

Some findings will not be fixed in a window: a switch past end of support waiting for its replacement, an old device that does not support SNMPv3, a FortiGate policy a supplier needs until a migration ends.

- Record each exception in the *Exceptions* table of the pack: device, rule, reason, compensating control, owner and an end date.
- The change board accepts or rejects it; an accepted exception keeps showing in the review until it is fixed, so it is not forgotten.
- Compensating controls are concrete: the management ACL limited to two hosts, the port shut down, the policy limited to the supplier's addresses and logged.
- Review all exceptions every quarter, and every one whose end date has passed at the next weekly review.
