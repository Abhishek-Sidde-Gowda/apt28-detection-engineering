# APT28 Detection Engineering Lab

A detection-as-code project mapping APT28 (Fancy Bear) TTPs to Sigma rules, validated through adversary emulation and deployed to Microsoft Sentinel.

## Project Goals

- Map APT28's known ATT&CK techniques to custom Sigma detection rules
- Automate rule conversion to Sentinel KQL via CI/CD (GitHub Actions)
- Validate detections using Atomic Red Team emulation
- Measure and improve detection coverage with quantified before/after metrics

## Architecture

```
Home Lab VMs (Windows + Linux)
        │
        ▼ Sysmon + AMA + Azure Arc
Microsoft Sentinel (Log Analytics Workspace)
        │
        ▼ KQL queries deployed from CI/CD
Detection Rules ← converted from Sigma by GitHub Actions
```

## Repository Structure

```
sigma-rules/          # Detection rules written in Sigma format
  initial-access/
  execution/
  persistence/
  defense-evasion/
  credential-access/
  discovery/
  lateral-movement/
  exfiltration/

converted/
  sentinel-kql/       # Auto-converted KQL (generated, do not edit manually)

emulation/
  atomic-tests/       # Atomic Red Team test plans mapped to APT28

metrics/              # Detection coverage reports (before/after tuning)

docs/                 # Methodology, ATT&CK coverage map, screenshots
  screenshots/
```

## APT28 ATT&CK Coverage

| Tactic | Technique | Sub-technique | Sigma Rule | Validated |
|--------|-----------|---------------|------------|-----------|
| Initial Access | T1566 Phishing | T1566.001 Spearphishing Attachment | ✅ | ⬜ |
| Execution | T1059 Command Interpreter | T1059.001 PowerShell | ✅ | ⬜ |
| Persistence | T1547 Boot Autostart | T1547.001 Registry Run Keys | ✅ | ⬜ |
| Defense Evasion | T1055 Process Injection | T1055.001 DLL Injection | ✅ | ⬜ |
| Credential Access | T1003 OS Credential Dumping | T1003.001 LSASS Memory | ✅ | ⬜ |
| Discovery | T1082 System Info Discovery | — | ✅ | ⬜ |
| Lateral Movement | T1021 Remote Services | T1021.001 RDP | ✅ | ⬜ |
| Exfiltration | T1041 Exfil Over C2 Channel | — | ✅ | ⬜ |

## Methodology

1. **Threat Model** — Select APT28 TTPs from MITRE ATT&CK (Group G0007)
2. **Detection Hypothesis** — Write Sigma rules targeting each technique
3. **Deployment** — GitHub Actions auto-converts Sigma → KQL on push
4. **Emulation** — Atomic Red Team runs simulate each TTP in the lab
5. **Validation** — Confirm rule fires, measure MTTD, tune false positives
6. **Metrics** — Document coverage % before and after tuning

## Results

| Metric | Before Tuning | After Tuning |
|--------|--------------|--------------|
| Detection Coverage | TBD | TBD |
| False Positive Rate | TBD | TBD |
| Mean Time to Detect (MTTD) | TBD | TBD |

*Results updated after emulation phase completes.*

## Lab Environment

- **SIEM:** Microsoft Sentinel (Log Analytics Workspace, free tier)
- **Log Source:** Windows VM with Sysmon (Olaf Hartong config)
- **Connectivity:** Azure Arc + Azure Monitor Agent (AMA)
- **Emulation:** Atomic Red Team
- **Rule Format:** Sigma → KQL (via pySigma + sigma-cli)

## References

- [MITRE ATT&CK G0007 - APT28](https://attack.mitre.org/groups/G0007/)
- [Sigma Project](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Olaf Hartong Sysmon Config](https://github.com/olafhartong/sysmon-modular)
