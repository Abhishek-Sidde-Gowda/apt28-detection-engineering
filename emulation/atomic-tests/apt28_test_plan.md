# APT28 Emulation Test Plan

## Purpose
Validate detection rules fire against real simulated APT28 TTPs using Atomic Red Team.

## Prerequisites
- Atomic Red Team installed on test Windows VM: `IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics`
- Sysmon running with Olaf Hartong config
- Logs flowing to Sentinel

## Test Cases

### 1. PowerShell Encoded Command (T1059.001)
**Atomic test:** `Invoke-AtomicTest T1059.001 -TestNumbers 1`
**Expected rule:** `apt28_powershell_encoded_command.yml`
**Sysmon EventID:** 1 (Process Create)
**Validation query (KQL):**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| where EventData.DataItem.EventData.Data has "-EncodedCommand"
| project TimeGenerated, Computer, EventData
```
**Result:** [ ] Fired / [ ] Missed — MTTD: ___

---

### 2. LSASS Memory Dump (T1003.001)
**Atomic test:** `Invoke-AtomicTest T1003.001 -TestNumbers 1`
**Expected rule:** `apt28_lsass_memory_dump.yml`
**Sysmon EventID:** 10 (ProcessAccess)
**Validation query (KQL):**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 10
| extend EventData = parse_xml(EventData)
| where EventData.DataItem.EventData.Data has "lsass.exe"
| project TimeGenerated, Computer, EventData
```
**Result:** [ ] Fired / [ ] Missed — MTTD: ___

---

### 3. Registry Run Key Persistence (T1547.001)
**Atomic test:** `Invoke-AtomicTest T1547.001 -TestNumbers 1`
**Expected rule:** `apt28_registry_run_key.yml`
**Sysmon EventID:** 13 (RegistryEvent)
**Result:** [ ] Fired / [ ] Missed — MTTD: ___

---

### 4. Remote Thread Injection (T1055.001)
**Atomic test:** `Invoke-AtomicTest T1055.001 -TestNumbers 1`
**Expected rule:** `apt28_process_injection_remote_thread.yml`
**Sysmon EventID:** 8 (CreateRemoteThread)
**Result:** [ ] Fired / [ ] Missed — MTTD: ___

---

### 5. RDP Lateral Movement (T1021.001)
**Manual test:** RDP from workstation VM to target VM using stolen creds
**Expected rule:** `apt28_rdp_unusual_source.yml`
**Windows Security EventID:** 4624 (Logon Type 10)
**Result:** [ ] Fired / [ ] Missed — MTTD: ___

---

## Coverage Summary

| Rule | Technique | Fired? | MTTD | False Positives |
|------|-----------|--------|------|-----------------|
| PowerShell Encoded | T1059.001 | | | |
| LSASS Dump | T1003.001 | | | |
| Registry Run Key | T1547.001 | | | |
| Remote Thread | T1055.001 | | | |
| RDP Lateral Move | T1021.001 | | | |

**Coverage: _/5 (___%)** before tuning → **_/5 (___%)** after tuning
