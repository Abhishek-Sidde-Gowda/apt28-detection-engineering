# Lab Setup Guide

## 1. Install Sysmon on Windows VM

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon

# Download Olaf Hartong's config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"

# Install
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify
Get-Service sysmon64
```

Check Event Viewer: Applications and Services Logs → Microsoft-Windows-Sysmon/Operational

## 2. Create Azure Resources

1. Create **Log Analytics Workspace** (free tier — 5GB/day)
2. Set a daily **data ingestion cap** (Workspace → Usage and estimated costs → Data Cap) to avoid unexpected charges
3. Enable **Microsoft Sentinel** on the workspace
4. Note down the Workspace ID and Primary Key

## 3. Onboard Home Lab VM via Azure Arc

Since this is an on-prem/home lab VM (not an Azure VM), Azure Arc is required before AMA can be deployed.

```powershell
# On the Windows VM — download and run the Arc onboarding script from Azure Portal
# Portal: Azure Arc → Machines → Add/Create → Add a machine → Single server
# Download the generated script and run it as Administrator
```

## 4. Deploy Azure Monitor Agent (AMA) with Custom DCR

In Sentinel: **Content hub** → search "Windows Security Events" → Install

Then create a **Data Collection Rule** that explicitly includes Sysmon's event log:

- Event log: `Microsoft-Windows-Sysmon/Operational`
- Minimum level: Information

**Important:** The default DCR only captures the Security event log. Sysmon events live in `Microsoft-Windows-Sysmon/Operational` — you must add this explicitly.

## 5. Verify Logs in Sentinel

```kql
// Confirm Sysmon events are arriving
Event
| where Source == "Microsoft-Windows-Sysmon"
| summarize count() by EventID, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

Key Sysmon EventIDs to confirm:
- **1** — Process Create
- **8** — CreateRemoteThread
- **10** — ProcessAccess
- **11** — FileCreate
- **13** — RegistryEvent (Value Set)

## 6. Install Atomic Red Team (on isolated test VM only)

```powershell
# Run as Administrator
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```
