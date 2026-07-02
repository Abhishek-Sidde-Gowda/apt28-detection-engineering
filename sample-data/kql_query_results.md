# KQL Query Results — APT28 Detection Validation

Sample output demonstrating each detection rule firing against simulated APT28 activity.
Log source: Sysmon EventIDs ingested into Microsoft Sentinel (Log Analytics Workspace).

---

## 1. PowerShell Encoded Command (T1059.001)

**KQL Query:**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend CommandLine = tostring(EventData.DataItem.EventData.Data[10]["#text"])
| extend Image = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| where Image has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any ("-EncodedCommand", "-enc ", "-ec ")
| project TimeGenerated, Computer, Image, CommandLine
```

**Result:**
| TimeGenerated | Computer | Image | CommandLine |
|--------------|----------|-------|-------------|
| 2026-06-29T14:23:11Z | WORKSTATION-01 | powershell.exe | powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA== |

**Decoded payload:** `Invoke-WebRequest` — C2 download attempt  
**MTTD:** 00:00:43 (43 seconds from execution to alert)

---

## 2. LSASS Memory Dump (T1003.001)

**KQL Query:**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 10
| extend EventData = parse_xml(EventData)
| extend SourceImage = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| extend TargetImage = tostring(EventData.DataItem.EventData.Data[5]["#text"])
| extend GrantedAccess = tostring(EventData.DataItem.EventData.Data[6]["#text"])
| where TargetImage has "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x147a", "0x143a")
| project TimeGenerated, Computer, SourceImage, TargetImage, GrantedAccess
```

**Result:**
| TimeGenerated | Computer | SourceImage | TargetImage | GrantedAccess |
|--------------|----------|-------------|-------------|---------------|
| 2026-06-29T14:31:44Z | WORKSTATION-01 | mimikatz.exe | lsass.exe | 0x1410 |

**MTTD:** 00:00:31  
**Severity:** HIGH — credential theft in progress

---

## 3. Registry Run Key Persistence (T1547.001)

**KQL Query:**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| extend EventData = parse_xml(EventData)
| extend TargetObject = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| extend Details = tostring(EventData.DataItem.EventData.Data[5]["#text"])
| extend Image = tostring(EventData.DataItem.EventData.Data[3]["#text"])
| where TargetObject has_any (
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce"
  )
| project TimeGenerated, Computer, TargetObject, Details, Image
```

**Result:**
| TimeGenerated | Computer | TargetObject | Details | Image |
|--------------|----------|--------------|---------|-------|
| 2026-06-29T14:38:02Z | WORKSTATION-01 | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\WindowsUpdater | C:\Users\labuser\AppData\Roaming\svchost32.exe | dropper.exe |

**MTTD:** 00:00:28  
**Note:** Persistence mechanism masquerading as Windows Update service

---

## 4. Remote Thread Injection (T1055.001)

**KQL Query:**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 8
| extend EventData = parse_xml(EventData)
| extend SourceImage = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| extend TargetImage = tostring(EventData.DataItem.EventData.Data[5]["#text"])
| where TargetImage has_any ("explorer.exe", "svchost.exe", "lsass.exe", "spoolsv.exe")
| project TimeGenerated, Computer, SourceImage, TargetImage, NewThreadId = tostring(EventData.DataItem.EventData.Data[6]["#text"])
```

**Result:**
| TimeGenerated | Computer | SourceImage | TargetImage | NewThreadId |
|--------------|----------|-------------|-------------|-------------|
| 2026-06-29T14:42:19Z | WORKSTATION-01 | injector.exe | explorer.exe | 9823 |

**MTTD:** 00:00:19  
**Severity:** HIGH — code injection into trusted process

---

## 5. System Information Discovery (T1082)

**KQL Query:**
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend EventData = parse_xml(EventData)
| extend Image = tostring(EventData.DataItem.EventData.Data[4]["#text"])
| extend ParentImage = tostring(EventData.DataItem.EventData.Data[20]["#text"])
| where Image has_any ("systeminfo.exe", "ipconfig.exe", "whoami.exe", "nltest.exe")
| where ParentImage has_any ("powershell.exe", "cmd.exe")
| summarize Commands = make_list(Image), Count = count() by Computer, ParentProcessId = tostring(EventData.DataItem.EventData.Data[19]["#text"]), bin(TimeGenerated, 5m)
| where Count >= 2
```

**Result:**
| TimeGenerated | Computer | ParentProcessId | Commands | Count |
|--------------|----------|-----------------|----------|-------|
| 2026-06-29T14:45:00Z | WORKSTATION-01 | 4821 | ["systeminfo.exe","ipconfig.exe","whoami.exe"] | 3 |

**MTTD:** 00:01:02  
**Note:** 3 enumeration commands in 15 seconds from same parent process

---

## Detection Coverage Summary

| Rule | Technique | Alert Fired | MTTD | False Positives |
|------|-----------|-------------|------|-----------------|
| PowerShell Encoded | T1059.001 | ✅ | 43s | 0 |
| LSASS Dump | T1003.001 | ✅ | 31s | 0 |
| Registry Run Key | T1547.001 | ✅ | 28s | 0 |
| Remote Thread | T1055.001 | ✅ | 19s | 0 |
| System Enumeration | T1082 | ✅ | 62s | 0 |
| RDP Lateral Move | T1021.001 | ⬜ | — | — |
| Office Macro | T1566.001 | ⬜ | — | — |
| DNS Tunneling | T1071.004 | ⬜ | — | — |

**Coverage: 5/8 techniques detected (62.5%)**  
**Average MTTD: 36.6 seconds**  
**False positive rate: 0%**
