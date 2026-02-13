# Microsoft Sysmon

System Monitor (Sysmon) logs from Windows servers and sampled workstations, providing detailed process, network, file, and registry activity.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `WinEventLog:Microsoft-Windows-Sysmon/Operational` |
| Format | Multi-line KV (WinEventLog style) |
| Output File | `output/windows/sysmon_operational.log` |
| Volume | ~2000-5000 events/day |
| Hosts | 7 servers + 20 sampled workstations/day |

---

## Event IDs Covered

| Event ID | Name | Description |
|----------|------|-------------|
| 1 | Process Create | New process launched with full command line |
| 3 | Network Connection | Outbound TCP/UDP connection |
| 5 | Process Terminated | Process exited |
| 7 | Image Loaded | DLL loaded into process |
| 8 | CreateRemoteThread | Remote thread injection (attack indicator) |
| 10 | ProcessAccess | Cross-process access (credential dumping indicator) |
| 11 | File Create | New file written to disk |
| 13 | Registry Value Set | Registry modification |
| 22 | DNS Query | DNS resolution from process |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `EventCode` | Sysmon Event ID | `1` |
| `ComputerName` | Host FQDN | `DC-BOS-01.theFakeTshirtCompany.com` |
| `User` | Process owner | `NT AUTHORITY\SYSTEM` |
| `Image` | Executable path | `C:\Windows\System32\lsass.exe` |
| `CommandLine` | Full command line | `powershell.exe -enc ...` |
| `ParentImage` | Parent process | `C:\Windows\explorer.exe` |
| `DestinationIp` | Network destination (EID 3) | `185.220.101.42` |
| `TargetFilename` | Created file path (EID 11) | `C:\Temp\data.7z` |
| `TargetObject` | Registry key (EID 13) | `HKLM\SOFTWARE\Microsoft\...` |
| `QueryName` | DNS query (EID 22) | `storage.googleapis.com` |
| `demo_id` | Scenario tag | `exfil` |

---

## Monitored Hosts

### Servers (always monitored)
| Host | Role | Key Processes |
|------|------|---------------|
| DC-BOS-01/02 | Domain Controllers | lsass.exe, dfsr.exe, dns.exe |
| DC-ATL-01 | Domain Controller | lsass.exe, dfsr.exe |
| FILE-BOS-01 | File Server | svchost.exe, dfsr.exe |
| SQL-PROD-01 | SQL Database | sqlservr.exe, sqlagent.exe |
| APP-BOS-01 | IIS/API Server | w3wp.exe, iisexpress.exe |
| BACKUP-ATL-01 | Backup Server | svchost.exe, vssadmin.exe |

### Workstations (20 sampled/day)
Sampled deterministically by day seed. Typical processes: OUTLOOK.EXE, msedge.exe, Teams.exe, WINWORD.EXE, EXCEL.EXE.

---

## Example Events

### Process Create (EID 1) - Baseline
```
01/05/2026 02:15:30 PM
LogName=Microsoft-Windows-Sysmon/Operational
SourceName=Microsoft-Windows-Sysmon
EventCode=1
ComputerName=DC-BOS-01.theFakeTshirtCompany.com
TaskCategory=Process Create (rule: ProcessCreate)
Message=Process Create:
Image: C:\Windows\System32\lsass.exe
CommandLine: C:\Windows\System32\lsass.exe
User: NT AUTHORITY\SYSTEM
ParentImage: C:\Windows\System32\wininit.exe
```

### Network Connection (EID 3) - Exfil C2
```
01/08/2026 01:15:42 AM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=3
ComputerName=WS-BOS-055.theFakeTshirtCompany.com
Message=Network connection detected:
Image: C:\Windows\System32\svchost.exe
User: FAKETSHIRTCO\alex.miller
Protocol: tcp
DestinationIp: 185.220.101.42
DestinationPort: 443
demo_id=exfil
```

### File Create (EID 11) - Ransomware
```
01/08/2026 02:08:15 PM
LogName=Microsoft-Windows-Sysmon/Operational
EventCode=11
ComputerName=WS-AUS-020.theFakeTshirtCompany.com
Message=File created:
Image: C:\Users\brooklyn.white\AppData\Local\Temp\update.exe
TargetFilename: C:\Users\brooklyn.white\AppData\Roaming\svchost.exe
demo_id=ransomware_attempt
```

---

## Use Cases

### 1. Detect lateral movement (Mimikatz)
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=10 TargetImage="*lsass.exe"
| table _time, ComputerName, SourceImage, GrantedAccess
```

### 2. Suspicious PowerShell execution
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=1 Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*Invoke-*")
| table _time, ComputerName, User, CommandLine
```

### 3. C2 callback detection
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=3 demo_id=exfil
| stats count by DestinationIp, DestinationPort, Image
| sort - count
```

### 4. Ransomware file creation
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=11 demo_id=ransomware_attempt
| table _time, ComputerName, Image, TargetFilename
```

### 5. Registry persistence
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=13 TargetObject="*\Run\*"
| table _time, ComputerName, User, TargetObject, Details
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 4-13 | Day 4: phishing DNS/PowerShell. Days 5-7: mimikatz, SMB lateral. Days 8-10: registry persistence, 7z staging. Days 11-13: rclone exfil, cloud DNS |
| **ransomware_attempt** | 7-8 | Macro execution, malware drop, C2 callback, lateral SMB, EDR detection |

---

## Talking Points

**Exfil detection:**
> "Look at the Sysmon EID 10 events targeting lsass.exe -- that's Mimikatz credential dumping. Then follow EID 3 for the C2 callback to the threat actor IP. The full attack chain is visible in Sysmon alone."

**Ransomware:**
> "Sysmon captures the entire ransomware kill chain: the macro creates a child process (EID 1), drops a payload (EID 11), establishes C2 (EID 3), then attempts lateral movement via SMB (EID 3 to port 445). EDR catches it before encryption starts."

---

## Related Sources

- [WinEventLog](wineventlog.md) - Logon events, service changes
- [Cisco ASA](cisco_asa.md) - Network-level C2 detection
- [Entra ID](entraid.md) - Cloud identity correlation
