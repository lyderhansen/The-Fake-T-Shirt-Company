# Windows Event Log

Windows Security and System event logs from domain controllers, file servers, and workstations.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `WinEventLog` |
| Format | KV pairs |
| Output File | `output/windows/windows_events.log` |
| Volume | 500-2000 events/day |
| Channels | Security, System |

---

## Monitored Servers

| Server | Role | Location |
|--------|------|----------|
| BOS-DC-01 | Domain Controller | Boston |
| BOS-DC-02 | Domain Controller | Boston |
| BOS-FILE-01 | File Server | Boston |
| BOS-SQL-PROD-01 | SQL Database | Boston |
| ATL-DC-01 | Domain Controller | Atlanta |
| AUS-WS-BWHITE01 | Workstation | Austin |

---

## Key Event IDs

### Security Events
| EventID | Description | Category |
|---------|-------------|----------|
| 4624 | Successful logon | Logon |
| 4625 | Failed logon | Logon |
| 4648 | Logon with explicit credentials | Logon |
| 4688 | Process created | Process |
| 4720 | User account created | Account |
| 4722 | User account enabled | Account |
| 4726 | User account deleted | Account |
| 4738 | User account changed | Account |
| 4756 | Member added to group | Group |
| 4697 | Service installed | Service |
| 1116 | Windows Defender detection | AV |

### System Events
| EventID | Description | Category |
|---------|-------------|----------|
| 7000 | Service failed to start | Service |
| 7001 | Service started | Service |
| 7002 | Service stopped | Service |
| 6005 | Event log service started | System |
| 6006 | Event log service stopped | System |

### SQL Server Events
| EventID | Description | Category |
|---------|-------------|----------|
| 17883 | Process not yielding | SQL |
| 833 | IO taking too long | SQL |
| 19406 | Backup media error | SQL |
| 17148 | SQL Server terminating | SQL |
| 17147 | SQL Server starting | SQL |

---

## Logon Types

| Type | Name | Description |
|------|------|-------------|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, network share |
| 4 | Batch | Scheduled task |
| 5 | Service | Service logon |
| 7 | Unlock | Workstation unlock |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `_time` | Event timestamp | `01/05/2026 02:23:45 PM` |
| `ComputerName` | Server FQDN | `BOS-DC-01.theFakeTshirtCompany.com` |
| `EventCode` | Event ID | `4624` |
| `Type` | Severity | `Information`, `Error` |
| `LogName` | Log channel | `Security`, `System` |
| `TargetUserName` | Target user | `alex.miller` |
| `SourceNetworkAddress` | Source IP | `10.10.30.55` |
| `LogonType` | Logon type | `3` (Network) |
| `NewProcessName` | Process path | `C:\Windows\System32\cmd.exe` |
| `ParentProcessName` | Parent process | `C:\Windows\explorer.exe` |

---

## Example Events

### Successful Logon (4624)
```
01/05/2026 08:15:00 AM
LogName=Security
EventCode=4624
ComputerName=BOS-DC-01.theFakeTshirtCompany.com
Type=Information
Message=An account was successfully logged on.
  TargetUserName: alex.miller
  TargetDomainName: FAKETSHIRTCO
  LogonType: 3
  SourceNetworkAddress: 10.10.30.55
  WorkstationName: BOS-WS-AMILLER01
```

### Failed Logon (4625)
```
01/08/2026 02:10:00 PM
LogName=Security
EventCode=4625
ComputerName=AUS-WS-BWHITE01.theFakeTshirtCompany.com
Type=Information
Message=An account failed to log on. Unknown user name or bad password.
  TargetUserName: administrator
  SourceNetworkAddress: 10.30.30.20
  FailureReason: %%2313
  Status: 0xC000006D
  SubStatus: 0xC000006A
demo_id=ransomware_attempt
```

### Process Creation (4688) - Ransomware
```
01/08/2026 02:03:00 PM
LogName=Security
EventCode=4688
ComputerName=AUS-WS-BWHITE01.theFakeTshirtCompany.com
Type=Information
Message=A new process has been created.
  NewProcessName: C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe
  ParentProcessName: C:\Program Files\Microsoft Office\WINWORD.EXE
  CommandLine: svchost_update.exe -silent
  TargetUserName: bwhite
demo_id=ransomware_attempt
```

### Service Installed (4697)
```
01/08/2026 02:04:00 PM
LogName=Security
EventCode=4697
ComputerName=AUS-WS-BWHITE01.theFakeTshirtCompany.com
Type=Information
Message=A service was installed in the system.
  ServiceName: Windows Update Helper
  ServiceFileName: C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe
  ServiceType: 0x10
demo_id=ransomware_attempt
```

### Defender Detection (1116)
```
01/08/2026 02:12:00 PM
LogName=Microsoft-Windows-Windows Defender/Operational
EventCode=1116
ComputerName=AUS-WS-BWHITE01.theFakeTshirtCompany.com
Type=Warning
Message=Windows Defender Antivirus has detected malware or other potentially unwanted software.
  Threat Name: Trojan:Win32/Emotet.RPK!MTB
  Path: C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe
  Action: Quarantine
  Category: Trojan
demo_id=ransomware_attempt
```

### SQL Server Error (17883)
```
01/11/2026 04:30:00 PM
LogName=Application
EventCode=17883
ComputerName=BOS-SQL-PROD-01.theFakeTshirtCompany.com
Type=Error
Message=Process 0:0:0 (0x0) Worker 0x00000000 appears to be non-yielding on Scheduler 0.
demo_id=cpu_runaway
```

---

## Use Cases

### 1. Authentication Monitoring
Track logon activity:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4624
| stats count by TargetUserName, LogonType
| sort - count
```

### 2. Failed Logon Detection
Find brute force attempts:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4625
| stats count by TargetUserName, SourceNetworkAddress
| where count > 5
| sort - count
```

### 3. Process Creation Chain
Track process genealogy:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4688
| table _time, ComputerName, NewProcessName, ParentProcessName, CommandLine
| sort _time
```

### 4. Service Installation
Monitor new services:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4697
| table _time, ComputerName, ServiceName, ServiceFileName
```

### 5. Ransomware Kill Chain
Full ransomware timeline:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" demo_id=ransomware_attempt
| sort _time
| table _time, EventCode, ComputerName, NewProcessName, TargetUserName
```

### 6. SQL Server Errors
Track database issues:
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" ComputerName="*SQL*"
  (EventCode=17883 OR EventCode=833 OR EventCode=19406)
| table _time, EventCode, Message
```

---

## Scenario Integration

| Scenario | Events | Pattern |
|----------|--------|---------|
| **ransomware_attempt** | 4688, 4697, 4625, 1116 | Word→dropper→service→lateral→quarantine |
| **cpu_runaway** | 17883, 833, 19406 | SQL non-yielding, I/O delays |
| **exfil** | 4624, 4625 | Suspicious logons from attacker |

---

## Ransomware Kill Chain

```
14:02 - 4688: WINWORD.EXE opens Invoice_Q4_2026.docm
14:03 - 4688: svchost_update.exe spawned from WINWORD
14:04 - 4697: Service "Windows Update Helper" installed
14:08 - 4625: Failed logon attempts to other machines
14:12 - 1116: Defender quarantines Trojan:Win32/Emotet
```

---

## Talking Points

**Ransomware Detection:**
> "The kill chain is clear in Windows events. Word opens the macro document at 14:02. One minute later, a suspicious EXE spawns from Word. A service gets installed for persistence. Then lateral movement attempts - failed logons. Finally Defender catches it at 14:12."

**Process Genealogy:**
> "svchost_update.exe spawned from WINWORD.EXE - that's highly suspicious. Normal Word documents don't launch executables. This is our smoking gun for the macro-based attack."

**SQL Server Correlation:**
> "Event 17883 (non-yielding process) correlates with the Perfmon CPU spike. SQL Server is telling us it's having problems at the same time we see 100% CPU."

**Lateral Movement:**
> "The 4625 failed logons from 10.30.30.20 to other Austin machines show the ransomware trying to spread. It's using Brooklyn's credentials to try to access other workstations."

---

## Related Sources

- [Perfmon](perfmon.md) - Performance correlation
- [ServiceNow](servicenow.md) - Incident tracking
- [Meraki](meraki.md) - Network isolation events

