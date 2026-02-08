# Windows Event Log

Windows Security and System event logs from domain controllers, file servers, and workstations.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `XmlWinEventLog` |
| Format | XML |
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
| `System.TimeCreated.SystemTime` | Event timestamp | `2026-01-05T14:23:45Z` |
| `System.Computer` | Server FQDN | `BOS-DC-01.theFakeTshirtCompany.com` |
| `System.EventID` | Event ID | `4624` |
| `System.Level` | Severity | `0` (Info), `2` (Error) |
| `System.Channel` | Log channel | `Security`, `System` |
| `EventData.TargetUserName` | Target user | `alex.miller` |
| `EventData.SourceNetworkAddress` | Source IP | `10.10.30.55` |
| `EventData.LogonType` | Logon type | `3` (Network) |
| `EventData.NewProcessName` | Process path | `C:\Windows\System32\cmd.exe` |
| `EventData.ParentProcessName` | Parent process | `C:\Windows\explorer.exe` |

---

## Example Events

### Successful Logon (4624)
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-05T08:15:00Z"/>
    <Computer>BOS-DC-01.theFakeTshirtCompany.com</Computer>
    <EventID>4624</EventID>
    <Level>0</Level>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">alex.miller</Data>
    <Data Name="TargetDomainName">FAKETSHIRTCO</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="SourceNetworkAddress">10.10.30.55</Data>
    <Data Name="WorkstationName">BOS-WS-AMILLER01</Data>
  </EventData>
</Event>
```

### Failed Logon (4625)
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-08T14:10:00Z"/>
    <Computer>AUS-WS-BWHITE01.theFakeTshirtCompany.com</Computer>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="SourceNetworkAddress">10.30.30.20</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
  <RenderingInfo>
    <Message>An account failed to log on. Unknown user name or bad password.</Message>
  </RenderingInfo>
  <demo_id>ransomware_attempt</demo_id>
</Event>
```

### Process Creation (4688) - Ransomware
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-08T14:03:00Z"/>
    <Computer>AUS-WS-BWHITE01.theFakeTshirtCompany.com</Computer>
    <EventID>4688</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe</Data>
    <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\WINWORD.EXE</Data>
    <Data Name="CommandLine">svchost_update.exe -silent</Data>
    <Data Name="TargetUserName">bwhite</Data>
  </EventData>
  <demo_id>ransomware_attempt</demo_id>
</Event>
```

### Service Installed (4697)
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-08T14:04:00Z"/>
    <Computer>AUS-WS-BWHITE01.theFakeTshirtCompany.com</Computer>
    <EventID>4697</EventID>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="ServiceName">Windows Update Helper</Data>
    <Data Name="ServiceFileName">C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe</Data>
    <Data Name="ServiceType">0x10</Data>
  </EventData>
  <demo_id>ransomware_attempt</demo_id>
</Event>
```

### Defender Detection (1116)
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-08T14:12:00Z"/>
    <Computer>AUS-WS-BWHITE01.theFakeTshirtCompany.com</Computer>
    <EventID>1116</EventID>
    <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Threat Name">Trojan:Win32/Emotet.RPK!MTB</Data>
    <Data Name="Path">C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe</Data>
    <Data Name="Action">Quarantine</Data>
    <Data Name="Category">Trojan</Data>
  </EventData>
  <demo_id>ransomware_attempt</demo_id>
</Event>
```

### SQL Server Error (17883)
```xml
<Event>
  <System>
    <TimeCreated SystemTime="2026-01-11T16:30:00Z"/>
    <Computer>BOS-SQL-PROD-01.theFakeTshirtCompany.com</Computer>
    <EventID>17883</EventID>
    <Channel>Application</Channel>
  </System>
  <EventData>
    <Data>Process 0:0:0 (0x0) Worker 0x00000000 appears to be non-yielding on Scheduler 0.</Data>
  </EventData>
  <demo_id>cpu_runaway</demo_id>
</Event>
```

---

## Use Cases

### 1. Authentication Monitoring
Track logon activity:
```spl
index=windows sourcetype=XmlWinEventLog EventID=4624
| stats count by EventData.TargetUserName, EventData.LogonType
| sort - count
```

### 2. Failed Logon Detection
Find brute force attempts:
```spl
index=windows sourcetype=XmlWinEventLog EventID=4625
| stats count by EventData.TargetUserName, EventData.SourceNetworkAddress
| where count > 5
| sort - count
```

### 3. Process Creation Chain
Track process genealogy:
```spl
index=windows sourcetype=XmlWinEventLog EventID=4688
| table _time, System.Computer, EventData.NewProcessName, EventData.ParentProcessName, EventData.CommandLine
| sort _time
```

### 4. Service Installation
Monitor new services:
```spl
index=windows sourcetype=XmlWinEventLog EventID=4697
| table _time, System.Computer, EventData.ServiceName, EventData.ServiceFileName
```

### 5. Ransomware Kill Chain
Full ransomware timeline:
```spl
index=windows sourcetype=XmlWinEventLog demo_id=ransomware_attempt
| sort _time
| table _time, System.EventID, EventData.NewProcessName, EventData.TargetUserName
```

### 6. SQL Server Errors
Track database issues:
```spl
index=windows sourcetype=XmlWinEventLog System.Computer="*SQL*"
  (EventID=17883 OR EventID=833 OR EventID=19406)
| table _time, System.EventID, EventData.Data
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

