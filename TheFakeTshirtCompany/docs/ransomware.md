# Ransomware Attempt Scenario

A ransomware attack that is **detected and stopped**. Sales engineer Brooklyn White in Austin receives phishing email with malicious Word macro. Meraki IDS detects lateral movement and automatically isolates the endpoint.

**Outcome:** Attack fails - EDR and IDS stop it before encryption.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 1 day (20 minutes active) |
| Category | Attack |
| demo_id | `ransomware_attempt` |
| Outcome | Blocked by EDR + IDS |

---

## Key Personnel

### Target User
| Attribute | Value |
|-----------|-------|
| Name | Brooklyn White |
| Role | Sales Engineer |
| Location | Austin |
| Email | brooklyn.white@theFakeTshirtCompany.com |
| Hostname | AUS-WS-BWHITE01 |
| IP | 10.30.30.20 |

### Command & Control Server
| Attribute | Value |
|-----------|-------|
| IP | 194.26.29.42 |
| Location | Russia |
| Port | 443 (HTTPS) |
| ASN | AS49505 |

---

## Malware Details

| Attribute | Value |
|-----------|-------|
| Filename | svchost_update.exe |
| Path | C:\Users\bwhite\AppData\Local\Temp\svchost_update.exe |
| Hash (SHA1) | a1b2c3d4e5f6789012345678901234567890abcd |
| AV Signature | Trojan:Win32/Emotet.RPK!MTB |
| IDS Signature | ET TROJAN Emotet CnC Beacon |
| Persistence | Service "Windows Update Helper" |

---

## Timeline - Day 8

| Time | Event | Description |
|------|-------|-------------|
| **13:55** | Email received | "Outstanding Invoice - Immediate Action Required" with `Invoice_Q4_2026.docm` |
| **14:02** | Macro executes | Brooklyn opens attachment, Word macro activates |
| **14:03** | Dropper launched | `svchost_update.exe` runs from Temp folder |
| **14:05** | C2 callback | HTTPS to 194.26.29.42:443 (Russia) |
| **14:08** | Lateral attempt | SMB scanning of Austin subnet (10.30.30.21-40) |
| **14:12** | EDR detection | Windows Defender detects `Trojan:Win32/Emotet.RPK!MTB` |
| **14:15** | Isolation | Meraki MX isolates client, AP disconnects |

---

## Kill Chain Visualization

```
13:55          14:02          14:03          14:05          14:08          14:12    14:15
  │              │              │              │              │              │        │
  ▼              ▼              ▼              ▼              ▼              ▼        ▼
┌────┐        ┌────┐        ┌────┐        ┌────┐        ┌────┐        ┌────┐    ┌────┐
│EMAIL│───────│MACRO│───────│DROP│────────│ C2 │────────│LAT │────────│ EDR│────│ISOL│
│RECV │       │EXEC │       │ER  │        │CALL│        │MOVE│        │ DET│    │ATE │
└────┘        └────┘        └────┘        └────┘        └────┘        └────┘    └────┘
                                                           │              │        │
                                                           │              │        │
                                                       BLOCKED        QUARANTINE  DISCONNECT
```

**Total time from infection to containment: 20 minutes**

---

## Phishing Email

| Attribute | Value |
|-----------|-------|
| From | accounting@invoices-delivery.com (spoofed) |
| To | brooklyn.white@theFakeTshirtCompany.com |
| Subject | "Outstanding Invoice - Immediate Action Required" |
| Attachment | Invoice_Q4_2026.docm (250-350KB) |
| From IP | 185.234.72.15 |

---

## Lateral Movement Targets

| IP | Hostname | User | Attempt | Result |
|----|----------|------|---------|--------|
| 10.30.30.21 | AUS-WS-DHARRIS01 | dakota.harris | SMB 445 | **Blocked** |
| 10.30.30.22 | AUS-WS-PMARTIN01 | phoenix.martin | SMB 445 | **Blocked** |
| 10.30.30.40 | AUS-WS-ACOLLINS01 | amelia.collins | SMB 445 | **Blocked** |

All lateral attempts blocked by Meraki IDS/IPS.

---

## Logs to Look For

### Exchange - Phishing email
```spl
index=cloud sourcetype="ms:o365:*"
  sender="*invoices-delivery.com"
  recipient="brooklyn.white*"
  demo_id=ransomware_attempt
```

### Windows Event Log - Kill chain
```spl
index=windows sourcetype=WinEventLog
  (EventCode=4688 OR EventCode=4697 OR EventCode=1116 OR EventCode=4625)
  ComputerName="AUS-WS-BWHITE01"
  demo_id=ransomware_attempt
| sort _time
```

**Event sequence:**
- **4688** - WINWORD.EXE opens Invoice_Q4_2026.docm
- **4688** - svchost_update.exe spawned from WINWORD
- **4697** - Service "Windows Update Helper" installed
- **4625** - Multiple failed logons to other Austin machines
- **1116** - Defender quarantine

### ASA - C2 communication
```spl
index=network sourcetype=cisco:asa
  dest_ip=194.26.29.42
  demo_id=ransomware_attempt
```

### Meraki - IDS and isolation
```spl
index=network sourcetype=meraki:*
  (type=ids_alert OR type=client_isolated)
  demo_id=ransomware_attempt
```

---

## Talking Points

**Opening:**
> "This scenario shows how modern defenses can stop a ransomware attack mid-chain. Brooklyn White in Austin receives a convincing invoice email."

**Detection:**
> "Notice the timing: only 10 minutes from macro execution to full isolation. Windows Defender detects the trojan, and simultaneously Meraki IDS sees lateral SMB scanning. The systems correlate automatically and isolate the endpoint."

**Value:**
> "Without this integration, the attacker would have had hours to move laterally and start encryption. Instead, we have full forensics data and an isolated machine ready for reimaging."

**Defense in depth:**
> "This shows our layered security: email filtering caught nothing (social engineering bypassed it), but endpoint protection and network security worked together to contain the threat."

---

## Splunk Queries

### Full attack timeline
```spl
index=* demo_id=ransomware_attempt
| sort _time
| table _time, sourcetype, host, EventCode, message, action
```

### Process creation chain
```spl
index=windows sourcetype=WinEventLog EventCode=4688
  ComputerName="AUS-WS-BWHITE01"
  demo_id=ransomware_attempt
| table _time, NewProcessName, ParentProcessName, CommandLine
```

### C2 beacons
```spl
index=network sourcetype=cisco:asa
  src_ip=10.30.30.20 dest_ip=194.26.29.42
  demo_id=ransomware_attempt
| timechart count
```

### Lateral movement attempts
```spl
index=windows EventCode=4625
  IpAddress=10.30.30.20
  demo_id=ransomware_attempt
| stats count by TargetUserName, IpPort
```

### Meraki isolation event
```spl
index=network sourcetype=meraki:mx
  type=client_isolated
  demo_id=ransomware_attempt
| table _time, deviceName, clientMac, eventData.reason
```
