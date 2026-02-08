# Exchange Message Tracking

Microsoft 365 Exchange message trace logs for email flow analysis.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `ms:o365:reporting:messagetrace` |
| Format | JSON |
| Output File | `output/cloud/exchange_messagetrace.log` |
| Volume | 500-1500 events/day |
| Domain | theFakeTshirtCompany.com |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `Received` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `SenderAddress` | From email | `jessica.brown@theFakeTshirtCompany.com` |
| `RecipientAddress` | To email | `external@gmail.com` |
| `Subject` | Email subject | `Q4 Financial Report` |
| `Status` | Delivery status | `Delivered`, `Failed` |
| `FromIP` | Sending server IP | `10.10.20.50` |
| `ToIP` | Receiving server IP | `8.8.8.8` |
| `Size` | Message size (bytes) | `524288` |
| `MessageID` | Message identifier | `<abc123@mail.com>` |
| `MessageTraceID` | Trace identifier | `trace-001` |
| `EventType` | Event type | `Receive`, `Send`, `Deliver` |
| `demo_id` | Scenario tag | `exfil` |

---

## Status Values

| Status | Description |
|--------|-------------|
| `Delivered` | Successfully delivered |
| `Failed` | Delivery failed |
| `Deferred` | Temporarily delayed |
| `Receive` | Message received |
| `FilteredAsSpam` | Caught by spam filter |
| `Quarantined` | In quarantine |

---

## Example Events

### Internal Email
```json
{
  "Received": "2026-01-05T10:30:00Z",
  "SenderAddress": "john.smith@theFakeTshirtCompany.com",
  "RecipientAddress": "team@theFakeTshirtCompany.com",
  "Subject": "Weekly Team Update",
  "Status": "Delivered",
  "FromIP": "10.10.30.10",
  "Size": 15360,
  "MessageTraceID": "internal-001"
}
```

### Phishing Email (Exfil)
```json
{
  "Received": "2026-01-04T16:42:00Z",
  "SenderAddress": "security@rnicrosoft-security.com",
  "RecipientAddress": "jessica.brown@theFakeTshirtCompany.com",
  "Subject": "Action Required: Verify your account security",
  "Status": "Delivered",
  "FromIP": "185.234.72.15",
  "Size": 28672,
  "MessageTraceID": "phish-001",
  "demo_id": "exfil"
}
```

### Ransomware Phishing
```json
{
  "Received": "2026-01-08T13:55:00Z",
  "SenderAddress": "accounting@invoices-delivery.com",
  "RecipientAddress": "brooklyn.white@theFakeTshirtCompany.com",
  "Subject": "Outstanding Invoice - Immediate Action Required",
  "Status": "Delivered",
  "FromIP": "185.234.72.15",
  "Size": 307200,
  "Attachment": "Invoice_Q4_2026.docm",
  "demo_id": "ransomware_attempt"
}
```

### Data Exfiltration Email
```json
{
  "Received": "2026-01-12T03:15:00Z",
  "SenderAddress": "alex.miller@theFakeTshirtCompany.com",
  "RecipientAddress": "drop-box-1337@protonmail.com",
  "Subject": "Documents",
  "Status": "Delivered",
  "FromIP": "10.10.30.55",
  "Size": 5242880,
  "MessageTraceID": "exfil-001",
  "demo_id": "exfil"
}
```

### Failed Delivery
```json
{
  "Received": "2026-01-05T11:00:00Z",
  "SenderAddress": "sales@theFakeTshirtCompany.com",
  "RecipientAddress": "invalid@nonexistent.com",
  "Subject": "Follow Up",
  "Status": "Failed",
  "FailureReason": "550 5.1.1 User unknown"
}
```

---

## Use Cases

### 1. Phishing Detection
Find suspicious external senders:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace"
  NOT SenderAddress="*@theFakeTshirtCompany.com"
  (Subject="*urgent*" OR Subject="*action required*" OR Subject="*verify*")
| table _time, SenderAddress, RecipientAddress, Subject
```

### 2. Data Exfiltration via Email
Track large emails to external recipients:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace"
  NOT RecipientAddress="*@theFakeTshirtCompany.com"
  Size > 1000000
| eval size_mb = round(Size / 1048576, 2)
| table _time, SenderAddress, RecipientAddress, Subject, size_mb
| sort - size_mb
```

### 3. Forwarding to Personal Email
Detect data leaving via personal accounts:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace"
  RecipientAddress IN ("*@gmail.com", "*@protonmail.com", "*@yahoo.com", "*@outlook.com")
| stats count, sum(Size) AS total_bytes by SenderAddress, RecipientAddress
| eval total_mb = round(total_bytes / 1048576, 2)
| sort - total_mb
```

### 4. Email Volume Analysis
Track email patterns:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace"
| timechart span=1h count by Status
```

### 5. Domain Analysis
Identify communication with unusual domains:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace"
  NOT RecipientAddress="*@theFakeTshirtCompany.com"
| rex field=RecipientAddress "@(?<domain>.+)$"
| stats count by domain
| sort - count
```

### 6. Exfil Email Timeline
Track exfiltration scenario emails:
```spl
index=cloud sourcetype="ms:o365:reporting:messagetrace" demo_id=exfil
| sort _time
| table _time, SenderAddress, RecipientAddress, Subject, Size
```

---

## Suspicious Indicators

| Indicator | Pattern |
|-----------|---------|
| Typosquatting | `rnicrosoft` (rn = m) |
| Urgency | "Immediate", "Urgent", "Action Required" |
| External drops | ProtonMail, temp email services |
| Large attachments | Files > 5MB to external |
| Off-hours sending | Emails at 02:00-05:00 |
| Macro attachments | .docm, .xlsm files |

---

## Scenario Integration

| Scenario | Day | Activity |
|----------|-----|----------|
| **exfil** | 4 | Phishing from `rnicrosoft-security.com` |
| **exfil** | 11-14 | Data exfil to ProtonMail |
| **ransomware** | 8 | Malicious .docm attachment |

---

## Attack Patterns

### Exfil Phishing Chain
```
Day 4, 16:42: Phishing email received
  From: security@rnicrosoft-security.com
  To: jessica.brown@theFakeTshirtCompany.com
  Subject: Action Required: Verify your account security

Day 4, 17:05: Jessica clicks link (not in email logs)

Day 5+: Attacker has credentials
```

### Ransomware Email
```
Day 8, 13:55: Malicious email received
  From: accounting@invoices-delivery.com
  To: brooklyn.white@theFakeTshirtCompany.com
  Subject: Outstanding Invoice - Immediate Action Required
  Attachment: Invoice_Q4_2026.docm (250KB)

Day 8, 14:02: Brooklyn opens attachment
```

### Data Exfiltration
```
Day 11-14, 01:00-05:00: Multiple large emails
  From: alex.miller@theFakeTshirtCompany.com
  To: drop-box-1337@protonmail.com
  Size: 5-10 MB each
  Subject: Generic ("Documents", "Files", "Report")
```

---

## Talking Points

**Typosquatting:**
> "Look at the sender domain: `rnicrosoft-security.com`. That's 'r-n' not 'm'. Classic typosquatting - looks like Microsoft at a glance but isn't."

**Email Exfiltration:**
> "The attacker is using Alex's email to send data to ProtonMail at 3 AM. ProtonMail is legitimate but often used for anonymity. Combined with off-hours timing and large attachments, this is clear data theft."

**Ransomware Delivery:**
> "The invoice email has a .docm attachment - that's a macro-enabled Word document. Classic ransomware delivery mechanism. The subject creates urgency to get the user to open it quickly."

**Defense Gaps:**
> "These phishing emails got delivered. Our spam filter didn't catch them because they used new domains and didn't have obvious malicious content. This is why user training matters."

---

## Related Sources

- [Entra ID](entraid.md) - Authentication after phishing
- [WinEventLog](wineventlog.md) - Attachment execution
- [Cisco ASA](cisco_asa.md) - Network exfiltration

