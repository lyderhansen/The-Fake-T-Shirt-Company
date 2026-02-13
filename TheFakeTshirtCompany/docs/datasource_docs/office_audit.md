# Office 365 Unified Audit Log

Microsoft 365 Unified Audit Log events across SharePoint, OneDrive, and Microsoft Teams for 175 employees. Covers file operations, collaboration, external sharing, and security compliance with 30+ operation types across 6 RecordTypes and 3 attack/awareness scenarios.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `o365:management:activity` |
| Format | JSON (NDJSON) |
| Output File | `output/cloud/microsoft/office_audit.json` |
| Volume | ~170 events/peak hour at scale 1.0 |
| Workloads | SharePoint (25%), OneDrive (35%), Teams (40%) |
| Tenant | theFakeTshirtCompany.com |
| Tenant ID | af23e456-7890-1234-5678-abcdef012345 |

---

## Key Fields

### Common Fields (All Operations)

| Field | Description | Example |
|-------|-------------|---------|
| `Id` | Unique event identifier | `a1b2c3d4-...` (UUID) |
| `RecordType` | M365 operation category | `6`, `7`, `25`, `14`, `146`, `18` |
| `CreationTime` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `Operation` | Specific operation name | `FileAccessed`, `MessageSent` |
| `OrganizationId` | Azure AD tenant ID | `af23e456-7890-1234-5678-abcdef012345` |
| `Workload` | Service component | `SharePoint`, `OneDrive`, `MicrosoftTeams` |
| `UserId` | User email (UPN) | `alex.miller@theTshirtCompany.com` |
| `ClientIP` | Source IP address | `10.10.30.55` |
| `UserType` | User classification | `0` (regular), `2` (admin) |
| `UserAgent` | Client application | `Mozilla/5.0...`, `Microsoft Office/16.0` |
| `ResultStatus` | Operation outcome | `Succeeded`, `Failed` |
| `demo_id` | Scenario tag | `exfil`, `ransomware_attempt`, `phishing_test` |

### SharePoint / OneDrive Fields

| Field | Description | Example |
|-------|-------------|---------|
| `ObjectId` | Full file URL path | `https://theTshirtCompany.sharepoint.com/sites/FinanceTeam/Shared Documents/Q4-Budget-2026.xlsx` |
| `SiteUrl` | SharePoint site URL | `https://theTshirtCompany.sharepoint.com/sites/FinanceTeam` |
| `SourceRelativeUrl` | Folder path relative to site | `Shared Documents` |
| `SourceFileName` | File name | `Q4-Budget-2026.xlsx` |
| `SourceFileExtension` | File type | `xlsx` |
| `ItemType` | Object type | `File` |
| `EventSource` | Source system | `SharePoint` |

### Teams Fields

| Field | Description | Example |
|-------|-------------|---------|
| `TeamName` | Team name (department-based) | `Finance Team` |
| `ChannelName` | Channel within team | `General`, `Budget-Planning` |
| `CommunicationType` | Message type | `Channel`, `OneOnOne` |

### Sharing Fields

| Field | Description | Example |
|-------|-------------|---------|
| `TargetUserOrGroupName` | Sharing recipient | `john@partner-company.com` |
| `TargetUserOrGroupType` | Recipient type | `Guest` |

### Failure Fields

| Field | Values |
|-------|--------|
| `ResultStatus` | `Succeeded`, `Failed` |
| `ResultStatusDetail` | `FileNotFound`, `AccessDenied`, `FileLocked`, `QuotaExceeded`, `VirusDetected`, `BlockedByPolicy` |

---

## Event Types

### SharePoint (RecordType 6, ~25% of events)

| Operation | Weight | Description |
|-----------|--------|-------------|
| FileAccessed | 40% | User reads a file from team site |
| FileModified | 25% | User edits a document |
| FileDownloaded | 15% | User downloads a file |
| FileUploaded | 8% | User uploads a new file |
| FileCheckedOut | 4% | User checks out file for editing |
| FileCheckedIn | 3% | User checks in modified file |
| FileDeleted | 3% | User deletes a file |
| SharingSet | 2% | User shares file with others |

### OneDrive (RecordType 7, ~35% of events)

| Operation | Weight | Description |
|-----------|--------|-------------|
| FileAccessed | 35% | User reads a personal file |
| FileModified | 30% | User edits a document |
| FileSyncUploadedFull | 15% | Sync client uploads file to cloud |
| FileDownloaded | 10% | User downloads a file |
| FileUploaded | 5% | User uploads a new file |
| FileDeleted | 3% | User deletes a file |
| SharingSet | 2% | User shares file with others |

Scenario-only operations:
- `FileRestored` -- IT admin restores files (ransomware recovery)
- `FileSyncDownloadedFull` -- Sync client downloads from cloud (exfil bulk download)

### Microsoft Teams (RecordType 25, ~40% of events)

| Operation | Weight | Description |
|-----------|--------|-------------|
| MessageSent | 50% | User sends channel/DM message |
| ChannelFileUploaded | 20% | File uploaded to Teams channel |
| ChannelFileAccessed | 15% | File accessed in Teams channel |
| MemberAdded | 5% | User added to team |
| MeetingCreated | 5% | Meeting created in Teams |
| TeamCreated | 3% | New team created |
| TeamDeleted | 2% | Team deleted |

### External Sharing (RecordType 14)

| Operation | Description |
|-----------|-------------|
| SharingInvitationCreated | External sharing invitation to partner domain |

Partner domains: partner-company.com, consulting-group.net, vendor-solutions.com, agency-creative.com, client-org.net

### Phishing / Security (RecordType 146, 18)

| Operation | RecordType | Workload | Description |
|-----------|-----------|----------|-------------|
| SafeLinksUrlClicked | 146 | ThreatIntelligence | Employee clicks phishing sim URL |
| SecurityComplianceSearch | 18 | SecurityComplianceCenter | Admin exports phishing results |
| ViewReport | 18 | SecurityComplianceCenter | Admin views campaign report |
| AdminActivity | 18 | SecurityComplianceCenter | Admin reviews campaign |

---

## SharePoint Sites

8 department-based sites with access control:

| Site | URL Slug | Departments | Files |
|------|----------|-------------|-------|
| All Company | /sites/AllCompany | All | 5-10 general docs |
| HR Portal | /sites/HRPortal | HR, Executive | Handbook, PTO policy, benefits |
| IT Resources | /sites/ITResources | IT, Engineering | Network topology, DR plan, security policy |
| Finance Team | /sites/FinanceTeam | Finance, Executive | Q4 Budget, revenue reports, invoices, forecasts |
| Engineering | /sites/Engineering | Engineering, IT | API specs, architecture, release notes |
| Sales Team | /sites/SalesTeam | Sales | Proposals, sales decks, price lists |
| Marketing | /sites/Marketing | Marketing | Brand guidelines, campaign assets |
| Product Catalog | /sites/ProductCatalog | Engineering, Marketing | Product docs, collateral |

---

## Teams Channels

| Department | Channels |
|-----------|----------|
| Finance | General, Budget-Planning, Month-End-Close, Expense-Reports |
| Sales | General, Pipeline, Deals, Customer-Success |
| Engineering | General, Code-Reviews, Incidents, Architecture |
| HR | General, Recruiting, Benefits, Announcements |
| Marketing | General, Campaigns, Content, Analytics |
| IT | General, Helpdesk, Infrastructure, Security |
| Executive | General, Strategy, Board-Updates |
| Legal | General, Contracts, Compliance |
| Operations | General, Shipping, Inventory |

---

## Volume Patterns

| Period | Events/Hour | Notes |
|--------|-------------|-------|
| Peak (9-11 AM, 1-3 PM) | ~170 | Full business hours |
| Lunch (12 PM) | ~102 | 60% of peak |
| Evening (6-9 PM) | ~34-51 | 20-30% of peak |
| Night (12-6 AM) | ~17 | 10% of peak |

- Monday boost: +15%
- Weekend: 30% of weekday (automated activity only)
- Daily noise: +/-15% (deterministic via date hashing)
- Baseline failure rate: ~3% on file operations

---

## Use Cases

### 1. File activity by workload
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity"
| stats count by Workload, Operation
| sort Workload, - count
```

### 2. External sharing detection
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" RecordType=14
| table _time, UserId, Operation, TargetUserOrGroupName, SourceFileName
| sort _time
```

### 3. Exfil bulk download detection (off-hours)
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" demo_id=exfil
    Operation IN ("FileDownloaded", "FileSyncDownloadedFull")
| eval hour=strftime(_time, "%H")
| where hour >= 1 AND hour <= 5
| stats count by UserId, SiteUrl, hour
| sort - count
```

### 4. Teams activity overview
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" Workload="MicrosoftTeams"
| stats count by Operation, TeamName
| sort - count
```

### 5. Failed operations
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" ResultStatus="Failed"
| stats count by UserId, Operation, ResultStatusDetail
| sort - count
```

### 6. Phishing campaign click rates
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" demo_id=phishing_test
    Operation="SafeLinksUrlClicked"
| stats count by UserId
| sort - count
```

### 7. Ransomware file recovery
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity" demo_id=ransomware_attempt
    Operation="FileRestored"
| table _time, UserId, SourceFileName, ObjectId
| sort _time
```

### 8. User file access timeline
```spl
index=fake_tshrt sourcetype="FAKE:o365:management:activity"
    UserId="alex.miller@theTshirtCompany.com"
| timechart span=1h count by Workload
```

---

## Scenario Integration

### Exfil (Days 4-13)

Multi-phase data theft through SharePoint and OneDrive:

| Phase | Days | Activity | Operations | Target |
|-------|------|----------|-----------|--------|
| Initial Access | Day 4 | Finance site access from threat IP | FileAccessed | FinanceTeam site |
| Lateral Movement | Days 5-7 | Jessica (compromised IT) browses HR, Finance, Engineering, Executive sites | FileDownloaded (30% chance/hour) | Multiple sites |
| Persistence | Days 8-10 | External sharing + staging to OneDrive | SharingSet, FileUploaded | Finance docs to external partner, OneDrive staging folder |
| Exfiltration | Days 11-13 | Bulk downloads at night (01:00-05:00) | FileDownloaded (40-80/night), FileSyncDownloadedFull (3-6/night) | FinanceTeam site, OneDrive staging |

Key indicators:
- Threat actor IP (`185.220.101.42`) in ClientIP field
- Off-hours bulk file access (01:00-05:00)
- External sharing to unknown domains
- Finance files accessed by IT admin (jessica.brown)

### Ransomware Attempt (Days 8-9)

| Phase | Day | Activity | Operations | Target |
|-------|-----|----------|-----------|--------|
| Encryption attempt | Day 8, 15:35-15:40 | Rapid file access/modification | FileAccessed + FileModified alternating (10-15 events) | Brooklyn White's OneDrive |
| Recovery | Day 9, 09:00-11:00 | IT admin restores files | FileRestored (3-6 events) | Brooklyn's OneDrive |

### Phishing Test (Days 21-23)

| Phase | Days | Activity | Operations | Target |
|-------|------|----------|-----------|--------|
| URL Clicks | Days 21-22 | Employees click phishing sim link | SafeLinksUrlClicked (RecordType 146) | Deterministic clicker set |
| Admin Review | Day 23, 10:00 | ashley.griffin reviews results | SecurityComplianceSearch, ViewReport, AdminActivity (RecordType 18) | Security compliance center |

---

## User Agents

| Type | Example |
|------|---------|
| Chrome (Windows) | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0` |
| Firefox | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0` |
| Chrome (Mac) | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0` |
| Microsoft Office | `Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0)` |
| OneDrive Sync | `Microsoft SkyDriveSync 23.235.1118 ship; Windows NT 10.0` |

---

## Talking Points

**M365 as attack surface:** "Office 365 audit logs capture every file access, share, and download. During the exfil scenario, we can see the attacker downloading finance documents at 2 AM -- a clear anomaly when normal business hours show zero activity."

**External sharing risk:** "The SharingInvitationCreated events show the attacker sharing sensitive Finance documents with external email addresses. This is a common exfiltration technique that bypasses network-layer detection."

**Cross-source correlation:** "When you see bulk FileDownloaded events in M365 Audit, correlate with Entra ID sign-ins (same user, same ClientIP from Germany) and ASA logs (large outbound data transfers) to build the complete attack narrative."

**Phishing awareness metrics:** "The phishing_test scenario shows SafeLinksUrlClicked events -- you can measure exactly which employees clicked the simulated phishing link and correlate with their department and location."

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Splunk Add-on for MS Office 365](https://splunkbase.splunk.com/app/4055) |
| **Ingestion** | Office 365 Management Activity API polling |
| **Real sourcetype** | `o365:management:activity` -- matches our generator exactly |
