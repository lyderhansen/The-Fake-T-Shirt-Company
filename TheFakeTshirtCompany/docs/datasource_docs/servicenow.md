# ServiceNow Incidents

IT Service Management incident records tracking infrastructure issues and their resolution.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `servicenow:incident` |
| Format | Key-Value pairs |
| Output File | `output/itsm/servicenow_incidents.log` |
| Volume | ~20 incidents/day |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 time | `2026-01-05T09:15:00Z` |
| `number` | Incident number | `INC0000001` |
| `state` | Current state | `New`, `In Progress`, `Resolved` |
| `short_description` | Brief summary | `SQL Server performance degradation` |
| `description` | Full description | `Users reporting slow queries...` |
| `category` | Issue category | `Hardware`, `Software`, `Network` |
| `subcategory` | Specific type | `Database`, `Server`, `Firewall` |
| `priority` | Priority (1-5) | `1` (Critical) |
| `urgency` | Urgency (1-5) | `2` |
| `impact` | Impact (1-4) | `2` |
| `caller_id` | Reporter email | `user@theFakeTshirtCompany.com` |
| `caller_name` | Reporter name | `John Smith` |
| `assignment_group` | Assigned team | `Database Admins` |
| `assigned_to` | Assigned user | `dba.admin@theFakeTshirtCompany.com` |
| `cmdb_ci` | Config item | `SQL-PROD-01` |
| `location` | Office location | `Boston HQ` |
| `close_code` | Resolution code | `Solved (Permanently)` |
| `close_notes` | Resolution details | `Killed runaway backup job` |
| `demo_id` | Scenario tag | `cpu_runaway` |

---

## States

| State | Description |
|-------|-------------|
| `New` | Just created |
| `In Progress` | Being worked on |
| `On Hold` | Waiting for something |
| `Resolved` | Fix applied |
| `Closed` | Verified and closed |

---

## Priority Levels

| Priority | Name | Response |
|----------|------|----------|
| 1 | Critical | Immediate |
| 2 | High | 1 hour |
| 3 | Moderate | 4 hours |
| 4 | Low | 24 hours |
| 5 | Planning | Scheduled |

---

## Categories

| Category | Subcategories |
|----------|---------------|
| `Hardware` | Server, Desktop, Printer |
| `Software` | Application, Database, OS |
| `Network` | Firewall, Router, VPN |
| `Account` | Password, Access, Permissions |
| `Infrastructure` | Storage, Database, Server |

---

## Assignment Groups

| Group | Handles |
|-------|---------|
| `Service Desk` | Initial triage |
| `Desktop Support` | Workstation issues |
| `Network Operations` | Network/firewall |
| `Database Admins` | SQL/database |
| `Linux Admins` | Linux servers |
| `Security Team` | Security incidents |
| `Cloud Operations` | AWS/GCP/Azure |

---

## Example Events

### New Incident (CPU Runaway)
```
timestamp="2026-01-11T15:30:00Z" number="INC0000123" state="New" short_description="SQL Server high CPU utilization" description="SQL-PROD-01 CPU at 100%, queries timing out" category="Infrastructure" subcategory="Database" priority=1 urgency=1 impact=2 caller_id="app.monitor@theFakeTshirtCompany.com" caller_name="Application Monitor" assignment_group="Database Admins" cmdb_ci="SQL-PROD-01" location="Boston HQ" demo_id=cpu_runaway
```

### In Progress
```
timestamp="2026-01-11T15:45:00Z" number="INC0000123" state="In Progress" assigned_to="dba.admin@theFakeTshirtCompany.com" assigned_to_name="DBA Admin" work_notes="Investigating SQL processes" demo_id=cpu_runaway
```

### Resolved
```
timestamp="2026-01-12T10:30:00Z" number="INC0000123" state="Resolved" close_code="Solved (Permanently)" close_notes="Backup job was stuck in infinite loop. Killed process, restarted backup service with new configuration." resolution_time="19h 0m" demo_id=cpu_runaway
```

### Memory Leak Incident
```
timestamp="2026-01-10T14:15:00Z" number="INC0000456" state="New" short_description="WEB-01 out of memory crash" description="Application server crashed due to OOM. Service restarting." category="Infrastructure" subcategory="Server" priority=1 caller_id="monitoring@theFakeTshirtCompany.com" assignment_group="Linux Admins" cmdb_ci="WEB-01" demo_id=memory_leak
```

### Disk Space Warning
```
timestamp="2026-01-08T09:00:00Z" number="INC0000789" state="New" short_description="Disk space warning on MON-ATL-01" description="Monitoring alert: MON-ATL-01 disk usage above 75%." category="Infrastructure" subcategory="Storage" priority=3 assignment_group="Linux Admins" cmdb_ci="MON-ATL-01" location="Atlanta" demo_id=disk_filling
```

### Firewall Misconfiguration
```
timestamp="2026-01-07T10:45:00Z" number="INC0000321" state="New" short_description="Website unreachable - customers reporting errors" description="Multiple customers reporting they cannot access theFakeTshirtCompany.com" category="Network" subcategory="Firewall" priority=1 assignment_group="Network Operations" cmdb_ci="FW-EDGE-01" demo_id=firewall_misconfig
```

### Certificate Expiry
```
timestamp="2026-01-12T06:30:00Z" number="INC0000654" state="New" short_description="SSL certificate expired - HTTPS failing" description="Wildcard cert for *.theFakeTshirtCompany.com expired at midnight" category="Network" subcategory="Certificates" priority=1 assignment_group="Network Operations" cmdb_ci="WEB-01" demo_id=certificate_expiry
```

### Ransomware Attempt
```
timestamp="2026-01-08T14:20:00Z" number="INC0000999" state="New" short_description="Security alert: Malware detected on AUS-WS-BWHITE01" description="EDR detected Trojan:Win32/Emotet.RPK!MTB. Endpoint isolated." category="Security" subcategory="Malware" priority=1 assignment_group="Security Team" cmdb_ci="AUS-WS-BWHITE01" demo_id=ransomware_attempt
```

---

## Use Cases

### 1. Incident Volume Trends
Track incident patterns:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident" state="New"
| timechart span=1d count by category
```

### 2. Priority Distribution
Analyze incident priorities:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident"
| stats count by priority
| eval priority_name=case(
    priority=1, "Critical",
    priority=2, "High",
    priority=3, "Moderate",
    priority=4, "Low",
    priority=5, "Planning"
)
| sort priority
```

### 3. MTTR by Category
Calculate mean time to resolve:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident" state="Resolved"
| rex field=resolution_time "(?<hours>\d+)h"
| stats avg(hours) AS mttr_hours by category
| sort mttr_hours
```

### 4. Assignment Group Workload
See team distribution:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident"
| stats count, dc(number) AS unique_incidents by assignment_group
| sort - count
```

### 5. Scenario-Specific Incidents
Track incidents by scenario:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident" demo_id=*
| stats count, values(short_description) AS incidents by demo_id
```

### 6. Incident Timeline
Full lifecycle of an incident:
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident" number="INC0000123"
| sort _time
| table _time, state, assigned_to, work_notes, close_notes
```

---

## Scenario Integration

| Scenario | Priority | Category | CI | Days |
|----------|----------|----------|-----|------|
| **cpu_runaway** | 1 | Infrastructure/Database | SQL-PROD-01 | 11-12 |
| **memory_leak** | 1 | Infrastructure/Server | WEB-01 | 5-10 |
| **disk_filling** | 3→2→1 | Infrastructure/Storage | MON-ATL-01 | 8, 11, 13 |
| **firewall_misconfig** | 1 | Network/Firewall | FW-EDGE-01 | 7 |
| **certificate_expiry** | 1 | Network/Certificates | WEB-01 | 12 |
| **ransomware_attempt** | 1 | Security/Malware | AUS-WS-BWHITE01 | 8 |

---

## Incident Lifecycle Example

### CPU Runaway Scenario
```
Day 11, 15:30: INC created (New, P1)
  - SQL-PROD-01 CPU at 100%

Day 11, 15:45: State → In Progress
  - DBA Admin assigned
  - Investigating processes

Day 11, 16:00: Work note added
  - Found backup job consuming all CPU

Day 11, 20:00: Work note added
  - Job still running, evaluating impact of kill

Day 12, 10:30: State → Resolved
  - Killed backup job
  - Reconfigured backup schedule
  - MTTR: 19 hours
```

---

## Talking Points

**Incident Correlation:**
> "The ServiceNow incident was created 15 minutes after our monitoring detected the CPU spike. We can correlate the perfmon data with the incident timeline to understand the full story."

**Priority Escalation:**
> "Notice the disk filling scenario: it started as P3 (warning), escalated to P2 (critical), then P1 (emergency). This mirrors the actual disk progression in the Linux metrics."

**Response Time:**
> "The ransomware incident was created just 8 minutes after EDR detection. Our automated alerting is working - the Security Team was notified immediately."

**Root Cause:**
> "Close notes capture the actual fix. For CPU runaway: 'Backup job was stuck in infinite loop.' For disk filling: 'Implemented log rotation.' This is valuable for post-incident review."

---

## Related Sources

- [Perfmon](perfmon.md) - Windows metrics (CPU runaway)
- [Linux](linux.md) - Linux metrics (memory leak, disk filling)
- [Cisco ASA](cisco_asa.md) - Network incidents
- [WinEventLog](wineventlog.md) - Security incidents

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) |
| **Ingestion** | Modular input polling ServiceNow REST Table API |
| **Real sourcetype** | `snow:incident` (and `snow:<table_name>` for other tables). Our generator uses `servicenow:incident` |

See [REFERENCES.md](REFERENCES.md#note-9-servicenow) for details.

