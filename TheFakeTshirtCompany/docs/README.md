# Demo Documentation

This folder contains detailed documentation for running Splunk demos with The FAKE T-Shirt Company log generators.

## Contents

### Scenario Guides

| File | Scenario | Category | Duration |
|------|----------|----------|----------|
| [exfil.md](exfil.md) | APT Data Exfiltration | Attack | 14 days |
| [ransomware.md](ransomware.md) | Ransomware Attempt (Blocked) | Attack | 1 day |
| [memory_leak.md](memory_leak.md) | Memory Leak & OOM Crash | Ops | 10 days |
| [cpu_runaway.md](cpu_runaway.md) | SQL Backup Job Stuck | Ops | 2 days |
| [disk_filling.md](disk_filling.md) | Disk Space Exhaustion | Ops | 14 days |
| [firewall_misconfig.md](firewall_misconfig.md) | ACL Misconfiguration | Network | 2 hours |
| [certificate_expiry.md](certificate_expiry.md) | SSL Certificate Expiry | Network | 7 hours |

### Reference

| File | Description |
|------|-------------|
| [splunk_queries.md](splunk_queries.md) | SPL queries for all scenarios |
| [scenario_overview.md](scenario_overview.md) | Quick reference table |

### Data Source Documentation

| Folder | Description |
|--------|-------------|
| [datasource_docs/](datasource_docs/) | Detailed docs for all 16 log sources |

See [datasource_docs/README.md](datasource_docs/README.md) for:
- **Network:** Cisco ASA, Meraki (MX/MR/MS/MV/MT)
- **Cloud:** AWS CloudTrail, GCP Audit, Entra ID, Exchange
- **Collaboration:** Webex Devices, Meetings TA, API
- **Windows:** Perfmon, Event Log
- **Linux:** System metrics
- **Web/Retail:** Access logs, Orders, ServiceBus
- **ITSM:** ServiceNow

---

## Quick Start

### Generate all scenarios
```bash
cd python_generators
python3 main_generate.py --all --scenarios=all --days=14
```

### Filter by scenario in Splunk
All scenarios are tagged with `demo_id` field:
```spl
index=fake_tshrt demo_id=exfil | stats count by sourcetype
```

---

## Scenario Timeline (14 days)

```
Day:  1   2   3   4   5   6   7   8   9  10  11  12  13  14
      │   │   │   │   │   │   │   │   │   │   │   │   │   │
Exfil ├───────────┼───┼───────┼───────┼───────────────────┤
      │  Recon    │Acc│Lateral│Persist│    Exfiltration   │
      │           │   │       │       │                   │
Ransom│           │   │       │   ████│                   │  Day 8 @14:00
      │           │   │       │       │                   │
MemLeak───────────────────────────────████                │  Day 10 @14:00 OOM
      │           │   │       │       │                   │
CPU   │           │   │       │       │   ████████████    │  Day 11-12
      │           │   │       │       │       │Fix@10:30  │
Disk  ├───────────────────────────────────────────────────┤  Gradual 45%→98%
      │           │   │       │       │                   │
FW    │           │   │   ████│       │                   │  Day 7 @10:15-12:05
      │           │   │       │       │                   │
Cert  │           │   │       │       │   ████            │  Day 12 @00:00-07:00
```

---

## Key Personnel

| Person | Role | Location | IP | Involved In |
|--------|------|----------|-----|-------------|
| Jessica Brown | IT Admin | Atlanta | 10.20.30.15 | Exfil (initial compromise) |
| Alex Miller | Financial Analyst | Boston | 10.10.30.55 | Exfil (primary target) |
| Brooklyn White | Sales Engineer | Austin | 10.30.30.20 | Ransomware attempt |

## Key Servers

| Server | Role | IP | Involved In |
|--------|------|-----|-------------|
| WEB-01 | Web Server | 172.16.1.10 | Memory leak, Exfil staging |
| SQL-PROD-01 | SQL Database | 10.10.20.30 | CPU runaway |
| MON-ATL-01 | Monitoring | 10.20.20.30 | Disk filling |

## Threat Actor

| Attribute | Value |
|-----------|-------|
| IP | 185.220.101.42 |
| Location | Frankfurt, Germany |
| ASN | AS205100 (F3 Netze e.V.) |
| Used in | Exfil scenario |

---

## Demo Tips

1. **Start with Exfil** - Shows full 14-day attack progression
2. **Jump to Ransomware** - Shows defense working (attack blocked in 10 min)
3. **Memory + CPU** - Shows cascading operational failures
4. **Disk filling** - Shows slow-burn issues often missed
5. **Firewall + Cert** - Shows operator error and infrastructure issues

**Universal Splunk filter:**
```spl
index=fake_tshrt demo_id=<scenario_name> | timechart count by sourcetype
```
