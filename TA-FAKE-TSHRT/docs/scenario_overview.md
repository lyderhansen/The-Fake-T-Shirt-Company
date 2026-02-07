# Scenario Overview

Quick reference table for all demo scenarios.

---

## Scenario Matrix

| Scenario | Category | Duration | Days | Peak Time | Primary Logs |
|----------|----------|----------|------|-----------|--------------|
| [exfil](exfil.md) | Attack | 14 days | 1-14 | Night (exfil) | ASA, CloudTrail, EntraID |
| [ransomware](ransomware.md) | Attack | 20 min | 8 | 14:00-14:15 | WinEventLog, ASA, Meraki |
| [memory_leak](memory_leak.md) | Ops | 10 days | 1-10 | Day 10 14:00 | Linux vmstat |
| [cpu_runaway](cpu_runaway.md) | Ops | 2 days | 11-12 | Day 11 15:00 | Perfmon, WinEventLog |
| [disk_filling](disk_filling.md) | Ops | 14 days | 1-14 | Day 13-14 | Linux df |
| [firewall_misconfig](firewall_misconfig.md) | Network | 2 hours | 7 | 10:15-12:05 | ASA |
| [certificate_expiry](certificate_expiry.md) | Network | 7 hours | 12 | 00:00-07:00 | ASA, Access |

---

## Timeline (14 days)

```
Day:   1   2   3   4   5   6   7   8   9  10  11  12  13  14
       |   |   |   |   |   |   |   |   |   |   |   |   |   |
Exfil  ├───────────┼───┼───────┼───────┼───────────────────┤
       │  Recon    │Acc│Lateral│Persist│    Exfiltration   │
       │           │   │       │       │                   │
Ransom │           │   │       │   ████│                   │  Day 8 @14:00
       │           │   │       │       │                   │
Memory ├───────────────────────────────████                │  OOM Day 10 @14:00
       │           │   │       │       │                   │
CPU    │           │   │       │       │   ████████████    │  Days 11-12
       │           │   │       │       │       │Fix@10:30  │
Disk   ├───────────────────────────────────────────────────┤  45%→98%
       │           │   │       │       │                   │
FW     │           │   │   ████│       │                   │  Day 7 @10:15-12:05
       │           │   │       │       │                   │
Cert   │           │   │       │       │   ████            │  Day 12 @00:00-07:00
```

---

## Key Personnel

| Person | Role | Location | IP | Scenario |
|--------|------|----------|-----|----------|
| Jessica Brown | IT Admin | Atlanta | 10.20.30.15 | exfil (initial compromise) |
| Alex Miller | Financial Analyst | Boston | 10.10.30.55 | exfil (primary target) |
| Brooklyn White | Sales Engineer | Austin | 10.30.30.20 | ransomware (target) |
| network.admin | Network Admin | Boston | 10.10.10.50 | firewall_misconfig |

---

## Key Servers

| Server | Role | IP | Scenario |
|--------|------|-----|----------|
| WEB-01 | Web Server | 172.16.1.10 | memory_leak, certificate_expiry |
| SQL-PROD-01 | SQL Database | 10.10.20.30 | cpu_runaway |
| MON-ATL-01 | Monitoring | 10.20.20.30 | disk_filling |
| FW-EDGE-01 | Perimeter FW | - | all network scenarios |

---

## Threat Actors

| IP | Location | ASN | Used In |
|----|----------|-----|---------|
| 185.220.101.42 | Frankfurt, DE | AS205100 | exfil |
| 194.26.29.42 | Russia | AS49505 | ransomware |

---

## Filter by demo_id

All scenarios are tagged with `demo_id` field:

```spl
# Single scenario
index=* demo_id=exfil

# Multiple scenarios
index=* demo_id IN ("exfil", "ransomware_attempt")

# All scenarios
index=* demo_id=*

# By category
index=* demo_id IN ("memory_leak", "cpu_runaway", "disk_filling")
```

---

## Recommended Demo Order

| # | Scenario | Why |
|---|----------|-----|
| 1 | **exfil** | Full 14-day attack progression, shows correlation |
| 2 | **ransomware** | Quick win - defense working, attack stopped |
| 3 | **memory_leak + cpu_runaway** | Cascading ops failures |
| 4 | **disk_filling** | Slow burn, often missed |
| 5 | **firewall_misconfig** | Human error, quick resolution |
| 6 | **certificate_expiry** | Preventable outage |

---

## Outcome Summary

| Scenario | Outcome | Detection Time | Resolution |
|----------|---------|----------------|------------|
| exfil | Data stolen | Not detected | Ongoing |
| ransomware | **Blocked** | 10 minutes | Automated |
| memory_leak | OOM crash | Day 10 | Manual restart |
| cpu_runaway | Service degraded | Hours | Manual fix |
| disk_filling | Near-full | Day 8 (warning) | Cleanup |
| firewall_misconfig | Outage | ~2 hours | Config rollback |
| certificate_expiry | Outage | ~6 hours | Cert renewal |

