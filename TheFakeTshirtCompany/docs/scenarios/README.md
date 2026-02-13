# Scenario Overview

Quick reference table for all demo scenarios.

---

## Scenario Matrix

| Scenario | Category | Duration | Days | Peak Time | Primary Logs |
|----------|----------|----------|------|-----------|--------------|
| [exfil](exfil.md) | Attack | 14 days | 1-14 | Night (exfil) | ASA, CloudTrail, GuardDuty, Billing, EntraID, GCP Audit |
| [ransomware_attempt](ransomware_attempt.md) | Attack | 20 min | 8 | 14:00-14:15 | WinEventLog, ASA, Meraki |
| [phishing_test](phishing_test.md) | Attack | 3 days | 21-23 | Day 21 09:00 | Exchange, EntraID, WinEventLog |
| [memory_leak](memory_leak.md) | Ops | 10 days | 1-10 | Day 10 14:00 | Linux vmstat |
| [cpu_runaway](cpu_runaway.md) | Ops | 2 days | 11-12 | Day 11 15:00 | Perfmon, WinEventLog, GCP Audit |
| [disk_filling](disk_filling.md) | Ops | 14 days | 1-14 | Day 13-14 | Linux df |
| [dead_letter_pricing](dead_letter_pricing.md) | Ops | 5 hours | 16 | 08:00-13:00 | ServiceBus, Orders, Access |
| [firewall_misconfig](firewall_misconfig.md) | Network | 2 hours | 7 | 10:15-12:05 | ASA |
| [certificate_expiry](certificate_expiry.md) | Network | 7 hours | 13 | 00:00-07:00 | ASA, Access |
| [ddos_attack](ddos_attack.md) | Network | 28 hours | 18-19 | Day 18 08:00 | ASA, Meraki, Access |

---

## Timeline (31 days)

```
Day:   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Exfil  [===recon====|acc|=lateral=|=persist=|=====exfiltration=====]
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Ransom |   |   |   |   |   |   |   ##  |   |   |   |   |   |   |   |   |   |   |   |   |   |   |  Day 8 @14:00 (blocked)
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Memory [================================##  |   |   |   |   |   |   |   |   |   |   |   |   |   |  OOM Day 10 @14:00
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
CPU    |   |   |   |   |   |   |   |   |   |   [=======]   |   |   |   |   |   |   |   |   |   |  Days 11-12, fix @10:30
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Disk   [=====================================================]  |   |   |   |   |   |   |   |   |  45% -> 98%
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
FW     |   |   |   |   |   |   ##  |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |  Day 7 @10:15-12:05
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Cert   |   |   |   |   |  (w) |   |   |  (w) |   |   ##  |   |   |   |   |   |   |   |   |   |  Day 13, warnings Day 6+10
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
DLQ    |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   ##  |   |   |   |   |   |   |  Day 16 @08:00-13:00
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
DDoS   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   [=======]   |   |   |  Days 18-19, peak @08:00
       |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
Phish  |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   [=======]  Days 21-23, post-incident

Legend: [===] sustained  ## peak/incident  (w) pre-warning
```

---

## Key Personnel

| Person | Role | Location | IP | Scenario |
|--------|------|----------|-----|----------|
| Jessica Brown | IT Admin | Atlanta | 10.20.30.15 | exfil (initial compromise) |
| Alex Miller | Financial Analyst | Boston | 10.10.30.55 | exfil (primary target) |
| Brooklyn White | Sales Engineer | Austin | 10.30.30.20 | ransomware (target) |
| Ashley Griffin | Security Analyst | Boston | 10.10.30.168 | phishing_test (campaign operator) |
| network.admin | Network Admin | Boston | 10.10.10.50 | firewall_misconfig, ddos_attack |

---

## Key Servers

| Server | Role | IP | Scenario |
|--------|------|-----|----------|
| WEB-01 | Web Server | 172.16.1.10 | memory_leak, certificate_expiry, ddos_attack, dead_letter_pricing |
| WEB-02 | Web Server | 172.16.1.11 | ddos_attack |
| SQL-PROD-01 | SQL Database | 10.10.20.30 | cpu_runaway |
| APP-BOS-01 | API Server | 10.10.20.40 | ddos_attack (downstream) |
| MON-ATL-01 | Monitoring | 10.20.20.30 | disk_filling |
| FW-EDGE-01 | Perimeter FW | - | all network scenarios |
| MX-BOS-01 | SD-WAN Hub | - | ddos_attack (failover), ransomware (cross-site IDS) |

---

## Threat Actors

| IP | Location | ASN | Used In |
|----|----------|-----|---------|
| 185.220.101.42 | Frankfurt, DE | AS205100 | exfil |
| 194.26.29.42 | Russia | AS49505 | ransomware |
| 10 wave 1 + 10 wave 2 IPs | Global botnet | Various | ddos_attack |
| 52.25.138.42 | AWS (KnowBe4) | - | phishing_test (simulation platform) |

---

## Filter by demo_id

All scenarios are tagged with `demo_id` field:

```spl
# Single scenario
index=fake_tshrt demo_id=exfil

# Multiple scenarios
index=fake_tshrt demo_id IN ("exfil", "ransomware_attempt")

# All scenarios
index=fake_tshrt demo_id=*

# By category (attack)
index=fake_tshrt demo_id IN ("exfil", "ransomware_attempt", "phishing_test")

# By category (ops)
index=fake_tshrt demo_id IN ("memory_leak", "cpu_runaway", "disk_filling", "dead_letter_pricing")

# By category (network)
index=fake_tshrt demo_id IN ("firewall_misconfig", "certificate_expiry", "ddos_attack")
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
| 6 | **certificate_expiry** | Preventable outage with ignored pre-warnings |
| 7 | **dead_letter_pricing** | Application-layer incident, pricing impact |
| 8 | **ddos_attack** | External threat, multi-layer defense response |
| 9 | **phishing_test** | Post-incident awareness campaign, ties back to exfil |

---

## Outcome Summary

| Scenario | Outcome | Detection Time | Resolution |
|----------|---------|----------------|------------|
| exfil | Data stolen | Not detected | Ongoing |
| ransomware | **Blocked** | 10 minutes | Automated |
| phishing_test | 31% click rate | N/A (authorized) | Training assigned |
| memory_leak | OOM crash | Day 10 | Manual restart |
| cpu_runaway | Service degraded | Hours | Manual fix |
| disk_filling | Near-full | Day 8 (warning) | Cleanup |
| dead_letter_pricing | Wrong prices | ~1 hour (DLQ alert) | Consumer restart |
| firewall_misconfig | Outage | ~2 hours | Config rollback |
| certificate_expiry | Outage | ~6 hours | Cert renewal |
| ddos_attack | Service degraded | ~1 hour (P1) | ISP filtering + ACLs |
