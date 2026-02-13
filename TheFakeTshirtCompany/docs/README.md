# Documentation

Documentation for The FAKE T-Shirt Company Splunk demo environment.

> **AI Disclaimer:** This project was primarily developed with AI assistance (Claude).
> While care has been taken to ensure accuracy, there may be inconsistencies or errors
> in the generated logs that have not yet been discovered.

---

## Directory Index

| Folder | Contents | Files |
|--------|----------|-------|
| [scenarios/](scenarios/) | Scenario guides and timelines | 10 scenarios + overview |
| [datasource_docs/](datasource_docs/) | Data source documentation | 29 sources + index |
| [reference/](reference/) | SPL queries, design specs, architecture | 4 files |
| [guides/](guides/) | Demo talking track, Docker setup | 2 files |
| [graphic/](graphic/) | Floor plan images and logos | PNG/SVG assets |
| [archive/](archive/) | Obsolete docs (kept for history) | 6 files |

---

## Scenarios

10 scenarios across 3 categories, tagged with `demo_id` field:

| Scenario | Category | Duration | Guide |
|----------|----------|----------|-------|
| **exfil** | Attack | 14 days | [scenarios/exfil.md](scenarios/exfil.md) |
| **ransomware_attempt** | Attack | 1 day | [scenarios/ransomware_attempt.md](scenarios/ransomware_attempt.md) |
| **phishing_test** | Attack | 3 days | [scenarios/phishing_test.md](scenarios/phishing_test.md) |
| **memory_leak** | Ops | 10 days | [scenarios/memory_leak.md](scenarios/memory_leak.md) |
| **cpu_runaway** | Ops | 2 days | [scenarios/cpu_runaway.md](scenarios/cpu_runaway.md) |
| **disk_filling** | Ops | 14 days | [scenarios/disk_filling.md](scenarios/disk_filling.md) |
| **dead_letter_pricing** | Ops | 1 day | [scenarios/dead_letter_pricing.md](scenarios/dead_letter_pricing.md) |
| **ddos_attack** | Network | 2 days | [scenarios/ddos_attack.md](scenarios/ddos_attack.md) |
| **firewall_misconfig** | Network | 2 hours | [scenarios/firewall_misconfig.md](scenarios/firewall_misconfig.md) |
| **certificate_expiry** | Network | 7 hours | [scenarios/certificate_expiry.md](scenarios/certificate_expiry.md) |

Full scenario overview: [scenarios/README.md](scenarios/README.md)

---

## Scenario Timeline (31 days)

```
Day:  1   2   3   4   5   6   7   8   9  10  11  12  13  14  ...  21  22  23
      |   |   |   |   |   |   |   |   |   |   |   |   |   |       |   |   |
Exfil |---Recon---|Acc|Lateral|Persist|---Exfiltration---|       |   |   |
Ransom|           |   |       |   XX  |                   |       |   |   |
MemLk |--Normal---|---|--Leak-|--OOM--|--Normal-----------|       |   |   |
CPU   |           |   |       |       |  XXXX  |          |       |   |   |
Disk  |---45%-----|---|--70%--|--85%--|--95%---|--98%-----|       |   |   |
FWMis |           |   |   XX  |       |        |          |       |   |   |
Cert  |           |   |       |       |   XX   |          |       |   |   |
DDoS  |           |   |       |       |        |    XXXX  |       |   |   |
DLQ   |           |   |       |       |        |     X    |       |   |   |
Phish |           |   |       |       |        |          |       |XXXXX  |
```

---

## Quick Start

```bash
# Generate all sources with all scenarios
python3 bin/main_generate.py --all --scenarios=all --days=31

# Filter by scenario in Splunk
index=fake_tshrt demo_id=exfil | stats count by sourcetype
```

---

## Key Personnel

| Person | Role | Location | IP | Scenario |
|--------|------|----------|-----|----------|
| Jessica Brown | IT Admin | Atlanta | 10.20.30.15 | Exfil (initial compromise) |
| Alex Miller | Financial Analyst | Boston | 10.10.30.55 | Exfil (primary target) |
| Brooklyn White | Sales Engineer | Austin | 10.30.30.20 | Ransomware attempt |
| Threat Actor | Attacker | Frankfurt, DE | 185.220.101.42 | Exfil |

## Key Servers

| Server | Role | IP | Scenario |
|--------|------|-----|----------|
| WEB-01 | Web Server (DMZ) | 172.16.1.10 | Memory leak, DDoS, Exfil staging |
| SQL-PROD-01 | SQL Database | 10.10.20.30 | CPU runaway |
| MON-ATL-01 | Monitoring | 10.20.20.30 | Disk filling |
| FW-EDGE-01 | Perimeter FW | ASA 5525-X | Firewall misconfig, Cert expiry |
