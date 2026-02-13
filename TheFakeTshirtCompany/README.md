# The Fake T-Shirt Company -- TA-FAKE-TSHRT

A Splunk Technology Add-on that generates realistic synthetic log data for demos and training.

> **AI Disclaimer:** This project was primarily developed with AI assistance (Claude).
> While care has been taken to ensure accuracy, there may be inconsistencies or errors
> in the generated logs that have not yet been discovered. Please report any issues.

---

## What Is This?

This project simulates a fictional e-commerce company called **The FAKE T-Shirt Company** --
175 employees across 3 US offices (Boston, Atlanta, Austin) selling IT-themed apparel.
It generates correlated log data across 26 data sources and 10 injectable security/ops/network
scenarios, all designed for Splunk demos, training, and development.

The generated data covers network firewalls, cloud platforms, identity providers, collaboration
tools, endpoints, applications, ERP, and ITSM -- producing 60+ distinct Splunk sourcetypes
that can be searched and correlated in a single index.

---

## Repository Structure

```
TheFakeTshirtCompany/
├── README.md                  <-- You are here
├── TA-FAKE-TSHRT/             Splunk app package (install this in Splunk)
│   ├── bin/                   Python generators, scenarios, shared utilities
│   │   ├── generators/        26 data source generators
│   │   ├── scenarios/         10 scenario implementations
│   │   ├── shared/            Company data, config, time utils, products
│   │   └── output/            Generated log files (gitignored)
│   ├── default/               Splunk configuration (props, transforms, inputs, etc.)
│   ├── lookups/               CSV lookup tables (ASA, identity, assets, MAC)
│   ├── metadata/              Splunk metadata
│   └── static/                App icons
└── docs/                      Project documentation
    ├── scenarios/             10 scenario guides with timelines
    ├── datasource_docs/       29 data source docs + index
    ├── reference/             SPL queries, design language, floor plans
    ├── guides/                Demo talking track, Docker setup
    └── graphic/               Floor plan images, logos
```

---

## Quick Start

```bash
# 1. Install the app
#    Copy the TA-FAKE-TSHRT folder into $SPLUNK_HOME/etc/apps/
cp -r TA-FAKE-TSHRT $SPLUNK_HOME/etc/apps/

# 2. Restart Splunk
#    The index "fake_tshrt" is created automatically via local/indexes.conf.
splunk restart

# 3. Verify the index exists (if not, create it manually)
splunk list index fake_tshrt
#    If missing: splunk add index fake_tshrt

# 4. Generate logs
#    Use the interactive TUI to select sources, scenarios, and settings.
#    With default settings this generates ~10 million events (~3.8 GB).
#    When generating to the production folder, data is automatically
#    ingested by Splunk. This may take some time depending on your hardware.
cd $SPLUNK_HOME/etc/apps/TA-FAKE-TSHRT/bin
python3 main_generate.py --tui

# 5. Restart Splunk to trigger ingestion of new data
splunk restart

# 6. Search
| tstats count where index=fake_tshrt earliest=0 latest=now by sourcetype
```

---

## Data Sources (26 generators)

| Category | Sources |
|----------|---------|
| **Network** | Cisco ASA, Meraki (MX/MR/MS/MV/MT), Catalyst Switches, ACI Fabric |
| **Cloud & Identity** | AWS CloudTrail/GuardDuty/Billing, GCP Audit, Entra ID, Secure Access, Catalyst Center |
| **Collaboration** | Exchange, M365 Audit, Cisco Webex (Devices/Meetings/API) |
| **Endpoints** | WinEventLog, Sysmon, Perfmon, MSSQL, Linux (metrics + auth) |
| **Applications** | Apache Access, Retail Orders, Azure ServiceBus, SAP S/4HANA, ServiceNow |

All sourcetypes are prefixed with `FAKE:` (e.g., `FAKE:cisco:asa`) and indexed to `fake_tshrt`.

---

## Scenarios (10)

| Scenario | Category | Duration | What Happens |
|----------|----------|----------|-------------|
| **exfil** | Attack | 14 days | APT-style data exfiltration across multiple sites |
| **ransomware_attempt** | Attack | 20 min | Ransomware detected and blocked by EDR |
| **phishing_test** | Attack | 3 days | IT-run phishing awareness campaign |
| **memory_leak** | Ops | 10 days | Application memory leak causing OOM crash |
| **cpu_runaway** | Ops | 2 days | SQL backup job stuck at 100% CPU |
| **disk_filling** | Ops | 14 days | Server disk gradually filling up |
| **dead_letter_pricing** | Ops | 5 hours | ServiceBus dead-letter queue causes wrong prices |
| **firewall_misconfig** | Network | 2 hours | Accidental ACL misconfiguration |
| **certificate_expiry** | Network | 7 hours | SSL certificate expiration |
| **ddos_attack** | Network | 28 hours | Volumetric HTTP flood from botnet |

All scenario events are tagged with `demo_id` for easy filtering:
```spl
index=fake_tshrt demo_id=exfil | stats count by sourcetype
```

---

## Requirements

- Python 3.8+ (stdlib only -- no external dependencies)
- Splunk Enterprise 8.0+

---

## Documentation

| Document | Description |
|----------|-------------|
| [TA-FAKE-TSHRT/README.md](TA-FAKE-TSHRT/README.md) | App overview, installation, usage |
| [TA-FAKE-TSHRT/bin/README.md](TA-FAKE-TSHRT/bin/README.md) | Generator engine, scenarios, shared utilities |
| [TA-FAKE-TSHRT/default/README.md](TA-FAKE-TSHRT/default/README.md) | Splunk configuration, sourcetypes, CIM mappings |
| [docs/scenarios/README.md](docs/scenarios/README.md) | Scenario overview, timeline, key personnel |
| [docs/datasource_docs/README.md](docs/datasource_docs/README.md) | Data source documentation index |
