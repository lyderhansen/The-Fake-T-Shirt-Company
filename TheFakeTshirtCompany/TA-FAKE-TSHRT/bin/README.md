# bin/ -- Log Generation Engine

> **AI Disclaimer:** This project was primarily developed with AI assistance (Claude).
> While care has been taken to ensure accuracy, there may be inconsistencies or errors
> in the generated logs that have not yet been discovered.

This directory contains the Python code that generates all synthetic log data for
The FAKE T-Shirt Company. No external dependencies -- stdlib only.

## How It All Fits Together

```
                    ┌──────────────────────┐
                    │   Entry Points       │
                    │                      │
                    │  main_generate.py    │◄── CLI: python3 main_generate.py --all
                    │  tui_generate.py     │◄── Interactive TUI (curses)
                    │  generate_logs.py    │◄── Splunk REST handler (from Web UI)
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Orchestration       │
                    │                      │
                    │  main_generate.py    │  Resolves sources, dependencies,
                    │                      │  scenarios. Runs generators in
                    │                      │  parallel via ThreadPoolExecutor.
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼────────┐ ┌────▼─────┐ ┌────────▼────────┐
    │   generators/    │ │ shared/  │ │   scenarios/    │
    │                  │ │          │ │                 │
    │ 26 generators    │ │ Company  │ │ 10 scenarios    │
    │ One per log      │ │ Config   │ │ injected into   │
    │ source type      │ │ Time     │ │ generator       │
    │                  │ │ Products │ │ output          │
    └────────┬─────────┘ └──────────┘ └─────────────────┘
             │
    ┌────────▼─────────┐
    │   output/        │
    │                  │
    │ network/         │  Generated log files.
    │ cloud/           │  Splunk's inputs.conf
    │ windows/         │  monitors these paths.
    │ linux/           │
    │ web/             │
    │ retail/          │
    │ servicebus/      │
    │ itsm/            │
    └──────────────────┘
```

## Directory Overview

| Directory | Purpose |
|-----------|---------|
| `generators/` | 26 log source generators -- each produces one or more types of logs |
| `shared/` | Shared data and utilities used by all generators |
| `scenarios/` | 10 attack/ops/network scenarios injected into baseline traffic |
| `output/` | Generated log files (gitignored). Splunk reads from here |

## Entry Points

| File | What It Does |
|------|--------------|
| **`main_generate.py`** | Main CLI orchestrator. Parses args, resolves dependencies, runs generators in parallel. This is the file you run. |
| **`tui_generate.py`** | Interactive terminal UI (curses). Select sources, scenarios, and options with keyboard. Calls main_generate under the hood. |
| **`generate_logs.py`** | Splunk REST handler. Lets the Splunk Web dashboard trigger log generation. Not meant to be run directly. |
| **`delete_index.py`** | Splunk REST handler. Deletes and recreates the `fake_tshrt` index from the Web UI. |

## shared/ — The Foundation

Every generator imports from these modules. They define "who we are" and "when things happen".

| File | What It Contains |
|------|-----------------|
| **`company.py`** | The company itself: 175 employees, 3 locations (Boston/Atlanta/Austin), IP ranges, servers, meeting rooms, Meraki devices, threat actor config. This is the single source of truth for all names, IPs, and org structure. |
| **`config.py`** | Generation settings: default dates, volume patterns (hourly activity curves, weekend factors, Monday boost), output paths, and the mapping of generator names to output files. |
| **`time_utils.py`** | Timestamp formatters (syslog, ISO, perfmon, etc.), volume multiplier calculations, and attack phase helpers. Every generator uses these to produce correctly-formatted timestamps with realistic volume patterns. |
| **`products.py`** | 72 IT-themed products (t-shirts, hoodies, joggers, accessories) with prices. Used by the orders and access log generators. |
| **`meeting_schedule.py`** | Shared Webex meeting schedule. Used by the Webex generators and Meraki (sensor correlation with meetings). |

### How Volume Works

Generators don't just produce flat event counts. `time_utils.py` provides:

1. **Hourly curves** — Peak at 9-11 AM and 1-3 PM, lunch dip at noon, minimal at night
2. **Weekend reduction** — Most sources drop to 20-30% (but web traffic *increases*)
3. **Monday boost** — 115% on Mondays (post-weekend catch-up)
4. **Daily noise** — ±15% random but deterministic (same date = same output)

A generator calls `calc_natural_events(base_events, date, day, hour, source_type)` and gets back a realistic count for that specific hour.

## generators/ -- The 26 Log Sources

Each generator is a self-contained Python file that:
1. Imports from `shared/` for company data, config, and timestamps
2. Generates baseline events with realistic volume patterns
3. Injects scenario events when scenarios are active
4. Writes output to `output/<category>/`

### Generator List

**Network**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_asa.py` | `network/cisco_asa.log` | Syslog | `cisco:asa` |
| `generate_meraki.py` | `network/meraki_*.json` | JSON (5 device types + health) | `meraki:*` |
| `generate_catalyst.py` | `network/catalyst_*.log` | Syslog | `cisco:ios` |
| `generate_aci.py` | `network/aci_*.json` | JSON (faults, events, audits) | `cisco:aci:*` |

**Cloud / Identity**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_aws.py` | `cloud/aws/cloudtrail.json` | JSON | `aws:cloudtrail` |
| `generate_aws_guardduty.py` | `cloud/aws/guardduty.json` | JSON | `aws:cloudwatch:guardduty` |
| `generate_aws_billing.py` | `cloud/aws/billing_cur.csv` | CSV | `aws:billing:cur` |
| `generate_gcp.py` | `cloud/gcp/audit.json` | JSON | `google:gcp:pubsub:message` |
| `generate_entraid.py` | `cloud/entraid/*.json` | JSON | `azure:aad:signin` / `audit` |
| `generate_secure_access.py` | `cloud/secure_access/*.csv` | CSV | `cisco:umbrella:*` (4 types) |
| `generate_catalyst_center.py` | `cloud/catalyst_center/*.json` | JSON | `cisco:catalyst:*` (4 types) |

**Collaboration**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_exchange.py` | `cloud/microsoft/exchange_*.json` | JSON | `ms:o365:reporting:messagetrace` |
| `generate_office_audit.py` | `cloud/microsoft/office_audit.json` | JSON | `o365:management:activity` |
| `generate_webex.py` | `cloud/webex/webex_events.json` | JSON | `cisco:webex:events` |
| `generate_webex_ta.py` | `cloud/webex/webex_ta_*.json` | JSON | `cisco:webex:meetings:history:*` |
| `generate_webex_api.py` | `cloud/webex/webex_api_*.json` | JSON | `cisco:webex:*` (5 types) |

**Windows / Endpoint**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_wineventlog.py` | `windows/wineventlog_*.log` | KV pairs | `WinEventLog` |
| `generate_perfmon.py` | `windows/perfmon_*.log` | KV pairs | `Perfmon:*` |
| `generate_mssql.py` | `windows/mssql_errorlog.log` | Native ERRORLOG | `mssql:errorlog` |
| `generate_sysmon.py` | `windows/sysmon_operational.log` | KV pairs (WinEventLog) | `WinEventLog:Sysmon` |

**Linux**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_linux.py` | `linux/*.log` | KV pairs (5 metrics + auth) | `cpu`, `vmstat`, `df`, `iostat`, `interfaces`, `linux:auth` |

**Web / Retail**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_access.py` | `web/access_combined.log` | Apache Combined | `access_combined` |
| `generate_orders.py` | `retail/orders.json` | JSON | `retail:orders` |
| `generate_servicebus.py` | `servicebus/servicebus_events.json` | JSON | `azure:servicebus` |

**ERP**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_sap.py` | `erp/sap_auditlog.log` | Pipe-delimited | `sap:auditlog` |

**ITSM**

| Generator | Output | Format | Sourcetype |
|-----------|--------|--------|------------|
| `generate_servicenow.py` | `itsm/servicenow_*.log` | KV pairs | `servicenow:incident`, `change`, `cmdb` |

### Dependencies

Some generators must run after others because they share data:

```
access  -->  orders        (order_registry.json links web sessions to orders)
access  -->  servicebus    (same order registry)
access  -->  sap           (same order registry)
webex   -->  meraki        (meeting schedule for sensor/meeting correlation)
webex   -->  exchange      (meeting schedule for calendar invite emails)
```

`main_generate.py` handles this automatically — Phase 1 runs independent generators in parallel, Phase 2 runs dependent ones.

### How to Add a New Generator

1. Copy `_template_generator.py` → `generate_<name>.py`
2. Implement your log format
3. Register in `main_generate.py` (import, GENERATORS dict, SOURCE_GROUPS)
4. Add output file mapping in `config.py`
5. Add Splunk config in `default/inputs.conf` and `default/props.conf`

## scenarios/ — Attack and Operational Stories

Scenarios inject tagged events (`demo_id=<name>`) into the baseline traffic across multiple generators simultaneously. This is what makes the data interesting — the same attack appears in firewall logs, auth logs, cloud audit trails, and endpoint telemetry.

### Structure

```
scenarios/
├── registry.py                # Central registry -- all scenarios defined here
├── security/
│   ├── exfil.py               # APT-style data exfiltration (14-day campaign)
│   ├── ransomware_attempt.py  # Ransomware detected and stopped by EDR
│   └── phishing_test.py       # IT-run phishing awareness campaign
├── ops/
│   ├── cpu_runaway.py         # SQL backup stuck at 100% CPU
│   ├── memory_leak.py         # Application OOM crash
│   ├── disk_filling.py        # Server disk filling up
│   └── dead_letter_pricing.py # ServiceBus dead-letter queue, wrong prices
└── network/
    ├── firewall_misconfig.py  # ACL misconfiguration outage
    ├── certificate_expiry.py  # SSL cert expired
    └── ddos_attack.py         # Volumetric HTTP flood from botnet
```

### How Scenarios Work

1. **`registry.py`** defines which generators participate in each scenario and what days they're active
2. Each generator checks `if "exfil" in active_scenarios and day == 4:` and injects scenario-specific events
3. Each scenario class (e.g., `ExfilScenario`) provides methods that generators call to get the scenario events in the correct format for that log type
4. All scenario events are tagged with `demo_id=<scenario_name>` for easy Splunk filtering

### Scenario Timeline (31-day run)

```
Day:  1   2   3   4   5   6   7   8   9  10  11  12  13  14  ...  16  ...  18  19  ...  21  22  23
      |   |   |   |   |   |   |   |   |   |   |   |   |   |       |       |   |       |   |   |
Exfil [---Recon---|Acc|Lateral|Persist|---Exfiltration---|       |       |   |       |   |   |
Disk  [---45%----|---|--70%--|--85%--|--95%---|--98%-----|       |       |   |       |   |   |
FWMis |           |   |   XX  |       |        |          |       |       |   |       |   |   |
Ranso |           |   |       |   XX  |        |          |       |       |   |       |   |   |
MemLk |           |   |--Leak-|--OOM--|        |          |       |       |   |       |   |   |
CPU   |           |   |       |       |  XXXX  |          |       |       |   |       |   |   |
Cert  |           |   |       |       |   XX   |          |       |       |   |       |   |   |
DLQ   |           |   |       |       |        |          |       X       |   |       |   |   |
DDoS  |           |   |       |       |        |          |       |       XXXXX       |   |   |
Phish |           |   |       |       |        |          |       |       |   |       XXXXX   |
```

### Cross-Generator Correlation

The exfil scenario is the most complex — the same attack appears in:

| Phase | Generators |
|-------|------------|
| Phishing email | Exchange, Entra ID, Office 365 Audit |
| Credential theft | Entra ID (failed then successful logins), Sysmon (mimikatz) |
| Lateral movement | ASA (cross-site traffic), Meraki (internal), Sysmon (SMB, net commands) |
| Data staging | Sysmon (7z compression), WinEventLog, Perfmon (disk/CPU spike) |
| Exfiltration | ASA (large outbound transfers), Sysmon (rclone), AWS/GCP (cloud access) |
| Incident response | ServiceNow (tickets), Office 365 Audit (admin actions) |

This means an analyst can start from any log source and pivot across all of them using
shared fields: `demo_id`, usernames, IPs, timestamps.

## Quick Start

```bash
# Generate everything (test mode — writes to output/tmp/)
python3 main_generate.py --all --scenarios=all --days=14

# Generate for Splunk (production — writes to output/)
python3 main_generate.py --all --scenarios=all --days=14 --no-test

# Generate specific sources
python3 main_generate.py --sources=sysmon,asa,entraid --scenarios=exfil

# Interactive mode
python3 tui_generate.py
```

## output/ — Where Logs Go

```
output/
├── network/       cisco_asa.log, meraki_*.json, catalyst_*.log, aci_*.json
├── cloud/
│   ├── aws/       cloudtrail.json, guardduty.json, billing_cur.csv
│   ├── entraid/   signin.json, audit.json
│   ├── gcp/       audit.json
│   ├── microsoft/ exchange_*.json, office_audit.json
│   ├── webex/     webex_events.json, webex_ta_*.json, webex_api_*.json
│   ├── secure_access/  dns.csv, proxy.csv, firewall.csv, audit.csv
│   └── catalyst_center/ devicehealth.json, networkhealth.json, clienthealth.json, issues.json
├── windows/       perfmon_*.log, wineventlog_*.log, mssql_errorlog.log, sysmon_operational.log
├── linux/         cpu.log, vmstat.log, df.log, iostat.log, interfaces.log, auth.log
├── web/           access_combined.log, order_registry.json
├── retail/        orders.json
├── servicebus/    servicebus_events.json
├── erp/           sap_auditlog.log
├── itsm/          servicenow_incidents.log, servicenow_cmdb.log, servicenow_change.log
└── tmp/           Same structure -- used by --test mode (default)
```

Splunk's `default/inputs.conf` has monitor stanzas pointing to `output/<category>/<file>`.
When you run with `--no-test`, the files land where Splunk can pick them up.
When you run with `--test` (default), they go to `output/tmp/` so you don't accidentally
overwrite production data.
