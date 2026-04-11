---
name: generate-logs
description: Generate demo log data for Splunk. Use when you need to create synthetic logs for testing, demos, or training.
allowed-tools: Bash(python3 *)
metadata:
  argument-hint: "[--sources=X,Y] [--days=N] [--scenarios=TYPE]"
---

# Log Generation

Generate realistic synthetic log data using the TA-FAKE-TSHRT generators.

## Output Modes

By default, generators write to `bin/output/tmp/` (**test mode**, safe — Splunk does NOT monitor this). Use `--no-test` to write to `bin/output/` which Splunk's `inputs.conf` ingests.

```bash
--test       # Default. Writes to output/tmp/
--no-test    # Production. Writes to output/ (Splunk-monitored)
```

## Quick Commands

```bash
cd TheFakeTshirtCompany/TA-FAKE-TSHRT/bin

# All sources, test mode (default)
python3 main_generate.py --all --scenarios=all --days=14

# Production run for Splunk ingestion
python3 main_generate.py --all --scenarios=all --days=14 --no-test

# Specific sources with one scenario
python3 main_generate.py --sources=asa,entraid,aws --scenarios=exfil

# High-volume demo (31 days)
python3 main_generate.py --all --days=31 --orders-per-day=3000 --clients=40 --full-metrics --no-test

# Minimal smoke test
python3 main_generate.py --sources=asa --days=1 --quiet
```

## Available Sources (26 generators)

| Category | Sources |
|----------|---------|
| Network | `asa`, `meraki`, `catalyst`, `aci` |
| Cloud/Security | `aws`, `aws_guardduty`, `aws_billing`, `gcp`, `entraid`, `secure_access`, `catalyst_center` |
| Collaboration | `exchange`, `office_audit`, `webex_ta`, `webex_api` |
| Windows | `wineventlog`, `perfmon`, `sysmon`, `mssql` |
| Linux | `linux` |
| Web/Retail | `access`, `orders`, `servicebus` |
| ERP/ITSM | `sap`, `servicenow` |
| OT/ICS | `cybervision` (Detroit plant, 21 OT assets) |

## Source Groups

| Group | Expands to |
|-------|------------|
| `all` | All 26 sources |
| `cloud` | aws, aws_guardduty, aws_billing, gcp, entraid, secure_access |
| `network` | asa, meraki, catalyst, aci, cybervision |
| `cisco` | asa, meraki, secure_access, catalyst, aci, catalyst_center, cybervision |
| `campus` | catalyst, catalyst_center |
| `datacenter` | aci |
| `ot` | cybervision |
| `windows` | wineventlog, perfmon, mssql, sysmon |
| `linux` | linux |
| `web` | access |
| `office` | office_audit, exchange |
| `email` | exchange |
| `retail` | orders, servicebus |
| `collaboration` | webex_ta, webex_api |
| `erp` | sap |
| `itsm` | servicenow |

## Scenarios (11 implemented)

| Scenario | Category | Days | Target |
|----------|----------|------|--------|
| `exfil` | attack | 1-14 | Alex Miller (Finance, Boston) |
| `ransomware_attempt` | attack | 8-9 | Brooklyn White (Austin) |
| `phishing_test` | attack | 21-23 | All employees (IT campaign) |
| `ot_rogue_device` | attack | 8 | PLC-PRINT-01 (Detroit Zone-1) |
| `memory_leak` | ops | 7-10 | WEB-01 |
| `cpu_runaway` | ops | 11-12 | SQL-PROD-01 |
| `disk_filling` | ops | 1-5 | MON-ATL-01 |
| `dead_letter_pricing` | ops | 16 | WEB-01 (ServiceBus) |
| `ddos_attack` | network | 18-19 | WEB-01 |
| `firewall_misconfig` | network | 6 | FW-EDGE-01 |
| `certificate_expiry` | network | 13 | FW-EDGE-01 |

Meta-values: `none`, `all`, `attack`, `ops`, `network`.

## Key Options

```
--start-date=YYYY-MM-DD  Start date (default: 2026-01-01)
--days=N                 Number of days (default: 14)
--scale=N.N              Volume multiplier (default: 1.0)
--scenarios=X,Y          Scenarios or category (default: none)
--parallel=N             Worker threads (default: 4)
--quiet                  Suppress progress output
--test / --no-test       Output mode (default: --test)

# Perfmon-specific
--clients=N              Client workstations (default: 5, min: 5, max: 195)
--client-interval=N      Minutes between non-scenario client metrics (default: 30)
--full-metrics           Include disk/network for clients (increases volume)

# Orders-specific
--orders-per-day=N       Target daily orders (default: ~224)

# Meraki-specific
--meraki-health-interval Health metric frequency (5/10/15/30 min)
```

**Note:** `scale` is ignored by `perfmon` (fixed intervals), `orders` (use `--orders-per-day`), and `servicebus` (1:1 with orders).

## Output Structure (test mode)

```
bin/output/tmp/
├── network/      # cisco_asa, meraki_*, catalyst, aci
├── cloud/        # aws, gcp, entraid, exchange, webex, secure_access, catalyst_center
├── windows/      # perfmon, wineventlog, sysmon, mssql
├── linux/        # vmstat, df, iostat, cpu, interfaces, auth
├── web/          # access_combined
├── retail/       # orders
├── servicebus/   # azure servicebus
├── erp/          # sap
└── itsm/         # servicenow
```

## Splunk Filtering

Splunk applies the `FAKE:` prefix to all sourcetypes at index time via `props.conf`/`transforms.conf`. Use the prefixed form in SPL:

```spl
index=fake_tshrt demo_id=exfil | stats count by sourcetype
index=fake_tshrt sourcetype="FAKE:cisco:asa" | timechart count by action
index=fake_tshrt sourcetype="FAKE:perfmon" demo_host="SQL-PROD-01" | timechart avg(Value) by counter
index=fake_tshrt sourcetype="FAKE:cisco:cybervision:events" demo_id=ot_rogue_device
```

All scenario events carry `demo_id=<scenario>` for easy filtering.
