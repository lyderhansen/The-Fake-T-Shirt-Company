---
name: generate-logs
description: Generate demo log data for Splunk. Use when you need to create synthetic logs for testing, demos, or training.
allowed-tools: Bash(python3 *)
metadata:
  argument-hint: "[--sources=X,Y] [--days=N] [--scenarios=TYPE]"
---

# Log Generation

Generate realistic synthetic log data using the TA-FAKE-TSHRT generators.

## Quick Commands

```bash
cd TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin

# All sources (14 days, default scenarios)
python3 main_generate.py --all

# Specific sources only
python3 main_generate.py --sources=asa,entraid,aws --scenarios=exfil

# High-volume demo (31 days)
python3 main_generate.py --all --days=31 --orders-per-day=3000 --clients=40 --full-metrics

# Minimal test run
python3 main_generate.py --sources=asa --days=1 --quiet
```

## Available Sources

| Category | Sources |
|----------|---------|
| Network | `asa`, `meraki` |
| Cloud | `aws`, `gcp`, `entraid` |
| Windows | `wineventlog`, `perfmon` |
| Linux | `linux` |
| Web/Retail | `access`, `orders`, `servicebus` |
| Collaboration | `webex`, `webex_ta`, `webex_api` |
| Email | `exchange` |
| ITSM | `servicenow` |

## Source Groups

Use these shortcuts instead of listing individual sources:

- `all` - Everything
- `cloud` - aws, gcp, entraid
- `network` - asa, meraki
- `windows` - wineventlog, perfmon
- `retail` - orders, servicebus
- `collaboration` - webex, webex_ta, webex_api

## Scenarios

| Scenario | Category | Description |
|----------|----------|-------------|
| `exfil` | attack | APT data exfiltration (14 days) |
| `cpu_runaway` | ops | SQL backup stuck causing 100% CPU |
| `memory_leak` | ops | Application memory leak → OOM crash |
| `disk_filling` | ops | Server disk gradually filling |
| `firewall_misconfig` | network | Accidental traffic block |
| `all` | - | All scenarios combined |

## Key Options

```
--start-date=YYYY-MM-DD  Start date (default: 2026-01-01)
--days=N                 Number of days (default: 14)
--scale=N.N              Volume multiplier (default: 1.0)
--scenarios=X,Y          Scenarios to include
--parallel=N             Worker threads (default: 4)
--quiet                  Suppress progress output

# Perfmon-specific
--clients=N              Client workstations (default: 5, max: 175)
--full-metrics           Include disk/network for clients

# Orders-specific
--orders-per-day=N       Target daily orders (default: ~224)
```

## Output Structure

```
TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/output/
├── network/      # cisco_asa.log, meraki_*.log
├── cloud/        # aws, gcp, entraid, exchange, webex
├── windows/      # perfmon, wineventlog
├── linux/        # vmstat, df, iostat
├── web/          # access_combined.log
├── retail/       # orders.json, servicebus
└── itsm/         # servicenow_incidents.log
```

## Splunk Filtering

All scenario events include `demo_id` field:

```spl
index=* demo_id=exfil | stats count by sourcetype
index=* demo_id=cpu_runaway | timechart count
```
