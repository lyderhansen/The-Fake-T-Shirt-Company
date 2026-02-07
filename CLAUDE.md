# CLAUDE.md - Project Guide for TA-FAKE-TSHRT

## Project Overview

**The Fake T-Shirt Company (TA-FAKE-TSHRT)** is a Splunk Technical Add-on that generates realistic synthetic log data for demos and training. It simulates a fictional e-commerce company with 175 employees across 3 US locations (Boston HQ, Atlanta Hub, Austin Office), producing correlated events across 17 data source generators with injectable security/ops/network scenarios.

## Repository Structure

```
The-Fake-T-Shirt-Company/
└── TA-FAKE-TSHRT/
    ├── TA-FAKE-TSHRT/           # Splunk app package
    │   ├── bin/                  # Python code
    │   │   ├── main_generate.py  # CLI orchestrator (parallel execution)
    │   │   ├── tui_generate.py   # Interactive TUI (curses-based)
    │   │   ├── generators/       # 17 data source generators
    │   │   ├── scenarios/        # Scenario implementations + registry
    │   │   ├── shared/           # Config, company data, time utils
    │   │   └── output/           # Generated log files (gitignored)
    │   ├── default/              # Splunk conf files (props, transforms, inputs, etc.)
    │   │   └── data/ui/views/    # Splunk dashboards (XML)
    │   ├── lookups/              # CSV lookup tables
    │   ├── metadata/             # Splunk metadata
    │   └── static/               # App icons
    └── docs/                     # Scenario docs, SPL queries, data source docs
```

## Tech Stack

- **Python 3.8+** (stdlib only - no external dependencies)
- **Splunk Enterprise 8.0+** target platform
- ThreadPoolExecutor for parallel generation
- curses for TUI interface

## Key Entry Points

| File | Purpose |
|------|---------|
| `bin/main_generate.py` | Main CLI orchestrator, parallel execution, dependency resolution |
| `bin/tui_generate.py` | Interactive TUI with source/scenario selection |
| `bin/generate_logs.py` | Legacy wrapper (calls main_generate.py) |
| `bin/delete_index.py` | Splunk index cleanup utility |

## Generators (bin/generators/)

17 generators producing correlated log data:

| Generator | Data Source | Key Details |
|-----------|------------|-------------|
| generate_asa.py | Cisco ASA firewall | Perimeter edge (FW-EDGE-01), syslog format |
| generate_meraki.py | Cisco Meraki (MX/MR/MS/MV/MT) | Largest generator (~126K lines) |
| generate_aws.py | AWS CloudTrail | Account 123456789012 |
| generate_gcp.py | GCP Audit Logs | Project faketshirtcompany-prod-01 |
| generate_entraid.py | Azure Entra ID | Signin + Audit logs |
| generate_exchange.py | Exchange message trace | Email flow logs |
| generate_webex.py | Webex Events API | Meeting/call events |
| generate_webex_ta.py | Webex TA format | Meeting usage + attendees |
| generate_webex_api.py | Webex REST API format | Meetings, audit, call history |
| generate_wineventlog.py | Windows Event Log | Security/System/Application |
| generate_perfmon.py | Windows Perfmon | CPU/Memory/Disk/Network metrics |
| generate_linux.py | Linux metrics | vmstat/df/iostat/interfaces |
| generate_access.py | Apache access logs | E-commerce web traffic |
| generate_orders.py | Retail orders | Depends on access logs |
| generate_servicebus.py | Azure ServiceBus | Depends on access logs |
| generate_servicenow.py | ServiceNow incidents | ITSM tickets |

**Dependencies:** orders and servicebus depend on access (via order_registry.json).

## Scenarios (bin/scenarios/)

7 implemented scenarios injected into baseline traffic, tagged with `demo_id` field:

| Scenario | Category | Days | Target |
|----------|----------|------|--------|
| exfil | security | 1-14 | Alex Miller (Finance, Boston) |
| ransomware_attempt | security | 8-9 | Brooklyn White (Sales, Austin) |
| memory_leak | ops | 6-9 | WEB-01 server |
| cpu_runaway | ops | 11-12 | SQL-PROD-01 server |
| disk_filling | ops | 1-5 | MON-ATL-01 server |
| firewall_misconfig | network | 7 | FW-EDGE-01 |
| certificate_expiry | network | 12 | FW-EDGE-01 |

Registry is in `bin/scenarios/registry.py`.

## Shared Utilities (bin/shared/)

| File | Purpose |
|------|---------|
| config.py | Global defaults, volume patterns, output paths, hour activity levels |
| company.py | 175 employees, 3 locations, network architecture, IP ranges, cloud config |
| time_utils.py | Timestamp formatters, volume multipliers, scenario phase helpers |
| products.py | 72 IT-themed products with pricing |
| meeting_schedule.py | Shared Webex meeting schedule across generators |

## Splunk Configuration (default/)

- `app.conf` - App identity (version 1.0.0)
- `inputs.conf` - Monitor inputs for generated log files
- `props.conf` - Field extractions, timestamp parsing, line breaking
- `transforms.conf` - Host routing, field extractions, lookup definitions
- `eventtypes.conf` / `tags.conf` - CIM-compatible event classification

## Common Commands

```bash
# Generate all sources with all scenarios
python3 bin/main_generate.py --all --scenarios=all --days=14

# Generate specific sources
python3 bin/main_generate.py --sources=asa,entraid,aws --scenarios=exfil --days=14

# Source groups: all, cloud, network, windows, linux, web, email, retail, collaboration, itsm
python3 bin/main_generate.py --sources=cloud --scenarios=none --days=7

# Interactive TUI
python3 bin/tui_generate.py

# Scale volume
python3 bin/main_generate.py --all --scale=0.5 --days=7
```

## Key Design Patterns

- **Volume realism**: Hourly activity curves, weekend/weekday factors, Monday boost (115%), daily noise (±15%)
- **Parallel execution**: Phase 1 (independent generators) then Phase 2 (dependent generators)
- **Scenario injection**: Events tagged with `demo_id` field; multiple scenarios run concurrently
- **Cross-generator correlation**: TCP sessions, VPN assignments, order-to-access linking, shared meeting schedules
- **Deterministic noise**: Seeded randomness via date hashing for reproducible patterns

## Key Personnel (for scenario context)

- **Jessica Brown** - IT Admin, Atlanta (10.20.30.15) - Initial compromise vector (exfil)
- **Alex Miller** - Financial Analyst, Boston (10.10.30.55) - Primary exfil target
- **Brooklyn White** - Sales Engineer, Austin (10.30.30.20) - Ransomware target
- **Threat actor IP**: 185.220.101.42 (Frankfurt, Germany)

## Development Notes

- All generators are self-contained Python files with no external dependencies
- The Meraki generator is the largest and most complex (~126K lines)
- Output goes to `bin/output/` organized by category (network/, cloud/, windows/, etc.)
- Default timeline: 14 days starting 2026-01-01
- Splunk index: `splunk_demo`
- All scenario events queryable via `demo_id` field in Splunk
