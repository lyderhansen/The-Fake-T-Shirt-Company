# CLAUDE.md - Project Guide for TA-FAKE-TSHRT

## Project Overview

**The Fake T-Shirt Company (TA-FAKE-TSHRT)** is a Splunk Technical Add-on that generates realistic synthetic log data for demos and training. It simulates a fictional e-commerce company with 175 employees across 3 US locations (Boston HQ, Atlanta Hub, Austin Office) and 13 servers, producing correlated events across 24 data source generators with injectable security/ops/network scenarios. Generators are written in Python (stdlib only) and cover network (Cisco ASA, Meraki MX/MR/MS/MV/MT, Cisco Catalyst, Cisco ACI), cloud/security (AWS CloudTrail, GCP Audit, Entra ID, Cisco Secure Access), collaboration (Cisco Webex, Office 365 audit logs, Exchange), infrastructure (WinEventLog, Sysmon, Perfmon, MSSQL, Linux, Catalyst Center), ERP (SAP S/4HANA), ITSM (ServiceNow), and retail (Apache access, orders, ServiceBus). Key directories and their purposes should be documented in the Repository Structure section below as they are created.

## Output Preferences

- Default to concise bullet-point format, English language, and minimal prose unless explicitly asked otherwise
- For file path references and structured data, use Markdown tables with consistent formatting on first attempt — ask for clarification on format only if the structure is ambiguous
- Default Splunk time picker for this project is January 2026 (all generated data uses the timeline starting 2026-01-01)

## Verification Rules

- **Never document unverified information.** When looking up external links (Splunkbase apps, vendor documentation, API references), verify that the URL actually leads to the correct resource before including it in any file. If a link cannot be confirmed, ASK the user instead of guessing.
- **If you can't find it, say so.** Do not fabricate or assume Splunkbase app IDs, vendor documentation URLs, or API endpoint paths. Wrong documentation is worse than no documentation.
- **When in doubt, ask.** If web searches or URL fetches return unexpected results, 404 errors, or content that doesn't match what you expected, stop and ask the user what to do rather than proceeding with potentially incorrect information.

## Documentation Language

- **All documentation files (`.md`, code comments, docstrings) MUST be written in English.** This includes CHANGEHISTORY.md, README files, scenario docs, inline comments, and any new documentation.

## Change History

- **All code changes MUST be documented in `docs/CHANGEHISTORY.md`** with date/time (UTC), affected files, and a description of what was changed and why.
- New entries go at the top of the file (newest first), under a heading with format: `## YYYY-MM-DD ~HH:MM UTC — Short description`
- Include a verification summary (generators run, event count, pass/fail) when changes affect generators.
- This rule applies to all changes — new features, bug fixes, refactoring, generator updates, scenario changes, config changes, etc.

## Network Architecture

```
                              INTERNET
                                  │
                                  ▼
                        ┌──────────────────┐
                        │   FW-EDGE-01     │  ◄── Cisco ASA 5525-X
                        │   (Perimeter)    │      ALL external traffic
                        │   ASA 5525-X     │
                        └────────┬─────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
                 ▼               ▼               ▼
            ┌────────┐     ┌──────────┐    ┌──────────┐
            │  DMZ   │     │  Boston  │    │ SD-WAN   │
            │172.16.1│     │  Core    │    │ Transit  │
            │WEB-01/02│    │          │    │          │
            └────────┘     └────┬─────┘    └────┬─────┘
                                │               │
                                ▼               ▼
                        ┌──────────────┐   ┌─────────┐
                        │ MX-BOS-01/02 │   │ AutoVPN │
                        │   (SD-WAN)   │   │  Mesh   │
                        └──────────────┘   └────┬────┘
                                                │
                               ┌────────────────┼────────────────┐
                               ▼                                 ▼
                        ┌──────────────┐                  ┌──────────────┐
                        │  MX-ATL-01   │                  │  MX-AUS-01   │
                        │   Atlanta    │                  │    Austin    │
                        └──────────────┘                  └──────────────┘
```

### Firewall Hierarchy

| Layer | Device | Role |
|-------|--------|------|
| **Perimeter** | FW-EDGE-01 (ASA 5525-X) | All external traffic, DMZ firewall |
| **SD-WAN Hub** | MX-BOS-01/02 (HA) | Boston internal, AutoVPN concentrator |
| **SD-WAN Spokes** | MX-ATL-01, MX-AUS-01 | Branch offices, internal segmentation |

**Key:** The ASA sees ALL external traffic (exfil, C2, attacks) AND internal 3-tier app traffic (WEB->APP->SQL). Meraki MX handles internal/SD-WAN routing.

### Internal Application Traffic (3-Tier E-Commerce)

```
External -> ASA -> WEB-01/02 (DMZ 172.16.1.x)
                      |
                      v  (ASA: dmz->inside, port 443/8443)
                   APP-BOS-01 (10.10.20.40, IIS/.NET API)
                      |
                      v  (ASA: inside->inside, port 1433)
                   SQL-PROD-01 (10.10.20.30, MSSQL)
```

This 3-tier flow generates correlated ASA Built/Teardown events (~2% of baseline traffic) plus ACI contract-match events ("Web-to-App", "App-to-DB").

### Additional Network Components

| Component | Role | Coverage |
|-----------|------|----------|
| **Cisco Catalyst Switches** | Campus LAN switching (IOS-XE) | All 3 sites - core/distribution/access layers |
| **Cisco ACI** | Data center fabric (Boston DC) | Spine/leaf topology for server connectivity |
| **Cisco Secure Access** | Cloud-delivered security (DNS, Proxy, FW) | All users/locations - internet-bound traffic |
| **Catalyst Center** | Network management and assurance | Device health, network health, client health, issues |

### Locations

| Location | Code | Type | Floors | Employees | Network |
|----------|------|------|--------|-----------|---------|
| Boston, MA | BOS | Headquarters | 3 | ~93 | 10.10.x.x |
| Atlanta, GA | ATL | IT/Regional Hub | 2 | ~43 | 10.20.x.x |
| Austin, TX | AUS | Sales/Engineering | 1 | ~39 | 10.30.x.x |

**Note:** Austin has no local servers or DC. Austin users authenticate against DC-BOS-01/02 via SD-WAN tunnel and appear in DC-BOS WinEventLog auth events with 10.30.x.x source IPs (~30% of DC-BOS auth events).

## Repository Structure

```
The-Fake-T-Shirt-Company/
└── TA-FAKE-TSHRT/
    ├── TA-FAKE-TSHRT/           # Splunk app package
    │   ├── bin/                  # Python code
    │   │   ├── main_generate.py  # CLI orchestrator (parallel execution)
    │   │   ├── tui_generate.py   # Interactive TUI (curses-based)
    │   │   ├── generators/       # 24 data source generators
    │   │   ├── scenarios/        # Scenario implementations + registry
    │   │   ├── shared/           # Config, company data, time utils
    │   │   └── output/           # Generated log files (gitignored)
    │   │       ├── cloud/        # aws/, entraid/, gcp/, microsoft/, webex/, secure_access/, catalyst_center/
    │   │       ├── network/      # cisco_asa/, meraki/, catalyst/, aci/
    │   │       ├── windows/      # perfmon, wineventlog, sysmon, mssql
    │   │       ├── linux/        # cpu, vmstat, df, iostat, interfaces, auth
    │   │       ├── web/          # access, order_registry
    │   │       ├── retail/       # orders
    │   │       ├── servicebus/   # azure servicebus
    │   │       ├── itsm/         # servicenow
    │   │       └── erp/          # sap
    │   ├── default/              # Splunk conf files (props, transforms, inputs, etc.)
    │   │   └── data/ui/views/    # Splunk dashboards (XML)
    │   ├── lookups/              # CSV lookup tables
    │   ├── metadata/             # Splunk metadata
    │   └── static/               # App icons
    └── docs/                     # Project documentation
        ├── scenarios/            # 10 scenario guides (exfil, ransomware, etc.)
        ├── datasource_docs/      # 29 data source docs + index
        ├── reference/            # Architecture diagrams, SPL queries, design language, floor plans
        ├── guides/               # Demo talking track, Docker setup
        ├── graphic/              # Floor plan images, logos
        └── archive/              # Obsolete docs (kept for history)
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

## Available Log Sources

24 generators producing correlated log data. Dependencies: orders, servicebus, sap depend on access (via order_registry.json).

**Network:** asa (cisco:asa), meraki (meraki:mx/mr/ms/mv/mt), catalyst (cisco:ios), aci (cisco:aci:fault/event/audit)
**Cloud/Security:** aws (aws:cloudtrail), gcp (google:gcp:pubsub:message), entraid (azure:aad:signin/audit), secure_access (cisco:umbrella:dns/proxy/firewall/audit), catalyst_center (cisco:catalyst:devicehealth/networkhealth/clienthealth/issue)
**Collaboration:** exchange (ms:o365:reporting:messagetrace), office_audit (o365:management:activity), webex (cisco:webex:events), webex_ta (cisco:webex:meetings:history:*), webex_api (cisco:webex:*)
**Windows:** perfmon (perfmon), wineventlog (XmlWinEventLog), sysmon (XmlWinEventLog:Microsoft-Windows-Sysmon/Operational), mssql (mssql:errorlog)
**Linux:** linux (linux:*)
**Web/Retail:** access (access_combined), orders (retail:orders), servicebus (azure:servicebus)
**ERP/ITSM:** sap (sap:auditlog), servicenow (servicenow:incident)

## CLI Options

```
--all                    Generate all log sources
--sources=X,Y            Comma-separated sources or groups
--start-date=YYYY-MM-DD  Start date (default: 2026-01-01)
--days=N                 Number of days (default: 14)
--scale=N.N              Volume scale factor (default: 1.0)
--scenarios=X            Scenarios: none, exfil, all, attack, ops, network
--parallel=N             Parallel workers (default: 4)
--quiet                  Suppress progress output

# Output mode
--test                   Write to output/tmp/ (DEFAULT - safe for testing)
--no-test                Write to output/ (production - for Splunk ingestion)

# Perfmon-specific
--clients=N              Client workstations (default: 5, max: 175)
--full-metrics           Include disk/network for clients

# Access/Orders-specific
--orders-per-day=N       Target orders per day (default: ~224)
                         Also drives dynamic customer pool size (see below)

# Meraki-specific
--meraki-health-interval Health metric frequency (5/10/15/30 min)
```

### Output Modes

By default, all generators write to `output/tmp/` (test mode). This prevents accidentally overwriting Splunk-monitored files during development and testing.

- `--test` (default): Writes to `output/tmp/` - safe for testing, won't affect Splunk
- `--no-test`: Writes to `output/` - production mode, Splunk's `inputs.conf` reads from here

The TUI also has a `[TEST]/[PROD]` toggle in the Configuration section.

### Source Groups

- `all` - All sources
- `cloud` - aws, gcp, entraid, secure_access
- `network` - asa, meraki, catalyst, aci
- `cisco` - asa, meraki, secure_access, catalyst, aci, catalyst_center
- `campus` - catalyst, catalyst_center
- `datacenter` - aci
- `windows` - wineventlog, perfmon, mssql, sysmon
- `linux` - linux
- `web` - access
- `office` - office_audit, exchange
- `email` - exchange
- `retail` - orders, servicebus
- `erp` - sap
- `collaboration` - webex, webex_ta, webex_api
- `itsm` - servicenow

### Common Commands

```bash
# Generate all sources (test mode - output/tmp/)
python3 bin/main_generate.py --all --scenarios=all --days=14

# Generate for Splunk (production mode - output/)
python3 bin/main_generate.py --all --scenarios=all --days=14 --no-test

# Generate specific sources
python3 bin/main_generate.py --sources=asa,entraid,aws --scenarios=exfil --days=14

# Source groups
python3 bin/main_generate.py --sources=cloud --scenarios=none --days=7

# Interactive TUI
python3 bin/tui_generate.py

# Scale volume
python3 bin/main_generate.py --all --scale=0.5 --days=7

# High-volume demo
python3 bin/main_generate.py --all --days=31 --scenarios=all --orders-per-day=3000 --clients=40 --full-metrics
```

## Scenarios (bin/scenarios/)

10 implemented scenarios injected into baseline traffic, tagged with `demo_id` field.

All scenarios add `demo_id=<scenario>` field for easy filtering in Splunk.

| Scenario | Category | Days | Target |
|----------|----------|------|--------|
| exfil | attack | 1-14 | Alex Miller (Finance, Boston) |
| ransomware_attempt | attack | 8-9 | Brooklyn White (Sales, Austin) |
| phishing_test | attack | 21-23 | All employees (IT awareness campaign) |
| memory_leak | ops | 7-10 | WEB-01 server |
| cpu_runaway | ops | 11-12 | SQL-PROD-01 server |
| disk_filling | ops | 1-5 | MON-ATL-01 server |
| dead_letter_pricing | ops | 16 | WEB-01 (ServiceBus) |
| ddos_attack | network | 18-19 | WEB-01 server |
| firewall_misconfig | network | 6 | FW-EDGE-01 |
| certificate_expiry | network | 13 | FW-EDGE-01 |

Registry is in `bin/scenarios/registry.py`.

### Attack Scenarios

**exfil** - APT-style data exfiltration (14 days, cross-site attack)

Attack path: Atlanta (initial compromise) → Boston (primary target)

| Phase | Days | Activity | Location |
|-------|------|----------|----------|
| Reconnaissance | 0-3 | Port scanning, phishing sent | External → All |
| Initial Access | 4 | Jessica Brown clicks phishing link | Atlanta (ATL) |
| Lateral Movement | 5-7 | Cross-site probing ATL→BOS, privesc | ATL → BOS |
| Persistence | 8-10 | Backdoor creation, data staging | Boston (BOS) |
| Exfiltration | 11-14 | Data theft via cloud storage | Boston → External |

Affected sources: asa, aws, office_audit, linux, webex, webex_api, gcp, meraki, secure_access, wineventlog, mssql, entraid, exchange, sysmon, servicenow, aws_billing, guardduty, aci, catalyst

**ransomware_attempt** - Ransomware detected and stopped (Days 8-9)
- Target: Brooklyn White (Austin, Sales Engineer)
- Outcome: Blocked by EDR in 10 minutes
- Affected sources: asa, exchange, wineventlog, meraki, servicenow, office_audit, sysmon, secure_access, entraid

**phishing_test** - IT-run phishing awareness campaign (Days 21-23)
- Target: All employees (post-exfil incident awareness training)
- Outcome: Simulated phishing emails sent, click rates tracked
- Affected sources: exchange, secure_access, office_audit, wineventlog, servicenow, entraid

### Ops Scenarios

**memory_leak** - Application memory leak causing OOM (Days 7-10)
- Target: WEB-01 (Linux)
- Gradual memory consumption → OOM crash on Day 9 at 14:00, manual restart
- Affected sources: access, orders, servicebus, linux, asa, sap, catalyst_center, servicenow, aws

**cpu_runaway** - SQL backup job stuck at 100% CPU (Days 11-12)
- Target: SQL-PROD-01
- 100% CPU → DB connection failures → web errors
- Manual fix at Day 12 10:30
- Affected sources: access, orders, perfmon, catalyst_center, sap, mssql, wineventlog, servicenow, aci, gcp, aws

**disk_filling** - Server disk gradually filling up (Days 1-5)
- Target: MON-ATL-01 (Atlanta monitoring server)
- Progression: 45% -> 98% over 5 days
- Affected sources: access, orders, linux, servicenow, sap

**dead_letter_pricing** - ServiceBus dead-letter queue causes wrong prices (Day 16)
- Target: WEB-01 (ServiceBus price update pipeline)
- Duration: 4-6 hours of incorrect product pricing on web store
- Affected sources: access, orders, servicebus, sap, servicenow

### Network Scenarios

**ddos_attack** - Volumetric HTTP flood targeting web servers (Days 18-19)
- Target: WEB-01 (DMZ web servers)
- Botnet-driven HTTP flood causing service degradation
- Affected sources: access, orders, asa, catalyst_center, perfmon, linux, meraki, aws, aws_billing, catalyst, aci, servicenow, sap

**firewall_misconfig** - ACL misconfiguration (Day 6)
- Duration: 10:15-12:05 (2-hour outage)
- Cause: Human error (network admin)
- Affected sources: asa, servicenow, catalyst

**certificate_expiry** - SSL certificate expiration (Day 13)
- Duration: 00:00-07:00 (7 hours)
- Outcome: Preventable outage
- Affected sources: asa, access, servicenow

## Company Data (company.py)

### Organization
- Name: The FAKE T-Shirt Company
- Tenant: theTshirtCompany.com
- Tenant ID: af23e456-7890-1234-5678-abcdef012345
- Employees: ~175 across 3 locations

### Network (Per Location)

| Location | Network | Users | Servers | IoT/Sensors | Cameras |
|----------|---------|-------|---------|-------------|---------|
| Boston (BOS) | 10.10.x.x | .30.0/23 | .20.0/24 | .60.0/24 | .70.0/24 |
| Atlanta (ATL) | 10.20.x.x | .30.0/24 | .20.0/24 | .60.0/24 | .70.0/24 |
| Austin (AUS) | 10.30.x.x | .30.0/24 | - | .60.0/24 | .70.0/24 |

- DMZ (Boston): 172.16.1.0/24
- VPN Pool: 10.250.0.0/24 (deterministic per-user via SHA256 hash, range .10-.209)
- SD-WAN: AutoVPN mesh between all sites

### Cloud
- AWS Account: 123456789012 (us-east-1)
- GCP Project: faketshirtcompany-prod-01 (us-central1)

### Key Users

| User | Role | Location | IP | Notes |
|------|------|----------|-----|-------|
| alex.miller | Sr. Financial Analyst | BOS Floor 2 | 10.10.30.55 | **Primary target** |
| jessica.brown | IT Administrator | ATL Floor 1 | 10.20.30.15 | **Initial compromise** |
| brooklyn.white | Sales Engineer | AUS | 10.30.30.20 | **Ransomware target** |
| john.smith | CEO | BOS Floor 3 | 10.10.30.10 | Executive |
| sarah.wilson | CFO | BOS Floor 2 | 10.10.30.12 | Finance leadership |
| mike.johnson | CTO | BOS Floor 3 | 10.10.30.11 | IT leadership |

### Threat Actor
- IP: 185.220.101.42
- Location: Frankfurt, Germany
- ASN: AS205100 (F3 Netze e.V.)

### Key Servers (13 total)

**Boston HQ (10.10.x.x) — 10 servers:**

| Hostname | IP | Role | OS |
|----------|-----|------|-----|
| DC-BOS-01 | 10.10.20.10 | Domain Controller | Windows |
| DC-BOS-02 | 10.10.20.11 | Domain Controller | Windows |
| FILE-BOS-01 | 10.10.20.20 | File Server | Windows |
| SQL-PROD-01 | 10.10.20.30 | SQL Database | Windows |
| APP-BOS-01 | 10.10.20.40 | e-Commerce API Server (IIS/.NET) | Windows |
| SAP-PROD-01 | 10.10.20.60 | SAP Application Server | Linux |
| SAP-DB-01 | 10.10.20.61 | SAP HANA Database | Linux |
| BASTION-BOS-01 | 10.10.10.10 | Bastion Host (management subnet) | Linux |
| WEB-01 | 172.16.1.10 | Web Server (DMZ) | Linux |
| WEB-02 | 172.16.1.11 | Web Server (DMZ) | Linux |

**Atlanta Hub (10.20.x.x) — 3 servers:**

| Hostname | IP | Role | OS |
|----------|-----|------|-----|
| DC-ATL-01 | 10.20.20.10 | Domain Controller | Windows |
| BACKUP-ATL-01 | 10.20.20.20 | Backup Server | Windows |
| MON-ATL-01 | 10.20.20.30 | Monitoring Server | Linux |

**Austin (10.30.x.x) — 0 servers** (branch office, no local infrastructure)

## Shared Utilities (bin/shared/)

| File | Purpose |
|------|---------|
| config.py | Global defaults, volume patterns, output paths, hour activity levels |
| company.py | 175 employees, 3 locations, network architecture, IP ranges, cloud config |
| time_utils.py | Timestamp formatters, volume multipliers, scenario phase helpers |
| products.py | 72 IT-themed products with pricing |
| meeting_schedule.py | Shared Webex meeting schedule across generators |

## Volume Patterns

### Hourly Activity (Weekday)
- Peak: 9-11 AM, 1-3 PM (100%)
- Lunch: 12 PM (60%)
- Evening: 6-9 PM (20-30%)
- Night: 12-6 AM (10%)

### Weekend Factors
- Web/retail: 70% of weekday
- Cloud: 30% (automated jobs)
- Email: 15%
- Auth: 20%

### Monday Boost
- 115% of normal volume (post-weekend catch-up)

### Daily Noise
- ±15% random variation (deterministic via date hashing)

## Product Catalog (products.py)

72 IT-themed products across 4 types:
- **T-shirts** (35): $34-45 - "It Works On My Machine", "It's Always DNS", etc.
- **Hoodies** (17): $72-85 - Premium versions of popular designs
- **Joggers** (10): $65-72 - Developer/DevOps lifestyle
- **Accessories** (10): $28-85 - Caps, beanies, backpack, laptop sleeve

Categories: developer, sysadmin, security, nerd, modern

## Customer Pool & VIP Segmentation

Dynamic pool: `pool_total = max(500, orders_per_day * days // 4)` (~4 orders/customer). VIP = top 5% driving 30% of orders. `lookups/customer_lookup.csv` covers CUST-00001 to CUST-00500 only.

## Meraki Device Configuration (Multi-Site)

4 MX (SD-WAN: BOS HA pair, ATL, AUS), 36 MR APs (BOS 16, ATL 12, AUS 8), 11 MS switches (BOS 5, ATL 4, AUS 2), 15 MV cameras (BOS 8, ATL 7, AUS 4), 14 MT infrastructure sensors + ~38 meeting room sensors (temp, humidity, door, water leak). SSIDs: FakeTShirtCo-Corp (802.1X), FakeTShirtCo-Guest (PSK), FakeTShirtCo-IoT (PSK), FakeTShirtCo-Voice (802.1X). Full device inventory in `generate_meraki.py`.

### Meraki Event Types
- **MX**: firewall, urls, security_event (IDS), vpn, sd_wan_health, sd_wan_failover
- **MR**: association, disassociation, 802.1X auth, WPA auth, rogue AP detection
- **MS**: port status, spanning tree, 802.1X port auth
- **MV**: motion_detection, person_detection, analytics, health_status
- **MT**: temperature, humidity, door_open/close, water_leak

---

## Webex Collaboration Devices

21 rooms across 3 sites (BOS 10, ATL 7, AUS 4), named after video game characters. Naming: `{TYPE}-{LOC}-{FLOOR}F-{NAME}`. Problem rooms: Kirby (wifi/codec), Cortana (bandwidth/echo). Sunny rooms: Link, Chief, Doom. Full inventory in `company.py` and `meeting_schedule.py`.

---

## Splunk Configuration (default/)

- `app.conf` - App identity (version 1.0.0)
- `inputs.conf` - Monitor inputs for generated log files
- `props.conf` - Field extractions, timestamp parsing, line breaking
- `transforms.conf` - Host routing, field extractions, lookup definitions
- `eventtypes.conf` / `tags.conf` - CIM-compatible event classification

### Key Fields for Dashboards
- `demo_id` - Filter by scenario (exfil, memory_leak, cpu_runaway, disk_filling, etc.)
- `demo_host` - Correlate by hostname
- `src` / `dst` - Network source/destination
- `user` / `userName` - User identity correlation

### Sample SPL Queries

```spl
index=fake_tshrt demo_id=exfil | stats count by sourcetype
index=fake_tshrt sourcetype="FAKE:cisco:asa" | timechart count by action
index=fake_tshrt sourcetype="FAKE:perfmon" demo_host="SQL-PROD-01" | timechart avg(Value) by counter
```

## Adding New Generators

1. Create `generate_<source>.py` following existing patterns
2. Import from `config.py`, `company.py`, `time_utils.py`
3. Implement `generate_<source>_logs()` function with standard signature:
   ```python
   def generate_xxx_logs(
       start_date: str = DEFAULT_START_DATE,
       days: int = DEFAULT_DAYS,
       scale: float = DEFAULT_SCALE,
       scenarios: str = "none",
       output_file: str = None,       # or output_dir for multi-file generators
       progress_callback=None,         # Called with (source_name, current_day, total_days)
       quiet: bool = False,
   ) -> int:  # Returns event count (or dict with {"total": N, "files": {...}})
   ```
   **Note:** `scale` controls volume for most generators. Perfmon (fixed metric intervals),
   orders (use `--orders-per-day`), and servicebus (1:1 with orders) intentionally ignore scale.
4. Add to `main_generate.py`:
   - Import the function
   - Add to `GENERATORS` dict
   - Add to appropriate `SOURCE_GROUPS`
5. If generator has dependencies, add to `GENERATOR_DEPENDENCIES`

## Key Design Patterns

- **Volume realism**: Hourly activity curves, weekend/weekday factors, Monday boost (115%), daily noise (±15%)
- **Parallel execution**: Phase 1 (independent generators) then Phase 2 (dependent generators)
- **Scenario injection**: Events tagged with `demo_id` field; multiple scenarios run concurrently
- **Cross-generator correlation**: TCP sessions, VPN assignments, order-to-access linking, shared meeting schedules
- **Deterministic noise**: Seeded randomness via date hashing for reproducible patterns

## Known Data Gaps

| Gap | Description | Fix Required |
|-----|-------------|-------------|
| SAP timestamps | SAP events use `%Y-%m-%d %H:%M:%S` but some events may have timezone inconsistencies | Data regeneration |
| GCP sourcetype split | GCP events split across `admin_activity:demo` and `data_access:demo` variants | Data regeneration |

## Development Notes

- All generators are self-contained Python files with no external dependencies
- The Meraki generator is the largest and most complex (~126K lines)
- Output goes to `bin/output/` organized by category (network/, cloud/, windows/, linux/, web/, retail/, erp/, itsm/, servicebus/)
- Default timeline: 14 days starting 2026-01-01
- Splunk index: `fake_tshrt`
- **Splunk sourcetypes are prefixed with `FAKE:`** -- e.g., `FAKE:cisco:asa`, `FAKE:aws:cloudtrail`. Generators produce events with standard sourcetype names; Splunk's `props.conf`/`transforms.conf` apply the `FAKE:` prefix at index time. All SPL queries in documentation must use: `index=fake_tshrt sourcetype="FAKE:cisco:asa"`
- All scenario events queryable via `demo_id` field in Splunk
- 13 servers across 2 locations (10 Boston, 3 Atlanta), 175 employees across 3 locations
- SAP generator correlates with orders via `order_registry.json` (NDJSON format, one JSON object per line). tshirtcid (browser cookie UUID) is included in VA01/VL01N/VF01 event details and extracted via `extract_sap_tshirtcid` transform
- Customer pool is dynamic: `pool_total = max(500, orders_per_day * days // 4)` targeting ~4 orders/customer. VIP = top 5% of pool driving 30% of traffic (Pareto). `customer_lookup.csv` covers 500 VIP customers only (CUST-00001 to CUST-00500)

## Future Enhancements

Planned generators:
- Palo Alto firewall
- CrowdStrike EDR
- Okta authentication
- Kubernetes logs
