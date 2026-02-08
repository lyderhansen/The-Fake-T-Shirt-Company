# CLAUDE.md - Project Guide for TA-FAKE-TSHRT

## Project Overview

**The Fake T-Shirt Company (TA-FAKE-TSHRT)** is a Splunk Technical Add-on that generates realistic synthetic log data for demos and training. It simulates a fictional e-commerce company with 175 employees across 3 US locations (Boston HQ, Atlanta Hub, Austin Office), producing correlated events across 18 data source generators with injectable security/ops/network scenarios. Generators are written in Python (stdlib only) and cover network (Cisco ASA, Meraki MX/MR/MS/MV/MT), cloud (AWS CloudTrail, GCP Audit, Entra ID), collaboration (Cisco Webex, Office 365 audit logs, Exchange), infrastructure (WinEventLog, Perfmon, Linux), and retail (Apache access, orders, ServiceBus). Key directories and their purposes should be documented in the Repository Structure section below as they are created.

## Output Preferences

- Default to concise bullet-point format, English language, and minimal prose unless explicitly asked otherwise
- For file path references and structured data, use Markdown tables with consistent formatting on first attempt — ask for clarification on format only if the structure is ambiguous
- Default Splunk time picker for this project is January 2026 (all generated data uses the timeline starting 2026-01-01)

## Verification Rules

- **Never document unverified information.** When looking up external links (Splunkbase apps, vendor documentation, API references), verify that the URL actually leads to the correct resource before including it in any file. If a link cannot be confirmed, ASK the user instead of guessing.
- **If you can't find it, say so.** Do not fabricate or assume Splunkbase app IDs, vendor documentation URLs, or API endpoint paths. Wrong documentation is worse than no documentation.
- **When in doubt, ask.** If web searches or URL fetches return unexpected results, 404 errors, or content that doesn't match what you expected, stop and ask the user what to do rather than proceeding with potentially incorrect information.

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

**Key:** The ASA sees ALL external traffic (exfil, C2, attacks). Meraki MX handles internal/SD-WAN routing.

### Locations

| Location | Code | Type | Floors | Employees | Network |
|----------|------|------|--------|-----------|---------|
| Boston, MA | BOS | Headquarters | 3 | ~93 | 10.10.x.x |
| Atlanta, GA | ATL | IT/Regional Hub | 2 | ~43 | 10.20.x.x |
| Austin, TX | AUS | Sales/Engineering | 1 | ~39 | 10.30.x.x |

## Repository Structure

```
The-Fake-T-Shirt-Company/
└── TA-FAKE-TSHRT/
    ├── TA-FAKE-TSHRT/           # Splunk app package
    │   ├── bin/                  # Python code
    │   │   ├── main_generate.py  # CLI orchestrator (parallel execution)
    │   │   ├── tui_generate.py   # Interactive TUI (curses-based)
    │   │   ├── generators/       # 18 data source generators
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

## Available Log Sources

18 generators producing correlated log data:

| Source | Generator | Output Format | Splunk Sourcetype |
|--------|-----------|---------------|-------------------|
| **Network** |
| Cisco ASA | generate_asa.py | Syslog | cisco:asa |
| Meraki MX (Firewall) | generate_meraki.py | Syslog | meraki:mx |
| Meraki MR (AP) | generate_meraki.py | Syslog | meraki:mr |
| Meraki MS (Switch) | generate_meraki.py | Syslog | meraki:ms |
| Meraki MV (Camera) | generate_meraki.py | Syslog | meraki:mv |
| Meraki MT (Sensor) | generate_meraki.py | Syslog | meraki:mt |
| **Cloud/Collaboration** |
| AWS CloudTrail | generate_aws.py | JSON | aws:cloudtrail |
| GCP Audit | generate_gcp.py | JSON | google:gcp:pubsub:message |
| Entra ID Sign-in | generate_entraid.py | JSON | azure:aad:signin |
| Entra ID Audit | generate_entraid.py | JSON | azure:aad:audit |
| Exchange | generate_exchange.py | CSV | ms:o365:reporting:messagetrace |
| M365 Audit | generate_office_audit.py | JSON | o365:management:activity |
| Cisco Webex | generate_webex.py | JSON | cisco:webex:events |
| Webex TA | generate_webex_ta.py | JSON | cisco:webex:meetings:history:* |
| Webex API | generate_webex_api.py | JSON | cisco:webex:* (5 types) |
| **Windows** |
| Perfmon | generate_perfmon.py | Multiline KV | perfmon |
| WinEventLog | generate_wineventlog.py | XML | XmlWinEventLog |
| **Linux** |
| vmstat/df/iostat | generate_linux.py | Syslog KV | linux:* |
| **Web/Retail** |
| Apache Access | generate_access.py | Combined log | access_combined |
| Orders | generate_orders.py | JSON | retail:orders |
| ServiceBus | generate_servicebus.py | JSON | azure:servicebus |
| **ITSM** |
| ServiceNow | generate_servicenow.py | Key-value | servicenow:incident |

**Dependencies:** orders and servicebus depend on access (via order_registry.json).

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
- `cloud` - aws, gcp, entraid
- `network` - asa, meraki
- `windows` - wineventlog, perfmon
- `linux` - linux
- `web` - access
- `office` - office_audit, exchange
- `email` - exchange
- `retail` - orders, servicebus
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

7 implemented scenarios injected into baseline traffic, tagged with `demo_id` field.

All scenarios add `demo_id=<scenario>` field for easy filtering in Splunk.

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

Affected sources: asa, meraki, entraid, aws, gcp, perfmon, wineventlog, exchange, office_audit

**ransomware_attempt** - Ransomware detected and stopped (Days 8-9)
- Target: Brooklyn White (Austin, Sales Engineer)
- Outcome: Blocked by EDR in 10 minutes
- Affected sources: asa, exchange, wineventlog, meraki, servicenow, office_audit

### Ops Scenarios

**memory_leak** - Application memory leak causing OOM (Days 6-9)
- Target: WEB-01 (Linux)
- Gradual memory consumption → OOM crash on Day 9 at 14:00, manual restart
- Affected sources: perfmon, linux, asa, access

**cpu_runaway** - SQL backup job stuck at 100% CPU (Days 11-12)
- Target: SQL-PROD-01
- 100% CPU → DB connection failures → web errors
- Manual fix at Day 12 10:30
- Affected sources: perfmon, wineventlog, asa, access

**disk_filling** - Server disk gradually filling up (Days 1-5)
- Target: MON-ATL-01 (Atlanta monitoring server)
- Progression: 45% → 98% over 5 days
- Affected sources: linux, access

### Network Scenarios

**firewall_misconfig** - ACL misconfiguration (Day 7)
- Duration: 10:15-12:05 (2-hour outage)
- Cause: Human error (network admin)
- Affected sources: asa, servicenow

**certificate_expiry** - SSL certificate expiration (Day 12)
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

### Key Servers

| Hostname | Role | Location | OS |
|----------|------|----------|-----|
| BOS-DC-01, BOS-DC-02 | Domain Controllers | Boston | Windows |
| BOS-FILE-01 | File Server | Boston | Windows |
| SQL-PROD-01 | SQL Database | Boston | Windows |
| ATL-DC-01 | Domain Controller | Atlanta | Windows |
| ATL-FILE-01 | File Server | Atlanta | Windows |
| WEB-01, WEB-02 | Web Servers | Boston DMZ | Linux |
| MON-ATL-01 | Monitoring Server | Atlanta | Linux |

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

## Log Format Examples

### Syslog (ASA)
```
Jan 05 2026 14:23:45 FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.0.10.150/54321 (203.0.113.10/54321) demo_id=exfil
```

### Meraki Syslog
```
<134>1 1735689600.123456789 MX-HQ-01 firewall src=10.0.10.150 dst=8.8.8.8 mac=AA:BB:CC:DD:EE:FF protocol=tcp sport=54321 dport=443 pattern: allow all
<134>1 1735689600.234567890 AP-HQ-FLOOR1 events type=association radio='1' vap='0' channel='36' rssi='55' client_mac='11:22:33:44:55:66' ssid='TShirtCo-Corp'
```

### JSON (AWS/GCP/EntraID)
```json
{"eventTime":"2026-01-05T14:23:45Z","eventSource":"s3.amazonaws.com","eventName":"GetObject","userIdentity":{"userName":"alex.miller"},"demo_id":"exfil"}
```

### Multiline KV (Perfmon)
```
01/05/2026 14:23:45.123
collection="Processor"
object=Processor
counter="% Processor Time"
instance=_Total
Value=45.23
demo_host=SQL-PROD-01
```

### Apache Combined (Access)
```
73.158.42.100 - - [05/Jan/2026:14:23:45 +0000] "GET /products/hack-the-planet-hoodie HTTP/1.1" 200 4523 "https://theTshirtCompany.com/" "Mozilla/5.0..." demo_id=exfil
```

### ServiceNow Key-Value
```
number="INC0001234" state="In Progress" priority="2" short_description="CPU runaway on SQL-PROD-01" assignment_group="IT Operations"
```

### Webex TA JSON (Meetings History)
```json
{"ConfName":"Weekly Team Sync","UserName":"john.smith@theTshirtCompany.com","StartTime":"01/05/2026 09:00:00","Duration":"45","AttendeeCount":"8"}
```

### Webex API JSON (REST API)
```json
{"id":"abc123","title":"Board Meeting","start":"2026-01-05T14:00:00Z","end":"2026-01-05T15:00:00Z","hostEmail":"john.smith@theTshirtCompany.com"}
```

## Product Catalog (products.py)

72 IT-themed products across 4 types:
- **T-shirts** (35): $34-45 - "It Works On My Machine", "It's Always DNS", etc.
- **Hoodies** (17): $72-85 - Premium versions of popular designs
- **Joggers** (10): $65-72 - Developer/DevOps lifestyle
- **Accessories** (10): $28-85 - Caps, beanies, backpack, laptop sleeve

Categories: developer, sysadmin, security, nerd, modern

## Meraki Device Configuration (Multi-Site)

### MX Security Appliances / SD-WAN
| Device | Model | Location | Role | WAN Links |
|--------|-------|----------|------|-----------|
| MX-BOS-01 | MX450 | Boston | Primary (HA) | Comcast, AT&T |
| MX-BOS-02 | MX450 | Boston | Secondary (HA) | Comcast, AT&T |
| MX-ATL-01 | MX250 | Atlanta | Primary | AT&T, Spectrum |
| MX-AUS-01 | MX85 | Austin | Primary | Verizon |

### MR Access Points (36 total)
| Location | Qty | Models | Areas |
|----------|-----|--------|-------|
| Boston | 16 | MR46 | 3 floors: Reception, Finance, Exec, Engineering |
| Atlanta | 12 | MR46 | 2 floors: IT Ops, NOC, Training, Engineering |
| Austin | 8 | MR46 | 1 floor: Sales, Engineering, Demo Lab |

### MS Switches (11 total)
| Location | Core | Access | Models |
|----------|------|--------|--------|
| Boston | 2x MS425-32 | 3x MS225-48 | Core stack + IDF per floor |
| Atlanta | 2x MS425-32 | 2x MS225-48 | DC core + floor access |
| Austin | - | 2x MS225-24 | Access only |

### MV Smart Cameras (19 total)
| Location | Indoor | Outdoor | Areas |
|----------|--------|---------|-------|
| Boston | 8x MV12/MV32 | 2x MV72 | Lobby, server rooms, parking |
| Atlanta | 6x MV12/MV32 | - | DC, NOC, entrances |
| Austin | 3x MV12 | - | Lobby, demo lab |

### MT Sensors (14 total)
| Type | Model | Locations |
|------|-------|-----------|
| Temperature | MT10 | Server rooms, data centers |
| Humidity | MT11 | Data centers |
| Door | MT20 | Server rooms, MDF/IDF |
| Water Leak | MT14 | Data center floors |

### Meraki SSIDs
- TShirtCo-Corp (802.1X) - Corporate network
- TShirtCo-Guest (PSK) - Guest network
- TShirtCo-IoT (PSK) - IoT devices

### Meraki Event Types
- **MX**: firewall, urls, security_event (IDS), vpn, sd_wan_health, sd_wan_failover
- **MR**: association, disassociation, 802.1X auth, WPA auth, rogue AP detection
- **MS**: port status, spanning tree, 802.1X port auth
- **MV**: motion_detection, person_detection, analytics, health_status
- **MT**: temperature, humidity, door_open/close, water_leak

---

## Webex Collaboration Devices

### Device Inventory (17 rooms)

| Location | Room | Device | Model | Capacity |
|----------|------|--------|-------|----------|
| **Boston** |
| | Cambridge (Boardroom) | WEBEX-BOS-CAMBRIDGE | Room Kit Pro + Board 85 Pro | 20 |
| | Faneuil | WEBEX-BOS-FANEUIL | Room Kit + Board 55 | 12 |
| | Quincy | WEBEX-BOS-QUINCY | Room Kit | 8 |
| | North End | WEBEX-BOS-NORTHEND | Desk Pro | 4 |
| | Back Bay | WEBEX-BOS-BACKBAY | Room Kit Mini | 6 |
| | Engineering Lab | WEBEX-BOS-LAB | Board 55 | 8 |
| | Harbor (Visitor) | WEBEX-BOS-HARBOR | Desk Pro | 6 |
| | Beacon (Visitor) | WEBEX-BOS-BEACON | Room Kit Mini | 4 |
| **Atlanta** |
| | Peachtree (Training) | WEBEX-ATL-PEACHTREE | Room Kit Pro | 16 |
| | Midtown | WEBEX-ATL-MIDTOWN | Room Kit + Board 55 | 10 |
| | NOC | WEBEX-ATL-NOC | Room Kit | 6 |
| | Buckhead | WEBEX-ATL-BUCKHEAD | Desk Pro | 4 |
| | Decatur | WEBEX-ATL-DECATUR | Desk Pro | 4 |
| | Innovation Lab | WEBEX-ATL-INNOVATION | Board 55 | 8 |
| **Austin** |
| | Congress | WEBEX-AUS-CONGRESS | Room Kit + Board 55 | 12 |
| | 6th Street | WEBEX-AUS-6THSTREET | Room Kit Mini | 6 |
| | Live Oak (Demo) | WEBEX-AUS-LIVEOAK | Room Kit | 8 |

### Webex Event Types
- **Meetings**: meeting_started, participant_joined, participant_left, meeting_ended
- **Quality**: quality_metrics (audio MOS, video loss, jitter, latency)
- **Device**: device_health (CPU, memory, peripherals)
- **Analytics**: room_analytics (people count, ambient noise)
- **Sharing**: wireless_share_started

---

## Sensor + Webex Correlation

Meeting room sensors and Webex devices generate correlated events:

### Meeting Lifecycle
```
-5 min   Door opens (MT)           First person arrives
-3 min   Person detected (MV)      Camera sees movement
-2 min   Temp begins rising        Body heat
 0 min   meeting_started           Webex meeting starts
+2 min   participants_join         People connect
+5 min   people_count: 6           Room analytics
+10 min  Temp +1.5C               Stabilizes higher
+55 min  participants_leave        People leave
+60 min  meeting_ended             Meeting ends
+62 min  Door opens                People exit
+75 min  Temp drops gradually      Room cools down
```

### Meeting Variations
| Type | Frequency | Description |
|------|-----------|-------------|
| Ghost meetings (no-show) | ~15% | Room booked but no one shows up - no Webex events, no sensor activity |
| Walk-in (unbooked) | ~10% | Door/camera activity without Webex meeting |
| Late start | ~20% | Meeting starts 5-15 min after scheduled time |
| Overfilled | ~5% | More participants than room capacity |

### Problem Rooms (Consistent Quality Issues)
| Room | Location | Issues | Cause |
|------|----------|--------|-------|
| **North End** | Boston Floor 3 | `wifi_congestion`, `old_equipment` | Near busy AP, outdated codec |
| **Peachtree** | Atlanta Floor 2 | `bandwidth_limited`, `echo_issues` | Too many video streams, bad acoustics |

Quality metrics for problem rooms show:
- `audio.mos_score` < 3.5 (poor/fair)
- `video.packet_loss_pct` > 3%
- `network.jitter_ms` > 40
- `audio.echo_detected: true` (Peachtree only)

### Sunny Rooms (Temperature Variations)
| Room | Location | Sun Direction | Peak Hours | Extra Heat |
|------|----------|---------------|------------|------------|
| Cambridge | Boston | South | 13:00-17:00 | +4C |
| Midtown | Atlanta | West | 14:00-18:00 | +3.5C |
| Congress | Austin | Southwest | 12:00-17:00 | +5C |

### After-Hours Activity
Legitimate overtime work on days 3 and 7 (NOT related to exfil scenario):
- Rooms: Back Bay, North End, Buckhead
- Time: 20:00-23:00
- Creates investigatable but non-malicious sensor/Webex events

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
# Find all exfil scenario events
index=* demo_id=exfil | stats count by sourcetype

# Timeline of attack phases
index=* demo_id=exfil | timechart count by sourcetype

# Compromised user activity
index=cloud sourcetype="azure:aad:signin" user="alex.miller"

# CPU runaway correlation
index=windows demo_host="SQL-PROD-01" | timechart avg(Value) by counter

# Order revenue by product type
index=retail sourcetype="retail:orders" | stats sum(total) by product_type
```

---

## Splunk App Development (TA-FAKE-TSHRT)

This project includes a Splunk Technology Add-on (TA) for managing log generation from within Splunk Web.

### REST Endpoint Development

#### Handler Pattern: PersistentServerConnectionApplication

Splunk custom REST endpoints **must** use `PersistentServerConnectionApplication` for proper HTTP method support:

```python
from splunk.persistconn.application import PersistentServerConnectionApplication
import json

class MyHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line, command_arg):
        super().__init__()

    def handle(self, in_string):
        request = json.loads(in_string)
        method = request.get('method', 'GET')
        session_key = request.get('session', {}).get('authtoken')

        # Parse form data (comes as list of [key, value] pairs)
        form_data = {}
        for item in request.get('form', []):
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                form_data[item[0]] = item[1]

        if method == 'POST':
            return {
                'status': 200,
                'payload': {'status': 'success', 'message': 'Done'}
            }
        return {'status': 200, 'payload': {'info': 'Use POST to execute'}}
```

**Important:** Do NOT use `MConfigHandler` or `admin_external` - these return 405 errors for POST requests.

#### restmap.conf Configuration

```ini
[script:my_endpoint]
match = /my_app/endpoint
script = my_handler.py
scripttype = persist                    # Required for PersistentServerConnectionApplication
handler = my_handler.MyHandler          # Class reference
requireAuthentication = true
output_modes = json
passPayload = true
passHttpHeaders = true
passHttpCookies = true
python.version = python3
```

#### web.conf - Exposing Endpoints to Splunk Web

Without `web.conf`, endpoints are only accessible via splunkd (port 8089). To access from dashboards (port 8000):

```ini
[expose:my_endpoint]
pattern = my_app/endpoint
methods = GET, POST
```

### SimpleXML Dashboard JavaScript

**Splunk strips `<script>` tags from SimpleXML HTML panels.** You must use external JavaScript files.

1. Create file in `appserver/static/`:
   ```javascript
   // appserver/static/my_dashboard.js
   require([
       'jquery',
       'splunkjs/mvc',
       'splunkjs/mvc/simplexml/ready!'
   ], function($, mvc) {
       'use strict';

       // Access dashboard tokens
       var tokens = mvc.Components.get("default");
       var myValue = tokens.get('my_token');

       // Event handlers (use delegated events)
       $(document).on('click', '#my-button', function() {
           // Handle click
       });
   });
   ```

2. Reference in dashboard XML:
   ```xml
   <dashboard version="1.1" theme="dark" script="my_dashboard.js">
   ```

#### AJAX Calls to REST Endpoints

```javascript
// Build URL that works from Splunk Web
var url = Splunk.util.make_url('/splunkd/__raw/services/my_app/endpoint');

$.ajax({
    url: url,
    method: 'POST',
    data: {
        param1: 'value1',
        output_mode: 'json'
    },
    timeout: 120000,
    success: function(response) {
        var payload = response.payload || response;
        console.log('Success:', payload);
    },
    error: function(xhr, status, error) {
        console.log('Error:', xhr.responseText);
    }
});
```

### Making Splunk REST API Calls from Handlers

```python
import splunk.rest as rest

# GET request
response, content = rest.simpleRequest(
    "/services/data/indexes/my_index",
    sessionKey=session_key,
    method='GET',
    getargs={'output_mode': 'json'}
)

# POST request
response, content = rest.simpleRequest(
    "/services/data/indexes",
    sessionKey=session_key,
    method='POST',
    postargs={
        'name': 'new_index',
        'maxDataSize': 'auto_high_volume'
    }
)

if response.status == 200:
    data = json.loads(content)
```

### Running External Commands from Handlers

For long-running operations (like log generation), spawn a subprocess:

```python
import subprocess
import os

app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
script_path = os.path.join(app_root, 'bin', 'main_generate.py')

cmd = ['python3', script_path, '--all', '--days=14']

result = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=600,
    cwd=os.path.dirname(script_path)
)
```

### Common Issues and Solutions

| Problem | Cause | Solution |
|---------|-------|----------|
| 405 Method Not Allowed | Using `MConfigHandler` | Use `PersistentServerConnectionApplication` with `scripttype = persist` |
| 401 CSRF Validation Failed | Missing CSRF token | Splunk handles this automatically when using `Splunk.util.make_url()` |
| JavaScript not running | `<script>` tags stripped | Use external JS file with `script="file.js"` attribute |
| Endpoint not accessible from dashboard | Missing `web.conf` | Add `[expose:...]` stanza to web.conf |
| Buttons don't respond | Inline onclick stripped | Use `$(document).on('click', '#id', fn)` |

### App Reload After Changes

After modifying REST handlers or configuration:

```bash
# Restart Splunk (full reload)
$SPLUNK_HOME/bin/splunk restart

# Or bump to reload app (faster, but not always sufficient for REST changes)
$SPLUNK_HOME/bin/splunk _internal call /services/apps/local/TA-FAKE-TSHRT/_reload
```

**Note:** Changes to `restmap.conf` or Python handlers usually require a full restart.

---

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
       output_file: str = None,
       quiet: bool = False,
   ) -> int:  # Returns event count
   ```
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

## Development Notes

- All generators are self-contained Python files with no external dependencies
- The Meraki generator is the largest and most complex (~126K lines)
- Output goes to `bin/output/` organized by category (network/, cloud/, windows/, etc.)
- Default timeline: 14 days starting 2026-01-01
- Splunk index: `splunk_demo`
- All scenario events queryable via `demo_id` field in Splunk

## Future Enhancements

Planned generators:
- Palo Alto firewall
- CrowdStrike EDR
- Okta authentication
- Kubernetes logs
