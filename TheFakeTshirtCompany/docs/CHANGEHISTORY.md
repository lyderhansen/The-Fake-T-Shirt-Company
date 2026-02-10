# CHANGEHISTORY.md — Change History for TA-FAKE-TSHRT

This file documents all project changes with date/time, affected files, and description.

---

## 2026-02-11 ~10:00 UTC — Fix Sankey/LinkGraph _raw bug + redesign Attack Journey link graph

### Bug Fix: `_raw` field in makeresults causes mvexpand failure

Both `ds_attack_flow_sankey` and `ds_attack_linkgraph` used `_raw` as the field name in `| makeresults | eval _raw="..." | makemv | mvexpand` patterns. Splunk treats `_raw` as a special internal field, causing `mvexpand` to return 1 collapsed row instead of separate rows.

**Root cause:** `_raw` is Splunk's raw event data field. Using it in `makeresults` → `makemv` → `mvexpand` does not properly expand into multiple rows.

**Fix:** Replaced all `_raw` with `data` in both data sources across both dashboard files:
- `eval _raw="..."` → `eval data="..."`
- `makemv delim="|" _raw` → `makemv delim="|" data`
- `mvexpand _raw` → `mvexpand data`
- `rex field=_raw` → `rex field=data`

**Files:** `scenario_exfil.xml`, `scenario_exfil_absolute.xml` (4 queries fixed total)

### Link Graph Redesign: Full Attack Journey Narrative

Redesigned the link graph (`ds_attack_linkgraph`) from a sourcetype-centric mapping to a full attack journey narrative. The graph now tells the complete 14-day APT story as a connected chain:

- **32 connected steps** tracing the entire kill chain
- **Nodes chain together:** Threat Actor → FW-EDGE-01 → SOC Visibility → INC → P1 Incident → response
- **Key hubs:** `185.220.101.42 (Threat Actor)`, `jessica.brown (IT Admin)`, `alex.miller (Finance BOS)`, `P1 Security Incident`
- **Includes:** Recon (port scans), phishing, credential harvest, email forwarding, lateral movement (ATL→BOS), cloud enumeration, persistence (IAM backdoor, app consent), exfil (SharePoint, rclone, curl, S3), cleanup, and full incident response chain

**Files:** `scenario_exfil.xml`, `scenario_exfil_absolute.xml`

---

## 2026-02-11 ~07:00 UTC — Fix CDATA Unicode error + rebuild absolute exfil dashboard

### CDATA Unicode Fix (scenario_exfil.xml)

Fixed "CData section not finished" XML parse error caused by non-ASCII Unicode characters inside the `<![CDATA[ ... ]]>` block.

**Root cause:** Splunk's XML parser for Dashboard Studio v2 cannot handle non-ASCII characters (emojis, em-dashes, arrows, middle dots) inside CDATA sections. The dashboard JSON contained Unicode characters from markdown narratives.

**Characters replaced (all instances):**
- `→` (U+2192) replaced with `->`
- `—` (U+2014) replaced with `--`
- `·` (U+00B7) replaced with `|`
- Emojis (skull, magnifier, fish hook, lock, checkmark, chart, shield, warning) replaced with ASCII labels like `[RECON]`, `[PHISH]`, `[LATERAL]`, `[LOCK]`, `[OK]`, `[+]`, `[MITRE]`, `[!]`
- `&` in `[ATT&CK]` replaced with `[MITRE]` (ampersand is XML-special)
- `<` in `<->` replaced with `[LATERAL]` (angle bracket is XML-special)

**Validation:** Python script confirmed zero non-ASCII characters remaining. JSON parsed successfully with 23 dataSources, 33 visualizations, all present in layout.structure.

### Absolute Dashboard Rebuild (scenario_exfil_absolute.xml)

Rebuilt the absolute layout variant from scratch with the same ASCII-safe content as the fixed grid version:

- Canvas: 1920 x 6600px, `auto-scale`, dark background `#0B0C10`
- Uses `layoutDefinitions` + `tabs` wrapper pattern (matching `boston_-_floor_plan.xml`)
- 7 `splunk.rectangle` background panels with phase-specific tinted colors
- 40 total visualizations (7 backgrounds + 33 content)
- Same 23 data sources and SPL queries as grid version
- Includes all 3 new viz types: 2 Sankey diagrams + 1 Link Graph
- All ASCII, validated with zero non-ASCII characters

### Knowledge Files Updated

Added Unicode/CDATA rule to project knowledge:
- `MEMORY.md` — Added rule under "Splunk Dashboard Studio Rules"
- `~/.claude/skills/splunk-dashboard-studio/SKILL.md` (global) — Added best practice #17
- `.claude/skills/splunk-dashboard-studio/SKILL.md` (project) — Added best practice #17
- `docs/dashboard_design_language.md` — Added to Section 8 checklist and Section 2 layout rules

**Affected files:**
- `default/data/ui/views/scenario_exfil.xml` — All Unicode replaced with ASCII equivalents
- `default/data/ui/views/scenario_exfil_absolute.xml` — Complete rebuild with ASCII-safe content

---

## 2026-02-11 ~05:00 UTC — Restyle Exfil dashboard ("hacker" look) + add Meraki CIM field extractions

### Dashboard Restyle (scenario_exfil.xml)

Redesigned the Scenario Exfil dashboard with a dark "hacker" aesthetic and replaced many tables with richer visualizations:

**Visual changes:**
- All markdown panels: dark surface background (`#13141A`) with colored font per phase (yellow/red/blue/purple/green)
- KPI single values: dark tinted backgrounds (`#1A1015` red, `#1A1520` purple, `#101A1F` blue, `#1A1A10` yellow)
- All charts: dark surface backgrounds instead of transparent
- Header markdown: bullet-point format instead of broken pipe tables

**New visualizations (replacing tables):**
- `splunk.sankey` — **Attack Flow Sankey**: Static makeresults showing Threat Actor → Phishing → Lateral Movement → Exfil → Data Exfiltrated
- `splunk.sankey` — **Network Cross-Source Sankey** (Phase 3): Live ASA firewall data with regex IP extraction, mapped to subnet labels (Boston/Atlanta/Austin/DMZ/External/Threat Actor)
- `splunk.linkgraph` — **Attack Kill Chain**: 5-column link graph showing Tactic → Actor → Action → Target → Evidence Source across all 14 attack steps

**Viz count:** 34 visualizations (was 30): 2 Sankey + 1 Link Graph + 5 charts + 10 tables + 10 markdown + 4 KPIs + 2 headers

**Affected files:**
- `default/data/ui/views/scenario_exfil.xml` — Complete restyle with hacker dark theme + 3 new viz types

### Meraki CIM Field Extractions

Added CIM-compatible field extractions to all 7 Meraki sourcetypes, modeled after the official `Splunk_TA_cisco_meraki` add-on:

**props.conf changes (7 sourcetypes):**
- Added `KV_MODE = JSON` to all Meraki stanzas (was missing)
- Added `FIELDALIAS-meraki_event_type = type AS meraki_event_type` to all stanzas
- `FAKE:meraki:securityappliances` — Full CIM extractions: action, app, dest, dest_ip, dest_port, dvc, protocol, severity, signature, signature_id, src, src_ip, src_mac, src_port, status, transport, url, user + 3 LOOKUP-transforms
- `FAKE:meraki:accesspoints` — CIM: app, description, dest, dvc, severity, src, src_ip, src_mac, ssid, status, type, user + 3 LOOKUP-transforms
- `FAKE:meraki:switches` — CIM: action, dest, dvc, object_attrs, object_category, object_id, result, src, src_mac, status + 3 LOOKUP-transforms
- `FAKE:meraki:cameras` — CIM: action, change_type, dest, dvc, object, object_attrs, object_category, src, status + 1 LOOKUP-transform
- `FAKE:meraki:sensors` — CIM: action, dest, dvc, object, object_attrs, object_category, src, status
- `FAKE:meraki:accesspoints:health` — CIM: dvc, dest, src, status
- `FAKE:meraki:switches:health` — CIM: dvc, dest, src, status

**transforms.conf changes:**
- Added 11 lookup definitions matching the official TA naming convention:
  - `cisco_meraki_accesspoints_action_lookup`
  - `cisco_meraki_accesspoints_change_type_object_object_category_result_lookup`
  - `cisco_meraki_accesspoints_object_attrs_lookup`
  - `cisco_meraki_cameras_lookup`
  - `cisco_meraki_securityappliances_action_lookup`
  - `cisco_meraki_securityappliances_change_type_result_lookup`
  - `cisco_meraki_securityappliances_object_object_category_lookup`
  - `cisco_meraki_switches_action_lookup`
  - `cisco_meraki_switches_change_type_object_lookup`
  - `cisco_meraki_switches_result_lookup`
  - `cisco_meraki_organizationsecurity_lookup`

All 11 CSV lookup files were already present in `lookups/` from a previous import.

**Affected files:**
- `default/props.conf` — Added CIM extractions to 7 Meraki sourcetype stanzas
- `default/transforms.conf` — Added 11 Meraki lookup definitions

---

## 2026-02-11 ~01:00 UTC — Add absolute layout variant of Scenario Exfil dashboard

Created `scenario_exfil_absolute.xml` as an absolute layout variant using Dashboard Studio v2 `layoutDefinitions` + tabs pattern (matching `boston_-_floor_plan.xml`). Fixed original `scenario_exfil.xml` to use grid layout (the only layout type that works without tabs).

**Root cause of CDATA error:** Splunk Dashboard Studio v2 does not support `"type": "absolute"` directly in the top-level `layout` object. Absolute layout requires `layoutDefinitions` with `tabs`. The grid variant uses `"type": "grid"` (width 1200, no options block).

**Absolute variant features (scenario_exfil_absolute.xml):**
- Canvas: 1920 x 5500px, `auto-scale`, dark background `#0B0C10`
- 7 `splunk.rectangle` background panels with phase-specific tinted colors
- 37 total visualizations (30 content + 7 backgrounds)
- Single tab "Attack Story" wrapping the absolute layout

**Grid variant (scenario_exfil.xml):**
- Standard grid layout (width 1200, no options block)
- 30 visualizations (no rectangles - grid doesn't support overlapping)
- Same 21 data sources and SPL queries

**Affected files:**
- `default/data/ui/views/scenario_exfil.xml` — Converted from broken absolute to working grid layout
- `default/data/ui/views/scenario_exfil_absolute.xml` — NEW absolute layout variant

---

## 2026-02-10 ~22:30 UTC — Replace Scenario Exfil dashboard with comprehensive APT walkthrough

Replaced the existing `scenario_exfil.xml` grid-layout dashboard with a comprehensive Dashboard Studio v2 dashboard (1920x5500px, vertical scroll).

**Dashboard features:**
- **21 data sources** with verified SPL queries using keyword search `demo_id exfil`
- **37 visualizations** including markdown narratives, KPI cards, area/column charts, tables, and background rectangles
- **5 attack phases** with MITRE ATT&CK technique mapping (15 techniques from T1595 through T1070)
- **Incident Response section** showing ServiceNow INC/CHG records and Entra ID remediation actions
- **Cross-source correlation matrix** (14 days × 12 source categories)
- **Identified gaps section** documenting 6 logical improvements needed in generators
- **MITRE ATT&CK summary table** with static makeresults mapping all 15 techniques

**Phase structure:**
1. Reconnaissance (Days 1-4): ASA port scan analysis with column chart and timeline
2. Initial Access (Day 5): Phishing email evidence and O365 activity tables
3. Lateral Movement (Days 6-8): Meraki IDS events and Entra ID risk detections
4. Persistence (Days 9-11): AWS IAM backdoor and Entra ID app consent tables
5. Exfiltration (Days 12-14): M365 downloads, AWS S3 ops, Sysmon/WinEventLog process evidence, risk detections

**Data verified:** ~3,820 events across 28 sourcetypes, Jan 1-14 2026

**Affected files:**
- `default/data/ui/views/scenario_exfil.xml` — Complete rewrite (779 lines, absolute layout)

**Key design decisions:**
- Keyword search `demo_id exfil` instead of `demo_id=exfil` (field value syntax returned 0 results for some sourcetypes)
- Phase-specific time ranges in queries (e.g., `earliest="01/01/2026:00:00:00" latest="01/05/2026:00:00:00"`) to scope data per section
- Background rectangles with phase-specific accent colors for visual separation

---

## 2026-02-10 ~20:30 UTC — SAP Stock & Sales SPL queries

Added 12 SPL queries to `docs/splunk_queries.md` across 3 new sections:

- **SAP Stock & Inventory (7 queries):** Net stock flow per product, daily movement trend, top 10 outbound products, receipt vs issue balance, stockout risk (lowest net stock), movement type distribution per week, variance/shrinkage events
- **SAP Sales & Revenue (4 queries):** Daily sales orders with revenue, order lifecycle pipeline (VA01→VL01N→VF01), top users by invoiced revenue, web orders vs SAP sales correlation
- **Retail Orders (1 query):** Order status funnel (created→delivered, payment_declined, cancelled)

All queries leverage the newly extracted SAP fields (`mvt_type`, `material_id`, `material_name`, `qty`, `amount`, `tcode`).

**Affected files:**
- `docs/splunk_queries.md` — Added 3 sections with 12 queries

**Verification:** All queries tested against live Splunk data (40,760 SAP events, 319K retail order events) — **PASS**

---

## 2026-02-10 ~19:45 UTC — SAP details sub-field extraction + demo_id fix

Added search-time extraction of 17 structured fields from the SAP `details` field, and fixed two issues with the Step 1 config.

**Fixes to Step 1:**
- Removed `demo_id` from `extract_sap_auditlog_fields` REPORT (was search-time, should only be index-time)
- Added missing `TRANSFORMS-demo_id = extract_demo_id_indexed` to `[FAKE:sap:auditlog]` (every other sourcetype had this)

**Bug fix:** Initial implementation used `SOURCE_KEY = details` which doesn't work — Splunk REPORT transforms can't chain off other REPORT-extracted fields. Removed all `SOURCE_KEY` lines so regex runs against `_raw` (default).

**Affected files:**

### `default/transforms.conf`
- **Fixed `[extract_sap_auditlog_fields]`:** Removed `demo_id::$9` from FORMAT and `(?:\|demo_id=(\S+))?` from REGEX
- **Added 9 detail extraction stanzas** (all search-time, regex against `_raw`):

| Stanza | Fields extracted | Matches |
|--------|-----------------|---------|
| `extract_sap_inventory` | mvt_type, material_id, material_name, qty, storage_loc | MIGO events (~10K) |
| `extract_sap_sales_order` | customer_id, item_count, order_total | VA01 events |
| `extract_sap_amount` | amount | FB01, F-28, VF01, ME21N, MM02 |
| `extract_sap_price_change` | old_price, new_price, material_id, material_name | MM02 events |
| `extract_sap_purchase_order` | vendor_name, vendor_category | ME21N events |
| `extract_sap_session` | sap_client | LOGIN/LOGOUT events |
| `extract_sap_terminal` | terminal | LOGIN events |
| `extract_sap_session_duration` | session_duration | LOGOUT events |
| `extract_sap_login_failure` | login_failure_reason | Failed LOGIN events |

### `default/props.conf`
- **Added** `TRANSFORMS-demo_id = extract_demo_id_indexed` (index-time, was missing)
- **Added** `REPORT-sap_details` with all 9 detail extraction stanzas (search-time)

**Verification (inline rex against 40,760 events):**
- Inventory: mvt_type=101/301/501/261, material_id, material_name, qty, storage_loc — **PASS**
- Sales: customer_id=CUST-00001..00026, item_count, order_total — **PASS**
- Amount: extracted across 6 tcodes (FB01, F-28, VF01, ME21N, MM02, VA01) — **PASS**
- PO: vendor_name + vendor_category (5 vendors) — **PASS**
- Session: sap_client=100, terminal=T*, session_duration, login_failure_reason — **PASS**

---

## 2026-02-10 ~19:00 UTC — Fix SAP audit log field extraction

SAP pipe-delimited fields (`user`, `tcode`, `status`, `dialog_type`, `description`, `document_number`, `details`) were not extracted in Splunk. Only EVAL/FIELDALIAS fields worked (`app`, `vendor`, `src`).

**Root cause:** `props.conf` used `DELIMS` and `FIELDS` directives which are not valid Splunk `props.conf` attributes — silently ignored.

**Affected files:**

### `default/transforms.conf`
- **Added `[extract_sap_auditlog_fields]`:** REGEX-based extraction for 9 pipe-delimited fields + optional `demo_id`
- Extracted field named `sap_host` (not `host`) to avoid collision with Splunk metadata `host`

### `default/props.conf`
- **Removed** invalid `DELIMS = "|"` and `FIELDS = ...` lines from `[FAKE:sap:auditlog]`
- **Added** `REPORT-sap_fields = extract_sap_auditlog_fields`
- Existing FIELDALIAS/EVAL lines unchanged (`host AS src` references metadata host)

**Extracted fields:**

| Field | Example |
|-------|---------|
| `sap_host` | SAP-PROD-01 |
| `dialog_type` | DIA, BTC, RFC |
| `user` | scott.morgan |
| `tcode` | VA01, MIGO, LOGIN, LOGOUT |
| `status` | S, E |
| `description` | Create Sales Order, User Login |
| `document_number` | SO-2026-04302 (or empty) |
| `details` | Client 100, session duration 361 min |
| `demo_id` | exfil (optional, scenario only) |

**Verification (inline rex against 40,760 existing events):**
- All 9 fields extract correctly — **PASS**
- Empty `document_number` handled (LOGIN/LOGOUT events) — **PASS**
- Special characters in `details` (commas, quotes) handled — **PASS**

**Note:** Requires Splunk restart or app reload for props.conf/transforms.conf changes to take effect.

---

## 2026-02-10 ~17:30 UTC — Windows Defender baseline events, LogName regex fix, timestamp parsing fixes

Four related fixes improving WinEventLog realism, source routing accuracy, and timestamp parsing across 7 sourcetypes.

**Affected files:**

### `bin/generators/generate_wineventlog.py` — Defender baseline events

Previously only 1 Defender event existed (EventCode=1116 from ransomware scenario). Added 4 baseline event types to simulate routine Windows Defender activity across all Windows servers:

| EventCode | Description | Frequency |
|-----------|-------------|-----------|
| 1000 | Scan started | 1/day/server at 02:00-03:00 AM |
| 1001 | Scan completed | 5-15 min after scan start |
| 2000 | Definitions updated | 2-3×/day/server (hours 6, 12, 18) |
| 5007 | Configuration changed | 1× on patch day (day 7) |

- **Added `event_defender()` template:** Generates `LogName=Microsoft-Windows-Windows Defender/Operational` events with proper `SourceName`, `EventType`, `RecordNumber`
- **Added `generate_baseline_defender_events()`:** Called in main hourly loop, appends to `security_events` list
- **Volume:** ~640 events over 14 days (~45/day across 10 Windows servers)

### `default/transforms.conf` — LogName regex fix

```ini
# BEFORE:
REGEX = LogName=(\S+)

# AFTER:
REGEX = LogName=(.+)
```

`\S+` stopped at the space in `Microsoft-Windows-Windows Defender/Operational`, capturing only `Microsoft-Windows-Windows` → wrong `source` field in Splunk. Changed to `.+` to capture until end-of-line.

### `default/props.conf` — ServiceBus timestamp fix (2 issues)

**Issue 1 — Missing space in TIME_PREFIX:**
```ini
# BEFORE:
TIME_PREFIX = \"enqueuedTimeUtc\":\"

# AFTER:
TIME_PREFIX = \"enqueuedTimeUtc\": \"
```
The generator produces `"enqueuedTimeUtc": "2026-..."` (with space after colon) but TIME_PREFIX had no space, so Splunk never found the timestamp anchor → all events indexed at ingestion time.

**Issue 2 — Invalid `%3N` format:**
```ini
# BEFORE:
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3NZ

# AFTER:
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%fZ
```
`%3N` is not a valid Splunk strptime directive. `%f` is correct for fractional seconds (microseconds).

### `default/props.conf` — `%3N` → `%f` across 6 sourcetypes

The same invalid `%3N` was found in 5 additional sourcetypes beyond ServiceBus:

| Sourcetype | TIME_FORMAT fixed |
|------------|-------------------|
| `FAKE:azure:servicebus` | `%Y-%m-%dT%H:%M:%S.%fZ` |
| `FAKE:cisco:asa` | `%b %d %Y %H:%M:%S.%f` |
| `FAKE:cisco:webex:events` | `%Y-%m-%dT%H:%M:%S.%fZ` |
| `FAKE:cisco:webex:meetings:history:meetingAttendeeReport` | `%m/%d/%Y %H:%M:%S.%f` |
| `FAKE:cisco:webex:meetings:history:meetingUsageReport` | `%m/%d/%Y %H:%M:%S.%f` |
| `FAKE:cisco:webex:meetings:history:meetingReport` | `%m/%d/%Y %H:%M:%S.%f` |

**Verification (2-day test, wineventlog):**
- 92 Defender events generated (20 scan start/complete + 52 def updates + 20 other) — **PASS**
- EventCode distribution: 1000×10, 1001×10, 2000×52, 5007×10, 1116×10 — **PASS**
- LogName regex `(.+)` captures full `Microsoft-Windows-Windows Defender/Operational` — **PASS**

**Note:** Requires Splunk restart for props.conf/transforms.conf changes to take effect. Previously ingested data needs re-indexing for correct timestamp parsing and source routing.

---

## 2026-02-10 ~15:25 UTC — Auto-move: generate to output/tmp/ then move to output/

Always generate logs to `output/tmp/` (staging), then atomically move completed files to `output/` for Splunk ingestion. Prevents Splunk from ingesting partial files during generation.

**New CLI behavior:**

| Flag | Behavior |
|------|----------|
| *(default)* | Generate to `output/tmp/` → move to `output/` |
| `--test` | Generate to `output/tmp/` only (no move) |
| ~~`--no-test`~~ | **Removed** |

**Affected files:**

### `bin/shared/config.py`
- **Added `move_output_to_production()`:** Moves all known generator output files from `output/tmp/` to `output/` using `shutil.move()` (atomic via `os.rename()` on same filesystem). Cleans up empty staging subdirectories. Returns result dict with moved/skipped/errors.

### `bin/main_generate.py`
- **Removed `--no-test` flag**, changed `--test` default from `True` to `False`
- **Always generates to `output/tmp/`** regardless of mode
- **Added move step** after successful generation (all generators must pass, skipped if `--test`)
- **Updated banner/summary** to show mode label and final output location
- **Updated help text** to reflect new output modes

### `bin/tui_generate.py`
- **Changed default** from TEST to PROD (`selected=False` for test_mode)
- **Updated status bar:** Shows `tmp/ → output/` for PROD, `output/tmp/ only` for TEST
- **Updated command preview/argv:** Shows `--test` instead of `--no-test`
- **Updated mode label** in generation summary

**Verification:**
- PROD mode: 35,045 ASA events generated → moved 1 file to `output/` — **PASS**
- TEST mode: 35,133 ASA events generated → files stay in `output/tmp/` — **PASS**
- `--show-files` PROD: Shows `output/network/cisco_asa.log` (final destination) — **PASS**
- `--show-files` TEST: Shows `output/tmp/network/cisco_asa.log` — **PASS**
- Staging cleanup: `output/tmp/network/` removed after move — **PASS**

---

## 2026-02-10 ~14:55 UTC — Fix Perfmon SQL Server sourcetype routing

SQL Server Perfmon events from SQL-PROD-01 (`SQLServer:SQL Statistics`, `SQLServer:Buffer Manager`, `SQLServer:Locks`) were stuck at `FAKE:Perfmon:Generic` because the routing regex only matched `(LogicalDisk|Memory|Processor)`. Added per-component sourcetype routing aligned with the official Splunk Add-on for Microsoft SQL Server naming convention.

**Affected files:**

### `default/transforms.conf`
- **Added 3 routing stanzas:** `FAKE_st_perfmon_sqlserver_sql_statistics`, `FAKE_st_perfmon_sqlserver_buffer_manager`, `FAKE_st_perfmon_sqlserver_locks`
- **Added field extraction:** `extract_perfmon_sqlserver_fields` — extracts `sql_component`, `counter`, `instance`, `value`

### `default/props.conf`
- **Updated `[FAKE:Perfmon:Generic]`:** Added 3 SQL Server transforms to `TRANSFORMS-route_sourcetype` chain
- **Added 3 new sourcetype stanzas:**
  - `[FAKE:Perfmon:SQLServer:sql_statistics]` — Batch Requests/sec
  - `[FAKE:Perfmon:SQLServer:buffer_manager]` — Page life expectancy, Buffer cache hit ratio
  - `[FAKE:Perfmon:SQLServer:locks]` — Lock Waits/sec

**New sourcetype mapping:**

| object= | → Sourcetype |
|---------|-------------|
| `SQLServer:SQL Statistics` | `FAKE:Perfmon:SQLServer:sql_statistics` |
| `SQLServer:Buffer Manager` | `FAKE:Perfmon:SQLServer:buffer_manager` |
| `SQLServer:Locks` | `FAKE:Perfmon:SQLServer:locks` |

**Verification (2-day test, perfmon + cpu_runaway):**
- 99,744 events generated — **PASS**
- 2,304 SQL Server events (576 sql_statistics + 1,152 buffer_manager + 576 locks) — **PASS**
- All 3 routing regexes match target events — **PASS**

**Note:** Requires re-index of existing Perfmon data for previously ingested events to route to new sourcetypes.

---

## 2026-02-10 ~13:40 UTC — TUI 3-column layout refactor + show-files path fix

Refactored TUI from 2×2 grid to 3-column top row (`Source Groups | Sources | Scenarios`) with 2-column bottom row (`Configuration | Meraki Health`). Fixed `--show-files` displaying hardcoded `output/` instead of `output/tmp/` in test mode.

**Affected files:**

### TUI (`bin/tui_generate.py`) — Full rewrite
- **3-column top row:** Split `self.sources` into `self.source_groups` (top-left) and `self.source_items` (top-middle), with `self.scenarios` (top-right)
- **5 sections:** `SECTION_GROUPS=0`, `SECTION_SOURCES=1`, `SECTION_SCENARIOS=2`, `SECTION_CONFIG=3`, `SECTION_MERAKI=4`
- **Border drawing:** Character-by-character mid-border construction handles 3→2 column junction transitions (`╩` where top divider ends, `╦` where bottom divider starts, `╬` where both align)
- **Navigation:** Left/Right cycles 3 columns on top row, 2 on bottom row. Tab cycles all 5 sections.
- **Source selection:** `_get_sources_str()` combines selections from both groups and individual items
- **Help text:** Added range hints to config labels — `Perfmon Clients (5-175)`, `Client Interval (5-60)`, `Orders/Day (1-10000)`
- **Removed separator:** No longer needed since groups and individual sources are in separate columns
- **Min terminal width:** Increased from 60 to 70

### CLI (`bin/main_generate.py`) — show-files path fix
- Added `output_label = "output/tmp" if args.test else "output"` after output base determination
- Fixed 4 print statements (2 in parallel block, 2 in sequential block) to use `output_label` instead of hardcoded `output/`
- Verified: `--show-files --test` now correctly shows `output/tmp/network/cisco_asa.log`

**Verification:**
- TUI module compiles: **PASS**
- TUIApp class structure: 5 section constants, `source_groups` + `source_items` lists — **PASS**
- show-files path fix: `output/tmp/` displayed correctly in test mode — **PASS**

---

## 2026-02-10 ~22:00 UTC — Phase 8: Documentation + lookups regeneration

Updated CLAUDE.md and regenerated lookup CSVs to reflect all Phase 1-7 changes.

**Affected files:**

### CLAUDE.md
- Updated project overview: 20 generators (was 18), 19 servers, added SAP/ERP/Sysmon/MSSQL mentions
- Updated repository structure: 20 generators (was 18)
- Updated Available Log Sources table: Added SAP S/4HANA, Sysmon, MSSQL rows; updated count
- Updated Source Groups: Added `erp` group, expanded `windows` group
- Expanded Key Servers section: Full 19-server inventory with IPs, organized by location (14 Boston, 5 Atlanta)
- Added SAP audit log format example
- Added SAP SPL query examples
- Updated Development Notes: Correct index name (`fake_tshrt`), server count, SAP correlation note

### Lookups
- **`lookups/asset_inventory.csv`:** Regenerated — 194 rows (175 users + 19 servers)
- **`lookups/identity_inventory.csv`:** Regenerated — 175 rows
- **`lookups/mac_inventory.csv`:** Regenerated — 194 rows

**Verification (3-day test, all generators, all scenarios):**
- Full run: 842,846 events — **PASS**

---

## 2026-02-10 ~21:00 UTC — Phase 7: Access health checks + ServiceNow lifecycle improvements

Added monitoring health check probes, bot crawler traffic, and expanded HTTP status codes to Access generator. Enhanced ServiceNow incident lifecycle with reopening, priority escalation, and SLA breach detection.

**Affected files:**

### Access (`bin/generators/generate_access.py`)
- **Health check probes (NEW):** MON-ATL-01 (10.20.20.30) pings `/health`, `/health/db`, `/health/cache` every 30 seconds, 24/7. Uses Nagios user agent. ~2,880 events/day. Helps establish monitoring baseline and detect when health checks stop (outage indicator).
- **Bot crawl requests (NEW):** Googlebot (66.249.x.x) crawling `/robots.txt`, `/sitemap.xml`, `/sitemap_products.xml`, `/favicon.ico`, `/.well-known/security.txt`. 2-5 per hour, daytime-weighted. ~60 events/day.
- **New HTTP status codes (NEW):** Added 401 Unauthorized (0.5%), 403 Forbidden (0.5%), 429 Too Many Requests (0.3%) to baseline traffic. Previously only had 200/301/304/404/500. Critical for detecting brute force (401 spikes), misconfigurations (403), and rate limiting (429).
- Updated `get_status_code()` distribution: 200 (94%), 304 (1.8%), 301 (1.4%), 404 (1.2%), 401 (0.5%), 403 (0.5%), 429 (0.3%), 500 (0.3%).

### ServiceNow (`bin/generators/generate_servicenow.py`)
- **Incident reopening (NEW):** ~8% of resolved incidents get reopened by end users. Generates Reopen → Re-resolve → Re-close events with `reopen_count=1` field. Realistic lifecycle: customer reports issue not fixed, tech re-investigates, re-resolves.
- **Priority escalation (NEW):** ~10% of P3+ incidents get escalated mid-lifecycle (e.g., P3→P2, P4→P3). Generates escalation event with `escalated_from`/`escalated_to` fields and reason (e.g., "Business impact increased", "SLA at risk").
- **SLA breach detection (NEW):** Compares actual resolution time against priority-based SLA targets. Adds `sla_breached="true"` field to Resolved events when SLA is exceeded. SLA targets: P1=4h, P2=8h, P3=24h, P4=72h, P5=168h.

**Verification (3-day test, all generators, all scenarios):**
- Full run: 844,157 events — **PASS**
- Access: 17,078 events (1-day spot check). Health checks: 8,640 (3-day). Bot crawl paths: 257. HTTP 401: 175, 403: 210, 429: 98.
- ServiceNow: 321 events (3-day). Reopened incidents: 12 (~8%). Priority escalations: 3 (~10% of P3+). SLA breached: present on qualifying resolved events.

---

## 2026-02-10 ~19:30 UTC — Phase 6: SAP ERP generator (NEW)

New generator producing SAP S/4HANA audit log events, correlated with existing order/product data.

**New files:**

### SAP Generator (`bin/generators/generate_sap.py`) — NEW
- **Sourcetype:** `sap:auditlog` (pipe-delimited, matches PowerConnect for SAP format)
- **Format:** `timestamp|host|dialog_type|user|tcode|status|description|document_number|details`
- **Event categories:**
  - **Transaction execution** (~80/hr peak): VA01/VA02/VA03 (Sales), VL01N (Delivery), VF01 (Billing), MIGO (Goods Movement), FB01 (GL Posting), F-28 (Payment), MM01/MM02 (Material Master), FK01 (Vendor), VD01/VD02 (Customer), ME21N (Purchase Order), SM37/STMS/SU01/RZ20 (Basis)
  - **User activity** (~30/hr peak): Login/logout, failed login (wrong password, user locked, user doesn't exist), password change, authorization check failures (S_TCODE, F_BKPF_BUK, M_BEST_WRK, etc.)
  - **Inventory movements** (~40/hr peak): Goods Receipt (101), Goods Issue (201/261/601), Stock Transfer (301), Receipt Without PO (501). ~1% variance warnings.
  - **Financial postings** (~15/hr peak): Invoice, incoming payment, GL journal entry, cost center allocation, vendor payment. Weekday-only.
  - **Batch jobs:** Nightly MRP run (2 AM), daily reports (5 AM), posting period close (day 0), weekly inventory recount (Sunday 4 AM).
  - **System events:** Transport imports, parameter changes. 1-2/day on weekdays.
- **SAP user mapping:** Company employees mapped by department — Finance→FI/CO, Sales→SD, Operations→MM/WM, Executive→Reporting, IT→BASIS. Plus service accounts (sap.batch, sap.rfc, sap.idoc).
- **Order correlation:** Reads `order_registry.json` and creates VA01 (Sales Order) events correlated with customer IDs and cart totals.
- **Material master:** All 72 products from `products.py` mapped as SAP material numbers (M-0001 through M-0072).
- **~2% transaction failure rate** (authorization check failures, document locks, number range exhaustion).
- **Business-hours weighted:** Full volume patterns with weekend reduction (~25% of weekday).

**Modified files:**

### Config (`bin/shared/config.py`)
- Added `erp` output directory to `OUTPUT_DIRS` and `set_output_base()`
- Added `sap` entry to `GENERATOR_OUTPUT_FILES`

### Main orchestrator (`bin/main_generate.py`)
- Imported `generate_sap_logs` from new generator
- Added `sap` to `GENERATORS` registry
- Added `erp` source group (containing `sap`)
- Added `sap` to `GENERATOR_DEPENDENCIES` (depends on `access` for order_registry.json)

### Splunk configuration
- **`default/props.conf`:** Added `[FAKE:sap:auditlog]` stanza with pipe-delimited field extraction (DELIMS/FIELDS), timestamp parsing, CIM field aliases (vendor_product, vendor, product, app, src, action, signature)
- **`default/inputs.conf`:** Added monitor input for `erp/sap_audit.log` with host=SAP-PROD-01

**Verification (3-day test, all generators, all scenarios):**
- Full run: 833,565 events — **PASS**
- SAP: 3,275 events. T-code distribution: MIGO 810, LOGIN 321, LOGOUT 202, FB01 194, VF01 162, F-28 150. Status: 3,095 success, 164 error, 15 warning. Batch jobs: 10 (MRP, reports, period close). VA01 orders correlated: 77 (from 949 in registry). 6 vendors, 72 materials.

---

## 2026-02-10 ~18:00 UTC — Phase 5: Entra ID service principals + Perfmon server-role counters

Added non-interactive service principal sign-ins to Entra ID and expanded Perfmon with SQL Server counters, memory pressure indicators, and disk queue depth.

**Affected files:**

### Entra ID (`bin/generators/generate_entraid.py`)
- **Service Principal Sign-ins (NEW):** ~15 events/hour (constant — machines don't follow business hours). 5 service principals: SAP S/4HANA Connector, Veeam Backup Agent, Splunk Cloud Forwarder, GitHub Actions CI/CD, Nagios Monitoring Agent. Category: `ServicePrincipalSignInLogs`. ~83% success rate; failures: 7000215 (invalid client secret), 7000222 (expired certificate).
- **New error codes:** 50053 (Account locked), 50058 (Silent sign-in interrupted), 70011 (Invalid scope). Added to existing interactive sign-in error code pool.

### Perfmon (`bin/generators/generate_perfmon.py`)
- **SQL Server counters (NEW, SQL-PROD-01 only):** `Batch Requests/sec` (SQLServer:SQL Statistics, 50-500 scaling with activity), `Page life expectancy` (SQLServer:Buffer Manager, 2000-5000 normal, 100-500 during cpu_runaway), `Buffer cache hit ratio` (97-99.9% normal, 85-95% during scenario), `Lock Waits/sec` (SQLServer:Locks, 0-3 normal, 10-50 during scenario).
- **Pages/sec (NEW, all servers):** Memory counter tracking paging activity. 0-20 normal, >100 during memory pressure scenarios.
- **Current Disk Queue Length (NEW, all servers):** LogicalDisk counter for I/O bottleneck detection. 0-2 normal, 5-20 during disk_filling/scenario conditions.
- **New server coverage:** WSUS-BOS-01, RADIUS-BOS-01, PRINT-BOS-01, APP-BOS-01, DC-ATL-01, BACKUP-ATL-01 added to SERVER_RAM_MB and SERVER_DISK_GB mappings.

**Verification (3-day test, all generators, all scenarios):**
- Full run: 832,188 events — **PASS**
- Entra ID: 1,874 events. Service principal sign-ins: 1,073. SP errors: 303 (162 expired cert, 141 invalid secret). New error codes: 50053=5, 50058=6, 70011=3.
- Perfmon: 149,616 events. SQL Server counters: 864 each (Batch Requests/sec, Page life expectancy, Buffer cache hit ratio, Lock Waits/sec). Pages/sec: 8,640 events (all servers). Current Disk Queue Length: 8,640 events (all servers).

---

## 2026-02-10 ~16:30 UTC — Phase 4: ASA traffic realism + Exchange failures

Improved ASA perimeter firewall realism and added email delivery failures with authentication results.

**Affected files:**

### ASA (`bin/generators/generate_asa.py`)
- **Hub-spoke site-to-site traffic:** BOS is now the hub (~70% of inter-site traffic involves BOS). Previously, all three sites had equal traffic distribution. ATL and AUS are spokes — most branch traffic goes to BOS for DC/file/app access; spoke-to-spoke (ATL↔AUS) is only ~30%.
- **DC-specific traffic (NEW):** Kerberos (88), LDAP (389/636), DNS (53), SMB (445), RPC (135), Global Catalog (3268). Workstations and servers constantly talk to DCs for auth and group policy. ~10% of baseline events. Weighted distribution: Kerberos 30%, LDAP 25%, DNS 15%, SMB 10%, LDAPS 10%, RPC 5%, GC 5%.
- **Internal ACL deny events (NEW):** Policy violations from workstations trying direct SQL access, unauthorized RDP, IoT scanning SMB, guest network reaching internal servers, SSH to DMZ from non-jumpboxes. ~1% of baseline events. Uses internal ACL names from company.py.
- **New server traffic (NEW):** WSUS (8530/8531), PROXY (3128/8080), SAP (3200/3300/8000/50013), SAP HANA (30015/30013), Bastion SSH (22). ~4% of baseline events. Bastion traffic uses "management" zone naming.
- **ICMP health checks (NEW):** MON-ATL-01 pings critical infrastructure (DCs, SQL, WEB, SAP, BACKUP). ~3% of baseline events. Uses ASA-6-302020 (ICMP built).
- Updated event distribution: reduced Web from 30→25%, Outbound TCP from 20→16%, DNS from 15→12%, Site-to-site from 12→9% to accommodate new event types while maintaining total event counts.

### Exchange (`bin/generators/generate_exchange.py`)
- **Failed outbound delivery (NEW):** ~3% of total events are bounce/NDR/rejected messages. Failure reasons include: recipient not found (550 5.1.1), access denied (550 5.7.1), mailbox full (452 4.2.2), domain not found (550 5.4.1), connection refused (421 4.7.0). Events include `FailureDetail` and `FailureType` (NDR/Rejected/Deferred) fields.
- **SPF/DKIM/DMARC authentication results (NEW):** All inbound email now includes `SPFResult`, `DKIMResult`, `DMARCResult`, and `CompAuth` fields. 85% all-pass, 15% mixed results (SoftFail, Neutral, BestGuessPass). Spam messages have failing auth results (Fail/None).
- Updated event distribution: Internal 34%, Inbound 19%, Outbound 14%, DL 8%, System notifications 7%, Calendar 6%, Responses 5%, Failed outbound 3%, OOO 2%, Spam 2%.

**Verification (3-day test, all generators, all scenarios):**
- Full run: 808,959 events — **PASS**
- ASA: 100,406 events. DC traffic: 9,658. Internal ACL denies: 558. New server traffic: 5,137. ICMP: 1,639. Management zone (Bastion): 942. Hub-spoke: BOS involved in 70.3% of site-to-site traffic.
- Exchange: 8,124 events. Failed outbound: 243 (3.0%). SPF/DKIM/DMARC fields on 1,738 inbound events. Auth pass rate: 84%. Failure types: NDR 98, Deferred 96, Rejected 49.

---

## 2026-02-10 ~14:00 UTC — Phase 3: Endpoint detection — Sysmon, WinEventLog, Linux auth.log

Expanded endpoint detection coverage: 4 new Sysmon EIDs, 4 new WinEventLog EIDs, and a completely new Linux auth.log output.

**Affected files:**

### Sysmon (`bin/generators/generate_sysmon.py`)
- **EID 5 (Process Terminated):** Completes process lifecycle — every process that starts (EID 1) should eventually terminate. ~12% of server/workstation events.
- **EID 7 (Image Loaded / DLL):** DLL loading baseline. Generates legitimate system DLL loads (ntdll.dll, kernel32.dll, advapi32.dll, etc.) for both servers and workstations. ~15% of events. Includes Signed/Signature/SignatureStatus fields for DLL sideloading detection baseline.
- **EID 8 (CreateRemoteThread):** Process injection detection baseline. Very rare (~1% server only, 0% workstation). Only legitimate source: Windows Defender (MsMpEng.exe) scanning svchost/lsass. Any other source is suspicious.
- **EID 10 (ProcessAccess):** LSASS credential dumping baseline. ~5% server, ~3% workstation. Server-side lsass access only from svchost.exe or wininit.exe with QUERY_LIMITED_INFORMATION (0x1000). Any PROCESS_ALL_ACCESS to lsass is suspicious.
- Added 3 new servers to SYSMON_SERVERS: WSUS-BOS-01, RADIUS-BOS-01, PRINT-BOS-01 with role-specific processes (wsusutil.exe, ias.exe, spoolsv.exe).
- Updated EID weight distributions to include new EIDs while maintaining realistic proportions.

### WinEventLog (`bin/generators/generate_wineventlog.py`)
- **EID 4740 (Account Lockout):** ~1-3/day during business hours. Users forget passwords after weekends/vacations. Key for password spray detection.
- **EID 4768 (Kerberos TGT Request):** ~10/peak hour (proportional to logon activity). 98% success, 2% failure (0x18=pre-auth failed, 0x17=expired, 0x6=unknown). Key for Kerberoasting/AS-REP roasting baseline.
- **EID 4776 (NTLM Credential Validation):** ~3/peak hour (lower than Kerberos in modern AD). 97% success, 3% failure (bad password, unknown user). Key for NTLM relay/pass-the-hash detection.
- **EID 4698 (Scheduled Task Created):** ~2-5/day. Higher during maintenance windows (3-4 AM). System account for automated tasks, admin accounts during business hours. Key for persistence detection.
- Added all 4 new EIDs to `format_scenario_event()` routing for scenario support.
- Added scheduled task templates (Windows Update, Defrag, DiskCleanup, Backup, Monitoring).

### Linux auth.log (`bin/generators/generate_linux.py`)
- **New output:** `linux/auth.log` — entirely new auth log generation alongside existing metrics.
- **SSH Accepted publickey:** Admin/service users (root, svc.deploy, svc.monitor, ansible) from management network (10.10.10.x). Includes key type (RSA/ED25519/ECDSA) and fingerprint.
- **SSH Failed password:** Internet scanner noise on exposed hosts (WEB-01, WEB-02, BASTION-BOS-01). Uses 6 scanner IPs and 10 common scanner usernames. Heavier at night (2-6 attempts) vs daytime (0-3).
- **sudo commands:** 15 realistic admin commands (systemctl, journalctl, netstat, iptables, docker, etc.).
- **cron jobs:** Deterministic per-host schedules (logrotate, backup, health checks, etc.). 9 hosts with 2-5 cron jobs each.
- **systemd service events:** Per-host service definitions (nginx, php-fpm, nagios, docker, squid, sshd, SAP services). Rare restarts/reloads (~8%/hour).
- **PAM session open/close:** Correlates with SSH accepted events.

### Configuration files
- `bin/shared/config.py` — Added `linux/auth.log` to `GENERATOR_OUTPUT_FILES["linux"]`.
- `default/inputs.conf` — Added `[monitor://...linux/auth.log]` with sourcetype `FAKE:linux:auth`.
- `default/props.conf` — Added `[FAKE:linux:auth]` stanza with timestamp parsing (syslog format), host extraction, and field extractions (process, pid, user, src, src_port, action).
- `default/transforms.conf` — Added `[set_host_from_auth_log]` transform for syslog-format host extraction.

**Verification (3-day test, all generators, all scenarios):**
- Total: 810,512 events across all generators (pass)
- Sysmon EIDs: 1=1,635 | 3=1,344 | 5=879 | 7=1,061 | 8=29 | 10=290 | 11=699 | 13=439 | 22=634
- WinEventLog new EIDs: 4768=202 | 4776=86 | 4740=2 | 4698=3
- Linux auth.log: 2,809 events (SSH accepted=162, SSH failed=463, sudo=144, cron=1,728, systemd=47)

---

## 2026-02-10 ~22:00 UTC — Phase 2: Failed operations across cloud/retail generators

The single biggest realism gap — 0% failure rate everywhere — is now fixed. All cloud and retail generators now produce realistic baseline error events.

**Affected files:**
- `bin/generators/generate_aws.py` — Added ~4% baseline failures (AccessDenied, NoSuchKey, NoSuchBucket, Throttling, UnauthorizedAccess). Added 5 new API actions: DeleteObject, AssumeRole, ConsoleLogin (with 5% login failures + MFA field), CreateAccessKey, DeleteAccessKey. Updated event distribution to include new actions.
- `bin/generators/generate_gcp.py` — Added ~3% baseline failures (PERMISSION_DENIED, NOT_FOUND, RESOURCE_EXHAUSTED, UNAUTHENTICATED). Failed events set severity=ERROR and authorizationInfo.granted=false. Added compute start/stop and IAM SA key create events. Updated event distribution.
- `bin/generators/generate_office_audit.py` — Added ~3% baseline failures for file operations (FileNotFound, AccessDenied, FileLocked, QuotaExceeded, VirusDetected, BlockedByPolicy). Added SharingInvitationCreated event type (~3% of SharePoint events) with external guest recipients.
- `bin/generators/generate_orders.py` — Added ~7% order failures: payment_declined (~5%), fraud_detected (~1%), address_invalid (~1%). Failed orders produce fewer events (stop at failure point) and generate $0 revenue. Each failure includes failureType and failureReason fields.
- `bin/generators/generate_servicebus.py` — Added ~3% transient failures (retried messages with deliveryCount > 1 and retryReason field). Added ~0.5% dead-letter queue events with deadLetterReason and deadLetterErrorDescription fields. DLQ queue names use `/$deadletterqueue` suffix.

**New fields added:**
- AWS: `errorCode`, `errorMessage`, `additionalEventData.MFAUsed`, `responseElements.ConsoleLogin`
- GCP: `severity: "ERROR"`, `protoPayload.status.code: 7/5/8/16`
- M365: `ResultStatusDetail` (reason for failure)
- Orders: `failureType`, `failureReason`, `payment.declineReason`
- ServiceBus: `deadLetterReason`, `deadLetterErrorDescription`, `properties.retryReason`

**Verification:**
- Full 3-day test: 806,384 events, all generators pass
- AWS: 4% errors (13/299 events)
- GCP: 4% errors (10/245 events)
- M365: 1% failures (62/3,471 events) + 23 sharing invites
- Orders: 5.5% failed (3,856/69,727 orders) — 4% payment declined, ~0.8% fraud, ~0.8% address invalid
- ServiceBus: ~3% retried, ~0.5% dead-lettered

---

## 2026-02-10 ~20:00 UTC — Phase 1: Infrastructure expansion — 7 new servers, DNS config, SAP in app catalog

Added 7 new servers to company.py, internal DNS configuration, replaced NetSuite with SAP S/4HANA in Entra app catalog, regenerated all lookup CSVs.

**Affected files:**
- `bin/shared/company.py` — Added INTERNAL_DNS_SERVERS (DC-based per location). Added 7 servers to _SERVER_DATA: WSUS-BOS-01, RADIUS-BOS-01, PROXY-BOS-01, PRINT-BOS-01, SAP-PROD-01, SAP-DB-01, BASTION-BOS-01. Replaced NetSuite with SAP S/4HANA in ENTRA_APP_CATALOG. Renamed SG-App-NetSuite-Users → SG-App-SAP-Users.
- `lookups/asset_inventory.csv` — Regenerated: 194 rows (175 users + 19 servers)
- `lookups/identity_inventory.csv` — Regenerated: 175 rows
- `lookups/mac_inventory.csv` — Regenerated: 194 rows

**Verification:**
- 19 servers total (10 Windows, 9 Linux)
- Full 3-day generation test: 807,196 events, no errors

---

## 2026-02-11 ~02:30 UTC — Add SourceMAC and DestinationMAC to Sysmon Event ID 3 (NetworkConnect)

Real Sysmon Event ID 3 (NetworkConnect) includes `SourceMAC` and `DestMAC` fields — our generator was missing them. Now that persistent MAC addresses exist for all users and servers, this gap is closed.

**Affected files:**
- `bin/generators/generate_sysmon.py` — Added `get_mac_for_ip, get_random_mac` imports; added `SourceMAC` and `DestinationMAC` fields to `sysmon_eid3()`. Known user/server IPs get their persistent MAC via `get_mac_for_ip()`; external IPs get a random MAC via `get_random_mac()`.
- `bin/shared/company.py` — Added `_IP_TO_SERVER` lookup dict, `_build_server_ip_lookup()`, and `get_server_by_ip()` helper. Updated `get_mac_for_ip()` to resolve both user IPs AND server IPs (previously only resolved user IPs).

**What does NOT change:**
- WinEventLog — Real Windows Security events (4624, 4625, etc.) don't contain MAC fields. Correct behavior.
- Perfmon — Real Perfmon counters reference adapter names, not MACs. Correct behavior.
- Other Sysmon EIDs — Only EID 3 (NetworkConnect) has MAC fields in real Sysmon.

**Verification:**
- Sysmon generation: SourceMAC and DestinationMAC fields present in EID 3 output
- Known user IPs resolve to persistent MACs (e.g., alex.miller 10.10.30.55 → persistent MAC)
- Server IPs resolve to persistent MACs (e.g., DC-BOS-01 10.10.20.10 → `DC:71:96:A5:D5:71`)
- External IPs get random MACs (different each generation)

---

## 2026-02-11 ~01:00 UTC — Identity management infrastructure: App catalog, group definitions, enriched audit events, Splunk ES lookups, Employee Changes dashboard

Complete identity data model overhaul to enable realistic Entra ID audit event analysis and Splunk ES asset/identity correlation.

**What changed:**

1. **Company data model** (`bin/shared/company.py`):
   - Replaced `ENTRA_APPS` (7 flat entries) with `ENTRA_APP_CATALOG` (16 structured apps: M365 E3, Splunk, CrowdStrike, Workday, NetSuite, Salesforce, Jira, GitHub, Confluence, Cisco Secure Access, etc.) — each with app ID, category, license type, and department-based access rules
   - Replaced `ENTRA_GROUPS` (14 flat names) with `ENTRA_GROUP_DEFINITIONS` (22 groups with membership rules: department, location, VPN, VIP, app-specific)
   - Replaced `ENTRA_ROLES` (6 flat names) with `ENTRA_ROLE_DEFINITIONS` (10 roles) + `ENTRA_ROLE_ASSIGNMENTS` (explicit user→role mappings)
   - Added `get_user_groups(user)`, `get_user_app_licenses(user)`, `get_user_roles(username)` helpers
   - Added `generate_asset_lookup_csv()` — Splunk ES-compatible asset inventory (187 rows)
   - Added `generate_identity_lookup_csv()` — Splunk ES-compatible identity inventory (175 rows)
   - All backward-compatible: `ENTRA_APPS`, `ENTRA_GROUPS`, `ENTRA_ROLES` aliases still work

2. **Enriched Entra ID audit events** (`bin/generators/generate_entraid.py`):
   - Added 4 new audit functions: `audit_add_member_to_group()`, `audit_remove_member_from_group()`, `audit_update_user()`, `audit_assign_license()` — all with real group/app/role/attribute names in `modifiedProperties`
   - Expanded `ADMIN_ACCOUNTS` from 3 to 7 (added mike.johnson, jessica.brown, sarah.wilson, ad.sync) with `_resolve_admin()` for runtime USERS lookup
   - Rewrote `generate_audit_day()` with proper frequency distribution: 2-4 group changes/day, 1-3 attribute updates/day, license every 3-5 days, role changes every 5-7 days
   - Legacy `audit_user_management()` preserved as wrapper delegating to enriched functions

3. **Splunk ES lookups**:
   - `lookups/asset_inventory.csv` — 187 rows (175 workstations + 12 servers) with ES headers: ip, mac, nt_host, dns, owner, priority, lat, long, city, country, bunit, category, is_expected, should_timesync, should_update, requires_av
   - `lookups/identity_inventory.csv` — 175 rows with ES headers: identity, nick, first, last, email, managedBy, priority, bunit, category (normal/privileged), watchlist (alex.miller=true)
   - `default/transforms.conf` — Added `[asset_inventory]` and `[identity_inventory]` lookup stanzas

4. **Employee Changes dashboard** (`default/data/ui/views/discovery_-_employee_changes.xml`):
   - Dashboard Studio v2, grid layout, dark theme
   - Row 1: 4 single values (Total, Group, Role, License changes)
   - Row 2: Stacked area chart (changes over time by activity type)
   - Row 3: Recent changes table (time, activity, admin, target user, details)
   - Row 4: Top changed users (bar) + Changes by admin (pie)
   - Row 5: Group membership changes detail table

**Verification:**
- All 19 generators: 3,578,611 events (38.6s) — PASS
- Entra ID audit: 341 events (14 days) with enriched details: 33 group adds, 9 group removes, 28 user updates, 3 license assignments, 1 role change, 23 password resets, 162 SSPR flows + exfil scenario events
- 20 distinct group names seen in events (SG-All-Employees through SG-VPN-Users)
- Asset lookup CSV: 187 rows (175 workstations + 12 servers), correct ES headers
- Identity lookup CSV: 175 rows, alex.miller on watchlist, 3 privileged users identified

---

## 2026-02-10 ~20:00 UTC — Add persistent MAC addresses for network client visibility

Every employee workstation and server now has a deterministic, persistent MAC address (UUID5-based, matching the pattern used for Entra ID Object IDs and AWS Principal IDs). This enables Splunk analysts to track client devices across the network stack by MAC ↔ IP ↔ hostname ↔ username correlation.

**Affected files:**
- `bin/shared/company.py` — Added `_generate_mac_address()` function (UUID5 + SHA-256 OUI selection), `mac_address` property on both User and Server dataclasses, `get_user_by_ip()` / `get_mac_for_ip()` IP→user lookup helpers, `generate_mac_lookup_csv()` for Splunk enrichment. Workstation MACs use Dell/Lenovo/HP OUIs; server MACs use Intel OUIs.
- `bin/generators/generate_meraki.py` — Updated MR wireless events: known users on 802.1X / corporate SSID get their persistent MAC+IP instead of random. Updated MX firewall, URL, and security events: IP-based MAC lookup resolves known users. Added imports for `get_user_by_ip`, `get_mac_for_ip`.
- `bin/scenarios/security/ransomware_attempt.py` — Replaced 4 hardcoded `"AA:BB:CC:DD:EE:20"` MACs with Brooklyn White's persistent MAC (`self.target_mac` resolved from USERS in `__init__`). All IDS alerts, client isolation, and disassociation events now use her real device MAC.
- `bin/generators/generate_webex_api.py` — Fixed Device MAC field in calling CDR: replaced random hex string with `caller_user.mac_address.replace(":", "")` for deterministic MACs in Webex API no-colon format.
- `lookups/mac_inventory.csv` — New file: 187 entries (175 user workstations + 12 servers) mapping mac_address → ip_address, hostname, username, display_name, location, department, device_type.
- `default/transforms.conf` — Added `[mac_inventory]` lookup definition for Splunk enrichment.

**Verification:**
- All 19 generators: 3,580,854 events (39.7s)
- 175 unique user MACs, 12 unique server MACs — zero collisions ✓
- Alex Miller (10.10.30.55): 23 MR wireless events with persistent MAC `00:50:B6:2B:7C:3E` ✓
- Brooklyn White ransomware: 4 MX events + 1 MR disassociation all with `34:17:EB:CC:53:83` ✓
- MR wireless MAC distribution: 53.3% known-user persistent MACs, 46.7% random (guest/IoT) ✓
- Webex API: deterministic MACs in no-colon format, cross-referenced to user lookup ✓

---

## 2026-02-10 ~17:00 UTC — Fix 13 logical issues across all 7 scenarios

Thorough review of all scenarios identified 13 logical issues — wrong ASA log directions, ServiceNow timeline misalignments, inconsistent resolution states, missing cross-generator integration, dead code bugs, and inaccurate message IDs.

**Affected files:**
- `bin/scenarios/security/ransomware_attempt.py` — **#1 CRITICAL:** Fixed ASA C2 connection direction (was `for outside:C2 to inside:target`, now `for inside:target to outside:C2`)
- `bin/scenarios/network/firewall_misconfig.py` — **#2 CRITICAL:** Fixed ASA deny `dst outside:` → `dst dmz:` for DMZ web server. **#7 HIGH:** Added `access_should_error()` method for HTTP error injection during outage. **#8 MEDIUM:** Fixed logout message from `%ASA-6-605004` (login denied) to `%ASA-6-315011` (SSH disconnect)
- `bin/generators/generate_servicenow.py` — **#3 CRITICAL:** Fixed disk_filling incident days from [7,10,12] to [2,3,4] matching actual scenario window (days 0–4). **#6 HIGH:** Fixed cpu_runaway change day 10→11 matching actual fix at day 12 10:30. **#11 MEDIUM:** Fixed memory_leak incident days to stay within scenario window (5–8). **#12 MINOR:** Added hour 12 to firewall_misconfig incident hours for resolution tracking
- `bin/scenarios/security/exfil.py` — **#4 HIGH:** Fixed lateral movement from "Built inbound" to "Built outbound" for internal→internal ASA traffic. **#9 MEDIUM:** Fixed dead code `has_exfil_events()` day==5 → day==8 for persistence phase
- `bin/scenarios/ops/memory_leak.py` — **#5 HIGH:** Fixed `is_resolved()` to return True at hour 14 (same hour as OOM+restart), aligning with `get_memory_pct()` returning 52%
- `bin/scenarios/registry.py` — **#7 HIGH:** Added "access" to firewall_misconfig sources. **#10 MEDIUM:** Removed "perfmon" from memory_leak sources (WEB-01 is Linux, not Windows)
- `bin/generators/generate_access.py` — **#7 HIGH:** Integrated FirewallMisconfigScenario — imports, initializes, checks `access_should_error()` in hourly loop. Produces 403/504 errors with `demo_id=firewall_misconfig` during outage (4,065 events)
- `bin/scenarios/network/certificate_expiry.py` — **#13 MINOR:** Added comment explaining 6-hour detection delay (no cert monitoring in place)

**Verification:**
- All 19 generators: 3,577,242 events (38.3s)
- Ransomware ASA: `for inside:10.30.30.20/... to outside:194.26.29.42/443` ✓
- Firewall deny: `dst dmz:203.0.113.10/...` ✓
- Firewall access: 4,065 events with `demo_id=firewall_misconfig` ✓
- Disk filling SN: Jan 3-5 (days 2-4) ✓
- CPU runaway SN change: Jan 12 (day 11) ✓
- SSH disconnect: `%ASA-6-315011` ✓

---

## 2026-02-10 ~14:00 UTC — Convert Sysmon from XML to KV format

**Affected files:**
- `bin/generators/generate_sysmon.py` — Full conversion from XML to KV (WinEventLog) format. Replaced XML helper functions (`_xml_system_block`, `_xml_data`, `_wrap_event`, `_xml_escape`) with KV helpers (`_kv_header`, `_wrap_kv_event`). Converted all 5 event builders (EID 1, 3, 11, 13, 22) to produce multi-line KV output with Message body. Updated timestamp extraction for sorting. Removed unused XML constants and `_record_id_counter`.
- `default/props.conf` — Replaced `[FAKE:XmlWinEventLog:Sysmon]` stanza with `[FAKE:WinEventLog:Sysmon]`: changed from `KV_MODE=xml` to `KV_MODE=AUTO`, updated LINE_BREAKER/TIME_FORMAT/TIME_PREFIX to match KV timestamp format, switched host extraction from `set_host_from_sysmon` (XML) to `set_host_from_wineventlog` (KV), added `REPORT-sysmon_fields` for 12 Message body field extractions.
- `default/transforms.conf` — Removed `[set_host_from_sysmon]` (XML-based, no longer needed). Added 12 new transforms for Sysmon Message field extraction: `extract_sysmon_image`, `extract_sysmon_commandline`, `extract_sysmon_user`, `extract_sysmon_parentimage`, `extract_sysmon_parentcommandline`, `extract_sysmon_targetfilename`, `extract_sysmon_targetobject`, `extract_sysmon_queryname`, `extract_sysmon_sourceip`, `extract_sysmon_destinationip`, `extract_sysmon_destinationport`, `extract_sysmon_protocol`.
- `default/inputs.conf` — Changed sourcetype from `FAKE:XmlWinEventLog:Sysmon` to `FAKE:WinEventLog:Sysmon`
- `default/data/ui/views/source_sysmon.xml` — Updated all queries: sourcetype change, `Event.System.EventID` → `EventCode`, removed complex `mvfind()`/`mvindex()` extraction for Image/CommandLine (now direct fields), updated markdown header format from "XML" to "KV pairs"
- `default/README.md` — Updated sourcetype reference and format
- `bin/README.md` — Updated sourcetype reference and format
- Various docs/ files — Updated sourcetype references in documentation

**Description:**
Converted the Sysmon generator from single-line XML format (`<Event xmlns=...>`) to multi-line KV format (same as WinEventLog generator). The new format uses `MM/DD/YYYY HH:MM:SS AM/PM` timestamp + KV header (`LogName=`, `EventCode=`, `ComputerName=`) + `Message=` body with `FieldName: value` pairs. This makes all fields directly searchable — `EventCode=1`, `Image=*`, `CommandLine=*` — instead of requiring nested XML paths (`Event.System.EventID`) and multivalue index lookups (`mvfind()`). Consistent with WinEventLog format.

**Verification:**
- Generator: 31,568 events, 14 days, all scenarios (exfil=40, ransomware=12)
- Format check: 0 XML events (`<Event xmlns` = 0), 31,568 `EventCode=` lines
- Output: KV format with correct timestamps, headers, and Message body fields

---

## 2026-02-10 ~11:00 UTC — Fix MSSQL severity extraction for non-Logon errors

**Affected files:**
- `default/transforms.conf` — Added `[mssql_error_general]` transform: extracts `error_code`, `severity`, `state` from all MSSQL error events regardless of prefix (Logon, Server, spid*)
- `default/props.conf` — Added `REPORT-fields_for_errors = mssql_error_general` to `[FAKE:mssql:errorlog]`

**Description:**
The existing `[logon_events]` transform only extracted `severity` from error events prefixed with `Logon` (50 events, all severity=14, from exfil scenario failed logins). The 48 error events from cpu_runaway scenario (prefixed with `Server` or `spid*`) had `Error:`, `Severity:`, and `State:` in _raw but were not being extracted. Added a general-purpose `[mssql_error_general]` transform that matches all three prefix types. After fix, `severity=*` returns 98 events with values 10, 13, 14, 16, 17.

**Also investigated:** ASA query `src=10.30.30.20 dest=10.30.30.*` returning 0 results. This is architecturally correct — the ASA (FW-EDGE-01) is a perimeter firewall that doesn't see internal Austin LAN traffic. Brooklyn White's lateral movement (ransomware scenario) occurs on the local Meraki MX and shows in `FAKE:meraki:mx` IDS alerts and `FAKE:XmlWinEventLog` 4625 failed logins.

**Verification:** Regex tested with `| rex` on live data — matches all 98 error events. Requires Splunk reload/restart for search-time extraction to take effect on existing data.

---

## 2026-02-09 ~21:00 UTC — New skill: sourcetype-fields reference

**Affected files:**
- `.claude/skills/sourcetype-fields/SKILL.md` — NEW: Complete field reference for all 40+ FAKE: sourcetypes in the fake_tshrt index

**Description:**
Created a comprehensive sourcetype field reference skill by querying Splunk `fieldsummary` for all 40 sourcetypes. Documents field names, types, distinct counts, and sample values organized by category (Network, Cloud, Collaboration, Email, Windows, Linux, Web/Retail, ITSM, Database). Includes CIM cross-reference table and identifies 4 sourcetypes with no data (FAKE:online:order, FAKE:azure:servicebus, FAKE:servicenow:cmdb, FAKE:cisco:webex:events). Enables Claude to write accurate SPL queries and build dashboards without re-querying Splunk each time.

---

## 2026-02-09 ~19:00 UTC — Navigation bar cleanup

**Affected files:**
- `default/data/ui/nav/default.xml` — Removed 9 placeholder views that don't exist as XML files, removed Admin menu

**Description:**
Updated navigation bar to only reference existing dashboard XML files. Removed: discovery_environmental, discovery_meeting_rooms, discovery_webex_quality, discovery_sdwan, discovery_wireless, discovery_floor_atlanta, discovery_floor_austin, admin_generator, admin_data. Final nav has 31 views across Discovery (3+1 floor plan), Scenarios (7), and Sources (19) menus.

---

## 2026-02-10 ~10:00 UTC — Fix field name mismatches in dashboard SPL queries

**Affected files (13 dashboards):**
- `default/data/ui/views/source_cisco_asa.xml` — `dst` → `dest` (2 queries), `action=Deny OR action=denied` → `action=blocked` (4 queries)
- `default/data/ui/views/discovery_netops.xml` — `dst` → `dest`, `action=Deny` → `action=blocked`, `client_mac` → `clientMac`
- `default/data/ui/views/scenario_exfil.xml` — `dst` → `dest` (2 occurrences)
- `default/data/ui/views/scenario_ransomware.xml` — `dst` → `dest` (4 occurrences in 2 queries)
- `default/data/ui/views/scenario_firewall_misconfig.xml` — `dst` → `dest`, `action=Deny` → `action=blocked` (2 queries)
- `default/data/ui/views/source_meraki.xml` — `client_mac` → `clientMac`
- `default/data/ui/views/source_linux.xml` — `UsePct` → `UsedPct`, `Filesystem` → `mount`, `free` → `memFreeMB`, `rkBps` → `rkB_s`, `RXbytes` → `rxKB_s`
- `default/data/ui/views/scenario_disk_filling.xml` — `UsePct` → `UsedPct`, `MountedOn` → `mount`, `pctIowait` → `pctIOWait` (4 queries)
- `default/data/ui/views/source_webex_ta.xml` — Sourcetype `meetingSummary` → `meetingusagehistory`, `ConfName` → `confName`, `UserName` → `hostEmail`, `AttendeeCount` → `peakAttendee`, markdown updated
- `default/data/ui/views/source_webex_api.xml` — 3 non-existent sourcetypes replaced (`group:memberships` → `security:audit:events`, `compliance:events` → `meeting:qualities`, `rooms:read` → `call:detailed_history`), markdown updated
- `default/data/ui/views/source_gcp_audit.xml` — `principalEmail` → `protoPayload.authenticationInfo.principalEmail`, `methodName` → `protoPayload.methodName`, `resourceName` → `protoPayload.resourceName`
- `default/data/ui/views/source_sysmon.xml` — `EventID` → `Event.System.EventID`, sample events use `mvfind()` to extract Image/CommandLine from multivalue `Event.EventData.Data`
- `default/data/ui/views/source_mssql.xml` — `severity` → `event_source` (already extracted by props.conf), `message` field now used directly (was missing), pie chart renamed to "Events by Source", Error Count KPI searches for `"Error:"` in _raw, added `exfil` to scenarios in header

**Description:**
Audited all SPL queries in 31 dashboards against the live sourcetype-fields reference (created via `fieldsummary`). Found ~45 field name mismatches across 13 dashboards where queries referenced non-existent fields (returning 0 results). Root causes: assumed field names that don't match generator output, CamelCase vs snake_case differences (`clientMac` vs `client_mac`), nested JSON fields not available as top-level (`protoPayload.methodName` vs `methodName`), XML event structure (`Event.System.EventID` vs `EventID`), incorrect sourcetype names, and missing field extractions for unstructured logs (MSSQL).

**Verification:** All corrected queries confirmed returning >0 results via `splunk_run_query`. Grep scan confirmed no remaining instances of broken field names (`dst`, `UsePct`, `client_mac`, `meetingSummary`, `action=Deny`, `pctIowait`).

---

## 2026-02-09 ~21:00 UTC — New skill: sourcetype-fields reference

**Affected files:**
- `.claude/skills/sourcetype-fields/SKILL.md` — NEW: Complete field reference for all 40+ FAKE: sourcetypes in the fake_tshrt index

**Description:**
Created a comprehensive sourcetype field reference skill by querying Splunk `fieldsummary` for all 40 sourcetypes. Documents field names, types, distinct counts, and sample values organized by category (Network, Cloud, Collaboration, Email, Windows, Linux, Web/Retail, ITSM, Database). Includes CIM cross-reference table and identifies 4 sourcetypes with no data (FAKE:online:order, FAKE:azure:servicebus, FAKE:servicenow:cmdb, FAKE:cisco:webex:events). Enables Claude to write accurate SPL queries and build dashboards without re-querying Splunk each time.

---

## 2026-02-10 ~08:00 UTC — Dashboard build-out: Discovery, Scenario, and Source dashboards

**Affected files:**
- `default/data/ui/views/overview.xml` — Updated 2 scenario queries from `demo_id=*` to `IDX_demo_id=*` for tstats acceleration
- `default/data/ui/views/discovery_soc.xml` — NEW: SOC Overview (10 data sources, 14 visualizations)
- `default/data/ui/views/discovery_itops.xml` — NEW: IT Operations (11 data sources, 12 visualizations)
- `default/data/ui/views/discovery_netops.xml` — NEW: Network Operations (12 data sources, 12 visualizations)
- `default/data/ui/views/scenario_exfil.xml` — NEW: Data Exfiltration scenario (12 data sources, 16 visualizations)
- `default/data/ui/views/scenario_ransomware.xml` — NEW: Ransomware Attempt scenario (9 data sources, 11 visualizations)
- `default/data/ui/views/scenario_memory_leak.xml` — NEW: Memory Leak scenario (10 data sources, 12 visualizations)
- `default/data/ui/views/scenario_cpu_runaway.xml` — NEW: CPU Runaway scenario (11 data sources, 13 visualizations)
- `default/data/ui/views/scenario_disk_filling.xml` — NEW: Disk Filling scenario (10 data sources, 12 visualizations)
- `default/data/ui/views/scenario_firewall_misconfig.xml` — NEW: Firewall Misconfiguration scenario (7 data sources, 9 visualizations)
- `default/data/ui/views/scenario_certificate_expiry.xml` — NEW: Certificate Expiry scenario (8 data sources, 11 visualizations)
- `default/data/ui/views/source_cisco_asa.xml` — NEW: Cisco ASA source dashboard
- `default/data/ui/views/source_meraki.xml` — NEW: Meraki source dashboard
- `default/data/ui/views/source_entraid.xml` — NEW: Entra ID source dashboard
- `default/data/ui/views/source_aws_cloudtrail.xml` — NEW: AWS CloudTrail source dashboard
- `default/data/ui/views/source_exchange.xml` — NEW: Exchange source dashboard
- `default/data/ui/views/source_o365_audit.xml` — NEW: M365 Audit source dashboard
- `default/data/ui/views/source_webex.xml` — NEW: Webex source dashboard
- `default/data/ui/views/source_perfmon.xml` — NEW: Perfmon source dashboard
- `default/data/ui/views/source_wineventlog.xml` — NEW: WinEventLog source dashboard
- `default/data/ui/views/source_linux.xml` — NEW: Linux source dashboard
- `default/data/ui/views/source_access.xml` — NEW: Apache Access source dashboard
- `default/data/ui/views/source_orders.xml` — NEW: Retail Orders source dashboard
- `default/data/ui/views/source_servicebus.xml` — NEW: ServiceBus source dashboard
- `default/data/ui/views/source_servicenow.xml` — NEW: ServiceNow source dashboard
- `default/data/ui/views/source_webex_ta.xml` — NEW: Webex TA source dashboard
- `default/data/ui/views/source_webex_api.xml` — NEW: Webex API source dashboard
- `default/data/ui/views/source_sysmon.xml` — NEW: Sysmon source dashboard
- `default/data/ui/views/source_mssql.xml` — NEW: MSSQL source dashboard
- `default/data/ui/views/source_gcp_audit.xml` — NEW: GCP Audit source dashboard

**Description:** Major dashboard build-out implementing the approved plan. Created 29 new Dashboard Studio v2 dashboards across three categories:

- **3 Discovery dashboards:** SOC Overview (cross-source security correlation), IT Operations (infrastructure health with Perfmon/Linux/ServiceNow), Network Operations (ASA + Meraki device health)
- **7 Scenario dashboards:** Each walks through a specific scenario with header, KPIs, phase timeline, cross-source correlation, and key evidence table. Uses immutable scenario colors (exfil=#DC4E41, ransomware=#F1813F, memory_leak=#F8BE34, cpu_runaway=#FF677B, disk_filling=#7B56DB, firewall_misconfig=#009CEB, certificate_expiry=#00CDAF)
- **19 Source dashboards:** Each covers a specific data source with header, KPIs, event timeline, field breakdowns, and sample events table

All dashboards use grid layout (w=1200), global time range input (Jan 2026 epochs), `tstats` for fast counting where possible, and `demo_id`/`IDX_demo_id` for scenario filtering.

---

## 2026-02-10 ~05:30 UTC — Index demo_id field for tstats acceleration

**Affected files:**
- `default/transforms.conf` — NEW stanza `extract_demo_id_indexed` with `WRITE_META = true` to write `demo_id` to TSIDX at index time. Regex matches both JSON (`"demo_id": "exfil"`) and KV (`demo_id=exfil`) formats.
- `default/props.conf` — Added `TRANSFORMS-demo_id = extract_demo_id_indexed` to all 46 `[FAKE:*]` sourcetype stanzas
- `default/fields.conf` — NEW file declaring `demo_id` as `INDEXED = true`

**Description:** `demo_id` was only available as a search-time field, meaning queries like `| tstats count where index=fake_tshrt demo_id=exfil` would not work. Added index-time field extraction so `demo_id` is written to TSIDX, enabling fast `tstats` queries for scenario filtering across all dashboards. The transform is applied per-sourcetype (not per-source) for maximum reliability.

**Note:** Requires re-indexing existing data for `tstats` to work on historical events. New data indexed after this change will have `demo_id` in TSIDX automatically.

---

## 2026-02-10 ~05:00 UTC — Fix ServiceNow demo_id quoting

**Affected files:**
- `bin/generators/generate_servicenow.py` — `format_kv_line()` now outputs `demo_id=exfil` (unquoted) instead of `demo_id="exfil"` (quoted)

**Description:** The ServiceNow generator's `format_kv_line()` function wraps all string values in double quotes (correct for ServiceNow KV fields like `short_description="Server down"`), but `demo_id` is a Splunk-level tagging field that should be unquoted for consistent extraction across all sourcetypes. All other generators (syslog, JSON, Linux KV) output `demo_id=value` without quotes. Added a special case in `format_kv_line()` to skip quoting for the `demo_id` key.

---

## 2026-02-10 ~04:00 UTC — Fix scenario table row coloring in Overview dashboard

**Affected files:**
- `default/data/ui/views/overview.xml` — Fixed scenario table: `matchValue` → `rangeValue` + `_color_rank`, `columnFormat` → `tableFormat`, removed breaking `rowColors` property
- `docs/dashboard_design_language.md` — Updated section 4.9 pattern to use `tableFormat` + `_color_rank` + `rangeValue`; renamed context variable from `rowColors` to `rowColorConfig` to avoid confusion with the breaking CSS property
- `.claude/skills/splunk-dashboard-studio/SKILL.md` — Updated sections 3.4, 7.3, 9.1: marked `matchValue` as broken, replaced examples with `tableFormat` + `rangeValue` + `_color_rank` pattern, removed invalid `options` block from grid layout skeleton, fixed checklist to exclude `matchValue`

**Description:** The Scenario Summary table in the Overview dashboard threw `e.map is not a function`. Three issues were fixed in sequence:

1. **`matchValue()` is broken** — Replaced with `rangeValue()` using a numeric `_color_rank` field (1-7) computed in SPL
2. **`"rowColors": "#ffffff"` causes JS error** — Removed this property entirely
3. **`columnFormat` only colors one column** — Changed to `tableFormat.rowBackgroundColors` for whole-row coloring
4. **`color_rank` column visible in table** — Renamed to `_color_rank` (underscore prefix auto-hides in Splunk tables)

Proven pattern for table row coloring:
- SPL: `| eval _color_rank=case(field=="val1",1, field=="val2",2, ...)`
- Viz: `"tableFormat": { "rowBackgroundColors": "> table | seriesByName(\"_color_rank\") | rangeValue(config)" }`
- Context: numeric `from`/`to` ranges mapped to colors

---

## 2026-02-10 ~02:00 UTC — Complete dashboard redesign: pilot Overview + design language

**Affected files:**
- `docs/dashboard_design_language.md` — NEW: Complete Dashboard Studio v2 design language specification (color palette, layout rules, naming conventions, 14 copy-paste component patterns, dashboard templates, scenario color mapping, verification checklist)
- `default/data/ui/views/overview.xml` — NEW: Pilot Overview dashboard (Dashboard Studio v2, grid layout, dark theme) with 6 sections: app header, 4 KPI cards, event volume area chart + category donut, scenario summary table with color-coded rows, data source catalog table, quick navigation links
- `default/data/ui/nav/default.xml` — NEW: Category-based navigation structure (Overview, Discovery, Scenarios, Sources, Admin) with Overview as default view
- 38 old dashboard XML files deleted from `default/data/ui/views/` (kept `boston_-_floor_plan.xml`)
- Old `default/data/ui/nav/default.xml` deleted

**Description:** Fresh-start dashboard redesign for Dashboard Studio v2. All 38 old SimpleXML v1.1 dashboards deleted. Created a design language specification defining the complete visual system (dark purple/navy theme, immutable scenario colors, chart series palette, grid layout rules). Built a pilot Overview dashboard to validate the design direction before building the remaining ~39 dashboards across 4 categories (Discovery, Scenario, Source, Admin).

Key design decisions:
- Dark theme (`#0B0C10` canvas) with cyan (`#00D2FF`) and purple (`#7B56DB`) accents
- Grid layout for all dashboards (absolute only for floor plans)
- Immutable scenario colors across all dashboards
- Default time range: Jan 1 -- Feb 1, 2026 (epochs 1767225600-1769904000)
- All SPL queries verified against Splunk (~11.2M events, 40 sourcetypes, 7 scenarios)

**Verification:**
- All 8 data sources return results ✅
- Scenario summary shows all 7 scenarios with correct date ranges ✅
- Event timeline by category: 8 clean series (Network, Windows, Web, Linux, Cloud, Collaboration, Retail, ITSM) ✅
- Category donut: all 8 categories present ✅
- Data source catalog: 40 sourcetypes with host counts ✅

---

## 2026-02-10 ~00:30 UTC — Fix WinEventLog ransomware scenario event format

**Affected files:**
- `bin/scenarios/security/ransomware_attempt.py` — Converted 5 `_winevent_*` methods from XML to KV header format

**Description:** Fixed a bug where ransomware scenario WinEventLog events were generated in raw XML format (`<Event xmlns=...>`) while all baseline events used the KV header format (`MM/DD/YYYY HH:MM:SS AM/PM` + `LogName=` + `EventCode=` + Message body). The `props.conf` LINE_BREAKER for `FAKE:WinEventLog` only matches the KV timestamp pattern, so XML events were never recognized as separate events by Splunk — they were concatenated into the preceding KV event.

Converted methods:
- `_winevent_4688()` — Process creation (Word macro launch)
- `_winevent_4688_dropper()` — Process creation (malware dropper)
- `_winevent_4697()` — Service installed (persistence)
- `_winevent_4625()` — Failed logon (lateral movement)
- `_winevent_1116()` — Windows Defender detection

Added `_winevent_ts()` static helper method for datetime-to-KV-timestamp conversion.

Note: The exfil scenario already used the correct approach (returning dicts formatted by `format_scenario_event()`).

**Verification:**
- `wineventlog` generator: 4,017 events, 7 ransomware events in KV format ✅
- `grep -c '<Event xmlns' wineventlog_security.log` = 0 (no XML events) ✅
- Full run: 19/19 generators OK, 3,579,185 events, 0 failures ✅

---

## 2026-02-09 ~23:30 UTC — Simplified Floor Plan Document

**Affected files:**
- `docs/floor_plan.md` — NEW: Simplified floor plan replacing OFFICE_LAYOUTS.md
- `docs/OFFICE_LAYOUTS.md` → `docs/OFFICE_LAYOUTS_old.md` — Renamed as backup

**Description:** Created a simplified floor plan document (`floor_plan.md`) to replace the complex 937-line `OFFICE_LAYOUTS.md`. Key changes:
- Replaced heavy Unicode box-drawing ASCII art (╔═║) with simple `+--+` grid format
- Translated all content from Norwegian to English (per CLAUDE.md rules)
- Added structured markdown equipment tables under each floor
- Fixed Cortana room placement (ATL Floor 1 → Floor 2, matching company.py)
- Added 4 missing rooms: Mario (BOS F2), Luigi (BOS F3), Kratos (ATL F1), Crash (AUS F1)
- Excluded attack scenario section (physical layout only)
- Reduced from ~937 lines to ~410 lines (~57% reduction)

---

## 2026-02-09 ~22:30 UTC — Ransomware Scenario Dashboard (Dashboard Studio v2)

**Affected files:**
- `default/data/ui/views/scenario_ransomware.xml` — Replaced Simple XML (v1.1) with Dashboard Studio (v2) dashboard

**Description:** Rebuilt the ransomware scenario dashboard from Simple XML to Dashboard Studio format with 3 tabbed views:

- **Incident Overview** — Markdown header with incident summary, 4 KPIs (Total Events, C2 Beacons, Lateral Attempts Blocked, Time to Containment), kill chain timeline table, stacked column chart (5-min intervals by sourcetype), pie chart (event distribution), and Sankey diagram (attack network flow)
- **Attack Analysis** — Exchange phishing email trace, Windows process execution chain (color-coded by phase), C2 callback table (ASA), lateral movement attempts (Event 4625), Meraki IDS/isolation events (color-coded by type)
- **Response & Recovery** — ServiceNow incidents (color-coded by priority), Office 365 file events (color-coded: FileModified=red, FileRestored=green), investigation SPL queries, complete event timeline

Features: 15 data sources, 20 visualizations, tabbed grid layout (1440px width), color-coded table columns via DOS `matchValue()`, `seriesColorsByField` for consistent chart colors, global time range input defaulting to Jan 2026.

---

## 2026-02-09 ~20:00 UTC — Meeting Room Standardization (Video Game Character Names)

**Background:** All 17 meeting rooms across 3 locations had Boston neighborhood names (Cambridge, Faneuil, Back Bay, etc.). Rooms were renamed to single-word video game character names, room count increased from 17 to 21, and floor info added to the device naming standard.

**Device naming standard:** `{TYPE}-{LOC}-{FLOOR}F-{NAME}` (e.g., `WEBEX-BOS-3F-LINK`, `MT-BOS-3F-DOOR-LINK`)

### New Room Inventory (21 rooms)

| Location | Rooms | Names |
|----------|-------|-------|
| Boston (10) | +2 new | Link, Zelda, Samus, Kirby, Yoshi, Sonic, Peach, Toad, **Mario**, **Luigi** |
| Atlanta (7) | +1 new | Cortana, Chief, Ryu, Pikachu, Megaman, Lara, **Kratos** |
| Austin (4) | +1 new | Doom, Fox, Jett, **Crash** |

### Name Mapping (old → new)

| Old Name | New Name | Role Preserved |
|----------|----------|----------------|
| Cambridge | Link | Boardroom, premium, south sun |
| Faneuil | Zelda | Conference, normal |
| Quincy | Samus | Conference, east sun |
| North End | Kirby | Huddle, **problematic** (wifi_congestion) |
| Back Bay | Yoshi | Huddle, after-hours |
| Engineering Lab | Sonic | Lab, premium |
| Harbor | Peach | Visitor |
| Beacon | Toad | Visitor |
| Peachtree | Cortana | Training, **problematic** (echo_issues) |
| Midtown | Chief | Conference, west sun |
| NOC | Ryu | Operations, premium |
| Buckhead | Pikachu | Huddle, after-hours |
| Decatur | Megaman | Huddle |
| Innovation Lab | Lara | Lab |
| Congress | Doom | Conference, southwest sun |
| 6th Street | Fox | Huddle |
| Live Oak | Jett | Demo, premium |

### Files Changed

| File | Change |
|------|--------|
| `bin/shared/company.py` | Replaced MEETING_ROOMS dict: 17→21 rooms, new names, floor-based sensor IDs |
| `bin/generators/generate_webex.py` | Replaced WEBEX_DEVICES dict: 21 entries with floor-based device IDs, updated fallback rooms |
| `bin/shared/meeting_schedule.py` | Updated AFTER_HOURS_CONFIG room names |
| `CLAUDE.md` | Updated device inventory, problem rooms, sunny rooms, after-hours sections |
| `docs/OFFICE_LAYOUTS.md` | Updated floor plan room labels and device references |
| `docs/datasource_docs/webex_devices.md` | Updated device inventory tables and examples |
| `docs/datasource_docs/webex_api.md` | Updated room name in example |
| `docs/datasource_docs/webex_meetings.md` | Updated room device example |
| `docs/datasource_docs/meraki.md` | Updated SPL query room references |

---

## 2026-02-09 ~15:00 UTC — Data Source Field Validation Fixes

**Background:** `data_source_field_validation_fix_list.md` identified 37 field validation findings across 5 generators where synthetic logs deviated from real vendor output. All fixes have been implemented and verified.

**Verification:** 19/19 generators OK, 3,553,531 events, 0 failures. Full run: `--all --scenarios=all --days=14`

### Phase 1: `bin/shared/company.py`

Centralized user identity so all generators use consistent IDs per user.

| Change | Details |
|--------|---------|
| `import hashlib, uuid` | New imports for deterministic ID generation |
| `_ENTRA_NS` namespace | UUID5 namespace for Entra ID objects |
| `_generate_entra_object_id()` | `uuid5(NS, "user:username")` — same UUID per user everywhere |
| `_generate_entra_device_id()` | `uuid5(NS, "device:hostname")` — deterministic device ID |
| `_generate_aws_principal_id()` | `AIDA` + SHA-256 hex — fixed per IAM user |
| `_generate_aws_access_key_id()` | `AKIA` + SHA-256 hex — fixed per IAM user |
| `DEPARTMENT_IDS` | Mapping department → numeric ID |
| `_AWS_USER_AGENT_PROFILES` | 5 user agent profiles per user role |
| User dataclass properties | `entra_object_id`, `entra_device_id`, `aws_principal_id`, `aws_access_key_id`, `aws_user_agent`, `department_id` |
| `KNOWN_MAC_OUIS` | 32 real vendor OUI prefixes (Apple, Dell, Lenovo, Intel, Cisco, HP, Microsoft) |
| `get_random_mac()` | MAC addresses with known vendor prefixes |

### Phase 2: `bin/generators/generate_aws.py`

Full rewrite of AWS CloudTrail generator for realistic IAMUser/AssumedRole split.

| Change | Details |
|--------|---------|
| `AWS_SERVICE_ROLES` dict | AssumedRole service accounts (Lambda, backup, pipeline) with AROA prefix |
| `AWS_HUMAN_USERS` list | IAMUser users from company.py (IT/DevOps staff) |
| `aws_iam_user_event()` | Uses `user.aws_principal_id`, `user.aws_access_key_id`, `user.ip_address`, `user.aws_user_agent` |
| `aws_assumed_role_event()` | AROA prefix, ASIA access key, full `sessionContext` with `sessionIssuer` |
| `readOnly`, `managementEvent` | New fields on all events |
| `resources` array | ARN list on resource-specific events |
| `aws_iam_list_users()` | New event type |
| `aws_sts_get_caller_identity()` | New event type |
| IAMUser:AssumedRole ratio | ~72%:28% (1193:468 in 14-day run) |

### Phase 3: `bin/generators/generate_meraki.py`

Targeted edits for IDS realism and MAC addresses.

| Change | Details |
|--------|---------|
| `IDS_SIGNATURES` | Replaced fake SIDs (45678, 23456...) with realistic Snort SIDs (1:40688:5, 1:49897:1, etc.) |
| `"ports"` field per signature | SSH scan→22, SQL injection→80/443/8080, DNS→53, etc. |
| `generate_ids_alert()` | Uses `signature.get("ports")` for dest port |
| `generate_mac()` | Calls `get_random_mac()` from company.py — known vendor OUIs |

### Phase 4: `bin/generators/generate_entraid.py`

Correlated client profiles, UUID identities, extended MFA.

| Change | Details |
|--------|---------|
| `_CLIENT_PROFILES` | 12 correlated (clientAppUsed, browser, OS, weight) tuples |
| `_pick_client_profile()` | Weighted selection — no iOS+Windows mismatch |
| `get_mfa_details()` | 5 methods: Authenticator (35%), PreviouslySatisfied (20%), Phone (15%), FIDO2 (15%), TOTP (15%) |
| `signin_success()` | `user.entra_object_id`, `user.entra_device_id`, `clientAppUsed`, `browser`, `authenticationRequirement`, `tokenIssuerType`, `riskDetail` |
| `signin_failed()` | Same new fields |
| `signin_lockout()` | Same new fields |
| `user.user_id` → `user.entra_object_id` | Global replace (4 locations) |

### Phase 5: `bin/generators/generate_gcp.py`

New fields and zone variation per resource type.

| Change | Details |
|--------|---------|
| `_RESOURCE_ZONES` dict | compute→`us-central1-a/b/c`, storage→`us-central1`, BQ→`US`, functions→`us-central1` |
| `_GCP_USER_AGENTS` | 5 variants: gcloud CLI, GCP Console, Python SDK, Go SDK, Terraform |
| `gcp_base_event()` rewrite | New `resource_type` parameter, `authorizationInfo`, `status`, `receiveTimestamp`, `severity` |
| All event generators | Pass `resource_type` explicitly, removed manual `event["resource"]["type"]` overrides |
| `from datetime import` | Moved to module level |

### Phase 6: `bin/generators/generate_webex_api.py`

Base64 encoding, correlated profiles, CDR fields.

| Change | Details |
|--------|---------|
| `generate_webex_id()` | Correct `base64.b64encode(f"ciscospark://us/{prefix}/{uuid}")` |
| `WEBEX_ORG_ID` | Correct base64 encoding of `ciscospark://us/ORGANIZATION/{tenant_id}` |
| `_CLIENT_PROFILES` | 6 correlated profiles (clientType+osType+hardwareType+networkType) |
| `_pick_client_profile()` | Weighted selection — 0/3044 mismatches |
| `generate_meeting_quality_record()` | Uses correlated profiles instead of random |
| `"Device MAC"` | Changed from `AA:BB:CC:DD:EE:FF` to `AABBCCDDEEFF` (12 hex no separator) |
| `"Call ID"` | Changed from UUID to SIP format: `SSE<digits>@<IP>` |
| `"Department ID"` | Changed from text to UUID via `uuid5(NAMESPACE_DNS, "dept:<name>")` |
| `"Duration"` | Changed from `str(secs)` to `int(secs)` |
| Grammar fix | "An user" → "A user" |
| `_CALL_CLIENT_TYPES` | New flat list for call history (replaced removed `CLIENT_TYPES`) |

### Files changed

| File | Change type |
|------|-------------|
| `bin/shared/company.py` | New identity generation, MAC OUI, AWS/Entra properties |
| `bin/generators/generate_aws.py` | Full rewrite — IAMUser/AssumedRole split |
| `bin/generators/generate_meraki.py` | IDS SIDs, ports, MAC OUI |
| `bin/generators/generate_entraid.py` | UUID IDs, correlated profiles, MFA, new fields |
| `bin/generators/generate_gcp.py` | Zone variation, new fields, userAgent |
| `bin/generators/generate_webex_api.py` | Base64, correlated profiles, CDR fields |

---

## 2026-02-03 — Meraki Security Events, Weekend Volume, TUI Checkbox

See `docs/changelog_2026-02-03.md` for full details.

- Meraki MX security events (IDS, content filtering, AMP, client isolation)
- MR clientIp field
- Weekend volume factors for e-commerce
- `--show-files` CLI flag
- TUI checkbox improvement
