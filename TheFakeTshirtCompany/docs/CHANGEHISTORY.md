# CHANGEHISTORY.md — Change History for TA-FAKE-TSHRT

This file documents all project changes with date/time, affected files, and description.

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
