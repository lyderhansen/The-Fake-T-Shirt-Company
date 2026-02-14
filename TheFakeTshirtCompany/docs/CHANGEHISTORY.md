# CHANGEHISTORY.md -- Change History for TA-FAKE-TSHRT

This file documents all project changes with date/time, affected files, and description.

---

## 2026-02-15 ~04:30 UTC -- Fix addon references in REFERENCES.md

### Fixed

- **`docs/datasource_docs/REFERENCES.md`** -- Corrected three addon references:
  - Webex REST API: Replaced wrong Splunkbase 8365 with correct GitHub repo (`splunk/ta_cisco_webex_add_on_for_splunk`)
  - Catalyst Center: Replaced wrong Splunkbase 7858 with correct 7538 (Cisco Catalyst Add-on for Splunk, covers both switches and Catalyst Center)
  - Cisco Secure Access: Verified already correct (Splunkbase 7569)

---

## 2026-02-15 ~03:30 UTC -- Dynamic customer pool + tshirtcid in SAP

### Fixed

- **`bin/generators/generate_access.py`** -- Customer pool now scales dynamically:
  - Previously hardcoded to 500 customers (CUST-00001 to CUST-00500), causing unrealistic ~408 orders/customer with high-volume configs
  - `get_customer_id()` now takes `pool_total` and `pool_vip` parameters
  - Pool calculated as `max(500, orders_per_day * days // 4)` for ~4 orders/customer average
  - VIP segment = 5% of pool, drives 30% of traffic (Pareto distribution preserved)
  - Examples: default 224/day x 14 days = 784 customers; 5000/day x 31 days = 38,750 customers
  - Pool size printed to stderr during generation for visibility

### Added

- **`bin/generators/generate_sap.py`** -- tshirtcid correlation field:
  - Reads `tshirtcid` (browser cookie UUID) from order_registry for each order
  - Appended to VA01, VL01N, and VF01 event details as `tshirtcid=<uuid>`
  - Enables cross-source correlation: access -> orders -> servicebus -> SAP

- **`default/transforms.conf`** -- `[extract_sap_tshirtcid]`:
  - New REGEX transform: `tshirtcid=([\w-]+)` extracts browser cookie from SAP details field

- **`default/props.conf`** -- `[FAKE:sap:auditlog]`:
  - Added `extract_sap_tshirtcid` to REPORT-sap_details extraction chain

### Verification

- Requires data regeneration (access + orders + servicebus + sap) to reflect new customer pool and tshirtcid
- `customer_lookup.csv` unchanged (500 VIP rows) -- customers above CUST-00500 won't match lookup (by design: VIP enrichment use case)

---

## 2026-02-15 ~02:30 UTC -- props.conf/transforms.conf audit and fixes

### Fixed

- **`default/props.conf`** -- `[FAKE:cisco:webex:events]`:
  - TIME_FORMAT had `.%fZ` (microseconds) but generator produces `%Y-%m-%dT%H:%M:%SZ` (no fractional seconds). Fixed to match actual output.

- **`default/props.conf`** -- `[FAKE:online:order]`:
  - Added CIM field aliases: `orderId` -> `order_id`, `customerId` -> `user`, `status` -> `action`, `channel` -> `dest`
  - Added `EVAL-vendor` and `EVAL-product` fields
  - Wired up previously unused `customer_lookup` transform for customer enrichment (name, email, segment)

### Added

- **`default/transforms.conf`** -- 4 missing GCP CIM Change transforms:
  - `gcp_change_updated_user1_demo` -- extracts user from IAM policy member field
  - `gcp_change_updated_user2_demo` -- extracts user from principalEmail field
  - `gcp_change_updated_value1_demo` -- extracts value from role field
  - `gcp_change_updated_value2_demo` -- extracts value from action field (ADD/REMOVE)
  - These were referenced in props.conf lines 700-701 and 1080-1081 but never defined

### Removed

- **`default/transforms.conf`** -- Removed stale `[host_from_demo]` transform (identical duplicate of `[host_from_demo_field]`, never referenced in props.conf)

---

## 2026-02-15 ~01:30 UTC -- Fix Entra ID props.conf field mappings

### Fixed

- **`default/props.conf`** -- `[FAKE:azure:aad:signin]` stanza:
  - `EVAL-user_id` was mapping to `properties.userPrincipalName` (email) instead of `properties.userId` (UUID). Now correctly maps to the Azure AD object ID.
  - Removed redundant `FIELDALIAS-user_for_signin` (was overridden by `EVAL-user` anyway)
  - Removed redundant `FIELDALIAS-action_for_signin` (was overridden by `EVAL-action` anyway)

### Added

- **`default/props.conf`** -- `[FAKE:azure:aad:riskDetection]` stanza:
  - `EVAL-action = "allowed"` -- CIM IDS/Alert action field
  - `EVAL-result = 'properties.riskState'` -- Maps riskState (atRisk/confirmedSafe/remediated/dismissed)
  - `EVAL-severity` -- Maps riskLevel to CIM severity (high->critical, medium->high, low->medium)
  - `EVAL-user = lower('properties.userPrincipalName')` -- CIM user field (replaces redundant FIELDALIAS)
  - `EVAL-user_id = lower('properties.userId')` -- Azure AD object ID
  - Removed redundant `FIELDALIAS-user_for_risk` (replaced by EVAL-user)

---

## 2026-02-15 ~00:00 UTC -- Fix TUI source counting bug + add file counter to status line

### Fixed

- **`bin/tui_generate.py`** -- Source counting bug when selecting groups:
  - **Bug**: Selecting a group like "network" showed `Sources: 1` instead of `Sources: 4` because `_get_sources_str()` returned the group name as-is and the status line counted comma-separated items
  - **Fix**: New `_expand_selected_sources()` method expands group names via `SOURCE_GROUPS` dict and deduplicates with a set (handles overlapping groups like network+cisco correctly)

### Added

- **`bin/tui_generate.py`** -- File counter in status line:
  - New `_count_output_files()` method counts output files using `GENERATOR_OUTPUT_FILES` from config.py
  - Status line now shows: `Sources: 26 | Files: 59 | Health: ~45,696/day`
  - Examples: network group = 4 sources/12 files, meraki alone = 1 source/7 files
- **Import**: Added `GENERATOR_OUTPUT_FILES` to TUI imports from `shared.config`

---

## 2026-02-14 ~23:15 UTC -- Phase 2 generator audit + TUI default changed to test mode

### Fixed

- **`bin/tui_generate.py`** -- Changed default output mode from PROD to TEST:
  - Line 178: `selected=True` (was `False`) -- TUI now defaults to test mode (output/tmp/) for safety
  - Preview line updated: shows `--no-test` when toggled to prod instead of `--test` when toggled to test

### Audit Results -- Phase 2 Generators (order_registry.json dependents)

All three order-flow generators (orders, servicebus, sap) were audited for volume, format, logic:

| Generator | Orders processed | Events generated | Status |
|-----------|-----------------|-----------------|--------|
| **orders** | 208,041 (all registry) | 1,008,354 (~4.8/order) | OK -- ~7% failure stops lifecycle early |
| **servicebus** | 208,041 (all registry) | 1,041,321 (~5.0/order) | OK -- includes DLQ + retry events |
| **sap** | 86,093 (14-day window) | 271,424 (~3.2/order) | OK -- processes 100% of orders within --days window |

**Key findings:**
- **orders**: Status distribution correct -- 208K created, ~197K delivered, ~8K payment_declined, ~1.6K fraud/address failures (~7% total)
- **servicebus**: 5 events/order + ~3% transient retries + 0.5% DLQ. Status: 1,034K completed, 5.8K failed, 1.1K dead-lettered
- **sap**: After fix (previous commit), 86,093 VA01 = 100% match with orders in 14-day window. Full lifecycle: VA01 -> VL01N (85,778) -> VF01 (83,150). Some VL01N/VF01 missing due to late-hour orders where delivery/billing would exceed midnight
- **Pricing format consistent**: cart_total in whole USD (int) across all generators (access, orders, servicebus, sap)
- **Correlation keys consistent**: order_id, customer_id, session_id, tshirtcid all match across generators

### Audit Results -- Phase 2 Generators (meeting_schedule dependents)

| Generator | Dependency | Status |
|-----------|-----------|--------|
| **meraki** | Reads `_meeting_schedule` for door/temp sensor correlation | OK -- walk-ins, ghosts, after-hours all working |
| **webex_ta** | Reads `_meeting_schedule`, converts to TA format | OK -- skips ghosts/walk-ins correctly |
| **exchange** | Imports `_meeting_schedule` | Partial -- imports but calendar invite correlation not fully implemented |
| **webex_api** | Imports `_meeting_schedule` | Partial -- generates independent meetings, not fully correlated with device logs |

**Known gaps (not blocking, enhancement only):**
- exchange.py: Calendar invite emails not fully correlated with Webex meeting schedule
- webex_api.py: REST API events generated independently from shared meeting schedule

---

## 2026-02-14 ~22:30 UTC -- Add docs/use-cases/ directory with order flow correlation doc

### Added

- **`docs/use-cases/`** -- New directory for use case documentation
- **`docs/use-cases/order-flow-correlation.md`** -- Complete order flow documentation:
  - Flow diagram showing data flow from web session through all 5 data sources
  - Correlation keys table (order_id, customer_id, session_id, tshirtcid, product slug, demo_id)
  - Detailed event timeline for each source with example log lines
  - ID format reference table
  - Scenario impact on order flow
  - SPL queries for order correlation in Splunk

---

## 2026-02-14 ~22:00 UTC -- Fix SAP generator to process all web orders (was only processing ~0.5%)

### Fixed

- **`bin/generators/generate_sap.py`** -- Major order processing fix:
  - **Root cause**: Orders from `order_registry.json` were only consumed when a randomly-selected t-code happened to be `VA01` (line 294: `if tcode == "VA01" and order_queue`). With Sales users being ~14% of SAP users and VA01 being 1 of 7 Sales t-codes, only ~2% of random events processed an order, resulting in ~1,030 SAP sales orders for 208,041 web orders.
  - **Solution**: Created dedicated `generate_order_lifecycle_events()` function that processes EVERY order from the registry with a complete SAP lifecycle:
    1. VA01 (Create Sales Order) - at order time
    2. VL01N (Create Delivery) - 15-45 min later
    3. VF01 (Create Billing Document) - 1-3 hours later
  - Removed order consumption from random `generate_tcode_events()` -- VA01 events there are now generic manual sales orders
  - Scenario `demo_id` tags propagate correctly through all 3 lifecycle events

### Verified

- **Before**: ~1,030 SAP sales orders for 208,041 web orders (0.5%)
- **After**: 86,093 VA01 + 85,778 VL01N + 83,150 VF01 = 271,424 total events (14-day run)
- 86,093 orders = 100% match with orders in the 14-day window (remaining 121,948 orders are days 14-30)
- Order lifecycle chain verified: VA01 -> VL01N (~30 min) -> VF01 (~2 hours), same user, same SO number
- Scenario tags (disk_filling, memory_leak, cpu_runaway, firewall_misconfig) carry through all lifecycle events

---

## 2026-02-14 ~20:30 UTC -- Redesign Tab 2 CORE layout to eliminate all arrow/box overlaps

### Fixed

- **`docs/reference/architecture_v2.html`** -- Major Tab 2 (Server Connections) layout redesign:
  - **Root cause**: DC-BOS-01/02 in Column A (x=440-600) blocked all horizontal data-flow lines from 3-tier column to FILE/SAP in Column B (x=640+). Every line at y=210-300 had to cross Column A.
  - **Solution**: Moved DC-BOS-01/02 down to y=335/y=390, leaving Column A empty at y=210-335. All horizontal data-flow lines now pass through empty space.
  - FILE-BOS-01, SAP-PROD-01, SAP-DB-01 widened from 140px to 160px
  - FILE auth stub re-routed RIGHT at x=810 (outside SAP column, was x=710 passing through SAP boxes)
  - SSH Bus moved from y=395 to y=440, Auth Bus from y=462 to y=522
  - All downstream sections (Atlanta, SD-WAN, Austin, Cloud, Legend) shifted +60px
  - viewBox expanded from 960 to 1020
- **Tab 1**: Internet to ASA line split into 2 solid + 1 faint dashed segment through Cloud Services box
- **Tab 2**: WEB-01 to Azure ServiceBus path moved to x=45 (outside 3-tier box)
- **Tab 2**: ASA to WEB path offset to x=400 (clear of CORE container edge)

### Verified

- SD-WAN port UDP/4500 (IPsec NAT-T) confirmed correct for Meraki AutoVPN -- no change needed
- All connection paths verified against all box positions -- zero overlaps

---

## 2026-02-14 ~17:00 UTC -- Create architecture_v2.html with port labels, redesigned diagrams, and enhanced tabs

### Added

- **`docs/reference/architecture_v2.html`** -- Complete v2 redesign of architecture reference page (standalone HTML, 7 tabs). Major improvements:

#### Tab 1: Network Overview
- Port labels on all SVG connection lines (TCP/443, UDP/4500, C2/TCP443, RESTCONF/443)
- Cloud services bar split into 2 rows (was 1 cramped row), added Azure ServiceBus and Catalyst Center
- ACI Fabric -> Server block connection with "Leaf ports" label
- Log generators categorized into 5 groups with colored borders (Network, Cloud & Collaboration, Infrastructure, Applications, ITSM) with dependency indicators

#### Tab 2: Server Connections
- 3-tier e-commerce flow redesigned as clear vertical stack (WEB-01/02 -> APP-BOS-01 -> SQL-PROD-01) in labeled box
- All port numbers on connections (TCP/443,8443, TCP/1433, TCP/445, TCP/30015, etc.)
- Auth Bus with port labels (TCP/88 Kerberos, TCP/389 LDAP, TCP/636 LDAPS)
- SSH Management Bus with port labels (TCP/22 SSH, TCP/3389 RDP)
- MON-ATL-01 monitoring connections (ICMP, TCP/5666 NRPE, TCP/3000 Grafana)
- Azure ServiceBus in Cloud Dependencies (AMQP/5671)
- SAP order_registry.json dependency line
- Expanded connection legend with 7 connection types

#### Tabs 3-5: Site Tabs
- Key Connections callout card at top of each tab with all critical ports
- Port columns added to server tables
- Austin auth warning callout: 10.30.x.x source IPs appear in DC-BOS WinEventLog (~30% of auth events) with SPL query

#### Tab 6: Cloud & SaaS
- Cards grouped by category (Identity & Security, Cloud Infrastructure, Collaboration, ITSM)
- New Azure ServiceBus card (AMQP/5671, queues: price-updates/inventory-sync, dead_letter_pricing scenario)
- Port column added to Cisco Secure Access table

#### Tab 7: Scenarios
- Timeline bars with hoverable tooltips showing phase details and revenue impact
- Infrastructure badges on each scenario card (colored mini-badges for affected servers/users)
- SPL query snippets as collapsible details/summary elements
- Correct day numbers verified from Python config dataclasses

#### General UX
- URL hash support (architecture_v2.html#scenarios for direct tab linking)
- Responsive CSS for mobile widths (@media max-width: 768px)
- Tooltip system works on both SVG and HTML .hoverable elements

### Port Numbers (verified from generate_asa.py + company.py)

All port labels cross-referenced against source code:
- Internet -> ASA: TCP/443, 80 (WEB_PORTS)
- WEB -> APP: TCP/443, 8443 (dmz->inside ACL)
- APP -> SQL: TCP/1433 (inside->inside ACL)
- Auth: TCP/88 (Kerberos), TCP/389 (LDAP), TCP/636 (LDAPS)
- DC Replication: TCP/389, TCP/3268 (Global Catalog)
- SMB: TCP/445, SAP HANA: TCP/30015, SSH: TCP/22, RDP: TCP/3389
- AutoVPN: UDP/4500 (IPsec NAT-T)
- Monitoring: ICMP, TCP/5666 (NRPE), TCP/3000 (Grafana)
- ServiceBus: TCP/5671 (AMQP)

---

## 2026-02-14 ~15:30 UTC -- Fix scenario day numbers and source lists in architecture.html

### Fixed

- **`docs/reference/architecture.html`** -- Corrected 3 scenario day numbers that were wrong (compared against Python config dataclasses):
  - `memory_leak`: Days 6-9 -> Days 7-10 (config: `start_day=5`, `oom_day=9`). Fixed tooltip, timeline bar position, card badge, and OOM crash description (Day 9 -> Day 10).
  - `firewall_misconfig`: Day 7 -> Day 6 (config: `day=5`). Fixed timeline bar position and card badge.
  - `certificate_expiry`: Day 12 -> Day 13 (config: `day=12`). Fixed timeline bar position and card badge.
- **`docs/reference/architecture.html`** -- Fixed scenario source lists:
  - `disk_filling`: Removed `access` from sources (MON-ATL-01 was removed from generate_access.py in previous change).
  - `memory_leak`: Added `orders` and `sap` to sources (WEB-01 impacts orders via order_registry).

---

## 2026-02-13 ~23:20 UTC -- Increase scenario revenue impact + remove disk_filling from access/orders

### Changed

- **`bin/scenarios/ops/cpu_runaway.py`** -- Increased `access_should_error()` error rates and converted return from 2-tuple `(bool, int)` to 3-tuple `(bool, int, float)` (adding response_time_multiplier). Severity 1: 5% -> 10%, 1.5x resp. Severity 2 (critical): 25% -> 45%, 4.0x resp. Severity 3 (recovery): 2% -> 3%, 1.2x resp.
- **`bin/scenarios/ops/memory_leak.py`** -- Increased error rates across all days to create a visible "descending staircase" revenue pattern. Day 7: 0% -> 5%. Day 8: 3% -> 15%. Day 9: 8% -> 30%. Day 10 pre-OOM: 15-25% -> 35-55%. Day 10 OOM: 50% -> 70%. Response multipliers also increased.
- **`bin/scenarios/ops/dead_letter_pricing.py`** -- Bumped peak error rates. Hour 8: 5% -> 8%. Hours 9-10: 15% -> 20%. Hour 11: 10% -> 12%. Hour 12: 3% -> 5%.
- **`bin/scenarios/network/ddos_attack.py`** -- Increased `access_should_error()` error rates. Full attack: 60% -> 80%. Partial mitigation: 40% -> 50%. Ramping: 20% -> 30%. Probing: 5% -> 8%. DDoS is a direct HTTP flood against WEB-01/WEB-02 and should be one of the most impactful scenarios.

### Removed

- **`bin/generators/generate_access.py`** -- Removed `disk_filling` scenario integration from access log generator. MON-ATL-01 is a monitoring server in Atlanta, not web infrastructure -- it has no impact on web traffic, orders, or revenue. Removed import of `DiskFillingScenario`, initialization, and the error injection block. Orders no longer tagged with `demo_id=disk_filling`.

### Fixed

- **`bin/generators/generate_access.py`** -- Updated cpu_runaway integration from 2-tuple to 3-tuple unpacking. Changed ddos_attack from `demo_id or "ddos_attack"` to `demo_id = "ddos_attack"` (overrides other tags, same as firewall_misconfig -- both are direct web-tier impacts).

### Context

Splunk timechart of hourly revenue (`sum(total) by demo_id`) showed that only `certificate_expiry` created a visible revenue drop. Two issues: (1) cpu_runaway, memory_leak, and ddos_attack had error rates too low to trigger meaningful session reduction, and (2) disk_filling was incorrectly tagging orders despite MON-ATL-01 having no relationship to the web/order pipeline. Scenarios unchanged: certificate_expiry (already perfect), firewall_misconfig (already 50%), exfil/ransomware/phishing (no web impact by design), disk_filling (still affects linux/servicenow logs, just not access/orders).

### Verification

- 21-day test run (`--sources=access,orders --scenarios=all`): 5,698 orders total
- disk_filling: Days 1-5 now show ONLY baseline orders (no more `demo_id=disk_filling`)
- memory_leak: Day 7=308, Day 8=176 (44% drop), Day 9=95 (70% drop), Day 10 OOM=20 then recovery
- cpu_runaway: Day 11=66 orders (78% drop), Day 12 recovery from hour 11
- dead_letter_pricing: Day 16=219 (30% drop), hours 9-10 show ~50% fewer orders
- ddos_attack: Day 18=167 (47% drop, was 230), full attack hours show 0-2 orders
- certificate_expiry: Day 13 hours 0-6 = 0 orders (unchanged, perfect)

---

## 2026-02-13 ~22:40 UTC -- Align --show-files counts and add ANSI color coding

### Changed

- **`bin/main_generate.py`** -- Per-file counts now globally right-aligned to a fixed column computed from the longest path in `GENERATOR_OUTPUT_FILES`. Previously each generator's counts aligned independently, causing jagged output when generators with short paths (e.g., `linux/cpu.log`) were mixed with long paths (e.g., `cisco_secure_access_firewall.csv`).
- **`bin/main_generate.py`** -- Added ANSI color coding to CLI output (auto-disabled when piped or `NO_COLOR` set): green checkmarks, yellow event counts, cyan per-file counts, dim file paths/timing. Summary footer also colorized (green "Complete!", yellow total).

### Verification

- 7-generator test run (`perfmon,wineventlog,linux,entraid,catalyst_center,aci,secure_access`): all per-file counts aligned to same column regardless of path length
- Colors render in iTerm2/Terminal.app, degrade gracefully to plain text when piped

---

## 2026-02-13 ~22:30 UTC -- Fix --show-files to display event counts instead of line counts

### Fixed

- **`bin/main_generate.py`** -- `run_generator()` now handles both `int` and `dict` returns from generators. Added `_print_file_counts()` helper that uses generator-reported per-file event counts instead of raw line counts (`sum(1 for _ in open(f))`). Both parallel and sequential `--show-files` display paths now call the new helper.
- **`bin/generators/generate_perfmon.py`** -- Returns `{"total": N, "files": {"windows/perfmon_*.log": n}}` with per-file event counts for all 4 metric files (processor, memory, logicaldisk, network_interface).
- **`bin/generators/generate_wineventlog.py`** -- Returns dict with per-file counts for security/system/application log files.
- **`bin/generators/generate_sysmon.py`** -- Returns dict with per-file count for sysmon_operational.log.
- **`bin/generators/generate_mssql.py`** -- Returns dict with per-file count for mssql_errorlog.log.
- **`bin/generators/generate_linux.py`** -- Returns dict with per-file counts for 6 files (cpu, vmstat, df, iostat, interfaces, auth).
- **`bin/generators/generate_meraki.py`** -- Returns dict with per-file counts for 7 files (mx, mr, mr_health, ms, ms_health, mv, mt).
- **`bin/generators/generate_servicenow.py`** -- Returns dict with per-file counts for incidents/cmdb/change files.
- **`bin/generators/generate_entraid.py`** -- Returns dict with per-file counts for signin/audit/risk_detection files.
- **`bin/generators/generate_aci.py`** -- Returns dict with per-file counts for fault/event/audit files.
- **`bin/generators/generate_secure_access.py`** -- Returns dict with per-file counts for dns/proxy/firewall/audit files.
- **`bin/generators/generate_catalyst_center.py`** -- Returns dict with per-file counts for devicehealth/networkhealth/clienthealth/issues files.
- **`bin/generators/generate_webex_ta.py`** -- Returns dict with per-file counts for meetingusage/attendee files.
- **`bin/generators/generate_webex_api.py`** -- Returns dict with per-file counts for meetings/admin_audit/security_audit/meeting_qualities/call_history files.
- **`bin/generators/generate_catalyst.py`** -- Returns dict (single-file, but syslog had multiline events causing 1,209 events vs 1,222 lines).
- **`bin/generators/generate_aws_billing.py`** -- Returns dict (single-file, but CSV header row caused 17 events vs 18 lines).

### Context

The `--show-files` feature displayed raw line counts per file, which was severely misleading for multiline log formats. Perfmon events span 7-8 lines each, WinEventLog XML ~17 lines, and Sysmon XML ~24 lines. For example, perfmon showed `98,112` lines for a file with only `14,016` events. The fix has each multi-file generator return a `{"total": N, "files": {"rel/path": count}}` dict. Single-file generators that don't have multiline issues continue returning `int` (backward compatible). The `_print_file_counts()` helper falls back to line counting for any file without a generator-reported count.

### Verification

- Full test run (`--all --scenarios=none --days=1 --test --show-files`): All 26 generators pass
- Perfmon: 37,776 total = 14,016 + 11,592 + 8,208 + 3,960 (was showing 98K/81K/57K/27K lines)
- WinEventLog: 591 total = 311 + 163 + 117 (was showing 5,459/2,867/1,965 lines)
- Sysmon: 2,567 total (was showing 62,321 lines)
- All per-file event counts sum correctly to generator totals

---

## 2026-02-13 ~22:00 UTC -- Increase Cloud/Entra Volume + Reduce Meraki MS Health Default

### Changed

- **`bin/generators/generate_aws.py`** -- `base_events_per_peak_hour` increased from 20 to 200 (~10x). Produces ~1,400 events/day at scale=1.0 instead of ~155.
- **`bin/generators/generate_gcp.py`** -- `base_events_per_peak_hour` increased from 15 to 150 (~10x). Produces ~1,000 events/day at scale=1.0 instead of ~116.
- **`bin/generators/generate_entraid.py`** -- `audit_per_day` increased from 20 to 200. Refactored `generate_audit_day()` to use `base_count` as a scale factor. All audit event categories scaled up: group changes (15-25/day), user attribute updates (10-20/day), license assignments (3-6/day), directory role changes (1-2/day), password resets (8-15/day), SSPR flows (30-50/day), app consent (5-10/day). Produces ~150-250 audit events/day at scale=1.0 instead of ~26.
- **`bin/generators/generate_meraki.py`** -- Default `health_interval` changed from 5 to 15 minutes. Reduces MS switch health events from ~127K/day to ~42K/day.
- **`bin/main_generate.py`** -- `--meraki-health-interval` default changed from 5 to 15 minutes, help text updated.

### Context

31-day full generation revealed unrealistically low volumes for AWS CloudTrail (~4.8K total), GCP Audit (~3.6K total), and Entra ID Audit (~800 total) compared to a 175-employee company. Meraki MS Health at 5min interval was conversely too high (~3.9M for 31 days). These adjustments bring volumes in line with realistic expectations.

### Verification

- 3-day test run (`--sources=aws,gcp,entraid,meraki --scenarios=exfil`): 187,353 total events
- AWS: 4,120 events (3 days) = ~1,373/day (was ~155)
- GCP: 3,062 events (3 days) = ~1,021/day (was ~116)
- Entra ID Audit: 439 events (3 days) = ~146/day (was ~26)
- Meraki MS Health: 126,720 events (3 days) = ~42,240/day (was ~126,720)

---

## 2026-02-14 ~16:00 UTC -- Sync Webex TA + API with Shared Meeting Schedule

### Changed

- **`bin/generators/generate_webex_ta.py`** -- Now reads from the shared `meeting_schedule.py` (populated by `generate_webex.py` in Phase 1) instead of generating independent meetings. Same meeting titles, times, hosts, and participants now appear across all Webex sourcetypes. Falls back to independent generation for standalone use.
- **`bin/generators/generate_webex_api.py`** -- Same as above: meetings and quality records now read from shared schedule. Admin audit, security audit, and call history remain independent (not meeting-specific). Falls back to independent generation for standalone use.
- **`bin/main_generate.py`** -- Added `webex_ta` and `webex_api` to `GENERATOR_DEPENDENCIES` (both depend on `webex`), moving them from Phase 1 to Phase 2.

### Added

- **`docs/reference/meeting_correlation_cheatsheet.md`** -- Quick reference for tracing meetings across all correlated sources: room-to-device mapping (21 rooms), correlation fields per sourcetype, Exchange email subject patterns, meeting behavior patterns, and sample SPL queries.

### Context

Previously, all three Webex generators had overlapping meeting template names ("Team Standup", "Project Review", etc.) but generated them independently -- different times, hosts, and participants. In Splunk, the same meeting title would appear at 3 different times with 3 different organizers, making cross-sourcetype correlation impossible. Now all five correlated generators (webex, webex_ta, webex_api, exchange, meraki) produce events for the exact same meetings.

### Verification

- Generated webex + webex_ta + webex_api with `--days=3 --scenarios=exfil`: all 177 meetings match perfectly across all 3 sourcetypes (same title, time, host)
- Exchange calendar invites include matching meeting titles with room names
- Phase 2 dependency ordering confirmed working

---

## 2026-02-14 ~14:00 UTC -- Fix cpu_runaway ASA Plot Hole

### Fixed

- **`bin/generators/generate_asa.py`** -- Integrated `CpuRunawayScenario.asa_get_events()` which was already fully implemented in the scenario class but never called from the generator. ASA now generates TCP SYN Timeout events (APP-BOS-01 -> SQL-PROD-01:1433) during the cpu_runaway scenario's critical phase (Days 11-12). 157 events in test run.

### Context

Full audit of all 10 scenarios vs all generators confirmed this was the only remaining plot hole. All 10 scenarios now have 100% source coverage matching their registry declarations.

---

## 2026-02-14 ~12:00 UTC -- Fix Scenario Source Gaps

### Fixed

- **`bin/generators/generate_secure_access.py`** -- Added `_generate_phishing_test_proxy_events()` function + integration call. Phishing test scenario now generates Secure Access Proxy logs (~95 events over 3 days) for employees clicking the simulated phishing link.
- **`bin/generators/generate_catalyst.py`** -- Enhanced `_generate_firewall_misconfig_events()` with interface flap events (`%LINK-3-UPDOWN`, `%LINEPROTO-5-UPDOWN`) on CAT-BOS-DIST-01 uplink during outage window (hours 10-12). Previously only generated STP topology traps.

### Corrected Documentation

- **`CLAUDE.md`** -- Updated Known Scenario Source Gaps: 2 of 4 gaps were already implemented (ransomware+ASA, certificate_expiry+Access). Remaining 2 gaps now fixed.

### Verification

- `secure_access --scenarios=phishing_test --days=25`: 95 proxy events with `demo_id=phishing_test` (days 21-23)
- `catalyst --scenarios=firewall_misconfig --days=14`: 10 events -- interface down at hour 10, STP traps hours 10-11, interface up at hour 12

---

## 2026-02-14 ~10:00 UTC -- Consolidate Nested Docs into Main Docs

### Moved

- **`TA-FAKE-TSHRT/docs/architecture.html`** (92KB) -> `docs/reference/architecture.html` -- Replaces older 48KB version
- **`TA-FAKE-TSHRT/docs/architecture_connections.svg`** -> `docs/reference/architecture_connections.svg`
- **`TA-FAKE-TSHRT/docs/architecture_overview.svg`** -> `docs/reference/architecture_overview.svg`
- **`TA-FAKE-TSHRT/docs/scenario_playground.html`** -> `docs/reference/scenario_playground.html`

### Removed

- **`TA-FAKE-TSHRT/docs/`** directory -- All files consolidated into `docs/reference/`. Splunk app package should only contain Splunk-specific content.

### Updated

- **`CLAUDE.md`** -- Updated Repository Structure `reference/` description to reflect new architecture files.

---

## 2026-02-14 ~09:00 UTC -- Document Custom Fields in Both READMEs

### Added

- **`README.md` (git root)** + **`TheFakeTshirtCompany/README.md`** -- Added "Custom Fields (Not in Real Logs)" section documenting all synthetic fields injected by generators: `demo_id`, `IDX_demo_id`, `demo_host`, `wrong_price`, `revenue_impact`, `originalPrice`, `priceErrorType`. Includes where each field appears, its purpose, and example SPL queries for filtering.
- **`CLAUDE.md`** -- Already had this information; README sections now match.

---

## 2026-02-14 ~08:00 UTC -- Quick Start Rewrite in Both READMEs

### Updated

- **`README.md` (git root)** + **`TheFakeTshirtCompany/README.md`** -- Rewrote Quick Start section. Now uses TUI as primary method (`python3 main_generate.py --tui`), explains expected output volume (~10M events, ~3.8GB), documents auto-index creation via `local/indexes.conf`, and adds verification step.

---

## 2026-02-14 ~07:00 UTC -- Fix ServiceNow CMDB Timestamp

### Root Cause

CMDB records (37 events) existed in Splunk but were invisible with the default Jan 2026 time range. All records had `sys_updated_on="2025-12-31T00:00:00Z"` (start_date minus 1 day), placing them outside the standard search window.

### Fixed

- **`bin/generators/generate_servicenow.py`** (line 1216) -- Changed CMDB `sys_updated_on` from `start_date - 1 day` to `start_date`. Records now timestamped at `2026-01-01T00:00:00Z`, within the data time range.

### Documentation Updated

- **`CLAUDE.md`** -- Removed CMDB from "Known Data Gaps" table (was not a real gap, just a timestamp issue)
- **`docs/QUALITY_CHECKLIST.md`** -- Marked CMDB item as fixed in P4 stretch goals

### Verification

- Pre-fix: 37 events found with `earliest=0` but 0 with `earliest=1767225600`
- Post-fix: Needs data regeneration (`--sources=servicenow`) for corrected timestamps

---

## 2026-02-14 ~06:00 UTC -- Root-Level README.md

### Created

- **`README.md` (git root)** -- New root-level README at same location as CLAUDE.md. Adapted from `TheFakeTshirtCompany/README.md` with adjusted relative links (prefixed with `TheFakeTshirtCompany/`). Includes project overview, repo structure from git root, quick start, data source summary, scenario table, and documentation index.

---

## 2026-02-14 ~05:00 UTC -- P3/P4 Quality Checklist: Scenario Dashboards, CIM Fields, Documentation

Completed remaining P3 and P4 items from QUALITY_CHECKLIST.md.

### Created

- **`default/data/ui/views/scenario_phishing_test.xml`** -- Dashboard Studio v2 dashboard for phishing test scenario (Days 21-23). 8 data sources, 10 visualizations: markdown header, 4 KPIs (events, sources, hosts, 31% click rate), email timeline, cross-source correlation, events donut, evidence table.
- **`default/data/ui/views/scenario_ddos_attack.xml`** -- Dashboard Studio v2 dashboard for DDoS attack scenario (Days 18-19). 10 data sources, 13 visualizations including ASA event breakdown and HTTP error rate.
- **`default/data/ui/views/scenario_dead_letter_pricing.xml`** -- Dashboard Studio v2 dashboard for dead-letter pricing scenario (Day 16). 9 data sources, 12 visualizations including ServiceBus event timeline and HTTP error rate.

### Updated

- **`default/data/ui/nav/default.xml`** -- Added 3 new scenario dashboards to navigation: phishing_test (Security), dead_letter_pricing (Operations), ddos_attack (Network).

- **`default/props.conf`** -- Added CIM field aliases:
  - Secure Access DNS: REPORT transform + query, query_type, reply_code, dest fields
  - Secure Access Proxy: REPORT transform + dest, http_method, status, bytes_in, bytes_out, http_content_type, http_user_agent
  - Secure Access Firewall: REPORT transform + dest_port, src_port, transport, direction
  - Catalyst Center devicehealth: dest, cpu_load_percent, mem_used_percent, status
  - Catalyst Center issue: signature, severity, description
  - Webex events: action, dest
  - Webex admin audit: user, action (from nested data{})
  - Webex attendee history: user

- **`default/transforms.conf`** -- Added 3 REPORT transforms for Secure Access headerless CSV field extraction (umbrella_dns_fields, umbrella_proxy_fields, umbrella_firewall_fields). Added comment documenting unreferenced cisco_asa_messageid.csv lookup.

- **`CLAUDE.md`** -- Updated "Affected sources" for 6 scenarios (exfil, memory_leak, cpu_runaway, disk_filling, dead_letter_pricing, ddos_attack) to match actual Splunk data. Added "Known Scenario Source Gaps" section documenting 4 code bugs. Added "Known Data Gaps" section for CMDB, SAP timestamps, and GCP sourcetype split.

### Verification

- VPN correlation: Confirmed -- ASA events with 10.250.x.x sources correlate with user identities
- Weekend patterns: Confirmed -- Sunday ~601K events vs weekday ~830K (30% reduction)
- Scenario dashboards: All 3 created with consistent pattern matching existing dashboards

---

## 2026-02-14 ~03:00 UTC -- README Update Pass: All 6 README Files + Root README

Comprehensive update of all README.md files to match current project state. Added AI disclaimer to all files.

### Created

- **`README.md` (root)** -- New root-level README with project overview, repository structure, quick start, data source summary, scenario list, and documentation index.

### Updated

- **`TA-FAKE-TSHRT/README.md`** -- Complete rewrite. Fixed: 17->26 generators, 7->10 scenarios, wrong sourcetype naming (`:demo` suffix -> `FAKE:` prefix), wrong index name (`splunk_demo` -> `fake_tshrt`). Added missing data sources (Secure Access, Catalyst, ACI, SAP, GuardDuty, Billing, Sysmon, linux:auth). Added missing CLI options (--scale, --parallel, --test/--no-test).

- **`TA-FAKE-TSHRT/default/README.md`** -- Fixed counts: 37->60 inputs, 46->64 props, 28->275 transforms, 15->31 eventtypes. Added 5 missing scenario event types and 6 missing CIM event types. Added Secure Access, Catalyst/ACI, Catalyst Center, SAP sourcetype sections. Added linux:auth to Linux section. Added inventory lookups (asset, identity, MAC) to lookup table.

- **`TA-FAKE-TSHRT/bin/README.md`** -- Fixed counts: 19->26 generators, 7->10 scenarios. Added missing generators: catalyst, aci, secure_access, catalyst_center, aws_guardduty, aws_billing, sap. Added missing scenarios: phishing_test, ddos_attack, dead_letter_pricing. Updated scenario timeline to show all 10 scenarios across 31 days. Added erp/ and updated output directory structure. Added sap dependency on access.

- **`docs/README.md`** -- Fixed ransomware link: `scenarios/ransomware.md` -> `scenarios/ransomware_attempt.md`.

- **`docs/datasource_docs/README.md`** -- Added linux:auth to Linux section. Added linux:auth volume entry.

### AI Disclaimer

Added to all README files:
> This project was primarily developed with AI assistance (Claude). While care has been taken to ensure accuracy, there may be inconsistencies or errors in the generated logs that have not yet been discovered.

---

## 2026-02-14 ~01:00 UTC -- P2-P4 Quality Checklist: CIM Eventtypes, vendor_product, Lookups, Ransomware Rename

Quality audit follow-up implementing P2-P4 items from `docs/QUALITY_CHECKLIST.md`. All changes are search-time config -- no data regeneration required.

### Batch 1: CIM Eventtypes + Tags

**eventtypes.conf** -- Added 4 new CIM-aligned eventtypes:
- `demo_performance` -- Perfmon:* + Linux metrics (cpu, vmstat, df, iostat, interfaces)
- `demo_endpoint` -- WinEventLog + WinEventLog:Sysmon
- `demo_intrusion_detection` -- GuardDuty + Umbrella blocked + ASA deny
- `demo_database` -- mssql:errorlog

**tags.conf** -- Added 4 matching CIM tag stanzas (performance, endpoint, ids+attack, database)

### Batch 2: vendor_product + Orphan Fix

**props.conf** -- Added `EVAL-vendor_product` to 13 sourcetypes:
- 6 Linux: FAKE:cpu, FAKE:vmstat, FAKE:df, FAKE:iostat, FAKE:interfaces, FAKE:linux:auth (value: "Linux")
- 7 Perfmon: Processor, Memory, LogicalDisk, Network_Interface, SQLServer:sql_statistics, SQLServer:buffer_manager, SQLServer:locks (value: "Microsoft Windows")

**props.conf** -- Removed 5 orphan lines in `[FAKE:Perfmon:SQLServer:locks]` that were duplicates from the Processor stanza (wrong host transform, wrong report, wrong metric_name "cpu" instead of "sqlserver")

### Batch 3: Inventory Lookups

**props.conf** -- Wired up 3 inventory lookups (LOOKUP- stanzas):
- `asset_inventory` on FAKE:cisco:asa (src + dest), FAKE:azure:aad:signin (src)
- `identity_inventory` on FAKE:azure:aad:signin, FAKE:WinEventLog, FAKE:linux:auth (user)
- `mac_inventory` on FAKE:meraki:accesspoints (clientMac)

**Note:** EntraID identity lookup uses `email AS user` (not `identity AS user`) because `user` is lowercase full email while `identity` is just the username.

### Batch 4: Field Verification

Verified all 61 sourcetypes via Splunk queries. Updated QUALITY_CHECKLIST.md section 3 -- all VERIFY items resolved to OK. Key findings:
- All vendor_product EVALs confirmed working
- All inventory lookups enriching events correctly
- servicenow:cmdb: stanza exists, 0 events (no generator)
- GCP + SAP marked STALE (waiting for regeneration)

### Batch 5: Ransomware Naming Alignment

Renamed `ransomware` to `ransomware_attempt` to match scenario registry (`demo_id=ransomware_attempt`):
- Renamed `scenario_ransomware.xml` to `scenario_ransomware_attempt.xml`
- Updated `default.xml` navigation reference
- Renamed `docs/scenarios/ransomware.md` to `docs/scenarios/ransomware_attempt.md`
- Updated `docs/scenarios/README.md` link

### Files changed

| File | Change |
|------|--------|
| `default/eventtypes.conf` | +4 CIM eventtypes |
| `default/tags.conf` | +4 CIM tag stanzas |
| `default/props.conf` | +13 vendor_product EVALs, -5 orphan lines, +7 LOOKUP stanzas |
| `default/data/ui/views/scenario_ransomware_attempt.xml` | Renamed from scenario_ransomware.xml |
| `default/data/ui/nav/default.xml` | Updated view reference |
| `docs/scenarios/ransomware_attempt.md` | Renamed from ransomware.md |
| `docs/scenarios/README.md` | Updated link |
| `docs/QUALITY_CHECKLIST.md` | Marked completed P1-P4 items |

---

## 2026-02-13 ~22:00 UTC -- Fix 4 Priority 1 Critical Bugs (Quality Audit)

Quality audit (`docs/QUALITY_CHECKLIST.md`) found 4 critical bugs in Splunk search-time config that broke event classification, user correlation, and CIM data model compliance across ~25.8M events. All fixes are search-time config -- no re-indexing required (except GCP, see below).

### Bug 1: eventtypes.conf -- Wrong index and sourcetype names

**Problem:** All 17 eventtypes used `index=splunk_demo` (wrong index) and `:demo` suffix sourcetypes (wrong naming convention). Every eventtype matched zero events.

**Fix:** Complete rewrite of `eventtypes.conf`:
- Changed `index=splunk_demo` to `index=fake_tshrt` in all stanzas
- Changed `:demo` suffix sourcetypes to `FAKE:` prefix (e.g., `cisco:asa:demo` to `FAKE:cisco:asa`)
- Added 5 missing scenario eventtypes: `ransomware_attempt`, `phishing_test`, `ddos_attack`, `dead_letter_pricing`, `certificate_expiry`
- Added 3 new source group eventtypes: `demo_erp`, `demo_campus`, `demo_datacenter`
- Added 2 new CIM eventtypes: `demo_email`, `demo_dns`
- Expanded existing groups: added `linux:auth` to demo_linux, `WinEventLog:Sysmon`/`mssql:errorlog` to demo_windows, `cisco:umbrella:*` to demo_network_security

Total: 22 stanzas (was 17). Also rewrote `tags.conf` to match -- added 5 scenario tags, 2 CIM tags, 3 source group tags.

### Bug 2: Entra ID signin/audit -- `user` field is null

**Problem:** EVAL statements in `props.conf` referenced bare field names (`userPrincipalName`, `appDisplayName`) but these are nested under `properties.*` in the JSON. EVALs override FIELDALIASes in Splunk, so `user` = null for all ~19,600 Entra ID events.

**Fix for `[FAKE:azure:aad:signin]`:** Changed 6 EVALs to use `properties.*` paths:
- `EVAL-user = lower('properties.userPrincipalName')`
- `EVAL-action = if('properties.status.errorCode'==0,"success","failure")`
- `EVAL-app = lower(replace('properties.appDisplayName', " ", ":"))`
- `EVAL-dest = if('properties.resourceDisplayName' == "null",...)`
- `EVAL-duration = 'properties.processingTimeInMilliseconds'/1000`
- Removed duplicate dead `EVAL-app = "azure:aad"` (overridden by later EVAL)

**Fix for `[FAKE:azure:aad:audit]`:** Rewrote with audit-appropriate EVALs (was copy-pasted from signin):
- `EVAL-action = coalesce('properties.operationType', operationName)`
- `EVAL-result = 'properties.result'`
- Removed EVAL-dest, EVAL-duration, EVAL-user, EVAL-user_id (let existing FIELDALIAS `identity AS user` work)

### Bug 3: GCP sourcetype `:demo` suffix mismatch

**Problem:** `transforms.conf` routed GCP events to `FAKE:...:demo` suffix sourcetypes, but `props.conf` stanzas had no `:demo` suffix. Result: 3,593 GCP events got zero CIM field extractions.

**Fix:** Removed `:demo` suffix from 2 FORMAT lines in `transforms.conf`:
- `FAKE:google:gcp:pubsub:audit:admin_activity:demo` -> `FAKE:google:gcp:pubsub:audit:admin_activity`
- `FAKE:google:gcp:pubsub:audit:data_access:demo` -> `FAKE:google:gcp:pubsub:audit:data_access`

**Note:** Existing GCP events in Splunk still have the `:demo` sourcetype. Must regenerate GCP data and re-ingest to fix.

### Bug 4: Orphaned lookup stanza in transforms.conf

**Problem:** `[sqlserver_host_dbserver_lookup]` stanza referenced `sqlserver_host_dbserver_lookup.csv` which does not exist.

**Fix:** Removed the orphaned stanza from `transforms.conf`.

**Files changed:**
- `default/eventtypes.conf` (complete rewrite -- 22 stanzas)
- `default/tags.conf` (complete rewrite -- 22 tag stanzas)
- `default/props.conf` (Entra ID signin + audit EVAL fixes)
- `default/transforms.conf` (removed orphaned lookup + removed `:demo` from 2 GCP FORMAT lines)

**User action needed:**
1. Restart Splunk or reload the TA to apply config changes
2. Regenerate GCP data and re-ingest to fix the `:demo` sourcetype suffix on existing events

---

## 2026-02-13 ~18:00 UTC -- Fix SAP-to-Access Order Correlation

SAP VA01 (Create Sales Order) events now include the web order ID (`ref ORD-2026-XXXXX`) in the details field, enabling direct correlation between SAP sales orders and web orders from access logs.

**Problem:** SAP generator read `order_registry.json` but never wrote the `order_id` field to output. The only correlation path was `customer_id` + approximate timestamp, which was fragile.

**Fix:**
- `generate_sap.py`: Added `web_order_id = order.get("order_id", "")` and appended `ref {web_order_id}` to VA01 details
- `transforms.conf`: Updated `extract_sap_sales_order` regex to capture `web_order_id` as auto-extracted field

**Before:** `Sales order for customer CUST-00019, 2 items, total $133.00`
**After:** `Sales order for customer CUST-00019, 2 items, total $133.00, ref ORD-2026-00456`

**Verification:** Generated 3 days, 96 VA01 events -- all 96 `ref ORD-*` values found in `order_registry.json`. Pass.

**Files changed:**
- `bin/generators/generate_sap.py` (line 301)
- `default/transforms.conf` (`extract_sap_sales_order` stanza)

---

## 2026-02-13 ~18:00 UTC -- Phase 14: Data Source Ingestion Reference Guide

Completely rewrote `docs/datasource_docs/REFERENCES.md` with full coverage of all 28+ data sources.

**Added:**
- Quick reference table with Splunk Add-on, Splunkbase ID, ingestion method, and sourcetype accuracy for every source
- 9 detailed "Sourcetype Accuracy Notes" documenting deliberate deviations from real TA sourcetypes
- Detailed references for 12 previously undocumented sources: ACI, Catalyst, Catalyst Center, Secure Access, Sysmon, MSSQL, SAP, Office 365 Audit, AWS GuardDuty, AWS Billing, Webex Devices, Webex REST API
- Ingestion architecture diagram (Syslog/API/UF flows)
- All Splunkbase URLs verified against live pages

**Files changed:**
- `docs/datasource_docs/REFERENCES.md` (complete rewrite)

---

## 2026-02-13 ~14:00 UTC -- Phase 13: docs/ Directory Reorganization

Reorganized the flat `docs/` directory (20+ files mixed together) into a clean subfolder structure.

### New structure

```
docs/
├── README.md              # Rewritten as navigation index
├── CHANGEHISTORY.md       # Stays at root
├── scenarios/             # 10 scenario guides + README (overview)
├── datasource_docs/       # 29 data source docs (unchanged)
├── reference/             # SPL queries, design language, floor plans, architecture
├── guides/                # Demo talking track, Docker setup
├── graphic/               # Floor plan images, logos (unchanged)
└── archive/               # 6 obsolete docs (old validations, changelog, checklist)
```

### File moves

| Action | From | To |
|--------|------|-----|
| Move (10 files) | `docs/*.md` (scenario docs) | `docs/scenarios/` |
| Move+Rename | `docs/scenario_overview.md` | `docs/scenarios/README.md` |
| Move (3 files) | `docs/splunk_queries.md`, `dashboard_design_language.md`, `floor_plan.md` | `docs/reference/` |
| Move+Rename | `docs/The FAKE T-Shirt Company...html` | `docs/reference/architecture.html` |
| Move+Rename | `docs/DEMO_TALKING_TRACK.md` | `docs/guides/demo_talking_track.md` |
| Move | `docs/Docker/docker.txt` | `docs/guides/docker_setup.md` |
| Move (6 files) | Stale docs (validation reports, old changelog, checklist) | `docs/archive/` |
| Delete | `docs/Docker/` | Empty directory removed |

### Other updates

- `docs/README.md` -- rewritten as directory index with all 10 scenarios, timeline, key personnel
- `CLAUDE.md` -- Repository Structure updated with new docs/ subfolder layout

### Files modified

| File | Change |
|------|--------|
| `docs/README.md` | Rewritten as navigation index |
| `CLAUDE.md` | Updated Repository Structure section |
| `docs/CHANGEHISTORY.md` | This entry |
| 26 files | Moved to new locations (see table above) |

---

## 2026-02-13 ~12:00 UTC -- Phase 12: Documentation Gaps (Office 365 Audit + Webex Cleanup)

### New: Office 365 Unified Audit Log documentation

Created `docs/datasource_docs/office_audit.md` -- comprehensive documentation for `generate_office_audit.py` (941-line generator):

- 3 workloads: SharePoint (25%), OneDrive (35%), Teams (40%)
- 30+ operation types across 6 RecordTypes (6, 7, 25, 14, 146, 18)
- ~170 events/peak hour at scale 1.0
- 8 SharePoint sites with department-based access control
- 9 Teams with 40+ channels
- 3 scenario integrations: exfil (Days 4-13, multi-phase data theft), ransomware_attempt (Days 8-9, encryption + recovery), phishing_test (Days 21-23, SafeLinks + admin review)
- 8 SPL use case queries, 4 talking points
- All SPL uses `index=fake_tshrt sourcetype="FAKE:o365:management:activity"`

### Deleted: Duplicate webex_meetings.md

Removed `docs/datasource_docs/webex_meetings.md` -- was a duplicate of `webex_ta.md`:
- Both documented the same generator (`generate_webex_ta.py`)
- Both covered the same sourcetypes (`cisco:webex:meetings:history:*`)
- `webex_ta.md` is more complete (includes scenario integration)

### README.md updates

- Added Office 365 Audit to Cloud & Identity table and Volume Summary
- Removed duplicate webex_meetings.md entry from Collaboration table
- Renamed webex_ta.md label from "Legacy" to primary

### Files modified

| File | Change |
|------|--------|
| `docs/datasource_docs/office_audit.md` | **NEW** -- comprehensive M365 Unified Audit Log documentation |
| `docs/datasource_docs/webex_meetings.md` | **DELETED** -- duplicate of webex_ta.md |
| `docs/datasource_docs/README.md` | Added office_audit, removed webex_meetings, updated volume summary |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-12 ~23:00 UTC -- Phase 11: Scenario Doc Updates + SPL Query Standardization

### Problem

Two documentation issues existed after Phases 8-10:

1. **Scenario docs were stale** -- exfil.md and cpu_runaway.md didn't reflect new AWS GuardDuty, AWS Billing, expanded GCP events, or registry changes (webex/linux added to exfil)
2. **SPL queries used wrong index/sourcetypes** -- ~275 SPL queries across ~40 docs used incorrect patterns (`index=network`, `index=cloud`, unprefixed sourcetypes) instead of `index=fake_tshrt` with `FAKE:` prefix

### Part A: Scenario content updates

**exfil.md -- Major update:**
- Added Days 6 credential pivot section documenting Jessica resetting Alex's password (WinEventLog 4724/4738) and MFA (Entra ID audit), explaining the IT Admin -> Finance privilege escalation
- Added GuardDuty findings to Days 8-10 (UnauthorizedAccess:IAMUser/MaliciousIPCaller, Persistence:IAMUser/UserPermissions)
- Added AWS Billing cost anomaly to Days 11-13 (S3 DataTransfer-Out 1.5x spike)
- Added GCP BigQuery exfil (Day 12, tabledata.list on customer_database) and cover tracks (Day 13, storage.objects.delete)
- Added "All Exfil Log Sources" table listing all 18 sources
- Added new SPL queries: GuardDuty findings, billing anomaly, GCP cover tracks, credential pivot events

**cpu_runaway.md -- GCP cascade added:**
- Added "Cross-Cloud Cascade (GCP)" section explaining SQL-PROD-01 -> BigQuery pipeline failure chain (RESOURCE_EXHAUSTED)
- Added GCP BigQuery SPL queries and talking point

**scenario_overview.md:**
- Updated exfil Primary Logs to include "GuardDuty, Billing, GCP Audit"
- Updated cpu_runaway Primary Logs to include "GCP Audit"

### Part B: SPL query standardization

Standardized all SPL queries across all documentation to use:
- `index=fake_tshrt` (replacing `index=network`, `index=cloud`, `index=windows`, `index=linux`, `index=web`, `index=retail`, `index=itsm`, `index=erp`, `index=servicebus`, `index=*`)
- `FAKE:` prefixed sourcetypes (e.g., `FAKE:cisco:asa` not `cisco:asa`)

### Part C: CLAUDE.md update

Added `FAKE:` prefix documentation rule to Development Notes section.

### Verification

```
Wrong index patterns (index=network/cloud/windows/linux/web/retail/itsm/erp/servicebus/*): 0 found
Non-FAKE sourcetypes in SPL: 0 found
Correct index=fake_tshrt references: 388 across 43 files
FAKE: prefix references: 471 across 44 files
```

### Files modified

**Scenario docs (12 files):**

| File | Changes |
|------|---------|
| `docs/exfil.md` | Major content update + SPL standardization |
| `docs/cpu_runaway.md` | GCP cascade content + SPL standardization |
| `docs/scenario_overview.md` | Updated Primary Logs + SPL standardization |
| `docs/ransomware.md` | SPL standardization (9 queries) |
| `docs/phishing_test.md` | SPL standardization (8 queries) |
| `docs/memory_leak.md` | SPL standardization (8 queries) |
| `docs/disk_filling.md` | SPL standardization (8 queries) |
| `docs/ddos_attack.md` | SPL standardization (8 queries) |
| `docs/firewall_misconfig.md` | SPL standardization (7 queries) |
| `docs/certificate_expiry.md` | SPL standardization (9 queries) |
| `docs/dead_letter_pricing.md` | SPL standardization (6 queries) |
| `docs/splunk_queries.md` | SPL standardization (~52 queries) |

**Datasource docs (26 files):**

| File | Changes |
|------|---------|
| `docs/datasource_docs/README.md` | SPL standardization (4 queries) |
| `docs/datasource_docs/cisco_asa.md` | SPL standardization |
| `docs/datasource_docs/meraki.md` | SPL standardization |
| `docs/datasource_docs/catalyst.md` | SPL standardization |
| `docs/datasource_docs/catalyst_center.md` | SPL standardization |
| `docs/datasource_docs/aci.md` | SPL standardization |
| `docs/datasource_docs/aws_cloudtrail.md` | SPL standardization |
| `docs/datasource_docs/aws_guardduty.md` | SPL standardization |
| `docs/datasource_docs/aws_billing.md` | SPL standardization |
| `docs/datasource_docs/gcp_audit.md` | SPL standardization |
| `docs/datasource_docs/entraid.md` | SPL standardization |
| `docs/datasource_docs/secure_access.md` | SPL standardization |
| `docs/datasource_docs/exchange.md` | SPL standardization |
| `docs/datasource_docs/wineventlog.md` | SPL standardization |
| `docs/datasource_docs/sysmon.md` | SPL standardization |
| `docs/datasource_docs/perfmon.md` | SPL standardization |
| `docs/datasource_docs/mssql.md` | SPL standardization |
| `docs/datasource_docs/linux.md` | SPL standardization |
| `docs/datasource_docs/access.md` | SPL standardization |
| `docs/datasource_docs/orders.md` | SPL standardization |
| `docs/datasource_docs/servicebus.md` | SPL standardization |
| `docs/datasource_docs/servicenow.md` | SPL standardization |
| `docs/datasource_docs/sap.md` | SPL standardization |
| `docs/datasource_docs/webex_api.md` | SPL standardization |
| `docs/datasource_docs/webex_devices.md` | SPL standardization |
| `docs/datasource_docs/webex_meetings.md` | SPL standardization |
| `docs/datasource_docs/webex_ta.md` | SPL standardization |

**Other docs (3 files):**

| File | Changes |
|------|---------|
| `docs/DEMO_TALKING_TRACK.md` | SPL standardization (29 queries) |
| `docs/README.md` | SPL standardization (2 queries) |
| `CLAUDE.md` | Added FAKE: prefix documentation rule |

**Total: 41 documentation files updated, ~300+ SPL queries standardized, 0 code changes.**

---

## 2026-02-13 ~07:30 UTC -- Phase 10: Registry Alignment + Entra ID Documentation

### Registry alignment (2 fixes)

Added sources to the exfil scenario that already had working scenario code but were missing from `registry.py`:

| Source | Evidence in generator |
|--------|-----------------------|
| `webex` | `EXFIL_USERS = {"jessica.brown", "alex.miller"}`, `should_tag_meeting_exfil()` tags meetings during Days 0-13 |
| `linux` | Imports `ExfilScenario`, calls `linux_cpu_anomaly()`, `linux_memory_anomaly()`, `linux_network_anomaly()`, tags with `demo_id="exfil"` |

Exfil scenario sources: 16 -> 18.

**Note:** Three other candidates (`access` -> exfil, `catalyst_center` -> disk_filling/firewall_misconfig) were investigated and rejected -- no scenario code exists in those generators. Registry entries without backing code would be misleading.

### Entra ID datasource documentation (entraid.md)

Rewrote `entraid.md` from a thin placeholder to comprehensive documentation for the richest identity source (1,905-line generator, 35+ event types, 3 scenarios):

- Sign-in events: interactive (35/peak hour), 5 MFA methods weighted, 10 client profiles, 7 error codes
- Service principal sign-ins: 5 SPs (SAP, Veeam, Splunk, GitHub, Nagios), 10-20/hour constant
- Audit events: user/group/app/role management, SSPR flows (5-10/day), CA policy updates
- Risk detection: 7 types (unfamiliarFeatures, anonymizedIPAddress, impossibleTravel, etc.)
- Password spray noise: ~6/day from 7 world IPs (Moscow, Beijing, Sao Paulo, etc.)
- Scenario integration: exfil (Days 4-14), ransomware_attempt (Days 8-9), phishing_test (Days 21-23)
- 10 SPL use case queries, 5 talking points, 6 admin accounts documented

### README.md scenario matrix update

- Renamed "Webex / TA" to "Webex" in scenario matrix
- Added X marks for webex + linux under exfil column (aligning with Phase 8-10 changes)

### Verification

```
Registry: 18 exfil sources (added webex, linux) -- confirmed sorted list matches
Webex + exfil (14 days): 26,076 events, 255 exfil-tagged
Linux + exfil (14 days): 131,820 events, 900 exfil-tagged (cpu: 252, interfaces: 252, iostat: 252, vmstat: 144)
Python compile check: registry.py passes
```

### Files modified

| File | Change |
|------|--------|
| `bin/scenarios/registry.py` | Added `webex`, `linux` to exfil sources (16 -> 18) |
| `docs/datasource_docs/entraid.md` | Rewritten -- comprehensive doc with sign-ins, audit, risk, scenarios, SPL queries, talking points |
| `docs/datasource_docs/README.md` | Updated scenario matrix for Phases 8-10 |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-13 ~06:00 UTC -- Phase 9: GCP Audit Log Generator Expansion

### GCP generator expansion (generate_gcp.py)

Added 6 new baseline event types (9 -> 15 event types), increased base rate from 12 to 15 events/peak hour:

| New Event | Service | Purpose |
|-----------|---------|---------|
| `WriteLogEntries` | Cloud Logging | App log ingestion baseline |
| `ListLogEntries` | Cloud Logging | Baseline + exfil Day 10 (attacker checks for detection) |
| `storage.objects.delete` | Cloud Storage | Baseline cleanup + exfil Day 13 (cover tracks) |
| `storage.buckets.get` | Cloud Storage | Bucket metadata queries |
| `TableDataService.List` | BigQuery | Table data reads + exfil Day 12 (second exfil channel) |
| `SetIamPolicy` | IAM | Baseline noise (makes exfil IAM changes harder to spot) |

Added scenario-specific events:

| Event | Scenario | Day | Description |
|-------|----------|-----|-------------|
| ListLogEntries (threat IP) | exfil | 10 | Attacker checks if SA creation was detected |
| BigQuery tabledata.list (threat IP) | exfil | 12 | Second exfil channel -- customer_database export |
| storage.objects.delete (threat IP) | exfil | 13 | Attacker deletes staging files to cover tracks (2-4 files) |
| BigQuery RESOURCE_EXHAUSTED | cpu_runaway | 11-12 | Data pipeline failure when SQL-PROD-01 is down |

### Registry update

- Added `gcp` to `cpu_runaway` scenario sources

### Verification

```
GCP baseline (7 days): 797 events, 15 unique methods
GCP + exfil (14 days): 1,655 events, 340 exfil tagged, threat IP events on Days 7-13
GCP + cpu_runaway (14 days): 1,639 events, 6 cpu_runaway tagged (BQ errors Days 11-12)
GCP + all scenarios (14 days): 1,659 events, 19 unique methods, exfil: 333, cpu_runaway: 6
```

### Files modified

| File | Change |
|------|--------|
| `bin/generators/generate_gcp.py` | 6 new event functions, 4 scenario functions, rebalanced distribution, scenario hooks, improved summary output |
| `bin/scenarios/registry.py` | Added `gcp` to cpu_runaway sources |
| `docs/datasource_docs/gcp_audit.md` | Rewritten with 15 event types, 2 scenarios, 9 SPL queries, talking points |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-13 ~04:00 UTC -- Phase 8: AWS CloudTrail expansion + GuardDuty + Billing

### New generators (2)

| File | Sourcetype | Format | Volume | Purpose |
|------|-----------|--------|--------|---------|
| `generate_aws_guardduty.py` | `FAKE:aws:cloudwatch:guardduty` | NDJSON | ~5-8 baseline + 3-6 scenario/day | Threat detection findings for exfil + ransomware scenarios |
| `generate_aws_billing.py` | `FAKE:aws:billing:cur` | CSV | 17 line items/day | Cost & Usage Report with DDoS/exfil cost spikes |

### CloudTrail expansion (generate_aws.py)

Added 7 new baseline event types (11 -> 18 event types), increased base rate from 15 to 20 events/peak hour:

| New Event | Service | Purpose |
|-----------|---------|---------|
| `RunInstances` | EC2 | Baseline + DDoS auto-scaling (Days 18-19) |
| `TerminateInstances` | EC2 | Instance lifecycle |
| `PutLogEvents` | CloudWatch Logs | Lambda log correlation |
| `GetSecretValue` | Secrets Manager | Baseline + exfil credential theft (Day 9) |
| `DescribeAlarms` | CloudWatch | Baseline + ops scenario monitoring |
| `StartConfigRulesEvaluation` | Config | Compliance check baseline |
| `PutEvaluations` | Config | Compliance results |

Added scenario-specific events:
- `SetAlarmState` for DDoS (WebServer-HighCPU), memory_leak (Lambda-ErrorRate), cpu_runaway (Database-ConnectionCount)
- `RunInstances` auto-scaling during DDoS (Days 18-19)
- `GetSecretValue` exfil credential theft (Day 9)

### Scenario integration updates (registry.py)

| Scenario | Sources added | Reason |
|----------|---------------|--------|
| exfil | `aws_guardduty`, `aws_billing` | GuardDuty detects IAM persistence + S3 exfil; billing shows S3 cost anomaly |
| ransomware_attempt | `aws_guardduty` | GuardDuty detects EC2 malicious IP |
| ddos_attack | `aws`, `aws_billing` | CloudWatch alarms + RunInstances auto-scaling; billing shows EC2/WAF cost spike |
| memory_leak | `aws` | CloudWatch Lambda-ErrorRate alarm |
| cpu_runaway | `aws` | CloudWatch Database-ConnectionCount alarm |

### Files modified

| File | Change |
|------|--------|
| `bin/generators/generate_aws.py` | +7 baseline event types, +3 scenario events, updated distribution, scenario hooks |
| `bin/generators/generate_aws_guardduty.py` | **NEW** -- GuardDuty findings generator |
| `bin/generators/generate_aws_billing.py` | **NEW** -- AWS billing CUR CSV generator |
| `bin/main_generate.py` | Registered 2 new generators, updated cloud source group |
| `bin/scenarios/registry.py` | Added aws/aws_guardduty/aws_billing to 5 scenario source lists |
| `bin/shared/config.py` | Added GENERATOR_OUTPUT_FILES entries for guardduty + billing |
| `default/inputs.conf` | Added 2 monitor stanzas for GuardDuty + Billing outputs |
| `default/props.conf` | Added 2 sourcetype definitions (FAKE:aws:cloudwatch:guardduty, FAKE:aws:billing:cur) |

### Verification

```
python3 bin/main_generate.py --sources=aws,aws_guardduty,aws_billing --scenarios=exfil,ddos_attack,ransomware_attempt --days=21 --test

  aws:           3,313 events (21 event types)  PASS
  aws_guardduty:   128 findings (baseline: 122, exfil: 5, ransomware: 1)  PASS
  aws_billing:     357 line items ($1,885 total, DDoS: $83 spike, Exfil: $7 anomaly)  PASS

Total: 3,798 events, 26 generators registered, 0 failures
```

---

## 2026-02-13 ~01:30 UTC -- Phase 7: Documentation completeness (HIGH priority items)

### Scenario documentation

Created 3 missing scenario walkthrough docs following existing pattern (timeline, SPL queries, talking points):

| File | Scenario | Content |
|------|----------|---------|
| `docs/ddos_attack.md` | DDoS Attack (Days 18-19) | Two-wave botnet attack, SD-WAN failover sequence, 9 affected sources, botnet IP lists |
| `docs/dead_letter_pricing.md` | Dead Letter Pricing (Day 16) | ServiceBus DLQ timeline, price error types, revenue impact, 4 affected sources |
| `docs/phishing_test.md` | Phishing Test (Days 21-23) | Campaign waves, response rates by location, narrative connection to exfil incident |

### Scenario overview update

Updated `docs/scenario_overview.md`:
- Extended timeline ASCII art from 14 days to 31 days (shows all 10 scenarios)
- Added 3 missing scenarios to matrix: phishing_test, ddos_attack, dead_letter_pricing
- Added certificate pre-warning markers (w) to timeline
- Added Ashley Griffin (phishing operator) and MX-BOS-01 to key personnel/servers
- Added botnet IPs and KnowBe4 platform to threat actors
- Updated demo order (9 scenarios) and outcome summary (10 scenarios)
- Added category-based SPL filters (attack, ops, network)

### Datasource documentation

Created 8 missing datasource docs following existing pattern (overview, key fields, examples, SPL queries, scenario integration, talking points):

| File | Source | Key Details |
|------|--------|-------------|
| `docs/datasource_docs/sysmon.md` | Microsoft Sysmon | 9 Event IDs, 7 servers + 20 workstations, exfil + ransomware scenarios |
| `docs/datasource_docs/mssql.md` | Microsoft SQL Server | ERRORLOG format, cpu_runaway + exfil scenarios, backup monitoring |
| `docs/datasource_docs/sap.md` | SAP S/4HANA | Pipe-delimited audit, order correlation, dead_letter_pricing tagging |
| `docs/datasource_docs/catalyst.md` | Cisco Catalyst | IOS-XE syslog, 3 switches, exfil/ddos/fw_misconfig scenarios |
| `docs/datasource_docs/aci.md` | Cisco ACI | 3 JSON types (fault/event/audit), spine-leaf fabric, exfil/ddos/cpu scenarios |
| `docs/datasource_docs/secure_access.md` | Cisco Secure Access | 4 CSV types (DNS/proxy/FW/audit), exfil/ransomware/phishing scenarios |
| `docs/datasource_docs/catalyst_center.md` | Cisco Catalyst Center | 4 JSON types (device/network/client/issues), ddos/cpu/memory scenarios |
| `docs/datasource_docs/webex_ta.md` | Webex Meetings TA | Meeting usage + attendee history, TA-compatible format |

Updated `docs/datasource_docs/README.md`:
- Added all 8 new docs to category tables (Network +2, Cloud +2, Collaboration +1, Windows +2, ERP +1)
- Updated Volume Summary with all new sources
- Expanded Scenario Integration matrix from 7 to 10 scenarios and 12 to 22 sources

### Summary

| Item | Count |
|------|-------|
| New scenario docs | 3 |
| New datasource docs | 8 |
| Updated docs | 2 (scenario_overview.md, datasource_docs/README.md) |
| Total docs coverage | Scenarios: 10/10 (was 7/10), Datasources: 26/26 (was 18/26) |

---

## 2026-02-13 ~00:30 UTC -- Phase 6b: DDoS failover + nightly backup traffic (2 fixes)

### Fix 6: DDoS SD-WAN failover events

**Problem**: DDoS scenario generated IDS alerts and health degradation but no SD-WAN failover events. When a WAN link is saturated, Meraki MX triggers an automatic failover to the backup WAN -- this was missing from the attack narrative.

| File | Change |
|------|--------|
| `bin/scenarios/network/ddos_attack.py` | Added failover logic to `meraki_hour()`: generates `sd_wan_failover` event (Comcast -> AT&T) when intensity crosses >= 0.8, and failback event (AT&T -> Comcast) when intensity drops below 0.5 after being >= 0.8. Uses previous-hour intensity comparison to fire only on transitions. |

**Verified**: 3 failover events in 20-day run:
- 08:02 -- Failover Comcast -> AT&T (full attack, intensity 1.0)
- 12:05 -- Failover Comcast -> AT&T (wave 2, intensity 0.8)
- 14:10 -- Failback AT&T -> Comcast (ISP filtering active, intensity drops to 0.4)

### Fix 7: BACKUP-ATL-01 nightly backup traffic

**Problem**: BACKUP-ATL-01 (10.20.20.20) exists as a server but generated zero ASA traffic. Nightly backup jobs from Atlanta to Boston (FILE-BOS-01) should produce SMB sessions on port 445 during the 22:00-04:00 backup window.

| File | Change |
|------|--------|
| `bin/generators/generate_asa.py` | Added `asa_backup_traffic()` function generating Built/Teardown SMB pairs from 10.20.20.20 -> 10.10.20.20:445. Active hours 22-23 (start: 3-5 sessions) and 00-03 (peak: 6-10, tail: 2-3). Large byte values (50-500MB). Called unconditionally in main loop as baseline traffic. |

**Verified**: 90 Built sessions over 3-day run (~30/night). Distribution: 22:00-23:00 = 3-5, 00:00-01:00 = 7-10, 02:00-03:00 = 2-3. All on port 445 with realistic large byte counts.

### Verification summary

| Fix | Generator | Events | Status |
|-----|-----------|--------|--------|
| 6. DDoS failover | meraki | 3,018,209 (3 failover) | PASS |
| 7. Nightly backup | asa | 103,967 (90 backup Built) | PASS |
| Syntax checks | 3 files | N/A | PASS |

---

## 2026-02-12 ~19:00 UTC -- Phase 6: Quick wins + scenario fixes (5 fixes)

### Fix 1: Memory leak gradual response time slowdown

**Problem**: Day 7 (1.2x multiplier) was **silently ignored** because `generate_access.py` only applied the multiplier when `should_error=True`. Day 6 had no access log impact at all despite being within scenario range.

| File | Change |
|------|--------|
| `bin/scenarios/ops/memory_leak.py` | Changed `start_day` from 6 to 5. Added Day 6 (index 5) case returning `(False, 0, 1.05)`. Changed Day 7 from `(False, 0, 1.2)` to `(True, 0, 1.2)` so access generator applies multiplier. |
| `bin/generators/generate_access.py` | Changed condition from `if should_error:` to `if should_error or mult > 1.0:` so response multiplier is applied even without error injection. Only tags `demo_id` when `should_error=True`. |
| `bin/scenarios/registry.py` | Updated memory_leak `start_day=6` to `start_day=5` |

**Verified**: Day 6 = 1.02x (subtle), Day 7 = 1.19x (was 1.0x!), Day 8 = 1.49x, Day 9 = 2.01x

### Fix 2: SAP scenario tagging from order_registry

**Problem**: `generate_sap.py` accepted `scenarios` parameter but never used it. Orders with `scenario` field in `order_registry.json` were not tagged in SAP output.

| File | Change |
|------|--------|
| `bin/generators/generate_sap.py` | Initialize `demo_id = None` per loop iteration. Extract `order.get("scenario")` in VA01 block. Pass `demo_id` to `_sap_event()` call. |

**Verified**: 22 SAP VA01 events tagged with `demo_id=dead_letter_pricing` in 31-day run.

### Fix 3: Certificate expiry pre-warning incidents

**Problem**: Certificate expires Day 13 with zero prior warnings. ServiceNow only had Day 12 (0-indexed) outage incidents.

| File | Change |
|------|--------|
| `bin/generators/generate_servicenow.py` | Added Day 5 and Day 9 to `SCENARIO_INCIDENTS["certificate_expiry"]` days list. Added P4 (7-day warning) and P3 (3-day reminder) incident templates. Updated existing outage close_notes to reference the ignored pre-warnings. |

**Verified**: 3 certificate_expiry incidents across Day 6, Day 10, Day 13 (pre-warnings + outage).

### Fix 4: Office Audit exfil -- jessica.brown in lateral phase + OneDrive staging

**Problem**: Exfil scenario used alex.miller for ALL phases including lateral movement (Days 5-7). Per attack timeline, jessica.brown (compromised IT admin) should be the actor during lateral movement. Also missing OneDrive data staging and sync events.

| File | Change |
|------|--------|
| `bin/generators/generate_office_audit.py` | Get `jessica.brown` reference. Lateral phase (Days 5-7) now uses `jessica` instead of `alex`. Added Finance to lateral sites. Added OneDrive FileUploaded events in persistence phase (Days 8-10, staging). Added FileSyncDownloadedFull events in exfil phase (Days 11-13, data extraction). |

**Verified**: 284 exfil events. jessica.brown=11 (lateral), alex.miller=273 (persistence+exfil). New operations: FileUploaded (2), FileSyncDownloadedFull (72).

### Fix 5: Ransomware cross-site effects (ASA deny + MX-BOS IDS)

**Problem**: Ransomware scenario only generated Austin events. No cross-site visibility when compromised machine (10.30.30.20) attempted to reach Boston servers via SD-WAN.

| File | Change |
|------|--------|
| `bin/scenarios/security/ransomware_attempt.py` | Added `crosssite_targets` to config (DC-BOS-01, FILE-BOS-01, SQL-PROD-01). Added `asa_crosssite_hour()` method (3 ASA Deny events to BOS servers on SMB/RDP/MSSQL). Added `meraki_crosssite_hour()` method (2 MX-BOS-01 IDS alerts for blocked AutoVPN traffic). Both only active during 14:08-14:15 lateral window. |
| `bin/generators/generate_asa.py` | Added call to `asa_crosssite_hour()` alongside existing `asa_hour()`. |
| `bin/generators/generate_meraki.py` | Added BOS location block for ransomware cross-site MX events. |

**Verified**: ASA = 3 new Deny events (10.30.30.20 -> DC-BOS-01:445, FILE-BOS-01:3389, SQL-PROD-01:1433). Meraki = 2 new MX-BOS-01 IDS alerts. All within 14:08-14:15 window.

### Verification summary

| Fix | Generator | Events | Status |
|-----|-----------|--------|--------|
| 1. Memory leak | access | 270,522 | PASS |
| 2. SAP tagging | access+orders+sap | 703,403 | PASS |
| 3. Cert pre-warnings | servicenow | 1,554 | PASS |
| 4. Office Audit exfil | office_audit | 19,059 | PASS |
| 5. Ransomware cross-site | asa+meraki | 2,627,043 | PASS |
| All syntax checks | 9 files | N/A | PASS |

---

## 2026-02-13 ~08:30 UTC -- ServiceBus: Fix tshirtcid field placement

### Problem

ServiceBus events had `tshirtcid` duplicated: once in the envelope (as `correlationId`) and once inside the `body` object. The field should only exist at the envelope level for Splunk field extraction.

### Changes

| File | Change |
|------|--------|
| `bin/generators/generate_servicebus.py` | Renamed `correlationId` to `tshirtcid` in all 6 event function envelopes. Removed duplicate `tshirtcid` from all 6 body dicts. Affects: `generate_dead_letter_event`, `generate_order_created`, `generate_payment_processed`, `generate_inventory_reserved`, `generate_shipment_created`, `generate_shipment_dispatched`. |

### Verification

- Syntax check: PASS
- Generated 1,321 ServiceBus events (1-day test run)
- `tshirtcid` at envelope level: 1,321/1,321 (100%)
- `tshirtcid` inside body: 0/1,321 (none)
- `correlationId` anywhere: 0 occurrences
- Correlation confirmed: all events for same order share same `tshirtcid` UUID

---

## 2026-02-13 ~07:00 UTC -- Phase 5: Architecture fixes (APP-BOS-01 traffic + Austin DC auth)

### Problem

Deep architecture analysis revealed two plot holes:

1. **APP-BOS-01 invisible in traffic flow**: Defined as e-Commerce API Server (IIS/.NET) -- the middle tier between WEB-01/02 and SQL-PROD-01. MSSQL generator already shows `svc_finance@10.10.20.40` connecting to SQL, but zero ASA/ACI evidence of this traffic existed.

2. **Austin users absent from DC auth events**: After Phase 4 #18 fix, `_location_for_server("DC-BOS-01")` returned "BOS" and `get_random_user(location="BOS")` returned only Boston's 93 users. Austin's 39 users (who auth against DC-BOS via SD-WAN) never appeared in any WinEventLog DC event.

### Changes

**Fix 1: APP-BOS-01 Internal Traffic**

| File | Change |
|------|--------|
| `bin/generators/generate_asa.py` | Added APP-BOS-01 to `NEW_SERVER_TRAFFIC` list (ports 443, 8443). Added `asa_internal_app_traffic()` function generating correlated WEB->APP (dmz->inside) and APP->SQL (inside->inside:1433) connection pairs. Integrated at 2% of baseline traffic distribution. |
| `bin/generators/generate_aci.py` | Added "Web-to-App" contract to both fault and audit contract lists (lines 297, 428) |

**Fix 2: Austin Users in DC-BOS Auth Events**

| File | Change |
|------|--------|
| `bin/shared/company.py` | Updated `get_random_user()` to accept `location` as str or list of str. Uses `in` operator instead of `==` for location filtering. Backward-compatible with all existing callers. |
| `bin/generators/generate_wineventlog.py` | Updated `_location_for_server()` to return `["BOS", "AUS"]` for BOS servers (was "BOS"). Austin users now appear in DC-BOS auth events proportionally (~30%). |

### Deferred findings (documented for future phase)

| Finding | Priority |
|---------|----------|
| DDoS: no Meraki SD-WAN failover events | Medium |
| certificate_expiry: no pre-expiry warnings | Low |
| BACKUP-ATL-01: no cross-site ASA traffic | Low |
| memory_leak: no gradual response time in access logs before Day 8 | Low |

### Verification

```
ASA APP-BOS-01 traffic (36,152 total events):
  - 1,982 events mentioning APP-BOS-01 (10.10.20.40)
  - 760 WEB->APP events (dmz:172.16.1.x -> inside:10.10.20.40)
  - 760 APP->SQL events (inside:10.10.20.40 -> inside:10.10.20.30:1433)

ACI Web-to-App contract:
  - 16 events with Web-to-App contract references

WinEventLog DC-BOS user distribution (107 DC auth events):
  - DC-BOS: 54 BOS users (71.1%) + 22 AUS users (28.9%)
  - DC-ATL: 31/31 ATL users (100%, no leakage)

All 4 modified files pass Python syntax check.
```

---

## 2026-02-13 ~05:00 UTC -- Phase 4 #17: VPN IP-pool correlation + #18: User-location filtering

### Problem

**#17 - VPN IP-pool correlation:**
ASA VPN pool IPs were generated randomly at runtime (`init_vpn_pool()` created 2-3 random IPs per user per run). These IPs existed only in ASA generator memory -- Secure Access had no way to know what VPN IP a user was assigned, making cross-generator VPN session correlation impossible.

**#18 - User-location filtering:**
`get_random_user()` in WinEventLog picked from all 175 users regardless of server location. This produced unrealistic events like Austin users (10.30.x.x) appearing in `DC-BOS-01` logon events, or Boston users in `DC-ATL-01` Kerberos tickets.

### Changes

**#17: Deterministic VPN IPs via company.py**

| File | Change |
|------|--------|
| `bin/shared/company.py` | Added `vpn_ip` property to `User` class -- deterministic via SHA256 hash of username, producing stable IPs in `10.250.0.{10-209}` range. Only meaningful for users with `vpn_enabled=True`. |
| `bin/generators/generate_asa.py` | Replaced random VPN pool with deterministic IPs. `init_vpn_pool()` now sets `user.vpn_ip` as assigned IP (kept random external "connecting from" IPs). VPN session events (722022/722023) now emit deterministic 10.250.0.x addresses. |
| `bin/generators/generate_secure_access.py` | Added 15% VPN IP injection for both DNS and Proxy events. When a VPN-enabled user generates an event and `random.random() < 0.15`, `InternalIp` uses `user.vpn_ip` instead of desk IP. Simulates remote workers routing through VPN tunnel. |

**#18: Location-based user filtering in WinEventLog**

| File | Change |
|------|--------|
| `bin/generators/generate_wineventlog.py` | Added `_location_for_server()` helper (ATL servers -> "ATL", all others -> "BOS"). Updated 5 `get_random_user()` call sites to filter by server location: `generate_baseline_logons`, `generate_baseline_failed_logons`, `generate_baseline_kerberos`, `generate_baseline_ntlm_validation`, `generate_baseline_account_lockouts`. Pattern: pick DC/computer first, then `get_random_user(location=_location_for_server(computer))`. |

### Verification

```
ASA VPN test (928 events):
  - 122 unique VPN users, 91 unique IPs
  - ALL IPs in 10.250.0.x subnet

Secure Access DNS (42,642 events):
  - 4,325 events with VPN IP (10.1%)
  - 122 unique VPN users

Secure Access Proxy (13,650 events):
  - 1,457 events with VPN IP (10.7%)

Cross-generator VPN correlation:
  - 122 users in both ASA and Secure Access
  - 122/122 matching IPs (100% correlation)

WinEventLog location accuracy (112 DC auth events):
  - DC-ATL-01: 38/38 correct (10.20.x.x) -- 100%
  - DC-BOS-01/02: 74/74 correct (10.10.x.x) -- 100%

All 4 modified files pass Python syntax check.
```

---

## 2026-02-13 ~03:00 UTC -- Scenario timeline rescheduling + revenue impact improvement

### Problem

1. Multiple ops/network scenarios overlapped on the same days, making it hard to isolate individual scenarios in Splunk demos
2. Web store revenue (orders) was not visibly affected by most scenarios -- only cpu_runaway and certificate_expiry showed clear impact

### Timeline changes (0-indexed -> 1-indexed days)

| Scenario | Old days | New days | Reason |
|----------|----------|----------|--------|
| memory_leak | 6-9 | **7-10** | Moved +1 day to avoid overlap with firewall_misconfig |
| firewall_misconfig | 7 | **6** | Moved -1 day to fill gap after disk_filling |
| certificate_expiry | 12 | **13** | Moved +1 day to avoid overlap with cpu_runaway |

New non-overlapping timeline (ops/network only):
- Day 1-5: disk_filling (MON-ATL-01)
- Day 6: firewall_misconfig (FW-EDGE-01)
- Day 7-10: memory_leak (WEB-01, OOM crash Day 10)
- Day 11-12: cpu_runaway (SQL-PROD-01)
- Day 13: certificate_expiry (FW-EDGE-01)
- Day 16: dead_letter_pricing (WEB-01)
- Day 18-19: ddos_attack (WEB-01)

Attack scenarios (exfil d1-14, ransomware d8-9, phishing d21-23) may overlap with ops/network -- this is intentional.

### Revenue impact improvement

Added session volume reduction in `generate_access.py` during high-error periods. Previously only individual page requests got error codes, but session count stayed constant. Now:
- error_rate >= 40%: sessions reduced to 30% (severe outage)
- error_rate >= 20%: sessions reduced to 50% (major issues)
- error_rate >= 8%: sessions reduced to 75% (moderate degradation)

Combined with per-page error rates, this creates clearly visible revenue drops:
- cpu_runaway Day 11: **48% fewer orders** (145 vs ~280 normal)
- memory_leak OOM Day 10: **visible crash at 14:00** with near-zero orders hours 3-10
- certificate_expiry Day 13: **zero orders 00:00-06:00** (SSL outage, already worked)

### Files modified

| File | Change |
|------|--------|
| `bin/scenarios/registry.py` | Updated start_day/end_day for memory_leak (6-9), firewall_misconfig (5), certificate_expiry (12) |
| `bin/scenarios/ops/memory_leak.py` | Shifted all day references +1 (config, memory progression dict, conditionals, severity, print_timeline) |
| `bin/scenarios/network/firewall_misconfig.py` | Changed day from 6 to 5, updated docstring |
| `bin/scenarios/network/certificate_expiry.py` | Changed day from 11 to 12, updated docstring |
| `bin/generators/generate_servicenow.py` | Updated SCENARIO_INCIDENTS day arrays for all 3 scenarios |
| `bin/generators/generate_access.py` | Added session volume reduction logic during high-error scenarios |
| `bin/main_generate.py` | Updated help text with new scenario days |
| `CLAUDE.md` | Updated scenario table and descriptions with new days |

### Verification

- `python3 bin/main_generate.py --sources=access,orders --scenarios=all --days=14 --test` -> 267,798 events, PASS
- Zero overlapping days between ops/network scenarios confirmed
- All files pass Python syntax check
- Revenue impact clearly visible in per-day order counts

---

## 2026-02-13 ~01:00 UTC -- Phase 4: Cross-generator MAC correlation for ACI and Catalyst

### Problem

ACI and Catalyst generators used fully random MAC addresses (`_random_mac()`), making it impossible to correlate network events with specific servers or users across generators. Meraki already used deterministic MACs via `get_mac_for_ip()` from company.py, but ACI and Catalyst did not.

### Changes

| File | Change |
|------|--------|
| `bin/generators/generate_aci.py` | Added `get_mac_for_ip` import. Updated `_random_mac()` to accept optional `ip` parameter -- returns deterministic MAC for known IPs (lowercase, ACI format). Added `_dc_ip_or_random()` helper (70% known datacenter IPs, 30% random). Updated `_generate_fault_event()` and `_generate_event()` to use real server IPs and MACs. |
| `bin/generators/generate_catalyst.py` | Added `get_mac_for_ip` import. Updated `_generate_auth_event()` -- 80% of 802.1X auth events now use real user MACs from matching location. Updated `_generate_switch_event()` -- 50% of port events use real user MACs. Both use `user.mac_address` from company.py for deterministic correlation with EntraID sign-in logs. |

### Verification

- `python3 bin/main_generate.py --sources=aci --days=1 --test --quiet` -- 1996 events, PASS
- `python3 bin/main_generate.py --sources=catalyst --days=1 --test --quiet` -- 1001 events, PASS
- ACI events contain deterministic server MACs: `dc:71:96:5f:d3:1b` (SQL-PROD-01), `48:51:b7:fb:bc:69` (SAP-DB-01), `80:86:f2:33:2c:8d` (APP-BOS-01), etc.
- Catalyst 802.1X events contain deterministic user MACs matching EntraID sign-in logs
- Both generators pass Python syntax check

---

## 2026-02-12 ~23:30 UTC -- Phase 2: Fix hostname mismatches across WinEventLog + exfil scenario

### Problem

WinEventLog generator and exfil scenario used non-canonical hostnames that didn't match `company.py` SERVERS dict. This broke cross-generator hostname correlation in Splunk (`demo_host` field wouldn't match across sourcetypes).

### Hostname corrections

| Wrong (before) | Correct (after) | Files affected |
|----------------|-----------------|----------------|
| `BOS-FILE-01` | `FILE-BOS-01` | generate_wineventlog.py, exfil.py |
| `BOS-SQL-PROD-01` | `SQL-PROD-01` | generate_wineventlog.py |
| `BOS-DC-01` | `DC-BOS-01` | generate_wineventlog.py, exfil.py |
| `ATL-DC-01` | `DC-ATL-01` | exfil.py |
| `ATL-FILE-01` | (removed -- no file server in Atlanta) | generate_wineventlog.py |
| `DC-01` / `DC-02` | `DC-BOS-01` / `DC-BOS-02` | generate_wineventlog.py |

### Files modified

| File | Change |
|------|--------|
| `bin/generators/generate_wineventlog.py` | Fixed 7 hostname references in WINDOWS_SERVICES dict, baseline generators, and format_scenario_event default |
| `bin/scenarios/security/exfil.py` | Fixed all `BOS-FILE-01` -> `FILE-BOS-01`, `BOS-DC-01` -> `DC-BOS-01`, `ATL-DC-01` -> `DC-ATL-01` in computer fields, UNC paths, and Kerberos SPN strings |
| `bin/generators/generate_perfmon.py` | Fixed docstring reference `BOS-SQL-PROD-01` -> `SQL-PROD-01` |

### Verification

- `python3 bin/main_generate.py --sources=wineventlog --days=1 --scenarios=exfil --test --quiet` -> 596 events, PASS
- All ComputerName values match company.py: DC-BOS-01, DC-BOS-02, DC-ATL-01, FILE-BOS-01, SQL-PROD-01, APP-BOS-01, BACKUP-ATL-01, WEB-01, WEB-02
- Zero instances of old hostname patterns remain in `bin/` directory

---

## 2026-02-12 ~23:00 UTC -- Phase 1: Quick fixes from project audit

### Summary

Six quick fixes from comprehensive project audit addressing inconsistencies and orphaned config.

### Changes

1. **ServiceNow default scenario** (`bin/generators/generate_servicenow.py` line 1769): Changed `scenarios: str = "all"` to `scenarios: str = "none"`. Was the only generator defaulting to "all", causing unexpected scenario events when running without `--scenarios` flag.

2. **Epilog generator count** (`bin/main_generate.py`): Updated `"all - All sources (19 generators)"` to `"all - All sources (24 generators)"`. Added missing source groups (campus, datacenter, itsm, erp) and individual sources (secure_access, catalyst, aci, catalyst_center) to help text.

3. **ALL_SOURCES list** (`bin/scenarios/registry.py` line 33): Expanded from 9 sources to all 24 generators to match actual codebase.

4. **CLAUDE.md exfil sources** (`CLAUDE.md`): Fixed exfil affected sources list -- removed `meraki` (not in registry), added `servicenow`, `mssql`, `sysmon` to match registry.py.

5. **.gitignore cleanup** (`.gitignore`): Removed legacy path `/TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/output` (wrong nesting level).

6. **PerfmonMk orphan stanza** (`default/props.conf`): Removed `[FAKE:PerfmonMk:Processor]` stanza -- no corresponding input, transform, or generator exists.

### Files modified

| File | Change |
|------|--------|
| `bin/generators/generate_servicenow.py` | Default scenarios "all" -> "none" |
| `bin/main_generate.py` | Epilog: 19->24 generators, added missing groups/sources |
| `bin/scenarios/registry.py` | ALL_SOURCES expanded to 24 entries |
| `CLAUDE.md` | Exfil sources corrected |
| `.gitignore` | Removed legacy path |
| `default/props.conf` | Removed orphaned PerfmonMk stanza |

---

## 2026-02-12 ~22:00 UTC -- Fix scenario timeline overlap + Boston Core SVG layout

### File: `TA-FAKE-TSHRT/docs/architecture.html`

1. **Scenario Timeline**: Replaced overlapping full-height bars with 3-row swim-lane Gantt chart (Attack/Ops/Network rows). Each category has its own horizontal lane with fixed 24px bar height, eliminating all visual collisions.

2. **Boston Core box**: Expanded BOSTON CORE rect from x=590 to x=400 so DC-BOS-01/02 are visually inside the box (they share the 10.10.20.x subnet).

3. **Auth bus bar**: Extended width from 580 to 730 to cover FILE-BOS-01's auth stub at x=1105. Re-centered label text.

4. **ASA to Bastion path**: Replaced generic "Internal" arrow with realistic VPN/SSH management flow: ASA right edge -> BASTION-BOS-01 (orthogonal L-path with "VPN / SSH" label). Added dashed SSH Management lines from Bastion to SAP-PROD-01 and SAP-DB-01, showing jump box access pattern.

5. **SVG render order**: Moved BOSTON CORE background rect before DC-BOS-01/02 elements so DCs are not hidden behind the box (SVG painter's model).

6. **DC positions**: Moved DC-BOS-01 from y=280 to y=310 and DC-BOS-02 from y=335 to y=365 so they don't overlap with BOSTON CORE label. Updated DC replication line endpoints accordingly.

7. **SSH Management bus**: Replaced individual Bastion-to-server lines with a horizontal SSH Management bus bar (y=430) mirroring the AD Auth bus pattern. Bastion feeds the bus, stubs go up to SAP-PROD-01, SAP-DB-01, and DCs.

8. **Section repositioning**: Shifted Atlanta (y=490->530), SD-WAN (y=490->530), Austin (y=490->530), Cloud Dependencies (y=650->690), and Connection Legend (y=790->830) down by 40px to accommodate taller Boston Core box (height 200->220). Updated AD Replication and SQL Backup path endpoints. ViewBox height 950->1000.

---

## 2026-02-12 ~16:00 UTC -- Complete redesign of architecture.html

### Summary

Rewrote `TA-FAKE-TSHRT/docs/architecture.html` (1535 lines, 92KB) with the following improvements:

1. **Layout redesign**: Expanded SVG viewBox from 1200x920 to 1440x1060. Reorganized Overview SVG into 6 horizontal layers (Internet -> Cloud -> Perimeter -> SD-WAN Backbone -> 3 Site Columns -> Log Generators). Increased gaps between site columns from 20px to 80-120px for much better readability.

2. **Orthogonal connections**: Replaced all diagonal SVG lines with Manhattan-routed `<path>` elements through a dedicated SD-WAN backbone band. AutoVPN mesh, Catalyst Center management, and ASA connections now route cleanly without crossing.

3. **Hover tooltip system**: Added JS-driven tooltip that appears on mouseover for all SVG components. Each component wrapped in `<g class="hoverable">` with `data-tt-title`, `data-tt-body`, `data-tt-detail` attributes. Shows hostname, IP, role, scenarios, and generators. Pipe-delimited details render as multi-line.

4. **Data corrections**:
   - Stats row: 19 Servers -> 13, 20 Generators -> 24, removed "+4 New" box
   - Boston tab: 14 servers -> 10 (removed phantom WSUS, RADIUS, PROXY, PRINT)
   - Atlanta tab: 5 servers -> 3 (removed phantom DEV-ATL-01/02)
   - Removed entire "Planned Expansion" toggle bar and all NEW/Planned badges
   - Secure Access, Catalyst, ACI, Catalyst Center now shown as standard infrastructure

5. **Server Connections SVG**: Replaced DC auth fan-out (diagonal lines to every server) with horizontal AD/Kerberos/LDAP bus-bar with vertical stubs. Orthogonal data flow arrows for HTTP API, SQL, SMB, HANA, backup paths.

6. **Scenario timeline bar**: Added visual 31-day timeline in Scenarios tab showing colored bars for each scenario with day ranges and category colors (red=attack, blue=ops, orange=network).

7. **Log generators legend**: Moved from inside SVG to HTML `<div>` below diagram with grid layout showing all 24 generators and their sourcetypes.

### Files Modified

| File | Change |
|------|--------|
| `TA-FAKE-TSHRT/docs/architecture.html` | Complete rewrite (1535 lines) |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-12 ~05:00 UTC -- Add 4 new Cisco generators (Secure Access, Catalyst, ACI, Catalyst Center)

### Summary

Added 4 new Cisco data source generators, expanding from 20 to 24 generators and adding 12 new output files across 12 new Splunk sourcetypes. Total new events: ~140K-175K/day (mostly Secure Access DNS).

1. **Cisco Secure Access** (`generate_secure_access.py`): SSE/SASE platform generating 4 CSV files:
   - DNS logs (v10, 16 columns, ~100K-120K/day) -- `FAKE:cisco:umbrella:dns`
   - Proxy/SWG logs (v5, 26 columns, ~25K-40K/day) -- `FAKE:cisco:umbrella:proxy`
   - Cloud Firewall logs (14 columns, ~8K/day) -- `FAKE:cisco:umbrella:firewall`
   - Audit logs (9 columns, ~15/day) -- `FAKE:cisco:umbrella:audit`
   - Scenarios: exfil (DNS C2, proxy uploads), ransomware_attempt (DNS+proxy blocks), phishing_test (DNS queries)

2. **Cisco Catalyst IOS-XE** (`generate_catalyst.py`): 3 Catalyst 9300 switches generating 1 syslog file:
   - IOS-XE syslog with PRI values (~3K/day) -- `FAKE:cisco:ios`
   - 3 switches: CAT-BOS-DIST-01/02 (Boston), CAT-ATL-DIST-01 (Atlanta)
   - Event types: Interface, 802.1X/Auth, System, STP, Switch/Platform
   - Scenarios: exfil (MAC flap, 802.1X), ddos_attack (interface util), firewall_misconfig (STP)

3. **Cisco ACI** (`generate_aci.py`): APIC REST API format generating 3 JSON files:
   - Faults (faultInst, ~500-1000/day) -- `FAKE:cisco:aci:fault`
   - Events (eventRecord, ~2000-3500/day) -- `FAKE:cisco:aci:event`
   - Audit (aaaModLR, ~30-50/day) -- `FAKE:cisco:aci:audit`
   - BOS fabric: 2 spines, 4 leafs, 1 APIC; ATL fabric: 1 spine, 2 leafs
   - Scenarios: exfil (contract denies, EP anomalies), ddos_attack (border leaf), cpu_runaway (EPG congestion)

4. **Cisco Catalyst Center** (`generate_catalyst_center.py`): Assurance API generating 4 JSON files:
   - Device Health (5-min polls, ~864/day) -- `FAKE:cisco:catalyst:devicehealth`
   - Network Health (5-min polls, ~576/day) -- `FAKE:cisco:catalyst:networkhealth`
   - Client Health (~100/day) -- `FAKE:cisco:catalyst:clienthealth`
   - Issues (~10-30/day) -- `FAKE:cisco:catalyst:issue`
   - Scenarios: ddos_attack (health drops, issues), cpu_runaway (CPU issues), memory_leak (client health)

### Verification

- `--all --days=3 --scenarios=all --test`: 930,984 events, 24 generators, 0 failures, PASS
- All 4 new generators tested standalone + through orchestrator
- Scenario integration verified: demo_id tagging present on all scenario events
- All baseline events have `demo_id: ""` for consistent field extraction

### New Files

| File | Description |
|------|------------|
| `bin/generators/generate_secure_access.py` | Cisco Secure Access (Umbrella) -- 4 CSV output files |
| `bin/generators/generate_catalyst.py` | Cisco Catalyst IOS-XE -- 1 syslog output file |
| `bin/generators/generate_aci.py` | Cisco ACI (APIC) -- 3 JSON output files |
| `bin/generators/generate_catalyst_center.py` | Cisco Catalyst Center -- 4 JSON output files |

### Modified Files

| File | Change |
|------|--------|
| `bin/shared/config.py` | Added 11 FILE_* constants, 4 GENERATOR_OUTPUT_FILES entries, 4 FILE_CATALYST_CENTER_* constants |
| `bin/main_generate.py` | Imported 4 generators, added to GENERATORS dict, updated SOURCE_GROUPS (cisco, network, campus, datacenter) |
| `bin/scenarios/registry.py` | Added new generators to scenario source lists (exfil, ddos_attack, cpu_runaway, memory_leak, ransomware_attempt, phishing_test, firewall_misconfig) |
| `default/inputs.conf` | Added 12 new [monitor:] stanzas for all new sourcetypes |
| `default/props.conf` | Added 12 new sourcetype stanzas (4 Umbrella CSV, 3 ACI JSON, 4 Catalyst Center JSON, 1 IOS-XE syslog) |
| `default/transforms.conf` | Added `catalyst_host_extraction` transform for IOS-XE syslog host routing |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-12 ~02:00 UTC -- Infrastructure cleanup (19->13 servers) + output directory restructuring + props.conf bugfix

### Summary

Three pre-requisite changes before adding new Cisco generators:

1. **Infrastructure cleanup (19->13 servers)**: Removed 6 servers that were unused, redundant, or unrealistic for a 175-person company in 2026:
   - **WSUS-BOS-01** -- Intune/Autopatch in 2026, baseline-only events
   - **RADIUS-BOS-01** -- Zero generators referenced it
   - **PROXY-BOS-01** -- Replaced by upcoming Cisco Secure Access (SWG)
   - **PRINT-BOS-01** -- Universal Print in 2026, not referenced
   - **DEV-ATL-01** -- Only generated cron-noise + 1 EntraID CI/CD login
   - **DEV-ATL-02** -- Only generated logrotate cron

   APP-BOS-01 role clarified as "e-Commerce API Server" in 3-tier architecture (WEB->APP->SQL).

2. **Output directory restructuring**: Organized flat output directories into logical subdirectories:
   - `cloud/` split into: `cloud/aws/`, `cloud/entraid/`, `cloud/gcp/`, `cloud/microsoft/`, `cloud/webex/`
   - `network/` split into: `network/cisco_asa/`, `network/meraki/`
   - Updated `get_output_path()` to auto-create nested subdirectories
   - All 20 generators, config.py, and inputs.conf updated

3. **props.conf bugfix**: `[FAKE:online:order]` TIME_PREFIX changed from `"updatedAt"` to `"timestamp"` (the orders generator uses `"timestamp"`, not `"updatedAt"`).

### Verification

- `--all --days=1 --scenarios=none --test`: 267,492 events, all 44 output files in new directory structure, PASS

### Files Changed

| File | Change |
|------|--------|
| `bin/shared/company.py` | Removed 6 servers from `_SERVER_DATA`, renamed APP-BOS-01 role |
| `bin/shared/config.py` | Updated FILE_* constants and GENERATOR_OUTPUT_FILES with subdirectory paths, enhanced `get_output_path()` |
| `bin/generators/generate_linux.py` | Removed DEV-ATL-01/02, PROXY-BOS-01 from cron jobs and systemd services |
| `bin/generators/generate_sysmon.py` | Removed WSUS/RADIUS/PRINT from SYSMON_SERVERS and SERVER_PROCESSES |
| `bin/generators/generate_perfmon.py` | Removed WSUS/RADIUS/PRINT from SERVER_RAM_MB and SERVER_DISK_GB |
| `bin/generators/generate_entraid.py` | Remapped CI/CD service principal IP from DEV-ATL-01 to MON-ATL-01 |
| `bin/generators/generate_asa.py` | Removed WSUS/PROXY from server traffic, updated comments |
| `bin/generators/generate_aws.py` | Updated output path to `cloud/aws/` subdirectory |
| `bin/generators/generate_gcp.py` | Updated output path to `cloud/gcp/` subdirectory |
| `bin/generators/generate_exchange.py` | Updated output path to `cloud/microsoft/` subdirectory |
| `bin/generators/generate_office_audit.py` | Updated output path to `cloud/microsoft/` subdirectory |
| `bin/generators/generate_webex.py` | Updated output path to `cloud/webex/` subdirectory |
| `bin/generators/generate_webex_ta.py` | Updated output path to `cloud/webex/` subdirectory |
| `bin/generators/generate_webex_api.py` | Updated output path to `cloud/webex/` subdirectory |
| `bin/generators/generate_meraki.py` | Updated output path to `network/meraki/` subdirectory |
| `lookups/asset_inventory.csv` | Removed 6 server rows |
| `lookups/mac_inventory.csv` | Removed 6 server rows |
| `default/inputs.conf` | Rewrote with new subdirectory paths + directory structure documentation |
| `default/props.conf` | Fixed `[FAKE:online:order]` TIME_PREFIX from `"updatedAt"` to `"timestamp"` |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-12 ~01:30 UTC -- Fix demo_id placement in ServiceBus + WinEventLog/Sysmon

### Summary

Two field placement fixes:

1. **ServiceBus**: `demo_id` moved from inside `body` object to top-level JSON (was `body.demo_id`, now `demo_id`). Affects `generate_servicebus.py` -- 5 occurrences.

2. **WinEventLog + Sysmon**: `demo_id` moved from bottom of multiline events to immediately after the `Type=<xyz>` line. This makes it visible early in the event header rather than buried at the end. Affects:
   - `generate_wineventlog.py`: New `_insert_demo_id()` helper function, replaced 14 append patterns
   - `generate_sysmon.py`: Updated `_wrap_kv_event()` to insert after `Type=` line
   - `ransomware_attempt.py`: Moved `demo_id=` in 5 f-string templates
   - `phishing_test.py`: Moved `demo_id=` in 1 f-string template

### Files Changed

| File | Change |
|------|--------|
| `bin/generators/generate_servicebus.py` | Changed `event["body"]["demo_id"]` to `event["demo_id"]` (5 occurrences) |
| `bin/generators/generate_wineventlog.py` | Added `_insert_demo_id()` helper, replaced 14 append patterns |
| `bin/generators/generate_sysmon.py` | Updated `_wrap_kv_event()` to insert demo_id after Type= line |
| `bin/scenarios/security/ransomware_attempt.py` | Moved demo_id from end to after Type= in 5 templates |
| `bin/scenarios/security/phishing_test.py` | Moved demo_id from end to after Type= in 1 template |
| `bin/scenarios/ops/dead_letter_pricing.py` | Moved demo_id from body to top-level in DLQ events |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-12 ~00:30 UTC -- Implement phishing_test scenario (Days 21-23)

### Summary

New attack scenario: IT Security (ashley.griffin) runs a KnowBe4-style phishing awareness campaign following the real APT exfil incident discovered on Day 12. All 175 employees receive a simulated "Microsoft 365 password expires in 24 hours" email. Waves sent at 09:00 (BOS), 10:00 (ATL), 11:00 (AUS) on Day 21. Deterministic participant selection ensures consistent 53 clickers (31%) and 17 credential submitters (10%) across all generators. Day 23: training emails sent to clickers, results compiled.

### Scenario Timeline

| Day | Time | Event |
|-----|------|-------|
| 21 (idx 20) | 09:00-11:00 | Campaign emails sent in 3 waves (175 total) |
| 21 (idx 20) | 12:00+ | First clicks begin (35 on Day 21) |
| 22 (idx 21) | all day | Late clickers (18 more on Day 22) |
| 23 (idx 22) | 10:00 | Admin reviews results |
| 23 (idx 22) | 11:00 | Training emails sent to 53 clickers |

### Expected Event Counts

| Source | Events | Description |
|--------|--------|-------------|
| Exchange | ~230 | 175 sim emails + 53 training emails |
| Entra ID | ~17 | Credential submitters sign-in from sim platform IP |
| WinEventLog | ~53 | 4688 process creation (OUTLOOK.EXE -> browser with sim URL) |
| Office 365 Audit | ~56 | SafeLinks clicks (53) + admin review (3) |
| ServiceNow | ~15 | 2 incidents (deployment + results) + 1 change (pre-approval) |

### Files Changed

| File | Change |
|------|--------|
| `bin/scenarios/security/phishing_test.py` | **NEW** -- Scenario class with deterministic participant selection |
| `bin/scenarios/security/__init__.py` | Added PhishingTestScenario export |
| `bin/scenarios/registry.py` | Set `implemented=True`, added `servicenow` to sources |
| `bin/generators/generate_exchange.py` | Import + init + hour loop injection for sim/training emails |
| `bin/generators/generate_entraid.py` | Dynamic import + init + signin injection for credential submitters |
| `bin/generators/generate_wineventlog.py` | Import + init + security_events injection for browser launches |
| `bin/generators/generate_office_audit.py` | Inlined `_phishing_test_events_for_hour()` function (SafeLinks + admin) |
| `bin/generators/generate_servicenow.py` | Added incidents, change, updated attack category filter |
| `bin/main_generate.py` | Updated epilog (removed [PLANNED], added sources) |
| `docs/CHANGEHISTORY.md` | This entry |

---

## 2026-02-11 ~20:00 UTC -- Implement ddos_attack scenario (Days 18-19)

### Summary

New network scenario: Volumetric HTTP flood targeting DMZ web servers (WEB-01/WEB-02) on Days 18-19 (Jan 18-19). A botnet launches probing at 02:00, ramps to full attack by 08:00 (~200 ASA events/hour), triggering rate limiting and IDS alerts. NOC applies emergency ACLs at 10:00 (wave 1 blocked), but attacker adapts with new IPs at 12:00 (wave 2). ISP-level DDoS filtering activated at 14:00. Attack subsides by 18:00 with residual traffic overnight. Fully stopped by 06:00 Day 19.

Revenue impact is automatic: 60% error_rate at peak causes ~60% of checkout attempts to return HTTP 503, naturally reducing orders generated.

### Scenario Timeline

```
Day 18 (index 17):
  02:00  Probing from wave 1 botnet IPs (intensity 0.05)
  06:00  Volume ramps up (intensity 0.3)
  08:00  Full-scale attack (intensity 1.0) -- ASA rate limiting
  09:00  ServiceNow P1 auto-created
  10:00  Emergency ACL blocks wave 1 subnets (intensity 0.5)
  12:00  Wave 2 -- new botnet IPs (intensity 0.8)
  14:00  ISP DDoS filtering activated (intensity 0.4)
  18:00  Mostly over (intensity 0.1 residual)

Day 19 (index 18):
  00:00-05:00  Residual traffic (intensity 0.05)
  06:00  Attack fully stopped
  10:00  Change request: permanent DDoS mitigation
```

### Attack Design

Two waves of 10 botnet IPs each from diverse global subnets. Single `_get_attack_intensity(day, hour)` function (0.0-1.0) drives all generators.

### Files Created

- `bin/scenarios/network/ddos_attack.py` -- New scenario class (~470 lines) with DdosAttackConfig dataclass and DdosAttackScenario class. Methods: `_get_attack_intensity()`, `_get_botnet_ips()`, `is_active()`, `generate_hour()` (ASA events), `access_should_error()`, `meraki_hour()` (IDS + SD-WAN), `linux_cpu_adjustment()`, `linux_network_multiplier()`, `perfmon_cpu_adjustment()`, `get_demo_id()`

### Files Modified

- `bin/scenarios/network/__init__.py` -- Added DdosAttackScenario + Config exports
- `bin/scenarios/registry.py` -- Set `implemented=True` for ddos_attack
- `bin/generators/generate_asa.py` -- Import, initialize, generate DDoS ASA events (deny, rate limit, threat detect, emergency ACL) in hour loop
- `bin/generators/generate_meraki.py` -- Import, initialize, generate DDoS IDS alerts + SD-WAN health degradation for BOS location
- `bin/generators/generate_access.py` -- Import, initialize, inject HTTP 503 errors (up to 60% rate, 10x response time) during DDoS
- `bin/generators/generate_linux.py` -- Import, add ddos_scenario param, apply CPU boost (+5 to +40) and network multiplier (2x-10x) for WEB-01
- `bin/generators/generate_perfmon.py` -- Import, add ddos_scenario param, apply downstream CPU effects on APP-BOS-01 (+5 to +15)
- `bin/generators/generate_servicenow.py` -- Added 3 DDoS incident templates (P1 attack alert, P1 customer complaints, P3 post-incident review), 1 emergency change request (permanent mitigation), updated network category filters
- `bin/main_generate.py` -- Removed [PLANNED] from ddos_attack epilog line, added sources, updated --scenarios help text

### Verification (--days=19, --scenarios=ddos_attack, --test)

| Source | Total Events | DDoS-tagged |
|--------|-------------|-------------|
| asa | 663,044 | 1,171 (deny, rate limit, threat detect, emergency ACL) |
| meraki | 2,831,869 | 132 (IDS alerts + SD-WAN health) |
| access | 377,983 | 19,371 (including 2,315 HTTP 503 errors) |
| linux | 265,198 | 672 (336 CPU + 336 interfaces on WEB-01) |
| perfmon | 947,568 | 432 (APP-BOS-01 downstream CPU effects) |
| servicenow | 2,013 | 23 (16 incident lifecycle + 7 change lifecycle) |

Backward compatibility: `--days=17` correctly skips ddos_attack (start_day=17 >= 17).
Implemented scenarios: 9 (was 8).

---

## 2026-02-11 ~17:00 UTC -- Implement dead_letter_pricing scenario (Day 16)

### Summary

New ops scenario: ServiceBus dead-letter queue causes wrong product prices on the web store for 4-6 hours on Day 16 (Jan 16). A price update consumer crashes at 08:00, messages pile up in the dead-letter queue, and the web store serves stale cached prices. IT discovers and fixes the issue by 13:00.

### Scenario Timeline

```
08:00  Price update consumer crashes (OutOfMemoryException)
08:15  First orders with wrong (stale/cached) prices
08:30  Checkout error rate increases
09:00  DLQ alert threshold hit -> ServiceNow P3 auto-created
11:00  IT investigates, finds dead-letter queue full
11:30  ServiceNow escalated to P2
12:00  Consumer restarted, DLQ replay begins
12:30  Prices corrected, DLQ drained
13:00  Full recovery, normal operations
```

### Price Error Types

42 of 72 products affected (~58%), with 4 error types:
- Stale discount not removed (40%): price 15-30% too low
- Stale price increase not applied (30%): price 10-20% too low
- Currency rounding error (20%): price 5-15% too high
- Double discount applied (10%): price 35-50% too low

### Files Created

- `bin/scenarios/ops/dead_letter_pricing.py` -- New scenario class with DeadLetterPricingConfig dataclass. Methods: `is_active()`, `get_demo_id()`, `get_wrong_price()`, `get_price_error_type()`, `get_revenue_impact()`, `get_dlq_rate()`, `access_should_error()`, `servicebus_should_deadletter()`, `generate_price_update_dlq_events()`, `get_resolution_events()`

### Files Modified

- `bin/scenarios/ops/__init__.py` -- Added DeadLetterPricingScenario + Config exports
- `bin/scenarios/registry.py` -- Set `implemented=True` for dead_letter_pricing
- `bin/generators/generate_servicebus.py` -- Added dead_letter_pricing to `get_scenario_effect()`, initialized scenario, generates PriceUpdateFailed DLQ events during scenario window
- `bin/generators/generate_access.py` -- Added DeadLetterPricingScenario import/init, injects checkout errors (5-15% rate, 1.3-1.8x response time) during scenario hours
- `bin/generators/generate_orders.py` -- Applies wrong prices to affected products during scenario, adds `originalPrice`, `priceErrorType`, `wrong_price`, `revenue_impact` fields
- `bin/generators/generate_servicenow.py` -- Added 3 incident templates (DLQ threshold alert, customer complaints, post-incident RCA) and emergency change request (consumer restart)

### Verification (--days=17, --scenarios=dead_letter_pricing, --test)

| Source | Events | Scenario-specific |
|--------|--------|-------------------|
| access | 337,400 | 5,801 with demo_id, 102 HTTP 500 errors |
| orders | 26,769 | 305 orders with wrong prices, $5,730 revenue impact |
| servicebus | 27,967 | 49 PriceUpdateFailed DLQ events, 67 total DeadLettered |
| servicenow | 1,764 | 1 incident (5 lifecycle events), 1 change request (7 lifecycle events) |

Backward compatibility: `--days=14` correctly skips dead_letter_pricing (starts Day 16).
Implemented scenarios: 8 (was 7).

---

## 2026-02-12 ~09:00 UTC -- Expand to 31 days + scenario registry + smart day filtering

### Changes

**DEFAULT_DAYS expanded from 14 to 31** to accommodate 3 new planned scenarios beyond the original 14-day window.

**3 new scenario definitions added to registry** (definitions only, not yet implemented):

| Scenario | Days | Category | Description |
|----------|------|----------|-------------|
| dead_letter_pricing | D16 | ops | ServiceBus dead-letter queue causes wrong product prices (4-6h) |
| ddos_attack | D18-19 | network | Volumetric HTTP flood targeting web servers |
| phishing_test | D21-23 | attack | IT-run phishing awareness campaign after exfil incident |

Old stubs `phishing` and `ddos_attempt` replaced with the new definitions above.

**Smart --days filtering:** When running with `--days=14`, scenarios that start on Day 15+ are automatically skipped. This allows shorter generation runs without errors. New `filter_scenarios_by_days()` helper in registry.py.

**Default --scenarios changed from "exfil" to "all"** to match common usage.

**TUI updated:**
- Scenario list now shows day ranges: `exfil [D1-14]`, `cpu_runaway [D11-12]`
- Planned (unimplemented) scenarios shown dimmed with `[-]` checkbox and `planned` label
- Scenarios beyond current `--days` setting shown in red with `skip` indicator
- Planned scenarios cannot be toggled (space bar disabled for them)

### Files Changed

- `bin/shared/config.py` - `DEFAULT_DAYS = 31` (was 14)
- `bin/scenarios/registry.py` - 3 new ScenarioDefinitions, updated category lists, added `filter_scenarios_by_days()`
- `bin/main_generate.py` - Smart scenario filtering by --days, default scenarios="all", updated help text
- `bin/tui_generate.py` - Day range display, planned scenario rendering, skip indicators

### 31-Day Scenario Timeline

```
D1-3:    Recon (exfil)
D1-5:    Disk filling (disk_filling)
D4:      Initial access (exfil)
D5-7:    Lateral movement (exfil)
D6-9:    Memory leak (memory_leak)
D7:      Firewall misconfig (firewall_misconfig)
D8-9:    Ransomware attempt (ransomware_attempt)
D8-10:   Persistence (exfil)
D11-12:  CPU runaway (cpu_runaway)
D11-13:  Exfiltration (exfil)
D12:     Certificate expiry (certificate_expiry)
D14:     Incident response (exfil)
D16:     Dead-letter pricing (dead_letter_pricing)
D18-19:  DDoS volumetric [PLANNED]
D21-23:  Internal phishing test [PLANNED]
D24-31:  Baseline traffic only
```

---

## 2026-02-11 ~22:00 UTC — Fix exfil scenario plot hole: credential pivot jessica -> alex

### Problem

The exfil scenario had a plot hole: the attacker compromises jessica.brown (IT Admin, Atlanta) via phishing, then suddenly has access to alex.miller (Finance, Boston) with no log events explaining HOW the credential theft occurred.

### Fix: Password Reset + MFA Reset via IT Admin Privileges

Added 7 new events on Day 6 (Jan 7, 02:15-02:26 UTC) showing the attacker using jessica.brown's IT Admin privileges to pivot to alex.miller:

| Time | Event | Source |
|------|-------|--------|
| 02:15 | jessica.brown queries `net group "Finance Department" /domain` | WinEventLog 4688 |
| 02:16 | jessica.brown runs `Get-ADUser -Filter {Department -eq "Finance"}` | WinEventLog 4688 |
| 02:22 | jessica.brown resets alex.miller's password | WinEventLog 4724 (NEW event type) |
| 02:22 | alex.miller account changed (PasswordLastSet) | WinEventLog 4738 (NEW event type) |
| 02:23 | jessica.brown deletes alex.miller's MFA method | EntraID Audit (NEW function) |
| 02:25 | alex.miller sign-in from Frankfurt (185.220.101.42) -> SUCCESS | EntraID SignIn |
| 02:26 | alex.miller registers new Authenticator App (attacker's device) | EntraID Audit |

### New Code

- `generate_wineventlog.py`: Added `event_4724()` (password reset) and `event_4738()` (user account changed) formatters + routing in `format_scenario_event()`
- `generate_entraid.py`: Added `audit_delete_authentication_method()` function for MFA reset audit events
- `exfil.py`: Added credential pivot events in `winevent_hour()` (lateral phase, day 6), `entraid_signin_hour()` (day 6, hour 2), and `entraid_audit_hour()` (day 6, hour 2)

### Dashboard Updates

- `scenario_exfil.xml`: Updated 6-column link graph from 24 to 27 rows, adding "AD query Finance Dept (4688)", "Password reset (4724)", "MFA reset + re-register", "Login from Frankfurt (02:25)" nodes in Lateral_Movement/Persistence columns
- `scenario_exfil_absolute.xml`: Synced from old 3-column (Source/Action/Target) to new 6-column (Recon/Initial_Access/Lateral_Movement/Persistence/Exfiltration/Response) link graph design

### MITRE ATT&CK Coverage Added

- T1098 Account Manipulation (password reset)
- T1556.006 MFA Modification (MFA reset)
- T1078.002 Valid Accounts: Domain Accounts (using alex.miller's reset credentials)

### Verification

- Generated with `--sources=wineventlog,entraid --scenarios=exfil --days=14 --test`
- All 7 events verified in output files with correct timestamps, usernames, and demo_id=exfil tagging
- Total output: 15,638 events (WinEventLog + EntraID combined)

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
