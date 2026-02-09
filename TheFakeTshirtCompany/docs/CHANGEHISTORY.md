# CHANGEHISTORY.md — Change History for TA-FAKE-TSHRT

This file documents all project changes with date/time, affected files, and description.

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
