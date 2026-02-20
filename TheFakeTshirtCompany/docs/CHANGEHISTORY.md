# CHANGEHISTORY.md -- Change History for TA-FAKE-TSHRT

This file documents all project changes with date/time, affected files, and description.

---

## 2026-02-20 ~21:00 UTC -- Secure Access: Fix demo_id corrupting last CSV field

### Context

Splunk verification revealed that `demo_id=exfil` was appended **within** the last CSV field (e.g., `organization_id="7654321" demo_id=exfil"`), causing DELIMS-based field extraction to corrupt the last field in all 4 sourcetypes. Affected ~232 DNS, ~107 proxy, and ~30 firewall scenario events.

### Changes

- **`bin/generators/generate_secure_access.py`**: Changed all 4 event generators (DNS, proxy, firewall, audit) to append `demo_id=xxx` as an **extra comma-separated field** after the last CSV field instead of space-appending to the last field's value. New format: `..."7654321",demo_id=exfil` (unquoted, so existing EXTRACT regex still works).

**Requires data regeneration** for secure_access source.

---

## 2026-02-20 ~20:15 UTC -- Secure Access DNS: Fix missing `action` field in Splunk

### Context

Post-verification of Secure Access fixes revealed DNS `action` field was not being extracted in Splunk. Root cause: Splunk reserves lowercase `action` as a CIM field, so REPORT transforms defining it directly as a field name get ignored. The proxy sourcetype works because it uses `Action` (PascalCase) + `FIELDALIAS Action AS action`.

### Changes

- **`TA-FAKE-TSHRT/default/transforms.conf`**: Changed `"action"` → `"Action"` (PascalCase) in `[umbrella_dns_fields]` FIELDS definition.
- **`TA-FAKE-TSHRT/default/props.conf`**: Added back `FIELDALIAS-action_for_umbrella_dns = Action AS action` for CIM compatibility.

**No data regeneration needed** — only Splunk restart/debug-refresh.

---

## 2026-02-20 ~19:30 UTC -- Secure Access Generator Realism Audit (5 fixes)

### Context

Deep audit of `generate_secure_access.py` against real Cisco Secure Access (Umbrella) S3 export formats and the official Cisco TA (`cisco-cloud-security` on Splunkbase). Generator was ~85% production-ready. Key finding: proxy field names in `transforms.conf` didn't match the real Cisco TA, causing `Blocked_Categories` values to appear under `File_Name` in Splunk.

### Changes

- **`TA-FAKE-TSHRT/default/transforms.conf`**:
  - **Fix 1 (CRITICAL) — Proxy field names**: Renamed positions 20-23 in `[umbrella_proxy_fields]` to match real Cisco TA: `Threat_Name`→`AMP_Malware_Name`, `Threat_Reason`→`AMP_Score`, `Identity_Type`→`Policy_Identity_Type`, `File_Name`→`Blocked_Categories`. Fixes 349K proxy events with wrong field assignments.
  - **Fix 5 — DNS field names**: Updated `[umbrella_dns_fields]` to match real Cisco TA field names: `Most_Granular_Identity`→`user`, `InternalIp`→`src`, `ExternalIp`→`src_translated_ip`, `QueryType`→`RecordType`, `ResponseCode`→`ReplyCode`, `Policy_ID`→`rule_id`, `Country`→`destination_countries`, `Request_ID`→`organization_id`, etc.

- **`bin/generators/generate_secure_access.py`**:
  - **Fix 2 — DNS Policy_ID**: Changed `rule_id` for Allowed DNS queries from `DNS_POLICY_DEFAULT ("100001")` to empty string `""`. Real Umbrella only populates rule_id for Blocked requests. Affects 1M+ DNS events.
  - **Fix 3 — AMP disposition**: Replaced invalid `"Low Risk"` with `"Grayware"` in `AMP_DISPOSITIONS`. Real AMP taxonomy: Clean, Unknown, Malicious, Grayware. Affects ~3,500 proxy events.
  - **Fix 4 — DNS query type format**: Changed from descriptive `"1 (A)"`, `"28 (AAAA)"` to numeric-only `"1"`, `"28"` matching real Umbrella DNS export. Affects 1M+ DNS events.

### Verification

```spl
-- Proxy field alignment fixed
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:proxy"
| head 100 | table AMP_Malware_Name AMP_Score Policy_Identity_Type Blocked_Categories

-- DNS rule_id empty for Allowed
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" action="Allowed"
| stats count by rule_id

-- No more "Low Risk" AMP
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:proxy" | stats count by AMP_Disposition

-- DNS query types numeric only
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" | stats count by RecordType
```

**Test run:** 61,166 events (1 day), 0 errors. DNS: 43,692, Proxy: 13,986, Firewall: 3,487, Audit: 1.

- **`TA-FAKE-TSHRT/default/props.conf`**:
  - Updated DNS FIELDALIAS section: Removed redundant aliases (`Most_Granular_Identity AS user`, `InternalIp AS src`, `Action AS action`) since transforms now use those names directly. Updated CIM aliases to reference new field names (`domain AS query`, `RecordType AS query_type`, `ReplyCode AS reply_code`).

- **`TA-FAKE-TSHRT/default/data/ui/views/discovery_security_overview.xml`**:
  - Updated `Action=Blocked` → `action=Blocked` (2 occurrences), `Domain` → `domain`, removed `Most_Granular_Identity` reference (now `user` directly).

**Note:** Fix 5 changes DNS field names in Splunk. Old names (`QueryType`, `InternalIp`, `Policy_ID`) replaced by Cisco TA standard names (`RecordType`, `src`, `rule_id`). Update any existing dashboards/saved searches.

---

## 2026-02-20 ~16:30 UTC -- ASA Generator Realism Audit (6 fixes)

### Context

Deep audit of `generate_asa.py` against real Cisco ASA 5525-X syslog behavior found 6 realism issues. The generator was ~75% production-ready — good syslog format, Built/Teardown correlation, byte distribution, volume patterns, and scenario hooks. Fixes address interface naming, fake event types, and volume realism.

### Changes

- **`bin/generators/generate_asa.py`**:
  - **Fix 1 — Interface names**: Changed site-based zone names (`atl:`, `bos:`, `aus:`) to proper ASA zone name `inside:` in `asa_site_to_site()` and `asa_backup_traffic()`. Real ASA logs VPN/SD-WAN traffic on inside zone, not per-site names. Affects ~48K events.
  - **Fix 2 — Remove fake HTTP inspect**: Removed `asa_http_inspect()` function — ASA does not log HTTP method/URI in firewall syslog. Message ID 302020 is ICMP only. Removed 2% event allocation, redistributed to ICMP and admin commands. Removes ~26K unrealistic events.
  - **Fix 3 — SSL format**: Added missing period at end of `%ASA-6-725001` message to match real ASA format.
  - **Fix 4 — Scan noise**: Increased background scan noise from ~1% to ~5% of traffic (`event_count // 100` → `event_count // 20`). Real internet-facing firewalls see 5-8% scan/bot traffic.
  - **Fix 5 — Rate limiting frequency**: Increased rate limiting from 5%→30% and threat detection from 3%→20% per business hour, with burst (1-3 events per trigger). Old: ~930 events/31 days. New: ~7K+.
  - **Fix 6 — Hardcoded IPs**: Replaced hardcoded IPs with `SERVERS` dict lookups for `WEB_SERVERS`, `mon_ip` (MON-ATL-01), `BACKUP_SRC` (BACKUP-ATL-01), `BACKUP_DST` (FILE-BOS-01), and ICMP ping targets.

### Verification

```spl
-- No more site-based interface names
index=fake_tshrt sourcetype="FAKE:cisco:asa" ("atl:" OR "aus:" OR "bos:") | stats count
-- Expected: 0

-- No more HTTP inspection with method/URI
index=fake_tshrt sourcetype="FAKE:cisco:asa" "302020" "method" | stats count
-- Expected: 0

-- Interface distribution
index=fake_tshrt sourcetype="FAKE:cisco:asa" "302013"
| rex field=_raw "for (?<src_iface>[^:]+):" | stats count by src_iface
-- Expected: inside, outside, dmz, management — NO atl/bos/aus
```

**Note:** Requires data regeneration for asa source.

---

## 2026-02-20 ~15:00 UTC -- Fix Secondary Device Determinism in webex_api

### Context

Post-verification found that 110/175 users had 4 distinct hardware types instead of expected max 2. Root cause: when a user joins on their secondary mobile device (~15% of meetings), hardware/camera/osVersion/network were chosen randomly from the profile's list instead of being deterministic per user.

### Changes

- **`bin/generators/generate_webex_api.py`**:
  - Secondary device block in `generate_meeting_quality_record()`: replaced `random.choice()` with hash-based deterministic selection (same pattern as primary device). Each user now always uses the same specific mobile device (e.g., always "iPhone 15 Pro", not rotating between iPhone 14/15 Pro/iPad Pro).

### Verification

```spl
index=fake_tshrt sourcetype="FAKE:cisco:webex:meeting:qualities"
| stats dc(hardwareType) as hw_count by webexUserEmail | stats count by hw_count
-- Expected: hw_count=1 (~41), hw_count=2 (~134)
```

---

## 2026-02-20 ~14:00 UTC -- Webex Deterministic User→Device Mapping + Field Fixes

### Context

Three issues found in the Webex generators:
1. **webex_api**: All 175 users showed identical 12 hardware types — `hardwareType`, `camera`, `osType`, `clientType` etc. randomly chosen per meeting event, not per user.
2. **webex_ta**: `clientType` and `clientOS` were completely uncorrelated (`random.choice()` from separate lists), producing impossible combos: "Cisco Room Device" + "Android 14", "Phone (PSTN)" + "ChromeOS", "Webex Mobile (iOS)" + "Windows 10".
3. **webex_api**: `speakerName`/`microphone`/`camera` hardcoded or uncorrelated with hardware; `serverRegion` used non-standard format.

### Changes

- **`bin/shared/company.py`**:
  - Added `WEBEX_CLIENT_PROFILES` — 6 correlated profiles (clientType ↔ osType ↔ hardware ↔ cameras ↔ audio ↔ networkTypes) with weighted distribution
  - Added 6 deterministic `User` properties: `webex_profile`, `webex_hardware`, `webex_camera`, `webex_os_version`, `webex_network`, `webex_secondary_profile` — all hash-based (same pattern as `vpn_ip`, `mac_address`)
  - Each user now has a fixed primary device (e.g. "Dell Latitude 5520" + Windows + "Speakers (Realtek Audio)") and optionally a secondary mobile device for ~15% of meetings

- **`bin/generators/generate_webex_api.py`**:
  - Removed local `_CLIENT_PROFILES` list and `_pick_client_profile()` — now imports `WEBEX_CLIENT_PROFILES` from company.py
  - `generate_meeting_quality_record()`: Uses `user.webex_*` properties instead of random per-event selection
  - `speakerName` and `microphone` now correlate with hardware profile (was hardcoded "Speakers (Realtek Audio)" for all)
  - `camera` now correlates with hardware profile (was random from global list)
  - `serverRegion` changed from "US East"/"US West" to city format: "San Jose, USA", "Chicago, USA", etc.

- **`bin/generators/generate_webex_ta.py`**:
  - Removed uncorrelated `CLIENT_TYPES` and `CLIENT_OS` lists
  - Added `_ta_os_label()` helper to convert profile osType + version to TA labels (e.g. "Windows 11", "macOS 14")
  - Added `_pick_ta_profile()` for external participants (random but correlated)
  - Fixed all 4 client_type/client_os assignment locations (2 in shared-schedule meetings, 2 in ad-hoc meetings)
  - Internal users: use deterministic `user.webex_profile` properties
  - External users: use `_pick_ta_profile()` for correlated random selection
  - "Cisco Room Device" now only appears as a proper participant (~5% of meetings) with correct OS: "RoomOS 11"
  - "Phone (PSTN)" now only appears for external participants (~2% chance) with "N/A" as OS

### Verification

```spl
-- Hardware per user: should be 1-2, NOT 12
index=fake_tshrt sourcetype="FAKE:cisco:webex:meeting:qualities"
| stats dc(hardwareType) as hw_count by webexUserEmail | sort -hw_count | head 10

-- No impossible combos in webex_ta
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingattendeehistory"
| stats count by clientType clientOS

-- Room Device must have RoomOS 11
index=fake_tshrt sourcetype="FAKE:cisco:webex:meetings:history:meetingattendeehistory" clientType="Cisco Room Device"
| stats count by clientOS
```

**Note:** Requires data regeneration for webex_api and webex_ta sources.

---

## 2026-02-20 ~01:45 UTC -- Meraki deviceSerial Completion Fix

### Context

Post-regeneration Splunk verification revealed that Fix #5 (deviceSerial) from Batch 2 was incomplete. The `replace_all` on `"deviceSerial": device` only caught event-generator functions where the variable was named `device`. Health functions, meeting room cameras/sensors used different variable names (`ap`, `switch`, `camera_id`, `sensor`) and were missed. ~92% of Meraki events (~1.6M) still had `deviceSerial` = `deviceName`.

### Changes

- **`bin/generators/generate_meraki.py`**:
  - **AP health** (`generate_mr_health_metrics`): Changed `"deviceSerial": ap` → `"deviceSerial": _get_serial(ap)` — fixes 106,992 AP health events
  - **Switch health** (`generate_ms_health_metrics`): Changed `"deviceSerial": switch` → `"deviceSerial": _get_serial(switch)` — fixes 1,307,680 switch port health events
  - **Meeting room cameras + sensors** in `_build_serial_registry()`: Added registration of meeting room cameras (`MV-*` from `MEETING_ROOMS` config, 6 cameras) and meeting room sensors (`MT-*-TEMP-*`, `MT-*-DOOR-*`, ~38 sensors). These were not in `MERAKI_MV_DEVICES`/`MERAKI_MT_DEVICES` and thus had no serial in the registry, causing `_get_serial()` fallback to return the device name. Now generates proper serials (Q2MV/Q2MT format) with sequence offsets to avoid collision with infrastructure device serials.

### Verification

```spl
-- Should return 0 rows after regeneration:
index=fake_tshrt sourcetype="FAKE:meraki:*"
| where deviceSerial=deviceName
| stats count by sourcetype
```

**Note:** Requires data regeneration for meraki source.

---

## 2026-02-20 ~01:00 UTC -- Meraki Generator Audit Batch 3: Edge Cases, Docs, Realism Polish

### Context

Final batch of the Meraki audit addresses 8 lower-severity but still valuable realism improvements: external IP generation, tunnel symmetry, documentation mismatches, device naming, and behavioral patterns.

### Changes

- **`bin/generators/generate_meraki.py`**:
  - **Fix #8 — External IP generator could produce RFC1918/bogon addresses**: `get_random_external_ip()` used `random.randint(1, 223)` for the first octet, which could generate private (10.x, 172.16-31.x, 192.168.x), CGNAT (100.64-127.x), loopback (127.x), and link-local (169.254.x) as "external" IPs. Added a while-loop with explicit filtering for all reserved ranges.
  - **Fix #9 — SD-WAN tunnel events were unidirectional**: `generate_sdwan_baseline_hour()` only generated tunnel status from `mx_a`'s perspective. Real AutoVPN tunnels report from both sides. Now generates symmetric events from both peers, with independent timestamps.
  - **Fix #12 — Austin "Server Room" camera/sensor**: Austin has no servers, but `CAM-AUS-1F-02`, `MT-AUS-TEMP-01`, and `MT-AUS-DOOR-01` had `area: "Server Room"`. Renamed to `"IDF Closet"` (industry-standard term for branch wiring closets).
  - **Fix #14 — MR WiFi floor affinity**: User-AP associations were completely random across all APs at a location. Now 75% of associations go to an AP on the user's assigned floor, 25% roam to other floors (elevator, meetings, etc.).
  - **Fix #15 — Person detection count=0**: After-hours `person_detected` events used `random.randint(0, 2)`, which could produce count=0 — semantically contradictory ("person detected" with zero people). Changed minimum to 1.

- **`CLAUDE.md`**:
  - **Fix #11 — SSID names**: Documentation said `TShirtCo-*` but code uses `FakeTShirtCo-*`. Updated CLAUDE.md to match actual SSIDs: FakeTShirtCo-Corp, FakeTShirtCo-Guest, FakeTShirtCo-IoT. Added FakeTShirtCo-Voice SSID.
  - **Fix #13 — Camera count mismatch**: Documentation said 19 MV cameras, actual device inventory is 15 (BOS 8, ATL 7 [including 4 meeting room], AUS 4 [including 1 meeting room]). Updated count and clarified MT sensor totals (14 infrastructure + ~38 meeting room sensors).

- **Fix #10 — MX fallback MAC**: Already resolved in Batch 2 (Fix #5 added unique MAC addresses to all 4 MX devices).

### Scenario Safety

All fixes are baseline-only or documentation. No scenario functions were modified.

**Note:** Requires data regeneration for meraki source.

---

## 2026-02-20 ~00:30 UTC -- Meraki Generator Audit Batch 2: deviceSerial, Cross-Site SD-WAN, IDS Fix

### Context

Batch 2 addresses deeper structural issues found during the Meraki generator audit: incorrect device serial numbers, missing inter-site SD-WAN traffic, and an architectural inconsistency in the exfil scenario IDS alerts.

### Changes

- **`bin/generators/generate_meraki.py`**:
  - **Fix #5 — deviceSerial uses device name instead of serial**: All ~35 event functions used `"deviceSerial": device` which produced values like "MX-BOS-01" — obviously not a Meraki serial number. Added `_build_serial_registry()` that generates proper serials for all device types (MX already had them, MR/MS/MV/MT now get generated serials like `Q2MR-BOS0-0001`). New `_get_serial()` helper replaces all `"deviceSerial": device` references. Also added `mac` field to all 4 MX devices (was a single hardcoded fallback `00:18:0A:01:02:03`).
  - **Fix #6 — Missing inter-site SD-WAN traffic**: All MX firewall events were internal→external. Added ~12% cross-site flows for ATL/AUS spokes targeting BOS servers (DC, File, SQL, App). Uses realistic ports (445/SMB, 389/LDAP, 88/Kerberos, 1433/SQL, 443/HTTPS). BOS MX excluded from cross-site (it is the hub).
  - **Fix #7 — External threat IP on internal MX IDS**: Days 4-6 used `THREAT_IP` (185.220.101.42) as source on MX-ATL-01, but per architecture all external traffic goes through ASA — MX only handles internal/SD-WAN. Removed days 4-6 from MX IDS (ASA covers this). MX IDS now starts at day 7 (lateral movement = internal cross-site traffic via AutoVPN, architecturally correct for MX inspection).

### Scenario Safety

Fix #7 modifies the exfil scenario's `generate_ids_alert()` function. The change makes the scenario more architecturally correct — MX IDS alerts now only appear for traffic the MX would actually see (internal lateral movement, not external perimeter attacks). Days 4-6 IDS coverage remains via the ASA generator.

**Note:** Requires data regeneration for meraki source.

---

## 2026-02-20 ~00:15 UTC -- Meraki Generator Audit Batch 1: STP, AMP, VPN Peers, 802.1X

### Context

Full audit of `generate_meraki.py` revealed four critical data realism issues verified against 31 days of Splunk data. A network engineer or SOC analyst would immediately flag these patterns.

### Changes

- **`bin/generators/generate_meraki.py`**:
  - **Fix #1 — STP role/state combinations**: Role and state were chosen independently via `random.choice()`, producing impossible combinations like root/blocking or alternate/forwarding. Added `stp_valid` mapping enforcing IEEE 802.1D spec: root→forwarding, designated→forwarding, alternate→blocking, backup→blocking. Also reduced STP event weight from 20% to 5% (1,306 STP changes in 31 days = unstable network).
  - **Fix #2 — AMP malware baseline volume**: 25% of security events were AMP malware detections (296 over 31 days, ~10/day with signatures like "Win.Ransomware.Locky"). Reduced weight from 25% to 2%. Healthy environment: 1-3 detections per month.
  - **Fix #3 — VPN site-to-site peer IPs**: Baseline VPN events used `get_random_external_ip()` as peer contact, producing Google (172.217.14.78), Microsoft, GitHub, and even RFC1918 IPs as "site-to-site VPN peers". Added `_get_vpn_peer_ip()` helper that returns actual peer MX WAN IPs from `SDWAN_PEERS` (203.0.113.1/20/30).
  - **Fix #4 — MS 802.1X fake usernames**: Switch 802.1X events used `user1` through `user100` fake accounts. Changed to use real employees from `get_users_by_location()`, matching the pattern already used by MR wireless 802.1X.

### Verification (SPL queries for post-regeneration)

```spl
-- Fix #1: STP role/state should be valid pairs
index=fake_tshrt sourcetype="FAKE:meraki:switches" type="stp_change"
| spath eventData.role | spath eventData.state
| stats count by "eventData.role" "eventData.state"

-- Fix #2: AMP detections should be ~20 over 31d (was 296)
index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" subtype="amp_malware_blocked"
| stats count

-- Fix #3: VPN peers should only be 203.0.113.x
index=fake_tshrt sourcetype="FAKE:meraki:securityappliances" type="vpn_connectivity_change"
| spath eventData.peer_contact | stats count by "eventData.peer_contact"

-- Fix #4: 802.1X should use real employee names
index=fake_tshrt sourcetype="FAKE:meraki:switches" type="8021x_auth"
| spath eventData.identity | stats count by "eventData.identity" | sort -count
```

### Scenario Safety

All four fixes affect only baseline generator functions (`generate_ms_baseline_hour`, `generate_mx_baseline_hour`). Scenario functions (`generate_ids_alert`, `generate_after_hours_motion`) are untouched.

**Note:** Requires data regeneration for meraki source.

---

## 2026-02-19 ~23:45 UTC -- Audit Batch 1: Entra ID + WinEventLog Realism Fixes

### Context

Full audit of `generate_entraid.py` and `generate_wineventlog.py` revealed three critical data realism issues that a SOC analyst or Splunk expert would immediately flag. All three are baseline-only changes — scenarios use their own event generators and are unaffected.

### Changes

- **`bin/generators/generate_entraid.py`**:
  - **Fix #1 — Failed sign-in app distribution**: `signin_failed()` hardcoded all user failures to "Office 365 Exchange Online" (verified: 424/424 = 100%). Now picks a random app from `ENTRA_APP_LIST`, matching the distribution pattern used by `signin_success()`.
  - **Fix #3 — authenticationRequirement mix**: `signin_success()` hardcoded 100% MFA (verified: 8103/8120 = 99.8%). Now uses ~70% `multiFactorAuthentication` / ~30% `singleFactorAuthentication` (trusted devices, remembered sessions, CA policy exceptions).

- **`bin/generators/generate_wineventlog.py`**:
  - **Fix #4 — Remove Logon Type 2 from servers**: `generate_baseline_logons()` used `logon_types = [2, 3, 10]` for all `WINDOWS_SERVERS`. Type 2 = Interactive (physical keyboard logon) is unrealistic for DCs, SQL servers, and file servers. Changed to `[3, 10]` (Network + RDP only). Client workstations already use Type 2 correctly in `generate_client_logon()`.

- **`bin/shared/company.py`**:
  - **SERVICE_ACCOUNTS dict**: Added centralized service account inventory documenting all 9 service accounts used across generators (svc.backup, svc_ecommerce, svc_finance, sap.batch, sap.rfc, it.admin, sec.admin, helpdesk, ad.sync) with their name variants, generator usage, and roles.

### Verification (SPL queries for post-regeneration)

```spl
-- Fix #1: failures should spread across multiple apps
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" action=failure category="SignInLogs"
| stats count by "properties.appDisplayName" | sort -count

-- Fix #3: should see ~30% singleFactor
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" action=success category="SignInLogs"
| stats count by "properties.authenticationRequirement"

-- Fix #4: servers should only have Type 3 and 10
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4624
  (host="DC-*" OR host="SQL-*" OR host="FILE-*" OR host="APP-*")
| stats count by Logon_Type host
```

### Scenario Safety

All three fixes affect only baseline generator functions (`signin_failed`, `signin_success`, `generate_baseline_logons`). Scenarios (exfil, ransomware, phishing) use their own event generators and never call these functions — confirmed via grep.

**Note:** Requires data regeneration for entraid and wineventlog sources.

---

## 2026-02-19 ~23:00 UTC -- Entra ID Generator: SP Burst Failure Pattern (one bad day per SP)

### Context

Replaced random 5% SP failure rate with a realistic burst pattern. In production, SP failures happen in bursts: a cert/secret expires overnight, fails for hours, and ops fixes it in the morning. Random drip of failures across all days is unrealistic.

### Changes

- **`bin/generators/generate_entraid.py`**:
  - **New `_sp_is_failing()` helper**: Each SP gets a deterministic "bad day" via `sum(ord(c) for c in sp_id) % total_days`. On that day, failures occur only during a 6-hour window (02:00-08:00 UTC). All other times: 0% failure.
  - **Burst failure rate**: 45% failure during the burst window (`SP_BURST_FAILURE_RATE = 0.45`). Replaced `SP_FAILURE_RATE = 0.05` (random drip).
  - **`total_days` parameter propagation**: Added to `signin_service_principal()` and `generate_signin_hour()`, propagated from `generate_entraid_logs()` main loop.
  - Uses `sum(ord(c))` instead of `hash()` for reproducibility across Python runs (Python 3.3+ randomizes string hashes via PYTHONHASHSEED).

### SP Bad Day Distribution (14-day run)

| Service Principal | Bad Day | Failure Window |
|------------------|---------|----------------|
| SAP S/4HANA Connector | Day 2 | 02:00-08:00 |
| Veeam Backup Agent | Day 8 | 02:00-08:00 |
| Splunk Cloud Forwarder | Day 11 | 02:00-08:00 |
| GitHub Actions CI/CD | Day 13 | 02:00-08:00 |
| Nagios Monitoring Agent | Day 11 | 02:00-08:00 |

### Expected Impact

| Metric | Before (random 5%) | After (burst) |
|--------|-------------------|---------------|
| SP failures per 14d | ~560 spread across all days | ~150-200 concentrated on bad days |
| Failure pattern | Random drip every hour | Clear spike → fix → clean |
| Failure rate off bad day | 5% | 0% |
| Failure rate on bad day (burst window) | 5% | 45% |

**Note:** Requires data regeneration for entraid source.

---

## 2026-02-19 ~22:00 UTC -- Entra ID Generator: Service Principal Failure Rate, Auth Method, Spray Noise

### Context

Dashboard "Auth Failures by User" panel was dominated by 5 service principals (~650 failures each) drowning out real user authentication failures (~15-27 each). Three bugs in `generate_entraid.py` caused unrealistic data.

### Changes

- **`bin/generators/generate_entraid.py`**:
  - **SP failure rate**: Reduced from ~29% to ~5% (`SP_FAILURE_RATE = 0.05`). Replaced weighted list with `random.random()` probability check.
  - **Auth-method-matched errors**: Error codes now match the SP's credential type via `SP_ERRORS_BY_AUTH_METHOD` dict. Certificate-based SPs (SAP, GitHub) get `7000222` ("Client certificate expired"), secret-based SPs (Veeam, Splunk, Nagios) get `7000215` ("Invalid client secret provided"). Previously the error code was always random regardless of auth method.
  - **Fixed authMethod per SP**: Each service principal now has a fixed `authMethod` field. The `authenticationDetails.authenticationMethod` value is consistent regardless of success/failure. Previously inverted: `"Client secret" if success else "Client certificate"`.
  - **Spray noise targets**: Replaced unrealistic fake accounts (`test`, `ceo`, `finance`, `hr`, `it.support`, `jane.doe`) with a realistic mix of generic enumeration targets (`admin`, `administrator`, `helpdesk`, `info`, `support`, `service`, `noreply`) and publicly-known executives (`john.smith`, `sarah.wilson`, `mike.johnson`).

### Service Principal Auth Methods

| Service Principal | Auth Method |
|------------------|-------------|
| SAP S/4HANA Connector | Client certificate |
| Veeam Backup Agent | Client secret |
| Splunk Cloud Forwarder | Client secret |
| GitHub Actions CI/CD | Client certificate |
| Nagios Monitoring Agent | Client secret |

### Expected Impact

| Metric | Before | After |
|--------|--------|-------|
| SP failure rate | ~29% (3246 failures/31d) | ~5% (~560 failures/31d) |
| Top Auth Failures users | 5 SPs dominate top 5 | Real users + executives visible |
| authenticationMethod | Flipped based on success/failure | Consistent per SP |

**Note:** Requires data regeneration for entraid source.

---

## 2026-02-19 ~21:00 UTC -- Security Overview: O365 Panel Rework (Suspicious + Baseline Activity)

### Context

Reworked O365 panel to distinguish genuinely suspicious file operations (scenario-driven) from normal baseline activity, then added baseline back for context. Stripped email domain from usernames for readability.

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`**:
  - `ds_o365_suspicious_ops`: Expanded query from just FileDownloaded/SharingSet to 6 operations:
    - **Baseline**: FileDownloaded, SharingSet (normal daily activity)
    - **Suspicious (scenario-driven)**: FileSyncDownloadedFull (exfil), SafeLinksUrlClicked (phishing), FileRestored (ransomware), SecurityComplianceSearch (phishing)
  - Added `eval UserId=replace(UserId, "@theFakeTshirtCompany.com", "")` to strip domain from usernames
  - `viz_o365_suspicious_ops`: Renamed title from "O365 Suspicious Activity" to "O365 File Activity" (now includes baseline)
  - Updated `seriesColors` from 4 to 6 colors (alphabetical chart series order):
    - FileDownloaded → #009CEB (blue, baseline)
    - FileRestored → #DC4E41 (red, suspicious)
    - FileSyncDownloadedFull → #F1813F (orange, suspicious)
    - SafeLinksUrlClicked → #F8BE34 (yellow, suspicious)
    - SecurityComplianceSearch → #7B56DB (purple, suspicious)
    - SharingSet → #53A051 (green, baseline)

---

## 2026-02-19 ~20:00 UTC -- Security Overview: Stacked Charts + Top Threat Sources Allowed/Blocked

### Context

Chart improvements: Top Threat Sources now shows both allowed and blocked events per IP (was blocked-only). Three bar charts converted to stacked mode for multi-series visibility.

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`**:
  - `ds_top_threat_sources`: Changed from `action=blocked | stats count by src` to `(action=blocked OR action=allowed) | chart count by src action | sort -blocked`. Added `src=$src_token$` token integration. Now shows allowed (green) vs blocked (red) per source IP.
  - `viz_top_threat_sources`: Added `stackMode: "stacked"`, colors `["#DC4E41", "#53A051"]` (blocked=red, allowed=green), legend moved to bottom, x-axis title changed from "Deny Events" to "Events"
  - `viz_sysmon_suspicious`: Added `stackMode: "stacked"` (CreateRemoteThread + ProcessAccess per host)
  - `viz_o365_suspicious_ops`: Added `stackMode: "stacked"` (FileDownloaded + SharingSet per user)
  - `ds_o365_suspicious_ops`: Added `| addtotals | sort -Total | head 15 | fields - Total` after chart to sort by combined count and limit to top 15 users

---

## 2026-02-19 ~19:00 UTC -- Dashboard Fixes, demo_id Extraction, ASA Severity

### Context

Multiple fixes based on dashboard review: chart improvements, demo_id search-time extraction producing literal `$1$2` values, and ASA severity field missing due to incomplete EVAL fallback.

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`**:
  - Added `dest` column to Recent Security Events table (between src and detail), renamed as "Destination"
  - Sysmon Suspicious Activity: changed `stats count by host activity` to `chart count by host activity` for multi-series bar chart (CreateRemoteThread + ProcessAccess per host)
  - O365 Suspicious File Operations: changed `stats count by UserId Operation` to `chart count by UserId Operation` for multi-series bar chart (FileDownloaded + SharingSet per user)
  - Renamed severity dropdown from "Severity" to "Incident Priority" (only applies to ServiceNow table)

- **`default/transforms.conf`**:
  - Removed `[extract_demo_id_search]` stanza (broken: `FORMAT = demo_id::$1$2` produced literal `$1$2` values when only one capture group matched)

- **`default/props.conf`**:
  - Replaced `REPORT-demo_id_search = extract_demo_id_search` with `EXTRACT-demo_id = (?|"demo_id":\s*"(?<demo_id>[^"]+)"|demo_id=(?<demo_id>\S+))` on all 57 sourcetype stanzas. Uses branch reset group `(?|...)` so both alternatives write to the same named capture group.
  - Fixed `EVAL-severity` on `[FAKE:cisco:asa]`: added `severity_level` fallback mapping (emergencies/alert → critical, error → high, warning → medium, notification → low, informational → informational, debugging → informational). Previously only 5 message_ids had severity; now ALL ASA events get severity via syslog log_level → severity_level lookup → EVAL fallback.

### ASA Severity Distribution (after fix)

| Severity | Count | Source |
|----------|-------|--------|
| informational | 4,673,057 | log_level 6 (conn build/teardown) |
| medium | 37,661 | log_level 4 (deny events: 106023, 313005) |
| low | 438 | log_level 5 + message_id 405001 |
| critical | 2 | log_level 1-2 |
| high | 2 | log_level 3 + message_id 212011 |

### demo_id Fix Verification

| Test | Before | After |
|------|--------|-------|
| `demo_id="$1$2"` events | 7 found | 0 (literal gone) |
| `demo_id=exfil` across sources | Working | Working (branch reset group) |

---

## 2026-02-19 ~16:00 UTC -- Security Overview: Token Coverage Audit and Fixes

### Context

Systematic audit of all 17 datasources against all 5 field tokens revealed 6 datasources missing token integration and a bug in ServiceNow priority field values (used `"1 - Critical"` but actual data has `"1"`).

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`**:
  - `ds_account_lockouts`: Added `user_token` filter via `mvindex(Account_Name,1)` (was unfiltered)
  - `ds_web_threat_blocks`: Added `src=$src_token$` (was unfiltered)
  - `ds_dns_blocked`: Added `src=$src_token$` (was unfiltered)
  - `ds_o365_suspicious_ops`: Added `src=$src_token$` + `UserId=$user_token$` filter (was unfiltered)
  - `ds_servicenow_incidents`: Added `priority=$severity_token$` filter + fixed `_color_rank` eval to match actual priority values (`"1"` not `"1 - Critical"`) + added `priority_label` for human-readable display
  - `input_severity` dropdown: Fixed values from `"1 - Critical"` to `"1"` etc., added `"5 - Planning"` option
  - Sysmon (`ds_sysmon_suspicious`) confirmed no applicable tokens — no user/src fields in EventCode 8/10 events

### Verification

| Query | Default (`*`) | Filtered | Result |
|-------|--------------|----------|--------|
| Account Lockouts (user) | 32 | `isabella.rodriguez` → 1 | OK |
| Web Threat Blocks (src) | 14,110 | — | OK |
| DNS Blocked (src) | 5 domains shown | — | OK |
| O365 File Ops (src+user) | 5 users shown | `src=10.10.30.74` → 23 | OK |
| ServiceNow (severity) | 195 total | `priority=2` → 61 | OK |

### Token Coverage Matrix (final)

| Datasource | src | dest | user | severity | source |
|------------|-----|------|------|----------|--------|
| Security Events (tstats) | — | — | — | — | — |
| Auth Failures Total | ✅ | — | ✅ | — | — |
| Firewall Denies Total | ✅ | ✅ | — | — | — |
| Large Transfers | ✅ | ✅ | — | — | — |
| Account Lockouts | — | — | ✅ | — | — |
| Web Threat Blocks | ✅ | — | — | — | — |
| Timeline (tstats) | — | — | — | — | — |
| Top Threat Sources | — | ✅ | — | — | — |
| Top Denied Ports | ✅ | ✅ | — | — | — |
| DNS Blocked Domains | ✅ | — | — | — | — |
| Auth Failures by User | ✅ | — | ✅ | — | — |
| Sysmon Suspicious | — | — | — | — | — |
| Privileged Logons | — | — | ✅ | — | — |
| Linux Failed Auth | ✅ | — | — | — | — |
| O365 File Ops | ✅ | — | ✅ | — | — |
| Recent Events | ✅ | ✅ | ✅ | — | ✅ |
| ServiceNow Incidents | — | — | — | ✅ | — |

---

## 2026-02-19 ~14:00 UTC -- Security Overview Dashboard v2: 1900px, Tokens, Endpoint Panels

### Context

Major update to the Security Overview dashboard based on user feedback:
1. Layout too narrow at 1600px — expanded to 1900px
2. Only 2 of 7 planned tokens were implemented (time, span) — added 5 missing tokens
3. FW Denies KPI used tstats with `action=blocked` which doesn't work (field not indexed) — switched to regular search to also support token filtering
4. ServiceNow table showed all incidents — filtered to security-relevant categories only
5. No endpoint/server visibility — added 6 new panels covering Sysmon, WinEventLog, Linux, O365, and Secure Access

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`** (rewritten):
  - Expanded from 1600px to 1900px wide, ~3510px tall
  - 17 data sources (was 11), 30 visualizations (was 21), 7 inputs (was 2)
  - 12 background rectangles (was 8) for new panel rows

  **New Tokens (5 added):**
  - `src_token` (text, default `*`) — filters src IP in firewall, threat sources, recent events, Linux auth
  - `dest_token` (text, default `*`) — filters dest IP in firewall denies, denied ports
  - `user_token` (text, default `*`) — filters user in auth failures, privileged logons, recent events
  - `severity_token` (dropdown, default `*`) — filters ServiceNow priority (Critical/High/Medium/Low)
  - `source_token` (dropdown, default `*`) — filters sourcetype in recent events table

  **New KPIs (2 added, total 6):**
  - Account Lockouts — WinEventLog EventCode=4740, color #FF677B (32 events)
  - Web Threat Blocks — Umbrella Proxy Action=Blocked, color #00CDAF (14,110 events)

  **New Bar Charts (4 added, total 8):**
  - Sysmon Suspicious Activity — EventCode 8 (CreateRemoteThread) + 10 (ProcessAccess) by host, #DC4E41
  - Privileged Logons — EventCode 4672 by Account_Name, #7B56DB
  - Linux Failed Auth — linux:auth action=failure by host, #F1813F
  - O365 Suspicious File Ops — FileDownloaded + SharingSet by UserId, #009CEB

  **Query Fixes:**
  - FW Denies: Changed from `tstats ... action=blocked` to `index=fake_tshrt sourcetype="FAKE:cisco:asa" action=blocked src=$src_token$ dest=$dest_token$ | stats count` (regular search for token support)
  - Auth Failures: Uses `action=failure` for Entra ID (not string-matching errorCode), `mvindex(Account_Name,1)` for WinEventLog 4625
  - Privileged Logons (4672): Uses `Account_Name` directly (single-value, unlike 4625 multi-value)
  - ServiceNow: Filtered to `category="Security" OR category="Account" OR category="Network"` (~195 incidents)
  - Recent Events: Expanded to include ASA blocked, Entra ID failures, WinEventLog 4625, Umbrella DNS blocked, Sysmon 8/10, Linux auth failures — all with token filters

---

## 2026-02-19 ~10:00 UTC -- New Dashboard: Discovery - Security Overview (initial build)

### Context

Added new Security Overview dashboard for SOC Analyst use case, designed iteratively panel by panel. Provides cross-source security posture view combining firewall, authentication, DNS security, and incident correlation data. Scenarios are discoverable through KPI anomalies rather than explicit demo_id filtering.

### Changes

- **`default/data/ui/views/discovery_security_overview.xml`** (new):
  - Dashboard Studio v2, absolute layout, dark theme, 1600px wide
  - 11 data sources, 13 visualizations (4 KPI + 1 area chart + 4 bar charts + 2 tables + 2 headers)
  - 8 background rectangles (#13141A) for card styling
  - Inputs: Global time range picker + Span dropdown (1h/4h/1d)
  - **KPIs:** Security Events (sparkline), Auth Failures, Firewall Denies, Large Transfers (>10MB)
  - **Charts:** Security Events Over Time (stacked area by source category), Top Threat Sources (bar), Top Denied Ports/Services (bar), DNS Blocked Domains (bar), Auth Failures by User (bar)
  - **Tables:** Recent Security Events (100 rows, multi-source), ServiceNow Incidents (priority-colored rows)
  - All queries use `index=fake_tshrt` with `FAKE:` sourcetype prefix
  - Default time range: Jan 1 - Feb 1, 2026 (epoch 1767225600-1769904000)
  - Color palette follows design language: Cisco colors (#00D2FF, #DC4E41, #F8BE34, #F1813F, #7B56DB, #009CEB)

- **`default/data/ui/nav/default.xml`**:
  - Added `discovery_security_overview` at top of Discovery collection (before discovery_soc)

### Data Sources

| Panel | Type | Source |
|-------|------|--------|
| Security Events KPI | tstats sparkline | ASA + Entra ID + WinEventLog + Sysmon + Umbrella + O365 + CloudTrail + GCP |
| Auth Failures KPI | stats count | Entra ID (action=failure) + WinEventLog (4625) |
| Firewall Denies KPI | regular search | ASA (action=blocked) with src/dest token filters |
| Large Transfers KPI | rex + stats | ASA Teardown events (bytes > 10MB) |
| Timeline | tstats + timechart | All security sourcetypes, grouped by category |
| Top Threat Sources | stats by src | ASA blocked events |
| Top Denied Ports | stats by dest_port | ASA blocked events with service mapping |
| DNS Blocked | stats by Domain | Umbrella DNS (Action=Blocked) |
| Auth Failures by User | stats by user | Entra ID + WinEventLog |
| Recent Events | table | ASA deny + Auth fail + DNS block + Sysmon process |
| ServiceNow Incidents | table with row coloring | servicenow:incident (priority-based _color_rank) |

---

## 2026-02-18 ~14:00 UTC -- Exfil: Fix GCP Day 13 Gap + Exchange Duplicate Forwarding

### Context

Deep audit of exfil.py found 2 bugs:
1. GCP exfiltration events only generated for Days 11-12, but exfil phase runs Days 11-13 — Day 13 had zero GCP storage events
2. `exchange_hour()` and `exchange_day()` both generated forwarded mail events for Days 6-11, creating duplicate forwarding since both are called from `generate_exchange.py`

### Changes

- **`bin/scenarios/security/exfil.py`**:
  - Line 879: Changed `(day == 11 or day == 12)` to `11 <= day <= 13` in `gcp_hour()` exfil block
  - Line 2050: Same fix in `has_exfil_events()` GCP check
  - `exchange_hour()`: Removed duplicate forwarding generation (kept in `exchange_day()` only)

---

## 2026-02-18 ~13:00 UTC -- Memory Leak: Fix OOM Hour Generating Zero ASA Events

### Context

Bug: The OOM crash hour (14:00, Day 10) generated **0 ASA events** because `asa_is_active()` called `is_resolved(day=9, hour=14)` which returned `True` since `restart_hour == oom_hour == 14`. The `>=` comparison treated the entire OOM hour as "resolved". Same issue affected `asa_baseline_suppression()` which returned 0.0 instead of 0.95 for the OOM hour.

### Changes

- **`bin/scenarios/ops/memory_leak.py`**:
  - `asa_is_active()`: Replaced `is_resolved()` call with direct `hour > restart_hour` check so OOM hour is included
  - `asa_baseline_suppression()`: Replaced `is_resolved()` call with direct day/hour checks so OOM hour correctly returns 0.95

### Verification

- Before fix: OOM hour (h14) = 0 memleak events, 0 "No matching connection" events
- After fix: OOM hour (h14) = 778 memleak events, 52 "No matching connection" events ✅
- Pre-OOM (h08-h13): Unchanged, escalating timeouts with 0.8 suppression ✅
- Post-restart (h15+): Unchanged, tapering off to 0 ✅

---

## 2026-02-18 ~12:00 UTC -- Memory Leak: Dynamic ASA Timeout/Reset Volume Scaling

### Context

Same issue as firewall_misconfig: the memory_leak scenario had hardcoded ASA event counts (30/80/150/250 per day) that didn't scale with `--scale` or `--orders-per-day`. At production scale (3.5, orders=5000), peak-hour DMZ baseline is ~11,500 events — the 250 events/day were invisible.

### Changes

- **`bin/scenarios/ops/memory_leak.py`**:
  - Added `normal_dmz_events` parameter to `asa_generate_hour()`
  - Replaced hardcoded daily event counting with dynamic formula: `max(minimum, int(normal_dmz_events * suppression))`
  - Reuses existing `asa_baseline_suppression()` values (0.2/0.4/0.6/0.8/0.95) for scaling
  - Added `_hourly_minimum()` helper for fallback when `normal_dmz_events=0`
  - OOM day special handling preserved (burst at hour 14, taper after restart)
- **`bin/generators/generate_asa.py`**:
  - Refactored `_normal_dmz` calculation to shared variable (DRY — used by both memory_leak and firewall_misconfig)
  - Passes `normal_dmz_events=_normal_dmz` to memory_leak scenario
  - Simplified firewall_misconfig callsite (removed duplicate calculation)

### Verification

- **scale=1.0**: Day 9 (supp 0.6) — 7,695 memleak events/day (was 150). Business hours 91-100% of baseline. PASS.
- **scale=2.0, orders=2000**: Day 9 (supp 0.6) — 62,999 memleak events/day. Business hours 95-103% of baseline. PASS.
- **Note**: OOM hour (h14) generates 0 events — pre-existing issue where `is_resolved(oom_day, oom_hour)` returns True because `restart_hour == oom_hour == 14`. Separate fix needed.

---

## 2026-02-18 ~08:00 UTC -- Firewall Misconfig: Dynamic Deny Volume Scaling

### Context

The firewall_misconfig deny events were hardcoded (700/1100/30), but DMZ baseline traffic scales with `--scale` and `--orders-per-day`. At production settings (scale=3.5, orders=5000), normal peak-hour DMZ volume was ~11,500 events but only 700 deny events were injected during full outage, making Day 6 appear as ~50% of normal traffic in Splunk timecharts.

### Changes

- **`bin/scenarios/network/firewall_misconfig.py`** -- Changed `generate_hour()` to accept `normal_dmz_events` parameter and calculate deny counts dynamically:
  - h10 (65% suppression, 40/60 min): `max(250, normal_dmz_events * 0.65 * 40/60)`
  - h11 (100% suppression): `max(400, normal_dmz_events)`
  - h12 (5% suppression): `max(20, normal_dmz_events * 0.05)`
  - Minimums ensure reasonable deny volume even without the parameter
- **`bin/generators/generate_asa.py`** -- Calculates `normal_dmz_events` estimate from registry session count + tcp_session DMZ fraction, passes to scenario. Formula: `(registry_sessions * 2) + (remaining * 0.41 * 0.5 * 2)`

### Verification

Scale 1.0 (default): Day 6 vs Day 7 DMZ events per hour within ±17%:
- h10: 1,225 vs 1,283 (95%) | h11: 1,444 vs 1,267 (113%) | h12: 1,230 vs 1,100 (111%)
- h11 composition: 34 Built + 46 Teardown + 1,297 Deny (deny dominates correctly)

Scale 3.5 + orders=5000 (production params): Day 6 vs Day 7 within ±19%:
- h10: 38,485 vs 40,413 (95%) | h11: 48,282 vs 40,254 (119%) | h12: 37,356 vs 34,483 (108%)
- h11 composition: 159 Built + 1,181 Teardown + 46,666 Deny

---

## 2026-02-18 ~06:00 UTC -- Firewall Misconfig: Calibrate Deny Volume to Match Suppressed DMZ Traffic

### Context

After ASA baseline suppression was implemented, the firewall_misconfig scenario (Day 6, h10-12) correctly suppressed DMZ Built/Teardown events. However, in Splunk timecharts filtered by `dest_zone=dmz`, Day 6 visually appeared as a low-traffic day because the deny events didn't compensate for the suppressed DMZ traffic volume.

### Changes

- **`bin/scenarios/network/firewall_misconfig.py`** -- Calibrated deny counts based on measured DMZ event totals:
  - h10 (65% suppression): 250 -> **700** denies (compensates ~690 suppressed DMZ events)
  - h11 (100% suppression): 400 -> **1100** denies (compensates ~1050 suppressed DMZ events)
  - h12 (5% suppression): 20 -> **30** denies (minor adjustment)

### Verification

21-day dataset with all scenarios, comparing `dest_zone=dmz` total events:

| Hour | Day 6 (scenario) | Day 7 (normal) | Delta |
|------|-----------------|----------------|-------|
| h09 (pre-outage) | 1,397 | 1,241 | +156 (normal noise) |
| h10 (outage start) | 1,313 | 1,304 | +9 |
| h11 (full outage) | 1,286 | 1,280 | +6 |
| h12 (rollback) | 1,185 | 1,104 | +81 |
| h13 (post-outage) | 1,270 | 1,216 | +54 (normal noise) |

Day 6 h11 composition: 43 Built + 53 Teardown + 1,100 Deny (deny dominates as expected).

---

## 2026-02-18 ~04:00 UTC -- CLAUDE.md Size Reduction (1023 → 549 lines)

### Context

CLAUDE.md had grown to 1023 lines, consuming significant context window on every message. Reviewed all sections for content that is either duplicated in code, purely historical, or generic reference material.

### Changes

- **`CLAUDE.md`** -- Removed 474 lines (46% reduction):
  - Removed "Splunk App Development" section (~190 lines) -- generic Splunk SDK tutorial, not project-specific
  - Removed "Log Format Examples" section (~55 lines) -- formats visible in generator code and output
  - Removed "Known Scenario Source Gaps" (~10 lines) -- all gaps already resolved
  - Removed full Webex 21-room device inventory table (~30 lines) -- replaced with 2-line summary
  - Removed "Sensor + Webex Correlation" section (~50 lines) -- meeting lifecycle, problem rooms, sunny rooms detail
  - Condensed "Customer Pool & VIP Segmentation" (~20 lines removed) -- kept formula, removed example tables
  - Condensed "Meraki Device Configuration" (~40 lines removed) -- replaced 5 sub-tables with 2-line summary
  - Condensed "Sample SPL Queries" (~15 lines removed) -- kept 3 key patterns
  - Condensed "Available Log Sources" (~25 lines removed) -- replaced 4-column table with grouped list
- **`docs/CLAUDE.md.backup-2026-02-18`** -- Full backup of pre-trimmed version (1023 lines)

### Sections Preserved

All essential project context retained: Network architecture, scenarios, company data, servers, key users, CLI options, volume patterns, design patterns, development notes.

---

## 2026-02-18 ~02:00 UTC -- ASA Baseline Suppression During Scenarios

### Context

ASA generator produced full baseline Built/Teardown events for external→DMZ web traffic even during outage scenarios (firewall_misconfig, DDoS, memory_leak, etc.). This meant Splunk showed hundreds of successful web connections simultaneously with deny events from ACL blocks -- unrealistic.

### Changes

- **`bin/scenarios/network/firewall_misconfig.py`** -- Added `asa_baseline_suppression()`: h10=0.65, h11=1.0, h12=0.05. Increased deny events: h10=250 (was 30), h11=400 (was 60), h12=20 (was 5).
- **`bin/scenarios/network/ddos_attack.py`** -- Added `asa_baseline_suppression()`: scales with intensity (`min(0.95, intensity)`). Increased DDoS event volume base from 200 to 600 per peak hour.
- **`bin/scenarios/ops/memory_leak.py`** -- Added `asa_baseline_suppression()`: Day 7=0.2, Day 8=0.4, Day 9=0.6, Day 10 pre-OOM=0.8, OOM=0.95.
- **`bin/scenarios/ops/cpu_runaway.py`** -- Added `asa_baseline_suppression()`: sev1=0.25, sev2=0.7, sev3=0.05.
- **`bin/scenarios/network/certificate_expiry.py`** -- Added `asa_baseline_suppression()`: 0.9 during cert outage (h0-7).
- **`bin/generators/generate_asa.py`** -- Added `web_suppression` parameter to `generate_baseline_hour()`. Filters registry web sessions by suppression factor. Added `_web_suppression_ctx` global so `asa_tcp_session()` reduces its 50% outside→dmz split during scenarios. Main loop calculates suppression from all active scenarios before baseline generation.

### Verification

21-day dataset with all scenarios:
- Firewall misconfig h11 (100% suppression): **0 DMZ Built**, 440 deny events (dominates)
- Firewall misconfig h10 (65% suppression): 248 DMZ Built (was ~600), 323 deny events
- DDoS h08 full attack: **4 DMZ Built** (was ~600), 370 deny + 91 rate-limit + 60 threat events
- Memory leak Day 9 (60% suppression): 3,206 DMZ Built (was ~6,800)
- CPU runaway Day 11 (70% critical): 2,042 DMZ Built (was ~6,800)
- Cert expiry h00-h06 (90% suppression): 6-12 DMZ Built per hour (was ~60-120)
- Normal day (no scenarios): 6,849 DMZ Built (unchanged baseline)
- Internal traffic (DC, VPN, site-to-site) unaffected during all scenarios

---

## 2026-02-18 ~00:30 UTC -- Scenario Error Rates: Realistic Severity

### Context

Scenario error rates in `access_should_error()` were too low, allowing orders to succeed during outages where the web shop should be completely unreachable. User feedback: "firewall misconfig should mean 0 orders if the webshop is blocked" and "DDoS and cpu_runaway should be even stricter".

### Changes

- **`bin/scenarios/network/firewall_misconfig.py`** -- ACL blocks ALL external traffic, so error_rate=100% during outage hours 10-11 (was 30/50%). Hour 12 (rollback at 12:03) set to 50% blend.
- **`bin/scenarios/network/ddos_attack.py`** -- Full attack (intensity>=0.8): 95% (was 80%). Partial mitigation (>=0.5): 80% (was 50%). Ramping (>=0.3): 60% (was 30%). Probing (>=0.05): 20% (was 8%).
- **`bin/scenarios/ops/cpu_runaway.py`** -- Critical severity (DB at 100% CPU): 85% (was 45%). Warning severity: 30% (was 10%). Recovery: 5% (was 3%).
- **`bin/scenarios/ops/memory_leak.py`** -- Day 7: 25% (was 12%). Day 8: 50% (was 25%). Day 9: 75% (was 40%). Day 10 pre-OOM: 85-92% (was 50-60%). OOM crash: 95% (was 70%).

### Verification

21-day dataset with all scenarios:
- Firewall misconfig (Jan 6): 0 orders during hour 11 (100% blocked), 239 total (normal outside outage window)
- DDoS (Jan 18): 129 orders total (vs ~300 normal), 0-1 orders during peak hours 06-09
- CPU runaway (Jan 11): 63 orders total, near-zero during critical phase
- CPU runaway (Jan 12): 0-8 orders pre-fix, snaps back to normal after 10:30 fix
- Memory leak descending staircase: 256 (Day 7) -> 173 (Day 8) -> 84 (Day 9) -> 0-3/hour pre-OOM (Day 10)
- Event volume consistent across all days (16K-25K/day) -- only error codes change, not session count

---

## 2026-02-17 ~22:00 UTC -- Access Log: Consistent Volume During Scenarios

### Context

Access log generator reduced session volume by 30-70% during scenarios (memory_leak, cpu_runaway, ddos_attack, firewall_misconfig, certificate_expiry) AND injected error codes. This caused event volume to drop dramatically during scenarios. Real web servers don't see less traffic when broken -- they see the SAME traffic but with more error responses.

### Changes

- **`bin/generators/generate_access.py`** -- Removed session volume reduction logic (lines 844-867: `effective_sessions = sessions * 30/50/75%`). Removed post-recovery ramp-up logic (lines 820-833, 858-866: gradual 30%->85% restoration). Replaced SSL outage special case (lines 835-842: `sessions // 3` error events) with `error_rate = 95` override that uses normal session generation. Sessions now always run at full baseline volume. Scenarios inject errors via `error_rate` parameter applied to EVERY page in each session. Orders drop naturally because `/checkout/complete` only registers when `status == 200`.

### Verification

14-day dataset with all scenarios:
- Event volume consistent: 16K-25K/day (variation from weekday/weekend factor only, no scenario drops)
- Error rates proportional to scenario severity: 0.2% baseline -> 33.8% memory_leak OOM -> 37.8% cpu_runaway critical
- Orders drop organically: 202/day (OOM day) vs 287-447/day (normal) -- checkout failures prevent order registration

---

## 2026-02-17 ~20:00 UTC -- Logical Correlation Verification (120 checks, 21 categories)

### Context

Systematic verification of all logical correlations between 24 log generators, 10 scenarios, and shared data structures. 120 checks across 21 categories were tested against a 14-day generated dataset (3.2M events).

### Bugs Fixed

- **`bin/generators/generate_gcp.py`** -- Fixed email domain: all 14 `principalEmail` references used hardcoded `@theTshirtCompany.com` instead of `@theFakeTshirtCompany.com`. Now imports and uses `TENANT` constant from company.py. Affected ~8,375 events per 14-day run.
- **`bin/generators/generate_sysmon.py`** -- Fixed 2 hardcoded domain references in Outlook process template: `autodiscover.theTshirtCompany.com` and `.ost` filename. Now uses f-string with `TENANT` constant.
- **`bin/generators/generate_webex_ta.py`** -- Fixed attendee IP assignment: all 4 calls to `get_user_ip(location)` (which generated random subnet IPs) replaced with deterministic `user.ip_address` / `host.ip_address` from company.py. All 175 employees now get consistent IPs across Webex TA and other generators.

### Verification Summary (120 checks)

| Category | Checks | Pass | Partial | Fail | Gap |
|----------|--------|------|---------|------|-----|
| 1. ASA Network Flow Logic | 10 | 9 | 0 | 0 | 1 |
| 2. E-Commerce Pipeline | 9 | 9 | 0 | 0 | 0 |
| 3. VPN & Remote Access | 7 | 5 | 0 | 0 | 2 |
| 4. Authentication Chain | 8 | 7 | 0 | 0 | 1 |
| 5. Exchange + O365 | 7 | 7 | 0 | 0 | 0 |
| 6. Meraki Multi-Device | 10 | 10 | 0 | 0 | 0 |
| 7. Meeting Room Correlation | 8 | 7 | 0 | 0 | 1 |
| 8. DNS & Secure Access | 6 | 6 | 0 | 0 | 0 |
| 9. ACI Data Center | 5 | 3 | 1 | 0 | 1 |
| 10. Catalyst & Catalyst Center | 5 | 5 | 0 | 0 | 0 |
| 11. Windows Metrics | 6 | 6 | 0 | 0 | 0 |
| 12. Linux Metrics + Access | 5 | 5 | 0 | 0 | 0 |
| 13. ServiceNow Incidents | 5 | 5 | 0 | 0 | 0 |
| 14. AWS + GCP Cloud | 6 | 6 | 0 | 0 | 0 |
| 15. Timestamps & Timezone | 4 | 4 | 0 | 0 | 0 |
| 16. Volume & Business Hours | 6 | 6 | 0 | 0 | 0 |
| 17. User-Device-IP Binding | 5 | 3 | 0 | 0 | 2 |
| 18. Scenario demo_id Tagging | 4 | 4 | 0 | 0 | 0 |
| 19. Dependency Chain | 4 | 4 | 0 | 0 | 0 |
| 20. Physical Impossibility | 4 | 4 | 0 | 0 | 0 |
| 21. Edge Cases | 3 | 3 | 0 | 0 | 0 |
| **TOTAL** | **120** | **112** | **1** | **0** | **8** |

### Known Gaps (not fixed, documented for future consideration)

1. **VPN IP hash collisions (minor)**: 26 of 90 VPN IPs shared by 2-4 users due to SHA256 mapping into 200-address pool. Each user is deterministic but not unique.
2. **EntraID missing VPN IPs**: VPN users show site-local IPs instead of 10.250.0.x in EntraID sign-ins.
3. **Ransomware scenario missing from EntraID**: CLAUDE.md lists `entraid` as affected source for ransomware_attempt, but no EntraID events carry demo_id=ransomware_attempt.
4. **Ghost meetings lack explicit tag**: ~15% ghost meetings per spec, but no explicit `ghost: true` field -- must be inferred from missing participant_joined events.
5. **ACI contract-match missing WEB->APP traffic**: APP->DB (22 events) present, but WebDMZ EPG events use random server IPs instead of DMZ 172.16.1.x.
6. **ACI not tagged for memory_leak**: ACI is not listed as affected source for memory_leak in CLAUDE.md (by design).
7. **Catalyst Center/ACI include empty demo_id key**: Baseline events have `"demo_id": ""` instead of omitting the key (cosmetic).

---

## 2026-02-17 ~18:00 UTC -- ASA CID Allocator Fix: Cross-Day Collisions

### Context

The previous CID allocator fix (same session) used per-day random base offsets with `init_cid_allocator(day)` resetting the counter each day. With 31 days and random bases in a 400K range, day ranges overlapped -- session_id 412720 appeared on 9 different days with different src/dst. Root cause: `_cid_base = rng.randint(100000, 500000)` per day with ~17,500 events/day = ranges overlap.

### Changes

- **`bin/shared/config.py`** -- Rewrote CID allocator to use a single global monotonic counter that NEVER resets across days. `init_cid_allocator()` now initializes once (first call only); subsequent calls are no-ops. Added `reset_cid_allocator()` for testing. Counter wraps within 100000-999999 range (900K unique IDs, sufficient for 31 days * ~17,500/day = ~540K events).
- **`bin/generators/generate_asa.py`** -- Updated comment on `init_cid_allocator(day)` call to reflect new no-op behavior.

### Verification

- Generated 31-day dataset with all scenarios: 1,034,191 events, 517,521 unique CIDs
- Zero cross-day collisions (previously ~2,000+ per day)
- Zero same-day duplicates
- CID range: 100001 to 617521 (well within 900K limit)

---

## 2026-02-17 ~16:00 UTC -- Project Audit: Splunk Config Cleanup

### Context

Full project audit covering generators, Splunk configuration, and cross-generator correlation. Found 1 critical bug, several consistency improvements.

### Changes

- **`default/transforms.conf`** -- Renamed stanza `[host_from_demo_field]` to `[perfmon_set_host_from_event]` for clarity.
- **`default/props.conf`** -- Fixed 4 broken transform references: Perfmon Processor/Memory/LogicalDisk/Network_Interface stanzas referenced `host_from_demo` (which didn't exist in transforms.conf). All 8 Perfmon stanzas now correctly reference `perfmon_set_host_from_event`.
- **`default/props.conf`** -- Added `CHARSET = UTF-8` to 9 stanzas that were missing it: o365:reporting:messagetrace, o365:management:activity, Perfmon:Generic, azure:servicebus, online:order:registry, online:order, google:gcp:pubsub:audit (base + admin_activity + data_access).
- **`default/README.md`** -- Updated transform name reference.
- **`CLAUDE.md`** -- Updated generator standard signature to include `progress_callback` and `output_dir` alternative. Added note about scale behavior in perfmon/orders/servicebus.

### Audit Results (no action needed)

- IP addresses: OK across all generators (company.py used consistently)
- Username/email format: OK (all use `user@theFakeTshirtCompany.com`)
- Order correlation chain: OK (access -> orders -> servicebus -> sap via tshirtcid)
- Webex/Meraki/Exchange meeting correlation: OK (shared meeting_schedule.py)
- Scenario demo_id tagging: OK
- ASA session_id uniqueness: OK (fixed earlier this session)
- inputs.conf coverage: OK (all generators have matching monitors)
- eventtypes.conf/tags.conf: OK (CIM-compatible)

---

## 2026-02-17 ~14:00 UTC -- ASA Unique Connection IDs (Session ID Collision Fix)

### Context

ASA connection IDs (session_id) were generated with `random.randint(100000, 999999)` per event, leading to collisions where different connections shared the same session ID on the same day. With ~17,500 sessions/day and 900,000 possible IDs, the Birthday Paradox caused ~17% collision probability per day. In Splunk, `| stats values(src) values(dest) by session_id _time` showed multiple source/dest pairs sharing the same session_id.

### Changes

- `bin/shared/config.py` -- Added `init_cid_allocator(day_seed)` and `next_cid()` functions. Monotonically increasing counter with per-day deterministic base offset. Shared between baseline generator and scenarios.
- `bin/generators/generate_asa.py` -- Replaced all 8 `random.randint(100000, 999999)` calls with `next_cid()`. Calls `init_cid_allocator(day)` at the start of each day's generation loop.
- `bin/scenarios/security/exfil.py` -- Replaced 5 `cid = random.randint(100000, 999999)` with `next_cid()`.
- `bin/scenarios/security/ransomware_attempt.py` -- Replaced 2 ASA `conn_id = random.randint(100000, 999999)` with `next_cid()`.
- `bin/scenarios/network/certificate_expiry.py` -- Replaced 1 `conn_id = random.randint(100000, 999999)` with `next_cid()`.
- `bin/scenarios/ops/memory_leak.py` -- Replaced 1 `conn_id = random.randint(100000, 999999)` with `next_cid()`.
- `bin/scenarios/ops/cpu_runaway.py` -- Replaced 1 `conn_id = random.randint(100000, 999999)` with `next_cid()`.

### Verification

```
14-day run with all scenarios:
  234,285 unique session IDs
  0 collisions (each CID appears exactly 2 times: Built + Teardown)
```

---

## 2026-02-17 ~13:00 UTC -- Search-Time demo_id Field Extraction

### Context

The `demo_id` field was only extracted at index time as `IDX_demo_id` (via `TRANSFORMS-demo_id` with `WRITE_META = true`). When `KV_MODE=AUTO` conflicted with other CIM field extractions on certain sourcetypes, the `demo_id` field was not reliably available at search time. Users had to use `IDX_demo_id` instead of the expected `demo_id` field name.

### Changes

- `default/transforms.conf` -- Added `[extract_demo_id_search]` stanza: same regex as `extract_demo_id_indexed` but outputs `demo_id::$1$2` (search-time field, no `WRITE_META`). Matches both KV format (`demo_id=exfil`) and JSON format (`"demo_id": "exfil"`).
- `default/props.conf` -- Added `REPORT-demo_id_search = extract_demo_id_search` to all 57 sourcetype stanzas (every stanza that already had `TRANSFORMS-demo_id`). This explicit `REPORT-` extraction works independently of `KV_MODE` settings.

### Result

- `demo_id` now available as a search-time field via explicit regex extraction (not dependent on `KV_MODE`)
- `IDX_demo_id` still available for `tstats` acceleration queries
- Both extractions use the same regex, applied at different processing stages
- No data regeneration required -- this is a Splunk config-only change

---

## 2026-02-17 ~12:00 UTC -- Consistent Short Hostnames Across Windows Generators

### Context

Perfmon, WinEventLog, and Sysmon used inconsistent hostname formats for the same machines. Perfmon used short hostnames (`demo_host=AUS-WS-BGARCIA01`) while WinEventLog and Sysmon used FQDNs (`ComputerName=AUS-WS-BGARCIA01.theFakeTshirtCompany.com`). This caused Splunk `host` field mismatches -- cross-correlation between sourcetypes failed because the host values differed.

### Changes

- `bin/generators/generate_wineventlog.py` -- Removed `.theFakeTshirtCompany.com` suffix from all 26 `ComputerName={computer}` lines across all event templates (4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4719, 4720, 4722, 4724, 4740, 4768, 4769, 4771, 4776, 5136, 5140, 5145, 7045, 7036, 1102, 6, 1074, 140). Used `replace_all`.
- `bin/generators/generate_sysmon.py` -- Removed `fqdn` variable from `_kv_header()`, changed `ComputerName={fqdn}` to `ComputerName={computer}`.
- `bin/generators/generate_sysmon.py` -- Changed `SourceHostname` in `sysmon_eid3()` from FQDN to short hostname.

### Preserved FQDN (by design)

- WinEventLog Event 37 time sync messages: `DC-BOS-01.theFakeTshirtCompany.com` (NTP source)
- WinEventLog Event 1014 DNS timeout targets: `wpad.theFakeTshirtCompany.com`
- Sysmon `DestinationHostname` in EID 3: Internal servers as DNS-resolved destinations
- Sysmon `DNS_INTERNAL` list and DNS query targets

### Verification

```
Perfmon:      demo_host=DC-BOS-01               (short) ✅
WinEventLog:  ComputerName=DC-BOS-02             (short) ✅
Sysmon:       ComputerName=FILE-BOS-01           (short) ✅
FQDN in time sync messages:                      preserved ✅
Sysmon DestinationHostname FQDN:                  preserved ✅
ComputerName FQDN leak check:                     0 lines ✅
```

---

## 2026-02-17 ~10:00 UTC -- Sysmon Client Workstation Scaling

### Context

The Sysmon generator had a fixed 20-workstation sample per day (deterministic seed, not configurable via `--clients`). After the WinEventLog client expansion, Sysmon was inconsistent -- WinEventLog scaled with `--clients=N` but Sysmon used random 20-workstation samples that didn't correlate with WinEventLog hostnames. A user running `--clients=40` would get 40 workstations in WinEventLog but random 20 in Sysmon.

### Changes

- `bin/generators/generate_sysmon.py` -- Added `num_clients` parameter to `generate_sysmon_logs()` (default 0 = legacy 20-sample behavior).
- `bin/generators/generate_sysmon.py` -- Added 8 `CLIENT_APP_PROFILES` with weighted application profiles (chrome, outlook, teams, edge, office, onedrive, system_background, misc_user). Each profile defines correlated process trees, network targets, DNS queries, file paths, and DLLs for realistic per-application event clusters.
- `bin/generators/generate_sysmon.py` -- Added `CLIENT_EID_WEIGHTS` for client workstation EID distribution (no EID 8/10 in baseline -- attack indicators only).
- `bin/generators/generate_sysmon.py` -- Added `_pick_app_profile()`, `_resolve_template()` helper functions.
- `bin/generators/generate_sysmon.py` -- Added 7 client sub-generator functions:
  - `_client_process_create()` -- EID 1 with parent-child process trees (30% child spawn chance)
  - `_client_network_connect()` -- EID 3 matching profile network targets
  - `_client_process_terminate()` -- EID 5 matching profile app
  - `_client_image_loaded()` -- EID 7 with profile-specific and common DLLs
  - `_client_file_create()` -- EID 11 with profile-specific cache/temp/doc files
  - `_client_registry_set()` -- EID 13 with workstation registry paths
  - `_client_dns_query()` -- EID 22 with profile-specific domains
- `bin/generators/generate_sysmon.py` -- Added `generate_client_sysmon_hour()` orchestrator with work-hour gating (7-18 weekdays, 10% weekend overtime), weighted EID selection.
- `bin/generators/generate_sysmon.py` -- Modified main loop: when `num_clients > 0`, uses `build_wineventlog_client_list()` (imported from WinEventLog) instead of legacy `select_sampled_workstations()`. Ensures same hostnames in both generators.
- `bin/generators/generate_sysmon.py` -- Updated standalone CLI with `--clients` argument.
- `bin/main_generate.py` -- Added `sysmon_kwargs` dict passing `num_clients` from `args.clients`.
- `bin/main_generate.py` -- Updated `get_kwargs_for_generator()` to return `sysmon_kwargs` for sysmon.
- `bin/main_generate.py` -- Added `_estimate_run()` sysmon block: server base 990/day + 18 events/client/day.

### Volume Impact

| --clients | Server events/day | Client events/day | Total/day | 14-day total |
|-----------|-------------------|-------------------|-----------|-------------|
| 0 (legacy) | ~990 | ~1,314 (20 random) | ~2,304 | ~15,067 |
| 5 | ~990 | 88 | ~1,076 | ~15,058 |
| 40 | ~990 | 698 | ~1,687 | ~23,614 |
| 175 | ~990 | 3,063 | ~4,053 | ~56,742 (est) |

~18 events/client/day (14-day average, scale=1.0).

### Client EID Distribution

| EID | Event Type | Percentage |
|-----|-----------|------------|
| 1 | ProcessCreate | 27% |
| 3 | NetworkConnect | 18% |
| 7 | ImageLoaded | 14% |
| 5 | ProcessTerminate | 11% |
| 11 | FileCreate | 10% |
| 22 | DNSQuery | 9% |
| 13 | RegistryValueSet | 8% |

### Files Changed

| File | Changes |
|------|---------|
| `bin/generators/generate_sysmon.py` | Added `num_clients` param, 8 app profiles, `CLIENT_EID_WEIGHTS`, 7 sub-generators, orchestrator, modified main loop, CLI update |
| `bin/main_generate.py` | Added `sysmon_kwargs`, updated `get_kwargs_for_generator()`, added `_estimate_run()` sysmon block |

### Verification

- Syntax check: both files pass
- 0 clients (legacy): 15,067 events / 14 days (no regression)
- 5 clients, 14 days: 15,058 events (estimation: 15,120, error 0.4%)
- 40 clients, 14 days: 23,614 events (estimation: 23,940, error 1.4%)
- Scenarios (exfil + ransomware, 5 clients): 15,125 events (+67 scenario events, no interference)
- Hostname correlation: identical 5 hosts in both Sysmon and WinEventLog (`BOS-WS-AMILLER01`, `ATL-WS-JBROWN01`, `AUS-WS-BWHITE01`, `BOS-WS-JSMITH01`, `BOS-WS-SWILSON01`)
- Sample event format verified (correct KV structure, parent-child trees, profile-driven content)

---

## 2026-02-17 ~08:00 UTC -- WinEventLog Baseline Client Workstation Events

### Context

WinEventLog generator only produced events for 13 Windows servers. Client workstations (`*WS-*`) had ~96 scenario-only events vs ~13K server events over 14 days. Splunk query `index=fake_tshrt sourcetype=FAKE:WinEventLog host=*WS-*` returned almost nothing. The `--clients` parameter only affected Perfmon. A real enterprise would have significant WinEventLog telemetry from endpoints.

### Changes

- `bin/generators/generate_wineventlog.py` -- Added `num_clients` parameter to `generate_wineventlog()` signature (default 0 for backward compatibility).
- `bin/generators/generate_wineventlog.py` -- Added client constants: `WORKSTATION_PROCESSES` (12 processes), `CLIENT_SERVICES` (13 services), `CLIENT_APP_CRASH_SOURCES` (7 crash sources).
- `bin/generators/generate_wineventlog.py` -- Added `build_wineventlog_client_list(num_clients)`: prioritizes scenario users (alex.miller, jessica.brown, brooklyn.white), fills remaining from USER_KEYS. Returns User objects.
- `bin/generators/generate_wineventlog.py` -- Added `_dc_for_client(client)`: location-aware DC selection (ATL -> DC-ATL-01, BOS/AUS -> random DC-BOS-01/02) matching network architecture.
- `bin/generators/generate_wineventlog.py` -- Added 2 new event templates: `event_4634()` (logoff, TaskCategory=Logoff) and `event_4689()` (process termination, TaskCategory=Process Termination).
- `bin/generators/generate_wineventlog.py` -- Added 10 client event generator functions:
  - `generate_client_logon()` -- EventCode 4624 type 2 (interactive), morning 7-8 AM
  - `generate_client_logoff()` -- EventCode 4634 type 2, evening 17-18
  - `generate_client_network_logons()` -- EventCode 4624 type 3 to FILE-BOS-01, 1-3/work hour
  - `generate_client_process_events()` -- EventCode 4688/4689 pairs, 4-6/work hour (scaled)
  - `generate_client_service_events()` -- EventCode 7036, 2-3 services/boot + occasional during day
  - `generate_client_system_events()` -- EventCodes 37 (time sync), 10016 (DCOM), 1014 (DNS)
  - `generate_client_failed_logon()` -- EventCode 4625, ~2% chance morning hours
  - `generate_client_special_logon()` -- EventCode 4672, morning logon with admin privs
  - `generate_client_app_events()` -- EventCodes 1000/1001/1026, ~3% chance per work hour
  - `generate_client_hour()` -- Orchestrator dispatching all client generators, returns security/system/application dict
- `bin/generators/generate_wineventlog.py` -- Work-hour gating: most events 7-18 weekdays only, 10% weekend overtime chance, minimal service events off-hours.
- `bin/generators/generate_wineventlog.py` -- Integrated client generation into main day/hour loop (after server baseline, before scenarios).
- `bin/generators/generate_wineventlog.py` -- Fixed WER (Windows Error Reporting) EventCode 1001 message: Application Name now shows actual crashing app (chrome.exe, Teams.exe, etc.) instead of "Windows Error Reporting".
- `bin/main_generate.py` -- Added `wineventlog_kwargs` dict passing `num_clients` from `args.clients`.
- `bin/main_generate.py` -- Updated `get_kwargs_for_generator()` to return `wineventlog_kwargs` for wineventlog.
- `bin/main_generate.py` -- Updated `_estimate_run()` with wineventlog client scaling: `client_events = max(0, num_clients) * 37` per day.
- `bin/tui_generate.py` -- Renamed "Perfmon Clients (5-175)" to "Clients (5-175)" since the parameter now drives both Perfmon and WinEventLog.

### Volume Impact

| --clients | Events/day (14d avg) | 14-day total | vs baseline |
|-----------|---------------------|--------------|-------------|
| 0 | ~434 (servers only) | ~6,054 | baseline |
| 5 (default) | ~620 | ~8,672 | +43% |
| 40 | ~1,797 | ~25,164 | +316% |
| 175 | ~6,909 | ~96,726 | +1,497% |

~37 events/client/day (14-day average, scale=1.0).

### Files Changed

| File | Changes |
|------|---------|
| `bin/generators/generate_wineventlog.py` | Added `num_clients` param, client constants, DC selection, 2 event templates, 10 generator functions, orchestrator, main loop integration, WER fix |
| `bin/main_generate.py` | Added `wineventlog_kwargs`, updated `get_kwargs_for_generator()`, updated `_estimate_run()` |
| `bin/tui_generate.py` | Renamed "Perfmon Clients" to "Clients" label |

### Verification

- Syntax check: all 3 files pass
- 0 clients, 1 day: 603 events (servers only, no regression)
- 5 clients, 1 day: 844 events (241 client events)
- 40 clients, 1 day: 2,515 events
- 5 clients, 14 days: 8,672 events (estimation predicted 8,666, ~0.1% error)
- Exfil scenario + 5 clients, 14 days: 8,732 events (scenarios still work alongside client baseline)
- Event type distribution verified: 4624, 4625, 4634, 4672, 4688, 4689, 7036, 37, 10016, 1014, 1000, 1001, 1026
- WER Application Name verified: chrome.exe, Teams.exe, EXCEL.EXE, explorer.exe (no more "Windows Error Reporting")
- Sample events match existing XML format patterns

---

## 2026-02-17 ~05:30 UTC -- TUI Source Selection UX: Mutual Exclusion, Dependency Highlighting, Group Estimation Fix

### Context

User reported that toggling source groups (e.g. "cloud", "network") in the TUI did not affect the estimation display -- only individual source toggles did. Root cause: `_get_sources_str()` fell back to "all" when nothing was explicitly selected, so deselecting the "all" group had no visible effect on estimation. Additionally, no visual indication that selecting a dependent generator (e.g. SAP) would auto-include its dependency (e.g. access).

### Changes

- `bin/tui_generate.py` -- **Mutual exclusion for source selection**: Selecting "all" now deselects all individual groups and sources. Selecting any group or source deselects "all". This makes the estimation immediately responsive to group toggles.
- `bin/tui_generate.py` -- **Removed empty-to-all fallback**: `_get_sources_str()` now returns empty string when nothing is selected (estimation shows 0 events / 0 time). The fallback to "all" is only applied in `collect_config()` for actual generation.
- `bin/tui_generate.py` -- **Auto-dependency resolution**: `_expand_selected_sources()` now auto-includes dependency generators (e.g. selecting SAP adds access, selecting meraki adds webex). Tracked in `_auto_deps` set for UI display.
- `bin/tui_generate.py` -- **Dependency indicators in SOURCES section**: Auto-added dependencies show as `[+] access +sap,orders` in yellow, indicating they are automatically included and which generators need them.
- `bin/tui_generate.py` -- **Preview command improvement**: Shows `--all` instead of `--sources=all`, and `--sources=(none)` when nothing selected.
- `bin/tui_generate.py` -- Imported `GENERATOR_DEPENDENCIES` from `main_generate`.
- `bin/tui_generate.py` -- Pre-compute `_expand_selected_sources()` once per frame in `draw()` via `_cached_expanded` to avoid redundant computation across status line, section rendering, and estimation.

### Files Changed

| File | Changes |
|------|---------|
| `bin/tui_generate.py` | Mutual exclusion, dep resolution, dep indicators, preview fix, caching |

### Verification

- Syntax check: passes
- Logic test: "all" = 26 gens/3.3M, deselect all = 0 gens/0, cloud group = 6 gens/758K, cloud+network = 12 gens/2.4M (auto-deps: access, webex), SAP only = 2 gens/315K (auto-dep: access), retail group = 3 gens/329K (auto-dep: access)

---

## 2026-02-17 ~04:00 UTC -- TUI Volume and Time Estimation

### Context

The CLI banner now shows estimated event count and time before generation starts. The TUI needed the same live estimation, updating dynamically as the user changes sources, days, scale, clients, orders, or meraki health settings -- matching the existing pattern used for the Meraki health volume display.

### Changes

- `bin/tui_generate.py` -- Imported `_estimate_run` from `main_generate`.
- `bin/tui_generate.py` -- Added `_calc_total_estimate()` method that reads all current TUI form values (sources, days, scale, clients, client_interval, orders_per_day, full_metrics, meraki health settings) and calls `_estimate_run()` to get (total_events, estimated_seconds).
- `bin/tui_generate.py` -- Extended `_draw_status_line()` with two new segments: `Events: ~3.3M` (yellow/bold) and `Time: ~48s` (cyan, or red if >5 min). These update in real-time as the user edits any configuration value.
- `bin/tui_generate.py` -- Fixed `col` tracking in status line so all segments (Output, Sources, Files, Health, Events, Time) flow correctly regardless of which optional segments are present.
- `bin/tui_generate.py` -- Changed Meraki Health display from `~45,696/day` to shorter `~45,696/d` to save horizontal space for the new segments.

### Files Changed

| File | Changes |
|------|---------|
| `bin/tui_generate.py` | Import `_estimate_run`, `_calc_total_estimate()`, extended status line |

### Verification

- Syntax check: passes
- Mock TUI test: default 14d = 3.3M events / 48s, orders=3000 = 8.2M / 130s, 175 clients full-metrics = 4.9M / 50s
- Values match CLI estimation output

---

## 2026-02-17 ~03:00 UTC -- Progress Display Alignment Fix + Pre-Run Estimation

### Context

Two issues with the progress display from the previous session: (1) `--show-files` file paths (`->` lines) appeared misaligned because the background progress display thread printed between the `[checkmark]` completion line and its file paths, and (2) no pre-run estimation of event count or execution time, especially important when `--orders-per-day` and `--clients` significantly change volume.

### Part 1: Fix Progress Line Interleaving

- `bin/main_generate.py` -- Added `_progress_pause` (`threading.Event`) at module level. The display thread checks `_progress_pause.is_set()` at top of loop and skips printing when paused.
- `bin/main_generate.py` -- In `as_completed()` loop: completion output (checkmark + file paths) is now wrapped in `_progress_pause.set()` ... `_progress_pause.clear()` with a 50ms sleep to let the display thread finish its current cycle before printing.
- `bin/main_generate.py` -- Added `_progress_pause.clear()` at phase start to ensure clean state.

### Part 2: Pre-Run Volume and Time Estimation

- `bin/main_generate.py` -- Added `_EVENTS_PER_DAY` dict with calibrated per-day event counts for all 26 generators (scale=1.0, 14-day average, default settings).
- `bin/main_generate.py` -- Added `_THROUGHPUT_EPS` dict with events/sec throughput per generator (single-thread reference).
- `bin/main_generate.py` -- Added `_estimate_run()` function that returns (total_events, estimated_seconds, per_gen_events) with generator-specific scaling for:
  - `access/orders/servicebus/sap`: linear with `--orders-per-day` (default 224)
  - `perfmon`: base 37,776/day + ~340/extra client (no full-metrics) or ~610/extra client (full-metrics), scales with `--client-interval`
  - `meraki`: base 12,348/day + health polling at MR 3,456 + MS 42,240 at 15-min, scales with `--meraki-health-interval`
  - Time estimation uses parallel phase simulation with 1.8x GIL/IO contention factor
- `bin/main_generate.py` -- Added estimation display in banner (before the closing `=` separator): `Estimated: ~3.3M events, ~48s`. Shows notes for non-default settings: `(orders=3000 (13.4x), clients=40, full-metrics)`.

### Files Changed

| File | Changes |
|------|---------|
| `bin/main_generate.py` | `_progress_pause` Event, pause/resume in display thread + completion loop, `_EVENTS_PER_DAY`, `_THROUGHPUT_EPS`, `_estimate_run()`, banner estimation display |

### Verification

14-day test (26 generators, all scenarios, scale=1.0):
- Estimated: ~3.3M events, ~48s
- Actual: 3,263,353 events, 41.0s (event accuracy ~1%, time accuracy ~17% conservative)
- All 26 generators: 0 failures
- File path alignment: `->` lines correctly grouped under their `[checkmark]` lines

Estimation accuracy with non-default settings tested:
- `--orders-per-day=3000 --clients=40 --full-metrics --days=31`: ~19.0M events, ~4.8 min
- `--sources=asa,entraid,aws --days=14`: ~848K events, ~12s

---

## 2026-02-17 ~00:30 UTC -- Live Progress Display + Generator Performance Fixes

### Context

After the 3x speedup (1209s -> 367s), two issues remained: (1) no live progress during parallel generation -- the terminal appeared frozen for slow generators, and (2) GCP/Entraid/AWS generators were still slow relative to their event counts due to unnecessary datetime parsing and premature JSON serialization.

### Part 1: Live Progress Display

- `bin/main_generate.py` -- Added thread-safe progress tracking system: `_progress` dict, `_progress_lock`, `_report_progress()` callback, `_progress_display_thread()` background thread.
- `bin/main_generate.py` -- Updated `run_phase()` to register generators in progress tracker, start/stop display thread, and clear progress line before printing completion lines.
- All 26 generator files -- Added `progress_callback=None` parameter to main generate function signature. Added `if progress_callback: progress_callback(name, day + 1, days)` as first line in day loops (23 generators with day loops; 3 without: orders, servicebus, webex).
- Display shows: `[done/total] gen1 day/days | gen2 day/days | ...` refreshed every 0.5s during parallel execution.

### Part 2: GCP Timestamp Fix

- `bin/generators/generate_gcp.py` -- Eliminated strptime+strftime round-trip in `gcp_base_event()`. The function was creating a timestamp string via `ts_gcp()`, then parsing it BACK to datetime with `strptime()` to add 50-500ms for `receiveTimestamp`, then formatting again with `strftime()` -- 3 datetime operations per event. Replaced with string manipulation: extract 6-digit microseconds from known position, add delay, swap in place. Falls back to datetime only on rare second overflow (~25% of events).
- Isolated benchmark: 37K events in 0.9s (was 32s) -- 35x speedup.

### Part 3: Entraid Dict Optimization

- `bin/generators/generate_entraid.py` -- Changed 12 event functions (`signin_success`, `signin_failed`, `signin_blocked_by_ca`, `signin_from_threat_ip`, `signin_spray_noise`, `signin_service_principal`, `audit_base`, `audit_user_registered_security_info`, `audit_sspr_flow`, `audit_sspr_reset`, `risk_detection`, `signin_lockout`) to return dicts instead of JSON strings. Deferred `json.dumps()` to write time.
- `bin/generators/generate_entraid.py` -- Eliminated json.loads/json.dumps round-trip in 12 audit wrapper functions that previously parsed the JSON string just to add `demo_id`.
- `bin/generators/generate_entraid.py` -- Added `_sort_key()` helper for mixed dict/string event sorting.
- `bin/generators/generate_entraid.py` -- Updated write loops to handle both dicts and strings (for scenario-injected events).
- Isolated benchmark: 25K events in 0.7s (was 29s) -- 41x speedup.

### Files Changed

| File | Changes |
|------|---------|
| `bin/main_generate.py` | Progress tracking system, display thread, callback in kwargs |
| `bin/generators/generate_gcp.py` | Timestamp string manipulation, progress_callback |
| `bin/generators/generate_entraid.py` | Dict returns, deferred JSON serialization, _sort_key, progress_callback |
| 24 other generator files | `progress_callback=None` parameter + day-loop callback |

### Verification

Full 31-day benchmark (26M events, scale=1.0, 5000 orders/day, all scenarios, --parallel=4):
- All 26 generators: 0 failures
- Event counts: ~26.1M (consistent with baseline)
- Isolated generator speedups: GCP 35x, Entraid 41x, AWS 27x
- Progress display: live day-by-day status for all running generators
- Wall-clock total bounded by access (207s) and orders/servicebus (163-167s) -- unchanged generators

---

## 2026-02-16 ~20:00 UTC -- Performance Optimization: 3x Speedup (1209s -> 402s)

### Context

Full 31-day production run (26M events, scale=1.0, 5000 orders/day) took 1209 seconds (20 min). Root cause analysis found two critical algorithmic bottlenecks:

1. **ASA registry O(n^2) scan**: 2.18M web sessions scanned linearly for each of 744 hours = 1.62 billion comparisons, each calling `datetime.strptime()` twice. ASA alone took 992 seconds.
2. **`get_random_user()` allocated a new 175-element list on every call**: Called millions of times across 15 generators. Exchange: ~2.78M calls at 330 events/sec. Webex API: 137 events/sec for only 23K events.

### Fix 1: Cache `get_random_user()` -- company.py

- `bin/shared/company.py` -- Added `_USERS_LIST`, `_USERS_BY_LOCATION`, `_USERS_BY_DEPARTMENT` pre-computed caches at module level (after VPN_USERS). Built once from USERS dict at import time.
- `bin/shared/company.py` -- Rewrote `get_random_user()`: fast path (no filters, ~80% of calls) is a single `random.choice(_USERS_LIST)` with zero allocation. Location/department filters use pre-computed dict lookups.
- `bin/shared/company.py` -- Optimized `get_users_by_location()` and `get_users_by_department()` to use the same caches.
- All 15 generators benefit automatically without code changes.
- Benchmark: 1M unfiltered calls in 0.41s (2.4M calls/sec) vs previous ~200K calls/sec.

### Fix 2: ASA Registry Pre-Indexing -- generate_asa.py

- `bin/generators/generate_asa.py` -- Added `_index_registry_sessions(sessions, start_date)` function that processes each session ONCE and buckets into `Dict[(day, hour), List[Dict]]`. Replaces O(N*H) with O(N) indexing + O(1) per-hour lookup.
- `bin/generators/generate_asa.py` -- Added `_PARSE_DAY_CACHE` for caching start_date datetime parsing.
- `bin/generators/generate_asa.py` -- Changed `generate_asa_logs()`: loads registry then pre-indexes it. Changed `generate_baseline_hour()` parameter from `registry_sessions: List[Dict]` to `registry_index: Dict`.
- `bin/generators/generate_asa.py` -- Replaced O(N) list comprehension filter (line 1072-1074) with O(1) `registry_index.get((day, hour), [])`.

### Verification

Full 31-day benchmark (26M events, scale=1.0, 5000 orders/day, all scenarios):

| Generator | Before (s) | After (s) | Speedup |
|-----------|-----------|-----------|---------|
| ASA | 992 | 186 | 5.3x |
| Exchange | 350 | 107 | 3.3x |
| Orders | 529 | 156 | 3.4x |
| ServiceBus | 566 | 160 | 3.5x |
| Webex API | 173 | 26 | 6.7x |
| SAP | 116 | 23 | 5.0x |
| Meraki | 640 | 84 | 7.6x |
| **Total** | **1209** | **402** | **3.0x** |

- Throughput: 21,571 events/sec -> 64,866 events/sec (3x)
- ASA web session correlation: 97,839/97,839 (100%) -- unchanged
- ASA employee IP correlation: 47,327/47,327 (100%) -- unchanged
- Event counts: ~26M events (consistent with before)
- No output format changes

---

## 2026-02-16 ~18:00 UTC -- Employee IP Correlation: ASA + GCP

### Context

After fixing customer IP correlation (access-ASA web sessions), analysis of all 24 generators revealed 2 remaining IP correlation gaps. 12 of 14 generators already used employees' deterministic `ip_address` property (from the User dataclass in company.py), but ASA employee traffic (outbound TCP, DNS, NAT) and GCP audit logs used random `get_internal_ip()` instead. This meant employee actions in these sources could not be correlated by IP with Entra ID, Secure Access, WinEventLog, Sysmon, AWS CloudTrail, or other sources.

### Changed

**ASA employee traffic (`bin/generators/generate_asa.py`):**
- Added `get_random_user` to import from `shared.company`
- `asa_tcp_session()`: Replaced `get_internal_ip()` with `get_random_user().ip_address` for the outbound half (employee -> outside). Inbound half (external -> DMZ) unchanged.
- `asa_dns_query()`: Replaced `get_internal_ip()` with `get_random_user().ip_address` for employee DNS queries (UDP 302015/302016)
- `asa_nat()`: Replaced `get_internal_ip()` with `get_random_user().ip_address` for employee NAT translations (305011/305012)
- NOT changed (intentionally): `asa_dc_traffic()` (broad workstation chatter, not user-specific), `asa_site_to_site()` (bulk data replication), `asa_vpn()` (already correct), `asa_web_session()` / `asa_web_session_from_registry()` (already fixed via customer IP registry)

**GCP audit logs (`bin/generators/generate_gcp.py`):**
- Added `USERS` and `get_random_user` to import from `shared.company`
- Added `GCP_HUMAN_USERS` list (6 cloud/IT team members: angela.james, carlos.martinez, brandon.turner, david.robinson, jessica.brown, patrick.gonzalez -- same team as AWS)
- Added `_pick_gcp_user()` helper function (same pattern as AWS `_pick_human_user()`)
- Modified `gcp_base_event()`: Added optional `caller_ip` parameter (backward-compatible, defaults to `get_internal_ip()` when None)
- Updated all 12 baseline event generators with 50/50 human/service account mix: `gcp_compute_list`, `gcp_storage_get`, `gcp_storage_create`, `gcp_function_call`, `gcp_compute_start_stop`, `gcp_iam_sa_key_create`, `gcp_bigquery_query`, `gcp_logging_write`, `gcp_logging_list`, `gcp_storage_delete`, `gcp_storage_bucket_get`, `gcp_bigquery_tabledata_list`, `gcp_iam_set_policy`, plus inline `compute.instances.get` in `generate_baseline_hour()`
- Scenario functions unchanged (already use correct IPs: exfil functions use THREAT_IP `185.220.101.42`, cpu_runaway uses specific service account)

### Verification

- Generators run: access (10,153), asa (18,868), gcp (135) -- test at scale 0.1-0.5
- **ASA outbound TCP: 1,720/1,720 (100%)** employee IPs match known employees
- **ASA DNS queries (to outside): 1,096/1,096 (100%)** match
- **ASA NAT events: 596/596 (100%)** match
- **GCP human user events: 63/63 (100%)** -- all human caller IPs match known employees
- GCP human/SA split: ~46%/54% (target: 50/50)
- DC traffic (inside->inside): Correctly uses random workstation IPs (by design)
- No regressions in other event types

---

## 2026-02-16 ~10:30 UTC -- International Customer IPs + Access-ASA 1:1 Correlation

### Context

Customer IP addresses in access logs and ASA firewall logs were all US-only (6 hardcoded US prefixes), despite `customer_lookup.csv` having international customers. Additionally, ASA web session events used random IPs with zero correlation to access log sessions.

### Added

**International IP pools (23 countries):**
- `bin/shared/company.py` -- Added `CUSTOMER_IP_POOLS` (60 IP prefixes across 23 countries: US, CA, NO, SE, DK, FI, UK, DE, FR, NL, BE, CH, AT, IE, ES, IT, PT, PL, JP, AU, SG, IN, KR), `BROWSE_REGION_WEIGHTS` (weighted country distribution for random browse traffic), pre-computed `_BROWSE_REGIONS`/`_BROWSE_WEIGHTS` lists

**Deterministic IP functions:**
- `bin/shared/company.py` -- Added `get_customer_region(customer_id)` (moved from generate_orders.py), `get_customer_ip(customer_id)` (SHA256 hash-based, same pattern as vpn_ip), `get_visitor_ip()` (random international visitor IP from weighted pools). Added all three to NetworkHelper class.

**Web session registry (new NDJSON file):**
- `bin/generators/generate_access.py` -- Added `WEB_SESSION_REGISTRY` that captures every web session (IP, timestamps, bytes, web server, port, session_id, page count). Written to `web_session_registry.json` alongside `order_registry.json`.

**ASA 1:1 correlation:**
- `bin/generators/generate_asa.py` -- Added `load_web_session_registry()`, `asa_web_session_from_registry()`, `_parse_registry_hour()`, `_parse_registry_day()`. Modified `generate_baseline_hour()` to accept `registry_sessions` parameter. Registry-driven web sessions replace random 25% web sessions; falls back to original behavior if registry not available.

### Changed

- `bin/generators/generate_access.py` -- Import `get_customer_ip`, `get_visitor_ip` from company.py instead of local US-only implementation. Reordered customer_id assignment BEFORE IP assignment for deterministic mapping. Updated `generate_ssl_error_event()` to use international `get_visitor_ip()`.
- `bin/generators/generate_orders.py` -- Import `get_customer_region` from `shared.company` instead of local definition (identical logic).
- `bin/main_generate.py` -- Added `"asa": ["access"]` to `GENERATOR_DEPENDENCIES` (ASA now runs in Phase 2 after access).

### Verification

- Generators run: access (24,342 events), asa (32,465 events) -- 3-day test at scale 0.3
- Web session registry: 3,216 sessions captured
- **1:1 correlation: 3,216/3,216 (100%) web sessions found in ASA log**
- International distribution: 23 countries represented (US 58.6%, UK 7.6%, DE 5.9%, NO 5.8%, FR 3.9%, etc.)
- Deterministic: same customer_id always maps to same IP
- Orders generator: verified working with new import path
- All non-web ASA traffic (employee outbound, DNS, VPN, DC, site-to-site) unchanged

---

## 2026-02-16 ~01:30 UTC -- Supporting TA Alignment Phase 17+18: Final 8 Sourcetypes (100% CIM)

### Added

- **Phase 17+18** of Supporting TA Alignment project. Final phase -- achieves 100% CIM coverage across all 62 sourcetypes (~13.2M events).
- 6 sourcetypes needed new eventtypes/tags; 2 (ServiceNow change/cmdb) already complete from Phase 8.

**Configuration:**
- `local/props.conf` -- 2 new stanzas:
  - `[FAKE:access_combined]`: CIM Web model FIELDALIASes (src_ip, http_referrer, http_user_agent, http_content_length)
  - `[FAKE:azure:servicebus]`: vendor/product split, practical FIELDALIASes (message_id, queue, topic, event_type, order_id, customer_id), EVALs (response_time, severity)
- `local/eventtypes.conf` -- 6 new eventtypes: fake_mssql_all, fake_web_access, fake_retail_orders, fake_retail_registry, fake_servicebus_all, fake_sap_all
- `local/tags.conf` -- 6 new tag stanzas:
  - MSSQL: database
  - Apache: web
  - Orders + Registry: sales
  - ServiceBus: cloud
  - SAP: application

**CIM Models covered:**
- Database: MSSQL errorlog
- Web: Apache access (combined format)
- Sales: Retail orders + order registry
- Cloud: Azure ServiceBus (messaging queue)
- Application: SAP S/4HANA audit log

**ServiceNow change/cmdb: already fully covered by Phase 8 (ticketing + inventory tags).**

**Verification:** All 8 sourcetypes confirmed with raw field queries against Splunk index. Total event counts: access_combined (10.5M), servicebus (977K), orders (928K), sap (620K), registry (197K), mssql (3K), servicenow:change (624), servicenow:cmdb (37).

---

## 2026-02-16 ~01:00 UTC -- Supporting TA Alignment Phase 16: Entra ID riskDetection Eventtypes

### Added

- **Phase 16** of Supporting TA Alignment project. Source: `Splunk_TA_microsoft-cloudservices` v5.x (Splunkbase #3110).
- Completes CIM alignment for `FAKE:azure:aad:riskDetection` (96 events). Phase 4 added props.conf CIM fields + tag stanzas but no eventtypes -- this phase adds the missing eventtypes so tags activate.

**Configuration:**
- `local/eventtypes.conf` -- 2 new eventtypes:
  - `fake_entra_risk_detection`: all riskDetection events
  - `fake_entra_risk_high`: high-severity risk detections only (properties.riskLevel="high")
- `local/tags.conf` -- no changes needed (stanzas already existed from Phase 4, lines 300-306)
- `local/props.conf` -- no changes needed (default/props.conf already has EVAL-user, EVAL-severity, EVAL-action)

**CIM Models covered:** Alert (all risk detections + high-severity subset)

**Verification:** 96 events across 7 risk types (passwordSpray, impossibleTravel, leakedCredentials, maliciousIPAddress, unfamiliarFeatures, anonymizedIPAddress, suspiciousBrowser), 3 risk levels (low: 40, medium: 37, high: 19).

---

## 2026-02-16 ~00:30 UTC -- Supporting TA Alignment Phase 15: AWS Billing CUR + GuardDuty CIM

### Added

- **Phase 15** of Supporting TA Alignment project. Source: `Splunk_TA_aws` (Splunkbase). Billing has no CIM in real TA; GuardDuty adapted from `guard_duty_events*` eventtypes/tags.
- Aligns 2 sourcetypes (706 events total) with CIM data models.

**Configuration:**
- `local/props.conf` -- 2 new stanzas:
  - `[FAKE:aws:billing:cur]`: vendor/product EVALs, 8 FIELDALIASes (service, cost, usage, operation, service_name, region, resource_name, account_id from CUR CSV column names with `/` -> `_`)
  - `[FAKE:aws:cloudwatch:guardduty]`: vendor/product EVALs, action (normalized from actionType), src_ip (coalesce across API/network/portprobe paths), user (coalesce userName/instanceId), dest (coalesce instanceId/accessKeyId), body, alert_id, finding_type
- `local/eventtypes.conf` -- 4 new eventtypes: fake_aws_billing, fake_aws_guardduty, fake_aws_guardduty_alert (API-based), fake_aws_guardduty_ids (network-based)
- `local/tags.conf` -- 4 new tag stanzas:
  - Billing: cloud
  - GuardDuty: cloud (all), alert (API threats), ids + attack (network threats)

**CIM Models covered:**
- Cloud: billing + all GuardDuty findings
- Alert: GuardDuty API-based threats (AWS_API_CALL, KUBERNETES_API_CALL, RDS_LOGIN_ATTEMPT)
- IDS: GuardDuty network-based threats (NETWORK_CONNECTION, DNS_REQUEST, PORT_PROBE)

**No new transforms or lookups needed.** All mappings are inline EVAL/FIELDALIAS.

---

## 2026-02-16 ~00:00 UTC -- Supporting TA Alignment Phase 14: Meraki Health / IoT CIM

### Added

- **Phase 14** of Supporting TA Alignment project. The official Splunk_TA_cisco_meraki has **no CIM alignment** for health metrics, sensor readings, or camera analytics. All mappings are custom.
- Aligns 4 sourcetypes (~1.7M events total) with CIM data models.

**Configuration:**
- `local/props.conf` -- 4 new stanzas:
  - `[FAKE:meraki:switches:health]`: dvc, dvc_type, interface (portId), status (Connected->up, Disconnected->down), speed, duplex, description
  - `[FAKE:meraki:accesspoints:health]`: dvc, dvc_type, rssi, snr, channel_utilization, health_score, client_count, dest (area), description
  - `[FAKE:meraki:sensors]`: dvc, dvc_type (sensor.model), location (sensor.name), action (normalized from type), metric_name, temperature, humidity, description
  - `[FAKE:meraki:cameras]`: dvc, dvc_type, action (type), zone, people_count, status (health_status->status, motion/person->detected, analytics->reporting), description
- `local/eventtypes.conf`:
  - **Fixed** `fake_meraki_sensors` -- removed `type="sensor_reading"` filter to include door_open, door_close, water events (was 250K, now 292K events)
  - **New** eventtypes: fake_meraki_switches_health, fake_meraki_ap_health, fake_meraki_sensors_door, fake_meraki_cameras_health
- `local/tags.conf`:
  - **Updated** `fake_meraki_sensors` -- added network, inventory tags (was change only)
  - **New** tag stanzas: switches_health (performance, inventory, network), ap_health (performance, network), sensors_door (physical, change), cameras_health (inventory, network)

**CIM Models covered:**
- Performance: switch port status, AP wireless metrics (rssi, snr, channel utilization, health score)
- Inventory: device identity (dvc, dvc_type) for all 4 sourcetypes + camera health
- Change/IoT: sensor readings and state changes (door, water, temperature, humidity)
- Physical Security: door open/close events, camera motion/person detection

**No new transforms or lookups needed.** All mappings are inline EVAL/FIELDALIAS.

---

## 2026-02-15 ~23:00 UTC -- Supporting TA Alignment Phase 13: Cisco Catalyst Center CIM

### Added

- **Phase 13** of Supporting TA Alignment project. **No Supporting TA exists** for Cisco Catalyst Center (DNA Center). All CIM mappings are custom based on actual Catalyst Center API field structure.
- Aligns 4 sourcetypes (~46K events total) with CIM data models.

**Configuration:**
- `local/props.conf` -- 4 new stanzas:
  - `[FAKE:cisco:catalyst:devicehealth]`: vendor/product EVALs, dvc/dvc_type/src_ip FIELDALIASes, os (IOS-XE concat), status (from reachabilityHealth + overallHealth), severity (from overallHealth)
  - `[FAKE:cisco:catalyst:networkhealth]`: vendor/product EVALs, status/severity (from healthScore thresholds)
  - `[FAKE:cisco:catalyst:clienthealth]`: vendor/product EVALs, dest (siteId)
  - `[FAKE:cisco:catalyst:issue]`: vendor/product EVALs, type (issueCategory), id (issueId), urgency (from issuePriority P1-P4), dest (issueEntityValue), body (issueSummary)
- `local/eventtypes.conf` -- 4 new eventtypes: fake_catcenter_devicehealth, fake_catcenter_networkhealth, fake_catcenter_clienthealth, fake_catcenter_issue
- `local/tags.conf` -- 4 new tag stanzas:
  - Device health: inventory, network, performance, report (Inventory/Performance)
  - Network health: performance, network, report (Performance)
  - Client health: performance, network, report (Performance)
  - Issues: alert (Alert)

**CIM Models covered:**
- Inventory: device identity (dvc, dvc_type, src_ip, os)
- Performance: health scores (status, severity from overallHealth/healthScore thresholds)
- Alert: issues (type, urgency, id, dest, body)

**No new transforms or lookups needed.** All mappings are inline EVAL/FIELDALIAS.

---

## 2026-02-15 ~22:00 UTC -- Supporting TA Alignment Phase 12: Cisco Webex CIM

### Added

- **Phase 12** of Supporting TA Alignment project. Both Supporting TAs (`ta-cisco-webex-meetings-add-on-for-splunk`, `ta_cisco_webex_add_on_for_splunk`) have **zero CIM alignment** -- no eventtypes, tags, or field aliases. All CIM mappings in this phase are custom, based on actual event field structure verified via Splunk queries.
- Aligns 8 sourcetypes (~92K events total) with CIM data models.

**Configuration:**
- `local/props.conf` -- 8 new stanzas:
  - `[FAKE:cisco:webex:events]`: dvc, dvc_type, status, description, severity (case from overall_status), src_ip (nested), cpu_load_percent (nested)
  - `[FAKE:cisco:webex:meetings:history:meetingusagehistory]`: user, user_name, session_id, signature FIELDALIASes; dest, session_duration, participant_count EVALs
  - `[FAKE:cisco:webex:meetings:history:meetingattendeehistory]`: user_name, src_ip, session_id, signature FIELDALIASes; dest, app, session_duration EVALs (user already in default/)
  - `[FAKE:cisco:webex:meetings]`: user, user_name, session_id, signature FIELDALIASes; dest, app EVALs
  - `[FAKE:cisco:webex:admin:audit:events]`: object, object_category, description, src_user, status, change_type EVALs (user/action already in default/)
  - `[FAKE:cisco:webex:security:audit:events]`: user, user_name, src_ip, action, app, http_user_agent, signature EVALs; status/action_name case logic for login success/failure
  - `[FAKE:cisco:webex:meeting:qualities]`: user, user_name, src_ip, session_id FIELDALIASes; app, os, dvc EVALs (nested QoS arrays kept minimal)
  - `[FAKE:cisco:webex:call:detailed_history]`: user, src_user, dest_user, src, dest, direction, duration, session_id, status, result, app, signature EVALs (JSON keys with spaces)
- `local/eventtypes.conf` -- 8 new eventtypes: fake_webex_events, fake_webex_meetings_usage, fake_webex_meetings_attendee, fake_webex_meetings_api, fake_webex_admin_audit, fake_webex_security_audit, fake_webex_qualities, fake_webex_calling_history
- `local/tags.conf` -- 8 new tag stanzas:
  - Device events: inventory, network (Inventory)
  - Meetings usage/attendee/API/calling: network, session, communicate (Network Sessions)
  - Admin audit: change, audit (Change)
  - Security audit: authentication (Authentication)
  - Meeting qualities: performance, network (Performance)

**CIM Models covered:**
- Inventory: device health (dvc, dvc_type, status, severity)
- Network Sessions: meetings + calling (user, session_id, signature, duration, src/dest)
- Change: admin audit (object, description, change_type, src_user)
- Authentication: security audit (user, src_ip, action, status, http_user_agent)
- Performance: meeting quality (user, src_ip, session_id, app, os, dvc)

**No new transforms or lookups needed.** All mappings are inline EVAL/FIELDALIAS.

---

## 2026-02-16 ~02:00 UTC -- Supporting TA Alignment Phase 11: Cisco Secure Access (Umbrella) CIM

### Added

- **Phase 11** of Supporting TA Alignment project. Source: `TA-cisco-cloud-security-addon` (Splunkbase).
- Aligns 4 sourcetypes: `FAKE:cisco:umbrella:dns`, `FAKE:cisco:umbrella:proxy`, `FAKE:cisco:umbrella:firewall`, `FAKE:cisco:umbrella:audit` with CIM data models.
- Real TA uses `cisco:cloud_security:*` sourcetypes; our FAKE TA uses `cisco:umbrella:*`.

**Note:** Only proxy data (349K events) is currently indexed. DNS, firewall, and audit stanzas added for completeness.

**Configuration:**
- `local/props.conf` -- 4 new stanzas:
  - `[FAKE:cisco:umbrella:dns]`: vendor/product EVALs, src_ip FIELDALIAS, record_type/query_type normalization, reply_code_id mapping, message_type, action lowercase
  - `[FAKE:cisco:umbrella:proxy]`: vendor/product EVALs, bytes total, action lowercase, http_user_agent_length, url_length
  - `[FAKE:cisco:umbrella:firewall]`: vendor/product EVALs, action normalization (ALLOW->allowed, BLOCK->blocked), direction lowercase, bytes/packets FIELDALIASes and totals, transport/protocol/protocol_version, src_ip FIELDALIAS, dvc
  - `[FAKE:cisco:umbrella:audit]`: vendor/product EVALs only (minimal fields)
- `local/eventtypes.conf` -- 4 new eventtypes: fake_umbrella_dns, fake_umbrella_proxy, fake_umbrella_firewall, fake_umbrella_audit
- `local/tags.conf` -- 4 new tag stanzas:
  - DNS: dns, network, resolution (Network Resolution)
  - Proxy: proxy, web (Web)
  - Firewall: communicate, network (Network Traffic)
  - Audit: change (Change)

**CIM Models covered:**
- DNS: Network Resolution (query, reply_code_id, record_type, message_type)
- Proxy: Web (bytes total, action normalization, user agent/URL length)
- Firewall: Network Traffic (action, direction, transport, protocol, protocol_version, bytes/packets)
- Audit: Change (vendor/product only -- user/action already mapped in default/)

**No new transforms or lookups needed.** All mappings are inline EVAL/FIELDALIAS. EVAL statements override existing FIELDALIASes from default/ where normalization is needed (lowercase action, transport name mapping, etc.).

---

## 2026-02-16 ~01:00 UTC -- Supporting TA Alignment Phase 10: Catalyst IOS + ACI CIM

### Added

- **Phase 10** of Supporting TA Alignment project. Source: `TA_cisco_catalyst` (Splunkbase).
- Aligns 4 sourcetypes: `FAKE:cisco:ios` (Catalyst IOS-XE), `FAKE:cisco:aci:fault`, `FAKE:cisco:aci:event`, `FAKE:cisco:aci:audit` with CIM data models.

**Key fix:** Catalyst events previously had ZERO extracted fields (no `facility`, `severity_id`, `mnemonic`) because the REPORT transform was missing from `default/props.conf`. The existing `FIELDALIAS-action_for_catalyst = mnemonic AS action` was dead since `mnemonic` never existed.

**Configuration:**
- `local/transforms.conf` -- 4 new entries:
  - REPORT: `extract_fake_cisco_ios_general` (regex extracts facility, severity_id, mnemonic, message_text from IOS syslog)
  - Lookups: `fake_cisco_ios_severity_lookup`, `fake_cisco_ios_actions_lookup`, `fake_cisco_ios_aci_fault_codes_lookup`
- `local/props.conf` -- 4 new stanzas:
  - `[FAKE:cisco:ios]`: KV_MODE=none, REPORT, 2 LOOKUPs, 5 EVALs (vendor, product, dvc, vendor_action, dest)
  - `[FAKE:cisco:aci:fault]`: 10 EVALs (severity mapping, signature, description, object, cause, etc.), 1 LOOKUP (fault codes)
  - `[FAKE:cisco:aci:event]`: 8 EVALs (severity, description, object, cause, action, change_type, user)
  - `[FAKE:cisco:aci:audit]`: 10 EVALs (user, object, description, action, change_type, src_user, severity, status)
- `local/eventtypes.conf` -- 17 new eventtypes:
  - Catalyst (12): fake_catalyst_all, port_down/up, login_success/failed, ssh_login, dot1x, config_change, reload, restart, interface_admin_change, acl_log
  - ACI (5): fake_aci_fault_all, fault_critical, event_all, event_contract_match, audit_all
- `local/tags.conf` -- 16 new tag stanzas:
  - Catalyst (11): network, problem, authentication (4), change (4), communicate
  - ACI (5): alert (2), network (2), change+audit
- `lookups/` -- 3 CSV files copied from Supporting TA:
  - `cisco_ios_severity.csv` (9 rows): severity_id -> CIM severity
  - `cisco_ios_actions.csv` (65 rows): vendor_action -> CIM action
  - `cisco_ios_aci_fault_codes.csv` (~500 rows): fault_code -> vendor explanation

**CIM Models covered:**
- Catalyst: Authentication (login, SSH, 802.1X/MAB), Change (config, reload, restart, interface admin), Network Traffic (ACL logs)
- ACI Fault: Alert (severity mapping, fault code enrichment)
- ACI Event: Change (action/change_type), Network (contract matches)
- ACI Audit: Change (user actions, object tracking)

**Not included (out of scope):**
- `cisco_ios_interface_name.csv` -- Interface prefix normalization (GigabitEthernet -> Gi). Our generator already uses full names.
- `cisco_ios_icmp_code.csv` -- ICMP code lookup. Generator doesn't produce ACL events with ICMP codes.
- `cisco_ios_acl_excluded_ips.csv` -- ACL exclusion list. Not applicable to generated data.
- Numerous specific mnemonic-based REPORT transforms from real TA (dot1x_auth, mab_auth, authmgr_*, sessionmgr_*, epm_*, dhcp_snooping, etc.) -- would extract MAC addresses, interface names, session IDs. Generator message_text doesn't match these specific patterns precisely enough for reliable extraction.

---

## 2026-02-15 ~23:30 UTC -- Make scenario revenue impact more visible in order data

### Problem

Revenue timecharts (`timechart span=1h sum(pricing.total)`) did not clearly show revenue drops during several operational scenarios. Root causes:
1. **Post-recovery compensation spike** -- When a scenario ends, sessions instantly returned to 100% baseline. On high-traffic hours (e.g., Saturday evening for memory_leak OOM, Monday morning for cpu_runaway fix), this created massive spikes (2-3x baseline) that washed out the revenue dip.
2. **Dead letter pricing too subtle** -- 60% of products affected with only 15-50% price variation over 4 hours was almost invisible in daily revenue totals.

### Changes

**`bin/generators/generate_access.py`** -- Post-recovery ramp-up logic
- Added recovery state tracking across hours within each day
- After severe outage (error_rate >= 40 -> < 8): 4-hour ramp at 30% -> 50% -> 70% -> 85% of baseline
- After moderate outage (error_rate >= 20 -> < 8): 3-hour ramp at 50% -> 70% -> 85%
- Prevents instant return to full sessions, simulating real-world user behavior (users slowly return, caches refill, word spreads that site is back)
- Affects: memory_leak (Jan 10 post-OOM), cpu_runaway (Jan 12 post-fix), ddos_attack (Jan 18 post-ISP-filter)

**`bin/scenarios/ops/dead_letter_pricing.py`** -- Increased price distortion severity
- `affected_product_pct`: 0.60 -> 0.80 (80% of products now have wrong prices)
- New error type: `price_reset_to_zero` (factor 0.01-0.05, essentially free items)
- `double_discount_applied` factor: 0.50-0.65 -> 0.20-0.40 (60-80% discount)
- `stale_discount_not_removed` factor: 0.70-0.85 -> 0.50-0.70 (30-50% cheaper)
- Error rates increased: hour 8: 8% -> 15%, hours 9-10: 20% -> 35-40%, hour 11: 12% -> 30%, hour 12: 5% -> 15%, added hour 13 at 5%
- DLQ failure rates increased: hour 8: 0.15 -> 0.25, hours 9-10: 0.40 -> 0.60, hour 11: 0.30 -> 0.45, hour 12: 0.10 -> 0.20
- `full_recovery_hour` extended: 13 -> 14

**`bin/scenarios/network/ddos_attack.py`** -- Extended attack duration with slower recovery
- ISP filtering phase (hour 14): intensity 0.4 -> 0.6 (still significant)
- Subsiding phase (hours 15-17): intensity 0.2 -> 0.4 (infrastructure stressed)
- Added evening second wave (hours 18-19): intensity 0.3 (attacker tries again)
- Late evening (hours 20-21): intensity 0.15 (trailing off)
- Result: sustained revenue impact through entire day instead of quick afternoon recovery

**`bin/scenarios/ops/memory_leak.py`** -- Steeper pre-OOM error rate progression
- Day 7: error_rate 5% -> 12%, response_mult 1.5x -> 2.0x
- Day 8: error_rate 15% -> 25%, response_mult 2.5x -> 3.5x
- Day 9: error_rate 30% -> 40%, response_mult 4.0x -> 5.0x
- Day 10 pre-OOM: error_rate starting at 35% -> 50%, response_mult 6.0x -> 7.0x

### Expected Revenue Impact (after data regeneration)

| Scenario | Day(s) | Before | After (est.) | Visibility |
|----------|--------|--------|-------------|------------|
| memory_leak | Jan 7 (Wed) | $868K (-0%) | ~$650K (-25%) | Clear dip |
| memory_leak | Jan 8 (Thu) | $534K (-29%) | ~$375K (-50%) | Very clear |
| memory_leak | Jan 9 (Fri) | $312K (-54%) | ~$200K (-71%) | Even clearer |
| memory_leak OOM | Jan 10 (Sat) | $650K (-34%) | ~$400K (-59%) | No spike |
| cpu_runaway fix | Jan 12 (Mon) | $682K (-16%) | ~$550K (-32%) | Clear dip |
| dead_letter | Jan 16 (Fri) | $597K (-12%) | ~$350K (-49%) | Clear crater |
| ddos_attack | Jan 18 (Sun) | $508K (-30%) | ~$300K (-59%) | Sustained |

### Verification

Requires data regeneration: `python3 bin/main_generate.py --all --scenarios=all --days=31 --no-test`

---

## 2026-02-15 ~22:00 UTC -- Supporting TA Alignment Phase 9: GCP (Splunk_TA_google-cloudplatform) CIM

### Added

- **Phase 9** of Supporting TA Alignment project. Source: `Splunk_TA_google-cloudplatform` v4.4.0 (Splunkbase #3088).
- Aligns 2 GCP sub-sourcetypes (`FAKE:google:gcp:pubsub:audit:admin_activity`, `FAKE:google:gcp:pubsub:audit:data_access`) with CIM data models.

**Configuration:**
- `local/eventtypes.conf` -- 7 new eventtypes:
  - Auth (1): `fake_gcp_audit_auth` (data_access events)
  - Change (5): `fake_gcp_audit_change` (all admin_activity), `fake_gcp_audit_change_instances` (compute), `fake_gcp_audit_change_storage` (storage), `fake_gcp_audit_change_iam` (IAM policy), `fake_gcp_audit_change_service_accounts` (SA key creation)
  - Catch-all (1): `fake_gcp_audit_all` (all GCP audit events)
- `local/tags.conf` -- 7 new tag stanzas mapping to CIM: Authentication, Change (with instance/account sub-tags), Cloud

**CIM Models covered:** Authentication (data_access), Change (admin_activity with instance/storage/IAM/service account sub-types)

**Props/Transforms:** No changes needed -- `default/props.conf` already has comprehensive CIM field mappings (command, dvc, dest, object, object_id, object_path, result, src, src_ip, action, change_type, object_category, status, user, vendor_product, etc.) copied from the real TA.

**Not included (out of scope):**
- 6 lookup CSVs from real TA -- object_category handled by inline EVAL, others for sourcetypes we don't generate (VPC flow, security alerts, bucket access logs)
- 13 additional eventtypes from real TA -- for methods/sourcetypes our generator doesn't produce (disks, firewalls, user settings, subscriptions, publisher, roles, storage IAM, login service, GSuite, VPC flow, security alerts, compute instance, bucket access logs)

---

## 2026-02-15 ~21:00 UTC -- Supporting TA Alignment Phase 8: ServiceNow (Splunk_TA_snow) CIM

### Added

- **Phase 8** of Supporting TA Alignment project. Source: `Splunk_TA_snow` (Splunkbase).
- Aligns 3 ServiceNow sourcetypes (`FAKE:servicenow:incident`, `FAKE:servicenow:change`, `FAKE:servicenow:cmdb`) with CIM data models.

**Configuration:**
- `local/props.conf` -- 3 new stanzas with ~24 CIM field additions:
  - `[FAKE:servicenow:incident]`: 7 FIELDALIAS (incident, severity_id, assignment_group_name, incident_state_name, affect_dest, assignment_user_name, name), 4 EVAL (dest, src_user, time_submitted, severity_name)
  - `[FAKE:servicenow:change]`: 6 FIELDALIAS (description, change, assignment_group_name, user, affect_dest, change_state_name), 3 EVAL (dest, src_user, time_submitted)
  - `[FAKE:servicenow:cmdb]`: 4 FIELDALIAS (dest, ip, serial, dns)
- `local/eventtypes.conf` -- 3 new eventtypes: `fake_snow_incident`, `fake_snow_change_request`, `fake_snow_cmdb_ci_list`
- `local/tags.conf` -- 3 new tag stanzas mapping to CIM: Ticket Management (ticketing, incident), Inventory

**CIM Models covered:** Ticket Management (Incident, Change), Inventory (CMDB)

**Not included (out of scope):**
- `snow_severities.csv` / `snow_change_states.csv` / `snow_problem_states.csv` lookups -- numbering doesn't match our generator output (inline EVAL-severity_name used instead)
- KVStore lookups (15 in real TA) -- require live ServiceNow connection
- `snow:problem` / `snow:sysevent` / `snow:em_event` eventtypes -- generator does not produce these

---

## 2026-02-15 ~20:00 UTC -- Supporting TA Alignment Phase 7: Linux (Splunk_TA_nix) CIM

### Added

- **Phase 7** of Supporting TA Alignment project. Source: `Splunk_TA_nix` (Splunkbase #833).
- Aligns 6 Linux sourcetypes (`FAKE:cpu`, `FAKE:vmstat`, `FAKE:df`, `FAKE:iostat`, `FAKE:interfaces`, `FAKE:linux:auth`) with CIM data models.

**Configuration:**
- `local/props.conf` -- 6 new stanzas with ~40 CIM field additions:
  - `[FAKE:cpu]`: FIELDALIAS-src, EVAL PercentIdleTime/PercentUserTime/PercentSystemTime/PercentWaitTime/cpu_user_percent
  - `[FAKE:vmstat]`: FIELDALIAS-src, EVAL mem/mem_free/mem_used/mem_free_percent + legacy FreeMBytes/UsedMBytes/TotalMBytes/UsedBytes
  - `[FAKE:df]`: FIELDALIAS-src, EVAL storage/storage_free/storage_used/storage_free_percent + legacy FreeMBytes/TotalMBytes/UsedMBytes/PercentUsedSpace/PercentFreeSpace
  - `[FAKE:iostat]`: FIELDALIAS-src, EVAL mount/read_ops/write_ops/latency/total_ops
  - `[FAKE:interfaces]`: EVAL enabled/speed
  - `[FAKE:linux:auth]`: FIELDALIAS-dvc, EVAL dest/app/action/status/authentication_method/object_category/user_role
- `local/eventtypes.conf` -- 12 new eventtypes:
  - Metrics (5): `fake_cpu`, `fake_vmstat`, `fake_df`, `fake_iostat`, `fake_interfaces`
  - Auth (7): `fake_nix_sshd_authentication`, `fake_nix_sshd_session_start`, `fake_nix_sshd_session_end`, `fake_nix_su_authentication`, `fake_nix_failed_login`, `fake_nix_cron`, `fake_nix_privileged_session`
- `local/tags.conf` -- 12 new tag stanzas mapping to CIM: Performance (OS, CPU, Memory, Storage), Inventory (Network), Authentication, Network Sessions

**CIM Models covered:** Performance (CPU, Memory, Storage, I/O), Inventory (Network Interfaces), Authentication, Network Sessions

**Not included (out of scope):**
- `nix_vendor_actions.csv` lookup -- CIM action mapping handled directly via EVAL-action case() (6 known event patterns)
- useradd/userdel/groupadd/password-change eventtypes -- generator does not produce these events
- Cross-platform coalesce chains (AIX, Solaris, OSX) -- generator is Linux-only
- Linux audit (`linux_audit`) stanza -- generator does not produce auditd events

---

## 2026-02-15 ~19:00 UTC -- Supporting TA Alignment Phase 6: Cisco Meraki CIM

### Added

- **Phase 6** of Supporting TA Alignment project. Source: `Splunk_TA_cisco_meraki` v3.2.0 (Splunkbase).
- Lightweight phase -- only eventtypes + tags needed. All 11 lookup CSVs, 11 transform definitions, and 7 props.conf stanzas with 30+ CIM fields per sourcetype were already present in `default/`.

**Configuration:**
- `local/eventtypes.conf` -- 12 new eventtypes covering 5 Meraki product families:
  - MX Security Appliances (5): `fake_meraki_securityappliances_alerts`, `_authentication`, `_change`, `_network`, `_networksessions`
  - MR Access Points (3): `fake_meraki_accesspoints_alerts`, `_authentication`, `_change`
  - MS Switches (1): `fake_meraki_switches_change`
  - MV Cameras (1): `fake_meraki_cameras`
  - MT Sensors (1): `fake_meraki_sensors`
- `local/tags.conf` -- 12 new tag stanzas mapping to CIM: Alert, Authentication, Change, Network Traffic, Network Sessions

**CIM Models covered:** Alert, Authentication, Change, Network Traffic, Network Sessions

**Not included (out of scope):**
- Health metric sourcetypes (`FAKE:meraki:accesspoints:health`, `FAKE:meraki:switches:health`) -- performance metrics, no CIM eventtype/tag needed
- API/audit sourcetypes (`meraki:audit`, `meraki:organizationsecurity`) -- generators don't produce these

---

## 2026-02-15 ~18:00 UTC -- Supporting TA Alignment Phase 5: Microsoft 365 / O365 CIM

### Added

- **Phase 5** of Supporting TA Alignment project. Source: `splunk_ta_o365` v5.1.0 (Splunkbase).
- Aligns `FAKE:o365:management:activity` (M365 Unified Audit Log) and `FAKE:ms:o365:reporting:messagetrace` (Exchange Message Trace) with CIM data models.

**Lookups (7 CSVs):**
- `splunk_ta_o365_cim_change_analysis_3_1_0.csv` (212 rows) -- Workload+Operation to dataset_name/action/change_type/object_category
- `splunk_ta_o365_cim_data_access_3_1_0.csv` (102 rows) -- SharePoint/OneDrive/Teams data access classification
- `splunk_ta_o365_cim_authentication_3_1_0.csv` (9 rows) -- AzureAD/Exchange auth dataset classification
- `splunk_ta_o365_cim_authentication_ResultStatus.csv` (5 rows) -- ResultStatus to CIM action (success/failure)
- `splunk_ta_o365_cim_authentication_RecordType.csv` (44 rows) -- RecordType code to name/description
- `splunk_ta_o365_cim_alerts.csv` (4 rows) -- SecurityComplianceCenter alert classification
- `splunk_ta_o365_cim_email_action_messagetrace.csv` (10 rows) -- replaces existing 7-row version with fuller real TA version

**Configuration:**
- `local/transforms.conf` -- 6 new lookup definitions (change_analysis, data_access, authentication, ResultStatus, RecordType, alerts)
- `local/eventtypes.conf` -- 7 new eventtypes: `fake_o365_change`, `fake_o365_endpoint_changes`, `fake_o365_data_access`, `fake_o365_authentication`, `fake_o365_account_management`, `fake_o365_alerts`, `fake_o365_reporting_messagetrace`
- `local/tags.conf` -- 7 new tag stanzas mapping to CIM: Change, Data Access, Authentication, Alert, Email, Endpoint
- `local/props.conf` -- 2 new stanzas:
  - `[FAKE:o365:management:activity]`: 6 LOOKUPs (dataset classification), 3 FIELDALIAS (vendor_account, command, src_name), 12 EVAL (dest, dest_name, src_user, user_type, status, result, object_id, object_attrs, signature, signature_id, category, dvc, file_size)
  - `[FAKE:ms:o365:reporting:messagetrace]`: 1 FIELDALIAS (vendor_account), 6 EVAL (src_user_name, orig_src, file_size, orig_recipient, status, dvc)

**CIM Models covered:** Change, Data Access, Authentication, Alert, Email

**Not included (out of scope):**
- DLP incident / email filtering lookups (generators don't produce these events)
- Authentication Reason lookup (766 rows -- O365 auth handled via Entra ID sourcetype)
- REGEX transforms (our generators produce flat JSON, not nested ExtendedProperties)

---

## 2026-02-15 ~16:30 UTC -- Reduce lunch dip in weekday activity curve

### Changed

- **`bin/shared/config.py`** -- `HOUR_ACTIVITY_WEEKDAY` hour 12: changed from 60 to 85.
  - The 40% drop (100→60) at noon created an unrealistically sharp dip visible in e-commerce order volume charts. Now a mild 15% dip (100→85) which is more realistic for a web store where customers shop during lunch breaks.
  - Affects all generators using the weekday activity curve.
  - **Impact:** Requires full data regeneration to take effect.

---

## 2026-02-15 ~16:00 UTC -- Fix SAP order timing bug (VA01/VL01N before web checkout)

### Fixed

- **`bin/generators/generate_sap.py`** -- `generate_order_lifecycle_events()`:
  - **Bug:** SAP VA01 (Create Sales Order) and VL01N (Create Delivery) events were generated with random minute/second values within the order's hour, ignoring the actual timestamp from `order_registry.json`. This caused SAP events to appear 5-55 minutes BEFORE the web checkout that triggered them (~50% of orders affected).
  - **Root cause:** Lines 286-287 used `random.randint(0, 59)` for minute/second instead of parsing the actual values from `order["timestamp"]`.
  - **Fix:** Parse `order["timestamp"]` to extract actual minute/second. VA01 now uses exact order time, VL01N is offset 15-45 min from actual time, VF01 uses actual minute with 1-3 hour offset.
  - **Impact:** Requires data regeneration (`--sources=sap`) to fix existing data.

---

## 2026-02-15 ~15:00 UTC -- Supporting TA Alignment Phase 4: Entra ID (Azure AD) CIM

### Added

- **`local/eventtypes.conf`** -- 10 new Entra ID eventtypes:
  - **Sign-in / Authentication** (4): `fake_entra_signin` (all sign-ins), `fake_entra_signin_success` (resultType=0), `fake_entra_signin_failure` (resultType!=0), `fake_entra_signin_mfa` (multiFactorAuthentication required)
  - **Audit / Change** (4): `fake_entra_audit` (all audit), `fake_entra_audit_account_mgmt` (UserManagement+GroupManagement), `fake_entra_audit_app_mgmt` (ApplicationManagement), `fake_entra_audit_role_mgmt` (RoleManagement)
  - **Risk / Alert** (2): `fake_entra_risk_detection` (all risk events), `fake_entra_risk_high` (riskLevel=high)
  - Source: Splunk_TA_microsoft-cloudservices v5.x (Splunkbase #3110)

- **`local/tags.conf`** -- 10 new CIM tag stanzas:
  - `authentication`, `cloud` for sign-in events (+ `multifactor` for MFA)
  - `change`, `cloud` for audit events (+ `account` for account management)
  - `alert`, `cloud` for risk detection events

- **`local/props.conf`** -- 3 new Entra ID stanzas with CIM field enrichment:
  - **`[FAKE:azure:aad:signin]`**: 5 FIELDALIAS (src_ip, signature, reason, authentication_service, vendor_account), 11 EVAL (authentication_method, dest_type, status, user_agent, user_name, signature_id, src_user, user_type, dvc, response_time), 2 LOOKUP (dataset, severity_type)
  - **`[FAKE:azure:aad:audit]`**: 5 FIELDALIAS (src_ip, signature, command, dest, vendor_account), 11 EVAL (dest_type, status, dvc, object, object_id, object_category, object_attrs, src_user, src_user_name, src_user_type, user_name), 1 LOOKUP (change_analysis)
  - **`[FAKE:azure:aad:riskDetection]`**: 4 FIELDALIAS (src_ip, signature, dest, vendor_account), 5 EVAL (dest_type, dvc, description, signature_id, user_name, type)
  - Note: Only NEW fields added in local/ -- default/ EVAL/FIELDALIAS preserved via Splunk merge

- **`local/transforms.conf`** -- 3 new lookup definitions:
  - `[mscs_aad_audit_authentication_lookup]` -- operationName+category to dataset_name (141 rows)
  - `[mscs_aad_change_analysis_lookup]` -- operationName to change_type+action+object_category (133 rows)
  - `[mscs_aad_severity_type_lookup]` -- properties.riskLevel to severity+type (6 rows)

- **`lookups/mscs_aad_audit_authentication.csv`** -- New file. Full copy from real TA (141 rows)
- **`lookups/mscs_aad_change_analysis.csv`** -- New file. Full copy from real TA (133 rows)
- **`lookups/mscs_aad_severity_type.csv`** -- New file. Full copy from real TA (6 rows)

### Design Notes

- Real TA uses single sourcetype `azure:monitor:aad` with 100+ operationName CASE conditions
- Our FAKE TA uses 3 separate sourcetypes (`FAKE:azure:aad:signin/audit/riskDetection`), simplifying per-stanza logic
- Lookup CSVs are full copies from real TA for future extensibility
- For audit events: `src_user` = who initiated, `user_name`/`object` = target resource (CIM Change model)

---

## 2026-02-15 ~09:00 UTC -- Supporting TA Alignment Phase 3: AWS CloudTrail CIM

### Added

- **`local/eventtypes.conf`** -- 10 new AWS CloudTrail eventtypes:
  - **Authentication** (4): `fake_aws_cloudtrail_auth` (AssumeRole+ConsoleLogin), `fake_aws_cloudtrail_consolelogin_auth`, `fake_aws_cloudtrail_assumeRole_auth`, `fake_aws_cloudtrail_multifactor_auth` (MFA events)
  - **Change** (4): `fake_aws_cloudtrail_change` (10 mutating eventNames), `fake_aws_cloudtrail_iam_change` (CreateAccessKey+DeleteAccessKey), `fake_aws_cloudtrail_delete_events` (Delete*/Terminate*), `fake_aws_cloudtrail_endpoint_change` (S3 PutObject+DeleteObject)
  - **Compute** (1): `fake_aws_cloudtrail_ec2_events` (RunInstances+TerminateInstances)
  - **Error** (1): `fake_aws_cloudtrail_errors` (any errorCode present)
  - Source: Splunk_TA_aws v7.x (Splunkbase #1876)
  - Scoped to the 19 eventNames our generator produces

- **`local/tags.conf`** -- 10 new CIM tag stanzas:
  - `authentication`, `default`, `cloud` for ConsoleLogin auth
  - `assume_role`, `cloud` for AssumeRole auth
  - `multifactor`, `cloud` for MFA events
  - `change`, `cloud` for change/delete/endpoint events
  - `error`, `cloud` for error events

- **`local/props.conf`** -- New `[FAKE:aws:cloudtrail]` stanza with CIM field enrichment:
  - **16 FIELDALIAS**: desc, start_time, temp_access_key, user_access_key, app (eventType), dvc (eventSource), region, signature (eventName), src_ip, user_group_id, vendor_region, reason, command, image_id, instance_type, result_id
  - **14 EVAL statements**: msg, user_arn, userName, result, vendor_account, user (complex CASE for IAMUser/AssumedRole identity), user_name, user_id, user_type, user_agent, aws_account_id, dest (per-eventName: instanceId, bucketName, LoginTo, eventSource), object (per-eventName resource), object_id (resource identifiers)
  - **4 LOOKUP statements**: action_status, object_category, changetype (by source), changetype (by eventName)
  - Note: EVAL-user and EVAL-dest override basic FIELDALIAS from default/props.conf (EVAL takes precedence in Splunk)

- **`local/transforms.conf`** -- 4 new lookup definitions:
  - `[aws_cloudtrail_action_status_lookup]` -- WILDCARD(errorCode), maps eventName+errorCode to action+status (58 rows)
  - `[aws_cloudtrail_eventname_lookup]` -- Maps eventName to object_category (19 rows)
  - `[aws_cloudtrail_changetype_lookup]` -- Maps eventSource to change_type (47 rows, full copy from real TA)
  - `[aws_cloudtrail_eventname_changetype_lookup]` -- Maps eventName to change_type (13 rows)

- **`lookups/aws_cloudtrail_action_status.csv`** -- New file. Action/status mapping for our 19 eventNames + error codes (58 rows, trimmed from 528 in real TA)
- **`lookups/aws_cloudtrail_eventname_lookup.csv`** -- New file. Object category mapping (19 rows, trimmed from 155 in real TA)
- **`lookups/aws_cloudtrail_changetype.csv`** -- New file. EventSource to change_type (47 rows, full copy from real TA + 3 added: signin, monitoring, config)
- **`lookups/aws_cloudtrail_eventname_changetype.csv`** -- New file. EventName to change_type (13 rows, trimmed from 86 in real TA)

### Not in Scope (Phase 3)

- **REPORT extraction**: Real TA has `user-for-aws-cloudtrail-acctmgmt` regex extraction for user from errorMessage. Not needed -- our generator includes userName in userIdentity.
- **Network dataset EVALs**: Real TA has dest_ip_range, dest_port_range, direction for network ACL events. We don't generate these eventNames.
- **object_attrs EVAL**: Real TA has 30+ line CASE for resource attribute extraction. Our events have simpler structure.

### Verification

- Requires Splunk restart to pick up changes
- Test: `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" | stats count by eventtype`
- Test CIM fields: `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" | stats count by user, dest, action, status, object_category`
- Test auth: `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=ConsoleLogin | table user, action, status, src, reason`
- Test change: `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName IN ("CreateAccessKey","RunInstances") | table user, action, object, change_type`
- Phase 3 of Supporting TA Alignment project. Next: Phase 4 (Entra ID)

---

## 2026-02-15 ~07:00 UTC -- Supporting TA Alignment Phase 2: Windows + Sysmon CIM

### Added

- **`local/eventtypes.conf`** -- 26 new eventtypes for Windows, Sysmon, and Perfmon:
  - **Windows base** (3): `fake_wineventlog_security`, `fake_wineventlog_system`, `fake_wineventlog_application` -- log source filters
  - **Authentication** (6): `fake_windows_logon_success` (4624), `fake_windows_logon_failure` (4625), `fake_windows_special_privileges` (4672), `fake_windows_auth_ticket_granted` (4768), `fake_windows_service_ticket_granted` (4769), `fake_windows_account_used4logon` (4776)
  - **Account Management** (3): `fake_windows_account_password_set` (4724), `fake_windows_account_modified` (4738), `fake_windows_account_lockout` (4740)
  - **Process Tracking** (1): `fake_windows_process_new` (4688)
  - **CIM Composite** (4): `fake_windows_security_authentication`, `fake_windows_security_change`, `fake_windows_security_change_account`, `fake_windows_endpoint_processes`
  - **System** (1): `fake_windows_time_sync` (EventCode 37)
  - **Perfmon** (3): `fake_perfmon_cputime`, `fake_perfmon_memory`, `fake_perfmon_logicaldisk`
  - **Sysmon** (5): `fake_sysmon_process` (1,5,7,8,10), `fake_sysmon_network` (3), `fake_sysmon_filemod` (11), `fake_sysmon_regmod` (13), `fake_sysmon_dns` (22)
  - Source: Splunk_TA_windows v9.x (Splunkbase #742) and Splunk_TA_microsoft_sysmon v4.x (Splunkbase #5765)
  - Scoped to EventCodes our generators actually produce (not the full 90+ from real TA)

- **`local/tags.conf`** -- 23 new CIM tag stanzas:
  - **Authentication**: 6 eventtypes -> `authentication` (+ `privileged` for 4672)
  - **Change (Account Mgmt)**: 3 eventtypes -> `change`, `account`, `modify`/`lock`/`password`
  - **Process**: 1 eventtype -> `process`, `execute`, `start`
  - **CIM Composite**: 4 eventtypes -> `authentication`, `change`, `process`, `report`
  - **Performance**: 4 eventtypes -> `performance`, `cpu`/`memory`/`disk`/`storage`/`report`
  - **Sysmon**: 5 eventtypes -> `process`/`report`, `network`/`communicate`, `endpoint`/`filesystem`, `endpoint`/`registry`, `network`/`resolution`/`dns`

- **`local/props.conf`** -- New file. CIM field enrichment for WinEventLog and Sysmon:
  - **`[FAKE:WinEventLog]`** -- 8 FIELDALIAS + 10 EVAL statements:
    - FIELDALIAS: dest_nt_host, severity_id, body, event_id, id, user_id, service_name, parent_process
    - EVAL: vendor, product, dest, src (EventCode-specific), authentication_method, authentication_service, process_name, process_path, process, parent_process_name, result_id
  - **`[FAKE:WinEventLog:Sysmon]`** -- 8 FIELDALIAS + 25 EVAL + 2 LOOKUP statements:
    - FIELDALIAS: dvc, src_port, query, reply_code_id, registry_path, granted_access, process_integrity_level, eventid
    - EVAL: action (by EventCode), dest, src, process_path, process_name, process_id, process_guid, process_exec, parent_process_path/name/id, file_path, file_name, registry_key_name, registry_value_name, app, direction, protocol, state, transport, user, object_category, os, status
    - LOOKUP: sysmon_eventcode_lookup (EventCode -> description/signature), sysmon_record_type_lookup (DNS record type)

- **`local/transforms.conf`** -- 2 new Sysmon lookup definitions:
  - `[sysmon_eventcode_lookup]` -- Maps EventCode to EventDescription (31 entries)
  - `[sysmon_record_type_lookup]` -- Maps DNS record_type_id to record_type_name (47 entries)

- **`lookups/sysmon_eventcode_lookup.csv`** -- New file. Sysmon EventCode descriptions (source: Splunk_TA_microsoft_sysmon)
- **`lookups/sysmon_record_type_lookup.csv`** -- New file. DNS record type names (source: Splunk_TA_microsoft_sysmon)

### Not in Scope (Phase 2)

- **Full XML parsing transforms**: Real TA has 348 transforms for XML block extraction. Our generators produce KV format, not XML, so these are irrelevant.
- **Windows lookups**: Real TA has 38 CSV files. Most are for sourcetypes/EventCodes we don't generate. We keep `windows_severity_lookup.csv` and `windows_signature_lookup.csv` from default/.

### Verification

- Requires Splunk restart to pick up changes
- Test: `index=fake_tshrt sourcetype="FAKE:WinEventLog" | stats count by eventtype`
- Test: `index=fake_tshrt sourcetype="FAKE:WinEventLog:Sysmon" | stats count by eventtype`
- Test: `index=fake_tshrt sourcetype="FAKE:Perfmon:*" | stats count by eventtype`
- Test Sysmon CIM fields: `index=fake_tshrt sourcetype="FAKE:WinEventLog:Sysmon" EventCode=1 | table process_name, process_path, parent_process_name, action, dest, user`
- Test WinEventLog CIM fields: `index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4624 | table src, dest, authentication_method, user`
- Phase 2 of Supporting TA Alignment project. Next: Phase 3 (AWS CloudTrail)

---

## 2026-02-15 ~06:00 UTC -- Supporting TA Alignment Phase 1: Cisco ASA CIM

### Changed

- **`default/eventtypes.conf`** -- Renamed all `demo_` prefixed eventtype stanza names to `fake_` (34 stanzas). Search strings with `demo_id=` field references preserved unchanged.
- **`default/tags.conf`** -- Renamed all `[eventtype=demo_*]` references to `[eventtype=fake_*]` (31 stanzas). Tag values unchanged.
- **`default/README.md`** -- Updated eventtype name references in documentation tables from `demo_` to `fake_` prefix. Kept `demo_id=` field references in search examples.

### Added

- **`local/transforms.conf`** -- New file. Override for 2 ASA lookup definitions missing `match_type`:
  - `[cisco_asa_change_analysis_lookup]` -- Added `match_type = WILDCARD(message_id)` (required for CSV wildcard matching)
  - `[cisco_asa_vendor_class_lookup]` -- Added `match_type = WILDCARD(message_id)`
  - Source: Splunk_TA_cisco-asa v6.0.0 (Splunkbase #1620)

- **`local/eventtypes.conf`** -- New file. 16 ASA-specific CIM eventtypes copied from real Splunk_TA_cisco-asa v6.0.0:
  - `fake_cisco_authentication` -- Authentication model (message_id: 109031, 605004, 605005, 716047, 772002-772004, etc.)
  - `fake_cisco_authentication_privileged` -- Authentication privileged (message_id: 113021)
  - `fake_cisco_connection` -- Network Traffic model (41 message_ids: 302013-302016, 305011-305013, 106023, etc.)
  - `fake_cisco_intrusion` -- IDS model (message_id: 400032, 106016, 106017, 430001)
  - `fake_cisco_vpn` -- VPN session (message_id: 722051, 713228)
  - `fake_cisco_vpn_start` -- VPN session start (message_id: 113039, 716001, 722022, etc.)
  - `fake_cisco_vpn_end` -- VPN session end (message_id: 113019, 716002, 722023, 602304)
  - `fake_cisco_asa_network_sessions` -- Network session (message_id: 609001, 609002, 716058-716059, etc.)
  - `fake_cisco_asa_configuration_change` -- Change model (change_class=* OR 505001-505009, 113003)
  - `fake_cisco_asa_audit_change` -- Change audit (message_id: 771002, 111009, 111004, etc.)
  - `fake_cisco_asa_endpoint_filesystem` -- Endpoint filesystem (message_id: 716015, 716014, 716016)
  - `fake_cisco_asa_certificates` -- Certificate model (message_id: 717009, 717022, 717027-717029, 717037)
  - `fake_cisco_asa_network_resolution` -- DNS resolution (message_id: 713154)
  - `fake_cisco_asa_alert` -- Alert model (message_id: 110003, 405001, 212011)
  - `fake_cisco_network_session_start` -- Network session start (message_id: 302022, 302024, 302026)
  - `fake_cisco_network_session_end` -- Network session end (message_id: 302023, 302025)
  - All searches use `sourcetype="FAKE:cisco:asa"` with exact message_id lists from real TA

- **`local/tags.conf`** -- New file. 16 CIM tag stanzas mapping ASA eventtypes to data models:
  - Network Traffic: `fake_cisco_connection` -> network, communicate
  - Authentication: `fake_cisco_authentication` -> authentication; `fake_cisco_authentication_privileged` -> authentication, privileged
  - VPN: `fake_cisco_vpn/vpn_start/vpn_end` -> vpn, network, session
  - Network Session: `fake_cisco_asa_network_sessions` -> network, session
  - Change: `fake_cisco_asa_configuration_change`, `fake_cisco_asa_audit_change` -> change
  - Endpoint: `fake_cisco_asa_endpoint_filesystem` -> endpoint, filesystem
  - Certificate: `fake_cisco_asa_certificates` -> certificate
  - DNS: `fake_cisco_asa_network_resolution` -> network, resolution, dns
  - IDS: `fake_cisco_intrusion` -> attack, ids
  - Alert: `fake_cisco_asa_alert` -> alert
  - Session Start/End: `fake_cisco_network_session_start` -> network, session, start; `fake_cisco_network_session_end` -> network, session, end

### Strategy

- All new CIM configurations placed in `local/` directory to keep `default/` stable
- Splunk merges `default/` + `local/` automatically (local/ has precedence at attribute level)
- Only NEW stanzas and attributes added in local/ -- no redefinition of existing default/ attributes
- Can be promoted to `default/` after verification in Splunk

### Verification

- Requires Splunk restart to pick up new local/ files
- Test eventtype matching: `index=fake_tshrt sourcetype="FAKE:cisco:asa" | stats count by eventtype`
- Test CIM Network Traffic: `| datamodel Network_Traffic All_Traffic search | stats count by sourcetype`
- Test lookup wildcard: `index=fake_tshrt sourcetype="FAKE:cisco:asa" message_id=505* | table message_id change_type object_category`
- Phase 1 of Supporting TA Alignment project (Cisco ASA). Next: Phase 2 (Windows + Sysmon)

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
