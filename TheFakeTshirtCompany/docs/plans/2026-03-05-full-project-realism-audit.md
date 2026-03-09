# Full Project Realism & Consistency Audit — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all realism issues, correlation gaps, and configuration inconsistencies found across the entire TA-FAKE-TSHRT project.

**Architecture:** 7-area audit covering 24 generators, Splunk configuration, and cross-generator correlation. Findings grouped into tasks by area. Each task is independent and can be parallelized.

**Tech Stack:** Python 3.8+ (stdlib only), Splunk props.conf/transforms.conf

---

## Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 8 | Breaks correlation, wrong event formats, missing Splunk config |
| MAJOR | 12 | Noticeable realism issues, missing scenario coverage |
| MINOR | 14 | Cosmetic, documentation, edge cases |

---

### Task 1: Splunk Config — Missing demo_id Extraction (CRITICAL)

**Files:**
- Modify: `default/props.conf` — Add TRANSFORMS-demo_id to 7 sourcetype stanzas

**Problem:** 7 sourcetypes lack `TRANSFORMS-demo_id = extract_demo_id_indexed` and `EXTRACT-demo_id`, breaking scenario filtering for Catalyst Center and ACI events.

**Step 1: Add demo_id extraction to all 7 stanzas**

Add these two lines to each of the following stanzas:
- `[FAKE:cisco:catalyst:devicehealth]` (line 1941)
- `[FAKE:cisco:catalyst:networkhealth]` (line 1959)
- `[FAKE:cisco:catalyst:clienthealth]` (line 1972)
- `[FAKE:cisco:catalyst:issue]` (line 1985)
- `[FAKE:cisco:aci:fault]` (line 2007)
- `[FAKE:cisco:aci:event]` (line 2020)
- `[FAKE:cisco:aci:audit]` (line 2033)

Add after the `TRUNCATE` or last existing line in each stanza:
```
TRANSFORMS-demo_id = extract_demo_id_indexed
EXTRACT-demo_id = (?|"demo_id":\s*"(?<demo_id>[^"]+)"|demo_id=(?<demo_id>\S+))
```

**Step 2: Verify count matches other stanzas**

Grep for `TRANSFORMS-demo_id` in props.conf. Before: ~59 occurrences. After: ~66 occurrences.

**Step 3: Commit**
```bash
git add default/props.conf
git commit -m "fix(props): Add missing demo_id extraction to Catalyst Center and ACI sourcetypes"
```

---

### Task 2: Webex API — Swapped Caller/Called in TERMINATING Leg (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_webex_api.py:582-585`

**Problem:** TERMINATING leg has Called/Calling line IDs swapped. From the callee's perspective, "Calling line ID" should be the caller (who called them), not themselves.

**Step 1: Fix the field assignments**

Change lines 582-585 from:
```python
"Called line ID": caller_user.display_name,
"Called number": caller_number,
"Calling line ID": called_user.display_name,
"Calling number": called_number,
```
To:
```python
"Called line ID": called_user.display_name,
"Called number": called_number,
"Calling line ID": caller_user.display_name,
"Calling number": caller_number,
```

**Step 2: Verify ORIGINATING leg is correct**

Read the ORIGINATING leg (~20 lines above) and confirm it has:
- "Called line ID": called_user (correct — the person being called)
- "Calling line ID": caller_user (correct — the person calling)

**Step 3: Commit**
```bash
git add bin/generators/generate_webex_api.py
git commit -m "fix(webex_api): Swap Called/Calling line IDs in TERMINATING leg"
```

---

### Task 3: Office 365 Audit — Non-existent Operations (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_office_audit.py:577,634`

**Problem:** "FileSyncDownloadedFull" (line 577) and "FileRestored" (line 634) are not real Office 365 audit operations. Real O365 won't have these, breaking any SPL query that uses real operation names.

**Step 1: Fix exfil scenario operation**

Line 577: Change `"FileSyncDownloadedFull"` to `"FileDownloaded"`:
```python
user=alex, operation="FileDownloaded", demo_id="exfil"
```

**Step 2: Fix ransomware recovery operation**

Line 634: Change `"FileRestored"` to `"FileUploaded"`:
```python
user=jessica, operation="FileUploaded", demo_id="ransomware_attempt"
```

**Step 3: Commit**
```bash
git add bin/generators/generate_office_audit.py
git commit -m "fix(office_audit): Replace non-existent O365 operations with real ones"
```

---

### Task 4: ServiceBus — Inventory Quantity Hardcoded to 1 (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_servicebus.py:395`

**Problem:** All InventoryReserved events hardcode `"quantity": 1` regardless of actual order quantity, breaking order-to-inventory correlation.

**Step 1: Fix quantity assignment**

Line 395: Change from:
```python
inv_items = [{"sku": item["sku"], "quantity": 1, "reserved": reserved} for item in items]
```
To:
```python
inv_items = [{"sku": item["sku"], "quantity": item.get("qty", 1), "reserved": reserved} for item in items]
```

**Step 2: Verify items have qty field**

Read `generate_access.py` to confirm that order_registry items include a `qty` field. Search for where items/products are written to order_registry.

**Step 3: Commit**
```bash
git add bin/generators/generate_servicebus.py
git commit -m "fix(servicebus): Use actual order quantity in InventoryReserved events"
```

---

### Task 5: WinEventLog — Event 4624 Realism (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_wineventlog.py:114-124`

**Problem:** Two issues with Event 4624:
1. `Elevated Token` is always `Yes` (line 124) — should only be Yes for admin logons (~5%)
2. Subject section is always empty/S-1-0-0 (lines 114-118) — should show SYSTEM for network logons

**Step 1: Fix Elevated Token based on logon type and user role**

Line 124: Replace `Elevated Token:\t\tYes` with logic based on parameters. The function needs to accept a parameter or determine elevation from context.

Add an `elevated` parameter to the template or the calling function. For network logons (type 3): always "No". For interactive (type 2/10): "Yes" only if user is in IT/admin role (~5% of users).

Check how the 4624 template is called — find the function that formats this template and add an `elevated_token` parameter:
```python
"Elevated Token:\t\t{elevated_token}"
```

At each call site:
- Logon type 3 (Network): `elevated_token="No"`
- Logon type 10 (RDP): `elevated_token="Yes"` only if user is IT admin
- Logon type 2 (Interactive): `elevated_token="Yes"` only if user is IT admin

**Step 2: Fix Subject section for network logons**

Lines 114-118: For logon type 3 (Network), Subject should be:
```
Subject:
\tSecurity ID:\t\tS-1-5-18
\tAccount Name:\t\tSYSTEM
\tAccount Domain:\t\tNT AUTHORITY
\tLogon ID:\t\t0x3E7
```

Add a conditional: if logon_type == 3, use SYSTEM subject; otherwise keep S-1-0-0.

**Step 3: Run generator and verify output**
```bash
python3 bin/main_generate.py --sources=wineventlog --days=1 --test --quiet
```

**Step 4: Commit**
```bash
git add bin/generators/generate_wineventlog.py
git commit -m "fix(wineventlog): Realistic 4624 Elevated Token and Subject fields"
```

---

### Task 6: MSSQL — Wrong Error Code 19406 (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_mssql.py:413-418`

**Problem:** Error 19406 message says "backup set cannot be used for restore" which is fabricated. Real error 19406 is unrelated. For cpu_runaway scenario, use realistic SQL Server CPU-related errors.

**Step 1: Replace with realistic SQL Server error**

Lines 413-418: Replace error 19406 with error 17883 (stuck non-yielding scheduler) or 833 (I/O taking longer than 15 seconds):

```python
events.append(format_mssql_event(
    ts, "spid67",
    error=17883, severity=18, state=1,
    message=f"Process {random.randint(50, 200)} appears to be non-yielding on Scheduler {random.randint(0, 3)}. Thread creation time: {ts.strftime('%Y-%m-%dT%H:%M:%S')}.{random.randint(0, 999):03d}. Approx Thread CPU Used: kernel {random.randint(5000, 30000)} ms, user {random.randint(10000, 60000)} ms.",
    demo_id=demo_id
))
```

**Step 2: Commit**
```bash
git add bin/generators/generate_mssql.py
git commit -m "fix(mssql): Use real SQL Server error 17883 for cpu_runaway scenario"
```

---

### Task 7: GCP — Exfil Event requestMetadata Override (CRITICAL)

**Files:**
- Modify: `bin/generators/generate_gcp.py:621`

**Problem:** Exfil function overrides `requestMetadata.callerIp` after event creation instead of passing `caller_ip` to `gcp_base_event()`. This creates inconsistent event structure.

**Step 1: Fix the callerIp injection**

Find the `gcp_bigquery_export_exfil()` function and how it calls `gcp_base_event()`. Pass `caller_ip="185.220.101.42"` (or THREAT_IP) as a parameter instead of overriding after:

Remove line 621:
```python
event["protoPayload"]["requestMetadata"]["callerIp"] = "185.220.101.42"
```

And ensure the `gcp_base_event()` call includes `caller_ip=THREAT_IP` parameter.

**Step 2: Commit**
```bash
git add bin/generators/generate_gcp.py
git commit -m "fix(gcp): Pass threat actor IP via caller_ip parameter instead of post-override"
```

---

### Task 8: AWS — Hardcoded Fake IAM Principal IDs (MAJOR)

**Files:**
- Modify: `bin/generators/generate_aws.py:665`

**Problem:** Exfil scenario uses `"AIDAMALICIOUS001"` / `"AKIAMALICIOUS001"` which don't match AWS ID formats and are obviously fake.

**Step 1: Generate realistic principal/access key IDs**

Replace hardcoded IDs with deterministic UUID5-based generation:
```python
import uuid
svc_principal = "AIDA" + uuid.uuid5(uuid.NAMESPACE_DNS, "svc-datasync").hex[:16].upper()
svc_access_key = "AKIA" + uuid.uuid5(uuid.NAMESPACE_DNS, "svc-datasync-key").hex[:16].upper()
```

**Step 2: Commit**
```bash
git add bin/generators/generate_aws.py
git commit -m "fix(aws): Generate realistic IAM principal/access key IDs for exfil scenario"
```

---

### Task 9: Entra ID — Spray Attack Location Inconsistency (MAJOR)

**Files:**
- Modify: `bin/generators/generate_entraid.py:550-610`

**Problem:** Password spray noise events use the same threat actor IP (185.220.101.42) but vary the geo location across Moscow, Beijing, Sao Paulo, etc. This breaks the single-attacker narrative — one IP can't be in multiple cities simultaneously.

**Step 1: Fix spray attack to use consistent attacker location**

The spray noise should either:
- **Option A:** Use the same Frankfurt IP + location for all spray events (single attacker)
- **Option B:** Use different IPs per geo (botnet — different IPs from different locations)

Option B is more realistic for spray attacks. Update the code so each geo entry has its own IP prefix and generates unique IPs:

For each geo in SPRAY_GEOS, use the `ip_prefix` field to generate a unique IP per spray event instead of reusing the threat actor IP.

**Step 2: Commit**
```bash
git add bin/generators/generate_entraid.py
git commit -m "fix(entraid): Use unique IPs per geo in spray attack for botnet realism"
```

---

### Task 10: Orders — Tax Rounding and Shipping Threshold (MAJOR)

**Files:**
- Modify: `bin/generators/generate_orders.py:47,347`

**Problem:**
1. Tax rounded to nearest dollar (`round(subtotal * tax_rate / 100)`) — should preserve cents
2. Free shipping threshold $50 too low — most single items exceed it

**Step 1: Fix tax precision**

Line 347: Change to:
```python
tax = round(subtotal * tax_rate / 100, 2)
```

**Step 2: Raise free shipping threshold**

Line 47: Change `FREE_SHIPPING_THRESHOLD` from `50` to `75`:
```python
FREE_SHIPPING_THRESHOLD = 75
```

**Step 3: Commit**
```bash
git add bin/generators/generate_orders.py
git commit -m "fix(orders): Preserve tax cents precision, raise free shipping threshold to $75"
```

---

### Task 11: ASA — 3-Tier App Traffic Missing from Baseline (MAJOR)

**Files:**
- Modify: `bin/generators/generate_asa.py` — baseline event loop (~line 1512+)

**Problem:** The `asa_internal_app_traffic()` function exists (lines 633-693) but is only called during scenarios, not in baseline. The core business traffic (WEB→APP→SQL) should occur regularly (~2% of TCP sessions).

**Step 1: Add 3-tier traffic to baseline generation**

Find the baseline hourly event loop and add internal app traffic generation. After the existing TCP session generation:

```python
# 3-tier application traffic (WEB -> APP -> SQL, ~2% of TCP sessions)
app_traffic_count = max(1, int(base_events * 0.02))
for _ in range(app_traffic_count):
    events.extend(asa_internal_app_traffic(ts_str, ...))
```

Verify `asa_internal_app_traffic()` function signature and required parameters.

**Step 2: Run generator and verify output**
```bash
python3 bin/main_generate.py --sources=asa --days=1 --test --quiet
```

**Step 3: Commit**
```bash
git add bin/generators/generate_asa.py
git commit -m "fix(asa): Add 3-tier app traffic to baseline (~2% of TCP sessions)"
```

---

### Task 12: Catalyst — Admin VTY IPs Not from company.py (MAJOR)

**Files:**
- Modify: `bin/generators/generate_catalyst.py:98-105`

**Problem:** `VTY_SOURCES` dict hardcodes admin IPs instead of looking them up from `company.py USERS`. This breaks user correlation (Entra ID → Catalyst login).

**Step 1: Replace hardcoded IPs with company.py lookups**

Lines 98-105: Change from hardcoded IPs to:
```python
VTY_SOURCES = {}
for admin_name in ["mike.johnson", "jessica.brown", "patrick.gonzalez", ...]:
    user = USERS.get(admin_name)
    if user:
        VTY_SOURCES[admin_name] = user.ip_address
```

Or build dynamically at module level using IT department users from USERS dict.

**Step 2: Commit**
```bash
git add bin/generators/generate_catalyst.py
git commit -m "fix(catalyst): Use company.py IPs for admin VTY sources"
```

---

### Task 13: ACI — Atlanta Leaf Node IDs Wrong (MAJOR)

**Files:**
- Modify: `bin/generators/generate_aci.py:75-79`

**Problem:** Atlanta leafs use node IDs 401-402 but should follow Cisco ACI convention: pod-2 leafs should be 302-303 (300-series for pod-2), not 400-series.

**Step 1: Update node IDs**

Change Atlanta leaf definitions:
- `node-401` → `node-302`
- `node-402` → `node-303`

Update all DN references that include these node IDs (search for "node-401" and "node-402" in the file).

**Step 2: Commit**
```bash
git add bin/generators/generate_aci.py
git commit -m "fix(aci): Correct Atlanta leaf node IDs from 401-402 to 302-303 per Cisco convention"
```

---

### Task 14: AWS — Missing S3 GetObject responseElements (MAJOR)

**Files:**
- Modify: `bin/generators/generate_aws.py:233`

**Problem:** S3 GetObject events have `responseElements = None` but real events include encryption headers.

**Step 1: Add realistic responseElements**

Line 233: Change from `None` to:
```python
event["responseElements"] = {
    "x-amz-server-side-encryption": "AES256",
    "content-type": "application/octet-stream",
}
```

**Step 2: Commit**
```bash
git add bin/generators/generate_aws.py
git commit -m "fix(aws): Add realistic responseElements to S3 GetObject events"
```

---

### Task 15: MSSQL — Backup Page Count Unrealistically Low (MAJOR)

**Files:**
- Modify: `bin/generators/generate_mssql.py` — backup completion messages

**Problem:** Backup messages show page count ~45,280 which implies a ~350MB database. An enterprise e-commerce DB should be much larger (50,000-500,000 pages / 400MB-4GB).

**Step 1: Find and fix backup page counts**

Search for `45280` or page count references in generate_mssql.py. Update to a realistic range:
```python
page_count = random.randint(280000, 350000)  # ~2.2-2.7 GB database
```

**Step 2: Commit**
```bash
git add bin/generators/generate_mssql.py
git commit -m "fix(mssql): Realistic backup page counts for enterprise e-commerce DB"
```

---

### Task 16: Exchange — Calendar Invite Subject Format (MINOR)

**Files:**
- Modify: `bin/generators/generate_exchange.py:649-651`

**Problem:** Meeting invite subjects use `"Meeting Invite: {title}"` prefix. Real Outlook sends just the meeting title as the subject.

**Step 1: Remove "Meeting Invite:" prefix**

Line 651: Change from:
```python
f"Meeting Invite: {meeting.meeting_title}{room_info}"
```
To:
```python
f"{meeting.meeting_title}{room_info}"
```

**Step 2: Commit**
```bash
git add bin/generators/generate_exchange.py
git commit -m "fix(exchange): Remove unrealistic 'Meeting Invite:' subject prefix"
```

---

### Task 17: Sysmon — DNS Query Status Always Success (MINOR)

**Files:**
- Modify: `bin/generators/generate_sysmon.py:832-833`

**Problem:** All DNS queries have `QueryStatus: 0` (success). Real systems have ~5% failures.

**Step 1: Add DNS failure variation**

Replace hardcoded `QueryStatus: 0` with weighted random:
```python
query_status = 0 if random.random() > 0.05 else random.choice([3, 5, 9501])  # NXDOMAIN, REFUSED, TIMEOUT
```

**Step 2: Commit**
```bash
git add bin/generators/generate_sysmon.py
git commit -m "fix(sysmon): Add ~5% DNS query failures for realism"
```

---

### Task 18: Perfmon — SQL Server Disk Instances Missing (MINOR)

**Files:**
- Modify: `bin/generators/generate_perfmon.py:163-166`

**Problem:** LogicalDisk instances hardcoded as "C:" only. SQL Server should show backup disk "G:\".

**Step 1: Add server-role-based disk instances**

Map server roles to disk letters:
- SQL-PROD-01: C:, G: (data/backup)
- FILE-BOS-01: C:, D: (file shares)
- All others: C: only

**Step 2: Commit**
```bash
git add bin/generators/generate_perfmon.py
git commit -m "fix(perfmon): Server-role-specific disk instances"
```

---

### Task 19: Update CHANGEHISTORY.md

**Files:**
- Modify: `docs/CHANGEHISTORY.md`

**Step 1: Add entry at top of file**

```markdown
## 2026-03-05 ~XX:XX UTC — Full project realism & consistency audit

**Scope:** 7-area audit across all 24 generators + Splunk configuration.

**Findings fixed:**
- [List each task completed with severity]

**Verification:** Full regression — all generators pass.
```

**Step 2: Commit**
```bash
git add docs/CHANGEHISTORY.md
git commit -m "docs: Full project realism audit change history"
```

---

## Task Priority Matrix

| Priority | Tasks | Rationale |
|----------|-------|-----------|
| **P0 — Do First** | T1 (demo_id), T2 (Webex), T3 (O365 ops), T4 (ServiceBus qty), T5 (4624), T6 (MSSQL error) | Breaks correlation or produces wrong data |
| **P1 — Do Second** | T7 (GCP), T8 (AWS IDs), T9 (Entra spray), T10 (Orders tax), T11 (ASA 3-tier), T12 (Catalyst VTY) | Major realism gaps |
| **P2 — Do Third** | T13 (ACI nodes), T14 (AWS S3), T15 (MSSQL pages) | Noticeable to domain experts |
| **P3 — Optional** | T16 (Exchange), T17 (Sysmon DNS), T18 (Perfmon disks) | Cosmetic improvements |

## Parallelization

These tasks are fully independent (no shared files except T19):
- **Group A** (Splunk config): T1
- **Group B** (Network): T11, T12, T13
- **Group C** (Cloud/Security): T7, T8, T9, T14
- **Group D** (Windows/Infra): T5, T6, T15, T17, T18
- **Group E** (Collaboration/Email): T2, T3, T16
- **Group F** (Retail): T4, T10
- **Group G** (Docs): T19 (last, after all fixes)

All groups can run in parallel. T19 runs last.
