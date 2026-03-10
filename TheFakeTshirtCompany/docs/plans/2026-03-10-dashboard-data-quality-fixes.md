# Dashboard & Data Quality Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 18 dashboard and data quality issues — broken panels, field name mismatches, incorrect queries, missing extractions, and makeresults replacements.

**Architecture:** Fixes are grouped by root cause: transforms/props.conf fixes first (unblocks multiple dashboards), then dashboard query fixes, then generator improvements. Each task is independent unless noted.

**Tech Stack:** Splunk Dashboard Studio (JSON-in-XML), props.conf, transforms.conf, Python generators

---

## Task 1+2: Fix Perfmon `value` → `Value` in dashboard queries

**Scope:** Just update dashboard SPL queries to use `Value` (capital V) to match what the generator produces. No changes to transforms.conf or props.conf.

**Files:**
- Modify: `default/data/ui/views/discovery_itops.xml`
- Modify: `default/data/ui/views/scenario_cpu_runaway.xml`

**Step 1: Fix discovery_itops panels**

Panel "CPU Usage (% Processor Time)" — change `avg(value)` to `avg(Value)`:
```spl
index=fake_tshrt sourcetype="FAKE:Perfmon:Processor" OR sourcetype="FAKE:Perfmon:Generic" object=Processor counter="% Processor Time" instance=_Total | timechart span=1h avg(Value) by host
```

Panel "Available Memory (MBytes)" — change `avg(value)` to `avg(Value)`:
```spl
index=fake_tshrt sourcetype="FAKE:Perfmon:Memory" OR sourcetype="FAKE:Perfmon:Generic" object=Memory counter="Available MBytes" | timechart span=1h avg(Value) by host
```

**Step 2: Fix scenario_cpu_runaway panels**

Panel "CPU Usage (% Processor Time) — SQL-PROD-01" — change `avg(value)` to `avg(Value)`:
```spl
index=fake_tshrt (sourcetype="FAKE:Perfmon:Processor" OR (sourcetype="FAKE:Perfmon:Generic" object=Processor)) counter="% Processor Time" instance=_Total host=SQL-PROD-01 | timechart span=1h avg(Value) as "% CPU"
```

Panel "Available Memory (MBytes) — SQL-PROD-01" — change `avg(value)` to `avg(Value)`:
```spl
index=fake_tshrt (sourcetype="FAKE:Perfmon:Memory" OR (sourcetype="FAKE:Perfmon:Generic" object=Memory)) counter="Available MBytes" host=SQL-PROD-01 | timechart span=1h avg(Value) as "Available MBytes"
```

**Step 3: Commit**

```bash
git add default/data/ui/views/discovery_itops.xml default/data/ui/views/scenario_cpu_runaway.xml
git commit -m "fix(dashboard): Use correct Value field case in Perfmon panels"
```

---

## Task 3: Fix discovery_security_overview DNS panel

**Files:**
- Modify: `default/data/ui/views/discovery_security_overview.xml`

**Step 1: Fix field name case**

Panel "DNS Blocked Domains" — change `Domain` to `domain`:
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" action=Blocked src=$src_token$ | stats count by domain | sort -count | head 15
```

**Step 2: Verify the generator field name**

Check `bin/generators/generate_secure_access.py` to confirm the JSON field is lowercase `domain`. If it's uppercase `Domain` in the generator, then fix the generator instead. The CIM standard for DNS is lowercase `domain`.

**Step 3: Commit**

```bash
git add default/data/ui/views/discovery_security_overview.xml
git commit -m "fix(dashboard): Use lowercase domain field in DNS Blocked Domains panel"
```

---

## Task 4: Fix discovery_netops Wireless Clients panel — CIM type field overwrite

**Root cause:** `props.conf` line 1648 has `EVAL-type` that sets `type=NULL` for association events:

```
EVAL-type = case(type="rogue_ssid_detected", "warning", type="health_alert", "alert", 1=1, NULL)
```

This overwrites the original `type` field. After this EVAL, `type=association` no longer exists. The original value is preserved in `meraki_event_type` (via FIELDALIAS), but the dashboard queries `type=association`.

**Files:**
- Modify: `default/props.conf` (FAKE:meraki:accesspoints stanza, ~line 1648)
- Modify: `default/data/ui/views/discovery_netops.xml`

**Step 1: Fix the EVAL-type to preserve event types**

Option A (recommended): Rename the CIM EVAL to avoid overwriting the original `type`:
```
EVAL-vendor_severity = case(type="rogue_ssid_detected", "warning", type="health_alert", "alert", 1=1, NULL)
```
Remove the `EVAL-type` entirely. The original `type` field (association, disassociation, etc.) stays intact.

Option B: Update the dashboard to use `meraki_event_type=association` instead of `type=association`.

**Choose Option A** — it fixes the root cause. The EVAL was trying to map severity-like values, not replace the event type.

**Step 2: Update dashboard query if needed**

If Option A is chosen, the query `type=association` should work again. Verify:
```spl
index=fake_tshrt sourcetype="FAKE:meraki:accesspoints" type=association | head 5
```

**Step 3: Commit**

```bash
git add default/props.conf default/data/ui/views/discovery_netops.xml
git commit -m "fix(meraki): Stop EVAL-type from overwriting original event type field"
```

---

## Task 5: Replace makeresults in Kill Chain panel (scenario_exfil)

**Files:**
- Modify: `default/data/ui/views/scenario_exfil.xml`
- Modify: `default/data/ui/views/scenario_exfil_absolute.xml`

**Context:** The "Attack Journey — Kill Chain" panel uses `makeresults` with 35 hardcoded rows describing the exfil scenario phases. This is educational/narrative content structured for a linkgraph visualization.

**Step 1: Evaluate feasibility**

The kill chain panel is a **linkgraph visualization** showing a narrative flow of the attack phases. This is not raw event data — it's a curated story. The data includes columns like:
- Phase names (Recon, Initial Access, Lateral Movement, etc.)
- Descriptive text for each step
- Connections between steps

**Decision:** This panel should remain `makeresults`-based because:
- It's a narrative visualization, not an event summary
- The linkgraph format requires specific structured data
- Real queries would need complex post-processing to produce the same narrative

**However**, the Sankey "Attack Flow" panel could potentially be built from real ASA/CloudTrail data. Evaluate whether the data volume and fields support it.

**Step 2: If replacing the Sankey panel**

Try this query for the Attack Flow Sankey:
```spl
index=fake_tshrt demo_id=exfil sourcetype="FAKE:cisco:asa"
| eval src_zone=case(
    cidrmatch("185.220.101.0/24", src), "Threat Actor",
    cidrmatch("172.16.1.0/24", src), "DMZ",
    cidrmatch("10.10.20.0/24", src), "Boston Servers",
    cidrmatch("10.10.30.0/24", src), "Boston Users",
    1=1, src)
| eval dest_zone=case(
    cidrmatch("172.16.1.0/24", dest), "DMZ",
    cidrmatch("10.10.20.0/24", dest), "Boston Servers",
    cidrmatch("10.10.30.0/24", dest), "Boston Users",
    1=1, dest)
| stats count by src_zone dest_zone
| sort -count
```

Test in Splunk first. If results are meaningful, replace the makeresults Sankey. If not, keep makeresults.

**Step 3: Commit if changes made**

```bash
git add default/data/ui/views/scenario_exfil.xml default/data/ui/views/scenario_exfil_absolute.xml
git commit -m "fix(dashboard): Replace makeresults Sankey with real exfil data query"
```

---

## Task 6: Fix demo_id=exfil leaking beyond day 14 in AWS CloudTrail

**Root cause:** `bin/generators/generate_aws.py:628`:
```python
if active_scenarios and "exfil" in active_scenarios and day >= 7 and rule == "iam-user-no-mfa":
```
There is no upper bound — `day >= 7` means Config compliance events get tagged `demo_id=exfil` forever after day 7.

**Files:**
- Modify: `bin/generators/generate_aws.py:628`

**Step 1: Add upper bound to day range**

The exfil scenario runs days 0-13 (14 days total). Change line 628:
```python
if active_scenarios and "exfil" in active_scenarios and 7 <= day <= 13 and rule == "iam-user-no-mfa":
```

**Step 2: Verify no other generators have unbounded day ranges**

Search all generators and scenario files for `day >=` without upper bounds that also set `demo_id`:
```bash
grep -rn "day >=" bin/generators/ bin/scenarios/ | grep -i "demo_id\|exfil\|scenario"
```

**Step 3: Commit**

```bash
git add bin/generators/generate_aws.py
git commit -m "fix(aws): Bound exfil demo_id tagging to days 7-13, preventing leak beyond scenario"
```

---

## Task 7: Fix demo_id freetext queries in exfil dashboards

**Scope:** `scenario_exfil.xml` has 19 queries using `demo_id exfil` (freetext) instead of `demo_id=exfil` (field syntax). Same in `scenario_exfil_absolute.xml`.

**Files:**
- Modify: `default/data/ui/views/scenario_exfil.xml`
- Modify: `default/data/ui/views/scenario_exfil_absolute.xml`

**Step 1: Replace all freetext occurrences**

In both files, replace every occurrence of `demo_id exfil` with `demo_id=exfil`. These are Dashboard Studio JSON dashboards embedded in XML, so the queries are in JSON strings.

Search and replace: `demo_id exfil` → `demo_id=exfil`

**Expected count:** 19 replacements per file, 38 total.

**Step 2: Verify no other dashboards have the same issue**

```bash
grep -rn 'demo_id [a-z]' default/data/ui/views/ | grep -v 'demo_id=' | grep -v 'demo_id"'
```

**Step 3: Commit**

```bash
git add default/data/ui/views/scenario_exfil.xml default/data/ui/views/scenario_exfil_absolute.xml
git commit -m "fix(dashboard): Use field syntax demo_id=exfil instead of freetext in exfil dashboards"
```

---

## Task 8: Fix Lateral Movement (SMB) panel in scenario_ransomware_attempt

**Root cause:** The panel queries `sourcetype="FAKE:cisco:asa" src=10.30.30.20 dest=10.30.30.*` but the ransomware scenario generates **WinEventLog 4625** events (failed network logons), not ASA firewall events. Brooklyn White (10.30.30.20) is in Austin — Austin has no ASA, traffic goes through Meraki MX.

The actual lateral movement events are WinEventLog 4625 with:
- `EventCode=4625` (failed logon)
- `Logon Type: 3` (network/SMB)
- `Source Network Address: 10.30.30.20`
- `demo_id=ransomware_attempt`
- Target accounts: `Administrator`

**Files:**
- Modify: `default/data/ui/views/scenario_ransomware_attempt.xml`

**Step 1: Replace the query with correct sourcetype and fields**

```spl
index=fake_tshrt demo_id=ransomware_attempt sourcetype="FAKE:WinEventLog" EventCode=4625
| rex "Source Network Address:\s+(?<src_ip>\S+)"
| rex "Account Name:\s+(?<target_account>\S+)"
| rex "ComputerName=(?<target_host>[^\s\.]+)"
| stats count by src_ip target_host target_account
| sort -count
| rename src_ip as "Source IP" target_host as "Target Host" target_account as "Target Account" count as "Attempts"
```

**Step 2: Commit**

```bash
git add default/data/ui/views/scenario_ransomware_attempt.xml
git commit -m "fix(dashboard): Use WinEventLog 4625 for ransomware lateral movement panel"
```

---

## Task 9: Expand scenario_phishing_test dashboard

**Current panels (7):** Scenario Events KPI, Affected Sources KPI, Affected Hosts KPI, Click Rate (makeresults), Phishing Email Volume, Cross-Source Correlation Timeline, Events by Source

**Files:**
- Modify: `default/data/ui/views/scenario_phishing_test.xml`

**Step 1: Replace Click Rate makeresults with real data**

The click rate can be computed from actual data — count Exchange emails sent vs Entra ID credential submissions:
```spl
index=fake_tshrt demo_id=phishing_test
| eval event_type=case(
    sourcetype="FAKE:o365:reporting:messagetrace", "email_sent",
    sourcetype="FAKE:azure:aad:signin", "credential_submit",
    1=1, NULL)
| where isnotnull(event_type)
| stats dc(eval(if(event_type="email_sent", recipient, NULL))) as emails_sent
        dc(eval(if(event_type="credential_submit", identity, NULL))) as submitters
| eval click_rate=round(submitters/emails_sent*100, 0)."%"
| fields click_rate
| rename click_rate as count
```

**Step 2: Add new panels based on available data**

Panel: **"Credential Submitters"** — Table of users who submitted credentials:
```spl
index=fake_tshrt demo_id=phishing_test sourcetype="FAKE:azure:aad:signin"
| spath properties.userDisplayName
| spath properties.ipAddress
| spath properties.location.city
| stats count earliest(_time) as first_seen by properties.userDisplayName properties.ipAddress properties.location.city
| sort first_seen
| rename properties.userDisplayName as "User" properties.ipAddress as "Source IP" properties.location.city as "City" first_seen as "Submission Time"
| fieldformat "Submission Time"=strftime('Submission Time', "%Y-%m-%d %H:%M:%S")
```

Panel: **"Phishing Email Recipients by Location"** — Pie chart:
```spl
index=fake_tshrt demo_id=phishing_test sourcetype="FAKE:o365:reporting:messagetrace"
| rex field=RecipientAddress "(?<username>[^@]+)@"
| lookup user_lookup username OUTPUT location
| stats count by location
| sort -count
```

Panel: **"Browser Launches (Endpoint Evidence)"** — WinEventLog process creation:
```spl
index=fake_tshrt demo_id=phishing_test sourcetype="FAKE:WinEventLog" EventCode=4688
| rex "New Process Name:\s+(?<process>[^\r\n]+)"
| rex "Account Name:\s+(?<user>\S+)" max_match=2
| stats count by user process
| sort -count
| rename user as "User" process as "Browser Process" count as "Launches"
```

Panel: **"SafeLinks URL Clicks"** — Office 365 Audit:
```spl
index=fake_tshrt demo_id=phishing_test sourcetype="FAKE:o365:management:activity"
| spath Workload
| where Workload="ThreatIntelligence" OR Operation="UrlClickedAuditData"
| timechart span=1h count
```

**Step 3: Commit**

```bash
git add default/data/ui/views/scenario_phishing_test.xml
git commit -m "feat(dashboard): Add credential submitters, location, endpoint panels to phishing_test"
```

---

## Task 10: Fix scenario_memory_leak WEB-01 panels (Linux, not Windows)

**Root cause:** WEB-01 is a Linux server (DMZ). The panels use Perfmon sourcetypes (Windows).

**Files:**
- Modify: `default/data/ui/views/scenario_memory_leak.xml`

**Step 1: Replace "Available Memory (MBytes) — WEB-01" with Linux vmstat data**

```spl
index=fake_tshrt sourcetype="FAKE:vmstat" host=WEB-01
| eval memFreeMB=tonumber(memFreeMB)
| timechart span=1h avg(memFreeMB) as "Available Memory (MB)"
```

**Step 2: Replace "CPU Usage (%) — WEB-01" with Linux CPU data**

```spl
index=fake_tshrt sourcetype="FAKE:cpu" host=WEB-01
| eval cpu_used=100-tonumber(pctIdle)
| timechart span=1h avg(cpu_used) as "% CPU"
```

**Step 3: Commit**

```bash
git add default/data/ui/views/scenario_memory_leak.xml
git commit -m "fix(dashboard): Use Linux metrics for WEB-01 in memory_leak scenario"
```

---

## Task 12: Document demo_id application logic

**Purpose:** Understand and document whether `demo_id` is set on ALL events during a scenario's active period, or only on scenario-specific injected events.

**Files:**
- Create: `docs/reference/demo_id_logic.md`

**Step 1: Research each generator**

For each of the 24 generators, check how `demo_id` is applied:
- Is it set on every event during the scenario's active days?
- Or only on specific scenario-injected events?
- Are there any that tag baseline events with demo_id?

**Step 2: Document findings**

Create a reference table:

| Generator | demo_id Scope | Notes |
|-----------|--------------|-------|
| asa | Injected only | Only scenario-specific events get demo_id |
| aws | Injected + leaked | Config compliance events tagged after day 7 (Task 6) |
| ... | ... | ... |

**Step 3: Commit**

```bash
git add docs/reference/demo_id_logic.md
git commit -m "docs: Add demo_id application logic reference"
```

---

## Task 13: Fix HTTP Error Rate in scenario_cpu_runaway

**Problem:** Panel shows error rates from ALL scenarios, not just cpu_runaway (days 11-12).

Current query:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" | eval is_error=if(status>=500, 1, 0) | timechart span=1h avg(is_error) as error_rate | eval error_rate=round(error_rate*100, 1)
```

**Files:**
- Modify: `default/data/ui/views/scenario_cpu_runaway.xml`

**Step 1: Add demo_id filter to scope the query**

Verified: access_combined events during cpu_runaway ARE tagged with `demo_id=cpu_runaway` (generate_access.py lines 842, 866-871). Add the filter:

```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=cpu_runaway
| eval is_error=if(status>=500, 1, 0)
| timechart span=1h sum(is_error) as errors count as total
| eval error_rate=round(errors/total*100, 1)
```

**Step 2: Commit**

```bash
git add default/data/ui/views/scenario_cpu_runaway.xml
git commit -m "fix(dashboard): Scope HTTP Error Rate to cpu_runaway scenario period"
```

---

## Task 14: Fix FAKE:df — multiple mount points + broken field extraction

**Three issues:**
1. Generator only produces one mount point (`/`) per host
2. REPORT transform (`extract_linux_df_fields`) expects `Filesystem=... Size=... MountedOn=...` but generator outputs `mount=/ TotalGB=... UsedGB=...` — **completely different field names, transform never matches**
3. `FIELDALIAS-mount = MountedOn AS mount` does nothing because `MountedOn` is never extracted
4. `KV_MODE = auto` should auto-extract `mount`, `TotalGB`, etc. from the key=value format, but `mount=/` may not extract properly (single `/` as value)

**Current state:**
- Generator outputs: `2026-01-01 00:00:00 host=WEB-01 mount=/ TotalGB=500 UsedGB=250 AvailGB=250 UsedPct=50.0`
- Transform regex: `Filesystem=(\S+)\s+Size=(\S+)\s+Used=(\S+)\s+Avail=(\S+)\s+UsePct=(\S+)\s+MountedOn=(\S+)` — **will never match**
- Dashboard query: `stats latest(UsedPct) as used_pct by host`

**Files:**
- Modify: `bin/generators/generate_linux.py:96-112`
- Modify: `default/transforms.conf` (extract_linux_df_fields)
- Modify: `default/props.conf` (FAKE:df stanza — fix FIELDALIAS)
- Possibly modify: `default/data/ui/views/discovery_itops.xml`

**Step 1: Fix the transform to match what the generator actually outputs**

Update `extract_linux_df_fields` in transforms.conf:
```
[extract_linux_df_fields]
REGEX = mount=(\S+)\s+TotalGB=(\d+)\s+UsedGB=(\d+)\s+AvailGB=(\d+)\s+UsedPct=([\d.]+)
FORMAT = mount::$1 TotalGB::$2 UsedGB::$3 AvailGB::$4 UsedPct::$5
```

**Step 2: Fix the field aliases in props.conf**

Replace the broken aliases with ones matching the actual fields:
```
FIELDALIAS-mount = mount AS MountedOn
EVAL-storage_used_percent = tonumber(UsedPct)
```

Remove the old `FIELDALIAS-mount = MountedOn AS mount` (backwards — `MountedOn` doesn't exist).
Remove `FIELDALIAS-filesystem = Filesystem AS filesystem` (Filesystem doesn't exist).
Remove `EVAL-storage_used_percent = tonumber(rtrim(UsePct, "%"))` (no `%` in the value).

**Step 3: Add multiple mount points to the generator**

Linux servers should have multiple mount points. Add a dict per host and update `disk_metric()`:

```python
LINUX_MOUNT_POINTS = {
    "WEB-01":        [("/", 500), ("/var/log", 100), ("/var/www", 200)],
    "WEB-02":        [("/", 500), ("/var/log", 100), ("/var/www", 200)],
    "MON-ATL-01":    [("/", 500), ("/var/log", 200), ("/data", 1000)],
    "BASTION-BOS-01":[("/", 100), ("/var/log", 50)],
    "SAP-PROD-01":   [("/", 500), ("/usr/sap", 300), ("/sapmnt", 200)],
    "SAP-DB-01":     [("/", 500), ("/hana/data", 2000), ("/hana/log", 500)],
}
```

Update `disk_metric()` to accept mount and total_gb parameters. Update the call site to loop over mount points.

**Step 4: Verify dashboard query**

The `discovery_itops.xml` "Disk Usage by Host" query uses `UsedPct` which should now be extracted by the fixed transform. Add mount point to the grouping:
```spl
index=fake_tshrt sourcetype="FAKE:df" | stats latest(UsedPct) as used_pct by host, mount | sort -used_pct
```

**Step 5: Commit**

```bash
git add bin/generators/generate_linux.py default/transforms.conf default/props.conf default/data/ui/views/discovery_itops.xml
git commit -m "fix(linux): Fix df field extraction, add multiple mount points per host"
```

---

## Task 15: Fix HTTP Error Rate in scenario_disk_filling

**Problem:** MON-ATL-01 is a monitoring server — it doesn't serve web traffic, so `sourcetype="FAKE:access_combined" host=MON-ATL-01` returns nothing.

**Files:**
- Modify: `default/data/ui/views/scenario_disk_filling.xml`

**Step 1: Replace with a relevant panel**

For a disk-filling scenario, show disk usage over time instead of HTTP error rate:

```spl
index=fake_tshrt sourcetype="FAKE:df" host=MON-ATL-01
| eval used_pct=tonumber(UsedPct)
| timechart span=4h max(used_pct) as "Disk Usage %"
```

Or show Linux system load impact:
```spl
index=fake_tshrt sourcetype="FAKE:iostat" host=MON-ATL-01
| timechart span=1h avg(pct_util) as "Disk I/O Utilization %"
```

Update the panel title from "HTTP Error Rate (%)" to "Disk Usage Over Time (%)" or similar.

**Step 2: Commit**

```bash
git add default/data/ui/views/scenario_disk_filling.xml
git commit -m "fix(dashboard): Replace HTTP Error Rate with disk usage panel in disk_filling scenario"
```

---

## Task 16: Replace makeresults in scenario_dead_letter_pricing

**Files:**
- Modify: `default/data/ui/views/scenario_dead_letter_pricing.xml`

**Step 1: Replace "Incident Duration" makeresults**

Current: `| makeresults | eval count="5 hrs" | fields count`

Replace with a query that calculates the actual duration from the data:
```spl
index=fake_tshrt demo_id=dead_letter_pricing
| stats min(_time) as first max(_time) as last
| eval duration_hrs=round((last-first)/3600, 1)
| eval count=duration_hrs." hrs"
| fields count
```

**Step 2: Commit**

```bash
git add default/data/ui/views/scenario_dead_letter_pricing.xml
git commit -m "fix(dashboard): Calculate dead_letter_pricing duration from real data"
```

---

## Task 17: Fix HTTP Error Rate in scenario_dead_letter_pricing

**Current query:**
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=dead_letter_pricing | eval is_error=if(status>=500, 1, 0) | timechart span=30m perc(is_error) as error_rate
```

**Problem:** `perc()` is not a valid Splunk function. Should be `perc95()`, `avg()`, or manual calculation.

**Files:**
- Modify: `default/data/ui/views/scenario_dead_letter_pricing.xml`

**Step 1: Fix the query**

```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=dead_letter_pricing
| eval is_error=if(status>=500, 1, 0)
| timechart span=30m sum(is_error) as errors count as total
| eval error_rate=round(errors/total*100, 1)
```

If `demo_id=dead_letter_pricing` doesn't exist on access_combined events, broaden the query to show error rates during the scenario time window by removing the demo_id filter and relying on the dashboard time picker.

**Step 2: Commit**

```bash
git add default/data/ui/views/scenario_dead_letter_pricing.xml
git commit -m "fix(dashboard): Fix HTTP Error Rate calculation in dead_letter_pricing"
```

---

## Task 18: Fix HTTP Error Rate in scenario_ddos_attack

**Current query:**
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=ddos_attack | eval is_error=if(status>=500, 1, 0) | timechart span=1h perc(is_error) as error_rate
```

**Same problem as Task 17:** `perc()` is not a valid Splunk function.

**Files:**
- Modify: `default/data/ui/views/scenario_ddos_attack.xml`

**Step 1: Fix the query**

```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=ddos_attack
| eval is_error=if(status>=500, 1, 0)
| timechart span=1h sum(is_error) as errors count as total
| eval error_rate=round(errors/total*100, 1)
```

**Step 2: Also fix "Attack Duration" makeresults if possible**

Current: `| makeresults | eval count="28 hrs" | fields count`

Replace:
```spl
index=fake_tshrt demo_id=ddos_attack
| stats min(_time) as first max(_time) as last
| eval duration_hrs=round((last-first)/3600, 0)
| eval count=duration_hrs." hrs"
| fields count
```

**Step 3: Commit**

```bash
git add default/data/ui/views/scenario_ddos_attack.xml
git commit -m "fix(dashboard): Fix HTTP Error Rate and Attack Duration in ddos_attack"
```

---

## Execution Order

All tasks are independent and can be done in any order:

**Quick fixes (dashboard query changes only):**
- Task 1+2 (Perfmon `value` → `Value` in discovery_itops + scenario_cpu_runaway)
- Task 3 (DNS `Domain` → `domain`)
- Task 7 (demo_id freetext → field syntax, 38 replacements)
- Task 13, 17, 18 (HTTP Error Rate query fixes)

**Root cause fixes (props.conf / generator):**
- Task 4 (Meraki EVAL-type overwrite)
- Task 6 (AWS exfil day bound)

**Panel replacements (wrong sourcetype/query):**
- Task 8 (Ransomware SMB → WinEventLog 4625)
- Task 10 (memory_leak WEB-01: Perfmon → Linux metrics)
- Task 15 (disk_filling: HTTP Error Rate → disk usage)
- Task 16 (dead_letter_pricing makeresults)

**Larger changes:**
- Task 14 (df mount points + field extraction)
- Task 9 (phishing_test dashboard expansion)
- Task 5 (kill chain makeresults evaluation)
- Task 12 (demo_id documentation)

---

## Verification

After all changes:
1. Regenerate data: `python3 bin/main_generate.py --all --scenarios=all --days=28 --no-test`
2. Re-index in Splunk
3. Verify each fixed panel shows data
4. Verify `demo_id=exfil` no longer appears after day 14 in CloudTrail
5. Verify Perfmon `Value` field extracts correctly
6. Verify `type=association` works for Meraki accesspoints
