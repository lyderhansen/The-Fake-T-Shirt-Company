# Quality Checklist — TA-FAKE-TSHRT

Comprehensive quality audit of all 61 sourcetypes across 24 generators.
Generated from live Splunk data (index=fake_tshrt, Jan 2026, ~25.8M events).

---

## Legend

| Symbol | Meaning |
|--------|---------|
| OK | Verified working |
| BUG | Broken — needs fix |
| MISS | Missing — needs to be created |
| WARN | Works but could be improved |
| N/A | Not applicable |
| STALE | Data in Splunk predates a code fix — needs regeneration |

---

## 1. CRITICAL BUGS (Must Fix)

### 1.1 eventtypes.conf — Wrong Index and Sourcetype Names

**Severity: CRITICAL** — All eventtypes and CIM tags are completely broken.

`eventtypes.conf` references `index=splunk_demo` and sourcetypes with `:demo` suffix.
Actual index is `fake_tshrt` and sourcetypes use `FAKE:` prefix.

| Eventtype | Current (Broken) | Should Be |
|-----------|------------------|-----------|
| `demo_scenario_exfil` | `index=splunk_demo demo_id=exfil` | `index=fake_tshrt demo_id=exfil` |
| `demo_cloud_security` | `sourcetype=aws:cloudtrail:demo` | `sourcetype="FAKE:aws:cloudtrail"` |
| `demo_network_security` | `sourcetype=cisco:asa:demo` | `sourcetype="FAKE:cisco:asa"` |
| `demo_windows` | `sourcetype=WinEventLog:demo` | `sourcetype="FAKE:WinEventLog"` |
| `demo_linux` | `sourcetype=cpu:demo` | `sourcetype="FAKE:cpu"` |
| `demo_collaboration` | `sourcetype=cisco:webex:*:demo` | `sourcetype="FAKE:cisco:webex:*"` |
| `demo_retail` | `sourcetype=online:order:demo` | `sourcetype="FAKE:online:order"` |
| `demo_itsm` | `sourcetype=servicenow:incident:demo` | `sourcetype="FAKE:servicenow:incident"` |
| `demo_authentication` | `sourcetype=azure:aad:signin:demo` | `sourcetype="FAKE:azure:aad:signin"` |
| `demo_network_traffic` | `sourcetype=cisco:asa:demo` | `sourcetype="FAKE:cisco:asa"` |
| `demo_change` | `sourcetype=azure:aad:audit:demo` | `sourcetype="FAKE:azure:aad:audit"` |
| `demo_malware` | `sourcetype=cisco:asa:demo` | `sourcetype="FAKE:cisco:asa"` |
| `demo_web` | `sourcetype=access_combined:demo` | `sourcetype="FAKE:access_combined"` |

**Impact:** All CIM data model tags (authentication, network, change, malware, web) and all scenario tags (exfil, memory_leak, etc.) are non-functional. No events will ever match these eventtypes.

**Files:** `eventtypes.conf`, `tags.conf`

---

### 1.2 Entra ID Sign-in — `user` Field is Null

**Severity: CRITICAL** — User correlation is broken for 8,546 interactive sign-in events.

The `EVAL-user` in props.conf uses `lower(userPrincipalName)` but this field does not exist at the top level of the JSON. The actual field path is `properties.userPrincipalName`.

The `FIELDALIAS-user_for_signin` correctly maps `properties.userPrincipalName AS user` but the EVAL-user overrides it (EVALs take priority over FIELDALIASes in Splunk).

**Affected sourcetypes:** `FAKE:azure:aad:signin`, `FAKE:azure:aad:audit`

**Current EVAL (broken):**
```
EVAL-user = lower(userPrincipalName)
```

**Fix:** Use nested JSON path:
```
EVAL-user = lower('properties.userPrincipalName')
```

**Also affected EVALs:** `EVAL-user_id`, `EVAL-app` (uses `appDisplayName` which is actually `properties.appDisplayName`), `EVAL-dest` (uses `resourceDisplayName`), `EVAL-duration` (uses `processingTimeInMilliseconds`)

---

### 1.3 Missing Lookup File: `sqlserver_host_dbserver_lookup.csv`

**Severity: HIGH** — transforms.conf line 246-247 references this lookup but the file does not exist in `lookups/`.

```ini
[sqlserver_host_dbserver_lookup]
filename = sqlserver_host_dbserver_lookup.csv
```

**Fix:** Either create the CSV file or remove the stanza from transforms.conf.

---

### 1.4 Unreferenced Lookup: `cisco_asa_messageid.csv`

**Severity: LOW** — File exists in `lookups/` but is never referenced in props.conf or transforms.conf. Dead file taking up space.

**Fix:** Either wire it up with a LOOKUP- stanza or remove it.

---

## 2. EVENTTYPES AND CIM COMPLETENESS

### 2.1 Missing Scenario Eventtypes

Only 5 of 10 scenarios have eventtypes. Missing:

| Scenario | demo_id | Sourcetype Count in Data |
|----------|---------|--------------------------|
| ransomware_attempt | `ransomware_attempt` | 11 sourcetypes |
| phishing_test | `phishing_test` | 7 sourcetypes |
| ddos_attack | `ddos_attack` | 21 sourcetypes |
| dead_letter_pricing | `dead_letter_pricing` | 6 sourcetypes |
| certificate_expiry | `certificate_expiry` | 4 sourcetypes |

### 2.2 Missing CIM Eventtype/Tag Coverage

Currently defined CIM eventtypes only cover 5 data models. Missing:

| CIM Data Model | Relevant Sourcetypes | Status |
|----------------|---------------------|--------|
| Authentication | FAKE:azure:aad:signin, FAKE:WinEventLog, FAKE:linux:auth | PARTIAL — linux:auth missing |
| Network Traffic | FAKE:cisco:asa, FAKE:meraki:securityappliances, FAKE:cisco:umbrella:firewall | PARTIAL — meraki/umbrella missing |
| Change | FAKE:azure:aad:audit, FAKE:aws:cloudtrail, FAKE:gcp:* | OK (once index is fixed) |
| Malware/IDS | FAKE:cisco:asa, FAKE:meraki:securityappliances | PARTIAL — meraki IDS missing |
| Web | FAKE:access_combined | OK (once index is fixed) |
| Email | FAKE:o365:reporting:messagetrace | MISS — no email eventtype |
| Endpoint | FAKE:WinEventLog, FAKE:WinEventLog:Sysmon | MISS — no endpoint eventtype for CIM |
| Performance | FAKE:Perfmon:*, FAKE:cpu, FAKE:vmstat, FAKE:df | MISS — no performance eventtype |
| Intrusion Detection | FAKE:aws:cloudwatch:guardduty, FAKE:cisco:umbrella:* | MISS |
| Ticket Management | FAKE:servicenow:incident | MISS |
| DNS | FAKE:cisco:umbrella:dns | MISS |

### 2.3 Missing Source Group Eventtypes

The following source groups exist in the data but have no eventtypes:

| Group | Sourcetypes |
|-------|-------------|
| ERP | FAKE:sap:auditlog |
| Campus Network | FAKE:cisco:ios, FAKE:cisco:catalyst:* |
| Data Center | FAKE:cisco:aci:* |
| Secure Access | FAKE:cisco:umbrella:* |

---

## 3. FIELD EXTRACTION AUDIT — Per Sourcetype

### 3.1 Network Sources

| Sourcetype | Events | host | src | dest | user | action | vendor_product | CIM Fields | Status |
|-----------|--------|------|-----|------|------|--------|----------------|------------|--------|
| FAKE:cisco:asa | 1,136K | OK (FW-EDGE-01) | OK (1485 uniq) | OK (580 uniq) | OK (75 uniq) | OK (7 values) | OK | Full CIM via lookups + EVALs | OK |
| FAKE:meraki:securityappliances | 40K | ? | ? | ? | N/A | ? | ? | Lookups defined | VERIFY |
| FAKE:meraki:accesspoints | 19K | ? | ? | ? | ? | ? | ? | Lookups defined | VERIFY |
| FAKE:meraki:switches | 6K | ? | ? | ? | N/A | ? | ? | Lookups defined | VERIFY |
| FAKE:meraki:cameras | 15K | ? | ? | ? | N/A | ? | ? | Lookups defined | VERIFY |
| FAKE:meraki:sensors | 291K | ? | N/A | N/A | N/A | N/A | ? | Health metrics | VERIFY |
| FAKE:meraki:accesspoints:health | 321K | ? | N/A | N/A | N/A | N/A | ? | Health metrics | VERIFY |
| FAKE:meraki:switches:health | 3,923K | ? | N/A | N/A | N/A | N/A | ? | Health metrics | VERIFY |
| FAKE:cisco:ios | 30K | ? | ? | ? | ? | ? | ? | No CIM EVALs in props | WARN |
| FAKE:cisco:aci:event | 36K | ? | ? | ? | ? | ? | ? | No CIM EVALs in props | WARN |
| FAKE:cisco:aci:fault | 8K | ? | ? | N/A | N/A | ? | ? | No CIM EVALs in props | WARN |
| FAKE:cisco:aci:audit | 45 | ? | ? | ? | ? | ? | ? | No CIM EVALs in props | WARN |

### 3.2 Cloud Security Sources

| Sourcetype | Events | host | user | src | action | vendor_product | Status |
|-----------|--------|------|------|-----|--------|----------------|--------|
| FAKE:aws:cloudtrail | 4,871 | ? | OK (via alias) | OK (via alias) | OK (via alias) | OK | OK |
| FAKE:aws:cloudwatch:guardduty | 169 | ? | ? | ? | ? | OK | VERIFY |
| FAKE:aws:billing:cur | 527 | ? | N/A | N/A | N/A | OK | OK |
| FAKE:azure:aad:signin | 19,639 | ? | **BUG** (null) | OK (188 uniq) | OK | OK | BUG 1.2 |
| FAKE:azure:aad:audit | 752 | ? | **BUG** (null) | ? | ? | OK | BUG 1.2 |
| FAKE:azure:aad:riskDetection | 91 | ? | ? | ? | N/A | OK | VERIFY |
| FAKE:google:gcp:pubsub:audit:admin_activity:demo | 2,601 | OK | OK (full CIM) | OK | OK | OK | OK |
| FAKE:google:gcp:pubsub:audit:data_access:demo | 992 | OK | OK (full CIM) | OK | OK | OK | OK |

**Note:** GCP sourcetypes have `:demo` suffix in index — this is a sourcetype routing artifact from transforms.conf. This should be verified as intentional.

### 3.3 Collaboration Sources

| Sourcetype | Events | Key Fields | vendor_product | Status |
|-----------|--------|------------|----------------|--------|
| FAKE:cisco:webex:events | 57K | ? | ? | VERIFY |
| FAKE:cisco:webex:meetings | 737 | ? | ? | VERIFY |
| FAKE:cisco:webex:meetings:history:meetingusagehistory | 588 | ? | ? | VERIFY |
| FAKE:cisco:webex:meetings:history:meetingattendeehistory | 4,754 | ? | ? | VERIFY |
| FAKE:cisco:webex:admin:audit:events | 549 | ? | ? | VERIFY |
| FAKE:cisco:webex:security:audit:events | 10K | ? | ? | VERIFY |
| FAKE:cisco:webex:meeting:qualities | 6,200 | ? | ? | VERIFY |
| FAKE:cisco:webex:call:detailed_history | 1,234 | ? | ? | VERIFY |
| FAKE:o365:reporting:messagetrace | 113K | ? | OK (via alias) | OK | VERIFY |
| FAKE:o365:management:activity | 41K | ? | OK (via alias) | OK | VERIFY |

### 3.4 Windows/Linux Sources

| Sourcetype | Events | host | Key Fields | vendor_product | Status |
|-----------|--------|------|------------|----------------|--------|
| FAKE:WinEventLog | 13K | OK (8 hosts) | signature_id (17 uniq) | OK | OK |
| FAKE:WinEventLog:Sysmon | 69K | ? | ? | ? | VERIFY |
| FAKE:Perfmon:Processor | 1,438K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:Memory | 1,141K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:LogicalDisk | 1,141K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:Network_Interface | 719K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:SQLServer:sql_statistics | 9K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:SQLServer:buffer_manager | 18K | ? | Value, counter | ? | VERIFY |
| FAKE:Perfmon:SQLServer:locks | 9K | ? | Value, counter | ? | VERIFY |
| FAKE:mssql:errorlog | 2,949 | ? | ? | ? | VERIFY |
| FAKE:cpu | 53K | ? | pctIdle, cpu_load_percent | ? | VERIFY |
| FAKE:vmstat | 53K | ? | MemFree, SwapUsed | ? | VERIFY |
| FAKE:df | 53K | ? | UsePct, mount | ? | VERIFY |
| FAKE:iostat | 53K | ? | rkBs, wkBs | ? | VERIFY |
| FAKE:interfaces | 53K | ? | Iface, rxBytes | ? | VERIFY |
| FAKE:linux:auth | 24K | ? | user, src, action, process | ? | VERIFY |

### 3.5 Web/Retail/ERP/ITSM Sources

| Sourcetype | Events | Key Fields | vendor_product | Status |
|-----------|--------|------------|----------------|--------|
| FAKE:access_combined | 11,018K | clientip, method, uri, status | OK | OK |
| FAKE:online:order | 986K | JSON auto-extracted | OK | OK |
| FAKE:online:order:registry | 209K | JSON auto-extracted | OK | OK |
| FAKE:azure:servicebus | 1,032K | JSON auto-extracted | OK | OK |
| FAKE:sap:auditlog | 42K | user (77 uniq), tcode (37 uniq) | N/A | STALE (web_order_id=0) |
| FAKE:servicenow:incident | 2,707 | number (410 uniq), state, priority | N/A | OK |
| FAKE:servicenow:change | 573 | ? | ? | VERIFY |
| FAKE:servicenow:cmdb | ? | ? | ? | VERIFY (has props stanza, no data?) |

### 3.6 Cisco Secure Access Sources

| Sourcetype | Events | Key Fields | vendor_product | Status |
|-----------|--------|------------|----------------|--------|
| FAKE:cisco:umbrella:dns | 1,067K | ? | ? | VERIFY |
| FAKE:cisco:umbrella:proxy | 341K | ? | ? | VERIFY |
| FAKE:cisco:umbrella:firewall | 106K | ? | ? | VERIFY |
| FAKE:cisco:umbrella:audit | 36 | ? | ? | VERIFY |

### 3.7 Catalyst Center Sources

| Sourcetype | Events | Key Fields | vendor_product | Status |
|-----------|--------|------------|----------------|--------|
| FAKE:cisco:catalyst:devicehealth | 27K | JSON auto-extracted | ? | VERIFY |
| FAKE:cisco:catalyst:networkhealth | 18K | JSON auto-extracted | ? | VERIFY |
| FAKE:cisco:catalyst:clienthealth | 1,116 | JSON auto-extracted | ? | VERIFY |
| FAKE:cisco:catalyst:issue | 15 | JSON auto-extracted | ? | VERIFY |

---

## 4. SCENARIO COVERAGE AUDIT

### 4.1 Scenario-to-Sourcetype Matrix

Cross-referenced from live Splunk data (`demo_id=*`):

| Scenario | Expected Sources (CLAUDE.md) | Actual Sources (Splunk) | Missing |
|----------|------------------------------|------------------------|---------|
| **exfil** | asa, entraid, aws, gcp, perfmon, wineventlog, exchange, office_audit, servicenow, mssql, sysmon, secure_access, catalyst, aci | 36 sourcetypes | Has extras (webex, linux metrics, guardduty, risk detection) |
| **ransomware_attempt** | asa, exchange, wineventlog, meraki, servicenow, office_audit, sysmon, secure_access | 11 sourcetypes | **Missing ASA** |
| **phishing_test** | exchange, entraid, wineventlog, office_audit, servicenow, secure_access | 7 sourcetypes | **Missing secure_access** (only dns present) |
| **memory_leak** | perfmon, linux, asa, access, catalyst_center | 12 sourcetypes | Has extras (aws, servicebus, orders, sap, servicenow) |
| **cpu_runaway** | perfmon, wineventlog, asa, access, aci, catalyst_center | 19 sourcetypes | Has extras (aws, gcp, mssql, orders, sap, servicenow) |
| **disk_filling** | linux, access | 8 sourcetypes | Has extras (orders, sap, servicenow) |
| **ddos_attack** | asa, meraki, access, perfmon, linux, servicenow, catalyst, aci, catalyst_center | 21 sourcetypes | Has extras (aws billing, orders, sap, ios) |
| **firewall_misconfig** | asa, servicenow, catalyst | 6 sourcetypes | Has extras (access, orders, sap) — **Missing catalyst** |
| **certificate_expiry** | asa, access, servicenow | 4 sourcetypes | Has extras (servicenow:change) — **Missing access** in data |
| **dead_letter_pricing** | servicebus, orders, access, servicenow | 6 sourcetypes | Has extras (sap) |

### 4.2 Scenario Issues Found

- [ ] **ransomware_attempt**: Missing `FAKE:cisco:asa` events (expected per CLAUDE.md)
- [ ] **phishing_test**: Missing `FAKE:cisco:umbrella:proxy` events (only dns present)
- [ ] **firewall_misconfig**: Missing `FAKE:cisco:ios` (catalyst) events
- [ ] **certificate_expiry**: Missing `FAKE:access_combined` events
- [ ] Several scenarios have MORE sources than documented — CLAUDE.md needs updating or generators are injecting scenario events more broadly than designed

### 4.3 Naming Mismatch

Dashboard and doc files use `ransomware` but the scenario registry uses `ransomware_attempt`:
- `scenario_ransomware.xml` (dashboard)
- `docs/scenarios/ransomware.md`

---

## 5. SPLUNK CONFIGURATION AUDIT

### 5.1 props.conf Stanza Coverage

| Category | Stanzas in props.conf | Sourcetypes in Splunk | Match |
|----------|----------------------|----------------------|-------|
| Cloud | 12 stanzas | 12 sourcetypes | OK |
| Network | 12 stanzas | 12 sourcetypes | OK |
| Windows | 10 stanzas | 10 sourcetypes | OK |
| Linux | 7 stanzas | 7 sourcetypes | OK |
| Web/Retail | 3 stanzas | 3 sourcetypes | OK |
| ERP | 1 stanza | 1 sourcetype | OK |
| ITSM | 3 stanzas | 3 sourcetypes | WARN (servicenow:cmdb has stanza but 0 events) |
| Collaboration | 8 stanzas | 8 sourcetypes | OK |
| Secure Access | 4 stanzas | 4 sourcetypes | OK |
| Catalyst Center | 4 stanzas | 4 sourcetypes | OK |

### 5.2 GCP Sourcetype `:demo` Suffix

GCP sourcetypes in Splunk have `:demo` suffix:
- `FAKE:google:gcp:pubsub:audit:admin_activity:demo`
- `FAKE:google:gcp:pubsub:audit:data_access:demo`

But props.conf stanzas are:
- `[FAKE:google:gcp:pubsub:audit:admin_activity]`
- `[FAKE:google:gcp:pubsub:audit:data_access]`

This means the CIM field extractions (which are extensive for GCP) may NOT be applied to the indexed data because the stanza names don't match. **Needs verification.**

### 5.3 Lookup Audit

| Lookup File | Referenced in transforms.conf | Referenced in props.conf | Status |
|-------------|------------------------------|------------------------|--------|
| cisco_asa_action_lookup.csv | Yes | Yes | OK |
| cisco_asa_change_analysis_lookup.csv | Yes | Yes | OK |
| cisco_asa_severity_lookup.csv | Yes | Yes | OK |
| cisco_asa_syslog_severity_lookup.csv | Yes | Yes | OK |
| cisco_asa_vendor_class_lookup.csv | Yes | Yes | OK |
| cisco_asa_protocol_version.csv | Yes | Yes | OK |
| cisco_asa_messageid.csv | No | No | WARN — unreferenced |
| cisco_meraki_securityappliances_action_lookup.csv | Yes | Yes | OK |
| cisco_meraki_securityappliances_change_type_result_lookup.csv | Yes | Yes | OK |
| cisco_meraki_securityappliances_object_object_category_lookup.csv | Yes | Yes | OK |
| cisco_meraki_accesspoints_action_lookup.csv | Yes | Yes | OK |
| cisco_meraki_accesspoints_change_type_object_object_category_result_lookup.csv | Yes | Yes | OK |
| cisco_meraki_accesspoints_object_attrs_lookup.csv | Yes | Yes | OK |
| cisco_meraki_switches_action_lookup.csv | Yes | Yes | OK |
| cisco_meraki_switches_change_type_object_lookup.csv | Yes | Yes | OK |
| cisco_meraki_switches_result_lookup.csv | Yes | Yes | OK |
| cisco_meraki_cameras_lookup.csv | Yes | Yes | OK |
| cisco_meraki_organizationsecurity_lookup.csv | Yes | ? | VERIFY |
| customer_lookup.csv | Yes | ? | VERIFY |
| windows_severity_lookup.csv | Yes | Yes | OK |
| windows_signature_lookup.csv | Yes | Yes | OK |
| splunk_ta_o365_cim_messagetrace_action.csv | Yes | Yes | OK |
| identity_inventory.csv | ? | ? | VERIFY |
| asset_inventory.csv | ? | ? | VERIFY |
| mac_inventory.csv | ? | ? | VERIFY |
| sqlserver_host_dbserver_lookup.csv | Yes (transforms.conf) | No | BUG — file missing |

---

## 6. DATA CONTINUITY AND CORRELATION

### 6.1 Cross-Generator Correlation Paths

| Correlation | Generator A | Generator B | Link Field | Status |
|-------------|-------------|-------------|------------|--------|
| Web order -> SAP | access (order_registry.json) | sap | web_order_id / ref ORD-* | STALE (code fixed, data not regenerated) |
| Web order -> Orders | access (order_registry.json) | orders | order_id | OK |
| Web order -> ServiceBus | access (order_registry.json) | servicebus | order_id | OK |
| User -> IP | company.py | all generators | user + src IP | OK |
| VPN -> IP | asa (VPN events) | entraid, wineventlog | assigned_ip | VERIFY |
| Meeting -> Sensors | webex | meraki (MV/MT) | timestamp + room | VERIFY |
| Incident -> Scenario | servicenow | all scenario sources | demo_id | OK |

### 6.2 Timeline Continuity

| Check | Expected | Status |
|-------|----------|--------|
| All data in Jan 2026 | 2026-01-01 to 2026-01-31 | OK |
| No events outside time range | No data before Jan 1 or after Jan 31 | VERIFY |
| Scenarios align with documented day ranges | e.g., exfil days 1-14 | VERIFY |
| Weekend volume reduction | Lower event counts Sat/Sun | VERIFY |
| Business hours pattern | Peak 9-11 AM, 1-3 PM | VERIFY |

---

## 7. DOCUMENTATION GAPS

### 7.1 Missing Datasource Overview Docs

These sub-docs exist but there's no top-level overview doc:
- [ ] `asa.md` — only `cisco_asa.md` exists (may be fine as-is)
- [ ] `aws.md` — sub-docs exist: aws_cloudtrail.md, aws_guardduty.md, aws_billing.md
- [ ] `gcp.md` — only gcp_audit.md exists
- [ ] `webex.md` — sub-docs exist: webex_ta.md, webex_api.md, webex_devices.md

### 7.2 Missing Scenario Dashboards

| Scenario | Dashboard | Status |
|----------|-----------|--------|
| exfil | scenario_exfil.xml | OK |
| memory_leak | scenario_memory_leak.xml | OK |
| cpu_runaway | scenario_cpu_runaway.xml | OK |
| disk_filling | scenario_disk_filling.xml | OK |
| ransomware_attempt | scenario_ransomware.xml | WARN (name mismatch) |
| firewall_misconfig | scenario_firewall_misconfig.xml | OK |
| certificate_expiry | scenario_certificate_expiry.xml | OK |
| phishing_test | ? | MISS |
| ddos_attack | ? | MISS |
| dead_letter_pricing | ? | MISS |

---

## 8. INGESTION AND TA VERIFICATION

Detailed in `docs/datasource_docs/REFERENCES.md`. Key items to verify:

### 8.1 Sourcetype Accuracy Notes

9 documented deviations between our sourcetypes and production TAs.
These are intentional simplifications but should be verified they don't break TA field extractions if real TAs are installed alongside.

| # | Our Sourcetype | Real TA Sourcetype | Risk |
|---|---------------|-------------------|------|
| 1 | FAKE:meraki:securityappliances | meraki | LOW — different stanza |
| 2 | FAKE:cisco:aci:fault | cisco:apic:fault | LOW — different stanza |
| 3 | FAKE:google:gcp:pubsub:audit:*:demo | google:gcp:pubsub:message | HIGH — :demo suffix mismatch |
| 4 | FAKE:azure:aad:signin | azure:aad:signin | LOW |
| 5 | FAKE:o365:reporting:messagetrace | ms:o365:reporting:messagetrace | LOW — prefix mismatch |
| 6 | FAKE:Perfmon:Processor etc. | Perfmon:Processor | LOW |
| 7 | FAKE:WinEventLog:Sysmon | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | MED — very different name |
| 8 | FAKE:cpu, FAKE:vmstat etc. | cpu, vmstat etc. | LOW |
| 9 | FAKE:servicenow:incident | snow:incident | LOW — different prefix |

---

## 9. ACTION ITEMS — Prioritized

### Priority 1: Critical Fixes

- [ ] **Fix eventtypes.conf** — Update all searches to use `index=fake_tshrt` and `FAKE:` sourcetype prefix
- [ ] **Fix tags.conf** — Ensure tags still map correctly after eventtype fix
- [ ] **Fix Entra ID user field** — Update EVAL-user in props.conf for FAKE:azure:aad:signin and FAKE:azure:aad:audit to use `'properties.userPrincipalName'` instead of `userPrincipalName`
- [ ] **Fix or remove sqlserver_host_dbserver_lookup** — Either create the CSV or remove the transforms.conf stanza

### Priority 2: High-Value Improvements

- [ ] **Verify GCP :demo suffix** — Check if props.conf field extractions actually apply to sourcetypes with `:demo` suffix
- [ ] **Add missing scenario eventtypes** — ransomware_attempt, phishing_test, ddos_attack, dead_letter_pricing, certificate_expiry
- [ ] **Add missing CIM eventtypes** — Email, DNS, Intrusion Detection, Endpoint, Performance, Ticket Management
- [ ] **Regenerate SAP data** — web_order_id field was added in code but Splunk data predates the fix
- [ ] **Fix ransomware naming** — Rename dashboard and doc from `ransomware` to `ransomware_attempt`

### Priority 3: Documentation and Polish

- [ ] **Update CLAUDE.md scenario table** — Several scenarios affect more sourcetypes than documented
- [ ] **Create 3 missing scenario dashboards** — phishing_test, ddos_attack, dead_letter_pricing
- [ ] **Clean up unreferenced lookup** — cisco_asa_messageid.csv
- [ ] **Verify all VERIFY items** in sections 3-6 above
- [ ] **Verify identity/asset/mac inventory lookups** — Check if they're referenced and populated correctly

### Priority 4: Stretch Goals

- [ ] Add `vendor_product` EVAL to all sourcetypes that lack it (cisco:ios, aci, sap, servicenow)
- [ ] Add CIM field aliases for Secure Access (DNS, Proxy, FW) sourcetypes
- [ ] Add CIM field aliases for Catalyst Center sourcetypes
- [ ] Verify Webex field extractions and CIM compliance
- [ ] Add servicenow:cmdb data generation (stanza exists but no data)

---

## 10. QUICK VERIFICATION QUERIES

Use these SPL queries to verify fixes after implementation:

```spl
-- Verify eventtypes work after fix
| eventcount summarize=false index=fake_tshrt | where count > 0

-- Check Entra ID user field after fix
index=fake_tshrt sourcetype="FAKE:azure:aad:signin" category="SignInLogs"
| stats count by user | head 10

-- Verify SAP web_order_id after regeneration
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=VA01
| stats dc(web_order_id) as uniq_orders, count

-- Validate all scenarios have events
index=fake_tshrt demo_id=* | stats count by demo_id

-- Check GCP field extraction works despite :demo suffix
index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:audit:admin_activity:demo"
| stats count(eval(isnotnull(user))) as has_user, count as total

-- Full CIM coverage check
| tstats count from datamodel=Authentication by sourcetype
| tstats count from datamodel=Network_Traffic by sourcetype
| tstats count from datamodel=Change by sourcetype
```
