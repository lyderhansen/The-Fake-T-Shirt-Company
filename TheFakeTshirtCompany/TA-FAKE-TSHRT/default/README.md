# default/ — Splunk Configuration

This directory contains all Splunk configuration files that tell Splunk how to ingest,
parse, and classify the generated log data.

## How It Works

```
  Generated log files                Splunk picks them up              Splunk parses and indexes
  (bin/output/)                      (inputs.conf)                     (props.conf + transforms.conf)

  output/network/cisco_asa.log  ──►  [monitor://...cisco_asa.log]  ──►  [FAKE:cisco:asa]
  output/cloud/aws_cloudtrail.json   sourcetype = FAKE:cisco:asa       TIME_FORMAT, KV_MODE,
  output/windows/perfmon_*.log       index = fake_tshrt                FIELDALIAS, EVAL, LOOKUP
  ...                                                                  ...
```

All sourcetypes use the `FAKE:` prefix to avoid conflicts with production data or
installed Technology Add-ons.

## Configuration Files

| File | Purpose |
|------|---------|
| **`app.conf`** | App identity — name, version (1.0.0), visibility |
| **`inputs.conf`** | 37 monitor stanzas — one per log file, all to `fake_tshrt` index |
| **`props.conf`** | 46 sourcetype definitions — timestamp parsing, field extraction, CIM mappings |
| **`transforms.conf`** | 28 transforms — host extraction, field extraction, sourcetype routing, lookups |
| **`eventtypes.conf`** | 15 event types — scenario filters, source groups, CIM-aligned categories |
| **`tags.conf`** | CIM tags — maps event types to data model tags (authentication, network, etc.) |
| **`restmap.conf`** | 2 REST endpoints — log generation and index management from Splunk Web |
| **`web.conf`** | Exposes REST endpoints to Splunk Web (port 8000) |
| **`data/ui/views/`** | Dashboard XML files |

---

## Sourcetypes and Inspiration

Every sourcetype is modeled after a real Splunk Technology Add-on. The field extractions,
aliases, and CIM mappings are designed to be compatible so dashboards and searches work
the same way they would with production data.

### Cloud Security

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:aws:cloudtrail` | JSON | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) | [AWS CloudTrail docs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/) |
| `FAKE:azure:aad:signin` | JSON | [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) | [Entra ID sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins) |
| `FAKE:azure:aad:audit` | JSON | [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) | [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) |
| `FAKE:azure:aad:riskDetection` | JSON | [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) | [Entra ID risk detections](https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks) |
| `FAKE:google:gcp:pubsub:audit` | JSON | [Splunk Add-on for Google Cloud Platform](https://splunkbase.splunk.com/app/3088) | [GCP Audit Logs](https://cloud.google.com/logging/docs/audit) |
| `FAKE:google:gcp:pubsub:audit:admin_activity` | JSON | [Splunk Add-on for Google Cloud Platform](https://splunkbase.splunk.com/app/3088) | [GCP Admin Activity](https://cloud.google.com/logging/docs/audit#admin-activity) |
| `FAKE:google:gcp:pubsub:audit:data_access` | JSON | [Splunk Add-on for Google Cloud Platform](https://splunkbase.splunk.com/app/3088) | [GCP Data Access](https://cloud.google.com/logging/docs/audit#data-access) |

### Email / Microsoft 365

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:o365:reporting:messagetrace` | JSON | [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) | [Message Trace API](https://learn.microsoft.com/en-us/previous-versions/office/developer/o365-enterprise-developers/jj984335(v=office.15)) |
| `FAKE:o365:management:activity` | JSON | [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) | [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference) |

### Network Security

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:cisco:asa` | Syslog | [Splunk Add-on for Cisco ASA](https://splunkbase.splunk.com/app/1620) | [Cisco ASA Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html) |
| `FAKE:meraki:securityappliances` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki Dashboard API](https://developer.cisco.com/meraki/api-latest/) |
| `FAKE:meraki:accesspoints` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki Wireless docs](https://documentation.meraki.com/MR) |
| `FAKE:meraki:switches` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki Switches docs](https://documentation.meraki.com/MS) |
| `FAKE:meraki:cameras` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki Smart Cameras docs](https://documentation.meraki.com/MV) |
| `FAKE:meraki:sensors` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki Sensors docs](https://documentation.meraki.com/MT) |
| `FAKE:meraki:accesspoints:health` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki MR Health API](https://developer.cisco.com/meraki/api-latest/) |
| `FAKE:meraki:switches:health` | JSON | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) | [Meraki MS Health API](https://developer.cisco.com/meraki/api-latest/) |

### Windows / Endpoint

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:WinEventLog` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Windows Event Log reference](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference) |
| `FAKE:Perfmon:Generic` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Performance Counters](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:Perfmon:Processor` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Processor object](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:Perfmon:Memory` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Memory object](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:Perfmon:LogicalDisk` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [LogicalDisk object](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:Perfmon:Network_Interface` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Network Interface object](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:PerfmonMk:Processor` | KV pairs | [Splunk Add-on for Windows](https://splunkbase.splunk.com/app/742) | [Performance Counters](https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-portal) |
| `FAKE:WinEventLog:Sysmon` | KV pairs | [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) | [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |
| `FAKE:mssql:errorlog` | Text | [Splunk Add-on for Microsoft SQL Server](https://splunkbase.splunk.com/app/2648) | [SQL Server Error Log](https://learn.microsoft.com/en-us/sql/relational-databases/performance/view-the-sql-server-error-log-sql-server-management-studio) |

### Linux

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:cpu` | KV pairs | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) | [sar(1) man page](https://man7.org/linux/man-pages/man1/sar.1.html) |
| `FAKE:vmstat` | KV pairs | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) | [vmstat(8) man page](https://man7.org/linux/man-pages/man8/vmstat.8.html) |
| `FAKE:df` | KV pairs | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) | [df(1) man page](https://man7.org/linux/man-pages/man1/df.1.html) |
| `FAKE:iostat` | KV pairs | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) | [iostat(1) man page](https://man7.org/linux/man-pages/man1/iostat.1.html) |
| `FAKE:interfaces` | KV pairs | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) | [/proc/net/dev](https://man7.org/linux/man-pages/man5/proc.5.html) |

### Web / Retail

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:access_combined` | Apache Combined | [Splunk Add-on for Apache Web Server](https://splunkbase.splunk.com/app/3186) | [Apache Log Format](https://httpd.apache.org/docs/current/logs.html#combined) |
| `FAKE:online:order` | JSON | Custom | Internal order management system |
| `FAKE:online:order:registry` | JSON | Custom | Internal order-to-session linking |
| `FAKE:azure:servicebus` | JSON | [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) | [Azure Service Bus docs](https://learn.microsoft.com/en-us/azure/service-bus-messaging/) |

### Collaboration (Cisco Webex)

Two Splunk add-ons are used as inspiration — one for the REST API sourcetypes and one for
the older XML API (meetings history):

- [Webex Add-on for Splunk](https://splunkbase.splunk.com/app/8365) (REST API) — [GitHub](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk)
- [Cisco WebEx Meetings App for Splunk](https://splunkbase.splunk.com/app/4992) (XML API) — [GitHub](https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk)

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:cisco:webex:events` | JSON | Webex Add-on (REST API) | [Webex Events API](https://developer.webex.com/docs/api/v1/events) |
| `FAKE:cisco:webex:meetings` | JSON | Webex Add-on (REST API) | [Webex Meetings API](https://developer.webex.com/docs/api/v1/meetings) |
| `FAKE:cisco:webex:admin:audit:events` | JSON | Webex Add-on (REST API) | [Webex Admin Audit API](https://developer.webex.com/docs/api/v1/admin-audit-events) |
| `FAKE:cisco:webex:security:audit:events` | JSON | Webex Add-on (REST API) | [Webex Security Audit API](https://developer.webex.com/docs/api/v1/security-audit-events) |
| `FAKE:cisco:webex:meeting:qualities` | JSON | Webex Add-on (REST API) | [Webex Meeting Qualities API](https://developer.webex.com/docs/api/v1/meeting-qualities) |
| `FAKE:cisco:webex:call:detailed_history` | JSON | Webex Add-on (REST API) | [Webex Call History API](https://developer.webex.com/docs/api/v1/call-history) |
| `FAKE:cisco:webex:meetings:history:meetingusagehistory` | JSON | WebEx Meetings App (XML API) | [Webex Meetings XML API](https://developer.cisco.com/site/webex-developer/web-conferencing/xml-api/overview/) |
| `FAKE:cisco:webex:meetings:history:meetingattendeehistory` | JSON | WebEx Meetings App (XML API) | [Webex Meetings XML API](https://developer.cisco.com/site/webex-developer/web-conferencing/xml-api/overview/) |

### ITSM (ServiceNow)

| Sourcetype | Format | Inspired By | Vendor Docs |
|------------|--------|-------------|-------------|
| `FAKE:servicenow:incident` | KV pairs | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) | [ServiceNow Incident API](https://developer.servicenow.com/dev.do#!/reference/api/vancouver/rest/c_TableAPI) |
| `FAKE:servicenow:cmdb` | KV pairs | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) | [ServiceNow CMDB API](https://developer.servicenow.com/dev.do#!/reference/api/vancouver/rest/cmdb-api) |
| `FAKE:servicenow:change` | KV pairs | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) | [ServiceNow Change Management](https://docs.servicenow.com/bundle/vancouver-it-service-management/page/product/change-management/concept/c_ITILChangeManagement.html) |

---

## Key Fields

All generators tag scenario events with `demo_id` for easy filtering in Splunk:

```spl
index=fake_tshrt demo_id=exfil | stats count by sourcetype
index=fake_tshrt demo_id=ransomware_attempt | stats count by sourcetype
```

### CIM Field Mappings

Every sourcetype includes field aliases and calculated fields that map to Splunk's
Common Information Model (CIM):

| CIM Field | Used In | Example Mapping |
|-----------|---------|-----------------|
| `user` | All auth/cloud sources | `userIdentity.userName AS user` (CloudTrail) |
| `src` | Network, cloud, email | `sourceIPAddress AS src` (CloudTrail) |
| `dest` | Network, endpoint | `host AS dest` (Perfmon) |
| `action` | All sources | `eventName AS action` (CloudTrail) |
| `vendor_product` | All sources | `EVAL-vendor_product = "Cisco ASA"` |
| `process` | Endpoint | `Image AS process` (Sysmon) |
| `signature_id` | ASA, WinEventLog, Sysmon | `EventID AS signature_id` |

---

## Host Extraction

Most sourcetypes extract the `host` field from inside the log data using transforms:

| Transform | Used By | Extracts From |
|-----------|---------|---------------|
| `set_host_from_asa_syslog_fake` | Cisco ASA | Hostname after syslog header |
| `set_host_from_wineventlog` | WinEventLog | `ComputerName=` field |
| `set_host_from_sysmon` | Sysmon | `<Computer>` XML element |
| `host_from_demo_field` | Perfmon | `demo_host=` field |
| `set_host_from_linux_fake` | Linux metrics | `host=` field after timestamp |
| `set_host_from_gcp_project` | GCP | `project_id` JSON field |
| `set_meraki_host_from_devicename` | All Meraki types | `deviceName` JSON field |

---

## Sourcetype Routing

Some inputs need dynamic sourcetype assignment based on event content:

**Perfmon** — A single `FAKE:Perfmon:Generic` input routes to specific sourcetypes:

| Transform | Regex Match | Routed Sourcetype |
|-----------|-------------|-------------------|
| `FAKE_st_perfmon_network_interface` | `object=Network` | `FAKE:Perfmon:Network_Interface` |
| `FAKE_st_perfmon_generic_object` | `object=(LogicalDisk\|Memory\|Processor)` | `FAKE:Perfmon:$1` |

**GCP** — A base `FAKE:google:gcp:pubsub:audit` input routes to specific sourcetypes:

| Transform | LogName Contains | Routed Sourcetype |
|-----------|-----------------|-------------------|
| `gcp_pubsub_activity_sourcetype_demo` | `cloudaudit.googleapis.com%2Factivity` | `FAKE:google:gcp:pubsub:audit:admin_activity` |
| `gcp_pubsub_data_access_sourcetype_demo` | `cloudaudit.googleapis.com%2Fdata_access` | `FAKE:google:gcp:pubsub:audit:data_access` |

---

## Lookup Tables

Lookups enrich events with additional fields at search time:

| Lookup | File | Used By |
|--------|------|---------|
| `cisco_asa_action_lookup` | `cisco_asa_action_lookup.csv` | ASA — maps vendor_action/message_id to CIM action |
| `cisco_asa_change_analysis_lookup` | `cisco_asa_change_analysis_lookup.csv` | ASA — change analysis by message_id |
| `cisco_asa_severity_lookup` | `cisco_asa_severity_lookup.csv` | ASA — severity by signature_id |
| `cisco_asa_syslog_severity_lookup` | `cisco_asa_syslog_severity_lookup.csv` | ASA — severity by log_level |
| `cisco_asa_vendor_class_lookup` | `cisco_asa_vendor_class_lookup.csv` | ASA — vendor class by message_id |
| `cisco_asa_protocol_version` | `cisco_asa_protocol_version.csv` | ASA — protocol version mapping |
| `windows_severity_lookup` | `windows_severity_lookup.csv` | WinEventLog — severity by event Type |
| `windows_signature_lookup` | `windows_signature_lookup.csv` | WinEventLog — signature, action, result by ID |
| `splunk_ta_o365_cim_messagetrace_action` | `splunk_ta_o365_cim_messagetrace_action.csv` | Exchange — action by Status |
| `customer_lookup` | `customer_lookup.csv` | Retail — customer enrichment |

---

## Event Types and Tags

Event types group sourcetypes into logical categories. Tags map these to CIM data models.

### Scenario Event Types

| Event Type | Search | Tags |
|------------|--------|------|
| `demo_scenario_exfil` | `demo_id=exfil` | attack, exfiltration, apt |
| `demo_scenario_memory_leak` | `demo_id=memory_leak` | performance, operations |
| `demo_scenario_cpu_runaway` | `demo_id=cpu_runaway` | performance, operations |
| `demo_scenario_disk_filling` | `demo_id=disk_filling` | performance, operations |
| `demo_scenario_firewall_misconfig` | `demo_id=firewall_misconfig` | misconfiguration, network |

### CIM Event Types

| Event Type | Maps To | Tags |
|------------|---------|------|
| `demo_authentication` | Entra ID sign-in, WinEventLog 4624/4625 | authentication |
| `demo_network_traffic` | Cisco ASA, Meraki MX | network, communicate |
| `demo_change` | Entra ID audit, CloudTrail, GCP | change |
| `demo_malware` | ASA IDS/IPS events | malware, attack |
| `demo_web` | Apache access logs | web |

---

## REST Endpoints

Two REST endpoints allow log management from the Splunk Web dashboard:

| Endpoint | Handler | Purpose |
|----------|---------|---------|
| `/services/ta_fake_tshrt/generate` | `generate_logs.py` | Generate demo logs (POST with params for sources, days, scenarios) |
| `/services/ta_fake_tshrt/delete` | `delete_index.py` | Delete and recreate the `fake_tshrt` index |

Both use `PersistentServerConnectionApplication` and require authentication.
`web.conf` exposes them to Splunk Web (port 8000) so dashboards can call them via AJAX.

---

## Adding a New Sourcetype

1. Add a monitor stanza in `inputs.conf`
2. Define the sourcetype in `props.conf` with:
   - Timestamp parsing (`TIME_FORMAT`, `TIME_PREFIX`)
   - Field extraction (`KV_MODE`, `REPORT-`, `FIELDALIAS-`, `EVAL-`)
   - Host extraction (`TRANSFORMS-set_host`)
3. Add any required transforms in `transforms.conf`
4. Add event types in `eventtypes.conf` if needed
5. Add CIM tags in `tags.conf` if needed
6. Place lookup CSV files in `lookups/`
