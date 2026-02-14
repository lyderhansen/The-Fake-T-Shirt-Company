# Data Source Format References

Splunk Add-on references, ingestion methods, and sourcetype accuracy for every data source in this project. Use this to understand how each log type would be collected in a real Splunk deployment.

---

## Quick Reference

| Source | Splunk Add-on | Splunkbase | Ingestion Method | Our Sourcetype | Accurate? |
|--------|--------------|------------|------------------|----------------|-----------|
| **Network** |
| Cisco ASA | Splunk Add-on for Cisco ASA | [1620](https://splunkbase.splunk.com/app/1620) | Syslog / SC4S | `cisco:asa` | Exact |
| Cisco Meraki | Cisco Meraki Add-on for Splunk | [5580](https://splunkbase.splunk.com/app/5580) | REST API / Webhooks | `meraki:mx` etc. | See note 1 |
| Cisco Catalyst (IOS) | Cisco Catalyst Add-on for Splunk | [7538](https://splunkbase.splunk.com/app/7538) | Syslog / SC4S | `cisco:ios` | Exact |
| Cisco ACI | Cisco DC Networking | [7777](https://splunkbase.splunk.com/app/7777) | REST API (APIC) | `cisco:aci:*` | See note 2 |
| **Cloud & Identity** |
| AWS CloudTrail | Splunk Add-on for AWS | [1876](https://splunkbase.splunk.com/app/1876) | S3 + SQS polling | `aws:cloudtrail` | Exact |
| AWS GuardDuty | Splunk Add-on for AWS | [1876](https://splunkbase.splunk.com/app/1876) | EventBridge + Firehose | `aws:cloudwatch:guardduty` | Exact |
| AWS Billing CUR | Splunk Add-on for AWS | [1876](https://splunkbase.splunk.com/app/1876) | S3 polling | `aws:billing:cur` | Exact |
| GCP Audit Logs | Splunk Add-on for GCP | [3088](https://splunkbase.splunk.com/app/3088) | Pub/Sub subscription | `google:gcp:pubsub:message` | See note 3 |
| Entra ID | Splunk Add-on for MS Cloud Services | [3110](https://splunkbase.splunk.com/app/3110) | Azure Event Hubs | `azure:aad:signin/audit` | See note 4 |
| Exchange | Splunk Add-on for MS Office 365 | [4055](https://splunkbase.splunk.com/app/4055) | Office 365 API | `ms:o365:reporting:messagetrace` | See note 5 |
| Office 365 Audit | Splunk Add-on for MS Office 365 | [4055](https://splunkbase.splunk.com/app/4055) | Management Activity API | `o365:management:activity` | Exact |
| Cisco Secure Access | Cisco Secure Access Add-on | [7569](https://splunkbase.splunk.com/app/7569) | S3 bucket polling | `cisco:umbrella:*` | Exact |
| Catalyst Center | Cisco Catalyst Add-on for Splunk | [7538](https://splunkbase.splunk.com/app/7538) | REST API | `cisco:catalyst:*` | Exact |
| **Collaboration** |
| Webex Devices | (custom) | -- | Webex xAPI / webhooks | `cisco:webex:events` | Custom |
| Webex Meetings TA | Cisco WebEx Meetings Add-on | [GitHub](https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk) | Webex XML API (legacy) | `cisco:webex:meetings:history:*` | Exact |
| Webex REST API | Cisco Webex Add-on for Splunk | [GitHub](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk) | Webex REST API | `cisco:webex:*` | Partial |
| **Windows** |
| Perfmon | Splunk Add-on for MS Windows | [742](https://splunkbase.splunk.com/app/742) | Universal Forwarder | `perfmon` | See note 6 |
| WinEventLog | Splunk Add-on for MS Windows | [742](https://splunkbase.splunk.com/app/742) | Universal Forwarder | `XmlWinEventLog` | Exact |
| Sysmon | Splunk Add-on for Sysmon | [5709](https://splunkbase.splunk.com/app/5709) | Universal Forwarder | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | See note 7 |
| MSSQL | Splunk Add-on for MS SQL Server | [2648](https://splunkbase.splunk.com/app/2648) | File monitor + DB Connect | `mssql:errorlog` | Exact |
| **Linux** |
| Linux Metrics | Splunk Add-on for Unix and Linux | [833](https://splunkbase.splunk.com/app/833) | Universal Forwarder (scripted) | `linux:*` | See note 8 |
| **Web & Retail** |
| Apache Access | (Splunk built-in) | -- | Universal Forwarder (file monitor) | `access_combined` | Exact |
| Retail Orders | (custom) | -- | File monitor | `retail:orders` | Custom |
| Azure ServiceBus | (custom) | -- | Custom / Event Hubs | `azure:servicebus` | Custom |
| **ERP** |
| SAP S/4HANA | PowerConnect for SAP Solutions | [3153](https://splunkbase.splunk.com/app/3153) | SAP ABAP push / UF file monitor | `sap:auditlog` | Community |
| **ITSM** |
| ServiceNow | Splunk Add-on for ServiceNow | [1928](https://splunkbase.splunk.com/app/1928) | REST API polling | `servicenow:incident` | See note 9 |

---

## Sourcetype Accuracy Notes

Our project uses the `FAKE:` prefix for all sourcetypes at index time (e.g., `FAKE:cisco:asa`). The base sourcetype names are designed to match what real Splunk TAs produce, with some deliberate deviations documented below.

### Note 1: Cisco Meraki

**Our sourcetypes:** `meraki:mx`, `meraki:mr`, `meraki:ms`, `meraki:mv`, `meraki:mt`

**Real TA sourcetypes:**
- API-based: `meraki:securityappliances` (MX), `meraki:accesspoints` (MR), `meraki:switches` (MS), `meraki:cameras` (MV)
- Syslog-based: generic `meraki` (via SC4S or TA-meraki community add-on)
- No official MT (sensor) sourcetype exists

**Decision:** We use shorter device-type-based names for clarity in demos. The official names are longer and less intuitive for training purposes.

### Note 2: Cisco ACI

**Our sourcetypes:** `cisco:aci:fault`, `cisco:aci:event`, `cisco:aci:audit`

**Real TA sourcetypes:** `cisco:apic:health`, `cisco:apic:stats`, `cisco:apic:class`, `cisco:apic:authentication`

**Decision:** We use event-type-based naming (`fault/event/audit`) which maps more naturally to security operations use cases. The real TA uses data-category-based naming from the APIC API. The legacy [Cisco ACI Add-on](https://splunkbase.splunk.com/app/1897) (deprecated) and current [Cisco DC Networking](https://splunkbase.splunk.com/app/7777) app both use `cisco:apic:*`.

### Note 3: GCP Audit Logs

**Our sourcetype:** `google:gcp:pubsub:message`

**Real TA sourcetypes (v4.0.0+):**
- `google:gcp:pubsub:audit:admin_activity`
- `google:gcp:pubsub:audit:data_access`
- `google:gcp:pubsub:audit:system_event`
- `google:gcp:pubsub:audit:policy_denied`
- `google:gcp:pubsub:message` (catch-all for unclassified messages)

**Decision:** We use the generic `google:gcp:pubsub:message` which is valid but represents the catch-all type. In a real deployment with GCP TA v4.0.0+, audit logs are auto-classified into the more specific subtypes.

### Note 4: Microsoft Entra ID

**Our sourcetypes:** `azure:aad:signin`, `azure:aad:audit`

**Current recommended TA:** [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) uses `azure:monitor:aad` for all Entra ID data (sign-in and audit distinguished by `body.records.category` field).

**Legacy TA:** [Splunk Add-on for Microsoft Azure](https://splunkbase.splunk.com/app/3757) (deprecated) uses `azure:aad:signin` and `azure:aad:audit`.

**Decision:** We use the legacy (but widely recognized) sourcetype names. Splunk ES detections and many real-world deployments still reference `azure:aad:signin/audit`. These names are more descriptive for training.

### Note 5: Exchange Message Trace

**Our sourcetype:** `ms:o365:reporting:messagetrace`

**Current TA sourcetype:** `o365:reporting:messagetrace` (no `ms:` prefix)

**Decision:** Our `ms:` prefix comes from the older Microsoft Office 365 Reporting Add-on. The current [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) drops the prefix. Both are widely seen in real deployments.

### Note 6: Windows Perfmon

**Our sourcetype:** `perfmon`

**Real TA sourcetypes:** `Perfmon:CPU`, `Perfmon:Memory`, `Perfmon:LogicalDisk`, `Perfmon:Network`, `Perfmon:PhysicalDisk`, `Perfmon:Process`, etc.

**Decision:** We use a single generic `perfmon` sourcetype. The real TA subdivides by counter object. Our approach simplifies demos while preserving the counter/instance structure in the event data.

### Note 7: Microsoft Sysmon

**Our sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

**Current TA:** [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) uses `XmlWinEventLog` as sourcetype with `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` as the **source** field.

**Legacy TA:** [Splunk Add-on for Microsoft Sysmon](https://splunkbase.splunk.com/app/1914) (archived) used `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` as the sourcetype directly.

**Decision:** We follow the legacy convention which is more descriptive and still common in many deployments.

### Note 8: Linux Metrics

**Our sourcetypes:** `linux:cpu`, `linux:vmstat`, `linux:df`, `linux:iostat`, `linux:interfaces`, `linux:auth`

**Real TA sourcetypes:** `cpu`, `vmstat`, `df`, `iostat`, `interfaces`, `linux_secure`

**Decision:** We add a `linux:` prefix for namespace clarity in a multi-source demo environment. The real [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) uses shorter names without the prefix.

### Note 9: ServiceNow

**Our sourcetype:** `servicenow:incident`

**Real TA sourcetype:** `snow:incident` (and `snow:<table_name>` for other tables)

**Decision:** We use a more descriptive `servicenow:` prefix. The real [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) uses the abbreviated `snow:` prefix.

---

## Detailed References by Category

### Network

#### Cisco ASA

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Cisco ASA](https://splunkbase.splunk.com/app/1620) (v6.0.0) |
| **Splunk Docs** | [Configure inputs for Cisco ASA](https://docs.splunk.com/Documentation/AddOns/released/CiscoASA/Inputs) |
| **SC4S** | [Splunk Connect for Syslog - Cisco](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/) |
| **Cisco Docs** | [ASA Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html) |

**Sourcetype:** `cisco:asa` | **Ingestion:** Syslog (UDP/TCP) to Splunk or SC4S

**Key Message Codes:**
- `%ASA-6-302013/302014` - TCP connection built/teardown
- `%ASA-4-106023` - Packet denied by ACL
- `%ASA-4-733100` - Threat detection triggered

---

#### Cisco Meraki

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) (v3.2.0) |
| **SC4S** | [SC4S - Cisco Meraki](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/cisco_meraki/) |
| **Meraki Docs** | [Meraki Add-on for Splunk](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Add-on_for_Splunk) |
| **Meraki API** | [Dashboard API v1](https://developer.cisco.com/meraki/api-v1/) |

**Sourcetypes:** `meraki:securityappliances`, `meraki:accesspoints`, `meraki:switches`, `meraki:cameras`, `meraki:webhook`

**Ingestion:** REST API polling (device/network data) + Webhooks via HEC (alerts). Syslog via SC4S for traditional syslog.

#### MR Wireless Health API Endpoints

| Event Type | API Endpoint |
|------------|--------------|
| `ap_health_score` | [Device Wireless Health Scores](https://developer.cisco.com/meraki/api-v1/get-device-wireless-health-scores/) |
| `signal_quality` | [Network Wireless Signal Quality History](https://developer.cisco.com/meraki/api-v1/get-network-wireless-signal-quality-history/) |
| `channel_utilization` | [Network Wireless Channel Utilization History](https://developer.cisco.com/meraki/api-v1/get-network-wireless-channel-utilization-history/) |
| `latency_stats` | [Device Wireless Latency Stats](https://developer.cisco.com/meraki/api-v1/get-device-wireless-latency-stats/) |
| `client_health_score` | [Network Wireless Client Health Scores](https://developer.cisco.com/meraki/api-v1/get-network-wireless-client-health-scores/) |
| `health_alert` | [Network Health Alerts](https://developer.cisco.com/meraki/api-v1/get-network-health-alerts/) |

---

#### Cisco Catalyst Switches (IOS/IOS-XE)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Catalyst Add-on for Splunk](https://splunkbase.splunk.com/app/7538) (v3.0.0) |
| **Legacy TA** | [Cisco Networks Add-on (TA-cisco_ios)](https://splunkbase.splunk.com/app/1467) (deprecated) |
| **SC4S** | [SC4S - Cisco IOS](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/) |

**Sourcetype:** `cisco:ios` | **Ingestion:** Syslog (UDP/TCP) to Splunk or SC4S

---

#### Cisco ACI

| Resource | Link |
|----------|------|
| **Splunk App** | [Cisco DC Networking](https://splunkbase.splunk.com/app/7777) (v1.2.0) |
| **Legacy TA** | [Cisco ACI Add-on](https://splunkbase.splunk.com/app/1897) (deprecated) |

**Sourcetypes (real):** `cisco:apic:health`, `cisco:apic:stats`, `cisco:apic:class`, `cisco:apic:authentication`

**Ingestion:** REST API polling from APIC controller via modular inputs

---

### Cloud & Identity

#### AWS CloudTrail

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) (v8.1.0) |
| **GitHub Docs** | [CloudTrail Input](https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudTrail/) |
| **AWS Docs** | [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html) |

**Sourcetype:** `aws:cloudtrail` | **Ingestion:** S3 bucket polling via SQS notifications, or Kinesis Firehose push to HEC

---

#### AWS GuardDuty

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) (v8.1.0) |
| **GitHub Docs** | [AWS Data Types](https://splunk.github.io/splunk-add-on-for-amazon-web-services/DataTypes/) |

**Sourcetypes:**
- `aws:cloudwatch:guardduty` (push via EventBridge + Firehose -- our choice)
- `aws:cloudwatchlogs:guardduty` (pull via CloudWatch Logs)

**Ingestion:** EventBridge rule catches GuardDuty findings, routes to Kinesis Firehose, pushes to Splunk HEC

---

#### AWS Billing (Cost & Usage Report)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) (v8.1.0) |
| **GitHub Docs** | [Billing CUR Input](https://splunk.github.io/splunk-add-on-for-amazon-web-services/BillingCostandUsage/) |

**Sourcetype:** `aws:billing:cur` | **Ingestion:** S3 polling of CUR files delivered by AWS

---

#### GCP Audit Logs

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for GCP](https://splunkbase.splunk.com/app/3088) (v5.0.1) |
| **GitHub Docs** | [GCP Sourcetypes](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |
| **Google Docs** | [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) |

**Sourcetype:** `google:gcp:pubsub:message` (catch-all; v4.0.0+ auto-classifies into `google:gcp:pubsub:audit:*`)

**Ingestion:** GCP Cloud Logging exports to Pub/Sub topic via log sink; Splunk add-on pulls from Pub/Sub subscription

---

#### Microsoft Entra ID (Azure AD)

| Resource | Link |
|----------|------|
| **Current TA** | [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) (v6.1.0) |
| **Legacy TA** | [Splunk Add-on for Microsoft Azure](https://splunkbase.splunk.com/app/3757) (deprecated) |
| **Microsoft Docs** | [Sign-in log schema](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema) |

**Sourcetypes:**
- Current: `azure:monitor:aad` (via Event Hubs)
- Legacy: `azure:aad:signin`, `azure:aad:audit` (via Graph API -- our choice)

**Ingestion:** Azure Event Hubs (recommended) or Microsoft Graph API (legacy)

---

#### Exchange (Message Trace)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) (v5.1.0) |
| **GitHub Docs** | [Message Trace Input](https://splunk.github.io/splunk-add-on-for-microsoft-office-365/ConfigureMessageTraceInput/) |

**Sourcetype:** `o365:reporting:messagetrace` (current TA) / `ms:o365:reporting:messagetrace` (legacy -- our choice)

**Ingestion:** Office 365 Message Trace Report API polling

**Limitation:** API returns max 7 days of data

---

#### Office 365 Unified Audit Log

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) (v5.1.0) |
| **GitHub Docs** | [Management Activity Input](https://splunk.github.io/splunk-add-on-for-microsoft-office-365/) |

**Sourcetype:** `o365:management:activity` | **Ingestion:** Office 365 Management Activity API polling

---

#### Cisco Secure Access (Umbrella)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Secure Access Add-on for Splunk](https://splunkbase.splunk.com/app/7569) (v1.0.48) |
| **Cisco DevNet** | [Cloud Security Add-on Docs](https://developer.cisco.com/docs/cloud-security/cisco-cloud-security-add-on-for-splunk/) |

**Sourcetypes:** `cisco:umbrella:dns`, `cisco:umbrella:proxy`, `cisco:umbrella:firewall`, `cisco:umbrella:audit`

**Ingestion:** S3 bucket polling (Umbrella/Secure Access exports logs to AWS S3)

---

#### Cisco Catalyst Center

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Catalyst Add-on for Splunk](https://splunkbase.splunk.com/app/7538) (same add-on as Catalyst switches -- includes Catalyst Center inputs) |

**Sourcetypes:** `cisco:catalyst:devicehealth`, `cisco:catalyst:networkhealth`, `cisco:catalyst:clienthealth`, `cisco:catalyst:issue` (+ `cisco:catalyst:client`, `cisco:catalyst:compliance`, `cisco:catalyst:securityadvisory`)

**Ingestion:** REST API polling from Catalyst Center API

---

### Collaboration

#### Webex Room Devices

No dedicated Splunk TA for Webex device telemetry (xAPI events).

**Our sourcetype:** `cisco:webex:events` (custom)

**Real-world options:**
- Webex Control Hub can export device analytics
- Custom webhook/xAPI integration to HEC
- [Cisco Webex Add-on for Splunk](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk) covers meetings/calls but not device telemetry

---

#### Webex Meetings TA (XML API)

| Resource | Link |
|----------|------|
| **GitHub** | [ta-cisco-webex-meetings-add-on-for-splunk](https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk) |

**Sourcetypes:** `cisco:webex:meetings:history:meetingusagehistory`, `...meetingattendeehistory`, etc.

**Ingestion:** Webex Meetings XML API (legacy, deprecated by Cisco)

---

#### Webex REST API

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Webex Add-on for Splunk](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk) |
| **Webex Developer** | [Webex REST API](https://developer.webex.com/) |

**Sourcetypes:** `cisco:webex:meetings`, `cisco:webex:admin:audit:events`, `cisco:webex:security:audit:events`, `cisco:webex:meeting:qualities`, `cisco:webex:call:detailed_history`

**Ingestion:** Webex REST API polling

---

### Windows

#### Windows Performance Monitor (Perfmon)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) (v9.1.2) |
| **GitHub Docs** | [Splunk Add-on for Microsoft Windows](https://splunk.github.io/splunk-add-on-for-microsoft-windows/) |

**Sourcetype (real):** `Perfmon:CPU`, `Perfmon:Memory`, `Perfmon:LogicalDisk`, etc. (one per counter object)

**Ingestion:** Universal Forwarder with `[perfmon://...]` input stanzas. Use `useEnglishOnly=true` for ES compatibility.

---

#### Windows Event Log

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) (v9.1.2) |
| **Splunk Docs** | [Monitor Windows Event Log data](https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/MonitorWindowseventlogdata) |

**Sourcetypes:** `WinEventLog` (classic) / `XmlWinEventLog` (XML, default since TA v6.0.0)

**Ingestion:** Universal Forwarder with `[WinEventLog://Security]` etc., `renderXml=true` for XML mode

---

#### Microsoft Sysmon

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) (v5.0.0) |
| **Legacy TA** | [Splunk Add-on for Microsoft Sysmon](https://splunkbase.splunk.com/app/1914) (archived) |

**Ingestion:** Universal Forwarder monitoring `Microsoft-Windows-Sysmon/Operational` channel with `renderXml=true`

**Dependencies:** Microsoft Sysmon installed on endpoint + Splunk Add-on for Microsoft Windows (App 742)

---

#### Microsoft SQL Server

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft SQL Server](https://splunkbase.splunk.com/app/2648) (v3.1.0) |

**Sourcetypes:** `mssql:errorlog` (file monitor), `mssql:agentlog`, `mssql:audit` (DB Connect), `mssql:trclog` (DB Connect)

**Ingestion:** File monitoring for error/agent logs + Splunk DB Connect for audit/trace data

---

### Linux

#### Linux System Metrics

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Unix and Linux](https://splunkbase.splunk.com/app/833) (v10.2.0) |
| **GitHub Docs** | [Sourcetypes](https://splunk.github.io/splunk-add-on-for-unix-and-linux/Sourcetypes/) |

**Sourcetypes (real):** `cpu`, `vmstat`, `df`, `iostat`, `interfaces`, `linux_secure` (no prefix)

**Ingestion:** Universal Forwarder with scripted inputs executing system commands on schedule

---

### Web & Retail

#### Apache Access Logs

**Sourcetype:** `access_combined` (Splunk built-in pretrained sourcetype, no TA required)

**Alternative TA:** [Splunk Add-on for Apache Web Server](https://splunkbase.splunk.com/app/3186) uses `apache:access:combined`

**Ingestion:** Universal Forwarder monitoring Apache log files

**Reference:** [Apache Log Files](https://httpd.apache.org/docs/current/logs.html)

---

#### Retail Orders

Custom JSON format for fictional e-commerce orders. No real-world equivalent.

**Sourcetype:** `retail:orders` (custom) | **Ingestion:** File monitor

---

#### Azure ServiceBus

Custom JSON format for ServiceBus dead-letter/message data. No dedicated Splunk TA exists.

**Sourcetype:** `azure:servicebus` (custom) | **Ingestion:** Custom integration (Azure Functions to HEC, or Event Hubs via [MS Cloud Services Add-on](https://splunkbase.splunk.com/app/3110))

---

### ERP

#### SAP S/4HANA Audit Log

| Resource | Link |
|----------|------|
| **Commercial TA** | [PowerConnect for SAP Solutions](https://splunkbase.splunk.com/app/3153) (v9.0.1, by SoftwareOne) |
| **Community Guide** | [WALLSEC/SAPtoSPLUNK](https://github.com/WALLSEC/SAPtoSPLUNK) |

**Sourcetype:** `sap:auditlog` (community convention)

**Ingestion options:**
- **PowerConnect** (commercial): SAP-side ABAP add-on pushes data to Splunk
- **Custom/UF** (free): Universal Forwarder monitors SAP Security Audit Log files in `/SAL` directory

**Note:** SAP audit logs are UTF-16LE encoded with 200-char fixed-width records. Custom `props.conf` required for proper parsing.

---

### ITSM

#### ServiceNow

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) (v9.2.1) |
| **GitHub Docs** | [ServiceNow Datatypes](https://splunk.github.io/splunk-add-on-for-servicenow/Datatypes/) |

**Sourcetype (real):** `snow:incident` (schema: `snow:<table_name>`)

**Ingestion:** Modular input polling ServiceNow REST Table API

---

## Ingestion Architecture Summary

```
                    Real-World Ingestion Methods
                    ============================

  [Syslog Sources]           [API Sources]              [File Sources]
  ASA, Catalyst, Meraki      AWS, GCP, Azure,           Perfmon, WinEventLog,
                             O365, ServiceNow,          Sysmon, MSSQL, Linux,
                             Catalyst Center,           Apache, SAP
                             Secure Access, Webex
        |                          |                          |
        v                          v                          v
  +----------+            +--------------+           +------------------+
  | SC4S /   |            | Splunk HF    |           | Universal        |
  | Syslog   |            | (Heavy Fwd)  |           | Forwarder (UF)   |
  | Server   |            | Modular      |           | on endpoint      |
  +----------+            | Inputs       |           +------------------+
        |                 +--------------+                    |
        |                        |                            |
        +------------------------+----------------------------+
                                 |
                                 v
                        +----------------+
                        | Splunk Indexer  |
                        | index=fake_tshrt|
                        +----------------+
```
