# Data Source Format References

This document tracks the source documentation used to create each log generator, with links to official Splunk Add-ons and vendor API documentation.

---

## Reference Status Summary

| Source | Splunk Add-on | Vendor API | Status |
|--------|--------------|------------|--------|
| Cisco ASA | ✅ | ✅ | Documented |
| Meraki | ✅ | ✅ | Documented |
| AWS CloudTrail | ✅ | ✅ | Documented |
| GCP Audit | ✅ | ✅ | Documented |
| Microsoft Entra ID | ✅ | ✅ | Documented |
| Exchange | ✅ | ✅ | Documented |
| Webex Meetings TA | ✅ | ✅ | Documented |
| Webex REST API | ✅ | ✅ | Documented |
| Windows Perfmon | ✅ | N/A | Documented |
| Windows Event Log | ✅ | N/A | Documented |
| Linux Metrics | N/A | N/A | Standard format |
| Apache Access | N/A | N/A | Standard format |
| Retail Orders | N/A | N/A | Custom (fictional) |
| Azure ServiceBus | ❌ | ❌ | Not documented |
| ServiceNow | ✅ | ✅ | Documented |

---

## Network

### Cisco ASA

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Cisco ASA](https://splunkbase.splunk.com/app/1620) |
| **Splunk Docs** | [Configure inputs for Cisco ASA](https://docs.splunk.com/Documentation/AddOns/released/CiscoASA/Inputs) |
| **SC4S** | [Splunk Connect for Syslog - Cisco](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/) |
| **Cisco Docs** | [ASA Syslog Messages](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html) |
| **Cisco Setup** | [Configure ASA Syslog](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/63884-config-asa-00.html) |

**Sourcetype:** `cisco:asa`

**Key Message Codes:**
- `%ASA-6-302013` - TCP connection built (outbound)
- `%ASA-6-302014` - TCP connection teardown
- `%ASA-4-106023` - Packet denied by ACL
- `%ASA-4-733100` - Threat detection triggered

---

### Cisco Meraki

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Meraki Add-on for Splunk](https://splunkbase.splunk.com/app/5580) |
| **Splunk Docs** | [Splunk Add-on for Cisco Meraki](https://docs.splunk.com/Documentation/AddOns/released/Meraki/Sourcetypes) |
| **SC4S** | [Splunk Connect for Syslog - Cisco Meraki](https://splunk.github.io/splunk-connect-for-syslog/main/sources/vendor/Cisco/cisco_meraki/) |
| **Meraki Docs** | [Cisco Meraki Add-on for Splunk](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Add-on_for_Splunk) |
| **Meraki API** | [Meraki Dashboard API](https://developer.cisco.com/meraki/api-v1/) |

**Sourcetypes:** `meraki`, `meraki:webhook`, `cisco:meraki:*`

#### MR Wireless Health Events (API References)

| Event Type | API Endpoint |
|------------|--------------|
| `ap_health_score` | [Device Wireless Health Scores](https://developer.cisco.com/meraki/api-v1/get-device-wireless-health-scores/) |
| `signal_quality` | [Network Wireless Signal Quality History](https://developer.cisco.com/meraki/api-v1/get-network-wireless-signal-quality-history/) |
| `channel_utilization` | [Network Wireless Channel Utilization History](https://developer.cisco.com/meraki/api-v1/get-network-wireless-channel-utilization-history/) |
| `latency_stats` | [Device Wireless Latency Stats](https://developer.cisco.com/meraki/api-v1/get-device-wireless-latency-stats/) |
| `client_health_score` | [Network Wireless Client Health Scores](https://developer.cisco.com/meraki/api-v1/get-network-wireless-client-health-scores/) |
| `health_alert` | [Network Health Alerts](https://developer.cisco.com/meraki/api-v1/get-network-health-alerts/) |
| `application_health` | [Network Insight Application Health By Time](https://developer.cisco.com/meraki/api-v1/get-network-insight-application-health-by-time/) |

**KPI Thresholds** (from [Meraki Best Practices](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Monitoring_and_Reporting/Meraki_Health_Overview)):
- SNR: >27 dB good, 20-27 dB fair, <20 dB poor
- RSSI: >-50 dBm good, -50 to -70 dBm fair, <-70 dBm poor
- Latency: <30 ms good, 30-60 ms fair, >60 ms poor

---

## Cloud & Identity

### AWS CloudTrail

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) |
| **Splunk Docs** | [Configure CloudTrail inputs](https://docs.splunk.com/Documentation/AddOns/released/AWS/CloudTrail) |
| **Source Types** | [AWS Source Types](https://docs.splunk.com/Documentation/AddOns/released/AWS/DataTypes) |
| **GitHub Docs** | [Splunk Add-on for AWS - CloudTrail](https://splunk.github.io/splunk-add-on-for-amazon-web-services/CloudTrail/) |
| **AWS Docs** | [CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html) |
| **Splunk Lantern** | [Onboarding AWS CloudTrail data](https://lantern.splunk.com/Data_Sources/Amazon/Onboarding_AWS_CloudTrail_data) |

**Sourcetype:** `aws:cloudtrail`

---

### GCP Audit Logs

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Google Cloud Platform](https://splunkbase.splunk.com/app/3088) |
| **Splunk Docs** | [GCP Source Types](https://docs.splunk.com/Documentation/AddOns/released/GoogleCloud/Sourcetypes) |
| **GitHub Docs** | [Splunk Add-on for GCP - Sourcetypes](https://splunk.github.io/splunk-add-on-for-google-cloud-platform/Sourcetypes/) |
| **Google Docs** | [Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) |
| **Splunk Blog** | [Getting to Know Google Cloud Audit Logs](https://www.splunk.com/en_us/blog/partners/getting-to-know-google-cloud-audit-logs.html) |

**Sourcetype:** `google:gcp:pubsub:message`

**Note:** Version 4.0.0+ has improved sourcetyping with more granular types like `google:gcp:pubsub:audit:auth`.

---

### Microsoft Entra ID (Azure AD)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Azure](https://splunkbase.splunk.com/app/3757) |
| **Splunk Docs** | [Microsoft Cloud Services Add-on](https://docs.splunk.com/Documentation/AddOns/released/MSCloudServices/ConfigureappinAzureAD) |
| **GitHub Wiki** | [Splunk Add-on for Microsoft Azure](https://github.com/splunk/splunk-add-on-microsoft-azure/wiki) |
| **Microsoft Docs** | [Sign-in log schema](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema) |
| **Microsoft Tutorial** | [Configure Microsoft Entra SSO for Splunk](https://learn.microsoft.com/en-us/azure/active-directory/saas-apps/splunkenterpriseandsplunkcloud-tutorial) |

**Sourcetypes:** `azure:aad:signin`, `azure:aad:audit`, `azure:monitor:aad`

**Note:** Best practice is to send Entra ID data to Event Hub, then use `azure:monitor:aad` sourcetype.

---

### Exchange (Office 365 Message Trace)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Office 365](https://splunkbase.splunk.com/app/4055) |
| **Splunk Docs** | [Configure Message Trace Input](https://docs.splunk.com/Documentation/AddOns/released/MSO365/Configureinputmessagetrace) |
| **GitHub Docs** | [Configure Message Trace Input](https://splunk.github.io/splunk-add-on-for-microsoft-office-365/ConfigureMessageTraceInput/) |
| **Splunk Lantern** | [Microsoft Office 365 Reporting](https://lantern.splunk.com/Data_Descriptors/Data_Sources/Microsoft:_Office_365_Reporting) |
| **Microsoft Docs** | [Message Trace](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac) |

**Sourcetype:** `ms:o365:reporting:messagetrace`

**API Endpoint:** `https://reports.office365.com/ecp/reportingwebservice/reporting.svc/MessageTrace`

**Limitation:** API can only return data up to 7 days back (portal shows 90 days).

---

## Collaboration

### Webex Meetings TA (XML API)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco WebEx Meetings Add-on for Splunk](https://splunkbase.splunk.com/app/4992) |
| **GitHub** | [ta-cisco-webex-meetings-add-on-for-splunk](https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk) |
| **Splunk Blog** | [Splunking Cisco Webex Meetings Data](https://www.splunk.com/en_us/blog/it/splunking-cisco-webex-meetings-data.html) |
| **Webex API** | [Webex Meetings XML API](https://developer.webex.com/) |

**Sourcetypes:**
- `cisco:webex:meetings:history:meetingusagehistory`
- `cisco:webex:meetings:history:meetingattendeehistory`
- `cisco:webex:meetings:history:trainingattendeehistory`
- `cisco:webex:meetings:history:supportattendeehistory`
- `cisco:webex:meetings:history:eventattendeehistory`

**Note:** Historical data may be incomplete if fetched <48 hours after meeting end. Set interval to 86400+ for historical inputs.

---

### Webex REST API

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Cisco Webex Add-on for Splunk](https://splunkbase.splunk.com/app/5781) |
| **GitHub** | [ta_cisco_webex_add_on_for_splunk](https://github.com/splunk/ta_cisco_webex_add_on_for_splunk) |
| **Webex Developer** | [Webex REST API](https://developer.webex.com/) |

**Sourcetypes:**
- `cisco:webex:meetings`
- `cisco:webex:admin:audit:events`
- `cisco:webex:security:audit:events`
- `cisco:webex:meeting:qualities`
- `cisco:webex:call:detailed_history`

---

## Windows

### Windows Performance Monitor (Perfmon)

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) |
| **Splunk Docs** | [Monitor Windows performance](https://docs.splunk.com/Documentation/Splunk/9.2.1/Data/MonitorWindowsperformance) |
| **Source Types** | [Windows Add-on Sourcetypes](https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo) |
| **GitHub Docs** | [Splunk Add-on for Microsoft Windows](https://splunk.github.io/splunk-add-on-for-microsoft-windows/) |

**Sourcetype:** `Perfmon`

**Collection Modes:**
- **single** (default): One event per counter/instance combination
- **multikv**: Smaller indexing volume, but some apps require single mode

**Note:** Use `useEnglishOnly=true` for compatibility with apps like Enterprise Security.

---

### Windows Event Log

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) |
| **Splunk Docs** | [Monitor Windows event log data](https://docs.splunk.com/Documentation/Splunk/9.4.2/Data/MonitorWindowseventlogdata) |
| **Source Types** | [Windows Add-on Sourcetypes](https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo) |
| **CIM Changes** | [CIM and Field Mapping Changes](https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/CIMModelandFieldMappingChanges) |
| **Microsoft Docs** | [Windows Security Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview) |

**Sourcetypes:** `WinEventLog`, `XmlWinEventLog`

**Note:** This project uses the classic `WinEventLog` format (KV pairs), not the XML format (`XmlWinEventLog`). The Sysmon sourcetype is `WinEventLog:Sysmon`.

---

## ITSM

### ServiceNow

| Resource | Link |
|----------|------|
| **Splunk Add-on** | [Splunk Add-on for ServiceNow](https://splunkbase.splunk.com/app/1928) |
| **Splunk Docs** | [About the Add-on](https://splunk.github.io/splunk-add-on-for-servicenow/) |
| **Source Types** | [ServiceNow Source Types](https://splunk.github.io/splunk-add-on-for-servicenow/Datatypes/) |
| **ServiceNow Docs** | [Table API](https://developer.servicenow.com/dev.do#!/reference/api/vancouver/rest/c_TableAPI) |

**Sourcetype:** `snow:incident` (schema: `snow:<table_name>`)

**Features:**
- Collects data from any ServiceNow table exposed via REST API
- Can create incidents/events in ServiceNow from Splunk alerts
- Auto-creates incidents from Critical (severity=1) events

---

## Standard Formats (No Add-on Required)

### Linux Metrics

Standard Linux command output formats:
- **vmstat** - CPU/memory statistics
- **df** - Disk space usage
- **iostat** - I/O statistics
- **interfaces** - Network statistics

**Sourcetypes:** `linux:vmstat`, `linux:df`, `linux:iostat`, `linux:interfaces`

---

### Apache Access Logs

Standard Apache Combined Log Format - widely documented.

**Format:** `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`

**Sourcetype:** `access_combined`

**Reference:** [Apache Log Files](https://httpd.apache.org/docs/current/logs.html)

---

## Custom/Fictional Formats

### Retail Orders

Custom JSON format for fictional e-commerce data. No external reference.

**Sourcetype:** `retail:orders`

---

### Azure ServiceBus

Custom JSON format based on typical ServiceBus message structure.

**Sourcetype:** `azure:servicebus`

**Note:** No specific Splunk Add-on reference documented. Consider using [Splunk Add-on for Microsoft Cloud Services](https://splunkbase.splunk.com/app/3110) for real Azure data.

---

## Summary

This documentation provides links to:
1. **Splunk Add-ons** on Splunkbase for each data source
2. **Splunk Documentation** for configuration and sourcetypes
3. **Vendor APIs** for understanding the original data format
4. **GitHub repositories** for add-on source code and additional docs

When generating synthetic logs, these references ensure our format matches what Splunk expects from real data sources.
