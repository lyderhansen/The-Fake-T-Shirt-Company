---
name: sourcetype-fields
description: Complete field reference for all FAKE: sourcetypes in the fake_tshrt index. Use when writing SPL queries, building dashboards, or understanding the data model.
---

# Sourcetype Field Reference

Complete field inventory for all sourcetypes in `index=fake_tshrt`. Data spans January 2026 (~11.2M events, 40 sourcetypes, 511 hosts).

**Common fields on ALL sourcetypes:** `host`, `source`, `sourcetype`, `index` (fake_tshrt), `_time`
**Scenario tagging:** `IDX_demo_id` (indexed), `demo_id` (search-time) - values: exfil, ransomware_attempt, memory_leak, cpu_runaway, disk_filling, firewall_misconfig, certificate_expiry

## Quick Reference

| # | Sourcetype | Category | Fields | Host(s) | vendor_product |
|---|-----------|----------|--------|---------|----------------|
| 1 | FAKE:cisco:asa | Network | 115 | FW-EDGE-01 | Cisco ASA |
| 2 | FAKE:meraki:securityappliances | Network | 41 | MX-BOS-01, MX-ATL-01, MX-AUS-01 | Cisco Meraki MX |
| 3 | FAKE:meraki:accesspoints | Network | 44 | AP-*-* (36 APs) | Cisco Meraki MR |
| 4 | FAKE:meraki:switches | Network | 39 | MS-*-* (11 switches) | Cisco Meraki MS |
| 5 | FAKE:meraki:cameras | Network | 41 | MV-*-* (19 cameras) | Cisco Meraki MV |
| 6 | FAKE:meraki:sensors | Network | 41 | MT-*-* (14 sensors) | Cisco Meraki MT |
| 7 | FAKE:meraki:accesspoints:health | Network | 49 | AP-*-* | Cisco Meraki MR |
| 8 | FAKE:meraki:switches:health | Network | 50 | MS-*-* | Cisco Meraki MS |
| 9 | FAKE:aws:cloudtrail | Cloud | 55 | aws | AWS CloudTrail |
| 10 | FAKE:azure:aad:signin | Cloud | 54 | azure_entraid | Microsoft Entra ID |
| 11 | FAKE:azure:aad:audit | Cloud | 40 | azure_entraid | Microsoft Entra ID |
| 12 | FAKE:azure:aad:riskDetection | Cloud | 39 | azure_entraid | Microsoft Entra ID |
| 13 | FAKE:google:gcp:pubsub:audit:admin_activity:demo | Cloud | 55 | faketshirtcompany-prod-01 | Google Cloud Platform |
| 14 | FAKE:google:gcp:pubsub:audit:data_access:demo | Cloud | 45 | faketshirtcompany-prod-01 | Google Cloud Platform |
| 15 | FAKE:cisco:webex:meetings | Collab | 45 | webex | Cisco Webex Meetings API |
| 16 | FAKE:cisco:webex:meetings:history:meetingusagehistory | Collab | 47 | webex | Cisco Webex Meetings |
| 17 | FAKE:cisco:webex:meetings:history:meetingattendeehistory | Collab | 42 | webex | Cisco Webex Meetings |
| 18 | FAKE:cisco:webex:admin:audit:events | Collab | 45 | webex | Cisco Webex Admin Audit |
| 19 | FAKE:cisco:webex:security:audit:events | Collab | 39 | webex | Cisco Webex Security Audit |
| 20 | FAKE:cisco:webex:meeting:qualities | Collab | 65 | webex | Cisco Webex Meeting Quality |
| 21 | FAKE:cisco:webex:call:detailed_history | Collab | 48 | webex | Cisco Webex Calling |
| 22 | FAKE:o365:reporting:messagetrace | Email | 58 | exchange | Microsoft Office 365 MessageTrace |
| 23 | FAKE:Perfmon:Processor | Windows | 29 | 27 servers + workstations | Windows Perfmon |
| 24 | FAKE:Perfmon:Memory | Windows | 29 | 27 servers + workstations | Windows Perfmon |
| 25 | FAKE:Perfmon:LogicalDisk | Windows | 29 | 27 servers + workstations | Windows Perfmon |
| 26 | FAKE:Perfmon:Network_Interface | Windows | 29 | 27 servers + workstations | Windows Perfmon |
| 27 | FAKE:WinEventLog | Windows | 63 | 14 servers | Microsoft Windows |
| 28 | FAKE:XmlWinEventLog:Sysmon | Windows | 47 | 27 servers + workstations | Microsoft Sysmon |
| 29 | FAKE:cpu | Linux | 29 | 5 Linux hosts | - |
| 30 | FAKE:vmstat | Linux | 28 | 5 Linux hosts | - |
| 31 | FAKE:df | Linux | 30 | 5 Linux hosts | - |
| 32 | FAKE:iostat | Linux | 28 | 5 Linux hosts | - |
| 33 | FAKE:interfaces | Linux | 28 | 5 Linux hosts | - |
| 34 | FAKE:access_combined | Web | 29 | WEB-01 | Apache |
| 35 | FAKE:online:order | Retail | 0 | - | **NO DATA** |
| 36 | FAKE:online:order:registry | Retail | 32 | WEB-01 | Retail Order System |
| 37 | FAKE:azure:servicebus | Retail | 0 | - | **NO DATA** |
| 38 | FAKE:servicenow:incident | ITSM | 52 | servicenow | ServiceNow |
| 39 | FAKE:servicenow:cmdb | ITSM | 0 | - | **NO DATA** |
| 40 | FAKE:servicenow:change | ITSM | 50 | servicenow | ServiceNow |
| 41 | FAKE:mssql:errorlog | Database | 30 | SQL-PROD-01 | Microsoft SQL Server |
| - | FAKE:cisco:webex:events | Collab | 0 | - | **NO DATA** |

---

## Network

### FAKE:cisco:asa
**Host:** FW-EDGE-01 | **vendor_product:** Cisco ASA | **~115 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| action | str | 4 | allowed (486), teardown (446), built (465), deny (9) |
| laction | str | 4 | built (465), teardown (446), deny (9), executed (6) |
| Cisco_ASA_message_id | num | 13 | 302014 (232), 302016 (214), 302013 (232), 302015 (214), 106023 (9) |
| message_id | num | 13 | same as Cisco_ASA_message_id |
| src / src_ip | str | 458 | 1.1.1.1, 8.8.8.8, 203.0.113.51, 10.30.30.160 |
| dest / dest_ip | str | 413 | 10.10.20.10, 172.16.1.10, 10.10.20.50, 10.30.30.20 |
| src_port | num | 478 | 53 (79), 80 (10), 443 (9), ephemeral ports |
| dest_port | num | 100 | 443 (345), 80 (156), 53 (79), 8080 (23), 22 (13) |
| transport | str | 2 | TCP (841), UDP (79) |
| protocol | str | 1 | ip |
| src_interface | str | 5 | outside (555), inside (228), aus (54), atl (44), bos (39) |
| dest_interface | str | 6 | dmz (463), outside (228), inside (92), atl (58), aus (43), bos (36) |
| src_zone | str | 5 | same as src_interface |
| dest_zone | str | 6 | same as dest_interface |
| direction | str | 2 | inbound (292), outbound (132) |
| session_id | num | 425 | random 6-digit numbers |
| duration | num | 73 | 0-578 sec, mean 30.7 |
| bytes_in | num | 164 | 0-976,028, mean 30,469 |
| bytes_out | num | 165 | 0-1,000,000, mean 29,629 |
| log_level | num | 3 | 6 (919), 5 (72), 4 (9) |
| severity_level | str | 3 | informational (919), notification (72), warning (9) |
| reason | str | 4 | TCP Reset-I (100), TCP Reset-O (96), TCP FINs (85), idle timeout (61) |
| user | str | 24 | VPN users - alex.miller, john.smith, etc. |
| group | str | 1 | Remote-Workers |
| rule | str | 3 | acl_outside, implicit-deny, outside_access_in |
| dvc | str | 1 | FW-EDGE-01 |
| ids_type | str | 1 | network |
| vendor | str | 1 | Cisco |
| product | str | 1 | ASA |

### FAKE:meraki:securityappliances
**Hosts:** MX-BOS-01, MX-ATL-01, MX-AUS-01 | **vendor_product:** Cisco Meraki MX | **41 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| type | str | 6 | firewall (576), url (209), sd_wan_health (98), vpn_connectivity_change (49), vpn_tunnel_status (36), security_event (32) |
| category | str | 1 | appliance |
| description | str | 78 | Firewall flow allowed (549), SD-WAN wan1 health: active (56), VPN tunnel status changed (49) |
| deviceName | str | 3 | MX-BOS-01 (537), MX-ATL-01 (267), MX-AUS-01 (196) |
| networkId | str | 3 | N_FakeTShirtCo_BOS (537), N_FakeTShirtCo_ATL (267), N_FakeTShirtCo_AUS (196) |
| eventData.src | str | 500 | Internal IPs (10.10/20/30.30.x) |
| eventData.dst | str | 500 | 172.217.14.78, 54.239.28.85, 52.169.118.173, 140.82.121.4 |
| eventData.sport | num | 500 | Ephemeral ports |
| eventData.dport | num | 8 | 8080 (79), 443 (77), 25 (76), 587 (74), 3389 (73) |
| eventData.protocol | str | 2 | tcp (303), udp (273) |
| eventData.pattern | str | 2 | allow all (549), deny all (27) |
| eventData.mac | str | 500 | Client MAC addresses |
| eventData.url | str | 74 | google.com, slack.com, api.service.com, github.com, microsoft.com |
| eventData.method | str | 1 | GET |
| eventData.status | str | 3 | active (80), up (36), degraded (18) |
| eventData.wan | str | 2 | wan1 (65), wan2 (33) |
| eventData.latency_ms | num | 85 | 13-27ms range |
| eventData.jitter_ms | num | 60 | 1-4ms range |
| eventData.loss_pct | num | 53 | 0.3-0.5% range |
| eventData.vpn_type | str | 2 | site-to-site (26), client (23) |
| eventData.connectivity | str | 2 | true (35), false (14) |
| eventData.peer | str | 2 | MX-AUS-01 (24), MX-ATL-01 (12) |
| subtype | str | 3 | content_filtering (22), amp_malware_blocked (7), client_isolation (3) |
| eventData.category (content) | str | 7 | Gambling (7), Botnets (4), Social Networking (4), Streaming Media (3) |
| eventData.threatName | str | 5 | Doc.Dropper.Generic, JS.Downloader.Generic, Win.Ransomware.Locky |

### FAKE:meraki:accesspoints
**Hosts:** 36 APs (AP-BOS-*/AP-ATL-*/AP-AUS-*) | **vendor_product:** Cisco Meraki MR | **44 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| type | str | 6 | association (489), disassociation (248), 8021x_eap_success (172), wpa_auth (81), 8021x_eap_failure (9), rogue_ssid_detected (1) |
| description | str | 6 | 802.11 association, 802.11 disassociation, 802.1X EAP authentication succeeded, WPA authentication |
| category | str | 1 | wireless |
| deviceName | str | 36 | AP-BOS-3F-06 (45), AP-BOS-2F-02 (42), etc. |
| networkId | str | 3 | N_FakeTShirtCo_BOS (525), N_FakeTShirtCo_ATL (261), N_FakeTShirtCo_AUS (214) |
| clientIp | str | 500 | 10.10/20/30.30.x range |
| clientMac | str | 500 | Unique MAC addresses |
| eventData.radio | str | 2 | 1 (722), 0 (277) |
| eventData.channel | num | 11 | 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 |
| eventData.rssi | num | 51 | 20-70 range, mean 43.9 |
| eventData.vap | num | 4 | 0, 1, 2, 3 |
| eventData.identity | str | 108 | employee emails @theFakeTshirtCompany.com |
| eventData.duration | num | 248 | 72-28764 seconds |
| eventData.reason | num | 5 | 1, 3, 4, 8, 23 |
| ssidNumber | num | 4 | 0-3 |

### FAKE:meraki:switches
**Hosts:** 11 switches (MS-BOS-*/MS-ATL-*/MS-AUS-*) | **vendor_product:** Cisco Meraki MS | **39 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| type | str | 4 | port_status (614), stp_topology_change (208), 8021x_port_auth (178) |
| description | str | 32 | Port 5 link up at 1 Gbps, STP topology change detected, etc. |
| deviceName | str | 11 | MS-BOS-CORE-01, MS-ATL-CORE-01, MS-BOS-1F-01, etc. |
| eventData.port | str | 31 | Port 1-48 |
| eventData.speed | str | 3 | 1 Gbps, 10 Gbps, 100 Mbps |
| eventData.status | str | 2 | up, down |
| eventData.client_mac | str | 500 | MAC addresses |
| eventData.vlan | num | 14 | 10, 20, 30, 100, 200, 300 |
| eventData.identity | str | 92 | Employee emails |

### FAKE:meraki:cameras
**Hosts:** 19 cameras (MV-BOS-*/MV-ATL-*/MV-AUS-*) | **vendor_product:** Cisco Meraki MV | **41 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| type | str | 4 | motion_detection (425), person_detection (342), analytics (160), health_status (73) |
| description | str | 400+ | Motion detected in zone..., Person detected..., etc. |
| eventData.zone | str | 6 | entrance, lobby, parking, hallway, server_room, loading_dock |
| eventData.confidence | num | 52 | 60-99% range |
| eventData.people_count | num | 10 | 0-15 people |
| eventData.motion_score | num | 66 | 15-100% |

### FAKE:meraki:sensors
**Hosts:** 14 sensors (MT-*) | **vendor_product:** Cisco Meraki MT | **41 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| type | str | 4 | temperature (485), humidity (260), door (185), water_leak (70) |
| eventData.temperature_c | num | 125 | 19.8-28.5C range |
| eventData.humidity_pct | num | 60 | 35-65% range |
| eventData.door_status | str | 2 | open, closed |
| eventData.water_detected | str | 2 | false (majority), true (rare) |
| eventData.location | str | 10 | Server Room A, Server Room B, MDF, IDF-*, Data Center |

### FAKE:meraki:accesspoints:health
**Hosts:** 36 APs | **vendor_product:** Cisco Meraki MR | **49 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metrics.channel_utilization | num | ~50 | 15-85% |
| metrics.client_count | num | ~30 | 0-45 clients |
| metrics.noise_floor | num | ~15 | -95 to -80 dBm |
| metrics.power_level | num | 3 | 8, 11, 14 dBm |
| metrics.band | str | 2 | 5GHz, 2.4GHz |
| status | str | 2 | online (majority), degraded |

### FAKE:meraki:switches:health
**Hosts:** 11 switches | **vendor_product:** Cisco Meraki MS | **50 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metrics.cpu_pct | num | ~50 | 10-60% |
| metrics.memory_pct | num | ~40 | 30-70% |
| metrics.port_errors | num | ~20 | 0-50 |
| metrics.power_draw_watts | num | ~100 | 50-400W |
| metrics.temperature_c | num | ~30 | 30-55C |
| metrics.uptime_seconds | num | 500 | High values (weeks) |
| status | str | 2 | online, degraded |

---

## Cloud

### FAKE:aws:cloudtrail
**Host:** aws | **vendor_product:** AWS CloudTrail | **55 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| eventName / action | str | 8 | GetObject (257), PutObject (212), Invoke (190), DescribeInstances (147), ListUsers (97) |
| eventSource | str | 5 | s3.amazonaws.com (469), lambda.amazonaws.com (190), ec2.amazonaws.com (147), iam.amazonaws.com (99), sts.amazonaws.com (95) |
| awsRegion / dest | str | 1 | us-east-1 |
| eventType | str | 1 | AwsApiCall |
| sourceIPAddress / src | str | 11 | lambda.amazonaws.com (166), 10.20.30.15 (126), 10.10.30.182 (118) |
| userIdentity.type | str | 2 | IAMUser (701), AssumedRole (299) |
| userIdentity.userName / user | str | 8 | jessica.brown (126), patrick.gonzalez (118), carlos.martinez (114), david.robinson (111), brandon.turner (104) |
| userIdentity.arn | str | 11 | IAM users + assumed roles (DataPipelineRole, DeploymentPipelineRole, BackupServiceRole) |
| userIdentity.accountId / recipientAccountId | num | 1 | 123456789012 |
| requestParameters.bucketName | str | 4 | faketshirtcompany-backups (153), faketshirtcompany-prod-data (148), faketshirtcompany-logs (141), faketshirtco-financial-reports (27) |
| requestParameters.key | str | 442 | confidential/customer-database.csv, confidential/employee-salaries.csv, reports/*, financial/* |
| requestParameters.functionName | str | 4 | api-handler, process-orders, send-notifications, data-transform |
| requestParameters.instancesSet.items{}.instanceId | str | 3 | i-0def789abc012, i-0123456789abc, i-0abc123def456 |
| resources{}.type | str | 4 | AWS::S3::Object (469), AWS::S3::Bucket (442), AWS::Lambda::Function (190), AWS::EC2::Instance (147) |
| userAgent | str | 7 | console.aws.amazon.com (573), lambda.amazonaws.com (166), aws-cli/2.15.0 (99), s3.amazonaws.com (85) |
| readOnly | str | 2 | true (596), false (402) |
| app | str | 1 | aws |

### FAKE:azure:aad:signin
**Host:** azure_entraid | **vendor_product:** Microsoft Entra ID | **54 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| properties.userPrincipalName | str | 182 | claire.roberts@, lucy.rogers@, madison.quinn@, nicholas.kelly@ |
| identity | str | 183 | Display names: Claire Roberts, Lucy Rogers, Madison Quinn |
| properties.ipAddress / callerIpAddress / src | str | 192 | 10.10.30/31.x, 10.20.30.x, 10.30.30.x |
| properties.status.errorCode | num | 5 | 0 (934 success), 50126 (28 bad password), 53003 (15 CA blocked), 50076 (12 MFA), 50074 (11) |
| properties.status.failureReason | str | 4 | Invalid username or password (28), Blocked by Conditional Access (15), MFA required (12) |
| properties.conditionalAccessStatus | str | 3 | success (934), failure (49), notApplied (17) |
| properties.appDisplayName | str | 8 | Custom HR App (142), SharePoint Online (142), Microsoft Graph (136), Custom Finance App (135), Microsoft Teams (129) |
| properties.clientAppUsed | str | 3 | Browser (751), Mobile Apps and Desktop clients (222), Other clients (27) |
| properties.deviceDetail.operatingSystem | str | 6 | Windows 11 (501), macOS (229), Windows 10 (204), iOS (25), Android (24) |
| properties.deviceDetail.browser | str | 3 | Chrome 120.0 (451), Edge 120.0 (202), Safari 17.2 (81) |
| properties.deviceDetail.displayName | str | 175 | Workstation names (BOS-WS-*, ATL-WS-*, AUS-WS-*) |
| properties.deviceDetail.isCompliant | str | 2 | true (934), false (17) |
| properties.location.city | str | 10 | Boston (521), Atlanta (235), Austin (227), Sao Paulo (4) |
| properties.location.countryOrRegion / location | str | 7 | US (986), BR (4), CN (3), DE (2), FR (2) |
| properties.mfaDetail.authMethod | str | 5 | Microsoft Authenticator (312), Previously satisfied (189), Phone call (151), Mobile app verification code (142), FIDO2 security key (140) |
| properties.authenticationRequirement | str | 1 | multiFactorAuthentication |
| properties.isInteractive | str | 1 | true |
| properties.riskState | str | 1 | none |
| tenantId | str | 1 | af23e456-7890-1234-5678-abcdef012345 |
| category | str | 1 | SignInLogs |
| action | str | 1 | failure |

### FAKE:azure:aad:audit
**Host:** azure_entraid | **vendor_product:** Microsoft Entra ID | **40 fields** | **627 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| operationName / properties.activityDisplayName | str | 16 | Self-service password reset flow activity progress (192), Add member to group (98), Update user (95), Remove member from group (86), Update group (78) |
| properties.initiatedBy.user.displayName / identity | str | 140 | IT Admin (142), Security Admin (118), Helpdesk Admin (106), + individual employees |
| properties.initiatedBy.user.userPrincipalName | str | 140 | it.admin@, sec.admin@, helpdesk@, + employee UPNs |
| callerIpAddress / src | str | 243 | 10.20.30.10 (142), 10.10.10.50 (118), 10.10.10.51 (106) |
| properties.result / resultType | str | 2 | success/Success (583), failure/Failure (44) |
| properties.category | str | 4 | UserManagement (621), ApplicationManagement (4), Policy (1), RoleManagement (1) |
| properties.loggedByService | str | 3 | Core Directory (366), Self-service Password Management (260), Authentication Methods (1) |
| properties.targetResources{}.displayName | str | 177 | Target user display names |
| properties.targetResources{}.type | str | 5 | User (621), Other (2), ServicePrincipal (2), Application (1), Policy (1) |
| properties.operationType | str | 2 | Update (626), Add (1) |
| tenantId | str | 1 | af23e456-7890-1234-5678-abcdef012345 |
| category | str | 1 | AuditLogs |

### FAKE:azure:aad:riskDetection
**Host:** azure_entraid | **vendor_product:** Microsoft Entra ID | **39 fields** | **69 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| properties.riskEventType / properties.riskType | str | 7 | maliciousIPAddress (24), unfamiliarFeatures (18), impossibleTravel (7), passwordSpray (6), leakedCredentials (5) |
| properties.riskLevel | str | 3 | medium (36), high (19), low (14) |
| properties.riskState | str | 1 | atRisk |
| properties.riskDetail | str | 7 | Sign-in from a malicious IP address (24), Sign-in with unfamiliar properties (18) |
| properties.userPrincipalName / user | str | 32 | alex.miller@ (29), jessica.brown@ (9), monique.wright@ (2) |
| properties.ipAddress / callerIpAddress / src | str | 32 | 185.220.101.42 (38 - threat actor), 102.67.x.x (random) |
| properties.location.city | str | 2 | Frankfurt (38), Unknown (31) |
| properties.location.countryOrRegion | str | 2 | Germany (38), Unknown (31) |
| properties.source | str | 1 | IdentityProtection |
| properties.activity | str | 1 | signin |
| properties.detectionTimingType | str | 1 | realtime |
| app | str | 1 | azure:aad |

### FAKE:google:gcp:pubsub:audit:admin_activity:demo
**Host:** faketshirtcompany-prod-01 | **55 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| protoPayload.methodName | str | 8 | compute.instances.list, storage.objects.get, jobcompleted, CloudFunctionsService.CallFunction, storage.objects.create, SetIamPolicy, CreateServiceAccount, CreateServiceAccountKey |
| protoPayload.serviceName | str | 6 | storage (346), compute (242), bigquery (210), cloudfunctions (199), iam (2), cloudresourcemanager (1) |
| protoPayload.authenticationInfo.principalEmail | str | 4 | svc-storage (357), svc-compute (334), svc-functions (306), alex.miller (3) |
| protoPayload.requestMetadata.callerIp | str | 500 | Internal IPs, including 185.220.101.42 (threat actor) |
| resource.type | str | 6 | gcs_bucket, gce_instance, bigquery_dataset, cloud_function, service_account, project |
| resource.labels.project_id | str | 1 | faketshirtcompany-prod-01 |
| severity | str | 2 | INFO (997), NOTICE (3) |
| logName | str | 1 | cloudaudit.googleapis.com%2Factivity |
| demo_id | str | 1 | exfil (170) |

### FAKE:google:gcp:pubsub:audit:data_access:demo
**Host:** faketshirtcompany-prod-01 | **45 fields** | **407 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| protoPayload.methodName | str | 3 | storage.objects.get (405), storage.buckets.getIamPolicy (1), storage.objects.list (1) |
| protoPayload.serviceName | str | 1 | storage.googleapis.com |
| protoPayload.authenticationInfo.principalEmail | str | 6 | svc-functions (135), svc-compute (131), svc-storage (126), compute-admin (13), alex.miller (1) |
| protoPayload.resourceName | str | 398 | Includes confidential bucket objects: finance/budget, hr/salary-data, legal/contracts, executive/board-minutes, strategy/roadmap |
| resource.labels.bucket_name | str | 1 | faketshirtco-confidential (15 events only) |
| resource.type | str | 1 | gcs_bucket |
| demo_id | str | 1 | exfil (203) |

---

## Collaboration

### FAKE:cisco:webex:meetings
**Host:** webex | **vendor_product:** Cisco Webex Meetings API | **45 fields** | **436 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| title | str | 10 | Weekly Team Sync, Sprint Planning, etc. |
| hostDisplayName | str | 158 | Employee display names |
| hostEmail | str | ~158 | employee@theFakeTshirtCompany.com |
| meetingType | str | 1 | scheduledMeeting |
| state | str | 1 | ended |
| siteUrl | str | 1 | theFakeTshirtCompany.webex.com |
| timezone | str | 1 | America/New_York |
| vendor | str | 1 | Cisco |
| product | str | 1 | Webex |

### FAKE:cisco:webex:meetings:history:meetingusagehistory
**Host:** webex | **vendor_product:** Cisco Webex Meetings | **47 fields** | **343 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| confName | str | 18 | Meeting types (team syncs, standups, reviews, etc.) |
| hostEmail | str | 157 | Employee emails |
| meetingType | str | 4 | TC, EC, SC, MC |
| duration | num | - | 15-120 minutes |
| peakAttendee | num | - | 1-40 |
| totalParticipants | num | - | 3-41 |

### FAKE:cisco:webex:meetings:history:meetingattendeehistory
**Host:** webex | **vendor_product:** Cisco Webex Meetings | **42 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| attendeeEmail | str | 238 | Employee + external emails |
| attendeeName | str | 198 | Attendee display names |
| confName | str | 18 | Meeting types |
| hostEmail | str | 94 | Meeting hosts |
| clientOS | str | 7 | Windows, macOS, iOS, Android, etc. |
| clientType | str | 6 | Desktop App, Browser, Mobile, etc. |
| participantType | str | 3 | ATTENDEE, HOST, GUEST |
| ipAddress | str | 500 | Attendee IP addresses |

### FAKE:cisco:webex:admin:audit:events
**Host:** webex | **vendor_product:** Cisco Webex Admin Audit | **45 fields** | **367 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| data.actorEmail | str | 2 | jessica.brown (exfil actor), mike.johnson (CTO) |
| data.actorName | str | 2 | Jessica Brown, Mike Johnson |
| data.eventCategory | str | 5 | COMPLIANCE, MEETINGS, GROUPS, USERS, DEVICES |
| data.eventDescription | str | 17 | Various admin audit actions |
| data.targetName | str | 152 | Target resources |
| data.actionText | str | 357 | Unique action descriptions |
| demo_id | str | 1 | exfil (161) |

### FAKE:cisco:webex:security:audit:events
**Host:** webex | **vendor_product:** Cisco Webex Security Audit | **39 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| data.eventDescription | str | 2 | A user logged out (569), A user logged in (431) |
| data.eventCategory | str | 1 | LOGINS |
| data.actorEmail | str | 167 | All employee emails |
| data.actorIp | str | 167 | Employee IP addresses |

### FAKE:cisco:webex:meeting:qualities
**Host:** webex | **vendor_product:** Cisco Webex Meeting Quality | **65 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| clientType | str | 4 | Webex Desktop (564), Web Browser (193), Mobile iOS (137), Mobile Android (106) |
| osType | str | 4 | Windows (464), macOS (293), iOS (137), Android (106) |
| networkType | str | 3 | wifi (485), ethernet (391), cellular (124) |
| hardwareType | str | 12 | HP EliteBook, Dell Latitude, Lenovo ThinkPad, MacBook Pro/Air, iPhone 14/15, iPad Pro, Samsung Galaxy, Google Pixel |
| audioIn{}.codec | str | 3 | G.711, opus, G.722 |
| audioIn{}.latency{} | num | - | 30-80ms |
| audioIn{}.jitter{} | num | - | 2-15ms |
| audioIn{}.packetLoss{} | num | - | 0.0-2.0% |
| audioIn{}.transportType | str | 2 | TCP, UDP |
| videoIn{}.codec | str | 3 | H.264, VP8, VP9 |
| videoIn{}.frameRate{} | num | 2 | 24, 30 fps |
| videoIn{}.resolutionHeight{} | num | 2 | 720, 1080 |
| videoIn{}.packetLoss{} | num | - | 0.0-3.0% |
| joinMeetingTime | num | - | 3-15 seconds |
| serverRegion | str | 4 | APAC, US West, EU West, US East |
| resources.processAverageCPU{} | num | - | 10-30% |
| resources.systemAverageCPU{} | num | - | 30-60% |
| webexUserEmail | str | 175 | All employee emails |
| publicIP | str | 252 | 203.0.113.x range |
| localIP | str | 175 | Internal IPs |

### FAKE:cisco:webex:call:detailed_history
**Host:** webex | **vendor_product:** Cisco Webex Calling | **48 fields** | **599 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| Call type | str | 3 | SIP_ENTERPRISE (220), SIP_NATIONAL (215), WEBEX_CALLING (164) |
| Call outcome | str | 2 | Success (526), NoAnswer (73) |
| Answered | str | 2 | true (526), false (73) |
| Direction | str | 1 | ORIGINATING |
| Duration | num | - | 0-599 seconds, mean 277 |
| User | str | 171 | employee@theFakeTshirtCompany.com |
| Called number | str | - | +1555xxxxxxx format |
| Dialed digits | str | - | 555xxxx |
| Client type | str | 4 | Desktop, mobile, etc. |
| User type | str | 1 | User |
| product | str | 1 | Webex Calling |

---

## Email

### FAKE:o365:reporting:messagetrace
**Host:** exchange | **vendor_product:** Microsoft Office 365 MessageTrace | **58 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| SenderAddress / src_user | str | 236 | facilities@, noreply@github.com, communications@, ceo-office@, splunk-alerts@ |
| RecipientAddress / recipient | str | 221 | boston-all@, employee emails, distribution lists (hr-team, finance, engineering) |
| Subject / subject | str | 300 | Team Lunch Friday? (55), Quick Question (47), RE: Action Items, FW: Customer Feedback, meeting invites |
| Status / status_code | str | 2 | Delivered (988), FilteredAsSpam (12) |
| action | str | 2 | delivered (988), blocked (12) |
| FromIP / src | str | 238 | 10.10.20.51 (396), 10.10.20.50 (368), external IPs |
| ToIP / dest | str | 134 | 10.10.20.50 (449), 10.10.20.51 (419) |
| Size / size | num | 500 | 2KB-2MB, mean 324KB |
| MessageTraceId | str | 500 | Unique UUIDs |
| src_user_domain | str | 24 | theFakeTshirtCompany.com (761), fabrikam.com, adventureworks.com, contoso.com, gmail.com |
| recipient_domain | str | 16 | theFakeTshirtCompany.com (860), outlook.com, gmail.com, northwindtraders.com |
| recipient_count | num | 1 | 1 |
| SystemName | str | 7 | GitHub (14), Splunk (11), Jira (9), Azure (8), ServiceNow (7), Slack (6), AWS (4) |

---

## Windows

### FAKE:Perfmon:Processor
**Hosts:** 27 (servers + workstations) | **vendor_product:** Windows Perfmon | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| collection | str | 1 | Processor |
| object | str | 1 | Processor |
| counter | str | 3 | % Processor Time, % Idle Time, % Interrupt Time |
| instance | str | 1 | _Total |
| Value | num | 500 | 0.0-100.0 (% values) |
| demo_host | str | 27 | SQL-PROD-01, DC-BOS-01, WEB-01, BOS-WS-*, ATL-WS-*, AUS-WS-* |

### FAKE:Perfmon:Memory
**Hosts:** 27 | **vendor_product:** Windows Perfmon | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| collection | str | 1 | Memory |
| object | str | 1 | Memory |
| counter | str | 4 | Available MBytes, % Committed Bytes In Use, Pages/sec, Pool Nonpaged Bytes |
| Value | num | 500 | Varies by counter (MBytes, %, pages/sec) |
| demo_host | str | 27 | Same hosts as Processor |

### FAKE:Perfmon:LogicalDisk
**Hosts:** 27 | **vendor_product:** Windows Perfmon | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| collection | str | 1 | LogicalDisk |
| object | str | 1 | LogicalDisk |
| counter | str | 4 | % Free Space, Free Megabytes, Disk Read Bytes/sec, Disk Write Bytes/sec |
| instance | str | 2 | C:, D: |
| Value | num | 500 | Varies by counter |
| demo_host | str | 27 | Same hosts |

### FAKE:Perfmon:Network_Interface
**Hosts:** 27 | **vendor_product:** Windows Perfmon | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| collection | str | 1 | Network Interface |
| object | str | 1 | Network Interface |
| counter | str | 4 | Bytes Received/sec, Bytes Sent/sec, Packets Received/sec, Packets Sent/sec |
| instance | str | 1 | Intel[R] Ethernet Connection I219-LM |
| Value | num | 500 | Bytes/sec or packets/sec |
| demo_host | str | 27 | Same hosts |

### FAKE:WinEventLog
**Hosts:** 14 servers | **vendor_product:** Microsoft Windows | **63 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| EventCode / signature_id | num | 12 | 7036 (430), 4624 (142), 10016 (140), 37 (132), 1014 (99) |
| LogName | str | 3 | System (842), Security (154), Application (4) |
| SourceName | str | 9 | Service Control Manager (430), Microsoft-Windows-Security-Auditing (154), Microsoft-Windows-DistributedCOM (140), Microsoft-Windows-Time-Service (132), Microsoft-Windows-DNS-Client (99) |
| ComputerName / dvc | str | 14 | DC-ATL-01, DC-BOS-02, BACKUP-ATL-01, APP-BOS-01, DC-BOS-01, SQL-PROD-01, FILE-BOS-01 |
| Type | str | 2 | Information (761), Warning (239) |
| Keywords | str | 3 | Classic (846), Audit Success (150), Audit Failure (4) |
| TaskCategory / category | str | 4 | None (846), Logon (146), Special Logon (5), Process Creation (3) |
| action | str | 2 | success (753), failure (243) |
| severity | str | 2 | informational (761), medium (239) |
| signature | str | 9 | Service entered the running/stopped state, An account was successfully logged on, Application-specific permission settings... |
| Logon_Type | num | 3 | 10-Remote (61), 3-Network (47), 2-Interactive (38) |
| Account_Name | str | 101 | Employee account names |
| Account_Domain | str | 2 | FAKETSHIRTCO, - |
| Source_Network_Address | str | 99 | Internal IPs |
| Workstation_Name | str | 86 | Employee workstation names |
| New_Process_Name | str | 2 | powershell.exe, curl.exe (exfil) |
| Process_Command_Line | str | 3 | Exfil commands (Compress-Archive, Base64, curl upload) |
| Failure_Reason | str | 1 | Unknown user name or bad password |
| RecordNumber | num | 500 | Sequential event records |
| app | str | 1 | windows |

### FAKE:XmlWinEventLog:Sysmon
**Hosts:** 27 (servers + workstations) | **vendor_product:** Microsoft Sysmon | **47 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| Event.System.EventID | num | 5 | 1-ProcessCreate (341), 3-NetworkConnect (251), 22-DNSQuery (156), 11-FileCreate (146), 13-RegistryValueSet (106) |
| Event.System.Computer | str | 27 | FQDN hostnames (.theFakeTshirtCompany.com) |
| Event.System.Channel | str | 1 | Microsoft-Windows-Sysmon/Operational |
| Event.System.Provider{@Name} | str | 1 | Microsoft-Windows-Sysmon |
| Event.EventData.Data | str | 500+ | Process paths, usernames, IPs, registry keys (multivalue) |
| Event.EventData.Data{@Name} | str | 43 | Image, ProcessGuid, ProcessId, RuleName, User, UtcTime, Hashes, CommandLine, Company, CurrentDirectory, ParentImage, DestinationIp, DestinationPort, QueryName, TargetFilename, TargetObject |
| Event.System.EventRecordID | num | 500 | 36138-37146 |
| Event.System.Level | num | 1 | 4 (Information) |
| Event.System.Security{@UserID} | str | 1 | S-1-5-18 |
| vendor | str | 1 | Microsoft |
| product | str | 1 | Sysmon |

**Key EventIDs:**
- 1: Process Create - CommandLine, ParentImage, Company, FileVersion
- 3: Network Connection - DestinationIp, DestinationPort, Protocol, SourcePort
- 11: File Create - TargetFilename, CreationUtcTime
- 13: Registry Value Set - TargetObject, Details, EventType
- 22: DNS Query - QueryName, QueryResults, QueryStatus

---

## Linux

### FAKE:cpu
**Hosts:** DEV-ATL-01, DEV-ATL-02, MON-ATL-01, WEB-01, WEB-02 | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metric_name | str | 1 | cpu |
| cpu_load_percent | num | 315 | 10.0-49.9%, mean 24.25 |
| pctUser | num | 234 | 7.0-34.9%, mean 16.98 |
| pctSystem | num | 80 | 2.0-10.0%, mean 4.85 |
| pctIOWait | num | 41 | 1.0-5.0%, mean 2.43 |
| pctIdle | num | 315 | 50.1-90.0%, mean 75.75 |
| cpu_count | num | 1 | 4 |
| dest | str | 5 | Equal distribution across 5 hosts |

### FAKE:vmstat
**Hosts:** Same 5 Linux hosts | **28 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metric_name | str | 1 | memory |
| memTotalMB | num | 2 | 16384 (800), 65536 (200) |
| memUsedMB | num | 500 | 4898-35389, mean 13389 |
| memFreeMB | num | 500 | 3290-32768, mean 12825 |
| memCachedMB | num | 500 | 1974-19660, mean 7695 |
| pctUsed | num | 361 | 29.9-79.9%, mean 50.45 |

### FAKE:df
**Hosts:** Same 5 Linux hosts | **30 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metric_name | str | 1 | disk |
| TotalGB | num | 1 | 500 |
| UsedGB | num | 149 | 200-349, mean 264 |
| AvailGB | num | 149 | 151-300, mean 236 |
| UsedPct | num | 287 | 40.1-70.0%, mean 52.87 |

### FAKE:iostat
**Hosts:** Same 5 Linux hosts | **28 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metric_name | str | 1 | disk_io |
| device | str | 1 | sda |
| rkB_s | num | 500 | 17-4975, mean 1507 |
| wkB_s | num | 500 | 10-1991, mean 596 |
| await | num | 500 | 0.56-18.35ms, mean 7.52 |
| pctUtil | num | 241 | 5.0-30.0%, mean 17.49 |

### FAKE:interfaces
**Hosts:** Same 5 Linux hosts | **28 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| metric_name | str | 1 | network |
| rxKB_s | num | 500 | 157-49798, mean 14123 |
| txKB_s | num | 500 | 42-19951, mean 5942 |
| rxPackets | num | 500 | 2669-2363000, mean 433035 |
| txPackets | num | 500 | 814-972400, mean 180714 |

---

## Web / Retail

### FAKE:access_combined
**Host:** WEB-01 | **vendor_product:** Apache | **29 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| http_method / method | str | 2 | GET (913), POST (87) |
| http_status / status | num | 5 | 200 (954), 304 (17), 301 (15), 500 (9), 404 (5) |
| uri / url | str | 144 | / (83), /products/category/security (40), /checkout (39), /products/category/nerd (39), /cart (38) |
| clientip / src | str | 253 | External IPs (108.28.x, 107.77.x, 174.63.x) |
| bytes | num | 500 | Response sizes |
| response_time | num | 147 | 43-85ms typical |
| referer | str | 144 | google.com (90), theFakeTshirtCompany.com (67), /cart (39) |
| useragent | str | 11 | Chrome, Edge, Safari, Firefox, mobile browsers |
| session_id | str | 271 | sess_* format |
| customer_id | str | 69 | CUST-* or "-" (622 anonymous) |
| order_id | str | 14 | ORD-2026-* or "-" (987) |
| product | str | 46 | IT-themed product slugs |
| product_price | num | 20 | $28-85 |
| qty | num | 2 | 1 (108), 2 (30) |
| cart_items | num | 6 | 1-6 items |
| cart_total | num | 34 | $28-485 |
| q | str | 6 | Search terms: funny+it+tshirts (38), code (30), security (25), coffee (24), linux (23) |
| tshirtcid | str | 271 | UUID correlation IDs |
| http_version | str | 1 | HTTP/1.1 |
| app | str | 1 | apache |

### FAKE:online:order
**NO DATA** - This sourcetype has zero events in the index.

### FAKE:online:order:registry
**Host:** WEB-01 | **vendor_product:** Retail Order System | **32 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| order_id | str | 500 | ORD-2026-* (unique per order) |
| customer_id | str | 400 | CUST-* format |
| session_id | str | 500 | sess_* format |
| products{}.slug | str | 72 | IT-themed product slugs (git-happens-hoodie, ai-overlords-tee, etc.) |
| products{}.price | num | 20 | $28-85 |
| products{}.qty | num | 2 | 1 (1400), 2 (365) |
| cart_total | num | 209 | $28-485, mean $112 |
| tshirtcid | str | 500 | UUID correlation IDs |
| scenario | str | 1 | null |

### FAKE:azure:servicebus
**NO DATA** - This sourcetype has zero events in the index.

---

## ITSM

### FAKE:servicenow:incident
**Host:** servicenow | **vendor_product:** ServiceNow | **52 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| number / ticket_id | str | 226 | INC0000001-INC0000226 (5 state transitions each) |
| state / status | str | 4 | In Progress (371), Closed (226), Resolved (216), New (187) |
| priority / severity / urgency | str | 5 | 3-Moderate (76), 2-High (45), 4-Low (35), 1-Critical (16), 5-Planning (15) |
| impact | str | 4 | 4 (62), 2 (60), 3 (50), 1 (15) |
| category | str | 6 | Hardware (51), Software (41), Infrastructure (36), Network (31), Account (25), Security (3) |
| subcategory | str | 32 | VPN (20), Peripheral (19), Laptop (13), etc. |
| short_description / description | str | 54 | VPN connection slow (10), External monitor no signal (8), etc. |
| assignment_group | str | 7 | Desktop Support (51), Application Support (41), Network Operations (32), Service Desk (26), Database Admins (24), Linux Admins (10), Security Operations (3) |
| assigned_to | str | 14 | desktop.tech1@, desktop.tech2@, app.support1@, etc. |
| caller_id | str | 110 | Employee emails |
| location | str | 4 | Austin (59), Boston (55), Atlanta (54), Boston HQ (19) |
| close_code | str | 2 | Solved (113), Workaround (103) |
| close_notes | str | 40 | Resolution descriptions |
| work_notes | str | 10 | Awaiting vendor response (70), Escalating to next level support (59) |
| cmdb_ci | str | 6 | MON-ATL-01, WEB-01, AUS-WS-BWHITE01, BOS-WS-AMILLER01, SQL-PROD-01, exchange |
| demo_id | str | 7 | disk_filling (29), memory_leak (23), cpu_runaway (14), certificate_expiry (10), ransomware_attempt (10), exfil (9), firewall_misconfig (1) |
| product | str | 1 | Incident Management |

### FAKE:servicenow:cmdb
**NO DATA** - This sourcetype has zero events in the index.

### FAKE:servicenow:change
**Host:** servicenow | **vendor_product:** ServiceNow | **50 fields** | **343 events**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| number / ticket_id | str | 49 | CHG0000001-CHG0000049 (7 state transitions each) |
| state / status | str | 7 | Assess, Authorize, Closed, Implement, New, Review, Scheduled (49 each) |
| type | str | 3 | standard (26), normal (18), emergency (5) |
| priority | str | 2 | 3 (32), 2 (17) |
| risk | str | 3 | Low (26), Moderate (18), High (5) |
| category | str | 6 | Infrastructure (18), Network (13), Database (7), Application (6), Security (3), Software (2) |
| short_description | str | 41 | VLANs, firmware upgrades, DB maintenance, emergencies |
| assignment_group | str | 6 | Linux Admins (14), Network Operations (14), Application Support (10), Database Admins (7), Desktop Support (2), Security Operations (2) |
| assigned_to | str | 12 | linux.admin2@, network.eng1@, etc. |
| close_code | str | 2 | Successful (48), Successful with issues (1) |
| cmdb_ci | str | 6 | WEB-01, AUS-WS-BWHITE01, BOS-WS-AMILLER01, FW-EDGE-01, MON-ATL-01, SQL-PROD-01 |
| demo_id | str | 7 | All 7 scenarios equally represented (7 each) |
| product | str | 1 | Change Management |

---

## Database

### FAKE:mssql:errorlog
**Host:** SQL-PROD-01 | **vendor_product:** Microsoft SQL Server | **30 fields**

| Field | Type | Distinct | Top Values |
|-------|------|----------|------------|
| dest | str | 1 | SQL-PROD-01 |
| demo_id | str | 2 | cpu_runaway (58), exfil (36) |
| DISK | str | 1 | Backup file path (N'G:\Backup\...) |
| NAME | str | 1 | N'TShirtDB-Full Backup' |
| product | str | 1 | SQL Server |
| vendor | str | 1 | Microsoft |
| linecount | num | 2 | 1 (921), 2 (79) - some multiline entries |

---

## CIM Cross-Reference

Common CIM fields and which sourcetypes populate them:

| CIM Field | Sourcetypes |
|-----------|-------------|
| `action` | cisco:asa, azure:aad:signin, azure:aad:audit, access_combined, WinEventLog, o365:messagetrace |
| `src` | cisco:asa, aws:cloudtrail, azure:aad:*, access_combined, o365:messagetrace, meraki:securityappliances |
| `dest` | cisco:asa, aws:cloudtrail, access_combined, meraki:securityappliances, linux (cpu/vmstat/df/iostat/interfaces), Perfmon:*, mssql:errorlog |
| `user` | cisco:asa, aws:cloudtrail, azure:aad:riskDetection, access_combined, WinEventLog |
| `dvc` | cisco:asa, WinEventLog |
| `vendor_product` | ALL sourcetypes (except some Linux metrics) |
| `demo_id` | cisco:asa, aws:cloudtrail, azure:aad:*, gcp:*, webex:*, o365:*, WinEventLog, Sysmon, Perfmon:*, mssql:errorlog, servicenow:* |
| `severity` | WinEventLog, servicenow:incident |
| `signature` | WinEventLog |
| `signature_id` | WinEventLog |
| `app` | aws:cloudtrail (aws), azure:aad:riskDetection (azure:aad), WinEventLog (windows), access_combined (apache) |
| `category` | WinEventLog, azure:aad:*, meraki:* |

## Sourcetypes With No Data

These sourcetypes are defined in props.conf/transforms.conf but have zero events:
- `FAKE:online:order` - Orders expected via generate_orders.py
- `FAKE:azure:servicebus` - ServiceBus expected via generate_servicebus.py
- `FAKE:servicenow:cmdb` - CMDB CIs expected via generate_servicenow.py
- `FAKE:cisco:webex:events` - Legacy webex events format
