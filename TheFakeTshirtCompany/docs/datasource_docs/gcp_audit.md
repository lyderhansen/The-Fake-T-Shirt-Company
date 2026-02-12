# GCP Audit Logs

Google Cloud Platform audit logs from project faketshirtcompany-prod-01 in us-central1, covering 7 services and 15+ event types with scenario-driven detection events.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `google:gcp:pubsub:message` |
| Format | JSON (NDJSON) |
| Output File | `output/cloud/gcp/gcp_audit.json` |
| Volume | ~100-130 events/day (baseline), ~130-160 with scenarios |
| Project | faketshirtcompany-prod-01 |
| Region | us-central1 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 timestamp | `2026-01-05T14:23:45.123456Z` |
| `protoPayload.serviceName` | GCP service | `storage.googleapis.com` |
| `protoPayload.methodName` | API method | `storage.objects.get` |
| `protoPayload.authenticationInfo.principalEmail` | Caller identity | `svc-storage@...iam.gserviceaccount.com` |
| `protoPayload.requestMetadata.callerIp` | Source IP | `10.10.30.55` |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | Caller tool | `google-cloud-sdk/462.0.1 gcloud/462.0.1` |
| `protoPayload.status.code` | gRPC status (0=OK) | `0`, `7`, `8` |
| `protoPayload.authorizationInfo[].granted` | Permission granted | `true`, `false` |
| `severity` | Log severity | `INFO`, `ERROR` |
| `resource.type` | Resource type | `gcs_bucket`, `gce_instance`, `bigquery_dataset` |
| `logName` | Audit log type | `...cloudaudit.googleapis.com%2Factivity` |
| `insertId` | Unique event ID | `abc123def456` |
| `receiveTimestamp` | Pipeline receive time | `2026-01-05T14:23:45.234567Z` |
| `demo_id` | Scenario tag | `exfil`, `cpu_runaway` |

---

## Event Types (15 baseline + 4 scenario-only)

| Service | methodName | Distribution | Log Type | Notes |
|---------|-----------|-------------|----------|-------|
| Compute Engine | `v1.compute.instances.list` | 14% | admin_activity | Instance monitoring |
| Cloud Storage | `storage.objects.get` | 28% | admin + data_access | Object reads (split) |
| Cloud Storage | `storage.objects.create` | 7% | admin_activity | Object writes |
| Cloud Storage | `storage.objects.delete` | 3% | admin_activity | Lifecycle cleanup |
| Cloud Storage | `storage.buckets.get` | 3% | admin_activity | Bucket metadata |
| Cloud Functions | `CloudFunctionsService.CallFunction` | 11% | admin_activity | Function execution |
| BigQuery | `jobservice.jobcompleted` | 10% | admin_activity | Query completion |
| BigQuery | `TableDataService.List` | 3% | data_access | Table data reads |
| Compute Engine | `v1.compute.instances.start/stop` | 4% | admin_activity | Instance lifecycle |
| IAM | `CreateServiceAccountKey` | 2% | admin_activity | SA key rotation |
| IAM | `SetIamPolicy` | 2% | admin_activity | Role grants/revokes |
| Compute Engine | `v1.compute.instances.get` | 4% | data_access | Instance details |
| Cloud Logging | `LoggingServiceV2.WriteLogEntries` | 6% | admin_activity | App log ingestion |
| Cloud Logging | `LoggingServiceV2.ListLogEntries` | 3% | data_access | Log queries |
| IAM | `CreateServiceAccount` | scenario | admin_activity | Exfil Day 8 |
| Cloud Storage | `storage.buckets.getIamPolicy` | scenario | admin_activity | Exfil Day 7 |
| Cloud Storage | `storage.objects.list` | scenario | data_access | Exfil Day 11 |
| IAM | `SetIamPolicy` (malicious) | scenario | admin_activity | Exfil Day 8 |

---

## GCP Configuration

| Resource | Details |
|----------|---------|
| **Service Accounts** | svc-compute, svc-storage, svc-functions |
| **Buckets** | faketshirtcompany-data, faketshirtcompany-backups, faketshirtcompany-exports |
| **Instances** | instance-prod-1, instance-prod-2, instance-web-1 |
| **Functions** | processData, sendAlerts, transformRecords |
| **BigQuery Datasets** | analytics, reporting, warehouse |

### Sensitive Buckets

| Bucket | Contents | Risk |
|--------|----------|------|
| `faketshirtco-confidential` | HR/salary data | HIGH - exfil target |
| `faketshirtcompany-exports` | Export staging | HIGH - exfil staging area |
| `faketshirtcompany-backups` | Production backups | MEDIUM |
| `faketshirtcompany-data` | Application data | MEDIUM |

---

## Example Events

### Cloud Storage Get Object (Data Access)
```json
{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "storage.googleapis.com", "methodName": "storage.objects.get", "authenticationInfo": {"principalEmail": "svc-storage@faketshirtcompany-prod-01.iam.gserviceaccount.com"}, "authorizationInfo": [{"permission": "storage.objects.get", "resource": "projects/faketshirtcompany-prod-01", "granted": true}], "requestMetadata": {"callerIp": "10.10.30.55", "callerSuppliedUserAgent": "google-api-python-client/2.108.0"}, "resourceName": "projects/_/buckets/faketshirtcompany-data/objects/data_4523.json", "status": {"code": 0, "message": ""}}, "insertId": "abc123", "resource": {"type": "gcs_bucket", "labels": {"project_id": "faketshirtcompany-prod-01", "zone": "us-central1"}}, "timestamp": "2026-01-12T02:30:00.123456Z", "receiveTimestamp": "2026-01-12T02:30:00.456789Z", "severity": "INFO", "logName": "projects/faketshirtcompany-prod-01/logs/cloudaudit.googleapis.com%2Fdata_access", "demo_id": "exfil"}
```

### BigQuery Pipeline Error (CPU Runaway)
```json
{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "bigquery.googleapis.com", "methodName": "jobservice.jobcompleted", "authenticationInfo": {"principalEmail": "svc-compute@faketshirtcompany-prod-01.iam.gserviceaccount.com"}, "resourceName": "projects/faketshirtcompany-prod-01/datasets/warehouse/tables/daily_orders", "status": {"code": 8, "message": "RESOURCE_EXHAUSTED: Data source connection failed - upstream database unavailable"}, "serviceData": {"jobCompletedEvent": {"job": {"jobStatus": {"state": "DONE", "errorResult": {"reason": "resourcesExceeded", "message": "Data source connection timeout after 300s"}}, "jobStatistics": {"totalBilledBytes": "0"}}}}}, "severity": "ERROR", "demo_id": "cpu_runaway"}
```

### Cloud Logging ListLogEntries (Exfil - Checking for Detection)
```json
{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "logging.googleapis.com", "methodName": "google.logging.v2.LoggingServiceV2.ListLogEntries", "authenticationInfo": {"principalEmail": "svc-gcs-sync@faketshirtcompany-prod-01.iam.gserviceaccount.com"}, "requestMetadata": {"callerIp": "185.220.101.42"}, "request": {"resourceNames": ["projects/faketshirtcompany-prod-01"], "filter": "protoPayload.methodName=\"google.iam.admin.v1.CreateServiceAccountKey\"", "pageSize": 100}}, "severity": "INFO", "logName": "projects/faketshirtcompany-prod-01/logs/cloudaudit.googleapis.com%2Fdata_access", "demo_id": "exfil"}
```

---

## Use Cases

### 1. Data exfiltration detection
```spl
index=cloud sourcetype="google:gcp:pubsub:message" demo_id=exfil
| stats count by protoPayload.methodName, protoPayload.authenticationInfo.principalEmail
| sort - count
```

### 2. Threat actor IP activity
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
    protoPayload.requestMetadata.callerIp="185.220.101.42"
| table _time, protoPayload.methodName, protoPayload.resourceName, severity
| sort _time
```

### 3. IAM persistence detection
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
    protoPayload.methodName IN ("google.iam.admin.v1.CreateServiceAccount",
    "google.iam.admin.v1.CreateServiceAccountKey", "google.iam.admin.v1.SetIamPolicy")
| table _time, protoPayload.authenticationInfo.principalEmail,
    protoPayload.methodName, protoPayload.resourceName
| sort _time
```

### 4. Off-hours activity
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by protoPayload.authenticationInfo.principalEmail,
    protoPayload.methodName, hour
```

### 5. Cloud Logging reconnaissance (attacker checking for detection)
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
    protoPayload.methodName="*ListLogEntries*"
| table _time, protoPayload.authenticationInfo.principalEmail,
    protoPayload.requestMetadata.callerIp, protoPayload.request.filter
```

### 6. BigQuery pipeline failures (cpu_runaway correlation)
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
    protoPayload.serviceName="bigquery.googleapis.com" severity=ERROR
| table _time, protoPayload.resourceName, protoPayload.status.message, demo_id
```

### 7. Multi-cloud exfil correlation (AWS + GCP)
```spl
index=cloud (sourcetype="aws:cloudtrail" OR sourcetype="google:gcp:pubsub:message")
    demo_id=exfil
| timechart span=1h count by sourcetype
```

### 8. Storage access by bucket
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
    protoPayload.serviceName="storage.googleapis.com"
| rex field=protoPayload.resourceName "buckets/(?<bucket>[^/]+)"
| stats count by bucket, protoPayload.methodName
| sort - count
```

### 9. Error rate by service
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
| stats count AS total, count(eval(severity="ERROR")) AS errors
    by protoPayload.serviceName
| eval error_pct=round(errors/total*100, 1)
| sort - error_pct
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 7 | Bucket IAM recon (getBucketIamPolicy) |
| **exfil** | 8 | Create malicious SA, grant storage.admin, create SA key |
| **exfil** | 10 | ListLogEntries -- attacker checks if SA creation was detected |
| **exfil** | 11 | List objects in sensitive bucket (discovery) |
| **exfil** | 11-12 | GCS object exfiltration (03:00-04:00, 2-4 files/hour) |
| **exfil** | 12 | BigQuery tabledata.list -- second exfil channel (customer_database) |
| **exfil** | 13 | Delete staging files from exports bucket (cover tracks) |
| **cpu_runaway** | 11-12 | BigQuery RESOURCE_EXHAUSTED errors (data pipeline failure from SQL-PROD-01 down) |

---

## Exfil Attack Pattern

```
Day 7:   getBucketIamPolicy (recon -- check bucket permissions)
Day 8:   CreateServiceAccount "svc-gcs-sync"
Day 8:   SetIamPolicy roles/storage.admin on svc-gcs-sync
Day 8:   CreateServiceAccountKey (persistence -- key for later use)
Day 10:  ListLogEntries (checking for detection -- "was my SA creation logged?")
Day 11:  storage.objects.list on confidential bucket (discovery)
Day 11:  storage.objects.get x2-4 at 03:00-04:00 (exfil night 1)
Day 12:  storage.objects.get x2-4 at 03:00-04:00 (exfil night 2)
Day 12:  BigQuery tabledata.list on warehouse/customer_database (second channel)
Day 13:  storage.objects.delete x2-4 on exports/staging/* (cover tracks)
```

---

## Talking Points

**Multi-cloud persistence:**
> "The attacker doesn't just hit AWS. On Day 8, they create a service account in GCP with storage.admin -- a backdoor that survives password resets. Then Day 10, they check Cloud Logging to see if anyone noticed. That's operational security awareness."

**Second exfil channel:**
> "GCS isn't the only data theft vector. On Day 12, the attacker also reads BigQuery tabledata -- the customer database table. So even if you catch the storage exfil, they already pulled analytics data through a different service."

**Cover tracks:**
> "Day 13 is interesting -- 3 staging file deletions from the exports bucket at 5 AM. The attacker cleans up after themselves. If you only alert on data access, you miss the cleanup. The delete operations are the 'anti-forensics' phase."

**Cross-cloud correlation:**
> "Put AWS CloudTrail next to GCP audit logs during the exfil window (Days 11-13). The attacker is running the same playbook in both clouds: create backdoor, stage data, exfil at night. The timing overlap is the smoking gun."

**CPU runaway cross-cloud impact:**
> "When SQL-PROD-01 goes down on Day 11, it's not just Windows Perfmon that shows it. BigQuery's data pipeline fails too -- RESOURCE_EXHAUSTED errors because the upstream database is unavailable. This is how on-prem incidents cascade into cloud."

---

## Related Sources

- [AWS CloudTrail](aws_cloudtrail.md) - Multi-cloud exfil correlation
- [AWS GuardDuty](aws_guardduty.md) - Threat detection findings
- [Entra ID](entraid.md) - User authentication
- [Cisco ASA](cisco_asa.md) - Network exfil traffic
- [Perfmon](perfmon.md) - CPU runaway server metrics
- [MSSQL](mssql.md) - Database connection failures (cpu_runaway)
