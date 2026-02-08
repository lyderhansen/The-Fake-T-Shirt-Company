# GCP Audit Logs

Google Cloud Platform audit logs from project faketshirtcompany-prod-01 in us-central1.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `google:gcp:pubsub:message` |
| Format | JSON |
| Output File | `output/cloud/gcp_audit.log` |
| Volume | 30-100 events/day |
| Project | faketshirtcompany-prod-01 |
| Region | us-central1 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `protoPayload.serviceName` | GCP service | `storage.googleapis.com` |
| `protoPayload.methodName` | API method | `storage.objects.get` |
| `protoPayload.authenticationInfo.principalEmail` | Caller identity | `user@domain.com` |
| `protoPayload.requestMetadata.callerIp` | Source IP | `10.10.30.55` |
| `severity` | Log severity | `INFO`, `WARNING`, `ERROR` |
| `resource.type` | Resource type | `gcs_bucket`, `gce_instance` |
| `insertId` | Unique event ID | `abc123xyz` |
| `demo_id` | Scenario tag | `exfil` |

---

## Common Services & Methods

### Cloud Storage
| Method | Description |
|--------|-------------|
| `storage.objects.get` | Download object |
| `storage.objects.list` | List objects |
| `storage.objects.create` | Upload object |
| `storage.objects.delete` | Delete object |
| `storage.buckets.get` | Get bucket info |

### Compute Engine
| Method | Description |
|--------|-------------|
| `compute.instances.list` | List VMs |
| `compute.instances.get` | Get VM details |
| `compute.instances.start` | Start VM |
| `compute.instances.stop` | Stop VM |

### IAM
| Method | Description |
|--------|-------------|
| `iam.serviceAccountKeys.create` | Create SA key |
| `iam.serviceAccountKeys.delete` | Delete SA key |
| `iam.roles.create` | Create custom role |

---

## Example Events

### Storage Object Get (Data Access)
```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.objects.get",
    "authenticationInfo": {
      "principalEmail": "alex.miller@theFakeTshirtCompany.com"
    },
    "requestMetadata": {
      "callerIp": "10.10.30.55"
    },
    "resourceName": "projects/_/buckets/faketshirtco-confidential/objects/employee-salaries.csv"
  },
  "timestamp": "2026-01-12T02:30:00Z",
  "severity": "INFO",
  "resource": {
    "type": "gcs_bucket",
    "labels": {
      "bucket_name": "faketshirtco-confidential",
      "project_id": "faketshirtcompany-prod-01"
    }
  },
  "insertId": "gcs-get-001",
  "demo_id": "exfil"
}
```

### Service Account Key Creation (Persistence)
```json
{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "iam.googleapis.com",
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "authenticationInfo": {
      "principalEmail": "alex.miller@theFakeTshirtCompany.com"
    },
    "requestMetadata": {
      "callerIp": "10.10.30.55"
    },
    "resourceName": "projects/faketshirtcompany-prod-01/serviceAccounts/svc-storage@faketshirtcompany-prod-01.iam.gserviceaccount.com"
  },
  "timestamp": "2026-01-08T11:00:00Z",
  "severity": "NOTICE",
  "demo_id": "exfil"
}
```

### Compute Instance List
```json
{
  "protoPayload": {
    "serviceName": "compute.googleapis.com",
    "methodName": "v1.compute.instances.list",
    "authenticationInfo": {
      "principalEmail": "svc-monitoring@faketshirtcompany-prod-01.iam.gserviceaccount.com"
    }
  },
  "timestamp": "2026-01-05T10:00:00Z",
  "severity": "INFO",
  "resource": {
    "type": "gce_instance"
  }
}
```

---

## Sensitive Buckets

| Bucket | Contents | Risk |
|--------|----------|------|
| `faketshirtco-confidential` | HR/salary data | HIGH - exfil target |
| `faketshirtco-prod-backups` | Production backups | MEDIUM |
| `faketshirtco-logs` | Application logs | LOW |

---

## Use Cases

### 1. Data Exfiltration Detection
Track sensitive data access:
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
  protoPayload.methodName="storage.objects.get"
  demo_id=exfil
| stats count by protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName
| sort - count
```

### 2. Service Account Key Creation
Detect persistence mechanisms:
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
  protoPayload.methodName="*CreateServiceAccountKey*"
| table _time, protoPayload.authenticationInfo.principalEmail, protoPayload.resourceName
```

### 3. Off-Hours Activity
Find suspicious timing:
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by protoPayload.authenticationInfo.principalEmail, protoPayload.methodName
```

### 4. Storage Access by Bucket
Monitor sensitive bucket access:
```spl
index=cloud sourcetype="google:gcp:pubsub:message"
  protoPayload.serviceName="storage.googleapis.com"
| rex field=protoPayload.resourceName "buckets/(?<bucket>[^/]+)"
| stats count by bucket, protoPayload.methodName
| sort - count
```

### 5. Multi-Cloud Correlation
Combine AWS + GCP exfil activity:
```spl
index=cloud (sourcetype=aws:cloudtrail OR sourcetype="google:gcp:pubsub:message")
  demo_id=exfil
| timechart span=1h count by sourcetype
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 8-10 | Service account key creation |
| **exfil** | 11-14 | Storage object downloads at night |

---

## Exfil Attack Pattern

```
Day 8:  CreateServiceAccountKey (persistence)
Day 9:  storage.buckets.get (reconnaissance)
Day 10: storage.objects.list (inventory)
Day 11-14: storage.objects.get (exfiltration)
```

---

## Talking Points

**Persistence:**
> "Day 8 we see CreateServiceAccountKey. The attacker is creating a backdoor - a service account key they can use even if we reset Alex's password."

**Data Theft:**
> "The storage.objects.get calls at 02:00-04:00 are targeting our confidential bucket. Files like 'employee-salaries.csv' and 'customer-database.csv'."

**Multi-Cloud:**
> "The attacker hit both AWS and GCP. Same pattern: create backdoor, enumerate data, exfiltrate at night. They're not just after one cloud."

---

## Related Sources

- [AWS CloudTrail](aws_cloudtrail.md) - Multi-cloud correlation
- [Entra ID](entraid.md) - User authentication
- [Cisco ASA](cisco_asa.md) - Network exfil

