# AWS CloudTrail

AWS API activity logs from account 123456789012 in us-east-1.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `aws:cloudtrail` |
| Format | JSON |
| Output File | `output/cloud/aws_cloudtrail.log` |
| Volume | 50-200 events/day |
| Account | 123456789012 |
| Region | us-east-1 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `eventTime` | ISO 8601 timestamp | `2026-01-05T14:23:45Z` |
| `eventSource` | AWS service | `s3.amazonaws.com` |
| `eventName` | API call | `GetObject` |
| `userIdentity.type` | Identity type | `IAMUser`, `AssumedRole` |
| `userIdentity.userName` | User/role name | `alex.miller` |
| `sourceIPAddress` | Caller IP | `10.10.30.55` |
| `awsRegion` | AWS region | `us-east-1` |
| `requestParameters` | Request details | `{"bucketName": "..."}` |
| `responseElements` | Response data | `{"status": "success"}` |
| `errorCode` | Error (if any) | `AccessDenied` |
| `demo_id` | Scenario tag | `exfil` |

---

## Common Event Sources

| Service | eventSource | Common Events |
|---------|-------------|---------------|
| S3 | `s3.amazonaws.com` | GetObject, PutObject, ListBucket, DeleteObject |
| EC2 | `ec2.amazonaws.com` | DescribeInstances, StartInstances, StopInstances |
| IAM | `iam.amazonaws.com` | CreateUser, AttachUserPolicy, DeleteUser |
| Lambda | `lambda.amazonaws.com` | InvokeFunction, CreateFunction |
| CloudTrail | `cloudtrail.amazonaws.com` | LookupEvents |

---

## Example Events

### S3 GetObject (Data Access)
```json
{
  "eventTime": "2026-01-12T03:15:00Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alex.miller"
  },
  "sourceIPAddress": "10.10.30.55",
  "awsRegion": "us-east-1",
  "requestParameters": {
    "bucketName": "faketshirtco-financial-reports",
    "key": "2026/q4/annual-financial-report.xlsx"
  },
  "responseElements": null,
  "demo_id": "exfil"
}
```

### IAM CreateUser (Backdoor)
```json
{
  "eventTime": "2026-01-08T10:45:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "CreateUser",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alex.miller"
  },
  "sourceIPAddress": "10.10.30.55",
  "requestParameters": {
    "userName": "svc-datasync"
  },
  "responseElements": {
    "user": {
      "userName": "svc-datasync",
      "userId": "AIDA...",
      "arn": "arn:aws:iam::123456789012:user/svc-datasync"
    }
  },
  "demo_id": "exfil"
}
```

### IAM AttachUserPolicy (Privilege Escalation)
```json
{
  "eventTime": "2026-01-08T10:46:00Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "AttachUserPolicy",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alex.miller"
  },
  "requestParameters": {
    "userName": "svc-datasync",
    "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
  },
  "demo_id": "exfil"
}
```

### EC2 DescribeInstances
```json
{
  "eventTime": "2026-01-05T09:00:00Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "DescribeInstances",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "data-pipeline"
  },
  "sourceIPAddress": "10.10.20.50",
  "awsRegion": "us-east-1"
}
```

### Lambda Invoke
```json
{
  "eventTime": "2026-01-05T14:30:00Z",
  "eventSource": "lambda.amazonaws.com",
  "eventName": "Invoke",
  "userIdentity": {
    "type": "AssumedRole",
    "sessionContext": {
      "sessionIssuer": {
        "userName": "order-processor-role"
      }
    }
  },
  "requestParameters": {
    "functionName": "process-orders"
  }
}
```

---

## Sensitive Buckets

| Bucket | Contents | Risk |
|--------|----------|------|
| `faketshirtco-financial-reports` | Financial data | HIGH - exfil target |
| `faketshirtco-prod-data` | Production data | MEDIUM |
| `faketshirtco-backups` | Backups | MEDIUM |

---

## Use Cases

### 1. Data Exfiltration Detection
Track large data downloads:
```spl
index=cloud sourcetype=aws:cloudtrail eventName=GetObject demo_id=exfil
| stats count, dc(requestParameters.key) AS unique_files by userIdentity.userName, requestParameters.bucketName
| sort - count
```

### 2. IAM Backdoor Detection
Find suspicious user creation:
```spl
index=cloud sourcetype=aws:cloudtrail eventName=CreateUser
| table _time, userIdentity.userName, requestParameters.userName
```

### 3. Privilege Escalation
Track admin policy attachments:
```spl
index=cloud sourcetype=aws:cloudtrail eventName=AttachUserPolicy
| where match(requestParameters.policyArn, "Administrator")
| table _time, userIdentity.userName, requestParameters.userName, requestParameters.policyArn
```

### 4. Sensitive Bucket Access
Monitor financial data access:
```spl
index=cloud sourcetype=aws:cloudtrail eventName IN ("GetObject", "PutObject", "ListBucket")
  requestParameters.bucketName="faketshirtco-financial-reports"
| timechart span=1h count by eventName
```

### 5. Off-Hours Activity
Detect unusual access times:
```spl
index=cloud sourcetype=aws:cloudtrail
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by userIdentity.userName, eventName, hour
```

### 6. Exfil Timeline
Full AWS activity during exfil:
```spl
index=cloud sourcetype=aws:cloudtrail demo_id=exfil
| timechart span=1d count by eventName
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 8-10 | IAM backdoor creation (CreateUser, AttachUserPolicy) |
| **exfil** | 11-14 | S3 data exfiltration (GetObject at night) |

---

## Exfil Attack Pattern

```
Day 8:  CreateUser "svc-datasync"
Day 8:  AttachUserPolicy AdministratorAccess
Day 9:  ListBucket on financial bucket
Day 10: First GetObject test
Day 11-14: Mass GetObject at 01:00-05:00
```

---

## Talking Points

**Backdoor Detection:**
> "Day 8 we see CreateUser followed immediately by AttachUserPolicy with AdministratorAccess. That's a textbook backdoor - creating a service account with full admin rights."

**Exfil Pattern:**
> "Look at the timing: GetObject calls between 01:00 and 05:00. The attacker knows our traffic patterns and chose the quiet hours. Files like 'annual-financial-report.xlsx' and 'merger-plans-2025.docx'."

**Who Did It:**
> "All these actions trace back to alex.miller's credentials. But we know from Entra ID that Alex's account was compromised. The real attacker is using stolen credentials."

---

## Related Sources

- [GCP Audit](gcp_audit.md) - Multi-cloud correlation
- [Entra ID](entraid.md) - User authentication
- [Cisco ASA](cisco_asa.md) - Network exfil correlation

