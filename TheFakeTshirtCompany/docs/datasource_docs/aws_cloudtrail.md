# AWS CloudTrail

AWS API activity logs from account 123456789012 in us-east-1, covering 8 services and 18+ event types with scenario-driven detection events.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `aws:cloudtrail` |
| Format | JSON (NDJSON) |
| Output File | `output/cloud/aws/aws_cloudtrail.json` |
| Volume | ~150-200 events/day (baseline), ~200-250 with scenarios |
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
| `readOnly` | Read or write event | `true`, `false` |
| `managementEvent` | Management plane event | `true` |
| `errorCode` | Error (if any) | `AccessDenied` |
| `demo_id` | Scenario tag | `exfil`, `ddos_attack` |

---

## Event Types (18 baseline + 3 scenario-only)

| Service | eventSource | Event | Distribution | Notes |
|---------|-------------|-------|-------------|-------|
| S3 | `s3.amazonaws.com` | GetObject | 16% | Data access |
| S3 | `s3.amazonaws.com` | PutObject | 12% | Data writes |
| S3 | `s3.amazonaws.com` | DeleteObject | 3% | Cleanup/lifecycle |
| EC2 | `ec2.amazonaws.com` | DescribeInstances | 10% | Instance monitoring |
| EC2 | `ec2.amazonaws.com` | RunInstances | 3% | Instance launches |
| EC2 | `ec2.amazonaws.com` | TerminateInstances | 2% | Instance termination |
| Lambda | `lambda.amazonaws.com` | Invoke | 15% | Function execution |
| IAM | `iam.amazonaws.com` | ListUsers | 6% | User enumeration |
| IAM | `iam.amazonaws.com` | CreateAccessKey | 2% | Key rotation |
| IAM | `iam.amazonaws.com` | DeleteAccessKey | 2% | Key rotation |
| STS | `sts.amazonaws.com` | GetCallerIdentity | 6% | Identity verification |
| STS | `sts.amazonaws.com` | AssumeRole | 7% | Role assumption |
| IAM | `signin.amazonaws.com` | ConsoleLogin | 5% | Console sign-ins |
| CloudWatch Logs | `logs.amazonaws.com` | PutLogEvents | 4% | Log ingestion |
| Secrets Manager | `secretsmanager.amazonaws.com` | GetSecretValue | 3% | Credential access |
| CloudWatch | `monitoring.amazonaws.com` | DescribeAlarms | 2% | Alarm monitoring |
| Config | `config.amazonaws.com` | StartConfigRulesEvaluation | 1% | Compliance checks |
| Config | `config.amazonaws.com` | PutEvaluations | 1% | Compliance results |
| IAM | `iam.amazonaws.com` | CreateUser | scenario | Exfil backdoor (Day 8) |
| IAM | `iam.amazonaws.com` | AttachUserPolicy | scenario | Exfil privesc (Day 8) |
| CloudWatch | `monitoring.amazonaws.com` | SetAlarmState | scenario | Alarm state changes |

---

## Example Events

### S3 GetObject (Data Access)
```json
{"eventTime": "2026-01-12T03:15:00Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "userIdentity": {"type": "IAMUser", "userName": "alex.miller"}, "sourceIPAddress": "10.10.30.55", "requestParameters": {"bucketName": "faketshirtcompany-prod-data", "key": "reports/q4-financial.xlsx"}, "readOnly": true, "demo_id": "exfil"}
```

### EC2 RunInstances (DDoS auto-scaling)
```json
{"eventTime": "2026-01-18T09:15:00Z", "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "userIdentity": {"type": "AssumedRole"}, "requestParameters": {"instanceType": "t3.large", "minCount": 1, "maxCount": 1}, "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0autoscale001"}]}}, "demo_id": "ddos_attack"}
```

### Secrets Manager GetSecretValue (exfil credential theft)
```json
{"eventTime": "2026-01-09T10:30:00Z", "eventSource": "secretsmanager.amazonaws.com", "eventName": "GetSecretValue", "userIdentity": {"type": "IAMUser", "userName": "svc-datasync"}, "sourceIPAddress": "185.220.101.42", "requestParameters": {"secretId": "prod/database/credentials"}, "demo_id": "exfil"}
```

### CloudWatch SetAlarmState (DDoS alarm)
```json
{"eventTime": "2026-01-18T09:00:00Z", "eventSource": "monitoring.amazonaws.com", "eventName": "SetAlarmState", "requestParameters": {"alarmName": "WebServer-HighCPU", "stateValue": "ALARM", "stateReason": "Threshold crossed"}, "demo_id": "ddos_attack"}
```

---

## Sensitive Buckets

| Bucket | Contents | Risk |
|--------|----------|------|
| `faketshirtcompany-prod-data` | Production data | HIGH - exfil target |
| `faketshirtcompany-backups` | Backups | MEDIUM |
| `faketshirtcompany-logs` | Audit logs | MEDIUM |

---

## Use Cases

### 1. Data exfiltration detection
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=GetObject demo_id=exfil
| stats count, dc(requestParameters.key) AS unique_files by userIdentity.userName, requestParameters.bucketName
| sort - count
```

### 2. IAM backdoor detection
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName IN ("CreateUser", "AttachUserPolicy")
| table _time, userIdentity.userName, eventName, requestParameters.userName, requestParameters.policyArn
```

### 3. Credential theft detection
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=GetSecretValue
| eval suspicious=if(like(sourceIPAddress,"185.%"),1,0)
| where suspicious=1
| table _time, userIdentity.userName, sourceIPAddress, requestParameters.secretId
```

### 4. DDoS auto-scaling response
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" demo_id=ddos_attack
| table _time, eventName, requestParameters.alarmName, requestParameters.instanceType
| sort _time
```

### 5. CloudWatch alarm history
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=SetAlarmState
| table _time, requestParameters.alarmName, requestParameters.stateValue, demo_id
```

### 6. Off-hours activity
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail"
| eval hour=strftime(_time, "%H")
| where hour < 6 OR hour > 22
| stats count by userIdentity.userName, eventName, hour
```

### 7. All event types overview
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudtrail"
| stats count by eventName, eventSource
| sort - count
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 8 | CreateUser "svc-datasync", AttachUserPolicy AdministratorAccess |
| **exfil** | 9 | GetSecretValue -- attacker fetches DB credentials from Secrets Manager |
| **exfil** | 11-13 | S3 GetObject mass data theft (off-hours) |
| **ddos_attack** | 18-19 | RunInstances auto-scaling, SetAlarmState WebServer-HighCPU |
| **memory_leak** | 8-9 | SetAlarmState Lambda-ErrorRate |
| **cpu_runaway** | 11-12 | SetAlarmState Database-ConnectionCount |

---

## Exfil Attack Pattern

```
Day 8:  CreateUser "svc-datasync"
Day 8:  AttachUserPolicy AdministratorAccess
Day 9:  GetSecretValue "prod/database/credentials" (from threat IP 185.220.101.42)
Day 10: S3 access begins
Day 11-13: Mass GetObject at 01:00-05:00
```

---

## Talking Points

**Backdoor detection:**
> "Day 8 we see CreateUser followed by AttachUserPolicy with AdministratorAccess. That's a textbook backdoor. Then Day 9, the new 'svc-datasync' user fetches database credentials from Secrets Manager -- from a German IP address."

**DDoS response:**
> "When the DDoS hits on Day 18, you can see CloudWatch alarms firing -- WebServer-HighCPU goes to ALARM state. Auto-scaling kicks in with RunInstances. The billing data shows the cost impact: EC2 data transfer spikes 4x."

**Cross-correlation:**
> "Correlate the CloudTrail GetSecretValue with MSSQL connection logs -- the attacker used those stolen credentials. Combine with GuardDuty findings for the detection timeline."

---

## Related Sources

- [AWS GuardDuty](aws_guardduty.md) - Threat detection findings
- [AWS Billing](aws_billing.md) - Cost anomaly detection
- [GCP Audit](gcp_audit.md) - Multi-cloud correlation
- [Entra ID](entraid.md) - User authentication
- [Cisco ASA](cisco_asa.md) - Network exfil correlation

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | [Splunk Add-on for AWS](https://splunkbase.splunk.com/app/1876) |
| **Ingestion** | S3 bucket polling via SQS, or Kinesis Firehose push to HEC |
| **Real sourcetype** | `aws:cloudtrail` -- matches our generator exactly |
