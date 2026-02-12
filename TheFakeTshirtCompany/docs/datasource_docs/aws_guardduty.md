# AWS GuardDuty

AWS GuardDuty threat detection findings providing automated security monitoring with baseline noise and scenario-injected high-severity detections.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `aws:cloudwatch:guardduty` |
| Format | NDJSON |
| Output File | `output/cloud/aws/aws_guardduty.json` |
| Volume | Baseline: 3-8/day (low severity), Scenario: +3-6/day (high severity) |
| Account | 123456789012 |
| Region | us-east-1 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `type` | Finding type | `UnauthorizedAccess:IAMUser/MaliciousIPCaller` |
| `severity` | Severity (0.1-10.0) | `8.0` |
| `title` | Finding title | `API CreateUser was invoked from a known malicious IP` |
| `description` | Detailed description | `An API was called from IP 185.220.101.42...` |
| `resource.resourceType` | Affected resource | `AccessKey`, `Instance` |
| `service.action.actionType` | Action type | `AWS_API_CALL`, `NETWORK_CONNECTION` |
| `service.count` | Event count | `1` |
| `createdAt` | Finding creation time | `2026-01-08T10:30:00Z` |
| `demo_id` | Scenario tag | `exfil`, `ransomware_attempt` |

---

## Finding Types

### Baseline (daily noise, severity 1-3)

| Type | Severity | Frequency | Description |
|------|----------|-----------|-------------|
| `Recon:EC2/PortProbeUnprotectedPort` | 2.0 | 2-3/day | Internet scanners probing open ports |
| `Recon:EC2/Portscan` | 2.0 | 2-3/day | Port scanning activity detected |
| `UnauthorizedAccess:S3/TorIPCaller` | 3.0 | 1-2/day | S3 API call from Tor exit node |
| `Policy:IAMUser/RootCredentialUsage` | 1.0 | 1-2/day | Root account usage compliance finding |

### Exfil Scenario (days 8-13, severity 7-8)

| Type | Severity | Day | Description |
|------|----------|-----|-------------|
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | 8.0 | 8 | API CreateUser from threat IP 185.220.101.42 |
| `Persistence:IAMUser/UserPermissions` | 7.0 | 8 | AdministratorAccess attached to new user |
| `Exfiltration:S3/AnomalousBehavior` | 8.0 | 11-13 | Anomalous S3 download pattern (off-hours) |

### Ransomware Scenario (day 8, severity 5)

| Type | Severity | Day | Description |
|------|----------|-----|-------------|
| `UnauthorizedAccess:EC2/MaliciousIPCaller` | 5.0 | 8 | EC2 connection attempt from known malicious IP |

---

## Example Events

### Baseline - Port Probe
```json
{"schemaVersion": "2.0", "accountId": "123456789012", "region": "us-east-1", "id": "abc123", "type": "Recon:EC2/PortProbeUnprotectedPort", "severity": 2.0, "title": "Unprotected port on EC2 instance is being probed", "createdAt": "2026-01-05T14:00:00Z"}
```

### Exfil - Malicious IP Caller
```json
{"schemaVersion": "2.0", "accountId": "123456789012", "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "severity": 8.0, "title": "API CreateUser was invoked from a known malicious IP", "resource": {"resourceType": "AccessKey", "accessKeyDetails": {"userName": "alex.miller"}}, "service": {"action": {"actionType": "AWS_API_CALL", "awsApiCallAction": {"api": "CreateUser", "callerType": "Remote IP", "remoteIpDetails": {"ipAddressV4": "185.220.101.42"}}}}, "demo_id": "exfil"}
```

---

## Use Cases

### 1. High-severity findings
```spl
index=cloud sourcetype="aws:cloudwatch:guardduty" severity>=7
| table _time, type, severity, title, demo_id
| sort - severity
```

### 2. Exfil detection timeline
```spl
index=cloud sourcetype="aws:cloudwatch:guardduty" demo_id=exfil
| table _time, type, severity, title
| sort _time
```

### 3. Finding type distribution
```spl
index=cloud sourcetype="aws:cloudwatch:guardduty"
| stats count, avg(severity) AS avg_sev by type
| sort - avg_sev
```

### 4. Cross-correlate with CloudTrail
```spl
index=cloud (sourcetype="aws:cloudwatch:guardduty" severity>=7) OR (sourcetype="aws:cloudtrail" eventName IN ("CreateUser","AttachUserPolicy","GetSecretValue") demo_id=exfil)
| table _time, sourcetype, type, eventName, severity
| sort _time
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 8 | MaliciousIPCaller (sev 8), UserPermissions (sev 7) |
| **exfil** | 11-13 | S3/AnomalousBehavior (sev 8) -- one per day |
| **ransomware_attempt** | 8 | EC2/MaliciousIPCaller (sev 5) |

---

## Talking Points

**Why GuardDuty matters:**
> "GuardDuty is the native AWS threat detector. On Day 8, it fires immediately when the attacker's German IP creates a backdoor user. Severity 8 -- that's a critical finding. If the SOC had alert routing configured, this would have stopped the breach before exfiltration."

**Detection timeline:**
> "Follow the GuardDuty findings: Day 8 we get two findings -- the malicious IP and the persistence activity. Days 11-13, three more findings for anomalous S3 behavior. Five high-severity findings total. Cross-reference with CloudTrail to see exactly what the attacker did."

---

## Related Sources

- [AWS CloudTrail](aws_cloudtrail.md) - API activity logs
- [AWS Billing](aws_billing.md) - Cost anomaly detection
- [Cisco Secure Access](secure_access.md) - DNS/proxy C2 detection
- [Entra ID](entraid.md) - Identity compromise
