# AWS Billing (Cost & Usage Report)

Daily AWS cost data in CUR format showing per-service billing with scenario-driven cost spikes for DDoS (EC2/WAF surge) and exfil (S3 data transfer anomaly).

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `aws:billing:cur` |
| Format | CSV (quoted fields, CUR format) |
| Output File | `output/cloud/aws/aws_billing_cur.csv` |
| Volume | 17 line items/day |
| Account | 123456789012 |
| Region | us-east-1 |
| Baseline Daily Cost | ~$90-100/day |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `identity/TimeInterval` | Billing period | `2026-01-05T00:00:00Z/2026-01-06T00:00:00Z` |
| `lineItem/ProductCode` | AWS service | `AmazonEC2`, `AmazonS3` |
| `lineItem/UsageType` | Usage category | `BoxUsage:t3.large`, `DataTransfer-Out-Bytes` |
| `lineItem/Operation` | Operation type | `RunInstances`, `GetObject` |
| `lineItem/UsageAmount` | Usage quantity | `72.000000` |
| `lineItem/UnblendedCost` | Cost in USD | `5.9904000000` |
| `lineItem/UnblendedRate` | Rate per unit | `0.0832000000` |
| `product/serviceName` | Service display name | `Amazon Elastic Compute Cloud` |
| `resourceTags/user:Name` | Resource tag | `web-prod`, `sql-prod` |
| `demo_id` | Scenario tag | `ddos_attack`, `exfil` |

---

## Billing Line Items (17 services)

| Service | UsageType | Baseline Daily Cost | Notes |
|---------|-----------|-------------------|-------|
| **EC2** | BoxUsage:t3.large | ~$6.00 | Web servers (WEB-01/02) |
| **EC2** | BoxUsage:t3.medium | ~$2.00 | App server |
| **EC2** | BoxUsage:t3.xlarge | ~$4.00 | Database (RDS equivalent) |
| **EC2** | DataTransfer-Out-Bytes | ~$4.50 | Egress traffic |
| **EC2** | EBS:VolumeUsage.gp3 | ~$48.00 | Block storage |
| **S3** | TimedStorage-ByteHrs | ~$11.50 | Object storage |
| **S3** | Requests-Tier1 | ~$0.03 | PUT/POST requests |
| **S3** | Requests-Tier2 | ~$0.01 | GET requests |
| **S3** | DataTransfer-Out-Bytes | ~$1.80 | S3 egress |
| **Lambda** | Lambda-GB-Second | ~$2.50 | Function duration |
| **Lambda** | Request | ~$0.10 | Invocation count |
| **RDS** | InstanceUsage:db.t3.xlarge | ~$6.53 | SQL database |
| **RDS** | StorageIOUsage | ~$0.20 | I/O operations |
| **CloudTrail** | TrailDelivery | ~$1.00 | Audit logging |
| **CloudWatch** | MetricMonitorUsage | ~$5.00 | Monitoring |
| **Config** | ConfigurationItemRecorded | ~$0.60 | Compliance |
| **WAF** | WebACL-Requests | ~$0.60 | Web firewall |

---

## Scenario Cost Impact

### DDoS Attack (Days 18-19)

| Service:UsageType | Normal | DDoS Multiplier | DDoS Daily Cost |
|-------------------|--------|-----------------|-----------------|
| EC2:DataTransfer-Out | ~$4.50 | 4x | ~$18.00 |
| EC2:BoxUsage:t3.large | ~$6.00 | 1.5x | ~$9.00 |
| S3:Requests-Tier2 | ~$0.01 | 2x | ~$0.02 |
| S3:DataTransfer-Out | ~$1.80 | 3x | ~$5.40 |
| Lambda:GB-Second | ~$2.50 | 2x | ~$5.00 |
| Lambda:Request | ~$0.10 | 2.5x | ~$0.25 |
| WAF:WebACL-Requests | ~$0.60 | 5x | ~$3.00 |
| CloudWatch:Metrics | ~$5.00 | 1.5x | ~$7.50 |

**Total daily DDoS impact: ~$90 -> ~$140 (+55%)**

### Exfil (Days 11-13)

| Service:UsageType | Normal | Exfil Multiplier | Exfil Daily Cost |
|-------------------|--------|-----------------|-----------------|
| S3:Requests-Tier2 | ~$0.01 | 1.3x | ~$0.013 |
| S3:DataTransfer-Out | ~$1.80 | 1.5x | ~$2.70 |

**Total daily exfil impact: subtle -- $2.70 vs $1.80 on S3 egress (barely noticeable)**

---

## Example CSV Record

```csv
"f15d054cc1a40e4395fdd3d2890d43c7","2026-01-18T00:00:00Z/2026-01-19T00:00:00Z","2026-01-01T00:00:00Z","2026-02-01T00:00:00Z","123456789012","123456789012","Usage","2026-01-18T00:00:00Z","2026-01-19T00:00:00Z","AmazonEC2","DataTransfer-Out-Bytes","RunInstances","200.000000","18.0000000000","0.0900000000","Data Transfer Out - US East","us-east-1","Amazon Elastic Compute Cloud","web-prod","production","ddos_attack"
```

---

## Use Cases

### 1. Daily cost trend
```spl
index=cloud sourcetype="aws:billing:cur"
| eval cost=tonumber('lineItem/UnblendedCost')
| timechart span=1d sum(cost) AS daily_cost
```

### 2. DDoS cost spike
```spl
index=cloud sourcetype="aws:billing:cur" demo_id=ddos_attack
| eval cost=tonumber('lineItem/UnblendedCost')
| stats sum(cost) AS ddos_cost by lineItem/ProductCode
| sort - ddos_cost
```

### 3. Cost by service
```spl
index=cloud sourcetype="aws:billing:cur"
| eval cost=tonumber('lineItem/UnblendedCost')
| stats sum(cost) AS total by product/serviceName
| sort - total
```

### 4. Exfil S3 cost anomaly
```spl
index=cloud sourcetype="aws:billing:cur" lineItem/ProductCode=AmazonS3 lineItem/UsageType="DataTransfer-Out-Bytes"
| eval cost=tonumber('lineItem/UnblendedCost')
| timechart span=1d sum(cost) AS s3_egress_cost
```

### 5. EC2 data transfer correlation with DDoS
```spl
index=cloud sourcetype="aws:billing:cur" lineItem/ProductCode=AmazonEC2 lineItem/UsageType="DataTransfer-Out-Bytes"
| eval cost=tonumber('lineItem/UnblendedCost')
| timechart span=1d sum(cost) AS ec2_transfer
| appendcols [search index=cloud sourcetype="aws:cloudtrail" eventName=SetAlarmState requestParameters.alarmName="WebServer-HighCPU" | timechart span=1d count AS alarm_count]
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **ddos_attack** | 18-19 | EC2 DataTransfer 4x, WAF 5x, S3 3x -- total daily cost ~55% higher |
| **exfil** | 11-13 | Subtle S3 egress bump (1.5x) -- easy to miss without baselining |

---

## Talking Points

**Cost as a detection signal:**
> "Billing data is an underused detection source. The DDoS attack on Days 18-19 shows a clear cost spike -- EC2 data transfer jumps 4x, WAF request costs 5x. That's a $50/day anomaly that finance or FinOps would notice even if the SOC missed it."

**Subtle exfil cost footprint:**
> "The exfil scenario is more interesting -- the cost anomaly is tiny. S3 egress goes from $1.80 to $2.70/day during the data theft. You'd only catch it with a tight baseline. This shows why billing data alone isn't enough -- you need GuardDuty and CloudTrail too."

---

## Related Sources

- [AWS CloudTrail](aws_cloudtrail.md) - API activity logs
- [AWS GuardDuty](aws_guardduty.md) - Threat detection findings
- [Cisco ASA](cisco_asa.md) - Perimeter traffic correlation
- [Perfmon](perfmon.md) - Server resource metrics
