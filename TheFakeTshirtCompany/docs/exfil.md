# Exfil Scenario - APT Data Exfiltration

A 14-day APT-style attack where a threat actor from Germany compromises an IT admin in Atlanta, moves laterally to Boston, and exfiltrates sensitive financial data across AWS and GCP.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 14 days |
| Category | Attack |
| demo_id | `exfil` |
| Outcome | Successful data theft |
| Log Sources | 18 (see full list below) |

### Attack Path
```
Frankfurt (Threat Actor) -> Atlanta (Initial Access) -> Boston (Target) -> AWS/GCP (Exfil)
```

---

## Key Personnel

### Initial Compromise
| Attribute | Value |
|-----------|-------|
| Name | Jessica Brown |
| Role | IT Administrator |
| Location | Atlanta |
| Email | jessica.brown@theFakeTshirtCompany.com |
| Hostname | ATL-WS-JBROWN01 |
| IP | 10.20.30.15 |

### Primary Target
| Attribute | Value |
|-----------|-------|
| Name | Alex Miller |
| Role | Sr. Financial Analyst |
| Location | Boston |
| Email | alex.miller@theFakeTshirtCompany.com |
| Hostname | BOS-WS-AMILLER01 |
| IP | 10.10.30.55 |

### Threat Actor
| Attribute | Value |
|-----------|-------|
| IP | 185.220.101.42 |
| Location | Frankfurt, Germany |
| ASN | AS205100 (F3 Netze e.V.) |

---

## Phishing Details

| Attribute | Value |
|-----------|-------|
| Fake Domain | `rnicrosoft-security.com` (note: "rn" looks like "m") |
| Sender | security@rnicrosoft-security.com |
| Subject | "Action Required: Verify your account security" |
| URL | https://rnicrosoft-security.com/verify?token=a8f3d9c2 |
| Recipient | jessica.brown@theFakeTshirtCompany.com |
| Sent | Day 1, 16:42 |

---

## Day-by-Day Timeline

### Days 1-3: Reconnaissance

**What happens:**
- Threat actor scans network from external IP
- Port scanning: 22, 80, 443, 445, 1433, 3389
- Phishing email sent to Jessica Brown (Day 1)

**Time:** 20:00-23:00 (primarily evening hours)

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| ASA | Port scans blocked | `index=fake_tshrt sourcetype="FAKE:cisco:asa" src=185.220.101.42 "%ASA-4-106023"` |
| ASA | Threat detection | `index=fake_tshrt sourcetype="FAKE:cisco:asa" "%ASA-4-733100" OR "%ASA-4-733101"` |
| Exchange | Phishing sent | `index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace" sender=*rnicrosoft-security.com` |

**Talking point:**
> "Here we see early indicators of reconnaissance. An external IP (185.220.101.42) from Germany is scanning our perimeter ports. Simultaneously, we see a phishing email sent to our IT admin Jessica Brown. This is classic APT behavior - patient preparation before the actual attack."

---

### Day 4: Initial Access

**What happens:**
- Jessica Brown clicks phishing link
- Credentials harvested
- Attacker gains access to Jessica's email

**Time:** 14:00-15:00 (mid-workday)

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| ASA | Inbound connection | `index=fake_tshrt sourcetype="FAKE:cisco:asa" src=185.220.101.42 "%ASA-6-302013"` |
| Exchange | Safe Links click | `index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace" SafeLinksPolicy jessica.brown` |
| Entra ID | Suspicious login | `index=fake_tshrt sourcetype="FAKE:azure:aad:signin" user=jessica.brown location=Germany` |

**Talking point:**
> "Day 4 is the turning point. Jessica clicks the link and her credentials are stolen. We see an inbound connection from the threat actor IP, and a suspicious login from Germany to her account. From this moment, the attacker has a foothold in the network."

---

### Days 5-7: Lateral Movement & Credential Pivot

**What happens:**
- Attacker moves from Atlanta to Boston via SD-WAN
- SMB, RDP, and SSH attempts against servers
- Multiple "access denied" events
- Forwarding rule created on Jessica's mailbox
- **Day 6: Credential pivot -- Jessica resets Alex's password and MFA**
- GCP: Bucket IAM recon (getBucketIamPolicy on Day 7)

**Time:** 10:00-17:00 (business hours), credential pivot at 02:00

**Hosts involved:**
- Atlanta DC: 10.20.20.10
- Boston file server: 10.10.20.20
- Boston SQL: 10.10.20.30

**Day 6 credential pivot (02:00-02:30):**

This is the key escalation step. Jessica Brown is an IT Administrator -- she has admin privileges to reset passwords and manage MFA, but she has **no access to financial data**. Alex Miller is a Senior Financial Analyst with access to sensitive financial systems and data. The attacker uses Jessica's compromised IT admin account to pivot to Alex's Finance account:

| Time | Event | Source | Details |
|------|-------|--------|---------|
| 02:15 | AD query: Finance dept members | WinEventLog 4688 | `net group "Finance Department" /domain` |
| 02:16 | PowerShell AD query | WinEventLog 4688 | `Get-ADUser -Filter {Department -eq "Finance"}` |
| 02:22 | Password reset: Alex Miller | WinEventLog 4724 | Jessica resets Alex's password on DC-BOS-01 |
| 02:22 | Account changed | WinEventLog 4738 | PasswordLastSet updated |
| 02:23 | MFA deleted: Alex Miller | Entra ID Audit | Jessica deletes Alex's Authenticator App |
| 02:26 | MFA registered: Alex Miller | Entra ID Audit | Attacker registers new Authenticator App |

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| ASA | Cross-site probing | `index=fake_tshrt sourcetype="FAKE:cisco:asa" acl=cross_site_policy action=deny` |
| ASA | Internal ACL denies | `index=fake_tshrt sourcetype="FAKE:cisco:asa" acl=server_segment_acl action=deny` |
| WinEventLog | Failed logon | `index=fake_tshrt sourcetype="FAKE:WinEventLog" EventID=4625 src=10.20.30.15` |
| WinEventLog | Password reset | `index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4724 demo_id=exfil` |
| Entra ID | MFA deleted | `index=fake_tshrt sourcetype="FAKE:azure:aad:audit" "Admin deleted authentication method" demo_id=exfil` |
| Entra ID | MFA registered | `index=fake_tshrt sourcetype="FAKE:azure:aad:audit" "User registered security info" demo_id=exfil` |
| Exchange | Forwarding rule | `index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace" InboxRule jessica.brown forward` |
| GCP Audit | Bucket recon | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName="storage.buckets.getIamPolicy"` |

**Talking point:**
> "Now we see lateral movement. The attacker uses Jessica's credentials to probe Boston servers via SD-WAN. But the real pivot happens at 2 AM on Day 6. Jessica is an IT Admin -- she can reset passwords but has no access to financial data. Alex Miller is in Finance with access to everything the attacker wants. So the attacker uses Jessica's admin rights to reset Alex's password, delete his MFA, and register a new authenticator. In 11 minutes, they go from IT admin access to Finance access. This is why role separation and privileged access monitoring matter."

---

### Days 8-10: Privilege Escalation & Persistence

**What happens:**
- Attacker creates backdoor IAM user in AWS
- GCP service account key generated
- GuardDuty detects IAM manipulation
- AWS Config rule goes NON_COMPLIANT
- Attacker fetches DB credentials from Secrets Manager (using Alex's compromised account)
- Attacker checks GCP audit logs for detection
- Data staging on WEB-01

**Critical events:**

| Day | Time | Event | Source |
|-----|------|-------|--------|
| 8 | 10:45 | AWS: CreateUser `svc-datasync` | CloudTrail |
| 8 | 10:46 | AWS: AttachUserPolicy AdministratorAccess | CloudTrail |
| 8 | ~11:00 | GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller | GuardDuty |
| 8 | ~11:00 | GuardDuty: Persistence:IAMUser/UserPermissions | GuardDuty |
| 8 | 11:00 | GCP: CreateServiceAccountKey | GCP Audit |
| 8+ | ongoing | AWS Config: IAM MFA rule NON_COMPLIANT | CloudTrail |
| 9 | 10:00 | AWS: GetSecretValue (DB credentials) from threat IP | CloudTrail |
| 10 | 22:00 | GCP: ListLogEntries -- attacker checks if SA creation was detected | GCP Audit |

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| AWS CloudTrail | IAM user created | `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=CreateUser` |
| AWS CloudTrail | Admin policy | `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=AttachUserPolicy` |
| AWS CloudTrail | Secrets Manager | `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=GetSecretValue sourceIPAddress=185.220.101.42` |
| AWS GuardDuty | IAM findings | `index=fake_tshrt sourcetype="FAKE:aws:cloudwatch:guardduty" detail.type=*IAMUser* demo_id=exfil` |
| GCP Audit | Service account | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName=*CreateServiceAccountKey*` |
| GCP Audit | Log recon | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName=*ListLogEntries* protoPayload.requestMetadata.callerIp=185.220.101.42` |
| Linux vmstat | WEB-01 anomaly | `index=fake_tshrt sourcetype="FAKE:vmstat" host=WEB-01 demo_id=exfil` |

**Talking point:**
> "This is the persistence phase. The attacker creates a backdoor IAM user 'svc-datasync' with full administrator access. GuardDuty fires two findings: MaliciousIPCaller and UserPermissions. In GCP, a service account key is created. On Day 9, the attacker uses the stolen credentials to fetch database secrets from AWS Secrets Manager. Day 10 at 10pm, they query GCP Cloud Logging to check if anyone noticed their SA creation -- that's operational security awareness."

---

### Days 11-13: Exfiltration

**What happens:**
- Data exfiltrated from S3 and GCS buckets
- Large transfers at night to avoid detection
- 500MB-2.5GB per session
- GuardDuty detects anomalous S3 behavior
- AWS billing shows data transfer cost spike
- GCP BigQuery used as second exfil channel
- Attacker deletes staging files to cover tracks

**Time:** 01:00-05:00 (nighttime - low activity period)

**Sensitive files exfiltrated:**
- `annual-financial-report.xlsx`
- `merger-plans-2025.docx`
- `employee-salaries.csv`
- `customer-database.csv`
- `q4-projections.xlsx`

**Critical events:**

| Day | Time | Event | Source |
|-----|------|-------|--------|
| 11-13 | 01:00-05:00 | S3 GetObject on financial-reports bucket | CloudTrail |
| 11-13 | 01:00-05:00 | GCS storage.objects.get on confidential bucket | GCP Audit |
| 11-13 | ~02:00 | GuardDuty: Exfiltration:S3/AnomalousBehavior | GuardDuty |
| 11-13 | daily | AWS Billing: S3 DataTransfer-Out 1.5x, GetRequests 1.3x | Billing CUR |
| 12 | 03:00 | GCP: BigQuery tabledata.list on customer_database | GCP Audit |
| 13 | 05:00 | GCP: storage.objects.delete on exports/staging/* (2-4 files) | GCP Audit |

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| AWS CloudTrail | S3 GetObject | `index=fake_tshrt sourcetype="FAKE:aws:cloudtrail" eventName=GetObject demo_id=exfil` |
| AWS GuardDuty | S3 exfil finding | `index=fake_tshrt sourcetype="FAKE:aws:cloudwatch:guardduty" detail.type=*S3*Anomalous* demo_id=exfil` |
| AWS Billing | Cost anomaly | `index=fake_tshrt sourcetype="FAKE:aws:billing:cur" lineItem.productCode=AmazonS3 demo_id=exfil` |
| GCP Audit | Storage access | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName="storage.objects.get" demo_id=exfil` |
| GCP Audit | BigQuery export | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName=*TableDataService.List* protoPayload.requestMetadata.callerIp=185.220.101.42` |
| GCP Audit | Cover tracks | `index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message" protoPayload.methodName="storage.objects.delete" protoPayload.requestMetadata.callerIp=185.220.101.42` |
| ASA | Large outbound | `index=fake_tshrt sourcetype="FAKE:cisco:asa" bytes>500000000 demo_id=exfil` |
| Linux | High network | `index=fake_tshrt sourcetype="FAKE:interfaces" host=WEB-01 demo_id=exfil` |

**Talking point:**
> "Here's the actual data theft. Between 01:00 and 05:00 we see large data transfers. The attacker has learned our traffic patterns and knows this is the low-activity period. We see GetObject calls against our financial S3 bucket. GuardDuty fires Exfiltration:S3/AnomalousBehavior -- but by the time you see it, data is already gone. On Day 12, they also export BigQuery customer data -- a second exfil channel. Day 13 at 5am, they delete staging files from GCP to cover their tracks. And look at the AWS bill: S3 data transfer costs are 50% higher than normal."

---

## Cloud Resources

### AWS
| Attribute | Value |
|-----------|-------|
| Account | 123456789012 |
| Region | us-east-1 |
| Sensitive bucket | faketshirtco-financial-reports |
| Backdoor user | svc-datasync |
| GuardDuty findings | 2 IAM (Day 8) + 3 S3 (Days 11-13) |
| Billing anomaly | S3 DataTransfer-Out 1.5x, GetRequests 1.3x (Days 11-13) |

### GCP
| Attribute | Value |
|-----------|-------|
| Project | faketshirtcompany-prod-01 |
| Region | us-central1 |
| Sensitive bucket | faketshirtco-confidential |
| Malicious SA | svc-gcs-sync |
| BigQuery target | warehouse/customer_database |

---

## All Exfil Log Sources (18)

| Source | Sourcetype | Key Events |
|--------|-----------|------------|
| ASA | `FAKE:cisco:asa` | Port scans, C2 connections, large outbound transfers |
| Entra ID | `FAKE:azure:aad:signin`, `FAKE:azure:aad:audit` | Compromised sign-ins, risk detections, privilege escalation |
| AWS CloudTrail | `FAKE:aws:cloudtrail` | IAM backdoor, S3 access, SecretsManager, Config |
| AWS GuardDuty | `FAKE:aws:cloudwatch:guardduty` | IAM + S3 threat findings (5 findings total) |
| AWS Billing | `FAKE:aws:billing:cur` | Cost anomaly -- S3 transfer + request spike |
| GCP Audit | `FAKE:google:gcp:pubsub:message` | SA creation, BigQuery export, audit log recon, cover tracks |
| Exchange | `FAKE:ms:o365:reporting:messagetrace` | Phishing email delivery, forwarding rule |
| Office Audit | `FAKE:o365:management:activity` | SafeLinks click events, file access |
| WinEventLog | `FAKE:WinEventLog` | Failed logons (4625), process creation (4688), password reset (4724), account changed (4738) |
| Sysmon | `FAKE:XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Credential access, suspicious processes |
| Perfmon | `FAKE:perfmon` | Server metric anomalies during staging |
| MSSQL | `FAKE:mssql:errorlog` | Brute-force login attempts |
| ServiceNow | `FAKE:servicenow:incident` | Incident lifecycle |
| Secure Access | `FAKE:cisco:umbrella:dns`, `FAKE:cisco:umbrella:proxy` | DNS/proxy for C2 and phishing domains |
| Catalyst | `FAKE:cisco:ios` | Network anomalies during lateral movement |
| ACI | `FAKE:cisco:aci:event` | Data center fabric events |
| Webex | `FAKE:cisco:webex:events` | Meeting tagging for exfil users |
| Linux | `FAKE:vmstat`, `FAKE:interfaces`, `FAKE:cpu` | CPU/memory/network anomalies on WEB-01 |

---

## Summary Table

| Day | Phase | Key Event | Primary Logs |
|-----|-------|-----------|--------------|
| 1-3 | Recon | Port scanning, phishing sent | ASA deny, Exchange |
| 4 | Access | Jessica clicks link | ASA inbound, Entra ID |
| 5-7 | Lateral | ATL->BOS movement, Day 6 credential pivot (Jessica resets Alex's password + MFA), GCP bucket recon | ASA ACL, WinEventLog 4724/4738, Entra ID Audit, GCP Audit |
| 8-10 | Persist | AWS/GCP backdoors, GuardDuty alerts, Secrets Manager, log recon | CloudTrail, GuardDuty, GCP Audit |
| 11-13 | Exfil | Data theft 01:00-05:00, BigQuery export, cover tracks, billing spike | S3/GCS access, GuardDuty, Billing, ASA bytes |

---

## Splunk Queries

### Threat actor activity
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" src=185.220.101.42 demo_id=exfil
| stats count by action, dest_port
| sort - count
```

### Attack timeline
```spl
index=fake_tshrt demo_id=exfil
| timechart span=1d count by sourcetype
```

### Compromised users
```spl
index=fake_tshrt demo_id=exfil
  (user=jessica.brown OR user=alex.miller)
| stats count, earliest(_time) AS first_seen, latest(_time) AS last_seen by user, sourcetype
```

### Cloud data access
```spl
index=fake_tshrt (sourcetype="FAKE:aws:cloudtrail" OR sourcetype="FAKE:google:gcp:pubsub:message")
  (eventName=GetObject OR protoPayload.methodName="storage.objects.get")
  demo_id=exfil
| stats count by sourcetype
```

### Lateral movement
```spl
index=fake_tshrt demo_id=exfil
  (src_ip=10.20.30.15 OR src_ip=10.10.30.55)
  (dest_ip=10.10.20.* OR dest_ip=10.20.20.*)
| stats count by src_ip, dest_ip, dest_port
```

### Exfiltration bursts
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=exfil
  action=built dest_port=443
| bin _time span=1h
| stats sum(bytes) AS total_bytes by _time
| where total_bytes > 100000000
```

### GuardDuty threat findings
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudwatch:guardduty" demo_id=exfil
| table _time, detail.type, detail.severity, detail.resource.resourceType
| sort _time
```

### AWS billing anomaly
```spl
index=fake_tshrt sourcetype="FAKE:aws:billing:cur" demo_id=exfil
| stats sum(lineItem.unblendedCost) AS cost by lineItem.productCode
| sort - cost
```

### GCP cover tracks (Day 13)
```spl
index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message"
    protoPayload.methodName="storage.objects.delete"
    protoPayload.requestMetadata.callerIp="185.220.101.42"
| table _time, protoPayload.resourceName
| sort _time
```

### Multi-cloud exfil correlation
```spl
index=fake_tshrt demo_id=exfil
    (sourcetype="FAKE:aws:cloudtrail" OR sourcetype="FAKE:google:gcp:pubsub:message"
     OR sourcetype="FAKE:aws:cloudwatch:guardduty")
| timechart span=1d count by sourcetype
```
