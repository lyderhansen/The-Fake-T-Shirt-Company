# Exfil Scenario - APT Data Exfiltration

A 14-day APT-style attack where a threat actor from Germany compromises an IT admin in Atlanta, moves laterally to Boston, and exfiltrates sensitive financial data.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 14 days |
| Category | Attack |
| demo_id | `exfil` |
| Outcome | Successful data theft |

### Attack Path
```
Frankfurt (Threat Actor) → Atlanta (Initial Access) → Boston (Target) → External (Exfil)
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
| ASA | Port scans blocked | `%ASA-4-106023 src=185.220.101.42` |
| ASA | Threat detection | `%ASA-4-733100` or `%ASA-4-733101` |
| Exchange | Phishing sent | `sender=*rnicrosoft-security.com` |

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
| ASA | Inbound connection | `%ASA-6-302013 src=185.220.101.42` |
| Exchange | Safe Links click | `SafeLinksPolicy jessica.brown` |
| Entra ID | Suspicious login | `user=jessica.brown location=Germany` |

**Talking point:**
> "Day 4 is the turning point. Jessica clicks the link and her credentials are stolen. We see an inbound connection from the threat actor IP, and a suspicious login from Germany to her account. From this moment, the attacker has a foothold in the network."

---

### Days 5-7: Lateral Movement

**What happens:**
- Attacker moves from Atlanta to Boston via SD-WAN
- SMB, RDP, and SSH attempts against servers
- Multiple "access denied" events
- Forwarding rule created on Jessica's mailbox

**Time:** 10:00-17:00 (business hours)

**Hosts involved:**
- Atlanta DC: 10.20.20.10
- Boston file server: 10.10.20.20
- Boston SQL: 10.10.20.30

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| ASA | Cross-site probing | `acl=cross_site_policy deny` |
| ASA | Internal ACL denies | `acl=server_segment_acl deny` |
| WinEventLog | Failed logon | `EventID=4625 src=10.20.30.15` |
| Exchange | Forwarding rule | `InboxRule jessica.brown forward` |

**Talking point:**
> "Now we see lateral movement. The attacker uses Jessica's credentials to attempt access to Boston servers via our SD-WAN tunnel. We see multiple 'access denied' from our ACLs. Meanwhile, a forwarding rule is created that sends copies of Jessica's emails to an external ProtonMail account."

---

### Days 8-10: Privilege Escalation & Persistence

**What happens:**
- Attacker creates backdoor IAM user in AWS
- GCP service account key generated
- Alex Miller's credentials compromised
- Data staging on WEB-01

**Critical events:**

| Day | Time | Event |
|-----|------|-------|
| 5 | 10:45 | AWS: CreateUser `svc-datasync` |
| 5 | 10:46 | AWS: AttachUserPolicy AdministratorAccess |
| 5 | 11:00 | GCP: CreateServiceAccountKey |

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| AWS CloudTrail | IAM user created | `eventName=CreateUser userIdentity.userName=alex.miller` |
| AWS CloudTrail | Admin policy | `eventName=AttachUserPolicy` |
| GCP Audit | Service account | `methodName=CreateServiceAccountKey` |
| Linux vmstat | WEB-01 anomaly | `host=WEB-01 cpu_pct>60` |

**Talking point:**
> "This is the persistence phase. The attacker creates a backdoor IAM user 'svc-datasync' with full administrator access. We also see Alex Miller's credentials being used - he's our senior financial analyst with access to sensitive data. WEB-01 shows unusual high CPU activity indicating data staging."

---

### Days 11-13: Exfiltration

**What happens:**
- Data exfiltrated from S3 and GCS buckets
- Large transfers at night to avoid detection
- 500MB-2.5GB per session

**Time:** 01:00-05:00 (nighttime - low activity period)

**Sensitive files exfiltrated:**
- `annual-financial-report.xlsx`
- `merger-plans-2025.docx`
- `employee-salaries.csv`
- `customer-database.csv`
- `q4-projections.xlsx`

**Logs to look for:**

| Log Source | Event | Search |
|------------|-------|--------|
| AWS CloudTrail | S3 GetObject | `eventName=GetObject bucket=faketshirtco-financial-reports demo_id=exfil` |
| GCP Audit | Storage access | `methodName=storage.objects.get` |
| ASA | Large outbound transfers | `bytes>500000000 demo_id=exfil` |
| Linux | High network traffic | `host=WEB-01 network_bytes` |

**Talking point:**
> "Here's the actual data theft. Between 01:00 and 05:00 we see large data transfers. The attacker has learned our traffic patterns and knows this is the low-activity period. We see GetObject calls against our financial S3 bucket with files like 'merger-plans-2025.docx' and 'employee-salaries.csv'. Total exfiltrated data: several gigabytes over 3 nights."

---

## Cloud Resources

### AWS
| Attribute | Value |
|-----------|-------|
| Account | 123456789012 |
| Region | us-east-1 |
| Sensitive bucket | faketshirtco-financial-reports |
| Backdoor user | svc-datasync |

### GCP
| Attribute | Value |
|-----------|-------|
| Project | faketshirtcompany-prod-01 |
| Region | us-central1 |
| Sensitive bucket | faketshirtco-confidential |
| Malicious key | malicious-key-001 |

---

## Summary Table

| Day | Phase | Key Event | Primary Logs |
|-----|-------|-----------|--------------|
| 1-3 | Recon | Port scanning, phishing sent | ASA deny, Exchange |
| 4 | Access | Jessica clicks link | ASA inbound, Entra ID |
| 5-7 | Lateral | ATL→BOS movement | ASA ACL, WinEventLog 4625 |
| 8-10 | Persist | AWS/GCP backdoors | CloudTrail, GCP Audit |
| 11-13 | Exfil | Data theft 01:00-05:00 | S3/GCS access, ASA bytes |

---

## Splunk Queries

### Threat actor activity
```spl
index=network sourcetype=cisco:asa src=185.220.101.42 demo_id=exfil
| stats count by action, dest_port
| sort - count
```

### Attack timeline
```spl
index=* demo_id=exfil
| timechart span=1d count by sourcetype
```

### Compromised users
```spl
index=* demo_id=exfil
  (user=jessica.brown OR user=alex.miller)
| stats count, earliest(_time) AS first_seen, latest(_time) AS last_seen by user, sourcetype
```

### Cloud data access
```spl
index=cloud (sourcetype=aws:cloudtrail OR sourcetype=google:gcp:*)
  (eventName=GetObject OR methodName=*get*)
  demo_id=exfil
| stats count by eventName, bucketName
```

### Lateral movement
```spl
index=* demo_id=exfil
  (src_ip=10.20.30.15 OR src_ip=10.10.30.55)
  (dest_ip=10.10.20.* OR dest_ip=10.20.20.*)
| stats count by src_ip, dest_ip, dest_port
```

### Exfiltration bursts
```spl
index=network sourcetype=cisco:asa demo_id=exfil
  action=built dest_port=443
| bin _time span=1h
| stats sum(bytes) AS total_bytes by _time
| where total_bytes > 100000000
```
