# Cisco Secure Access

Cloud-delivered security logs from Cisco Secure Access (formerly Umbrella), covering DNS, web proxy, cloud firewall, and audit events for all 175 employees.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `cisco:umbrella:dns`, `cisco:umbrella:proxy`, `cisco:umbrella:firewall`, `cisco:umbrella:audit` |
| Format | CSV (S3 export format) |
| Output Files | `output/cloud/cisco_secure_access/cisco_secure_access_*.csv` |
| Volume | DNS: ~100-120K/day, Proxy: ~25-40K/day, Firewall: ~8K/day, Audit: ~15/day |

---

## Log Types

### DNS Logs (16 columns)
| Field | Description | Example |
|-------|-------------|---------|
| `Timestamp` | Event time | `2026-01-05 14:23:45` |
| `Identity` | User identity | `alex.miller (alex.miller@...)` |
| `Identities` | Group memberships | `alex.miller,BOS-HQ,FakeTShirtCo-Corp` |
| `InternalIp` | Source IP | `10.10.30.55` |
| `ExternalIp` | NAT IP | `203.0.113.10` |
| `Action` | DNS verdict | `Allowed`, `Blocked` |
| `QueryType` | DNS record type | `1 (A)`, `28 (AAAA)` |
| `ResponseCode` | DNS response | `NOERROR`, `NXDOMAIN` |
| `Domain` | Queried domain | `outlook.office365.com` |
| `Categories` | Domain categories | `Business Services,Cloud Services` |
| `demo_id` | Scenario tag | `exfil` |

### Proxy/SWG Logs (26 columns)
| Field | Description | Example |
|-------|-------------|---------|
| `URL` | Full request URL | `https://storage.googleapis.com/upload` |
| `Action` | Proxy verdict | `ALLOWED`, `BLOCKED` |
| `StatusCode` | HTTP status | `200`, `403` |
| `ContentType` | Response MIME type | `text/html` |
| `RequestSize` | Upload bytes | `125000` |
| `ResponseSize` | Download bytes | `120000` |
| `SHA256` | Content hash | `abc123...` |
| `Verdict` | Threat verdict | `Clean`, `Malicious` |

### Cloud Firewall Logs (14 columns)
| Field | Description | Example |
|-------|-------------|---------|
| `SourceIP` | Internal source | `10.10.30.55` |
| `DestinationIP` | External destination | `185.220.101.42` |
| `DestinationPort` | Target port | `443` |
| `Verdict` | Firewall action | `Allowed`, `Blocked` |

### Audit Logs (9 columns)
| Field | Description | Example |
|-------|-------------|---------|
| `AdminUser` | Admin who made change | `it.admin@theTshirtCompany.com` |
| `ActionType` | Change category | `Policy`, `Network`, `User` |
| `ActionName` | Specific action | `Updated DNS policy` |

---

## Example Events

### DNS - Allowed
```csv
"2026-01-05 14:23:45","alex.miller (alex.miller@theTshirtCompany.com)","alex.miller,BOS-HQ,FakeTShirtCo-Corp","10.10.30.55","203.0.113.10","Allowed","1 (A)","NOERROR","outlook.office365.com","Business Services,Cloud Services","AD Users","AD Users,Internal Networks","","100001","US","7654321"
```

### DNS - Blocked (ransomware)
```csv
"2026-01-08 14:10:30","brooklyn.white","brooklyn.white,AUS,FakeTShirtCo-Corp","10.30.30.20","203.0.113.30","Blocked","1 (A)","NXDOMAIN","malware-c2.darknet.ru","Malware","AD Users","AD Users","Command and Control","100245","US","" demo_id=ransomware_attempt
```

### Proxy - Cloud Storage Upload (exfil)
```csv
"2026-01-12 02:30:15","alex.miller","10.10.30.55","203.0.113.10","52.96.1.10","application/octet-stream","ALLOWED","https://storage.googleapis.com/upload","","Mozilla/5.0...","200","2345","125000","120000","abc123...","Cloud Storage","","","Clean","","","AD Users","","alex.miller,BOS-HQ","AD Users,Internal Networks","POST" demo_id=exfil
```

---

## Use Cases

### 1. Blocked DNS domains
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" Action="Blocked"
| stats count by Domain, Categories
| sort - count
```

### 2. Exfil cloud storage detection
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:proxy" demo_id=exfil
  Categories="Cloud Storage"
| stats sum(RequestSize) AS uploaded_bytes by Identity, URL
| eval uploaded_mb = round(uploaded_bytes/1048576, 2)
| sort - uploaded_mb
```

### 3. C2 beacon pattern
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" demo_id=exfil
| bin _time span=5m
| stats count by _time, Domain
| eventstats stdev(count) AS stdev, avg(count) AS avg by Domain
| where stdev < 2
```

### 4. Ransomware blocked domains
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" demo_id=ransomware_attempt Action="Blocked"
| table _time, Identity, Domain, Categories
```

### 5. Phishing simulation DNS
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:dns" demo_id=phishing_test
| stats count by Domain, Action
```

### 6. Admin audit trail
```spl
index=fake_tshrt sourcetype="FAKE:cisco:umbrella:audit"
| table _time, AdminUser, ActionType, ActionName
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **exfil** | 4-13 | DNS: phishing domains, C2 beacons, cloud storage. Proxy: large uploads. Firewall: outbound C2 |
| **ransomware_attempt** | 7-8 | DNS: blocked malware/C2 domains. Proxy: blocked malware downloads |
| **phishing_test** | 20-22 | DNS: KnowBe4 simulation domain resolution |

---

## Talking Points

**Exfil detection:**
> "Secure Access sees everything. The DNS logs show the attacker's C2 domain being resolved -- regular beacons every few minutes. The proxy logs capture the actual data upload to Google Cloud Storage. The firewall logs show the outbound connection being established."

**Ransomware defense:**
> "This is where Umbrella earns its keep. The ransomware tries to reach its C2 domain, and DNS security blocks it immediately. You can see the 'Blocked' action and 'Command and Control' category. The attack is stopped at the DNS layer before any connection is established."

**Phishing test:**
> "During the phishing simulation, you can see who resolved the KnowBe4 domain -- that's who clicked the link. Cross-correlate with the Entra ID sign-in logs to see who actually submitted credentials."

---

## Related Sources

- [Entra ID](entraid.md) - Cloud identity and authentication
- [Cisco ASA](cisco_asa.md) - Perimeter firewall (network-level view)
- [Exchange](exchange.md) - Email trace for phishing
- [Sysmon](sysmon.md) - Endpoint process/network activity
