# Certificate Expiry Scenario

Wildcard SSL certificate expires at midnight, causing a 7-hour service outage until the NOC discovers and fixes the issue in the morning.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 7 hours (00:00-07:00) |
| Category | Network |
| demo_id | `certificate_expiry` |
| Day | 12 |
| Impact | HTTPS completely broken |

---

## Certificate Details

| Attribute | Value |
|-----------|-------|
| Common Name (CN) | *.theFakeTshirtCompany.com |
| Issuer | DigiCert SHA2 Extended Validation Server CA |
| Serial | 0A:1B:2C:3D:4E:5F:6A:7B:8C:9D |
| Expired | Day 12 at 00:00:00 |

---

## Affected Services

| Service | Server | IP | Impact |
|---------|--------|-----|--------|
| Main website | WEB-01 | 172.16.1.10 | SSL errors |
| API endpoints | WEB-02 | 172.16.1.11 | SSL errors |
| All *.theFakeTshirtCompany.com | - | - | Broken |

---

## Timeline - Day 12

| Time | Phase | Event |
|------|-------|-------|
| **00:00** | Expiry | Certificate expires at midnight |
| 00:00-05:00 | Undetected | Low overnight traffic, SSL failures |
| 05:00-06:00 | Building | Morning traffic increases, more failures |
| **06:15** | Detection | NOC engineer notices alerts |
| 06:30 | Investigation | Root cause identified |
| 06:45 | Action | Emergency certificate renewal initiated |
| **07:00** | Fix | New certificate installed |
| 07:00+ | Recovery | Services restored, traffic normalizes |

---

## Timeline Visualization

```
Hour:  00   01   02   03   04   05   06   07   08
       |    |    |    |    |    |    |    |    |
       v    v    v    v    v    v    v    v    v
CERT   ____________________________________
EXPIRES|<--- LOW TRAFFIC --->|<-- BUSY -->|
       |    |    |    |    |    |    |    |
       |    |    |    |    |    |    v    |
       |    |    |    |    |    |  DETECTED|
       |    |    |    |    |    |         v
       |    |    |    |    |    |       FIXED
       |                                  |
       +---------- OUTAGE ----------------+
              7 HOURS
```

---

## Event Volumes by Hour

| Hour | SSL Failures | Access Errors | Phase |
|------|-------------|---------------|-------|
| 00:00 | 5-15 | 3-10 | Overnight (low) |
| 01:00 | 5-15 | 3-10 | Overnight (low) |
| 02:00 | 5-15 | 3-10 | Overnight (low) |
| 03:00 | 5-15 | 3-10 | Overnight (low) |
| 04:00 | 5-15 | 3-10 | Overnight (low) |
| 05:00 | 20-40 | 15-30 | Morning rush |
| 06:00 | 20-40 | 15-30 | Peak + detection |
| 07:00 | 5 fail, 10 success | Mixed | Recovery |

---

## Error Types

### SSL Errors (ASA)
| Message | Meaning |
|---------|---------|
| `%ASA-6-725007` | SSL handshake failed |
| `%ASA-4-725006` | Certificate expired error |
| `%ASA-6-302014` | TCP Reset (SSL failure) |

### HTTP Errors (Access)
| Code | Percentage | Meaning |
|------|------------|---------|
| 502 | 50% | Bad Gateway |
| 503 | 50% | Service Unavailable |

---

## Logs to Look For

### ASA - SSL failures
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  ("%ASA-6-725007" OR "%ASA-4-725006")
  demo_id=certificate_expiry
| timechart span=1h count
```

### ASA - Certificate expired message
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-725006" "certificate expired"
  demo_id=certificate_expiry
| table _time, message
```

### Access - HTTP 5xx errors
```spl
index=fake_tshrt sourcetype="FAKE:access_combined"
  (status=502 OR status=503)
  demo_id=certificate_expiry
| timechart span=1h count by status
```

---

## Talking Points

**Setup:**
> "Day 12 at midnight. Our wildcard SSL certificate for *.theFakeTshirtCompany.com quietly expires. No one is watching at midnight."

**Overnight:**
> "From midnight to 5am we have low traffic, but every single HTTPS connection fails. Customers see 'Your connection is not private' or the site just doesn't load."

**Morning rush:**
> "Around 5-6am traffic picks up. Now we have dozens of SSL failures per hour. At 6:15 the NOC finally notices the alerts."

**Fix:**
> "It takes 45 minutes to get an emergency certificate issued and installed. By 7am we're back online."

**Impact:**
> "7 hours of total HTTPS outage. Any customer who tried to access the site overnight got an error. Mobile apps that pin certificates might still fail even after the fix."

**Lesson:**
> "Certificate expiry is 100% preventable. Splunk can monitor certificate validity and alert 30, 14, and 7 days before expiry. This should never happen."

---

## Splunk Queries

### Full incident timeline
```spl
index=fake_tshrt demo_id=certificate_expiry
| sort _time
| table _time, sourcetype, message, status
```

### SSL failures by hour
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=certificate_expiry
| timechart span=1h count by action
```

### Customer impact
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-6-725007" demo_id=certificate_expiry
| stats dc(src_ip) AS unique_customers, count AS total_failures
```

### Recovery verification
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=certificate_expiry
| eval status=case(
    match(message, "725007|725006|302014.*Reset"), "Failed",
    match(message, "725001"), "Success",
    true(), "Other"
)
| timechart span=15m count by status
```

### Certificate details
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-725006" demo_id=certificate_expiry
| rex "CN=(?<cert_cn>[^,]+)"
| stats count by cert_cn
```

### Business hours impact
```spl
index=fake_tshrt demo_id=certificate_expiry
| eval hour=strftime(_time, "%H")
| eval business_hours=if(hour>=8 AND hour<=18, "Business", "After-hours")
| stats count by business_hours, sourcetype
```
