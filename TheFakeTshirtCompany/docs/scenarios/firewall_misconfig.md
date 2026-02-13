# Firewall Misconfiguration Scenario

IT admin attempts to block a threat IP but accidentally blocks inbound traffic TO the web server's public IP, causing a 2-hour customer-facing outage.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 2 hours (10:15-12:05) |
| Category | Network |
| demo_id | `firewall_misconfig` |
| Day | 7 |
| Impact | Complete website outage |

---

## Key Personnel

### Admin Who Made the Mistake
| Attribute | Value |
|-----------|-------|
| Username | network.admin |
| Source IP | 10.10.10.50 |
| Action | Mistyped ACL rule |

### Affected Target
| Attribute | Value |
|-----------|-------|
| Server | WEB-01 |
| Public IP | 203.0.113.10 |
| Ports | 80, 443 |

---

## Timeline - Day 7

| Time | Event | Description |
|------|-------|-------------|
| **10:15** | Admin login | network.admin logs into FW-EDGE-01 via SSH |
| **10:16** | Config mode | Admin enters `configure terminal` |
| **10:18** | Bad ACL | `deny tcp any host 203.0.113.10 eq https` (THE MISTAKE) |
| **10:20** | Outage begins | Customer connections blocked |
| **10:20-12:00** | Deny events | ~90 blocked connections logged |
| **12:03** | Rollback | `no access-list` removes bad rule |
| **12:04** | Save config | `write memory` to persist fix |
| **12:05** | Admin logout | Session ends |

---

## The Mistake

**Intended action:** Block traffic FROM threat actor IP
```
access-list outside_access_in deny tcp host 185.220.101.42 any
```

**Actual action:** Block traffic TO web server public IP
```
access-list outside_access_in deny tcp any host 203.0.113.10 eq https
```

**Result:** All customer HTTPS traffic to the website is blocked.

---

## Timeline Visualization

```
10:15    10:18    10:20                    12:00   12:03   12:05
  |        |        |                        |       |       |
  v        v        v                        v       v       v
LOGIN -> CONFIG -> BAD ACL -----------------> FIX -> SAVE -> LOGOUT
           |        |                        |
           |        +--- OUTAGE PERIOD ------+
           |             (~90 deny events)
           |
         THE MISTAKE
```

---

## Deny Event Volumes

| Time Window | Deny Events | Description |
|-------------|-------------|-------------|
| 10:20-10:59 | ~30 | Initial wave |
| 11:00-11:59 | ~60 | Peak (customer retries) |
| 12:00-12:02 | ~5 | Final denies before fix |
| **Total** | **~95** | All blocked connections |

---

## Logs to Look For

### ASA - Admin activity
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" user="network.admin" demo_id=firewall_misconfig
| sort _time
```

**Key messages:**
- `%ASA-6-605005: Login permitted` - Admin login
- `%ASA-5-111008: executed 'configure terminal'` - Config mode
- `%ASA-5-111010: executed 'access-list...'` - Rule change

### ASA - Blocked traffic
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-106023" dest=203.0.113.10
  demo_id=firewall_misconfig
| timechart span=5m count
```

---

## Talking Points

**Setup:**
> "Day 7, around 10:15. Our network admin sees what looks like suspicious traffic and decides to add a block rule. Good instinct, bad execution."

**The mistake:**
> "Notice the ACL syntax: 'deny tcp any host 203.0.113.10'. That's blocking traffic TO our web server, not FROM the threat. One word difference, massive impact."

**Detection:**
> "Almost 2 hours of customer-impacting outage. We see ~95 deny events in the ASA logs. Every single customer trying to reach our website gets blocked."

**Fix:**
> "At 12:03 we see the rollback - 'no access-list' removes the bad rule. Traffic normalizes immediately."

**Lesson:**
> "This is why change management exists. A peer review would have caught this in seconds. The fix took 3 minutes, but finding the problem took almost 2 hours."

---

## Splunk Queries

### Full incident timeline
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=firewall_misconfig
| sort _time
| table _time, action, message
```

### Config changes only
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  ("%ASA-5-111008" OR "%ASA-5-111010")
  demo_id=firewall_misconfig
| table _time, message
```

### Deny events over time
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-106023" demo_id=firewall_misconfig
| timechart span=5m count AS "Blocked Connections"
```

### Impact assessment
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-106023" demo_id=firewall_misconfig
| stats count AS blocked_connections,
        dc(src_ip) AS unique_customers
```

### Compare to normal traffic
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" dest=203.0.113.10
| eval status=if(action="deny", "Blocked", "Allowed")
| timechart span=15m count by status
```
