# DDoS Attack Scenario

Volumetric HTTP flood from a global botnet targeting the company's DMZ web servers, causing a 28-hour service disruption with SD-WAN failover and multi-layer defense response.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | ~28 hours (Day 18 02:00 - Day 19 06:00) |
| Category | Network |
| demo_id | `ddos_attack` |
| Days | 18-19 |
| Impact | Website degradation, SD-WAN failover, P1 incident |

---

## Key Personnel

### Network Admin (Responder)
| Attribute | Value |
|-----------|-------|
| Username | network.admin |
| Source IP | 10.10.10.50 |
| Action | Emergency ACL deployment |

### Affected Targets
| Server | IP | Role |
|--------|-----|------|
| WEB-01 | 172.16.1.10 (DMZ) / 203.0.113.10 (Public) | Primary web server |
| WEB-02 | 172.16.1.11 | Secondary web server |
| APP-BOS-01 | 10.10.20.40 | API server (downstream impact) |
| MX-BOS-01 | - | SD-WAN hub (failover triggered) |

---

## Timeline - Day 18

| Time | Event | Intensity | Description |
|------|-------|-----------|-------------|
| **02:00** | Probing begins | 5% | Wave 1 botnet (10 IPs) starts port scanning |
| **06:00** | Volume ramps | 30% | SYN flood + HTTP flood begins |
| **08:00** | Full attack | 100% | Full-scale assault, ASA rate limiting triggers |
| **08:02** | SD-WAN failover | - | MX-BOS-01 fails over Comcast -> AT&T (WAN saturated) |
| **09:00** | P1 incident | - | ServiceNow P1 auto-created from monitoring alerts |
| **10:00** | Emergency ACLs | 50% | network.admin blocks wave 1 subnets |
| **12:00** | Wave 2 | 80% | Attacker adapts with 10 new IPs |
| **12:05** | SD-WAN failover | - | Second failover event (wave 2 saturates link) |
| **14:00** | ISP filtering | 40% | ISP-level DDoS mitigation activated |
| **14:10** | SD-WAN failback | - | MX-BOS-01 restores Comcast (primary recovered) |
| **15:00** | Subsiding | 20% | Attack volume drops significantly |
| **18:00** | Residual | 10% | Mostly stopped, occasional probing |

## Timeline - Day 19

| Time | Event | Intensity | Description |
|------|-------|-----------|-------------|
| **00:00-05:00** | Overnight | 5% | Low-level residual traffic |
| **06:00** | Attack ends | 0% | No further attack traffic |
| **08:00** | Recovery confirmed | - | Full service restoration |
| **10:00** | Change request | - | Permanent DDoS mitigation CR created |

---

## Attack Waves

### Wave 1 - Initial Botnet (02:00-10:00)

10 IPs from diverse global locations:

| IP | Region |
|----|--------|
| 103.45.67.12 | China |
| 91.134.56.23 | France |
| 45.227.255.34 | Brazil |
| 112.85.42.45 | China |
| 185.156.73.56 | Russia |
| 198.51.100.67 | EU |
| 103.78.12.78 | Indonesia |
| 41.205.45.89 | Nigeria |
| 93.184.216.90 | Europe |
| 202.56.78.101 | India |

Blocked at 10:00 by emergency ACLs.

### Wave 2 - Adapted Botnet (12:00-18:00)

10 new IPs activated after wave 1 is blocked:

| IP | Region |
|----|--------|
| 176.123.45.12 | Ukraine |
| 31.13.67.23 | Netherlands |
| 115.239.210.34 | China |
| 89.248.167.45 | Netherlands |
| 61.177.172.56 | China |
| 178.128.90.67 | Germany |
| 45.33.32.78 | US (compromised) |
| 118.193.21.89 | Hong Kong |
| 51.15.183.90 | France |
| 122.228.10.101 | China |

Mitigated by ISP-level filtering at 14:00.

---

## Timeline Visualization

```
Day 18
02:00     06:00     08:00     10:00     12:00     14:00     18:00
  |         |         |         |         |         |         |
  v         v         v         v         v         v         v
PROBE --> RAMP --> FULL ATK --> ACL ----> WAVE 2 -> ISP ----> RESIDUAL
  5%       30%      100%       50%        80%      40%        10%
                      |                    |         |
                   FAILOVER             FAILOVER  FAILBACK
                  (Comcast->AT&T)      (Comcast->AT&T) (AT&T->Comcast)

Day 19
00:00     06:00     08:00     10:00
  |         |         |         |
  v         v         v         v
RESIDUAL -> END --> RECOVERY -> CHANGE REQUEST
  5%        0%
```

---

## SD-WAN Failover Sequence

| Time | Event | From | To | Reason |
|------|-------|------|----|--------|
| 08:02 | Failover | Comcast | AT&T | WAN link saturated - packet loss exceeds threshold |
| 12:05 | Failover | Comcast | AT&T | WAN link saturated (wave 2) |
| 14:10 | Failback | AT&T | Comcast | Primary WAN recovered - restoring preferred path |

---

## Affected Log Sources

| Source | Events | Description |
|--------|--------|-------------|
| **ASA** | SYN flood denies, rate limiting, threat detection | Emergency ACLs, connection limits |
| **Meraki MX** | IDS alerts, SD-WAN health, failover events | HTTP flood detection, WAN saturation |
| **Access** | 503 errors, slow responses | Reduced orders, degraded UX |
| **Linux** | High CPU/network on WEB-01 | Up to +40% CPU at peak |
| **Perfmon** | Elevated CPU on APP-BOS-01 | Downstream API impact |
| **ServiceNow** | P1 incident, change request | Incident management trail |
| **Catalyst** | Network impact events | Campus network effects |
| **ACI** | Data center fabric events | DC-level impact |
| **Catalyst Center** | Health score degradation, issues | Network assurance alerts |

---

## Logs to Look For

### ASA - Attack traffic
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=ddos_attack
| timechart span=1h count by action
```

### ASA - Emergency ACLs
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=ddos_attack
  ("%ASA-5-111008" OR "%ASA-5-111010")
| table _time, message
```

### Meraki - IDS alerts
```spl
index=fake_tshrt sourcetype="FAKE:meraki:mx" type="security_event" demo_id=ddos_attack
| stats count by eventData.message
```

### Meraki - SD-WAN failover
```spl
index=fake_tshrt sourcetype="FAKE:meraki:mx" type="sd_wan_failover" demo_id=ddos_attack
| table _time, description, eventData.from_wan, eventData.to_wan, eventData.reason
```

### Meraki - SD-WAN health degradation
```spl
index=fake_tshrt sourcetype="FAKE:meraki:mx" type="sd_wan_health" demo_id=ddos_attack
| timechart span=1h avg(eventData.latencyMs) AS latency, avg(eventData.lossPercent) AS loss
```

### Access - Error rate
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=ddos_attack
| eval is_error=if(status>=500, 1, 0)
| timechart span=1h avg(is_error) AS error_rate
```

### ServiceNow - Incident timeline
```spl
index=fake_tshrt sourcetype="FAKE:servicenow:incident" demo_id=ddos_attack
| table _time, number, priority, short_description, state
```

### Full cross-source timeline
```spl
index=fake_tshrt demo_id=ddos_attack
| timechart span=1h count by sourcetype
```

---

## Talking Points

**Setup:**
> "Day 18, around 2 AM. We start seeing probing activity from 10 globally distributed IPs. By 6 AM it ramps into a full volumetric HTTP flood targeting our web servers."

**Peak attack:**
> "At 8 AM we hit full intensity. The ASA is rate-limiting connections, generating threat detection events. Look at the Meraki MX -- the primary WAN link is saturated, triggering an automatic SD-WAN failover from Comcast to AT&T."

**Wave 2:**
> "At 10 AM, network.admin deploys emergency ACLs to block the first wave. But at noon, the attacker adapts -- 10 completely new IPs. This is a common DDoS pattern: the attacker has more resources than we can block manually."

**Resolution:**
> "The turning point is 2 PM when ISP-level DDoS filtering kicks in. Within the hour, traffic drops enough for the MX to fail back to the primary WAN link. By Day 19 morning, we're fully recovered."

**Lesson:**
> "This shows the value of layered defense. The ASA, Meraki IDS, SD-WAN failover, and ISP mitigation all played roles. Manual ACLs alone weren't enough -- the attacker adapted faster than we could block."
