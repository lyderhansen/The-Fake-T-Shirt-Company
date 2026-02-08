# Cisco ASA Firewall

Perimeter firewall logs from FW-EDGE-01, a Cisco ASA 5525-X protecting all external traffic.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `cisco:asa` |
| Format | Syslog |
| Output File | `output/network/cisco_asa.log` |
| Volume | 500-2000 events/day |
| Device | FW-EDGE-01 (ASA 5525-X) |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | Syslog timestamp | `Jan 05 2026 14:23:45` |
| `hostname` | Firewall hostname | `FW-EDGE-01` |
| `message_code` | ASA message ID | `%ASA-6-302013` |
| `severity` | Log severity (1-7) | `6` (informational) |
| `src` | Source IP | `10.10.30.55` |
| `dst` | Destination IP | `8.8.8.8` |
| `sport` | Source port | `54321` |
| `dport` | Destination port | `443` |
| `protocol` | Protocol | `tcp`, `udp`, `icmp` |
| `action` | Connection action | `Built`, `Teardown`, `Deny` |
| `acl` | Access Control List | `outside_access_in` |
| `connection_id` | Connection ID | `12345` |
| `duration` | Session duration | `0:01:15` |
| `bytes` | Bytes transferred | `524288` |
| `demo_id` | Scenario tag | `exfil` |

---

## Common Message Codes

| Code | Severity | Description |
|------|----------|-------------|
| `%ASA-6-302013` | Info | TCP connection built (outbound) |
| `%ASA-6-302014` | Info | TCP connection teardown |
| `%ASA-6-302015` | Info | UDP connection built |
| `%ASA-6-302016` | Info | UDP connection teardown |
| `%ASA-4-106023` | Warning | Packet denied by ACL |
| `%ASA-4-733100` | Warning | Threat detection triggered |
| `%ASA-6-605005` | Info | Login permitted |
| `%ASA-5-111008` | Notice | Admin command executed |
| `%ASA-5-111010` | Notice | ACL change |
| `%ASA-6-725001` | Info | SSL handshake started |
| `%ASA-6-725007` | Info | SSL handshake failed |
| `%ASA-4-725006` | Warning | Certificate expired |

---

## Example Events

### Connection Built (Outbound)
```
<166>Jan 05 2026 14:23:45 FW-EDGE-01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:8.8.8.8/443 (8.8.8.8/443) to inside:10.10.30.55/54321 (203.0.113.10/54321) demo_id=exfil
```

### Connection Teardown
```
<166>Jan 05 2026 14:25:00 FW-EDGE-01 %ASA-6-302014: Teardown TCP connection 12345 for outside:8.8.8.8/443 to inside:10.10.30.55/54321 duration 0:01:15 bytes 524288 TCP FINs demo_id=exfil
```

### Denied Connection (Port Scan)
```
<164>Jan 03 2026 20:15:30 FW-EDGE-01 %ASA-4-106023: Deny tcp src outside:185.220.101.42/45678 dst inside:203.0.113.10/22 by access-group "outside_access_in" [0x0, 0x0] demo_id=exfil
```

### Admin Login
```
<166>Jan 07 2026 10:15:22 FW-EDGE-01 %ASA-6-605005: Login permitted from 10.10.10.50/52435 to inside:10.10.10.1/ssh for user "network.admin" demo_id=firewall_misconfig
```

### ACL Change
```
<165>Jan 07 2026 10:18:15 FW-EDGE-01 %ASA-5-111010: User 'network.admin' executed 'access-list outside_access_in line 1 extended deny tcp any host 203.0.113.10 eq https' demo_id=firewall_misconfig
```

### SSL Handshake Failure
```
<166>Jan 12 2026 02:15:30 FW-EDGE-01 %ASA-6-725007: SSL session with client outside:73.158.42.100/52435 to inside:172.16.1.10/443 terminated due to SSL handshake failure demo_id=certificate_expiry
```

---

## Use Cases

### 1. Exfiltration Detection
Track large outbound data transfers:
```spl
index=network sourcetype=cisco:asa action=Teardown demo_id=exfil
| eval bytes_mb = bytes / 1048576
| where bytes_mb > 10
| stats sum(bytes_mb) AS total_mb by src, dst
| sort - total_mb
```

### 2. Port Scan Detection
Identify reconnaissance activity:
```spl
index=network sourcetype=cisco:asa "%ASA-4-106023"
| stats dc(dport) AS unique_ports, count by src
| where unique_ports > 10
| sort - unique_ports
```

### 3. C2 Beacon Detection
Find periodic outbound connections (potential C2):
```spl
index=network sourcetype=cisco:asa action=Built dest_port=443
| bin _time span=5m
| stats count by _time, src, dst
| eventstats stdev(count) AS stdev, avg(count) AS avg by src, dst
| where stdev < 2 AND count > 0
```

### 4. Admin Activity Audit
Track firewall configuration changes:
```spl
index=network sourcetype=cisco:asa ("%ASA-5-111008" OR "%ASA-5-111010" OR "%ASA-6-605005")
| table _time, message
| sort _time
```

### 5. SSL Certificate Issues
Monitor certificate problems:
```spl
index=network sourcetype=cisco:asa ("%ASA-6-725007" OR "%ASA-4-725006")
| timechart span=1h count by message_code
```

### 6. Connection Timeline (Exfil)
Full timeline for exfil scenario:
```spl
index=network sourcetype=cisco:asa demo_id=exfil
| timechart span=1d count by action
```

---

## Scenario Integration

| Scenario | Activity | Key Events |
|----------|----------|------------|
| **exfil** | C2 beacons, data transfer | Day 4-14: Outbound to 185.220.101.42, large transfers |
| **ransomware_attempt** | Malware beaconing | Day 8: Outbound to 194.26.29.42 |
| **firewall_misconfig** | Bad ACL blocks website | Day 7: 106023 denies to 203.0.113.10 |
| **certificate_expiry** | SSL failures | Day 12: 725007 handshake failures |
| **memory_leak** | Connection timeouts | Day 6-10: Teardowns from WEB-01 |

---

## Talking Points

**Exfiltration:**
> "Watch the bytes field in teardown events. Normal web traffic is kilobytes. When you see megabytes or gigabytes in a single session, that's potential data theft."

**Port Scanning:**
> "106023 denies from external IPs hitting multiple ports is classic reconnaissance. The attacker is mapping our perimeter."

**Admin Changes:**
> "Every ACL change is logged with the exact command and username. This is how we caught the firewall misconfiguration - we could see exactly what was changed and by whom."

**SSL Issues:**
> "725007 events spike when something is wrong with certificates. Combined with 725006 'certificate expired', you have your root cause."

---

## Related Sources

- [Meraki MX](meraki.md) - Internal SD-WAN firewall
- [Entra ID](entraid.md) - VPN authentication
- [WinEventLog](wineventlog.md) - Correlate with user logons

