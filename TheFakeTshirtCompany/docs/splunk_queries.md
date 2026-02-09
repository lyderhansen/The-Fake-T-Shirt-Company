# Splunk Queries Reference

Consolidated SPL queries for all demo scenarios. All queries use the `demo_id` field for filtering.

---

## Universal Queries

### Find all scenario events
```spl
index=* demo_id=* | stats count by demo_id, sourcetype
```

### Timeline by scenario
```spl
index=* demo_id=* | timechart span=1d count by demo_id
```

### Sourcetype distribution
```spl
index=* demo_id=<scenario_name> | stats count by sourcetype | sort - count
```

---

## Exfil Scenario (14 days)

### Attack timeline
```spl
index=* demo_id=exfil | timechart span=1d count by sourcetype
```

### Threat actor activity
```spl
index=network sourcetype=cisco:asa src=185.220.101.42 demo_id=exfil
| stats count by action, dest_port | sort - count
```

### Compromised users
```spl
index=* demo_id=exfil (user=jessica.brown OR user=alex.miller)
| stats count, earliest(_time) AS first, latest(_time) AS last by user, sourcetype
```

### Phishing email
```spl
index=cloud sourcetype="ms:o365:*" sender="*rnicrosoft-security.com" demo_id=exfil
```

### Lateral movement
```spl
index=* demo_id=exfil
  (src_ip=10.20.30.15 OR src_ip=10.10.30.55)
  (dest_ip=10.10.20.* OR dest_ip=10.20.20.*)
| stats count by src_ip, dest_ip, dest_port
```

### Cloud exfiltration
```spl
index=cloud (sourcetype=aws:cloudtrail OR sourcetype=google:gcp:*)
  (eventName=GetObject OR methodName=*get*)
  demo_id=exfil
| stats count by eventName, bucketName
```

### Exfil volume
```spl
index=network sourcetype=cisco:asa demo_id=exfil action=built dest_port=443
| bin _time span=1h
| stats sum(bytes) AS total_bytes by _time
| where total_bytes > 100000000
```

---

## Ransomware Attempt (Day 8)

### Full kill chain
```spl
index=* demo_id=ransomware_attempt | sort _time
| table _time, sourcetype, host, EventCode, message, action
```

### Process creation chain
```spl
index=windows sourcetype=WinEventLog EventCode=4688
  ComputerName="AUS-WS-BWHITE01" demo_id=ransomware_attempt
| table _time, NewProcessName, ParentProcessName, CommandLine
```

### C2 communication
```spl
index=network sourcetype=cisco:asa
  src_ip=10.30.30.20 dest_ip=194.26.29.42
  demo_id=ransomware_attempt
| timechart count
```

### Lateral attempts
```spl
index=windows EventCode=4625 IpAddress=10.30.30.20 demo_id=ransomware_attempt
| stats count by TargetUserName, IpPort
```

### Meraki isolation
```spl
index=network sourcetype=meraki:mx type=client_isolated demo_id=ransomware_attempt
| table _time, deviceName, clientMac, eventData.reason
```

---

## Memory Leak (10 days)

### Memory trend
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| timechart span=4h avg(mem_used_pct) AS "Memory %"
```

### OOM detection
```spl
index=linux sourcetype=vmstat host=WEB-01 mem_used_pct>95 demo_id=memory_leak
| table _time, mem_used_pct, swap_used_pct
```

### Timeout correlation (ASA)
```spl
index=network sourcetype=cisco:asa dest=172.16.1.10
  ("%ASA-6-302014" OR "%ASA-6-710003")
  demo_id=memory_leak
| timechart span=1h count
```

### Daily progression
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| eval day=strftime(_time, "%Y-%m-%d")
| stats avg(mem_used_pct) AS avg_mem, max(mem_used_pct) AS max_mem by day
| sort day
```

---

## CPU Runaway (Days 11-12)

### CPU trend
```spl
index=windows demo_host="SQL-PROD-01" demo_id=cpu_runaway
  counter="% Processor Time"
| timechart span=15m avg(Value) AS "CPU %"
```

### Pre/during/post comparison
```spl
index=windows demo_host="SQL-PROD-01" demo_id=cpu_runaway
  counter="% Processor Time"
| eval phase=case(
    _time < relative_time(now(), "-2d"), "Before",
    _time < relative_time(now(), "-1d"), "During",
    true(), "After"
)
| stats avg(Value) by phase
```

### SQL errors (WinEventLog)
```spl
index=windows sourcetype=WinEventLog
  (EventCode=17883 OR EventCode=833 OR EventCode=19406)
  ComputerName="SQL-PROD-01" demo_id=cpu_runaway
| table _time, EventCode, Message
```

### Connection failures
```spl
index=network sourcetype=cisco:asa dest=10.10.20.30 dest_port=1433
  demo_id=cpu_runaway
| timechart span=15m count by action
```

---

## Disk Filling (14 days)

### Disk progression
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| timechart span=1d avg(pct_used) AS "Disk %"
```

### Daily breakdown
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| eval day=strftime(_time, "%Y-%m-%d")
| stats min(pct_used) AS min, max(pct_used) AS max, avg(pct_used) AS avg by day
| sort day
```

### IO wait correlation
```spl
index=linux host=MON-ATL-01 demo_id=disk_filling
  (sourcetype=df OR sourcetype=vmstat)
| eval metric=if(sourcetype="df", "disk_pct", "io_wait")
| eval value=if(sourcetype="df", pct_used, io_wait)
| timechart span=4h avg(value) by metric
```

### Threshold alerts
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| eval severity=case(
    pct_used >= 95, "EMERGENCY",
    pct_used >= 85, "CRITICAL",
    pct_used >= 75, "WARNING",
    true(), "NORMAL"
)
| timechart span=1d count by severity
```

### Free space calculation
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| eval free_gb = (100 - pct_used) * 5
| timechart span=1d avg(free_gb) AS "Free GB"
```

---

## Firewall Misconfig (Day 7)

### Incident timeline
```spl
index=network sourcetype=cisco:asa demo_id=firewall_misconfig
| sort _time
| table _time, action, message
```

### Config changes
```spl
index=network sourcetype=cisco:asa
  ("%ASA-5-111008" OR "%ASA-5-111010")
  demo_id=firewall_misconfig
| table _time, message
```

### Blocked connections
```spl
index=network sourcetype=cisco:asa
  "%ASA-4-106023" demo_id=firewall_misconfig
| timechart span=5m count AS "Blocked Connections"
```

### Customer impact
```spl
index=network sourcetype=cisco:asa
  "%ASA-4-106023" demo_id=firewall_misconfig
| stats count AS blocked, dc(src_ip) AS unique_customers
```

---

## Certificate Expiry (Day 12)

### SSL failures
```spl
index=network sourcetype=cisco:asa
  ("%ASA-6-725007" OR "%ASA-4-725006")
  demo_id=certificate_expiry
| timechart span=1h count
```

### Certificate error details
```spl
index=network sourcetype=cisco:asa
  "%ASA-4-725006" "certificate expired"
  demo_id=certificate_expiry
| table _time, message
```

### HTTP errors
```spl
index=web sourcetype=access_combined
  (status=502 OR status=503)
  demo_id=certificate_expiry
| timechart span=1h count by status
```

### Recovery verification
```spl
index=network sourcetype=cisco:asa demo_id=certificate_expiry
| eval status=case(
    match(message, "725007|725006"), "Failed",
    match(message, "725001"), "Success",
    true(), "Other"
)
| timechart span=15m count by status
```

---

## Cross-Scenario Analysis

### All security events
```spl
index=* demo_id IN ("exfil", "ransomware_attempt")
| timechart span=1d count by demo_id
```

### All ops events
```spl
index=* demo_id IN ("memory_leak", "cpu_runaway", "disk_filling")
| timechart span=1d count by demo_id
```

### All network events
```spl
index=* demo_id IN ("firewall_misconfig", "certificate_expiry")
| timechart span=1h count by demo_id
```

### Event count by category
```spl
index=* demo_id=*
| eval category=case(
    demo_id IN ("exfil", "ransomware_attempt"), "Security",
    demo_id IN ("memory_leak", "cpu_runaway", "disk_filling"), "Operations",
    demo_id IN ("firewall_misconfig", "certificate_expiry"), "Network",
    true(), "Other"
)
| stats count by category, demo_id
```

