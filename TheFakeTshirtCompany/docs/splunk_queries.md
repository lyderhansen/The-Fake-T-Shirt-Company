# Splunk Queries Reference

Consolidated SPL queries for all demo scenarios. All queries use `index=fake_tshrt` with `FAKE:`-prefixed sourcetypes and the `demo_id` field for filtering.

---

## Universal Queries

### Find all scenario events
```spl
index=fake_tshrt demo_id=* | stats count by demo_id, sourcetype
```

### Timeline by scenario
```spl
index=fake_tshrt demo_id=* | timechart span=1d count by demo_id
```

### Sourcetype distribution
```spl
index=fake_tshrt demo_id=<scenario_name> | stats count by sourcetype | sort - count
```

---

## Exfil Scenario (14 days)

### Attack timeline
```spl
index=fake_tshrt demo_id=exfil | timechart span=1d count by sourcetype
```

### Threat actor activity
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" src=185.220.101.42 demo_id=exfil
| stats count by action, dest_port | sort - count
```

### Compromised users
```spl
index=fake_tshrt demo_id=exfil (user=jessica.brown OR user=alex.miller)
| stats count, earliest(_time) AS first, latest(_time) AS last by user, sourcetype
```

### Phishing email
```spl
index=fake_tshrt sourcetype="FAKE:ms:o365:reporting:messagetrace" sender="*rnicrosoft-security.com" demo_id=exfil
```

### Lateral movement
```spl
index=fake_tshrt demo_id=exfil
  (src_ip=10.20.30.15 OR src_ip=10.10.30.55)
  (dest_ip=10.10.20.* OR dest_ip=10.20.20.*)
| stats count by src_ip, dest_ip, dest_port
```

### Cloud exfiltration
```spl
index=fake_tshrt (sourcetype="FAKE:aws:cloudtrail" OR sourcetype="FAKE:google:gcp:pubsub:message")
  (eventName=GetObject OR methodName=*get*)
  demo_id=exfil
| stats count by eventName, bucketName
```

### Exfil volume
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=exfil action=built dest_port=443
| bin _time span=1h
| stats sum(bytes) AS total_bytes by _time
| where total_bytes > 100000000
```

### GuardDuty findings
```spl
index=fake_tshrt sourcetype="FAKE:aws:cloudwatch:guardduty" demo_id=exfil
| table _time, detail.type, detail.severity, detail.resource.instanceDetails.instanceId
| sort _time
```

### Billing anomaly
```spl
index=fake_tshrt sourcetype="FAKE:aws:billing:cur" demo_id=exfil
  lineItem_ProductCode="AmazonS3" lineItem_UsageType="*DataTransfer-Out*"
| timechart span=1d sum(lineItem_UnblendedCost) AS daily_cost
```

---

## Ransomware Attempt (Day 8)

### Full kill chain
```spl
index=fake_tshrt demo_id=ransomware_attempt | sort _time
| table _time, sourcetype, host, EventCode, message, action
```

### Process creation chain
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4688
  ComputerName="AUS-WS-BWHITE01" demo_id=ransomware_attempt
| table _time, NewProcessName, ParentProcessName, CommandLine
```

### C2 communication
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  src_ip=10.30.30.20 dest_ip=194.26.29.42
  demo_id=ransomware_attempt
| timechart count
```

### Lateral attempts
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" EventCode=4625 IpAddress=10.30.30.20 demo_id=ransomware_attempt
| stats count by TargetUserName, IpPort
```

### Meraki isolation
```spl
index=fake_tshrt sourcetype="FAKE:meraki:mx" type=client_isolated demo_id=ransomware_attempt
| table _time, deviceName, clientMac, eventData.reason
```

---

## Memory Leak (10 days)

### Memory trend
```spl
index=fake_tshrt sourcetype="FAKE:vmstat" host=WEB-01 demo_id=memory_leak
| timechart span=4h avg(mem_used_pct) AS "Memory %"
```

### OOM detection
```spl
index=fake_tshrt sourcetype="FAKE:vmstat" host=WEB-01 mem_used_pct>95 demo_id=memory_leak
| table _time, mem_used_pct, swap_used_pct
```

### Timeout correlation (ASA)
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" dest=172.16.1.10
  ("%ASA-6-302014" OR "%ASA-6-710003")
  demo_id=memory_leak
| timechart span=1h count
```

### Daily progression
```spl
index=fake_tshrt sourcetype="FAKE:vmstat" host=WEB-01 demo_id=memory_leak
| eval day=strftime(_time, "%Y-%m-%d")
| stats avg(mem_used_pct) AS avg_mem, max(mem_used_pct) AS max_mem by day
| sort day
```

---

## CPU Runaway (Days 11-12)

### CPU trend
```spl
index=fake_tshrt demo_host="SQL-PROD-01" demo_id=cpu_runaway
  counter="% Processor Time"
| timechart span=15m avg(Value) AS "CPU %"
```

### Pre/during/post comparison
```spl
index=fake_tshrt demo_host="SQL-PROD-01" demo_id=cpu_runaway
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
index=fake_tshrt sourcetype="FAKE:WinEventLog"
  (EventCode=17883 OR EventCode=833 OR EventCode=19406)
  ComputerName="SQL-PROD-01" demo_id=cpu_runaway
| table _time, EventCode, Message
```

### Connection failures
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" dest=10.10.20.30 dest_port=1433
  demo_id=cpu_runaway
| timechart span=15m count by action
```

### GCP BigQuery pipeline failures
```spl
index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message"
  protoPayload.serviceName="bigquery.googleapis.com" severity=ERROR
  demo_id=cpu_runaway
| table _time, protoPayload.status.message
```

---

## Disk Filling (14 days)

### Disk progression
```spl
index=fake_tshrt sourcetype="FAKE:df" host=MON-ATL-01 demo_id=disk_filling
| timechart span=1d avg(pct_used) AS "Disk %"
```

### Daily breakdown
```spl
index=fake_tshrt sourcetype="FAKE:df" host=MON-ATL-01 demo_id=disk_filling
| eval day=strftime(_time, "%Y-%m-%d")
| stats min(pct_used) AS min, max(pct_used) AS max, avg(pct_used) AS avg by day
| sort day
```

### IO wait correlation
```spl
index=fake_tshrt host=MON-ATL-01 demo_id=disk_filling
  (sourcetype="FAKE:df" OR sourcetype="FAKE:vmstat")
| eval metric=if(sourcetype="FAKE:df", "disk_pct", "io_wait")
| eval value=if(sourcetype="FAKE:df", pct_used, io_wait)
| timechart span=4h avg(value) by metric
```

### Threshold alerts
```spl
index=fake_tshrt sourcetype="FAKE:df" host=MON-ATL-01 demo_id=disk_filling
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
index=fake_tshrt sourcetype="FAKE:df" host=MON-ATL-01 demo_id=disk_filling
| eval free_gb = (100 - pct_used) * 5
| timechart span=1d avg(free_gb) AS "Free GB"
```

---

## Firewall Misconfig (Day 7)

### Incident timeline
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=firewall_misconfig
| sort _time
| table _time, action, message
```

### Config changes
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  ("%ASA-5-111008" OR "%ASA-5-111010")
  demo_id=firewall_misconfig
| table _time, message
```

### Blocked connections
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-106023" demo_id=firewall_misconfig
| timechart span=5m count AS "Blocked Connections"
```

### Customer impact
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-106023" demo_id=firewall_misconfig
| stats count AS blocked, dc(src_ip) AS unique_customers
```

---

## Certificate Expiry (Day 12)

### SSL failures
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  ("%ASA-6-725007" OR "%ASA-4-725006")
  demo_id=certificate_expiry
| timechart span=1h count
```

### Certificate error details
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa"
  "%ASA-4-725006" "certificate expired"
  demo_id=certificate_expiry
| table _time, message
```

### HTTP errors
```spl
index=fake_tshrt sourcetype="FAKE:access_combined"
  (status=502 OR status=503)
  demo_id=certificate_expiry
| timechart span=1h count by status
```

### Recovery verification
```spl
index=fake_tshrt sourcetype="FAKE:cisco:asa" demo_id=certificate_expiry
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
index=fake_tshrt demo_id IN ("exfil", "ransomware_attempt")
| timechart span=1d count by demo_id
```

### All ops events
```spl
index=fake_tshrt demo_id IN ("memory_leak", "cpu_runaway", "disk_filling")
| timechart span=1d count by demo_id
```

### All network events
```spl
index=fake_tshrt demo_id IN ("firewall_misconfig", "certificate_expiry")
| timechart span=1h count by demo_id
```

### Event count by category
```spl
index=fake_tshrt demo_id=*
| eval category=case(
    demo_id IN ("exfil", "ransomware_attempt"), "Security",
    demo_id IN ("memory_leak", "cpu_runaway", "disk_filling"), "Operations",
    demo_id IN ("firewall_misconfig", "certificate_expiry"), "Network",
    true(), "Other"
)
| stats count by category, demo_id
```

---

## SAP Stock & Inventory

### Net stock flow per product
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type=*
| eval direction=case(
    mvt_type IN ("101","501"), "inbound",
    mvt_type IN ("201","261","601"), "outbound",
    mvt_type="301", "transfer")
| eval signed_qty=if(direction="outbound", qty*-1, qty)
| stats sum(signed_qty) as net_flow
    sum(eval(if(direction="inbound",qty,0))) as total_in
    sum(eval(if(direction="outbound",qty,0))) as total_out
    dc(mvt_type) as mvt_types
    by material_id material_name
| eval total_out=abs(total_out)
| sort -net_flow
```

### Daily inventory movement trend
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type=*
| eval direction=case(
    mvt_type IN ("101","501"), "inbound",
    mvt_type IN ("201","261","601"), "outbound",
    mvt_type="301", "transfer")
| timechart span=1d count by direction
```

### Top 10 products by outbound volume
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type IN ("201","261","601")
| stats sum(qty) as total_issued count as movements by material_id material_name
| sort -total_issued
| head 10
```

### Goods Receipt vs Goods Issue balance
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type IN ("101","501","201","261","601")
| eval flow=if(mvt_type IN ("101","501"), "receipts", "issues")
| timechart span=1d sum(qty) as total_qty by flow
```

### Products with lowest net stock (stockout risk)
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type=*
| eval signed_qty=case(
    mvt_type IN ("101","501"), qty,
    mvt_type IN ("201","261","601"), qty*-1,
    1=1, 0)
| stats sum(signed_qty) as net_stock by material_id material_name
| sort net_stock
| head 10
```

### Movement type distribution per week
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO mvt_type=*
| eval mvt_label=case(
    mvt_type="101","101-GR for PO",
    mvt_type="201","201-GI Cost Center",
    mvt_type="261","261-GI Production",
    mvt_type="301","301-Stock Transfer",
    mvt_type="501","501-Receipt w/o PO",
    mvt_type="601","601-GI Delivery")
| timechart span=1w count by mvt_label
```

### Inventory variance events (shrinkage)
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=MIGO "VARIANCE DETECTED"
| table _time user material_id material_name qty mvt_type
```

---

## SAP Sales & Revenue

### Daily sales orders with revenue
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=VA01 amount=*
| timechart span=1d count as orders sum(amount) as revenue
```

### Sales order lifecycle pipeline
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode IN ("VA01","VL01N","VF01")
| eval stage=case(
    tcode="VA01","1-Order Created",
    tcode="VL01N","2-Delivery Created",
    tcode="VF01","3-Invoice Posted")
| stats count by stage
| sort stage
```

### Top 10 users by invoiced revenue
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode=VF01 amount=*
| stats sum(amount) as total_invoiced count as invoices by user
| sort -total_invoiced
| head 10
```

### Web orders vs SAP sales orders correlation
```spl
index=fake_tshrt
    (sourcetype="FAKE:sap:auditlog" tcode=VA01)
    OR (sourcetype="FAKE:retail:orders" status="created")
| eval source_type=if(sourcetype="FAKE:sap:auditlog","SAP Sales Orders","Web Orders")
| timechart span=1d count by source_type
```

---

## Retail Orders

### Order status funnel
```spl
index=fake_tshrt sourcetype="FAKE:retail:orders"
| stats count by status
| eval sort_order=case(
    status="created",1, status="payment_confirmed",2,
    status="processing",3, status="shipped",4,
    status="delivered",5, status="payment_declined",6,
    status="cancelled",7, status="address_validation_failed",8)
| sort sort_order
| table status count
```
