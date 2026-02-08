# Windows Performance Monitor

Windows server and workstation performance metrics including CPU, memory, disk, and network.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `perfmon` |
| Format | Multiline Key-Value |
| Output File | `output/windows/perfmon.log` |
| Volume | 12 measurements/hour/server |
| Interval | 5 minutes |

---

## Monitored Servers

| Server | Role | Location |
|--------|------|----------|
| BOS-DC-01 | Domain Controller | Boston |
| BOS-DC-02 | Domain Controller | Boston |
| BOS-FILE-01 | File Server | Boston |
| BOS-SQL-PROD-01 | SQL Database | Boston |
| ATL-DC-01 | Domain Controller | Atlanta |
| ATL-FILE-01 | File Server | Atlanta |
| + Workstations | Client PCs | All sites |

---

## Collections & Counters

### Processor
| Counter | Description | Normal Range |
|---------|-------------|--------------|
| `% Processor Time` | Total CPU usage | 20-60% |
| `% User Time` | User-mode CPU | 15-40% |
| `% Privileged Time` | Kernel-mode CPU | 5-20% |
| `% Interrupt Time` | Interrupt handling | 0-5% |

### Memory
| Counter | Description | Normal Range |
|---------|-------------|--------------|
| `% Committed Bytes In Use` | Memory usage | 40-70% |
| `Available MBytes` | Free memory | >1000 MB |
| `Pages/sec` | Paging activity | <50 |

### PhysicalDisk
| Counter | Description | Normal Range |
|---------|-------------|--------------|
| `% Disk Time` | Disk busy % | <50% |
| `Avg. Disk Queue Length` | Queue depth | <2 |
| `Free Space` | Free disk (%) | >20% |

### Network Interface
| Counter | Description | Normal Range |
|---------|-------------|--------------|
| `Bytes Sent/sec` | Outbound traffic | Variable |
| `Bytes Received/sec` | Inbound traffic | Variable |
| `Packets/sec` | Packet rate | Variable |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | MM/DD/YYYY HH:MM:SS.mmm | `01/05/2026 14:23:45.123` |
| `collection` | Collection name | `Processor` |
| `object` | Performance object | `Processor` |
| `counter` | Counter name | `% Processor Time` |
| `instance` | Instance | `_Total`, `0`, `C:` |
| `Value` | Metric value | `45.23` |
| `demo_host` | Server name | `SQL-PROD-01` |
| `demo_id` | Scenario tag | `cpu_runaway` |

---

## Example Events

### Normal CPU Usage
```
01/05/2026 14:23:45.123
collection="Processor"
object=Processor
counter="% Processor Time"
instance=_Total
Value=32.45
demo_host=BOS-DC-01
```

### CPU Runaway (High CPU)
```
01/11/2026 16:00:00.000
collection="Processor"
object=Processor
counter="% Processor Time"
instance=_Total
Value=98.7
demo_host=SQL-PROD-01
demo_id=cpu_runaway
```

### Memory Usage
```
01/05/2026 14:23:45.123
collection="Memory"
object=Memory
counter="% Committed Bytes In Use"
instance=_Total
Value=58.2
demo_host=BOS-FILE-01
```

### Disk Usage
```
01/05/2026 14:23:45.123
collection="PhysicalDisk"
object=PhysicalDisk
counter="% Disk Time"
instance=C:
Value=12.5
demo_host=ATL-DC-01
```

### Network Traffic
```
01/05/2026 14:23:45.123
collection="Network Interface"
object="Network Interface"
counter="Bytes Sent/sec"
instance="Intel[R] Ethernet"
Value=524288
demo_host=BOS-SQL-PROD-01
```

---

## Use Cases

### 1. CPU Trend Analysis
Track CPU over time:
```spl
index=windows sourcetype=perfmon counter="% Processor Time" instance="_Total"
| timechart span=15m avg(Value) by demo_host
```

### 2. High CPU Detection
Find servers with high CPU:
```spl
index=windows sourcetype=perfmon counter="% Processor Time" Value>80
| stats count, avg(Value) AS avg_cpu, max(Value) AS max_cpu by demo_host
| where count > 3
```

### 3. Memory Pressure
Identify memory issues:
```spl
index=windows sourcetype=perfmon counter="% Committed Bytes In Use"
| timechart span=1h avg(Value) by demo_host
```

### 4. Disk Space Monitoring
Track available disk:
```spl
index=windows sourcetype=perfmon counter="Free Space"
| stats latest(Value) AS free_pct by demo_host, instance
| where free_pct < 20
```

### 5. CPU Runaway Timeline
Full CPU runaway scenario:
```spl
index=windows sourcetype=perfmon demo_id=cpu_runaway counter="% Processor Time"
| timechart span=15m avg(Value) AS cpu_pct
```

### 6. Pre/During/Post Comparison
Compare CPU across scenario phases:
```spl
index=windows sourcetype=perfmon demo_host="SQL-PROD-01" counter="% Processor Time"
| eval phase=case(
    _time < relative_time(now(), "-3d"), "Before",
    _time < relative_time(now(), "-1d"), "During",
    true(), "After"
)
| stats avg(Value) AS avg_cpu by phase
```

### 7. Server Health Dashboard
Multi-metric overview:
```spl
index=windows sourcetype=perfmon
| stats latest(Value) AS value by demo_host, counter
| eval metric=case(
    counter="% Processor Time", "CPU",
    counter="% Committed Bytes In Use", "Memory",
    counter="% Disk Time", "Disk",
    true(), counter
)
| xyseries demo_host metric value
```

---

## Scenario Integration

| Scenario | Server | Metric | Pattern |
|----------|--------|--------|---------|
| **cpu_runaway** | SQL-PROD-01 | CPU | 40%→100%→30% over 2 days |
| **exfil** | Various | Network | Elevated outbound traffic |

---

## CPU Runaway Timeline

```
Day 10 (baseline):  CPU ~35-45%
Day 11, 15:00:      CPU starts climbing
Day 11, 16:00:      CPU hits 80%
Day 11, 18:00:      CPU at 95-100%
Day 11-12 overnight: CPU stays at 98-100%
Day 12, 10:30:      Fix applied, CPU drops
Day 12, 11:00:      CPU back to normal (~30%)
```

---

## Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| CPU % | >70% | >90% |
| Memory % | >80% | >95% |
| Disk % | >80% | >95% |
| Disk Queue | >2 | >5 |
| Pages/sec | >50 | >100 |

---

## Talking Points

**CPU Runaway:**
> "Watch the CPU trend for SQL-PROD-01. Day 10 it's normal around 40%. Day 11 at 3 PM it starts climbing. By 6 PM we're at 100% and we stay there overnight. The fix comes Day 12 at 10:30 AM."

**Correlation:**
> "The ServiceNow incident was created when CPU hit 80%. The Windows Event Log shows SQL Server generating timeout errors. Perfmon gives us the metrics, other sources tell us the impact."

**Baseline:**
> "Normal CPU for SQL-PROD-01 is 30-45%. Anything sustained above 70% is unusual. The runaway hit 100% for almost 20 hours - that's a severe incident."

**Multi-Metric:**
> "CPU isn't the only story. During CPU runaway, disk I/O also spiked as the backup job was hammering the disk. Memory stayed stable because the issue wasn't a memory leak."

---

## Related Sources

- [WinEventLog](wineventlog.md) - Windows events
- [ServiceNow](servicenow.md) - Incident correlation
- [Cisco ASA](cisco_asa.md) - Network timeout correlation

