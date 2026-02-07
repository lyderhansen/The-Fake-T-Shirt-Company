# Linux System Metrics

Linux server performance metrics including CPU, memory, disk, I/O, and network.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetypes | `linux:vmstat`, `linux:df`, `linux:iostat`, `linux:interfaces` |
| Format | Syslog Key-Value |
| Output Files | `output/linux/linux_*.log` |
| Volume | 12 measurements/hour/server |
| Interval | 5 minutes |

---

## Monitored Servers

| Server | Role | Location | IP |
|--------|------|----------|-----|
| WEB-01 | Web Server | Boston DMZ | 172.16.1.10 |
| WEB-02 | Web Server | Boston DMZ | 172.16.1.11 |
| MON-ATL-01 | Monitoring | Atlanta | 10.20.20.30 |

---

## Metric Types

### vmstat (CPU/Memory)
| Metric | Description | Normal Range |
|--------|-------------|--------------|
| `cpu_count` | Number of CPUs | Static |
| `pctIdle` | CPU idle % | 40-80% |
| `pctUser` | User CPU % | 10-40% |
| `pctSystem` | System CPU % | 5-15% |
| `pctIOWait` | I/O wait % | 0-10% |
| `mem_total_mb` | Total RAM (MB) | Static |
| `mem_used_pct` | Memory used % | 40-70% |
| `mem_available_mb` | Available RAM | >1000 MB |
| `swap_free_kb` | Free swap | >50% |

### df (Disk Space)
| Metric | Description | Normal Range |
|--------|-------------|--------------|
| `disk` | Mount point | `/`, `/var`, etc. |
| `pctUsed` | Disk used % | <80% |
| `inodesUsed` | Inode used % | <80% |
| `totalGb` | Total size (GB) | Static |
| `availGb` | Available (GB) | Variable |

### iostat (Disk I/O)
| Metric | Description | Normal Range |
|--------|-------------|--------------|
| `device` | Disk device | `sda`, `nvme0n1` |
| `readMBps` | Read MB/sec | Variable |
| `writeMBps` | Write MB/sec | Variable |
| `readIops` | Read ops/sec | Variable |
| `writeIops` | Write ops/sec | Variable |
| `avgWaitMs` | Avg I/O wait | <20 ms |
| `utilization` | Device busy % | <70% |

### interfaces (Network)
| Metric | Description | Normal Range |
|--------|-------------|--------------|
| `interface` | Interface name | `eth0`, `ens192` |
| `bytesIn` | Bytes received | Variable |
| `bytesOut` | Bytes sent | Variable |
| `packetsIn` | Packets in | Variable |
| `packetsOut` | Packets out | Variable |
| `errors` | Error count | 0 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | Syslog time | `Jan 05 14:23:45` |
| `host` | Server hostname | `WEB-01` |
| `metric type` | Metric category | `CPU`, `Memory`, `Disk` |
| `demo_id` | Scenario tag | `memory_leak` |

---

## Example Events

### CPU Metrics (vmstat)
```
Jan 05 14:23:45 WEB-01 vmstat: host=WEB-01 cpu_count=4 CPU pctIdle=68.5 pctUser=24.3 pctSystem=5.1 pctIOWait=2.1
```

### Memory Metrics (vmstat)
```
Jan 05 14:23:45 WEB-01 vmstat: host=WEB-01 Memory mem_total_mb=8192 mem_used_pct=58.2 mem_available_mb=3420 swap_free_kb=2097152
```

### Memory Leak (High Usage)
```
Jan 10 14:00:00 WEB-01 vmstat: host=WEB-01 Memory mem_total_mb=8192 mem_used_pct=97.5 mem_available_mb=205 swap_free_kb=524288 demo_id=memory_leak
```

### Disk Space (df)
```
Jan 05 14:23:45 MON-ATL-01 df: host=MON-ATL-01 Filesystem disk=/ pctUsed=45.2 inodesUsed=12.3 totalGb=500 availGb=274
```

### Disk Filling (High Usage)
```
Jan 13 14:00:00 MON-ATL-01 df: host=MON-ATL-01 Filesystem disk=/ pctUsed=96.5 inodesUsed=45.2 totalGb=500 availGb=17.5 demo_id=disk_filling
```

### Disk I/O (iostat)
```
Jan 05 14:23:45 WEB-01 iostat: host=WEB-01 device=sda readMBps=12.5 writeMBps=8.3 readIops=125 writeIops=83 avgWaitMs=4.5 utilization=23.5
```

### Network (interfaces)
```
Jan 05 14:23:45 WEB-01 interfaces: host=WEB-01 interface=eth0 bytesIn=1048576 bytesOut=2097152 packetsIn=1024 packetsOut=2048 errors=0
```

---

## Use Cases

### 1. Memory Leak Detection
Track memory growth over time:
```spl
index=linux sourcetype=linux:vmstat host=WEB-01 mem_used_pct=*
| timechart span=4h avg(mem_used_pct) AS "Memory %"
```

### 2. Disk Space Trending
Monitor disk filling:
```spl
index=linux sourcetype=linux:df host=MON-ATL-01
| timechart span=1d avg(pctUsed) AS "Disk %"
```

### 3. OOM Prediction
Find servers approaching OOM:
```spl
index=linux sourcetype=linux:vmstat mem_used_pct>90
| stats latest(mem_used_pct) AS mem_pct, latest(mem_available_mb) AS avail_mb by host
| where avail_mb < 500
```

### 4. Disk Space Alerts
Find critically full disks:
```spl
index=linux sourcetype=linux:df pctUsed>85
| stats latest(pctUsed) AS disk_pct, latest(availGb) AS free_gb by host, disk
| sort - disk_pct
```

### 5. Memory Leak Timeline
Full memory leak scenario:
```spl
index=linux sourcetype=linux:vmstat host=WEB-01 demo_id=memory_leak
| timechart span=4h avg(mem_used_pct) AS "Memory %"
```

### 6. Disk Filling Timeline
Full disk filling scenario:
```spl
index=linux sourcetype=linux:df host=MON-ATL-01 demo_id=disk_filling
| timechart span=1d avg(pctUsed) AS "Disk %"
```

### 7. I/O Wait Correlation
Correlate I/O wait with disk usage:
```spl
index=linux host=MON-ATL-01 (sourcetype=linux:vmstat OR sourcetype=linux:df)
| eval metric=if(sourcetype="linux:vmstat", "io_wait", "disk_pct")
| eval value=if(sourcetype="linux:vmstat", pctIOWait, pctUsed)
| timechart span=4h avg(value) by metric
```

### 8. Network Anomalies
Detect unusual traffic:
```spl
index=linux sourcetype=linux:interfaces host=WEB-01
| eval bytes_total = bytesIn + bytesOut
| timechart span=1h sum(bytes_total) AS total_bytes
```

---

## Scenario Integration

| Scenario | Server | Metric | Pattern |
|----------|--------|--------|---------|
| **memory_leak** | WEB-01 | Memory | 50%→98% over 10 days, OOM Day 10 |
| **disk_filling** | MON-ATL-01 | Disk | 45%→98% over 14 days |
| **exfil** | WEB-01 | Network | Elevated outbound Day 11-14 |

---

## Memory Leak Timeline

```
Day 1-2:   Memory ~50-55% (baseline)
Day 3-4:   Memory ~60-65%
Day 5-6:   Memory ~70-75%
Day 7-8:   Memory ~80-85%
Day 9:     Memory ~90-95%
Day 10:    Memory 98%+ → OOM crash at 14:00
```

---

## Disk Filling Timeline

```
Day 1-3:   Disk 45-55% (normal)
Day 4-6:   Disk 55-70%
Day 7:     Disk 70-75% ← Warning threshold
Day 8-10:  Disk 75-88% ← WARNING
Day 11:    Disk 88-92% ← CRITICAL
Day 12:    Disk 92-95%
Day 13-14: Disk 95-98% ← EMERGENCY
```

---

## Thresholds

| Metric | Warning | Critical | Emergency |
|--------|---------|----------|-----------|
| Memory % | >80% | >90% | >95% |
| Disk % | >75% | >85% | >95% |
| I/O Wait % | >20% | >40% | >60% |
| Swap Used % | >50% | >75% | >90% |

---

## Talking Points

**Memory Leak:**
> "Look at WEB-01's memory trend. Day 1 it's at 50%. Every day it climbs about 5%. By Day 9 we're at 95%. Day 10 at 2 PM - boom - OOM crash. This is a classic slow memory leak."

**Disk Filling:**
> "MON-ATL-01 starts at 45% disk. The slope tells us it's gaining about 4% per day. Day 7 we cross the warning threshold at 75%. By Day 13 we're at 96% - emergency territory."

**I/O Correlation:**
> "As the disk fills, I/O wait increases. The filesystem has to work harder to find free blocks. By Day 13, I/O wait is 25% - that's significant performance degradation."

**Root Cause:**
> "The memory leak was an application bug - objects not being released. The disk filling was excessive logging without rotation. Both are preventable with proper monitoring and configuration."

---

## Related Sources

- [Perfmon](perfmon.md) - Windows metrics (similar patterns)
- [ServiceNow](servicenow.md) - Incident correlation
- [Apache Access](access.md) - Web tier correlation

