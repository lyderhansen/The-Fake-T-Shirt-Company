# Disk Filling Scenario

Monitoring server in Atlanta gradually fills up disk over 14 days. This demonstrates "slow burn" operational problems that are often overlooked until critical.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 14 days |
| Category | Ops |
| demo_id | `disk_filling` |
| Start | 45% disk usage |
| End | 98% disk usage |

---

## Target Server

| Attribute | Value |
|-----------|-------|
| Hostname | MON-ATL-01 |
| IP | 10.20.20.30 |
| Location | Atlanta |
| OS | Linux (Ubuntu 22.04) |
| Total Disk | 500 GB |
| Role | Monitoring server (Splunk forwarder) |

---

## Disk Progression

| Day | Disk % | Status | GB Free | IO Wait |
|-----|--------|--------|---------|---------|
| 1 | 45-50% | Normal | 250-275 | 0% |
| 2 | 48-52% | Normal | 240-260 | 0% |
| 3 | 50-55% | Normal | 225-250 | 0% |
| 4 | 55-60% | Normal | 200-225 | 0% |
| 5 | 60-65% | Gradual | 175-200 | 0% |
| 6 | 65-70% | Noticeable | 150-175 | 0% |
| 7 | 70-75% | Noticeable | 125-150 | 0% |
| **8** | **75-80%** | **WARNING** | 100-125 | +2-5% |
| 9 | 78-82% | WARNING | 90-110 | +5-10% |
| 10 | 82-88% | HIGH | 60-90 | +5-10% |
| **11** | **88-92%** | **CRITICAL** | 40-60 | +10-20% |
| 12 | 92-95% | CRITICAL | 25-40 | +10-20% |
| **13** | **95-97%** | **EMERGENCY** | 15-25 | +20-35% |
| 14 | 97-98% | EMERGENCY | 10-15 | +20-35% |

---

## Timeline Visualization

```
Disk %
100│                                              ████
 95│                                         █████
 90│                                    █████
 85│                               █████
 80│                          █████     ◄── Day 8: WARNING (75%)
 75│                     █████
 70│                █████
 65│           █████
 60│      █████                              ◄── Day 11: CRITICAL (85%)
 55│ █████
 50│█
 45├────────────────────────────────────────────────────►
   │ Day 1  3    5    7    9    11   13   14
                           │          │
                           │          └── EMERGENCY
                           └── WARNING starts
```

---

## Severity Levels

| Level | Disk % | Days | Action Recommended |
|-------|--------|------|-------------------|
| Normal | <75% | 1-7 | Routine monitoring |
| Warning | 75-85% | 8-10 | Investigate, plan cleanup |
| Critical | 85-95% | 11-12 | Immediate cleanup required |
| Emergency | >95% | 13-14 | Service impact likely |

---

## Root Cause

**Problem:** Excessive logging from monitoring agents without log rotation policy.

**Files growing:**
- `/var/log/splunkforwarder/` - Splunk forwarder logs
- `/var/log/monitoring/` - Agent debug logs
- `/var/log/syslog` - System logs not rotated

---

## IO Wait Correlation

As disk fills, IO wait increases (system spends more time waiting for disk):

```
IO Wait %
 35│                                              ████
 30│                                         █████
 25│                                    █████
 20│                               █████
 15│                          █████
 10│                     █████
  5│                █████
  0│████████████████
   └────────────────────────────────────────────────►
     Day 1    5      8     10     12     14
```

---

## Logs to Look For

### Linux df - Disk trend
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| timechart span=4h avg(pct_used) AS "Disk %"
```

### Linux - IO Wait correlation
```spl
index=linux sourcetype=vmstat host=MON-ATL-01 demo_id=disk_filling
| timechart span=4h avg(io_wait) AS io_wait, avg(disk_pct) AS disk
```

### Disk by mount point
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| stats latest(pct_used) AS disk_pct by mount
| sort - disk_pct
```

---

## Talking Points

**Trend:**
> "This shows a 14-day trend. Disk starts at 45% and climbs steadily to 98%. Day 8 we cross 75% - the warning threshold. Day 11 we're critical at 90%. Days 13-14 we're in the emergency zone."

**Root cause:**
> "The cause is excessive logging from monitoring agents without a log rotation policy. A simple configuration problem that grows to critical over time."

**Correlation:**
> "Notice how IO wait increases as the disk fills. When the disk is near full, the system works harder to find free space, affecting all I/O operations."

**Detection window:**
> "We had a full week of warning before reaching critical. With alerting at 70% disk usage, this could have been addressed during a maintenance window instead of becoming an emergency."

---

## Splunk Queries

### Disk progression over 14 days
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

### IO Wait correlation
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

### Free space in GB
```spl
index=linux sourcetype=df host=MON-ATL-01 demo_id=disk_filling
| eval free_gb = (100 - pct_used) * 5
| timechart span=1d avg(free_gb) AS "Free GB"
```
