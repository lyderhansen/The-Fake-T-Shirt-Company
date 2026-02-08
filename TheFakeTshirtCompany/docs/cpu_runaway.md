# CPU Runaway Scenario

SQL backup job on SQL-PROD-01 gets stuck and causes 100% CPU utilization for 32 hours. DBA identifies and fixes the problem on Day 12 at 10:30.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 2 days (Day 11-12) |
| Category | Ops |
| demo_id | `cpu_runaway` |
| Root Cause | Backup job hits locked table |
| Fix Time | Day 12 @ 10:30 |

---

## Target Server

| Attribute | Value |
|-----------|-------|
| Hostname | SQL-PROD-01 |
| IP | 10.10.20.30 |
| Location | Boston |
| OS | Windows Server 2022 |
| Role | Production SQL Database |

---

## Timeline

### Day 11 (Start)

| Time | CPU % | Event |
|------|-------|-------|
| 02:00 | 40% | Backup job starts |
| 08:00 | 65% | Users notice slowness |
| 14:00 | 78% | Application timeouts start |
| 20:00 | 88% | Disk queue building |

### Day 12 (Critical + Fix)

| Time | CPU % | Event |
|------|-------|-------|
| 02:00 | 94% | Near full capacity |
| 08:00 | 100% | Full CPU saturation |
| **10:30** | **30%** | **DBA kills job, restarts SQL** |
| 14:00 | 22% | Normalizing |
| 18:00 | 15% | Normal operation |

---

## Timeline Visualization

```
CPU %
100│                              ████████████████
 90│                         █████                ▼ FIX @10:30
 80│                    █████                     │
 70│               █████                          │
 60│          █████                               │
 50│     █████                                    │
 40│█████                                         ████
 30│                                              │   ████
 20│                                              │       ████
 15│                                              │           ████████
   ├──────────────────────────────────────────────┴───────────────────►
   │ Day 11                                       │ Day 12
   │ 02:00                                        │ 10:30
   │ Backup starts                                │ DBA fixes
```

---

## Impact Chain

```
Backup Job Stuck
       │
       ▼
   CPU 100%
       │
       ├──► Memory Pressure (+25%)
       │
       ├──► Disk Queue (8x normal)
       │
       ├──► SQL Connection Timeouts
       │
       └──► Web Server 502 Errors
                  │
                  ▼
           Customer Impact
```

---

## Logs to Look For

### Perfmon - CPU trend
```spl
index=windows sourcetype=perfmon
  host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| timechart span=1h avg(Value) AS "CPU %"
```

### Windows Event Log - SQL errors
```spl
index=windows sourcetype=XmlWinEventLog
  host=SQL-PROD-01
  (EventID=17883 OR EventID=833 OR EventID=19406)
  demo_id=cpu_runaway
| sort _time
```

**Event types:**
| EventID | Meaning |
|---------|---------|
| 17883 | "Process appears to be non-yielding on CPU" |
| 833 | "I/O requests taking longer than 15 seconds" |
| 19406 | "Backup job is not responding" |

### Windows Event Log - Fix events
```spl
index=windows sourcetype=XmlWinEventLog
  host=SQL-PROD-01
  (EventID=17148 OR EventID=17147)
  demo_id=cpu_runaway
```

**Fix events:**
| EventID | Meaning |
|---------|---------|
| 17148 | "KILL command issued for SPID 67" |
| 17147 | "SQL Server service restarted successfully" |

### Access Log - Error rates
```spl
index=web sourcetype=access_combined
  (status=502 OR status=503)
  demo_id=cpu_runaway
| timechart span=1h count AS errors
```

---

## Talking Points

**The problem:**
> "Look at this CPU graph. Day 11 at 02:00, the backup job starts. CPU climbs steadily from 40% to 100% over 32 hours. Users start complaining around 65% - 'the system is slow'."

**Impact:**
> "At 100% CPU, we see cascading effects: database connections time out, the web server returns 502 errors, and users can't complete orders."

**The solution:**
> "Day 12 at 10:30, the DBA identifies the problem. A KILL command terminates the stuck process, and SQL Server is restarted. CPU drops immediately to 30% and normalizes to 15% over a few hours."

**Root cause:**
> "Root cause: backup job hit a locked table and went into an infinite retry loop. The fix was simple, but finding it took time because monitoring alerts were set at 90%, not 75%."

---

## Splunk Queries

### CPU over time
```spl
index=windows sourcetype=perfmon host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| timechart span=30m avg(Value) AS cpu
```

### Disk queue correlation
```spl
index=windows sourcetype=perfmon host=SQL-PROD-01
  (counter="% Processor Time" OR counter="Current Disk Queue Length")
  demo_id=cpu_runaway
| timechart span=1h avg(Value) by counter
```

### Before and after fix
```spl
index=windows sourcetype=perfmon host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| where strftime(_time, "%Y-%m-%d") = "2026-01-12"
| timechart span=15m avg(Value) AS cpu
```

### Error correlation
```spl
index=* demo_id=cpu_runaway
  (host=SQL-PROD-01 OR sourcetype=access_combined)
| eval metric=case(
    sourcetype="perfmon" AND counter="% Processor Time", "CPU %",
    sourcetype="access_combined" AND status>=500, "HTTP 5xx",
    true(), "other"
)
| timechart span=1h count by metric
```

### Fix event detail
```spl
index=windows sourcetype=XmlWinEventLog host=SQL-PROD-01
  (EventID=17148 OR EventID=17147)
  demo_id=cpu_runaway
| table _time, EventID, Message
```
