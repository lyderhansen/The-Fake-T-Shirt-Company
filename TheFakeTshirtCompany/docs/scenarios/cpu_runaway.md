# CPU Runaway Scenario

SQL backup job on SQL-PROD-01 gets stuck and causes 100% CPU utilization for 32 hours. DBA identifies and fixes the problem on Day 12 at 10:30. The database outage cascades into GCP BigQuery pipeline failures as upstream data feeds go unavailable.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 2 days (Day 11-12) |
| Category | Ops |
| demo_id | `cpu_runaway` |
| Root Cause | Backup job hits locked table |
| Fix Time | Day 12 @ 10:30 |
| Primary Logs | Perfmon, WinEventLog, Access, GCP Audit |

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
| ~22:00 | 90%+ | GCP BigQuery pipeline starts failing (RESOURCE_EXHAUSTED) |

### Day 12 (Critical + Fix)

| Time | CPU % | Event |
|------|-------|-------|
| 02:00 | 94% | Near full capacity |
| ~03:00 | 95%+ | GCP BigQuery pipeline failures continue |
| 08:00 | 100% | Full CPU saturation |
| **10:30** | **30%** | **DBA kills job, restarts SQL** |
| 14:00 | 22% | Normalizing |
| 18:00 | 15% | Normal operation |

---

## Timeline Visualization

```
CPU %
100|                              ________________
 90|                         _____                v FIX @10:30
 80|                    _____                     |
 70|               _____                          |
 60|          _____                               |
 50|     _____                                    |
 40|_____                                         ____
 30|                                              |   ____
 20|                                              |       ____
 15|                                              |           ________
   +----------------------------------------------+--------------------->
   | Day 11                                       | Day 12
   | 02:00                                        | 10:30
   | Backup starts                                | DBA fixes
```

---

## Impact Chain

```
Backup Job Stuck
       |
       v
   CPU 100%
       |
       +---> Memory Pressure (+25%)
       |
       +---> Disk Queue (8x normal)
       |
       +---> SQL Connection Timeouts
       |         |
       |         +---> GCP BigQuery Pipeline Failures
       |                (RESOURCE_EXHAUSTED -- upstream DB unavailable)
       |
       +---> Web Server 502 Errors
                  |
                  v
           Customer Impact
```

---

## Cross-Cloud Cascade (GCP)

When SQL-PROD-01 becomes unresponsive, the GCP BigQuery data pipeline loses its upstream data feed. The pipeline jobs fail with `RESOURCE_EXHAUSTED` errors because the source database connection times out after 300 seconds.

| Day | Time | GCP Event | Details |
|-----|------|-----------|---------|
| 11 | ~22:00 | `jobservice.jobcompleted` (ERROR) | Data source connection failed -- upstream database unavailable |
| 12 | ~03:00 | `jobservice.jobcompleted` (ERROR) | Data source connection timeout after 300s |
| 12 | ~10:30+ | Pipeline recovers | SQL-PROD-01 back online after DBA fix |

These events appear in GCP Audit logs as BigQuery job failures tagged `demo_id=cpu_runaway`. The error chain is: SQL CPU 100% -> connection timeouts -> BigQuery ETL jobs fail -> `RESOURCE_EXHAUSTED`.

---

## Logs to Look For

### Perfmon - CPU trend
```spl
index=fake_tshrt sourcetype="FAKE:perfmon"
  host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| timechart span=1h avg(Value) AS "CPU %"
```

### Windows Event Log - SQL errors
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog"
  host=SQL-PROD-01
  (EventCode=17883 OR EventCode=833 OR EventCode=19406)
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
index=fake_tshrt sourcetype="FAKE:WinEventLog"
  host=SQL-PROD-01
  (EventCode=17148 OR EventCode=17147)
  demo_id=cpu_runaway
```

**Fix events:**
| EventID | Meaning |
|---------|---------|
| 17148 | "KILL command issued for SPID 67" |
| 17147 | "SQL Server service restarted successfully" |

### Access Log - Error rates
```spl
index=fake_tshrt sourcetype="FAKE:access_combined"
  (status=502 OR status=503)
  demo_id=cpu_runaway
| timechart span=1h count AS errors
```

### GCP BigQuery - Pipeline failures
```spl
index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message"
  protoPayload.serviceName="bigquery.googleapis.com"
  severity=ERROR
  demo_id=cpu_runaway
| table _time, protoPayload.resourceName, protoPayload.status.message
| sort _time
```

---

## Talking Points

**The problem:**
> "Look at this CPU graph. Day 11 at 02:00, the backup job starts. CPU climbs steadily from 40% to 100% over 32 hours. Users start complaining around 65% - 'the system is slow'."

**Impact:**
> "At 100% CPU, we see cascading effects: database connections time out, the web server returns 502 errors, and users can't complete orders."

**Cross-cloud cascade:**
> "Here's what makes this interesting for a multi-cloud shop. When SQL-PROD-01 goes down, it's not just Perfmon that shows it. GCP BigQuery's data pipeline fails too -- RESOURCE_EXHAUSTED errors because the upstream database is unavailable. This is how on-prem incidents cascade into cloud services."

**The solution:**
> "Day 12 at 10:30, the DBA identifies the problem. A KILL command terminates the stuck process, and SQL Server is restarted. CPU drops immediately to 30% and normalizes to 15% over a few hours."

**Root cause:**
> "Root cause: backup job hit a locked table and went into an infinite retry loop. The fix was simple, but finding it took time because monitoring alerts were set at 90%, not 75%."

---

## Splunk Queries

### CPU over time
```spl
index=fake_tshrt sourcetype="FAKE:perfmon" host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| timechart span=30m avg(Value) AS cpu
```

### Disk queue correlation
```spl
index=fake_tshrt sourcetype="FAKE:perfmon" host=SQL-PROD-01
  (counter="% Processor Time" OR counter="Current Disk Queue Length")
  demo_id=cpu_runaway
| timechart span=1h avg(Value) by counter
```

### Before and after fix
```spl
index=fake_tshrt sourcetype="FAKE:perfmon" host=SQL-PROD-01
  counter="% Processor Time"
  demo_id=cpu_runaway
| where strftime(_time, "%Y-%m-%d") = "2026-01-12"
| timechart span=15m avg(Value) AS cpu
```

### Error correlation (on-prem + cloud)
```spl
index=fake_tshrt demo_id=cpu_runaway
  (host=SQL-PROD-01 OR sourcetype="FAKE:access_combined"
   OR sourcetype="FAKE:google:gcp:pubsub:message")
| eval metric=case(
    sourcetype="FAKE:perfmon" AND counter="% Processor Time", "CPU %",
    sourcetype="FAKE:access_combined" AND status>=500, "HTTP 5xx",
    sourcetype="FAKE:google:gcp:pubsub:message" AND severity="ERROR", "GCP BigQuery Error",
    true(), "other"
)
| timechart span=1h count by metric
```

### Fix event detail
```spl
index=fake_tshrt sourcetype="FAKE:WinEventLog" host=SQL-PROD-01
  (EventCode=17148 OR EventCode=17147)
  demo_id=cpu_runaway
| table _time, EventCode, Message
```

### GCP pipeline failure timeline
```spl
index=fake_tshrt sourcetype="FAKE:google:gcp:pubsub:message"
  demo_id=cpu_runaway
| table _time, protoPayload.methodName, protoPayload.status.code,
    protoPayload.status.message, severity
| sort _time
```
