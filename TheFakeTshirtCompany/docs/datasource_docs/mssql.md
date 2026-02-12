# Microsoft SQL Server

SQL Server ERRORLOG entries from SQL-PROD-01, the primary e-commerce database server.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `mssql:errorlog` |
| Format | Native SQL Server ERRORLOG |
| Output File | `output/windows/mssql_errorlog.log` |
| Volume | ~50-200 events/day |
| Host | SQL-PROD-01 (10.10.20.30) |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `timestamp` | Event timestamp | `2026-01-05 14:23:45.32` |
| `source` | SQL component | `Logon`, `spid22`, `Server` |
| `error` | Error number | `17883` |
| `severity` | Error severity | `16` |
| `message` | Event description | `Login succeeded for user...` |
| `demo_id` | Scenario tag | `cpu_runaway` |

---

## Event Categories

| Category | Frequency | Description |
|----------|-----------|-------------|
| Startup/Recovery | Day 0 only | Server boot, database recovery |
| Nightly Backups | 02:00-03:00 daily | Full backup completions |
| Checkpoints | Every few hours | FlushCache/checkpoint events |
| User Logins | Business hours | Login succeeded/failed events |
| Deadlocks | Occasional | Lock contention events |

---

## Example Events

### User Login
```
2026-01-05 14:23:45.32 Logon       Login succeeded for user 'svc_ecommerce'. Connection made using SQL Server authentication. [CLIENT: 172.16.1.10]
```

### Nightly Backup
```
2026-01-05 02:35:12.45 spid22      Backup database successfully processed 45280 pages in 23.456 seconds (15.2 MB/sec).
```

### Non-Yielding Scheduler (cpu_runaway)
```
2026-01-10 15:30:22.11 spid67      Error: 17883, Severity: 16, State: 1.
                                    Process 0:0:0 (0x0043) Worker 0x0000DEADBEEF appears to be non-yielding on Scheduler 2. demo_id=cpu_runaway
```

### Failed Login (exfil lateral probing)
```
2026-01-06 22:15:30.78 Logon       Login failed for user 'jessica.brown'. Reason: Password did not match. [CLIENT: 10.20.30.15] demo_id=exfil
```

---

## Use Cases

### 1. Backup monitoring
```spl
index=windows sourcetype=mssql:errorlog "Backup database"
| rex "processed (?<pages>\d+) pages in (?<duration>[\d.]+) seconds"
| timechart span=1d avg(duration) AS backup_duration_sec
```

### 2. CPU runaway detection
```spl
index=windows sourcetype=mssql:errorlog demo_id=cpu_runaway
| sort _time
| table _time, message
```

### 3. Failed login brute force
```spl
index=windows sourcetype=mssql:errorlog "Login failed"
| rex "\[CLIENT: (?<client_ip>[^\]]+)\]"
| stats count by client_ip
| where count > 5
```

### 4. Deadlock detection
```spl
index=windows sourcetype=mssql:errorlog "deadlock"
| timechart span=1d count AS deadlocks
```

### 5. xp_cmdshell usage (exfil)
```spl
index=windows sourcetype=mssql:errorlog "xp_cmdshell" demo_id=exfil
| table _time, message
```

---

## Scenario Integration

| Scenario | Days | Activity |
|----------|------|----------|
| **cpu_runaway** | 10-11 | Non-yielding scheduler, I/O timeouts, backup stuck, KILL + restart |
| **exfil** | 5-13 | Failed login brute-force (lateral), xp_cmdshell (data staging) |

---

## Talking Points

**CPU runaway:**
> "Watch the SQL ERRORLOG around Day 10. The backup job starts at 2 AM but never finishes. By afternoon you see 'non-yielding scheduler' errors -- the CPU is pegged at 100% and SQL can't process anything. It takes a manual KILL command on Day 11 to recover."

**Exfil:**
> "The attacker probes SQL-PROD-01 with failed logins from jessica.brown's IP during lateral movement. Once they get in, look for xp_cmdshell -- that's how they stage data for exfiltration."

---

## Related Sources

- [Perfmon](perfmon.md) - CPU/memory metrics for SQL-PROD-01
- [WinEventLog](wineventlog.md) - Service start/stop events
- [Cisco ASA](cisco_asa.md) - Network connections to SQL port 1433
