# Memory Leak Scenario

A gradual memory leak on WEB-01 over 10 days that culminates in an OOM crash. This scenario demonstrates how operational problems escalate and correlate across multiple log sources.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 10 days (Days 1-10) |
| Category | Ops |
| demo_id | `memory_leak` |
| Critical Event | Day 10 @ 14:00 - OOM crash |
| Outcome | Server crashes, auto-restart |

---

## Target Server

| Attribute | Value |
|-----------|-------|
| Hostname | WEB-01 |
| IP | 172.16.1.10 |
| Location | Boston DMZ |
| OS | Linux (Ubuntu 22.04) |
| RAM | 64 GB |
| Role | Web Server |

---

## Memory Progression

| Days | Memory % | Swap | CPU Impact | Status |
|------|----------|------|------------|--------|
| 1-3 | 50-60% | 0 | None | Normal |
| 4-5 | 60-75% | 0 | None | Degrading |
| 6-7 | 75-85% | 2-4 GB | None | Concerning |
| 8-9 | 85-95% | 8-16 GB | +5-15% | **WARNING** |
| **10 @14:00** | 98% → OOM | 25-30 GB | +10-25% | **CRASH** |
| 11-14 | 50-60% | 0 | None | Recovered |

---

## Timeline Visualization

```
Memory %
100│                                          ▲ OOM!
 95│                                     ╱────┤
 90│                                ╱────     │
 85│                           ╱────          │
 80│                      ╱────               │
 75│                 ╱────                    │
 70│            ╱────                         │
 65│       ╱────                              │
 60│──────╱                                   │  ◄── Restart
 55│                                          ▼     Back to normal
 50├──────────────────────────────────────────┴──────────────────
   │
   └──Day 1─────Day 5─────Day 7─────Day 9────Day 10────Day 14──►
```

---

## Critical Event: Day 10, 14:00

**What happens:**
1. Memory reaches 98%
2. Swap at 25-30 GB (extreme thrashing)
3. OOM killer activates
4. Server crashes
5. Automatic restart
6. Memory drops back to ~50%

**Symptoms before crash:**
- Response times increase dramatically
- ASA sees connection timeouts
- Users report "504 Gateway Timeout" errors

---

## ASA Connection Timeouts

The firewall sees TCP connection failures correlating with memory pressure:

| Day | Timeout Events/Day | Severity |
|-----|-------------------|----------|
| 1-5 | 0 | None |
| 6-7 | ~50 | Starting |
| 8-9 | ~150 | Escalating |
| **10** | **~300** | **Peak before crash** |
| 11-14 | 0 | Recovered |

**Timeout reasons:**
- TCP FINs
- TCP Reset-O
- TCP Reset-I
- Idle timeout
- SYN Timeout

---

## Logs to Look For

### Linux vmstat - Memory trend
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| eval memory_gb = memory_used_kb / 1048576
| eval swap_gb = swap_used_kb / 1048576
| timechart span=1h avg(memory_gb) AS "Memory (GB)", avg(swap_gb) AS "Swap (GB)"
```

### ASA - Connection timeouts
```spl
index=network sourcetype=cisco:asa
  dest_ip=172.16.1.10
  ("TCP FINs" OR "TCP Reset" OR "SYN Timeout")
  demo_id=memory_leak
| timechart span=1h count AS timeouts
```

### Linux - Memory percentage over time
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| timechart span=1h avg(memory_pct) AS "Memory %"
```

---

## Correlation View

```spl
index=* demo_id=memory_leak (host=WEB-01 OR dest_ip=172.16.1.10)
| eval metric=case(
    sourcetype="vmstat", "Memory %: ".memory_pct,
    sourcetype="cisco:asa", "ASA Timeout",
    true(), sourcetype
)
| timechart span=1h count by metric
```

---

## Talking Points

**Trend analysis:**
> "Look at this graph. Memory increases gradually over 10 days - from 55% to 98%. This is a classic memory leak. Swap usage starts on day 6 and accelerates. Day 10 at 14:00, the server crashes."

**Correlation:**
> "Simultaneously, we see ASA timeout events correlated with memory increase. Customers experience slowness because the server spends more time swapping than handling requests."

**Root cause:**
> "Root cause: memory leak in the web application. After restart, the problem is temporarily resolved, but a permanent fix requires a code change."

**Detection opportunity:**
> "Notice how we had 4-5 days of warning before the crash. With proper alerting at 75% memory, this outage could have been prevented."

---

## Splunk Queries

### Memory progression
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| timechart span=4h avg(memory_pct) AS memory, avg(swap_pct) AS swap
```

### Day of crash detail
```spl
index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
| where strftime(_time, "%Y-%m-%d") = "2026-01-10"
| timechart span=15m avg(memory_pct) AS memory
```

### Timeout correlation
```spl
index=network sourcetype=cisco:asa dest_ip=172.16.1.10 demo_id=memory_leak
| timechart span=1h count AS timeouts
| join _time [
    search index=linux sourcetype=vmstat host=WEB-01 demo_id=memory_leak
    | timechart span=1h avg(memory_pct) AS memory
]
```

### OOM event
```spl
index=linux host=WEB-01 demo_id=memory_leak
  ("Out of memory" OR "OOM killer" OR "oom-killer")
| table _time, message
```
