# Dead Letter Pricing Scenario

ServiceBus price update consumer crashes, causing messages to dead-letter and product prices to go stale on the web store for 5 hours.

---

## Summary

| Attribute | Value |
|-----------|-------|
| Duration | 5 hours (08:00-13:00) |
| Category | Ops |
| demo_id | `dead_letter_pricing` |
| Day | 16 |
| Impact | ~60% of products show wrong prices, revenue loss |

---

## Key Components

### Affected System
| Attribute | Value |
|-----------|-------|
| Server | WEB-01 (172.16.1.10) |
| Service | Azure ServiceBus price update consumer |
| Queue | Price update messages |
| Impact | Stale/cached prices displayed to customers |

### Price Error Types
| Error Type | Description |
|------------|-------------|
| Stale discount | Old promotional price still active |
| Missed increase | Price increase not applied |
| Rounding error | Price calculation off by pennies |
| Double discount | Discount applied twice |

~60% of products affected with deterministic errors (seeded by date).

---

## Timeline - Day 16

| Time | Event | Description |
|------|-------|-------------|
| **08:00** | Consumer crash | Price update consumer process crashes |
| **08:15** | Wrong prices | First orders with stale/cached prices appear |
| **08:30** | Error spike | Checkout error rate increases (payment validation mismatches) |
| **09:00** | DLQ alert | Dead-letter queue threshold hit, ServiceNow P3 auto-created |
| **10:00** | Complaints | Customer complaints about pricing start arriving |
| **11:00** | Investigation | IT discovers dead-letter queue is full |
| **11:30** | Escalation | ServiceNow escalated from P3 to P2 |
| **12:00** | Fix applied | Consumer restarted, DLQ replay begins |
| **12:30** | Prices corrected | Error rate drops as prices update |
| **13:00** | Full recovery | DLQ fully drained, normal operations resume |
| **13:30** | Post-mortem | Post-incident review ticket created |

---

## Timeline Visualization

```
08:00     09:00     10:00     11:00     12:00     13:00
  |         |         |         |         |         |
  v         v         v         v         v         v
CRASH --> DLQ ALERT --> COMPLAINTS --> FOUND --> FIX --> RECOVERED
  |         |                          |         |
  |    P3 created                 Escalate P2  Replay DLQ
  |         |                          |         |
  +-------- Wrong prices visible ------+-------- Prices correcting
```

---

## Dead-Letter Queue Progression

| Time Window | DLQ Rate | Accumulated Messages | Effect |
|-------------|----------|---------------------|--------|
| 08:00-09:00 | 100% | Growing | All price updates dead-lettering |
| 09:00-12:00 | 100% | Full | Queue saturated, prices frozen |
| 12:00-12:30 | Draining | Decreasing | Replay in progress, prices correcting |
| 12:30-13:00 | 0% | Empty | Queue drained, all prices current |

---

## Affected Log Sources

| Source | Events | Description |
|--------|--------|-------------|
| **ServiceBus** | Dead-letter events, queue metrics | DLQ messages accumulating, replay events |
| **Orders** | Orders with wrong prices | Revenue impact calculation, price mismatches |
| **Access** | Elevated error rate, slow responses | Checkout validation failures (400/500 errors) |
| **ServiceNow** | P3 incident, P2 escalation | Incident lifecycle from alert to resolution |

---

## Logs to Look For

### ServiceBus - Dead letter events
```spl
index=servicebus sourcetype="azure:servicebus" demo_id=dead_letter_pricing
| timechart span=30m count by messageType
```

### ServiceBus - DLQ accumulation
```spl
index=servicebus sourcetype="azure:servicebus" demo_id=dead_letter_pricing
  "deadLetter"
| timechart span=15m count AS dead_letter_messages
```

### Orders - Revenue impact
```spl
index=retail sourcetype="retail:orders" demo_id=dead_letter_pricing
| eval price_diff = expected_total - total
| stats sum(price_diff) AS revenue_impact, count AS affected_orders
```

### Access - Error rate during incident
```spl
index=web sourcetype=access_combined demo_id=dead_letter_pricing
| eval is_error=if(status>=400, 1, 0)
| timechart span=15m avg(is_error) AS error_rate, count AS requests
```

### ServiceNow - Incident progression
```spl
index=itsm sourcetype=servicenow:incident demo_id=dead_letter_pricing
| table _time, number, priority, state, short_description
| sort _time
```

### Cross-source correlation
```spl
index=* demo_id=dead_letter_pricing
| timechart span=30m count by sourcetype
```

---

## Talking Points

**Setup:**
> "Day 16, 8 AM. The ServiceBus price update consumer crashes silently. Messages start piling up in the dead-letter queue. The web store keeps serving, but with stale cached prices."

**Impact:**
> "About 60% of products are showing wrong prices. Some have old discounts still applied, others missed price increases. Customers are placing orders at the wrong price -- this is a real revenue impact."

**Detection gap:**
> "It takes a full hour before the DLQ alert threshold triggers a P3 incident. Another 2 hours before IT actually finds the root cause. Meanwhile, customer complaints are piling up."

**Resolution:**
> "Once they find the dead-letter queue, the fix is simple -- restart the consumer and replay the DLQ. Prices correct within 30 minutes. But the damage is done: hours of orders at wrong prices."

**Lesson:**
> "This is a classic microservices failure pattern. The consumer crashed, but the producer kept running. Without proper health checks on the consumer, the system looked healthy while serving stale data. The monitoring gap between DLQ threshold and actual customer impact is where the pain lives."
