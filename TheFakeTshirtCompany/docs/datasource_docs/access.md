# Apache Access Logs

Web server access logs from theFakeTshirtCompany.com e-commerce site.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `access_combined` |
| Format | Apache Combined Log |
| Output File | `output/web/access_combined.log` |
| Volume | 2000-3000 events/day |
| Website | theFakeTshirtCompany.com |

---

## Log Format

Apache Combined Log Format:
```
%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" response_time=%D session_id=%{SESSIONID}C tshirtcid=%{TSHIRTCID}C
```

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `clientip` | Visitor IP | `73.158.42.100` |
| `ident` | Identity (usually `-`) | `-` |
| `user` | Auth user (usually `-`) | `-` |
| `timestamp` | Request time | `05/Jan/2026:14:23:45 +0000` |
| `method` | HTTP method | `GET`, `POST` |
| `uri` | Request URI | `/products/dns-tshirt` |
| `status` | HTTP status | `200`, `404`, `500` |
| `bytes` | Response size | `4523` |
| `referer` | Referring page | `https://theFakeTshirtCompany.com/` |
| `useragent` | Browser/client | `Mozilla/5.0...` |
| `response_time` | Time (ms) | `125` |
| `session_id` | Session ID | `sess_abc123` |
| `tshirtcid` | Customer ID | `cid_001` |
| `order_id` | Order ID | `ORD-2026-000001` |
| `demo_id` | Scenario tag | `memory_leak` |

---

## HTTP Status Codes

| Code | Description | Cause |
|------|-------------|-------|
| 200 | OK | Normal |
| 301/302 | Redirect | Normal |
| 304 | Not Modified | Cache hit |
| 400 | Bad Request | Client error |
| 404 | Not Found | Missing page |
| 500 | Internal Error | App crash |
| 502 | Bad Gateway | Backend down |
| 503 | Service Unavailable | Overload |
| 504 | Gateway Timeout | Backend timeout |

---

## URL Patterns

| Pattern | Description |
|---------|-------------|
| `/` | Homepage |
| `/products/*` | Product pages |
| `/cart/*` | Shopping cart |
| `/checkout/*` | Checkout flow |
| `/orders/*` | Order confirmation |
| `/api/orders` | Order API |
| `/api/v1/*` | API endpoints |
| `/static/*` | Static assets |

---

## Session Types

| Type | Percentage | Behavior |
|------|------------|----------|
| Bounce | 40% | 1-2 pages, leaves |
| Browser | 35% | 3-10 pages, browses only |
| Abandoned | 15% | Adds to cart, starts checkout, leaves |
| Purchase | 10% | Completes full purchase |

---

## Example Events

### Normal Page View
```
73.158.42.100 - - [05/Jan/2026:14:23:45 +0000] "GET /products/its-always-dns-tshirt HTTP/1.1" 200 4523 "https://theFakeTshirtCompany.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" response_time=125 session_id=sess_abc123 tshirtcid=cid_001
```

### Add to Cart
```
73.158.42.100 - - [05/Jan/2026:14:25:30 +0000] "POST /cart/add HTTP/1.1" 302 0 "https://theFakeTshirtCompany.com/products/its-always-dns-tshirt" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" response_time=85 session_id=sess_abc123 product_id=TSH-001
```

### Checkout
```
73.158.42.100 - - [05/Jan/2026:14:27:00 +0000] "POST /checkout/complete HTTP/1.1" 302 0 "https://theFakeTshirtCompany.com/checkout/payment" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" response_time=1250 session_id=sess_abc123 order_id=ORD-2026-000001
```

### Order Confirmation
```
73.158.42.100 - - [05/Jan/2026:14:27:02 +0000] "GET /orders/ORD-2026-000001 HTTP/1.1" 200 8192 "https://theFakeTshirtCompany.com/checkout/complete" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" response_time=95 session_id=sess_abc123 order_id=ORD-2026-000001
```

### Gateway Timeout (Memory Leak)
```
71.222.45.88 - - [10/Jan/2026:14:15:00 +0000] "GET /products/hack-the-planet-hoodie HTTP/1.1" 504 0 "https://theFakeTshirtCompany.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)" response_time=30000 session_id=sess_xyz789 demo_id=memory_leak
```

### SSL Error (Certificate Expiry)
```
98.45.12.55 - - [12/Jan/2026:02:30:00 +0000] "GET /products HTTP/1.1" 502 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" response_time=45000 ssl_error=certificate_expired demo_id=certificate_expiry
```

---

## Use Cases

### 1. Traffic Analysis
Track page views over time:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined"
| timechart span=1h count
```

### 2. Popular Products
Find most viewed products:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" uri="/products/*" status=200
| rex field=uri "/products/(?<product>.+)"
| stats count by product
| sort - count | head 10
```

### 3. Conversion Funnel
Track checkout funnel:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined"
| eval stage=case(
    match(uri, "^/$"), "1_homepage",
    match(uri, "^/products"), "2_product",
    match(uri, "^/cart"), "3_cart",
    match(uri, "^/checkout"), "4_checkout",
    match(uri, "^/orders"), "5_complete"
)
| stats dc(session_id) AS sessions by stage
| sort stage
```

### 4. Error Detection
Find error spikes:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" status>=500
| timechart span=15m count by status
```

### 5. Response Time Analysis
Monitor performance:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" status=200
| timechart span=1h avg(response_time) AS avg_ms, p95(response_time) AS p95_ms
```

### 6. Memory Leak Impact
Track errors during memory leak:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=memory_leak
| timechart span=1h count(eval(status>=500)) AS errors, count AS total
| eval error_rate = round(errors/total*100, 2)
```

### 7. Certificate Expiry Impact
Track SSL errors:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" demo_id=certificate_expiry
| timechart span=1h count by status
```

### 8. Session Analysis
Track user journeys:
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" session_id=sess_abc123
| sort _time
| table _time, uri, status, response_time
```

---

## Scenario Integration

| Scenario | Pattern | HTTP Status |
|----------|---------|-------------|
| **memory_leak** | Increasing timeouts | 504 |
| **cpu_runaway** | Slow responses | 504 |
| **certificate_expiry** | SSL failures | 502, 503 |

---

## Memory Leak Impact

```
Day 1-5:   Normal (<1% errors)
Day 6-7:   Occasional 504s (1-2%)
Day 8-9:   Growing timeouts (5-10%)
Day 10:    Major impact (20%+ errors)
Day 10, 14:00: OOM crash (site down)
```

---

## Certificate Expiry Impact

```
Day 12, 00:00: Cert expires
Day 12, 00:00-05:00: Low traffic, all HTTPS fails
Day 12, 05:00-07:00: Morning rush, flood of 502/503
Day 12, 07:00: New cert installed
Day 12, 07:00+: Recovery
```

---

## Talking Points

**Conversion Funnel:**
> "We can track the full customer journey. 100% hit the homepage, 60% view a product, 20% add to cart, 15% start checkout, but only 10% complete purchase. That's our conversion rate."

**Error Impact:**
> "During the memory leak, watch the 504 errors climb. Day 6 they're 1%. Day 9 they're 8%. Day 10 before the crash - 20% of requests are timing out. Customers are leaving."

**Response Time:**
> "Normal response time is 50-200ms. During CPU runaway, we see p95 jump to 5+ seconds. That's terrible user experience."

**SSL Outage:**
> "Certificate expires at midnight. Between midnight and 7 AM, every HTTPS request fails. That's 7 hours of complete e-commerce outage."

---

## Related Sources

- [Orders](orders.md) - Completed purchases
- [Linux](linux.md) - Server health
- [ServiceNow](servicenow.md) - Incident correlation

---

## Ingestion Reference

| | |
|---|---|
| **Splunk Add-on** | Built-in Splunk pretrained sourcetype (no TA required). Optional: [Splunk Add-on for Apache Web Server](https://splunkbase.splunk.com/app/3186) |
| **Ingestion** | Universal Forwarder monitoring Apache log files |
| **Real sourcetype** | `access_combined` (built-in) -- matches our generator exactly |

