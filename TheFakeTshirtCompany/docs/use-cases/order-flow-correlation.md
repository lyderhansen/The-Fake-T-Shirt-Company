# Use Case: Order Flow Correlation

How a single customer order flows through all data sources, from web click to SAP billing document.

---

## Flow Diagram

```
  CUSTOMER (browser)
       |
       v
  +------------------------------------------------------------------+
  |  generate_access.py                                              |
  |  sourcetype: access_combined                                     |
  |                                                                  |
  |  Session: /products -> /cart/add -> /checkout -> /checkout/       |
  |           complete (POST, 200)                                   |
  |                                                                  |
  |  Output:  access_combined.log  (Apache Combined)                 |
  |           order_registry.json  (JSONL) <-- shared source         |
  +---------------------+--------------------------------------------+
                        |
                        |  order_registry.json
                        |
          +-------------+-------------+-----------------+
          v             v             v                 v
     +---------+  +-----------+  +----------+   +-----------+
     | orders  |  | servicebus|  |   sap    |   |    asa    |
     |         |  |           |  |          |   | (indirect)|
     | 5 evts  |  | 5 evts    |  | 3 evts   |   | Built/    |
     | per     |  | per       |  | per      |   | Teardown  |
     | order   |  | order     |  | order    |   | 3-tier    |
     +---------+  +-----------+  +----------+   +-----------+
```

## Data Sources in the Order Flow

| # | Generator | Sourcetype | Input | Output | Reads registry? |
|---|-----------|-----------|-------|--------|-----------------|
| 1 | `generate_access.py` | `access_combined` | None (primary source) | `web/access_combined.log` + `web/order_registry.json` | No (CREATES it) |
| 2 | `generate_orders.py` | `retail:orders` | `order_registry.json` | `retail/orders.json` | Yes |
| 3 | `generate_servicebus.py` | `azure:servicebus` | `order_registry.json` | `servicebus/servicebus_events.jsonl` | Yes |
| 4 | `generate_sap.py` | `sap:auditlog` | `order_registry.json` | `erp/sap_audit.log` | Yes |
| 5 | `generate_asa.py` | `cisco:asa` | None (indirect) | `network/cisco_asa.log` | No (generates 3-tier traffic independently) |

## Execution Order (main_generate.py)

```
Phase 1 (parallel):   access + all independent generators
                          |
                          v  order_registry.json ready
Phase 2 (sequential): orders -> servicebus -> sap
```

---

## Correlation Keys

| Key | Format | Example | Origin | Used in |
|-----|--------|---------|--------|---------|
| `order_id` | `ORD-YYYY-NNNNN` | `ORD-2026-00001` | access | orders, servicebus, sap |
| `customer_id` | `CUST-NNNNN` | `CUST-00050` | access | access, orders, sap |
| `session_id` | `sess_XXXXXXXX` | `sess_a1b2c3d4` | access | access, orders, servicebus |
| `tshirtcid` | UUID v4 | `a1b2c1d2-...` | access | access, orders, servicebus |
| `product slug` | kebab-case | `works-on-my-machine-tee` | products.py | access (URL), orders (SKU), sap (material) |
| `demo_id` | scenario tag | `dead_letter_pricing` | scenarios | all 5 sources |

---

## Event Timeline for a Single Order

### Step 1: Web Session (access_combined)

The order starts as a browser session flowing through product pages, cart, and checkout.

| Event | URL | Status | Key Fields |
|-------|-----|--------|------------|
| Browse | `GET /products/hack-the-planet-tee` | 200 | `session_id`, `tshirtcid` |
| Add to cart | `GET /cart/add?product=hack-the-planet-tee&qty=1` | 200 | `cart_items=1`, `cart_total=3999` |
| View cart | `GET /cart` | 200 | |
| Checkout | `GET /checkout` | 200 | `customer_id=CUST-00050` |
| Complete | `POST /checkout/complete` | 200 | `order_id=ORD-2026-00001` |

**Example log line (checkout complete):**
```
73.158.42.100 - CUST-00050 [05/Jan/2026:14:23:45 +0000] "POST /checkout/complete HTTP/1.1" 200 2045
  "https://theFakeTshirtCompany.com/checkout" "Mozilla/5.0..."
  response_time=245 session_id=sess_a1b2c3d4 tshirtcid=a1b2c1d2-4e56-4f7g-h8i9-j1k2l3m4n5o6
  customer_id=CUST-00050 order_id=ORD-2026-00001 cart_items=2 cart_total=11500
```

**Order Registry entry (JSONL):**
```json
{
  "order_id": "ORD-2026-00001",
  "tshirtcid": "a1b2c1d2-4e56-4f7g-h8i9-j1k2l3m4n5o6",
  "customer_id": "CUST-00050",
  "session_id": "sess_a1b2c3d4",
  "timestamp": "2026-01-05T14:23:45Z",
  "products": [
    {"slug": "hack-the-planet-tee", "price": 3999, "qty": 1},
    {"slug": "sudo-sandwich-hoodie", "price": 7501, "qty": 1}
  ],
  "cart_total": 11500,
  "scenario": "none"
}
```

### Step 2: Retail Order Events (retail:orders)

Each order produces 5 status events tracking the order lifecycle:

| # | Status | Offset | Key Fields Added |
|---|--------|--------|------------------|
| 1 | `created` | T+0s | Base pricing, items |
| 2 | `payment_confirmed` | T+1-10s | `payment.method`, `payment.transactionId` |
| 3 | `processing` | T+5-30 min | |
| 4 | `shipped` | T+1-12h | `trackingNumber` |
| 5 | `delivered` | T+1-4 days | Final status |

**Example event (created):**
```json
{
  "orderId": "ORD-2026-00001",
  "tshirtcid": "a1b2c1d2-4e56-4f7g-h8i9-j1k2l3m4n5o6",
  "sessionId": "sess_a1b2c3d4",
  "customerId": "CUST-00050",
  "status": "created",
  "timestamp": "2026-01-05T14:23:45Z",
  "items": [
    {
      "sku": "hack-the-planet-tee",
      "name": "Hack the Planet Tee",
      "category": "security",
      "unitPrice": 3999,
      "quantity": 1,
      "lineTotal": 3999
    }
  ],
  "pricing": {
    "subtotal": 11500,
    "tax": 920,
    "taxRate": 8.0,
    "shipping": 0,
    "total": 12420,
    "currency": "USD"
  },
  "source": "web",
  "channel": "theFakeTshirtCompany.com"
}
```

**Failure rates (~7% of orders):**

| Failure | Rate | Effect |
|---------|------|--------|
| `payment_declined` | 5% | Lifecycle stops after payment attempt |
| `fraud_detected` | 1% | Lifecycle stops after fraud check |
| `address_invalid` | 1% | Lifecycle stops during processing |

### Step 3: Azure ServiceBus Events (azure:servicebus)

Each order produces 5 message events across different queues:

| # | Event Type | Queue | Offset |
|---|-----------|-------|--------|
| 1 | `OrderCreated` | `orders-queue` | T+0s |
| 2 | `PaymentProcessed` | `payments-queue` | T+1-5s |
| 3 | `InventoryReserved` | `inventory-queue` | T+2-10s |
| 4 | `ShipmentCreated` | `shipments-queue` | T+1-4h |
| 5 | `ShipmentDispatched` | `shipments-queue` | T+4-24h |

**Example event (OrderCreated):**
```json
{
  "messageId": "msg-ORD-2026-00001-OrderCreated-75234",
  "sessionId": "sess_a1b2c3d4",
  "tshirtcid": "a1b2c1d2-4e56-4f7g-h8i9-j1k2l3m4n5o6",
  "enqueuedTimeUtc": "2026-01-05T14:23:45.123Z",
  "sequenceNumber": 42,
  "deliveryCount": 1,
  "namespace": "faketshirtcompany-prod",
  "queueName": "orders-queue",
  "topicName": "order-events",
  "status": "Completed",
  "processingTimeMs": 342,
  "body": {
    "eventType": "OrderCreated",
    "orderId": "ORD-2026-00001",
    "customerId": "CUST-00050",
    "totalAmount": 12420,
    "currency": "USD"
  }
}
```

**Failure rates:**

| Failure | Rate | Indicator |
|---------|------|-----------|
| Transient retry | ~3% | `deliveryCount` > 1, `properties.retryReason` |
| Dead-lettered | ~0.5% | Moved to DLQ with `deadLetterReason` |

### Step 4: SAP S/4HANA Audit Log (sap:auditlog)

Each order produces 3 events (complete SAP order lifecycle):

| # | T-code | Description | Doc Prefix | Offset |
|---|--------|-------------|-----------|--------|
| 1 | `VA01` | Create Sales Order | `SO` | T+0 min |
| 2 | `VL01N` | Create Delivery | `DL` | T+15-45 min |
| 3 | `VF01` | Create Billing Document | `INV` | T+1-3 hours |

**Example lifecycle (pipe-delimited):**
```
2026-01-05 14:25:13|SAP-PROD-01|DIA|noah.reed|VA01|S|Create Sales Order|SO-2026-00001|Sales order for customer CUST-00050, 2 items, total $115.00, ref ORD-2026-00001
2026-01-05 14:47:41|SAP-PROD-01|DIA|noah.reed|VL01N|S|Create Delivery|DL-2026-00001|Delivery for SO-2026-00001, shipping point BOS1, 2 items
2026-01-05 16:12:33|SAP-PROD-01|DIA|noah.reed|VF01|S|Create Billing Document|INV-2026-00001|Invoice for SO-2026-00001, $115.00
```

**SAP field positions:**

| Pos | Field | Example |
|-----|-------|---------|
| 1 | Timestamp | `2026-01-05 14:25:13` |
| 2 | Host | `SAP-PROD-01` |
| 3 | Dialog type | `DIA` (interactive), `BTC` (batch), `RFC` (remote) |
| 4 | User | `noah.reed` (SD_USER role) |
| 5 | T-code | `VA01` |
| 6 | Status | `S` (success), `E` (error), `W` (warning) |
| 7 | Description | `Create Sales Order` |
| 8 | Document number | `SO-2026-00001` |
| 9 | Details | Free text with customer, items, total, web ref |
| 10 | demo_id (optional) | `demo_id=dead_letter_pricing` |

**SAP document chain:**
- `SO-2026-NNNNN` references `ORD-2026-NNNNN` (web order) in the details field
- `DL-2026-NNNNN` references `SO-2026-NNNNN` in the details field
- `INV-2026-NNNNN` references `SO-2026-NNNNN` in the details field

### Step 5: Cisco ASA Firewall (cisco:asa) -- Indirect

The ASA does not read order_registry.json. Instead, it generates 3-tier application traffic independently. ~2% of baseline traffic represents the WEB -> APP -> SQL flow that processes orders.

**3-tier network path:**
```
Internet -> FW-EDGE-01 -> WEB-01/02 (172.16.1.10/11, DMZ)
                              |
                              v  port 443/8443
                          APP-BOS-01 (10.10.20.40)
                              |
                              v  port 1433
                          SQL-PROD-01 (10.10.20.30)
```

**Example ASA events:**
```
Jan 05 2026 14:23:45 FW-EDGE-01 %ASA-6-302013: Built inbound TCP connection 54321
  for dmz:172.16.1.10/12345 (73.158.42.100/54321) to inside:10.10.20.40/443
Jan 05 2026 14:23:45 FW-EDGE-01 %ASA-6-302013: Built inbound TCP connection 54322
  for inside:10.10.20.40/23456 to inside:10.10.20.30/1433
```

---

## ID Formats Summary

| ID Type | Format | Example | Range |
|---------|--------|---------|-------|
| Order ID | `ORD-YYYY-NNNNN` | `ORD-2026-00001` | Sequential per run |
| Customer ID | `CUST-NNNNN` | `CUST-00050` | Pareto: 30% top 50, 70% rest up to ~500 |
| Session ID | `sess_XXXXXXXX` | `sess_a1b2c3d4` | Random hex |
| Tracking cookie | UUID v4 | `a1b2c1d2-4e56-...` | Standard UUID |
| ServiceBus message | `msg-ORDER_ID-TYPE-NNNNN` | `msg-ORD-2026-00001-OrderCreated-75234` | Unique per message |
| SAP Sales Order | `SO-YYYY-NNNNN` | `SO-2026-00001` | Sequential per year |
| SAP Delivery | `DL-YYYY-NNNNN` | `DL-2026-00001` | Sequential per year |
| SAP Invoice | `INV-YYYY-NNNNN` | `INV-2026-00001` | Sequential per year |
| SAP Material | `M-NNNN` | `M-0001` | 72 products (M-0001 to M-0072) |

---

## Scenario Impact on Order Flow

| Scenario | Day | Effect on orders |
|----------|-----|-----------------|
| `dead_letter_pricing` | 16 | Wrong prices for 4-6 hours. ServiceBus messages dead-lettered. Orders have `wrong_price=true`. |
| `memory_leak` | 7-10 | Slow response times, 500 errors on day 9. Fewer orders completed. |
| `cpu_runaway` | 11-12 | SQL failures cause order processing errors. |
| `ddos_attack` | 18-19 | HTTP flood causes 503 errors. Most orders fail. |
| `firewall_misconfig` | 6 | 2-hour outage (10:15-12:05). No orders during window. |
| `certificate_expiry` | 13 | SSL errors for 7 hours (00:00-07:00). Orders fail with connection errors. |

---

## SPL Queries for Order Correlation

### Track a single order across all sources
```spl
index=fake_tshrt "ORD-2026-00001"
| stats count by sourcetype
| sort sourcetype
```

### Order lifecycle timeline
```spl
index=fake_tshrt "ORD-2026-00001"
| eval time=_time
| table _time sourcetype _raw
| sort _time
```

### Count orders per source (verify correlation)
```spl
index=fake_tshrt sourcetype IN ("FAKE:access_combined", "FAKE:retail:orders", "FAKE:azure:servicebus", "FAKE:sap:auditlog")
| search "ORD-2026-*"
| stats dc(order_id) AS orders by sourcetype
```

### Find orders missing SAP correlation
```spl
index=fake_tshrt sourcetype="FAKE:access_combined" order_id="ORD-*"
| stats values(order_id) AS web_orders
| mvexpand web_orders
| join type=left web_orders
  [search index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode="VA01"
   | rex field=_raw "ref (?<web_order>ORD-\d{4}-\d{5})"
   | stats count by web_order
   | rename web_order AS web_orders]
| where isnull(count)
```

### SAP order lifecycle duration
```spl
index=fake_tshrt sourcetype="FAKE:sap:auditlog" tcode IN ("VA01", "VL01N", "VF01")
| rex field=_raw "(?<so_ref>SO-2026-\d{5})"
| stats min(_time) AS first_event max(_time) AS last_event values(tcode) AS tcodes by so_ref
| eval duration_hours=round((last_event-first_event)/3600, 1)
| stats avg(duration_hours) AS avg_hours median(duration_hours) AS median_hours
```

### Dead letter pricing impact
```spl
index=fake_tshrt demo_id="dead_letter_pricing"
| stats count by sourcetype
| sort -count
```
