# Azure ServiceBus

Order processing events from Azure ServiceBus message queues.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `azure:servicebus` |
| Format | JSON |
| Output File | `output/retail/servicebus_events.log` |
| Volume | 5 events per order |

---

## Event Types

Each order generates 5 ServiceBus events:

| Event | Description | Timing |
|-------|-------------|--------|
| `OrderCreated` | Order placed | t=0 |
| `PaymentProcessed` | Payment completed | t+1-5 seconds |
| `InventoryReserved` | Stock allocated | t+2-10 seconds |
| `ShipmentCreated` | Shipment prepared | t+1-4 hours |
| `ShipmentDispatched` | Package sent | t+4-24 hours |

---

## Key Fields

### Common Fields
| Field | Description | Example |
|-------|-------------|---------|
| `messageId` | Unique message ID | `msg-ORD-2026-000001-ordercreated-12345` |
| `eventType` | Event type | `OrderCreated` |
| `timestamp` | ISO 8601 with ms | `2026-01-05T14:30:00.123Z` |
| `order_id` | Order ID | `ORD-2026-000001` |
| `customer_id` | Customer ID | `CUST-12345` |
| `queue_name` | ServiceBus queue | `orders-queue` |
| `topic_name` | ServiceBus topic | `order-events` |
| `properties.MessageID` | Message ID | Same as messageId |
| `properties.CorrelationId` | Order correlation | Same as order_id |

### Event-Specific Fields

#### OrderCreated
| Field | Description |
|-------|-------------|
| `body.subtotal` | Order subtotal |
| `body.tax` | Tax amount |
| `body.shipping` | Shipping cost |
| `body.order_total` | Total amount |
| `body.item_count` | Number of items |

#### PaymentProcessed
| Field | Description |
|-------|-------------|
| `body.amount` | Payment amount |
| `body.payment_method` | Payment type |
| `body.transaction_id` | Transaction ID |
| `body.status` | Payment status |

#### InventoryReserved
| Field | Description |
|-------|-------------|
| `body.items` | Reserved items |
| `body.items[].product_id` | Product ID |
| `body.items[].quantity` | Quantity reserved |
| `body.items[].warehouse_id` | Warehouse |

#### ShipmentCreated
| Field | Description |
|-------|-------------|
| `body.shipment_id` | Shipment ID |
| `body.items` | Shipped items |
| `body.shipping_address` | Destination |
| `body.carrier` | Carrier code |

#### ShipmentDispatched
| Field | Description |
|-------|-------------|
| `body.shipment_id` | Shipment ID |
| `body.tracking_number` | Tracking # |
| `body.carrier` | Carrier code |
| `body.carrier_name` | Carrier name |
| `body.estimated_delivery` | ETA |

---

## Example Events

### OrderCreated
```json
{
  "messageId": "msg-ORD-2026-000001-ordercreated-12345",
  "eventType": "OrderCreated",
  "timestamp": "2026-01-05T14:30:00.123Z",
  "order_id": "ORD-2026-000001",
  "customer_id": "CUST-12345",
  "queue_name": "orders-queue",
  "topic_name": "order-events",
  "properties": {
    "MessageID": "msg-ORD-2026-000001-ordercreated-12345",
    "CorrelationId": "ORD-2026-000001"
  },
  "body": {
    "subtotal": 98.97,
    "tax": 7.92,
    "shipping": 8.00,
    "order_total": 114.89,
    "item_count": 3
  }
}
```

### PaymentProcessed
```json
{
  "messageId": "msg-ORD-2026-000001-paymentprocessed-12346",
  "eventType": "PaymentProcessed",
  "timestamp": "2026-01-05T14:30:03.456Z",
  "order_id": "ORD-2026-000001",
  "customer_id": "CUST-12345",
  "queue_name": "payments-queue",
  "topic_name": "payment-events",
  "body": {
    "amount": 114.89,
    "payment_method": "Visa",
    "transaction_id": "TXN-2026-000001",
    "status": "SUCCESS"
  }
}
```

### InventoryReserved
```json
{
  "messageId": "msg-ORD-2026-000001-inventoryreserved-12347",
  "eventType": "InventoryReserved",
  "timestamp": "2026-01-05T14:30:08.789Z",
  "order_id": "ORD-2026-000001",
  "customer_id": "CUST-12345",
  "queue_name": "inventory-queue",
  "topic_name": "inventory-events",
  "body": {
    "items": [
      {"product_id": "TSH-001", "quantity": 2, "warehouse_id": "WH-BOS"},
      {"product_id": "ACC-003", "quantity": 1, "warehouse_id": "WH-BOS"}
    ]
  }
}
```

### ShipmentCreated
```json
{
  "messageId": "msg-ORD-2026-000001-shipmentcreated-12348",
  "eventType": "ShipmentCreated",
  "timestamp": "2026-01-05T16:15:00.000Z",
  "order_id": "ORD-2026-000001",
  "customer_id": "CUST-12345",
  "queue_name": "shipping-queue",
  "topic_name": "shipping-events",
  "body": {
    "shipment_id": "SHIP-2026-000001",
    "items": [
      {"product_id": "TSH-001", "quantity": 2},
      {"product_id": "ACC-003", "quantity": 1}
    ],
    "shipping_address": {
      "city": "Boston",
      "state": "MA",
      "country": "US"
    },
    "carrier": "USPS"
  }
}
```

### ShipmentDispatched
```json
{
  "messageId": "msg-ORD-2026-000001-shipmentdispatched-12349",
  "eventType": "ShipmentDispatched",
  "timestamp": "2026-01-06T10:30:00.000Z",
  "order_id": "ORD-2026-000001",
  "queue_name": "shipping-queue",
  "topic_name": "shipping-events",
  "body": {
    "shipment_id": "SHIP-2026-000001",
    "tracking_number": "9400111899223456789012",
    "carrier": "USPS",
    "carrier_name": "United States Postal Service",
    "estimated_delivery": "2026-01-09T17:00:00Z"
  }
}
```

---

## Use Cases

### 1. Order Lifecycle
Track complete order journey:
```spl
index=retail sourcetype=azure:servicebus order_id="ORD-2026-000001"
| sort timestamp
| table timestamp, eventType, body.*
```

### 2. Event Volume by Type
Monitor message throughput:
```spl
index=retail sourcetype=azure:servicebus
| timechart span=1h count by eventType
```

### 3. Payment Success Rate
Track payment outcomes:
```spl
index=retail sourcetype=azure:servicebus eventType="PaymentProcessed"
| stats count by body.status
| eval pct = round(count / sum(count) * 100, 2)
```

### 4. Processing Latency
Measure order-to-payment time:
```spl
index=retail sourcetype=azure:servicebus eventType IN ("OrderCreated", "PaymentProcessed")
| transaction order_id maxspan=1m
| eval latency_ms = duration * 1000
| stats avg(latency_ms) AS avg_latency, p95(latency_ms) AS p95_latency
```

### 5. Fulfillment Time
Measure order-to-ship time:
```spl
index=retail sourcetype=azure:servicebus eventType IN ("OrderCreated", "ShipmentDispatched")
| transaction order_id maxspan=48h
| eval hours_to_ship = duration / 3600
| stats avg(hours_to_ship) AS avg_hours, p95(hours_to_ship) AS p95_hours
```

### 6. Queue Health
Monitor queue depths:
```spl
index=retail sourcetype=azure:servicebus
| stats count by queue_name
| sort - count
```

### 7. Warehouse Distribution
Track inventory allocation:
```spl
index=retail sourcetype=azure:servicebus eventType="InventoryReserved"
| spath body.items{}
| mvexpand body.items{}
| spath input=body.items{} output=warehouse path=warehouse_id
| stats count by warehouse
```

### 8. Carrier Usage
Analyze shipping carriers:
```spl
index=retail sourcetype=azure:servicebus eventType="ShipmentDispatched"
| stats count by body.carrier_name
| sort - count
```

---

## Order Lifecycle Timeline

```
t=0:00:00     OrderCreated       Order placed
t=0:00:03     PaymentProcessed   Payment captured
t=0:00:08     InventoryReserved  Stock allocated
t=1:45:00     ShipmentCreated    Package prepared
t=20:00:00    ShipmentDispatched Package shipped
```

---

## Integration Points

| Source | Correlation |
|--------|-------------|
| [Orders](orders.md) | `order_id` matches |
| [Access Logs](access.md) | `order_id` in URL |

### Cross-Source Order View
```spl
(index=retail sourcetype=retail:orders) OR (index=retail sourcetype=azure:servicebus)
| eval source=if(sourcetype="retail:orders", "Order", "ServiceBus")
| transaction order_id
| table order_id, source, eventType, status, order_total
```

---

## Talking Points

**Event-Driven Architecture:**
> "Every order triggers 5 ServiceBus messages. This decouples our systems - the order service, payment service, inventory service, and shipping service all operate independently."

**Processing Latency:**
> "Payment processing averages 3 seconds. Inventory reservation is another 5 seconds. From order to 'ready to ship' is under 10 seconds."

**Fulfillment Metrics:**
> "Average time from order to dispatch is 18 hours. 95th percentile is 36 hours. We're shipping most orders same-day or next-day."

**Correlation:**
> "The order_id links everything. We can trace from the web click, to the order JSON, through all 5 ServiceBus events, to the final tracking number."

---

## Related Sources

- [Orders](orders.md) - Original order data
- [Access Logs](access.md) - Web checkout flow

