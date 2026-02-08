# Retail Orders

E-commerce orders from theFakeTshirtCompany.com online store.

---

## Overview

| Attribute | Value |
|-----------|-------|
| Sourcetype | `retail:orders` |
| Format | JSON |
| Output File | `output/retail/orders.json` |
| Volume | ~224/day (configurable) |

---

## Product Catalog

### Product Types
| Type | Count | Price Range |
|------|-------|-------------|
| T-Shirts | 35 | $34-45 |
| Hoodies | 17 | $72-85 |
| Joggers | 10 | $65-72 |
| Accessories | 10 | $28-85 |

### Popular Products
| Product | Category | Price |
|---------|----------|-------|
| It's Always DNS | T-Shirt | $34.99 |
| Hack the Planet | Hoodie | $79.99 |
| sudo rm -rf /* | T-Shirt | $34.99 |
| 404 Sleep Not Found | T-Shirt | $34.99 |
| DevOps Joggers | Joggers | $68.99 |

---

## Key Fields

| Field | Description | Example |
|-------|-------------|---------|
| `order_id` | Order identifier | `ORD-2026-000001` |
| `customer_id` | Customer ID | `CUST-12345` |
| `order_date` | ISO 8601 timestamp | `2026-01-05T14:30:00Z` |
| `customer_name` | Customer name | `John Smith` |
| `customer_email` | Customer email | `john@example.com` |
| `items` | Array of products | `[{...}, {...}]` |
| `subtotal` | Before tax/shipping | `69.98` |
| `tax` | Sales tax | `5.50` |
| `shipping_cost` | Shipping | `8.00` |
| `order_total` | Final total | `83.48` |
| `status` | Order status | `Processing` |
| `payment_method` | Payment type | `Visa` |
| `shipping_address` | Delivery address | `{street, city, ...}` |
| `carrier` | Shipping carrier | `USPS` |

### Item Fields
| Field | Description | Example |
|-------|-------------|---------|
| `product_id` | Product ID | `TSH-001` |
| `product_name` | Product name | `It's Always DNS T-Shirt` |
| `category` | Product type | `tshirt` |
| `quantity` | Qty ordered | `2` |
| `unit_price` | Price each | `34.99` |
| `subtotal` | Line total | `69.98` |

---

## Order Statuses

| Status | Description |
|--------|-------------|
| `Pending` | Just placed |
| `Processing` | Being prepared |
| `Shipped` | In transit |
| `Delivered` | Completed |
| `Cancelled` | Cancelled |

---

## Payment Methods

| Method | Percentage |
|--------|------------|
| Visa | 35% |
| Mastercard | 25% |
| American Express | 15% |
| PayPal | 20% |
| Apple Pay | 5% |

---

## Shipping Carriers

| Carrier | Regions |
|---------|---------|
| USPS | US domestic |
| UPS | US domestic |
| FedEx | US domestic |
| DHL | International |

---

## Customer Distribution

| Region | Percentage |
|--------|------------|
| United States | 70% |
| Europe (UK, DE, FR, NL) | 20% |
| Norway | 10% |

---

## Example Event

```json
{
  "order_id": "ORD-2026-000001",
  "customer_id": "CUST-12345",
  "order_date": "2026-01-05T14:30:00Z",
  "customer_name": "John Smith",
  "customer_email": "john.smith@example.com",
  "items": [
    {
      "product_id": "TSH-001",
      "product_name": "It's Always DNS T-Shirt",
      "category": "tshirt",
      "quantity": 2,
      "unit_price": 34.99,
      "subtotal": 69.98
    },
    {
      "product_id": "ACC-003",
      "product_name": "Developer Beanie",
      "category": "accessory",
      "quantity": 1,
      "unit_price": 28.99,
      "subtotal": 28.99
    }
  ],
  "subtotal": 98.97,
  "tax": 7.92,
  "shipping_cost": 8.00,
  "order_total": 114.89,
  "status": "Processing",
  "payment_method": "Visa",
  "shipping_address": {
    "street": "123 Main Street",
    "city": "Boston",
    "state": "MA",
    "country": "US",
    "zip": "02101"
  },
  "carrier": "USPS",
  "customer_location": "US"
}
```

---

## Use Cases

### 1. Daily Revenue
Track sales over time:
```spl
index=retail sourcetype=retail:orders
| timechart span=1d sum(order_total) AS revenue
```

### 2. Product Performance
Find best sellers:
```spl
index=retail sourcetype=retail:orders
| spath items{}
| mvexpand items{}
| spath input=items{} output=product_name path=product_name
| spath input=items{} output=quantity path=quantity
| stats sum(quantity) AS units_sold by product_name
| sort - units_sold | head 10
```

### 3. Category Breakdown
Revenue by product type:
```spl
index=retail sourcetype=retail:orders
| spath items{}
| mvexpand items{}
| spath input=items{} output=category path=category
| spath input=items{} output=subtotal path=subtotal
| stats sum(subtotal) AS revenue by category
| sort - revenue
```

### 4. Average Order Value
Calculate AOV:
```spl
index=retail sourcetype=retail:orders
| stats avg(order_total) AS aov, count AS orders, sum(order_total) AS total_revenue
| eval aov = round(aov, 2)
```

### 5. Geographic Analysis
Sales by region:
```spl
index=retail sourcetype=retail:orders
| stats count AS orders, sum(order_total) AS revenue by customer_location
| eval avg_order = round(revenue/orders, 2)
| sort - revenue
```

### 6. Payment Method Analysis
Track payment preferences:
```spl
index=retail sourcetype=retail:orders
| stats count AS orders, sum(order_total) AS revenue by payment_method
| sort - orders
```

### 7. Hourly Order Volume
Peak shopping hours:
```spl
index=retail sourcetype=retail:orders
| eval hour = strftime(_time, "%H")
| stats count by hour
| sort hour
```

### 8. Cart Size Analysis
Items per order distribution:
```spl
index=retail sourcetype=retail:orders
| spath items{}
| eval item_count = mvcount(items{})
| stats count by item_count
| sort item_count
```

---

## Business Metrics

### Key Performance Indicators
| KPI | Calculation |
|-----|-------------|
| AOV | avg(order_total) |
| Units/Order | avg(item_count) |
| Conversion Rate | orders / sessions |
| Revenue/Day | sum(order_total) per day |

### Sample Dashboard Query
```spl
index=retail sourcetype=retail:orders
| stats
    count AS orders,
    sum(order_total) AS revenue,
    avg(order_total) AS aov,
    dc(customer_id) AS unique_customers
| eval revenue = round(revenue, 2)
| eval aov = round(aov, 2)
```

---

## Correlation with Other Sources

| Source | Correlation |
|--------|-------------|
| [Access Logs](access.md) | `order_id` in URL |
| [ServiceBus](servicebus.md) | `order_id` in all events |

### Order Lifecycle Query
```spl
(index=web uri="/orders/*") OR (index=retail sourcetype=retail:orders) OR (index=retail sourcetype=azure:servicebus)
| eval source=case(
    sourcetype="access_combined", "Web",
    sourcetype="retail:orders", "Order",
    sourcetype="azure:servicebus", "ServiceBus"
)
| transaction order_id maxspan=1h
| table order_id, source, eventType, status
```

---

## Talking Points

**Revenue Trends:**
> "We average $15-20K in daily revenue. Monday is our busiest day - post-weekend shopping. Weekend volume is about 70% of weekday."

**Product Mix:**
> "T-shirts are 50% of volume but only 40% of revenue. Hoodies are 15% of volume but 25% of revenue - higher margin. Pushing hoodie sales improves overall margin."

**Geographic Reach:**
> "70% US, 20% Europe, 10% Norway. International orders have higher shipping cost but similar AOV. We might be underpriced for international markets."

**Conversion:**
> "Correlating with access logs, our conversion rate is about 2%. Industry average is 2-3%. We have room to improve checkout flow."

---

## Related Sources

- [Apache Access](access.md) - Web traffic
- [ServiceBus](servicebus.md) - Order processing events

