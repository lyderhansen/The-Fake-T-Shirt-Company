#!/usr/bin/env python3
"""
Azure ServiceBus Event Generator.
Generates ServiceBus events based on order_registry.json from access logs.

This generator READS from order_registry.json (created by generate_access.py)
to ensure correlation of order_id, tshirtcid, session_id, and customer_id
across access logs, orders, and servicebus events.

Events per order:
  1. OrderCreated - When checkout completes
  2. PaymentProcessed - 1-5 seconds after
  3. InventoryReserved - 2-10 seconds after
  4. ShipmentCreated - 1-4 hours after (business hours)
  5. ShipmentDispatched - 4-24 hours after shipment
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add
from scenarios.registry import expand_scenarios
from scenarios.ops.dead_letter_pricing import DeadLetterPricingScenario

# =============================================================================
# CONFIGURATION
# =============================================================================

SERVICE_BUS_NAMESPACE = "faketshirtcompany-prod"

PAYMENT_METHODS = ["Visa", "Mastercard", "American Express", "PayPal", "Apple Pay", "Google Pay"]
CARRIERS = ["USPS", "UPS", "FedEx", "DHL"]

# Baseline ServiceBus error rates (independent of scenario effects)
# ~3% of messages experience transient failures (retried), ~0.5% dead-lettered
_SB_TRANSIENT_FAILURE_RATE = 0.03
_SB_DEAD_LETTER_RATE = 0.005

_SB_DEAD_LETTER_REASONS = [
    "MaxDeliveryCountExceeded",
    "TTLExpiredException",
    "MessageSizeExceeded",
    "SessionCannotBeLocked",
]

_SB_TRANSIENT_ERRORS = [
    "ServiceBusy",
    "ServerBusy",
    "MessageLockLost",
    "SessionLockLost",
]


# =============================================================================
# HELPERS
# =============================================================================

def generate_message_id(order_id: str, event_type: str) -> str:
    """Generate message ID."""
    return f"msg-{order_id}-{event_type.lower()}-{random.randint(10000, 99999)}"


def add_seconds(ts: datetime, seconds: int) -> datetime:
    """Add seconds to timestamp."""
    return ts + timedelta(seconds=seconds)


def format_ts(dt: datetime) -> str:
    """Format timestamp with milliseconds."""
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{random.randint(0, 999):03d}Z"


def get_queue_name(event_type: str) -> str:
    """Get queue name for event type."""
    queues = {
        "OrderCreated": "orders-queue",
        "PaymentProcessed": "payments-queue",
        "InventoryReserved": "inventory-queue",
        "ShipmentCreated": "shipments-queue",
        "ShipmentDispatched": "shipments-queue",
    }
    return queues.get(event_type, "default-queue")


def get_topic_name(event_type: str) -> str:
    """Get topic name for event type."""
    topics = {
        "OrderCreated": "order-events",
        "PaymentProcessed": "payment-events",
        "InventoryReserved": "inventory-events",
        "ShipmentCreated": "shipment-events",
        "ShipmentDispatched": "shipment-events",
    }
    return topics.get(event_type, "default-topic")


def get_scenario_effect(scenario: str, day: int, hour: int) -> dict:
    """
    Get scenario effect (delay multiplier, failure rate).
    Returns: dict with delay_mult, failure_rate, and has_effect
    """
    delay_mult = 100
    failure_rate = 0
    has_effect = False

    if scenario == "memory_leak":
        if day in [5, 6]:
            delay_mult = 150
            failure_rate = 2
            has_effect = True
        elif day in [7, 8]:
            delay_mult = 300
            failure_rate = 10
            has_effect = True
        elif day == 9 and hour < 14:
            delay_mult = 500
            failure_rate = 25
            has_effect = True

    elif scenario == "firewall_misconfig":
        if day == 6 and 10 <= hour < 12:
            failure_rate = 80
            has_effect = True

    elif scenario == "dead_letter_pricing":
        # Handled by DeadLetterPricingScenario object (see _dead_letter_scenario)
        # This branch is for orders that arrive via registry with scenario tag
        if day == 15 and 8 <= hour < 13:
            dlq_rates = {8: 15, 9: 40, 10: 40, 11: 30, 12: 10}
            failure_rate = dlq_rates.get(hour, 0)
            delay_mult = 200 if hour < 12 else 150
            has_effect = True

    return {"delay_mult": delay_mult, "failure_rate": failure_rate, "has_effect": has_effect}


def _sb_maybe_inject_transient(event: Dict) -> Dict:
    """Potentially inject a transient failure into a ServiceBus event (~3% chance).

    Transient failures result in retries (deliveryCount > 1) but ultimately succeed.
    """
    if random.random() > _SB_TRANSIENT_FAILURE_RATE:
        return event

    # Transient: message was retried but succeeded
    event["deliveryCount"] = random.randint(2, 4)
    event["processingTimeMs"] = random.randint(800, 5000)  # Slower due to retries
    event["properties"] = event.get("properties", {})
    event["properties"]["retryReason"] = random.choice(_SB_TRANSIENT_ERRORS)
    return event


def generate_dead_letter_event(order_id: str, tshirtcid: str, customer_id: str,
                                session_id: str, ts: datetime, event_type: str,
                                seq_num: int) -> Dict:
    """Generate a dead-letter queue event for a message that permanently failed."""
    delay = random.randint(60, 600)  # 1-10 min after original
    event_ts_dt = add_seconds(ts, delay)
    message_id = generate_message_id(order_id, f"DLQ-{event_type}")
    event_ts = format_ts(event_ts_dt)

    reason = random.choice(_SB_DEAD_LETTER_REASONS)

    return {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": random.randint(5, 10),  # Max retries exhausted
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": f"{get_queue_name(event_type)}/$deadletterqueue",
        "topicName": get_topic_name(event_type),
        "status": "DeadLettered",
        "deadLetterReason": reason,
        "deadLetterErrorDescription": f"Message moved to DLQ: {reason}",
        "processingTimeMs": random.randint(100, 1000),
        "body": {
            "eventType": event_type,
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
        }
    }


# =============================================================================
# EVENT GENERATORS
# =============================================================================

def generate_order_created(order_id: str, tshirtcid: str, customer_id: str,
                           session_id: str, ts: datetime, items: List[Dict],
                           cart_total: int, scenario: str, seq_num: int) -> Dict:
    """Generate OrderCreated event."""
    message_id = generate_message_id(order_id, "OrderCreated")
    event_ts = format_ts(ts)

    status = "Completed"
    delivery_count = 1
    processing_time = random.randint(50, 500)

    day = (ts - datetime(ts.year, ts.month, 1)).days
    hour = ts.hour
    effect = get_scenario_effect(scenario, day, hour)

    if effect["failure_rate"] > 0 and random.randint(0, 99) < effect["failure_rate"]:
        status = "Failed"
        delivery_count = random.randint(2, 5)

    event = {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": delivery_count,
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": get_queue_name("OrderCreated"),
        "topicName": get_topic_name("OrderCreated"),
        "status": status,
        "processingTimeMs": processing_time,
        "body": {
            "eventType": "OrderCreated",
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
            "items": items,
            "totalAmount": cart_total,
            "currency": "USD"
        }
    }

    # Only add demo_id when scenario actually affects this event
    if effect["has_effect"]:
        event["demo_id"] = scenario

    return _sb_maybe_inject_transient(event)


def generate_payment_processed(order_id: str, tshirtcid: str, customer_id: str,
                               session_id: str, ts: datetime, cart_total: int,
                               scenario: str, seq_num: int) -> Dict:
    """Generate PaymentProcessed event."""
    delay = random.randint(1, 5)
    event_ts_dt = add_seconds(ts, delay)
    message_id = generate_message_id(order_id, "PaymentProcessed")
    event_ts = format_ts(event_ts_dt)

    method = random.choice(PAYMENT_METHODS)
    txn_id = f"TXN-{random.randint(100000000, 999999999)}"

    status = "Completed"
    payment_status = "Approved"
    delivery_count = 1
    processing_time = random.randint(50, 500)

    day = (ts - datetime(ts.year, ts.month, 1)).days
    hour = ts.hour
    effect = get_scenario_effect(scenario, day, hour)

    if effect["failure_rate"] > 0 and random.randint(0, 99) < effect["failure_rate"]:
        status = "Failed"
        payment_status = "Declined"
        delivery_count = random.randint(2, 5)

    event = {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": delivery_count,
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": get_queue_name("PaymentProcessed"),
        "topicName": get_topic_name("PaymentProcessed"),
        "status": status,
        "processingTimeMs": processing_time,
        "body": {
            "eventType": "PaymentProcessed",
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
            "amount": cart_total,
            "currency": "USD",
            "paymentMethod": method,
            "transactionId": txn_id,
            "paymentStatus": payment_status
        }
    }

    # Only add demo_id when scenario actually affects this event
    if effect["has_effect"]:
        event["demo_id"] = scenario

    return _sb_maybe_inject_transient(event)


def generate_inventory_reserved(order_id: str, tshirtcid: str, customer_id: str,
                                session_id: str, ts: datetime, items: List[Dict],
                                scenario: str, seq_num: int) -> Dict:
    """Generate InventoryReserved event."""
    delay = random.randint(2, 10)
    event_ts_dt = add_seconds(ts, delay)
    message_id = generate_message_id(order_id, "InventoryReserved")
    event_ts = format_ts(event_ts_dt)

    status = "Completed"
    delivery_count = 1
    processing_time = random.randint(50, 500)
    reserved = True

    day = (ts - datetime(ts.year, ts.month, 1)).days
    hour = ts.hour
    effect = get_scenario_effect(scenario, day, hour)

    if effect["failure_rate"] > 0 and random.randint(0, 99) < effect["failure_rate"]:
        status = "Failed"
        reserved = False
        delivery_count = random.randint(2, 5)

    # Transform items for inventory
    inv_items = [{"sku": item["sku"], "quantity": 1, "reserved": reserved} for item in items]

    event = {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": delivery_count,
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": get_queue_name("InventoryReserved"),
        "topicName": get_topic_name("InventoryReserved"),
        "status": status,
        "processingTimeMs": processing_time,
        "body": {
            "eventType": "InventoryReserved",
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
            "warehouseId": "WH-US-EAST-01",
            "items": inv_items
        }
    }

    # Only add demo_id when scenario actually affects this event
    if effect["has_effect"]:
        event["demo_id"] = scenario

    return _sb_maybe_inject_transient(event)


def generate_shipment_created(order_id: str, tshirtcid: str, customer_id: str,
                              session_id: str, ts: datetime, scenario: str,
                              seq_num: int) -> Dict:
    """Generate ShipmentCreated event."""
    delay = random.randint(3600, 14400)  # 1-4 hours
    event_ts_dt = add_seconds(ts, delay)
    message_id = generate_message_id(order_id, "ShipmentCreated")
    event_ts = format_ts(event_ts_dt)

    shipment_id = f"SHP-{order_id[4:]}"
    carrier = random.choice(CARRIERS)

    # ETA: 2-5 days
    eta_delay = 86400 * random.randint(2, 5)
    eta_dt = add_seconds(event_ts_dt, eta_delay)
    eta = format_ts(eta_dt)

    day = (ts - datetime(ts.year, ts.month, 1)).days
    hour = ts.hour
    effect = get_scenario_effect(scenario, day, hour)

    event = {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": 1,
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": get_queue_name("ShipmentCreated"),
        "topicName": get_topic_name("ShipmentCreated"),
        "status": "Completed",
        "processingTimeMs": random.randint(50, 500),
        "body": {
            "eventType": "ShipmentCreated",
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
            "shipmentId": shipment_id,
            "carrier": carrier,
            "estimatedDelivery": eta
        }
    }

    # Only add demo_id when scenario actually affects this event
    if effect["has_effect"]:
        event["demo_id"] = scenario

    return _sb_maybe_inject_transient(event)


def generate_shipment_dispatched(order_id: str, tshirtcid: str, customer_id: str,
                                 session_id: str, ts: datetime, scenario: str,
                                 seq_num: int) -> Dict:
    """Generate ShipmentDispatched event."""
    delay = random.randint(18000, 90000)  # 5-25 hours
    event_ts_dt = add_seconds(ts, delay)
    message_id = generate_message_id(order_id, "ShipmentDispatched")
    event_ts = format_ts(event_ts_dt)

    shipment_id = f"SHP-{order_id[4:]}"
    tracking = f"1Z{random.randint(100000000, 999999999)}{random.randint(1000, 9999)}"
    carrier = random.choice(CARRIERS)

    day = (ts - datetime(ts.year, ts.month, 1)).days
    hour = ts.hour
    effect = get_scenario_effect(scenario, day, hour)

    event = {
        "messageId": message_id,
        "sessionId": session_id,
        "tshirtcid": tshirtcid,
        "enqueuedTimeUtc": event_ts,
        "sequenceNumber": seq_num,
        "deliveryCount": 1,
        "namespace": SERVICE_BUS_NAMESPACE,
        "queueName": get_queue_name("ShipmentDispatched"),
        "topicName": get_topic_name("ShipmentDispatched"),
        "status": "Completed",
        "processingTimeMs": random.randint(50, 500),
        "body": {
            "eventType": "ShipmentDispatched",
            "timestamp": event_ts,
            "orderId": order_id,
            "customerId": customer_id,
            "shipmentId": shipment_id,
            "trackingNumber": tracking,
            "carrier": carrier
        }
    }

    # Only add demo_id when scenario actually affects this event
    if effect["has_effect"]:
        event["demo_id"] = scenario

    return _sb_maybe_inject_transient(event)


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_servicebus_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    progress_callback=None,
    quiet: bool = False,
) -> int:
    """Generate ServiceBus events from order_registry.json.

    IMPORTANT: This generator requires generate_access.py to run first,
    which creates the order_registry.json file with correlated IDs.
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("servicebus", "servicebus_events.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Order registry path (created by generate_access.py)
    registry_path = get_output_path("web", "order_registry.json")

    # Initialize dead_letter_pricing scenario if active
    active_scenarios = expand_scenarios(scenarios)
    dead_letter_scenario = None
    if "dead_letter_pricing" in active_scenarios:
        dead_letter_scenario = DeadLetterPricingScenario(demo_id_enabled=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  ServiceBus Event Generator (Python)", file=sys.stderr)
        print(f"  Reading from: {registry_path}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Load order registry
    if not registry_path.exists():
        print(f"  ERROR: Order registry not found: {registry_path}", file=sys.stderr)
        print(f"  Run generate_access.py first to create order_registry.json", file=sys.stderr)
        return 0

    # Read JSONL format (one JSON object per line)
    with open(registry_path, "r") as f:
        order_registry = [json.loads(line) for line in f if line.strip()]

    if not order_registry:
        print(f"  WARNING: Order registry is empty", file=sys.stderr)
        return 0

    if not quiet:
        print(f"  Found {len(order_registry)} orders in registry", file=sys.stderr)

    all_events = []
    seq_num = 1

    for i, entry in enumerate(order_registry):
        if not quiet and (i + 1) % 100 == 0:
            print(f"  [ServiceBus] Processing {i + 1}/{len(order_registry)}...", file=sys.stderr, end="\r")

        # Extract correlated IDs from registry
        order_id = entry["order_id"]
        customer_id = entry["customer_id"]
        session_id = entry["session_id"]
        tshirtcid = entry["tshirtcid"]
        timestamp = entry["timestamp"]
        cart_total = entry["cart_total"]
        products = entry.get("products", [])
        scenario = entry.get("scenario")

        # Parse timestamp
        ts = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")

        # Convert products to items format
        items = [{"sku": p["slug"], "price": p["price"]} for p in products]

        # Use scenario from registry or override
        order_scenario = scenario if scenario else (scenarios if scenarios != "none" else None)

        # Generate all 5 events
        all_events.append(generate_order_created(
            order_id, tshirtcid, customer_id, session_id, ts, items, cart_total, order_scenario, seq_num))
        seq_num += 1

        all_events.append(generate_payment_processed(
            order_id, tshirtcid, customer_id, session_id, ts, cart_total, order_scenario, seq_num))
        seq_num += 1

        all_events.append(generate_inventory_reserved(
            order_id, tshirtcid, customer_id, session_id, ts, items, order_scenario, seq_num))
        seq_num += 1

        all_events.append(generate_shipment_created(
            order_id, tshirtcid, customer_id, session_id, ts, order_scenario, seq_num))
        seq_num += 1

        all_events.append(generate_shipment_dispatched(
            order_id, tshirtcid, customer_id, session_id, ts, order_scenario, seq_num))
        seq_num += 1

        # Baseline dead-letter events (~0.5% of orders get a dead-lettered message)
        if random.random() < _SB_DEAD_LETTER_RATE:
            dlq_event_type = random.choice(["OrderCreated", "PaymentProcessed",
                                             "InventoryReserved", "ShipmentCreated"])
            all_events.append(generate_dead_letter_event(
                order_id, tshirtcid, customer_id, session_id, ts, dlq_event_type, seq_num))
            seq_num += 1

    # Generate price update DLQ events for dead_letter_pricing scenario
    if dead_letter_scenario:
        for hour in range(8, 13):  # 08:00-12:59 on scenario day
            base_ts = date_add(start_date, dead_letter_scenario.cfg.start_day)
            base_ts_str = base_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
            dlq_events = dead_letter_scenario.generate_price_update_dlq_events(
                dead_letter_scenario.cfg.start_day, hour, base_ts_str)
            all_events.extend(dlq_events)
            seq_num += len(dlq_events)
        if not quiet:
            dlq_scenario_count = sum(1 for e in all_events
                                     if e.get("body", {}).get("eventType") == "PriceUpdateFailed")
            print(f"  [ServiceBus] Dead letter pricing: {dlq_scenario_count} PriceUpdateFailed events", file=sys.stderr)

    # Sort by enqueuedTimeUtc
    all_events.sort(key=lambda x: x["enqueuedTimeUtc"])

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    event_count = len(all_events)
    order_count = len(order_registry)

    if not quiet:
        retry_count = sum(1 for e in all_events if e.get("deliveryCount", 1) > 1 and e.get("status") != "DeadLettered")
        dlq_count = sum(1 for e in all_events if e.get("status") == "DeadLettered")
        print(f"\n  Complete!", file=sys.stderr)
        print(f"  Orders: {order_count:,}", file=sys.stderr)
        print(f"  Events: {event_count:,}", file=sys.stderr)
        print(f"  Retried: {retry_count:,} ({retry_count * 100 // max(event_count, 1)}%) | Dead-lettered: {dlq_count:,}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    return event_count


def main():
    parser = argparse.ArgumentParser(description="Generate ServiceBus events")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-file")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_servicebus_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output_file, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
