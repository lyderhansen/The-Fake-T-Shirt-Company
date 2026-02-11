#!/usr/bin/env python3
"""
Dead Letter Pricing Scenario - ServiceBus DLQ causes wrong product prices.

Timeline (Day 16 = 0-indexed day 15, single day):
    08:00  Price update consumer crashes, messages start dead-lettering
    08:15  First orders with wrong (stale/cached) prices appear
    08:30  Checkout error rate increases (payment validation mismatches)
    09:00  DLQ alert threshold hit -> ServiceNow P3 auto-created
    10:00  Customer complaints arrive
    11:00  IT investigates, finds dead-letter queue full
    11:30  ServiceNow escalated to P2
    12:00  Consumer restarted, DLQ replay begins
    12:30  Prices corrected, error rate drops
    13:00  DLQ fully drained, normal operations resume
    13:30  Post-incident review ticket created

Price errors are deterministic per product (seeded random). ~60% of products
are affected with varied error types: stale discounts, missed price increases,
rounding errors, and double discounts.
"""

import random
from typing import Tuple, List, Optional, Dict
from dataclasses import dataclass


@dataclass
class DeadLetterPricingConfig:
    """Configuration for dead letter pricing scenario."""
    demo_id: str = "dead_letter_pricing"

    # Target server (web store)
    host: str = "WEB-01"
    host_ip: str = "172.16.1.10"

    # Timeline (0-indexed days)
    start_day: int = 15          # Day 16
    end_day: int = 15            # Same day (single-day scenario)

    # Incident progression (hours on Day 16)
    incident_start_hour: int = 8   # 08:00 - consumer crashes
    detection_hour: int = 9        # 09:00 - DLQ alert threshold
    investigation_hour: int = 11   # 11:00 - IT finds the problem
    resolution_hour: int = 12      # 12:00 - consumer restarted
    full_recovery_hour: int = 13   # 13:00 - DLQ fully drained

    # Price error seed for deterministic wrong prices per product
    price_error_seed: int = 20260116

    # Percentage of products affected by stale prices
    affected_product_pct: float = 0.60


class DeadLetterPricingScenario:
    """
    Dead Letter Pricing Scenario.

    A ServiceBus consumer that processes price update messages crashes.
    Messages pile up in the dead-letter queue. The web store falls back
    to stale cached prices. Some products are sold too cheap (lost revenue),
    others too expensive (customer complaints).

    Timeline (Day 16):
        08:00-09:00  Building up: DLQ count rising, 5% checkout errors
        09:00-11:00  Peak impact: 15% errors, 40% DLQ failure rate
        11:00-12:00  Investigation: 10% errors, 30% DLQ rate
        12:00-13:00  Recovery: consumer restarted, DLQ draining
        13:00+       Normal operations
    """

    # Price error types with probabilities and price change ranges
    ERROR_TYPES = [
        # (error_type, weight, min_factor, max_factor, direction)
        # direction: "down" = price too low (revenue loss), "up" = price too high (complaints)
        ("stale_discount_not_removed", 40, 0.70, 0.85, "down"),
        ("stale_price_increase_not_applied", 30, 0.80, 0.90, "down"),
        ("currency_rounding_error", 20, 1.05, 1.15, "up"),
        ("double_discount_applied", 10, 0.50, 0.65, "down"),
    ]

    def __init__(self, config: Optional[DeadLetterPricingConfig] = None,
                 demo_id_enabled: bool = True):
        self.cfg = config or DeadLetterPricingConfig()
        self.demo_id_enabled = demo_id_enabled

        # Pre-compute deterministic price errors per product
        self._price_errors: Dict[str, Dict] = {}
        self._build_price_errors()

        # DLQ rate progression by hour (hour -> failure_rate as fraction 0.0-1.0)
        self._dlq_rates = {
            8: 0.15,    # 08:00-09:00: building up
            9: 0.40,    # 09:00-10:00: peak
            10: 0.40,   # 10:00-11:00: peak continues
            11: 0.30,   # 11:00-12:00: partial mitigation
            12: 0.10,   # 12:00-13:00: recovery (consumer restarted, draining)
        }

        # Accumulated DLQ counts by hour (approximate for metric events)
        self._dlq_counts = {
            8: 85,      # ~85 messages dead-lettered in first hour
            9: 280,     # Accumulated
            10: 480,    # Peak accumulation
            11: 620,    # Still growing (slower)
            12: 350,    # Draining (consumer replaying)
            13: 50,     # Almost drained
        }

    def _build_price_errors(self):
        """Pre-compute deterministic price errors per product.

        Uses seeded random so the same products always get the same
        wrong prices, enabling correlation across generators.
        """
        from shared.products import PRODUCTS

        rng = random.Random(self.cfg.price_error_seed)

        # Build weighted list for error type selection
        error_weights = [et[1] for et in self.ERROR_TYPES]

        for product in PRODUCTS:
            # ~60% of products affected
            if rng.random() > self.cfg.affected_product_pct:
                continue

            # Pick error type (weighted)
            error_type_idx = rng.choices(range(len(self.ERROR_TYPES)),
                                         weights=error_weights, k=1)[0]
            error_type, _, min_factor, max_factor, direction = self.ERROR_TYPES[error_type_idx]

            # Calculate wrong price
            factor = rng.uniform(min_factor, max_factor)
            correct_price = product.price
            wrong_price = round(correct_price * factor)

            # Ensure wrong price is at least $1 different
            if wrong_price == correct_price:
                wrong_price = correct_price - 1 if direction == "down" else correct_price + 1

            # Ensure minimum price of $1
            wrong_price = max(1, wrong_price)

            self._price_errors[product.slug] = {
                "error_type": error_type,
                "correct_price": correct_price,
                "wrong_price": wrong_price,
                "direction": direction,
                "revenue_impact_per_unit": correct_price - wrong_price,  # Positive = loss
            }

    # =========================================================================
    # CORE STATUS METHODS
    # =========================================================================

    def is_active(self, day: int, hour: int = 0) -> bool:
        """Check if the dead letter pricing scenario is active at this day/hour.

        Active from incident_start_hour until full_recovery_hour on the scenario day.
        """
        if day != self.cfg.start_day:
            return False
        return self.cfg.incident_start_hour <= hour < self.cfg.full_recovery_hour

    def is_resolved(self, day: int, hour: int = 0) -> bool:
        """Check if the scenario has been fully resolved.

        Resolved after full_recovery_hour on the scenario day, or any day after.
        """
        if day > self.cfg.start_day:
            return True
        if day == self.cfg.start_day and hour >= self.cfg.full_recovery_hour:
            return True
        return False

    def get_demo_id(self, day: int, hour: int) -> str:
        """Get demo_id if scenario is active."""
        if self.demo_id_enabled and self.is_active(day, hour):
            return self.cfg.demo_id
        return ""

    # =========================================================================
    # PRICE ERROR METHODS
    # =========================================================================

    def get_wrong_price(self, product_slug: str, day: int, hour: int) -> Optional[int]:
        """Get the wrong (stale) price for a product during the scenario.

        Returns None if product is not affected or scenario not active.
        Returns the wrong price (int) if the product has a stale cached price.
        """
        if not self.is_active(day, hour):
            return None

        error_info = self._price_errors.get(product_slug)
        if error_info is None:
            return None

        # During recovery (consumer restarted), fewer products affected
        if hour == self.cfg.resolution_hour:
            # 50% of products corrected in first hour of recovery
            rng = random.Random(hash(product_slug) + hour)
            if rng.random() < 0.50:
                return None

        return error_info["wrong_price"]

    def get_price_error_type(self, product_slug: str) -> Optional[str]:
        """Get the error type for a product (if affected).

        Returns None if product is not affected.
        """
        error_info = self._price_errors.get(product_slug)
        if error_info is None:
            return None
        return error_info["error_type"]

    def get_revenue_impact(self, product_slug: str, quantity: int = 1) -> float:
        """Calculate revenue impact for a product.

        Positive = revenue loss (sold too cheap)
        Negative = overcharge (sold too expensive)
        """
        error_info = self._price_errors.get(product_slug)
        if error_info is None:
            return 0.0
        return error_info["revenue_impact_per_unit"] * quantity

    def get_affected_products(self) -> Dict[str, Dict]:
        """Get all affected products and their price errors.

        Returns dict of {slug: {error_type, correct_price, wrong_price, direction}}.
        """
        return dict(self._price_errors)

    def get_affected_product_count(self) -> int:
        """Get count of products with wrong prices."""
        return len(self._price_errors)

    # =========================================================================
    # DLQ RATE METHODS (for ServiceBus generator)
    # =========================================================================

    def get_dlq_rate(self, day: int, hour: int) -> float:
        """Get the dead-letter queue failure rate for this hour.

        Returns 0.0-1.0 fraction of messages that should be dead-lettered.
        """
        if day != self.cfg.start_day:
            return 0.0
        return self._dlq_rates.get(hour, 0.0)

    def get_dlq_count(self, day: int, hour: int) -> int:
        """Get approximate accumulated DLQ message count at this hour."""
        if day != self.cfg.start_day:
            return 0
        return self._dlq_counts.get(hour, 0)

    def servicebus_should_deadletter(self, day: int, hour: int) -> Tuple[bool, float]:
        """Check if ServiceBus messages should be dead-lettered.

        Returns (should_deadletter, failure_rate).
        Used by generate_servicebus.py to increase DLQ events.
        """
        rate = self.get_dlq_rate(day, hour)
        if rate > 0:
            return (True, rate)
        return (False, 0.0)

    # =========================================================================
    # ACCESS LOG INTEGRATION
    # =========================================================================

    def access_should_error(self, day: int, hour: int) -> Tuple[bool, int, float]:
        """Return (should_inject_errors, error_rate_pct, response_time_multiplier).

        Timeline for WEB-01:
            08:00-09:00: 5% error rate, 1.3x response time (building up)
            09:00-11:00: 15% error rate, 1.8x response time (peak)
            11:00-12:00: 10% error rate, 1.5x response time (investigation)
            12:00-13:00: 3% error rate, 1.2x response time (recovery)
            13:00+:      0% error rate, 1.0x response time (normal)
        """
        if day != self.cfg.start_day:
            return (False, 0, 1.0)

        if hour == 8:
            return (True, 5, 1.3)
        elif 9 <= hour <= 10:
            return (True, 15, 1.8)
        elif hour == 11:
            return (True, 10, 1.5)
        elif hour == 12:
            return (True, 3, 1.2)
        else:
            return (False, 0, 1.0)

    # =========================================================================
    # SERVICEBUS SCENARIO EFFECT (for get_scenario_effect compatibility)
    # =========================================================================

    def get_scenario_effect(self, day: int, hour: int) -> dict:
        """Get scenario effect for ServiceBus event generation.

        Returns dict compatible with generate_servicebus.get_scenario_effect().
        """
        if day != self.cfg.start_day:
            return {"delay_mult": 100, "failure_rate": 0, "has_effect": False}

        rate = self.get_dlq_rate(day, hour)
        if rate > 0:
            # Convert fraction to percentage for compatibility
            failure_pct = int(rate * 100)
            # Processing delays increase during the incident
            delay_mult = 200 if hour < 12 else 150
            return {"delay_mult": delay_mult, "failure_rate": failure_pct, "has_effect": True}

        return {"delay_mult": 100, "failure_rate": 0, "has_effect": False}

    # =========================================================================
    # RESOLUTION EVENTS (for Linux/ServiceNow generators)
    # =========================================================================

    def get_resolution_events(self, day: int) -> List[Dict]:
        """Get resolution log events for the scenario day.

        Returns list of events with timestamp info for Linux auth.log.
        """
        if day != self.cfg.start_day:
            return []

        return [
            # Consumer crashes
            {
                "hour": 8, "minute": 0, "second": 5,
                "message": "WEB-01 servicebus-consumer[8421]: FATAL: Unhandled exception in PriceUpdateConsumer.ProcessMessageAsync: System.OutOfMemoryException",
                "level": "CRIT",
            },
            {
                "hour": 8, "minute": 0, "second": 6,
                "message": "systemd[1]: servicebus-price-consumer.service: Main process exited, code=exited, status=134/ABRT",
                "level": "ERR",
            },
            {
                "hour": 8, "minute": 0, "second": 7,
                "message": "systemd[1]: servicebus-price-consumer.service: Failed with result 'exit-code'.",
                "level": "ERR",
            },
            # Auto-restart attempts (fail due to connection flood)
            {
                "hour": 8, "minute": 1, "second": 0,
                "message": "systemd[1]: servicebus-price-consumer.service: Scheduled restart job, restart counter is at 1.",
                "level": "INFO",
            },
            {
                "hour": 8, "minute": 1, "second": 5,
                "message": "WEB-01 servicebus-consumer[8455]: ERROR: Failed to connect to ServiceBus: The lock supplied is invalid. Either the lock expired, or the message has already been removed from the queue.",
                "level": "ERR",
            },
            {
                "hour": 8, "minute": 2, "second": 0,
                "message": "systemd[1]: servicebus-price-consumer.service: Start request repeated too quickly, refusing to start.",
                "level": "ERR",
            },
            {
                "hour": 8, "minute": 2, "second": 1,
                "message": "systemd[1]: servicebus-price-consumer.service: Failed with result 'start-limit-hit'.",
                "level": "ERR",
            },
            # IT restarts consumer manually
            {
                "hour": 12, "minute": 0, "second": 0,
                "message": "systemd[1]: Starting servicebus-price-consumer.service - Azure ServiceBus Price Update Consumer...",
                "level": "INFO",
            },
            {
                "hour": 12, "minute": 0, "second": 3,
                "message": "WEB-01 servicebus-consumer[12001]: INFO: Connected to ServiceBus namespace faketshirtcompany-prod, queue prices-queue",
                "level": "INFO",
            },
            {
                "hour": 12, "minute": 0, "second": 5,
                "message": "WEB-01 servicebus-consumer[12001]: INFO: Starting DLQ replay: 620 messages to process",
                "level": "INFO",
            },
            {
                "hour": 12, "minute": 0, "second": 8,
                "message": "systemd[1]: Started servicebus-price-consumer.service - Azure ServiceBus Price Update Consumer.",
                "level": "INFO",
            },
            # DLQ draining progress
            {
                "hour": 12, "minute": 15, "second": 0,
                "message": "WEB-01 servicebus-consumer[12001]: INFO: DLQ replay progress: 310/620 messages processed, 0 errors",
                "level": "INFO",
            },
            {
                "hour": 12, "minute": 30, "second": 0,
                "message": "WEB-01 servicebus-consumer[12001]: INFO: DLQ replay complete: 620/620 messages processed. Price cache refreshed.",
                "level": "INFO",
            },
            {
                "hour": 12, "minute": 30, "second": 5,
                "message": "WEB-01 servicebus-consumer[12001]: INFO: All product prices verified against catalog. 43 prices corrected.",
                "level": "INFO",
            },
            # Full recovery
            {
                "hour": 13, "minute": 0, "second": 0,
                "message": "Alert cleared: ServiceBus dead-letter queue count returned to normal (0 messages)",
                "level": "INFO",
            },
        ]

    # =========================================================================
    # PRICE UPDATE DLQ EVENTS (new event type for ServiceBus)
    # =========================================================================

    def generate_price_update_dlq_events(self, day: int, hour: int, base_ts_str: str) -> List[Dict]:
        """Generate PriceUpdateFailed dead-letter events during the scenario.

        These are new event types that appear in ServiceBus during the incident:
        price update messages that fail because the consumer is down.

        Args:
            day: 0-indexed day
            hour: Hour of day (0-23)
            base_ts_str: Base timestamp string for the hour (ISO format)

        Returns:
            List of ServiceBus event dicts
        """
        if not self.is_active(day, hour):
            return []

        events = []
        rate = self.get_dlq_rate(day, hour)

        # Generate price update DLQ events proportional to rate
        # ~20-50 price updates per hour normally, most fail during incident
        normal_updates = random.randint(20, 50)
        failed_count = int(normal_updates * rate)

        from datetime import datetime
        base_ts = datetime.strptime(base_ts_str, "%Y-%m-%dT%H:%M:%SZ") if isinstance(base_ts_str, str) else base_ts_str

        affected_slugs = list(self._price_errors.keys())

        for i in range(failed_count):
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            ts = base_ts.replace(hour=hour, minute=minute, second=second)
            ts_str = f"{ts.strftime('%Y-%m-%dT%H:%M:%S')}.{random.randint(0, 999):03d}Z"

            product_slug = random.choice(affected_slugs) if affected_slugs else "unknown-product"
            error_info = self._price_errors.get(product_slug, {})

            event = {
                "messageId": f"msg-price-update-{random.randint(10000, 99999)}",
                "sessionId": f"price-session-{random.randint(100, 999)}",
                "correlationId": f"price-{product_slug}-{random.randint(1000, 9999)}",
                "enqueuedTimeUtc": ts_str,
                "sequenceNumber": random.randint(100000, 999999),
                "deliveryCount": 10,  # Max retries exhausted
                "namespace": "faketshirtcompany-prod",
                "queueName": "prices-queue/$deadletterqueue",
                "topicName": "price-events",
                "status": "DeadLettered",
                "deadLetterReason": "MaxDeliveryCountExceeded",
                "deadLetterErrorDescription": "Consumer not running: servicebus-price-consumer.service failed with start-limit-hit",
                "processingTimeMs": random.randint(100, 500),
                "body": {
                    "eventType": "PriceUpdateFailed",
                    "timestamp": ts_str,
                    "productSlug": product_slug,
                    "correctPrice": error_info.get("correct_price", 0),
                    "cachedPrice": error_info.get("wrong_price", 0),
                    "priceSource": "catalog-service-v2",
                    "updateReason": random.choice([
                        "scheduled_price_refresh",
                        "promotion_update",
                        "supplier_cost_change",
                        "dynamic_pricing_adjustment",
                    ]),
                }
            }
            if self.demo_id_enabled:
                event["demo_id"] = self.cfg.demo_id
            events.append(event)

        return events

    # =========================================================================
    # HELPER / DEBUG
    # =========================================================================

    def print_timeline(self):
        """Print scenario timeline for debugging."""
        print("Dead Letter Pricing Scenario Timeline (Day 16)")
        print("=" * 65)
        print()
        print(f"Host: {self.cfg.host}")
        print(f"Incident start: Day {self.cfg.start_day + 1} at {self.cfg.incident_start_hour:02d}:00")
        print(f"Consumer restart: Day {self.cfg.start_day + 1} at {self.cfg.resolution_hour:02d}:00")
        print(f"Full recovery: Day {self.cfg.start_day + 1} at {self.cfg.full_recovery_hour:02d}:00")
        print()
        from shared.products import PRODUCTS
        total_products = len(PRODUCTS)
        print(f"Products affected: {self.get_affected_product_count()}/{total_products}")
        print()

        # Show timeline per hour
        print("Hour-by-hour progression:")
        for hour in range(7, 15):
            active = self.is_active(self.cfg.start_day, hour)
            resolved = self.is_resolved(self.cfg.start_day, hour)
            should_err, err_rate, resp_mult = self.access_should_error(self.cfg.start_day, hour)
            dlq_rate = self.get_dlq_rate(self.cfg.start_day, hour)
            dlq_count = self.get_dlq_count(self.cfg.start_day, hour)

            status = ""
            if resolved:
                status = " [RESOLVED]"
            elif hour == self.cfg.incident_start_hour:
                status = " <<< CONSUMER CRASHES"
            elif hour == self.cfg.detection_hour:
                status = " <<< DLQ ALERT THRESHOLD"
            elif hour == self.cfg.investigation_hour:
                status = " <<< IT INVESTIGATING"
            elif hour == self.cfg.resolution_hour:
                status = " <<< CONSUMER RESTARTED"
            elif active:
                status = " [ACTIVE]"

            print(f"  {hour:02d}:00  Active={active}, DLQ rate={dlq_rate:.0%}, "
                  f"DLQ count={dlq_count}, Errors={err_rate}%, "
                  f"Resp={resp_mult}x{status}")

        # Show sample affected products
        print()
        print("Sample affected products:")
        for slug, info in list(self._price_errors.items())[:5]:
            direction = "LOSS" if info["direction"] == "down" else "OVERCHARGE"
            impact = info["revenue_impact_per_unit"]
            print(f"  {slug}: ${info['correct_price']} -> ${info['wrong_price']} "
                  f"({info['error_type']}, {direction}: ${abs(impact)}/unit)")


if __name__ == "__main__":
    scenario = DeadLetterPricingScenario()
    scenario.print_timeline()
