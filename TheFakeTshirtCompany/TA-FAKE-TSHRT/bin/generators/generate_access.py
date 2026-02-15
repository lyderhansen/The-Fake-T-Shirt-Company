#!/usr/bin/env python3
"""
Web Access Log Generator (Apache Combined Format) with Full Session Tracking.
Generates realistic web server access logs with sessions, cart tracking, and orders.

Format:
  IP - user [timestamp] "METHOD /path HTTP/1.1" status bytes "referer" "user-agent"
  response_time=XX session_id=XX tshirtcid=XX customer_id=XX order_id=XX [extra_fields]

Session Types:
  - bounce (40%): 1-2 pages, leaves immediately
  - browser (35%): 3-10 pages, browses but doesn't buy
  - abandoned (15%): adds to cart, starts checkout, leaves
  - purchase (10%): completes full checkout
"""

import argparse
import random
import sys
import json
import os
from pathlib import Path
from typing import List, Tuple, Dict, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add, calc_natural_events
from shared.company import US_IP_PFX
from shared.products import PRODUCTS, PRODUCT_CATEGORIES
from scenarios.network import CertificateExpiryScenario
from scenarios.network.firewall_misconfig import FirewallMisconfigScenario
from scenarios.registry import expand_scenarios
from scenarios.ops.cpu_runaway import CpuRunawayScenario
from scenarios.ops.memory_leak import MemoryLeakScenario
# NOTE: DiskFillingScenario NOT imported — MON-ATL-01 does not affect web traffic
from scenarios.ops.dead_letter_pricing import DeadLetterPricingScenario
from scenarios.network.ddos_attack import DdosAttackScenario

# =============================================================================
# PRODUCTS (imported from products.py)
# =============================================================================

PRODUCT_SLUGS = [p.slug for p in PRODUCTS]
PRODUCT_PRICES = {p.slug: p.price for p in PRODUCTS}
CATEGORIES = PRODUCT_CATEGORIES

# User agents (realistic browser distribution)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Bot user agents (for occasional crawler traffic - 5%)
BOT_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]

REFERRERS = [
    "https://www.google.com/",
    "https://www.google.com/search?q=funny+it+tshirts",
    "https://www.reddit.com/r/ProgrammerHumor/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "-",
]

# Session types: (name, weight, page_range)
SESSION_TYPES = [
    ("bounce", 40, (1, 2)),
    ("browser", 35, (3, 10)),
    ("abandoned", 15, (4, 8)),
    ("purchase", 10, (5, 15)),  # Increased max for multi-item carts
]

# Cart size distribution (weighted): [1, 2, 3, 4, 5] items
# 40% have 1 item, 30% have 2, 15% have 3, 10% have 4, 5% have 5
CART_SIZE_WEIGHTS = [40, 30, 15, 10, 5]

# Quantity distribution: 80% qty=1, 20% qty=2
QTY_WEIGHTS = [80, 20]

# Order tracking
ORDER_SEQUENCE = 0
ORDER_REGISTRY: List[Dict] = []


# =============================================================================
# HELPERS
# =============================================================================

def get_visitor_ip() -> str:
    """Get a random visitor IP."""
    prefix = random.choice(US_IP_PFX)
    return f"{prefix}.{random.randint(1, 254)}"


def get_user_agent() -> str:
    """Get random user agent (95% browsers, 5% bots)."""
    if random.randint(1, 100) <= 95:
        return random.choice(USER_AGENTS)
    return random.choice(BOT_AGENTS)


def get_customer_id(pool_total: int = 10000, pool_vip: int = 500) -> str:
    """Get customer ID with Pareto distribution (30% from top VIPs, 70% from rest).

    Pool size scales dynamically with order volume to maintain ~4 orders/customer.
    VIP customers (top 5%) drive 30% of traffic (Pareto distribution).
    """
    if random.randint(1, 100) <= 30:
        return f"CUST-{random.randint(1, pool_vip):05d}"
    return f"CUST-{random.randint(pool_vip + 1, pool_total):05d}"


def generate_session_id() -> str:
    """Generate unique session ID."""
    return f"sess_{random.randint(0, 0xFFFFFFFF):08x}"


def generate_tshirtcid() -> str:
    """Generate tracking cookie ID (UUID v4 format)."""
    return f"{random.randint(0, 0xFFFF):04x}{random.randint(0, 0xFFFF):04x}-{random.randint(0, 0xFFFF):04x}-4{random.randint(0, 0xFFF):03x}-{random.randint(0x8000, 0xBFFF):04x}-{random.randint(0, 0xFFFF):04x}{random.randint(0, 0xFFFF):04x}{random.randint(0, 0xFFFF):04x}"


def get_method_for_url(url: str) -> str:
    """Get HTTP method based on URL."""
    if url.startswith("/cart/add") or url == "/checkout/complete" or "/api/" in url and "/cart" in url:
        return "POST"
    return "GET"


def get_response_size(url: str) -> int:
    """Get response size based on URL type."""
    if url == "/":
        return random.randint(8000, 13000)
    elif url.startswith("/products/category/"):
        return random.randint(7000, 11000)
    elif url.startswith("/products/"):
        return random.randint(6000, 9000)
    elif url == "/cart":
        return random.randint(4000, 6000)
    elif url.startswith("/cart/add"):
        return random.randint(200, 700)
    elif url == "/checkout":
        return random.randint(5000, 7000)
    elif url == "/checkout/complete":
        return random.randint(1500, 2500)
    elif url.startswith("/api/"):
        return random.randint(500, 2500)
    elif url.startswith("/static/") or url.startswith("/css/") or url.startswith("/js/"):
        return random.randint(10000, 60000)
    else:
        return random.randint(2000, 5000)


def get_response_time(url: str, multiplier: int = 100) -> int:
    """Get response time in ms based on URL type."""
    if url.startswith("/api/"):
        base_rt = random.randint(20, 70)
    elif url.startswith("/static/"):
        base_rt = random.randint(5, 15)
    elif url.startswith("/cart/add"):
        base_rt = random.randint(40, 120)
    elif url == "/checkout/complete":
        base_rt = random.randint(150, 350)
    elif url == "/checkout":
        base_rt = random.randint(100, 250)
    elif url.startswith("/products/"):
        base_rt = random.randint(40, 120)
    else:
        base_rt = random.randint(30, 90)

    jitter = random.randint(-base_rt // 4, base_rt // 4)
    return max(1, base_rt * multiplier // 100 + jitter)


def get_status_code(error_rate: int = 0) -> int:
    """Get HTTP status code with optional error injection."""
    if error_rate > 0 and random.randint(1, 100) <= error_rate:
        roll = random.randint(1, 100)
        if roll <= 60:
            return 503
        elif roll <= 90:
            return 504
        else:
            return 500

    roll = random.randint(1, 1000)
    if roll <= 940:
        return 200
    elif roll <= 958:
        return 304
    elif roll <= 972:
        return 301
    elif roll <= 984:
        return 404
    elif roll <= 989:
        return 401    # Unauthorized (expired session, bad API key)
    elif roll <= 994:
        return 403    # Forbidden (access denied)
    elif roll <= 997:
        return 429    # Too Many Requests (rate limiting)
    else:
        return 500


def format_apache_time(dt: datetime) -> str:
    """Format datetime as Apache log timestamp."""
    return dt.strftime("[%d/%b/%Y:%H:%M:%S +0000]")


# Monitoring server IP (MON-ATL-01) for health check probes
HEALTH_CHECK_IP = "10.20.20.30"
HEALTH_CHECK_UA = "Nagios/4.4.6 (health_check)"
HEALTH_PATHS = ["/health", "/health/db", "/health/cache"]

# Bot crawl paths
BOT_CRAWL_PATHS = [
    "/robots.txt", "/sitemap.xml", "/sitemap_products.xml",
    "/favicon.ico", "/.well-known/security.txt",
]


def generate_health_check_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate monitoring health check probes from MON-ATL-01.

    ~2 probes per minute (every 30s), cycling through health endpoints.
    Returns list of Apache combined log lines.
    """
    events = []
    dt = date_add(base_date, day)

    for minute in range(60):
        for sec_offset in (0, 30):
            second = sec_offset + random.randint(0, 3)
            ts = format_apache_time(dt.replace(hour=hour, minute=minute, second=min(second, 59)))
            path = random.choice(HEALTH_PATHS)
            # Health checks are fast and always succeed (unless scenario overrides)
            rt = random.randint(2, 8)
            size = random.randint(50, 200)
            line = (
                f'{HEALTH_CHECK_IP} - - {ts} "GET {path} HTTP/1.1" 200 {size} '
                f'"-" "{HEALTH_CHECK_UA}" response_time={rt}'
            )
            events.append(line)

    return events


def generate_bot_crawl_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate search engine bot crawl requests.

    ~2-5 per hour for robots.txt, sitemap.xml, etc.
    """
    events = []
    dt = date_add(base_date, day)
    count = random.randint(2, 5)

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = format_apache_time(dt.replace(hour=hour, minute=minute, second=second))
        path = random.choice(BOT_CRAWL_PATHS)
        ua = random.choice(BOT_AGENTS)
        rt = random.randint(5, 25)
        size = random.randint(200, 5000) if path != "/favicon.ico" else random.randint(1000, 4000)
        status = 200
        # ~5% chance of 404 for bots hitting non-existent paths
        if random.random() < 0.05:
            status = 404
            size = random.randint(200, 500)
        line = (
            f'{"66.249." + str(random.randint(64, 95)) + "." + str(random.randint(1, 254))} '
            f'- - {ts} "GET {path} HTTP/1.1" {status} {size} "-" "{ua}" response_time={rt}'
        )
        events.append(line)

    return events


# =============================================================================
# SESSION GENERATION
# =============================================================================

def generate_session(
    base_date: str,
    day: int,
    start_hour: int,
    start_min: int,
    start_sec: int,
    response_mult: int = 100,
    error_rate: int = 0,
    demo_id: Optional[str] = None,
    pool_total: int = 10000,
    pool_vip: int = 500,
) -> List[str]:
    """Generate a complete user session with full tracking."""
    global ORDER_SEQUENCE

    events = []

    # Session identifiers
    session_id = generate_session_id()
    tshirtcid = generate_tshirtcid()
    ip = get_visitor_ip()
    ua = get_user_agent()

    # Pick session type
    roll = random.randint(1, 100)
    cumulative = 0
    session_type = "bounce"
    page_range = (1, 2)

    for stype, weight, prange in SESSION_TYPES:
        cumulative += weight
        if roll <= cumulative:
            session_type = stype
            page_range = prange
            break

    page_count = random.randint(*page_range)

    # Customer ID for purchase/abandoned sessions
    customer_id = "-"
    if session_type in ("abandoned", "purchase"):
        customer_id = get_customer_id(pool_total, pool_vip)

    # Cart tracking
    cart_items = 0
    cart_total = 0
    cart_products: List[Tuple[str, int, int]] = []  # (slug, price, qty)

    # Plan cart for purchase/abandoned sessions (multi-item support)
    planned_cart: List[Tuple[str, int]] = []  # [(slug, qty), ...]
    if session_type in ("purchase", "abandoned"):
        # Determine number of unique items (1-5, weighted distribution)
        num_items = random.choices([1, 2, 3, 4, 5], weights=CART_SIZE_WEIGHTS)[0]
        # Select unique products
        selected_slugs = random.sample(PRODUCT_SLUGS, min(num_items, len(PRODUCT_SLUGS)))
        for slug in selected_slugs:
            # 20% chance of qty=2, otherwise qty=1
            qty = random.choices([1, 2], weights=QTY_WEIGHTS)[0]
            planned_cart.append((slug, qty))
    planned_cart_index = 0  # Track which planned item we're adding next

    # Time tracking
    dt = date_add(base_date, day)
    current_sec = start_hour * 3600 + start_min * 60 + start_sec

    # Landing page selection
    landing_roll = random.randint(1, 100)
    if landing_roll <= 40:
        current_url = "/"
    elif landing_roll <= 75:
        current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
    elif landing_roll <= 95:
        current_url = f"/products/category/{random.choice(CATEGORIES)}"
    else:
        current_url = random.choice(["/about", "/faq", "/shipping"])

    previous_url = "-"
    order_id = "-"
    pages_generated = 0

    while pages_generated < page_count:
        hour = current_sec // 3600
        minute = (current_sec % 3600) // 60
        sec = current_sec % 60

        if hour >= 24:
            break

        # Referer
        if previous_url == "-":
            ref_roll = random.randint(1, 100)
            if ref_roll <= 40:
                referer = "https://www.google.com/"
            elif ref_roll <= 60:
                referer = "https://www.google.com/search?q=funny+it+tshirts"
            elif ref_roll <= 75:
                referer = "https://www.reddit.com/r/ProgrammerHumor/"
            elif ref_roll <= 85:
                referer = "https://www.facebook.com/"
            elif ref_roll <= 95:
                referer = "https://twitter.com/"
            else:
                referer = "-"
        else:
            referer = f"https://theFakeTshirtCompany.com{previous_url}"

        # Status, response time, method, size
        status = get_status_code(error_rate)
        response_time = get_response_time(current_url, response_mult)
        method = get_method_for_url(current_url)
        size = get_response_size(current_url)

        # Extra fields
        extra_fields = ""

        # Product page: add product_price
        if current_url.startswith("/products/") and not current_url.startswith("/products/category/"):
            url_slug = current_url.replace("/products/", "")
            price = PRODUCT_PRICES.get(url_slug, 299)
            extra_fields += f" product_price={price}"

        # Cart add: update cart
        if current_url.startswith("/cart/add"):
            # Parse slug and qty from URL
            url_parts = current_url.replace("/cart/add?product=", "").split("&qty=")
            url_slug = url_parts[0]
            qty = int(url_parts[1]) if len(url_parts) > 1 else 1
            price = PRODUCT_PRICES.get(url_slug, 299)
            cart_items += qty
            cart_total += price * qty
            cart_products.append((url_slug, price, qty))
            extra_fields += f" product_price={price} qty={qty}"

        # Cart/checkout pages: add cart info
        if current_url in ("/cart", "/checkout", "/checkout/complete"):
            extra_fields += f" cart_items={cart_items} cart_total={cart_total}"

        # Order completion
        this_order_id = order_id
        if current_url == "/checkout/complete" and status == 200:
            ORDER_SEQUENCE += 1
            this_order_id = f"ORD-2026-{ORDER_SEQUENCE:05d}"
            order_id = this_order_id

            # Add to order registry
            iso_timestamp = dt.replace(hour=hour, minute=minute, second=sec).strftime("%Y-%m-%dT%H:%M:%SZ")
            ORDER_REGISTRY.append({
                "order_id": this_order_id,
                "tshirtcid": tshirtcid,
                "customer_id": customer_id,
                "session_id": session_id,
                "timestamp": iso_timestamp,
                "products": [{"slug": s, "price": p, "qty": q} for s, p, q in cart_products],
                "cart_total": cart_total,
                "scenario": demo_id,
            })

        # User field (customer ID at checkout)
        user = "-"
        if current_url.startswith("/checkout") and customer_id != "-":
            user = customer_id

        # Format timestamp
        ts = dt.replace(hour=hour, minute=minute, second=sec)
        timestamp = format_apache_time(ts)

        # Build log line
        line = f'{ip} - {user} {timestamp} "{method} {current_url} HTTP/1.1" {status} {size} "{referer}" "{ua}" response_time={response_time} session_id={session_id} tshirtcid={tshirtcid} customer_id={customer_id} order_id={this_order_id}'
        line += extra_fields
        if demo_id:
            line += f" demo_id={demo_id}"

        events.append(line)

        # Prepare for next page
        pages_generated += 1
        previous_url = current_url
        current_sec += random.randint(8, 180)  # 8s to 3min between pages

        # Determine next URL based on session type and progress
        remaining = page_count - pages_generated
        if remaining <= 0:
            break

        if session_type == "bounce":
            current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"

        elif session_type == "browser":
            browse_roll = random.randint(1, 100)
            if browse_roll <= 50:
                current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
            elif browse_roll <= 80:
                current_url = f"/products/category/{random.choice(CATEGORIES)}"
            else:
                search_terms = ["coffee", "code", "linux", "developer", "security"]
                current_url = f"/api/v1/search?q={random.choice(search_terms)}"

        elif session_type == "abandoned":
            # Pages needed: product view + cart add for each item, then /cart, /checkout
            items_remaining = len(planned_cart) - planned_cart_index
            checkout_pages = 2  # /cart and /checkout
            item_pages = items_remaining * 2  # view + add per item

            if remaining <= 1:
                current_url = "/checkout"
            elif remaining <= 2:
                current_url = "/cart"
            elif items_remaining > 0 and remaining <= checkout_pages + item_pages:
                # Time to add items to cart
                page_offset = remaining - checkout_pages - 1  # 0-indexed position in item sequence
                if page_offset >= 0 and page_offset < item_pages:
                    item_idx = (item_pages - 1 - page_offset) // 2
                    is_view = (item_pages - 1 - page_offset) % 2 == 0
                    if item_idx < items_remaining:
                        slug, qty = planned_cart[planned_cart_index + item_idx]
                        if is_view:
                            current_url = f"/products/{slug}"
                        else:
                            current_url = f"/cart/add?product={slug}&qty={qty}"
                    else:
                        current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
                else:
                    current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
            else:
                current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"

        elif session_type == "purchase":
            # Pages needed: product view + cart add for each item, then /cart, /checkout, /checkout/complete
            items_remaining = len(planned_cart) - planned_cart_index
            checkout_pages = 3  # /cart, /checkout, /checkout/complete
            item_pages = items_remaining * 2  # view + add per item

            if remaining <= 1:
                current_url = "/checkout/complete"
            elif remaining <= 2:
                current_url = "/checkout"
            elif remaining <= 3:
                current_url = "/cart"
            elif items_remaining > 0 and remaining <= checkout_pages + item_pages:
                # Time to add items to cart
                page_offset = remaining - checkout_pages - 1  # 0-indexed position in item sequence
                if page_offset >= 0 and page_offset < item_pages:
                    item_idx = (item_pages - 1 - page_offset) // 2
                    is_view = (item_pages - 1 - page_offset) % 2 == 0
                    if item_idx < items_remaining:
                        slug, qty = planned_cart[planned_cart_index + item_idx]
                        if is_view:
                            current_url = f"/products/{slug}"
                        else:
                            current_url = f"/cart/add?product={slug}&qty={qty}"
                    else:
                        current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
                else:
                    current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"
            else:
                current_url = f"/products/{random.choice(PRODUCT_SLUGS)}"

    return events


def generate_ssl_error_event(
    base_date: str,
    day: int,
    hour: int,
    minute: int,
    second: int,
    demo_id: str = "certificate_expiry",
) -> str:
    """Generate a single SSL error event (502/503) for certificate expiry scenario."""
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    ts = format_apache_time(dt)

    # Random customer IP
    ip = f"{random.choice(US_IP_PFX)}.{random.randint(1, 254)}"

    # Paths that would fail
    paths = ["/", "/products", "/cart", "/checkout", "/api/v1/products", "/api/v1/cart"]
    path = random.choice(paths)

    # Error status
    status = random.choice([502, 503])

    # User agent
    ua = random.choice(USER_AGENTS)

    # Response time (timeout - high)
    response_time = random.randint(30000, 60000)

    # Format: IP - user [timestamp] "METHOD /path HTTP/1.1" status bytes "referer" "ua" extras
    # During SSL outage, bytes=0 and we add ssl_error field
    log_line = (
        f'{ip} - - {ts} "GET {path} HTTP/1.1" {status} 0 '
        f'"-" "{ua}" response_time={response_time} ssl_error=certificate_expired '
        f'demo_id={demo_id}'
    )

    return log_line


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_access_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    orders_per_day: int = None,
    quiet: bool = False,
) -> int:
    """Generate web access logs with full session tracking.

    Args:
        orders_per_day: Target orders per day. If set, overrides base_sessions calculation.
                        Default (~224/day with base 300) can be increased to e.g. 3000/day
                        for high-volume demos with more revenue impact.
    """
    global ORDER_SEQUENCE, ORDER_REGISTRY

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("web", "access_combined.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Order registry path
    registry_path = output_path.parent / "order_registry.json"

    # Reset order tracking
    ORDER_SEQUENCE = 0
    ORDER_REGISTRY = []

    # Calculate base sessions per peak hour
    # Default: 300 sessions/peak hour -> ~224 orders/day
    # With orders_per_day override: scale up proportionally
    # Formula: orders_per_day ≈ base * 0.75 (10% purchase rate * daily multiplier)
    if orders_per_day:
        # Scale base to achieve target orders/day
        base_sessions_per_peak_hour = int((orders_per_day / 0.75) * scale)
    else:
        base_sessions_per_peak_hour = int(300 * scale)

    # Dynamic customer pool: ~4 orders per customer (realistic for e-commerce)
    total_orders_estimate = (orders_per_day or 224) * days
    pool_total = max(500, total_orders_estimate // 4)
    pool_vip = max(50, pool_total // 20)  # VIP = 5% of pool, drives 30% of traffic
    if not quiet:
        print(f"  Customer pool: {pool_total:,} customers ({pool_vip} VIP)", file=sys.stderr)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_cert_expiry = "certificate_expiry" in active_scenarios

    # Initialize scenarios
    cert_expiry_scenario = None
    if include_cert_expiry:
        cert_expiry_scenario = CertificateExpiryScenario(demo_id_enabled=True)

    # Initialize ops scenarios
    # NOTE: disk_filling is NOT initialized here — MON-ATL-01 is a monitoring
    # server in Atlanta, not web infrastructure. It does not affect web traffic.
    cpu_runaway_scenario = None
    memory_leak_scenario = None

    if "cpu_runaway" in active_scenarios:
        cpu_runaway_scenario = CpuRunawayScenario(demo_id_enabled=True)

    if "memory_leak" in active_scenarios:
        memory_leak_scenario = MemoryLeakScenario(demo_id_enabled=True)

    # Initialize network scenarios
    firewall_misconfig_scenario = None
    if "firewall_misconfig" in active_scenarios:
        firewall_misconfig_scenario = FirewallMisconfigScenario(demo_id_enabled=True)

    # Initialize dead_letter_pricing scenario
    dead_letter_scenario = None
    if "dead_letter_pricing" in active_scenarios:
        dead_letter_scenario = DeadLetterPricingScenario(demo_id_enabled=True)

    # Initialize ddos_attack scenario
    ddos_attack_scenario = None
    if "ddos_attack" in active_scenarios:
        ddos_attack_scenario = DdosAttackScenario(demo_id_enabled=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Web Access Log Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        if orders_per_day:
            print(f"  Target: ~{orders_per_day} orders/day", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events = []

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [Access] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        # Track recovery state across hours within each day.
        # After a major outage ends (error_rate drops from high to low),
        # sessions ramp back up gradually instead of snapping to 100%.
        # This simulates real-world behavior: users slowly return, caches
        # refill, CDN propagation catches up, word spreads that site is back.
        recovery_hours_remaining = 0
        recovery_ramp = []  # Session multiplier schedule, e.g. [0.30, 0.50, 0.70, 0.85]
        prev_error_rate = 0

        for hour in range(24):
            # Check if we're in SSL outage period (certificate_expiry scenario)
            is_ssl_outage = include_cert_expiry and cert_expiry_scenario.is_outage_period(day, hour)

            # Calculate sessions for this hour
            sessions = calc_natural_events(base_sessions_per_peak_hour, start_date, day, hour, "web")

            # Calculate error_rate and response_multiplier from ops scenarios
            error_rate = 0
            response_mult = 100  # percentage (100 = normal)
            demo_id = None

            # CPU Runaway - database issues cause web errors
            if cpu_runaway_scenario:
                should_error, rate, mult = cpu_runaway_scenario.access_should_error(day, hour)
                if should_error:
                    error_rate = max(error_rate, rate)
                    response_mult = max(response_mult, int(mult * 100))
                    demo_id = "cpu_runaway"

            # Memory Leak - web server issues
            if memory_leak_scenario:
                should_error, rate, mult = memory_leak_scenario.access_should_error(day, hour)
                if should_error or mult > 1.0:
                    error_rate = max(error_rate, rate)
                    response_mult = max(response_mult, int(mult * 100))
                    if should_error:
                        demo_id = "memory_leak"

            # NOTE: disk_filling is NOT integrated here -- MON-ATL-01 is a
            # monitoring server in Atlanta, not web infrastructure. It does not
            # affect web traffic, orders, or revenue.

            # Firewall Misconfiguration - ACL blocks web traffic (overrides other scenarios)
            if firewall_misconfig_scenario:
                should_error, rate, mult = firewall_misconfig_scenario.access_should_error(day, hour)
                if should_error:
                    error_rate = max(error_rate, rate)
                    response_mult = max(response_mult, int(mult * 100))
                    demo_id = "firewall_misconfig"  # Primary cause, overrides ops scenarios

            # Dead Letter Pricing - checkout errors from stale prices
            if dead_letter_scenario:
                should_error, rate, mult = dead_letter_scenario.access_should_error(day, hour)
                if should_error:
                    error_rate = max(error_rate, rate)
                    response_mult = max(response_mult, int(mult * 100))
                    demo_id = demo_id or "dead_letter_pricing"

            # DDoS Attack - volumetric HTTP flood overwhelms web servers (overrides ops scenarios)
            if ddos_attack_scenario:
                should_error, rate, mult = ddos_attack_scenario.access_should_error(day, hour)
                if should_error:
                    error_rate = max(error_rate, rate)
                    response_mult = max(response_mult, int(mult * 100))
                    demo_id = "ddos_attack"

            # ── Post-recovery ramp-up detection ──────────────────────────
            # Detect transition from outage to normal and start gradual recovery.
            # This prevents the "compensation spike" where instant return to full
            # sessions after an outage creates an unrealistic revenue surge.
            if prev_error_rate >= 40 and error_rate < 8:
                # Transition from severe outage (OOM, DDoS peak) -> normal
                # 4-hour ramp: 30% -> 50% -> 70% -> 85% of baseline sessions
                recovery_ramp = [0.30, 0.50, 0.70, 0.85]
                recovery_hours_remaining = len(recovery_ramp)
            elif prev_error_rate >= 20 and error_rate < 8:
                # Transition from moderate outage (pre-OOM, DDoS ramp) -> normal
                # 3-hour ramp: 50% -> 70% -> 85%
                recovery_ramp = [0.50, 0.70, 0.85]
                recovery_hours_remaining = len(recovery_ramp)

            if is_ssl_outage:
                # During outage: generate SSL error events instead of normal sessions
                # Reduced volume (customers can't complete requests)
                error_count = sessions // 3  # Fewer attempts due to errors
                for _ in range(error_count):
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    all_events.append(generate_ssl_error_event(start_date, day, hour, minute, second))
            else:
                # Reduce session volume during high-error scenarios
                # Simulates customer abandonment: word spreads that site is down,
                # fewer people attempt to visit. Combined with per-page error_rate,
                # this creates a visible revenue drop in orders.
                effective_sessions = sessions
                if error_rate >= 40:
                    # Severe outage (DDoS peak, OOM crash): 30% of normal traffic
                    effective_sessions = max(1, sessions * 30 // 100)
                elif error_rate >= 20:
                    # Major issues (pre-OOM, DDoS ramping): 50% of normal traffic
                    effective_sessions = max(1, sessions * 50 // 100)
                elif error_rate >= 8:
                    # Moderate degradation (cpu_runaway, memory critical): 75% traffic
                    effective_sessions = max(1, sessions * 75 // 100)
                elif recovery_hours_remaining > 0:
                    # Post-recovery ramp-up: gradually return to full volume.
                    # Users don't instantly come back after an outage -- word has
                    # to spread that the site is back, CDN caches need to refill,
                    # and users who gave up won't retry for a while.
                    ramp_idx = len(recovery_ramp) - recovery_hours_remaining
                    if 0 <= ramp_idx < len(recovery_ramp):
                        effective_sessions = max(1, int(sessions * recovery_ramp[ramp_idx]))
                    recovery_hours_remaining -= 1

                # Normal operation (with potential error injection from ops scenarios)
                for _ in range(effective_sessions):
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    all_events.extend(generate_session(
                        start_date, day, hour, minute, second,
                        response_mult=response_mult,
                        error_rate=error_rate,
                        demo_id=demo_id if error_rate > 0 else None,
                        pool_total=pool_total,
                        pool_vip=pool_vip,
                    ))

            # Track error rate for recovery detection in next hour
            prev_error_rate = error_rate

            # Health check probes from MON-ATL-01 (every 30s, all hours)
            all_events.extend(generate_health_check_events(start_date, day, hour))

            # Search engine bot crawls (2-5 per hour)
            all_events.extend(generate_bot_crawl_events(start_date, day, hour))

        if not quiet:
            print(f"  [Access] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort events by timestamp
    all_events.sort()

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(event + "\n")

    # Write order registry as JSONL (one JSON object per line for Splunk)
    with open(registry_path, "w") as f:
        for entry in ORDER_REGISTRY:
            f.write(json.dumps(entry) + "\n")

    if not quiet:
        print(f"  [Access] Complete! {len(all_events):,} events, {len(ORDER_REGISTRY)} orders", file=sys.stderr)

    return len(all_events)


def main():
    parser = argparse.ArgumentParser(description="Generate web access logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--orders-per-day", type=int, default=None,
                        help="Target orders per day (default: ~224, max recommended: 3000)")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_access_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output,
        orders_per_day=args.orders_per_day, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
