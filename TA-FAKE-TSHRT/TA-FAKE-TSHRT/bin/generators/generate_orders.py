#!/usr/bin/env python3
"""
Retail Orders Generator.
Generates detailed order records based on order_registry.json from access logs.

This generator READS from order_registry.json (created by generate_access.py)
to ensure correlation of order_id, tshirtcid, session_id, and customer_id
across access logs, orders, and servicebus events.

Customer distribution:
  - 70% United States
  - 20% Europe (UK, Germany, France, Netherlands)
  - 10% Norway

Output: JSON records with full order details including:
  - Product details with names
  - Pricing breakdown (subtotal, tax, shipping, total) in USD
  - Customer and shipping info
  - Order status progression
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add
from shared.products import PRODUCTS, get_random_product

# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_SHIPPING_COST = 8      # USD domestic
INTL_SHIPPING_COST = 15     # USD international
FREE_SHIPPING_THRESHOLD = 50

PAYMENT_METHODS = ["Visa", "Mastercard", "American Express", "PayPal", "Apple Pay", "Google Pay"]

# =============================================================================
# CUSTOMER DATA - UNITED STATES (70%)
# =============================================================================

US_FIRST_NAMES = ["James", "John", "Robert", "Michael", "David", "William", "Richard", "Joseph", "Thomas", "Christopher", "Mary", "Patricia", "Jennifer", "Linda", "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen", "Jason", "Ryan", "Jacob", "Gary", "Nicholas", "Eric", "Jonathan", "Stephen", "Larry", "Justin", "Brandon", "Raymond", "Samuel", "Benjamin", "Gregory", "Frank", "Alexander", "Patrick", "Jack", "Dennis", "Amanda", "Melissa", "Deborah", "Stephanie", "Rebecca", "Sharon", "Laura", "Cynthia", "Kathleen", "Amy", "Angela", "Shirley", "Anna", "Brenda", "Pamela", "Emma", "Nicole", "Helen", "Samantha", "Katherine"]
US_LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts"]

# Format: (state, abbrev, tax_rate, cities)
US_STATES = [
    ("California", "CA", 7.25, ["Los Angeles", "San Francisco", "San Diego", "San Jose", "Sacramento"]),
    ("Texas", "TX", 6.25, ["Houston", "San Antonio", "Dallas", "Austin", "Fort Worth"]),
    ("Florida", "FL", 6.00, ["Miami", "Orlando", "Tampa", "Jacksonville", "Fort Lauderdale"]),
    ("New York", "NY", 8.00, ["New York", "Buffalo", "Rochester", "Albany", "Syracuse"]),
    ("Pennsylvania", "PA", 6.00, ["Philadelphia", "Pittsburgh", "Allentown", "Erie", "Reading"]),
    ("Illinois", "IL", 6.25, ["Chicago", "Aurora", "Naperville", "Rockford", "Joliet"]),
    ("Ohio", "OH", 5.75, ["Columbus", "Cleveland", "Cincinnati", "Toledo", "Akron"]),
    ("Georgia", "GA", 4.00, ["Atlanta", "Augusta", "Columbus", "Savannah", "Athens"]),
    ("North Carolina", "NC", 4.75, ["Charlotte", "Raleigh", "Greensboro", "Durham", "Winston-Salem"]),
    ("Michigan", "MI", 6.00, ["Detroit", "Grand Rapids", "Warren", "Sterling Heights", "Ann Arbor"]),
    ("New Jersey", "NJ", 6.625, ["Newark", "Jersey City", "Paterson", "Elizabeth", "Edison"]),
    ("Virginia", "VA", 5.30, ["Virginia Beach", "Norfolk", "Chesapeake", "Richmond", "Newport News"]),
    ("Washington", "WA", 6.50, ["Seattle", "Spokane", "Tacoma", "Vancouver", "Bellevue"]),
    ("Arizona", "AZ", 5.60, ["Phoenix", "Tucson", "Mesa", "Chandler", "Scottsdale"]),
    ("Massachusetts", "MA", 6.25, ["Boston", "Worcester", "Springfield", "Cambridge", "Lowell"]),
    ("Tennessee", "TN", 7.00, ["Nashville", "Memphis", "Knoxville", "Chattanooga", "Clarksville"]),
    ("Indiana", "IN", 7.00, ["Indianapolis", "Fort Wayne", "Evansville", "South Bend", "Carmel"]),
    ("Missouri", "MO", 4.225, ["Kansas City", "St. Louis", "Springfield", "Columbia", "Independence"]),
    ("Maryland", "MD", 6.00, ["Baltimore", "Frederick", "Rockville", "Gaithersburg", "Bowie"]),
    ("Colorado", "CO", 2.90, ["Denver", "Colorado Springs", "Aurora", "Fort Collins", "Lakewood"]),
]

US_STREETS = ["Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Pine St", "Elm St", "Washington Ave", "Park Blvd", "Lake Dr", "Hill Rd", "River Rd", "Forest Ave", "Sunset Blvd", "Highland Ave", "Valley Rd", "Spring St", "Church St", "Mill Rd", "Academy St", "Center St"]

# =============================================================================
# CUSTOMER DATA - EUROPE (20%)
# =============================================================================

# UK (8%)
UK_FIRST_NAMES = ["Oliver", "Harry", "George", "Jack", "Jacob", "Noah", "Charlie", "Muhammad", "Thomas", "Oscar", "Olivia", "Amelia", "Isla", "Ava", "Emily", "Sophia", "Grace", "Mia", "Poppy", "Ella"]
UK_LAST_NAMES = ["Smith", "Jones", "Williams", "Taylor", "Brown", "Davies", "Evans", "Wilson", "Thomas", "Roberts", "Johnson", "Lewis", "Walker", "Robinson", "Wood", "Thompson", "White", "Watson", "Jackson", "Wright"]
UK_CITIES = [("London", "E1", "England"), ("Manchester", "M1", "England"), ("Birmingham", "B1", "England"), ("Leeds", "LS1", "England"), ("Glasgow", "G1", "Scotland"), ("Liverpool", "L1", "England"), ("Bristol", "BS1", "England"), ("Edinburgh", "EH1", "Scotland"), ("Sheffield", "S1", "England"), ("Newcastle", "NE1", "England")]
UK_STREETS = ["High Street", "Station Road", "Church Lane", "Victoria Road", "Green Lane", "Manor Road", "Park Avenue", "Queens Road", "Kings Road", "Mill Lane"]

# Germany (6%)
DE_FIRST_NAMES = ["Maximilian", "Alexander", "Paul", "Leon", "Louis", "Ben", "Jonas", "Noah", "Elias", "Felix", "Emma", "Mia", "Hannah", "Sofia", "Anna", "Emilia", "Lina", "Marie", "Lena", "Lea"]
DE_LAST_NAMES = ["Muller", "Schmidt", "Schneider", "Fischer", "Weber", "Meyer", "Wagner", "Becker", "Schulz", "Hoffmann", "Koch", "Richter", "Bauer", "Klein", "Wolf", "Zimmermann", "Braun", "Hartmann", "Kruger", "Lange"]
DE_CITIES = [("Berlin", "10115", "Berlin"), ("Hamburg", "20095", "Hamburg"), ("Munich", "80331", "Bavaria"), ("Cologne", "50667", "North Rhine-Westphalia"), ("Frankfurt", "60311", "Hesse"), ("Stuttgart", "70173", "Baden-Wurttemberg"), ("Dusseldorf", "40213", "North Rhine-Westphalia"), ("Leipzig", "04109", "Saxony"), ("Dortmund", "44135", "North Rhine-Westphalia"), ("Essen", "45127", "North Rhine-Westphalia")]
DE_STREETS = ["Hauptstrasse", "Bahnhofstrasse", "Schulstrasse", "Gartenstrasse", "Bergstrasse", "Kirchstrasse", "Waldstrasse", "Ringstrasse", "Friedhofstrasse", "Lindenstrasse"]

# France (4%)
FR_FIRST_NAMES = ["Gabriel", "Louis", "Raphael", "Jules", "Adam", "Lucas", "Leo", "Hugo", "Arthur", "Nathan", "Emma", "Louise", "Jade", "Alice", "Chloe", "Lina", "Mila", "Lea", "Manon", "Rose"]
FR_LAST_NAMES = ["Martin", "Bernard", "Dubois", "Thomas", "Robert", "Richard", "Petit", "Durand", "Leroy", "Moreau", "Simon", "Laurent", "Lefebvre", "Michel", "Garcia", "David", "Bertrand", "Roux", "Vincent", "Fournier"]
FR_CITIES = [("Paris", "75001", "Ile-de-France"), ("Marseille", "13001", "Provence-Alpes-Cote d'Azur"), ("Lyon", "69001", "Auvergne-Rhone-Alpes"), ("Toulouse", "31000", "Occitanie"), ("Nice", "06000", "Provence-Alpes-Cote d'Azur"), ("Nantes", "44000", "Pays de la Loire"), ("Strasbourg", "67000", "Grand Est"), ("Montpellier", "34000", "Occitanie"), ("Bordeaux", "33000", "Nouvelle-Aquitaine"), ("Lille", "59000", "Hauts-de-France")]
FR_STREETS = ["Rue de la Paix", "Avenue des Champs", "Boulevard Saint-Michel", "Rue du Commerce", "Place de la Republique", "Rue Victor Hugo", "Avenue Jean Jaures", "Rue de la Gare", "Boulevard Voltaire", "Rue Pasteur"]

# Netherlands (2%)
NL_FIRST_NAMES = ["Noah", "Daan", "Levi", "Sem", "Lucas", "Liam", "Finn", "Jesse", "Milan", "Luuk", "Emma", "Julia", "Mila", "Tess", "Sophie", "Zoey", "Sara", "Anna", "Noor", "Lieke"]
NL_LAST_NAMES = ["de Jong", "Jansen", "de Vries", "van den Berg", "van Dijk", "Bakker", "Janssen", "Visser", "Smit", "Meijer", "de Boer", "Mulder", "de Groot", "Bos", "Vos", "Peters", "Hendriks", "van Leeuwen", "Dekker", "Brouwer"]
NL_CITIES = [("Amsterdam", "1012", "North Holland"), ("Rotterdam", "3011", "South Holland"), ("The Hague", "2511", "South Holland"), ("Utrecht", "3511", "Utrecht"), ("Eindhoven", "5611", "North Brabant"), ("Groningen", "9711", "Groningen"), ("Tilburg", "5038", "North Brabant"), ("Almere", "1315", "Flevoland"), ("Breda", "4811", "North Brabant"), ("Nijmegen", "6511", "Gelderland")]
NL_STREETS = ["Hoofdstraat", "Kerkstraat", "Dorpsstraat", "Schoolstraat", "Molenstraat", "Stationsweg", "Julianastraat", "Beatrixlaan", "Marktstraat", "Nieuwstraat"]

# Norway (10%)
NO_FIRST_NAMES = ["Erik", "Lars", "Ole", "Per", "Hans", "Anders", "Magnus", "Thomas", "Martin", "Kristian", "Anna", "Kari", "Ingrid", "Marit", "Liv", "Silje", "Hilde", "Mette", "Line", "Kristin"]
NO_LAST_NAMES = ["Hansen", "Johansen", "Olsen", "Larsen", "Andersen", "Pedersen", "Nilsen", "Kristiansen", "Jensen", "Karlsen", "Johnsen", "Pettersen", "Eriksen", "Berg", "Haugen", "Hagen", "Bakken", "Solberg", "Dahl", "Moen"]
NO_CITIES = [("Oslo", "0150", "Oslo"), ("Bergen", "5003", "Vestland"), ("Trondheim", "7010", "Trondelag"), ("Stavanger", "4001", "Rogaland"), ("Drammen", "3015", "Viken"), ("Fredrikstad", "1601", "Viken"), ("Kristiansand", "4612", "Agder"), ("Tromso", "9008", "Troms og Finnmark"), ("Sandnes", "4306", "Rogaland"), ("Sarpsborg", "1702", "Viken")]
NO_STREETS = ["Storgata", "Kirkegata", "Hovedveien", "Parkveien", "Fjordgata", "Sjogata", "Skogveien", "Solveien", "Granveien", "Furveien"]


# =============================================================================
# CUSTOMER GENERATION
# =============================================================================

def get_customer_region(customer_id: str) -> str:
    """Determine region based on customer ID (deterministic)."""
    # Extract numeric part from customer_id
    nums = ''.join(filter(str.isdigit, customer_id))
    seed = int(nums[-6:]) if len(nums) >= 6 else int(nums) if nums else 1

    roll = seed % 100

    if roll < 70:
        return "US"
    elif roll < 78:
        return "UK"
    elif roll < 84:
        return "DE"
    elif roll < 88:
        return "FR"
    elif roll < 90:
        return "NL"
    else:
        return "NO"


def get_customer_data(customer_id: str, region: str) -> Dict:
    """Generate customer data based on region."""
    nums = ''.join(filter(str.isdigit, customer_id))
    seed = int(nums[-6:]) if len(nums) >= 6 else int(nums) if nums else 1

    if region == "US":
        first_name = US_FIRST_NAMES[seed % len(US_FIRST_NAMES)]
        last_name = US_LAST_NAMES[(seed * 7) % len(US_LAST_NAMES)]
        state_data = US_STATES[seed % len(US_STATES)]
        state_name, state_abbrev, tax_rate, cities = state_data
        city = cities[seed % len(cities)]
        street = US_STREETS[(seed * 3) % len(US_STREETS)]
        street_num = (seed * 17) % 9999 + 1
        street = f"{street_num} {street}"
        postal = f"{(seed * 13) % 90000 + 10000:05d}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_name, "country": "United States", "tax_rate": tax_rate
        }

    elif region == "UK":
        first_name = UK_FIRST_NAMES[seed % len(UK_FIRST_NAMES)]
        last_name = UK_LAST_NAMES[(seed * 7) % len(UK_LAST_NAMES)]
        city_data = UK_CITIES[seed % len(UK_CITIES)]
        city, postal_base, state_region = city_data
        postal = f"{postal_base} {chr(65 + (seed % 26))}{chr(65 + ((seed * 3) % 26))}{seed % 10}"
        street = UK_STREETS[(seed * 3) % len(UK_STREETS)]
        street_num = (seed * 17) % 200 + 1
        street = f"{street_num} {street}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_region, "country": "United Kingdom", "tax_rate": 20.00
        }

    elif region == "DE":
        first_name = DE_FIRST_NAMES[seed % len(DE_FIRST_NAMES)]
        last_name = DE_LAST_NAMES[(seed * 7) % len(DE_LAST_NAMES)]
        city_data = DE_CITIES[seed % len(DE_CITIES)]
        city, postal, state_region = city_data
        street = DE_STREETS[(seed * 3) % len(DE_STREETS)]
        street_num = (seed * 17) % 150 + 1
        street = f"{street} {street_num}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_region, "country": "Germany", "tax_rate": 19.00
        }

    elif region == "FR":
        first_name = FR_FIRST_NAMES[seed % len(FR_FIRST_NAMES)]
        last_name = FR_LAST_NAMES[(seed * 7) % len(FR_LAST_NAMES)]
        city_data = FR_CITIES[seed % len(FR_CITIES)]
        city, postal, state_region = city_data
        street = FR_STREETS[(seed * 3) % len(FR_STREETS)]
        street_num = (seed * 17) % 150 + 1
        street = f"{street_num} {street}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_region, "country": "France", "tax_rate": 20.00
        }

    elif region == "NL":
        first_name = NL_FIRST_NAMES[seed % len(NL_FIRST_NAMES)]
        last_name = NL_LAST_NAMES[(seed * 7) % len(NL_LAST_NAMES)]
        city_data = NL_CITIES[seed % len(NL_CITIES)]
        city, postal_base, state_region = city_data
        postal = f"{postal_base} AB"
        street = NL_STREETS[(seed * 3) % len(NL_STREETS)]
        street_num = (seed * 17) % 150 + 1
        street = f"{street} {street_num}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_region, "country": "Netherlands", "tax_rate": 21.00
        }

    else:  # NO
        first_name = NO_FIRST_NAMES[seed % len(NO_FIRST_NAMES)]
        last_name = NO_LAST_NAMES[(seed * 7) % len(NO_LAST_NAMES)]
        city_data = NO_CITIES[seed % len(NO_CITIES)]
        city, postal, state_region = city_data
        street = NO_STREETS[(seed * 3) % len(NO_STREETS)]
        street_num = (seed * 17) % 150 + 1
        street = f"{street} {street_num}"
        return {
            "first_name": first_name, "last_name": last_name,
            "street": street, "city": city, "postal": postal,
            "region": state_region, "country": "Norway", "tax_rate": 25.00
        }


# =============================================================================
# ORDER GENERATION
# =============================================================================

def add_seconds(ts: datetime, seconds: int) -> datetime:
    """Add seconds to timestamp."""
    return ts + timedelta(seconds=seconds)


def generate_order_events(registry_entry: Dict) -> List[Dict]:
    """Generate separate events for each order status change.

    Instead of one event with statusHistory, generates 5 separate events:
    - created, payment_confirmed, processing, shipped, delivered

    Returns list of events to be sorted and written to output.
    """
    order_id = registry_entry["order_id"]
    customer_id = registry_entry["customer_id"]
    session_id = registry_entry["session_id"]
    tshirtcid = registry_entry["tshirtcid"]
    timestamp = registry_entry["timestamp"]
    cart_total = registry_entry["cart_total"]
    products = registry_entry.get("products", [])
    scenario = registry_entry.get("scenario")

    # Parse timestamp
    dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")

    # Customer
    region = get_customer_region(customer_id)
    customer_data = get_customer_data(customer_id, region)
    customer_name = f"{customer_data['first_name']} {customer_data['last_name']}"
    email = f"{customer_data['first_name'].lower()}.{customer_data['last_name'].lower()}@example.com"

    # Items from registry (use actual products from access logs)
    items = []
    subtotal = 0

    if products:
        for p in products:
            # Get full product info from PRODUCTS list (Product dataclass objects)
            product_info = next((prod for prod in PRODUCTS if prod.slug == p["slug"]), None)
            if product_info:
                items.append({
                    "sku": p["slug"],
                    "name": product_info.name,
                    "category": product_info.category,
                    "unitPrice": p["price"],
                    "quantity": p.get("qty", 1),
                    "lineTotal": p["price"] * p.get("qty", 1)
                })
                subtotal += p["price"] * p.get("qty", 1)
            else:
                # Fallback if product not found
                items.append({
                    "sku": p["slug"],
                    "name": p["slug"].replace("-", " ").title(),
                    "category": "unknown",
                    "unitPrice": p["price"],
                    "quantity": p.get("qty", 1),
                    "lineTotal": p["price"] * p.get("qty", 1)
                })
                subtotal += p["price"] * p.get("qty", 1)
    else:
        # Fallback: use cart_total with generic item
        subtotal = cart_total
        items.append({
            "sku": "unknown",
            "name": "Unknown Product",
            "category": "unknown",
            "unitPrice": cart_total,
            "quantity": 1,
            "lineTotal": cart_total
        })

    # Pricing
    tax_rate = customer_data["tax_rate"]
    tax = int(subtotal * tax_rate / 100)

    if customer_data["country"] == "United States":
        shipping = BASE_SHIPPING_COST
    else:
        shipping = INTL_SHIPPING_COST

    if subtotal >= FREE_SHIPPING_THRESHOLD:
        shipping = 0

    total = subtotal + tax + shipping

    # Payment
    payment_method = random.choice(PAYMENT_METHODS)
    txn_id = f"TXN-{random.randint(100000000, 999999999)}"

    # Status timestamps
    ts_created = dt
    ts_payment = add_seconds(dt, random.randint(1, 10))
    ts_processing = add_seconds(dt, random.randint(300, 1800))  # 5-30 min
    ts_shipped = add_seconds(dt, random.randint(3600, 43200))   # 1-12 hours
    ts_delivered = add_seconds(dt, random.randint(86400, 345600))  # 1-4 days

    # Common fields for all events
    base_event = {
        "orderId": order_id,
        "tshirtcid": tshirtcid,
        "sessionId": session_id,
        "customerId": customer_id,
        "items": items,
        "pricing": {
            "subtotal": subtotal,
            "tax": tax,
            "taxRate": tax_rate,
            "shipping": shipping,
            "total": total,
            "currency": "USD"
        },
        "source": "web",
        "channel": "theFakeTshirtCompany.com"
    }

    if scenario and scenario != "none":
        base_event["demo_id"] = scenario

    # Generate separate events for each status
    events = []

    # Event 1: created
    event_created = {**base_event, "status": "created", "timestamp": ts_created.strftime("%Y-%m-%dT%H:%M:%SZ")}
    events.append(event_created)

    # Event 2: payment_confirmed
    event_payment = {
        **base_event,
        "status": "payment_confirmed",
        "timestamp": ts_payment.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "payment": {
            "method": payment_method,
            "transactionId": txn_id
        }
    }
    events.append(event_payment)

    # Event 3: processing
    event_processing = {**base_event, "status": "processing", "timestamp": ts_processing.strftime("%Y-%m-%dT%H:%M:%SZ")}
    events.append(event_processing)

    # Event 4: shipped
    event_shipped = {
        **base_event,
        "status": "shipped",
        "timestamp": ts_shipped.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trackingNumber": f"1Z{random.randint(100000000, 999999999)}"
    }
    events.append(event_shipped)

    # Event 5: delivered
    event_delivered = {**base_event, "status": "delivered", "timestamp": ts_delivered.strftime("%Y-%m-%dT%H:%M:%SZ")}
    events.append(event_delivered)

    return events, region, total


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_orders(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate retail orders from order_registry.json.

    IMPORTANT: This generator requires generate_access.py to run first,
    which creates the order_registry.json file with correlated IDs.
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("retail", "orders.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Order registry path (created by generate_access.py)
    registry_path = get_output_path("web", "order_registry.json")

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Retail Orders Generator (Python)", file=sys.stderr)
        print(f"  Reading from: {registry_path}", file=sys.stderr)
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
    region_counts = {"US": 0, "UK": 0, "DE": 0, "FR": 0, "NL": 0, "NO": 0}
    region_revenue = {"US": 0, "UK": 0, "DE": 0, "FR": 0, "NL": 0, "NO": 0}
    total_revenue = 0
    order_count = 0

    for i, entry in enumerate(order_registry):
        if not quiet and (i + 1) % 100 == 0:
            print(f"  [Orders] Processing {i + 1}/{len(order_registry)}...", file=sys.stderr, end="\r")

        events, region, total = generate_order_events(entry)
        all_events.extend(events)
        order_count += 1

        region_counts[region] += 1
        region_revenue[region] += total
        total_revenue += total

    # Sort all events by timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    event_count = len(all_events)

    if not quiet:
        print(f"\n  Complete!", file=sys.stderr)
        print(f"  Orders: {order_count:,}", file=sys.stderr)
        print(f"  Events: {event_count:,} (5 per order)", file=sys.stderr)
        print(f"  Revenue: ${total_revenue:,} USD", file=sys.stderr)
        print(f"\n  By Region:", file=sys.stderr)
        for region in ["US", "UK", "DE", "FR", "NL", "NO"]:
            count = region_counts[region]
            rev = region_revenue[region]
            pct = count * 100 // order_count if order_count > 0 else 0
            print(f"    {region}: {count} orders ({pct}%) - ${rev:,}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    return event_count


def main():
    parser = argparse.ArgumentParser(description="Generate retail orders")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-file")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_orders(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output_file, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
