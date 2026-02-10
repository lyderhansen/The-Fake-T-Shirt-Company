#!/usr/bin/env python3
"""
SAP S/4HANA Audit Log Generator.
Generates realistic SAP audit log events correlated with existing order/product data.

Sourcetype: sap:auditlog (matches PowerConnect for SAP, Splunkbase #3153)

Event categories:
  - Transaction execution (VA01, MIGO, FB01, MM01, VL01N, VF01, etc.)
  - User activity (login, logout, failed login, password change, auth check fail)
  - Masterdata changes (price change, BOM update, vendor/customer status)
  - Inventory events (goods receipt, goods issue, stock transfer)
  - Financial postings (invoice, payment run, GL journal entry)
  - Batch jobs (nightly MRP run, posting period close, report generation)
  - System events (transport import, background job schedule)

Format: pipe-delimited audit log
  timestamp|host|dialog_type|user|tcode|status|description|document_number|details

Correlation:
  - Reads order_registry.json for order→SAP sales order correlation
  - Uses products.py for material master data
  - SAP users mapped to company employees by department
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import (
    DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE,
    get_output_path,
)
from shared.time_utils import (
    date_add, is_weekend, calc_natural_events, get_hour_activity_level,
)
from shared.company import USERS, get_users_by_department
from shared.products import PRODUCTS

# =============================================================================
# CONFIGURATION
# =============================================================================

SAP_HOST = "SAP-PROD-01"
SAP_DB_HOST = "SAP-DB-01"
SAP_CLIENT = "100"  # Production client

# Base events per peak hour (before volume adjustments)
BASE_TCODE_EVENTS = 80       # Transaction executions
BASE_USER_EVENTS = 30        # Login/logout/auth events
BASE_INVENTORY_EVENTS = 40   # Goods movements
BASE_FINANCIAL_EVENTS = 15   # Financial postings
BASE_MASTERDATA_EVENTS = 3   # Masterdata changes (low frequency, business hours only)

# =============================================================================
# SAP USER MAPPING
# =============================================================================
# Map company employees to SAP roles by department

def _build_sap_users() -> Dict[str, Dict]:
    """Build SAP user pool from company employees by department."""
    sap_users = {}

    # Finance → FI/CO t-codes
    for u in get_users_by_department("Finance"):
        sap_users[u.username] = {
            "role": "FI_USER",
            "tcodes": ["FB01", "F-28", "FK01", "FS00", "FBL1N", "FBL3N", "FBL5N"],
            "department": "Finance",
        }

    # Sales → SD t-codes
    for u in get_users_by_department("Sales"):
        sap_users[u.username] = {
            "role": "SD_USER",
            "tcodes": ["VA01", "VA02", "VA03", "VL01N", "VF01", "VD01", "VD02"],
            "department": "Sales",
        }

    # Operations → MM/WM t-codes
    for u in get_users_by_department("Operations"):
        sap_users[u.username] = {
            "role": "MM_USER",
            "tcodes": ["MIGO", "MMBE", "MM01", "MM02", "MM03", "ME21N", "ME23N", "MB52"],
            "department": "Operations",
        }

    # Executive → reporting t-codes
    for u in get_users_by_department("Executive"):
        sap_users[u.username] = {
            "role": "REPORTING",
            "tcodes": ["SE16", "FAGLL03", "KSB1", "S_ALR_87013611"],
            "department": "Executive",
        }

    # IT → BASIS t-codes (pick 2-3 IT admins)
    it_users = get_users_by_department("IT")[:3]
    for u in it_users:
        sap_users[u.username] = {
            "role": "BASIS",
            "tcodes": ["SM37", "SM21", "STMS", "SU01", "ST22", "SM50", "SM66", "RZ20"],
            "department": "IT",
        }

    return sap_users


SAP_USERS = _build_sap_users()

# Service accounts
SAP_SERVICE_ACCOUNTS = {
    "sap.batch": {"role": "BATCH", "tcodes": ["SM37"], "department": "System"},
    "sap.rfc": {"role": "RFC", "tcodes": ["RFC"], "department": "System"},
    "sap.idoc": {"role": "IDOC", "tcodes": ["WE02", "BD87"], "department": "System"},
}

# Dialog types
DIALOG_TYPES = {
    "DIA": 70,   # Interactive dialog (user at screen)
    "RFC": 15,   # Remote function call
    "BTC": 10,   # Background/batch
    "UPD": 5,    # Update task
}

# =============================================================================
# SAP T-CODE DEFINITIONS
# =============================================================================

# T-code → (description, document_prefix, category)
TCODE_CATALOG = {
    # Sales & Distribution
    "VA01": ("Create Sales Order", "SO", "sd"),
    "VA02": ("Change Sales Order", "SO", "sd"),
    "VA03": ("Display Sales Order", "SO", "sd"),
    "VL01N": ("Create Delivery", "DL", "sd"),
    "VF01": ("Create Billing Document", "INV", "sd"),
    "VD01": ("Create Customer Master", "C", "sd"),
    "VD02": ("Change Customer Master", "C", "sd"),
    # Materials Management
    "MIGO": ("Goods Movement", "GM", "mm"),
    "MMBE": ("Stock Overview", None, "mm"),
    "MM01": ("Create Material Master", "M", "mm"),
    "MM02": ("Change Material Master", "M", "mm"),
    "MM03": ("Display Material Master", "M", "mm"),
    "ME21N": ("Create Purchase Order", "PO", "mm"),
    "ME23N": ("Display Purchase Order", "PO", "mm"),
    "MB52": ("Warehouse Stocks", None, "mm"),
    # Finance
    "FB01": ("Post Document", "DOC", "fi"),
    "F-28": ("Incoming Payment", "PAY", "fi"),
    "FK01": ("Create Vendor Master", "V", "fi"),
    "FS00": ("G/L Account Master", None, "fi"),
    "FBL1N": ("Vendor Line Items", None, "fi"),
    "FBL3N": ("G/L Account Line Items", None, "fi"),
    "FBL5N": ("Customer Line Items", None, "fi"),
    "FAGLL03": ("G/L Account Display", None, "fi"),
    "KSB1": ("Cost Center Actual Postings", None, "fi"),
    "S_ALR_87013611": ("Balance Sheet Report", None, "fi"),
    # Basis / System
    "SM37": ("Background Job Overview", None, "basis"),
    "SM21": ("System Log", None, "basis"),
    "STMS": ("Transport Management System", "TR", "basis"),
    "SU01": ("User Maintenance", None, "basis"),
    "ST22": ("ABAP Runtime Errors", None, "basis"),
    "SM50": ("Work Process Overview", None, "basis"),
    "SM66": ("Global Work Process Overview", None, "basis"),
    "RZ20": ("CCMS Monitoring", None, "basis"),
    "SE16": ("Data Browser", None, "basis"),
    # Reporting (display-only — no document number)
}

# =============================================================================
# MATERIAL MASTER (from products.py)
# =============================================================================

def _build_material_master() -> Dict[str, Dict]:
    """Map products.py to SAP material numbers."""
    materials = {}
    for p in PRODUCTS:
        mat_id = f"M-{p.id:04d}"
        materials[mat_id] = {
            "description": p.name,
            "slug": p.slug,
            "price": p.price,
            "type": p.product_type,
            "category": p.category,
        }
    return materials


MATERIAL_MASTER = _build_material_master()
MATERIAL_IDS = list(MATERIAL_MASTER.keys())

# =============================================================================
# VENDOR AND CUSTOMER MASTER
# =============================================================================

VENDORS = [
    ("V-10001", "Cotton Source Inc.", "Raw Materials"),
    ("V-10002", "Pacific Textile Mills", "Fabric Supply"),
    ("V-10003", "PrintTech Solutions", "Screen Printing"),
    ("V-10004", "BoxCraft Packaging", "Packaging"),
    ("V-10005", "SwiftShip Logistics", "Shipping"),
    ("V-10006", "YarnWorld Global", "Thread & Accessories"),
]

# Customer IDs align with order_registry customer_id prefix
CUSTOMER_PREFIX = "C"

# =============================================================================
# EVENT GENERATION FUNCTIONS
# =============================================================================

def _fmt_ts(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """SAP audit log timestamp: YYYY-MM-DD HH:MM:SS"""
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _sap_event(ts: str, dialog_type: str, user: str, tcode: str,
               status: str, description: str, doc_number: str,
               details: str, demo_id: str = None) -> str:
    """Format a single SAP audit log line."""
    line = f"{ts}|{SAP_HOST}|{dialog_type}|{user}|{tcode}|{status}|{description}|{doc_number}|{details}"
    if demo_id:
        line += f"|demo_id={demo_id}"
    return line


def _pick_sap_user(role_filter: str = None) -> str:
    """Pick a random SAP user, optionally filtered by role."""
    if role_filter:
        candidates = [u for u, d in SAP_USERS.items() if d["role"] == role_filter]
    else:
        candidates = list(SAP_USERS.keys())
    return random.choice(candidates) if candidates else "sap.batch"


def _next_doc_number(prefix: str, year: int, counter: dict) -> str:
    """Generate sequential document number: PREFIX-YEAR-NNNNN."""
    key = f"{prefix}-{year}"
    counter[key] = counter.get(key, 0) + 1
    return f"{prefix}-{year}-{counter[key]:05d}"


# =============================================================================
# EVENT CATEGORY GENERATORS
# =============================================================================

def generate_tcode_events(base_date: str, day: int, hour: int,
                          doc_counter: dict, order_queue: list) -> List[str]:
    """Generate transaction execution events for one hour."""
    events = []
    dt = date_add(base_date, day)
    year = dt.year
    is_wknd = is_weekend(dt)
    count = calc_natural_events(BASE_TCODE_EVENTS, base_date, day, hour, "default")

    if is_wknd:
        count = max(1, count // 4)  # Minimal SAP usage on weekends

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = _fmt_ts(base_date, day, hour, minute, second)

        # Pick user and one of their t-codes
        username = _pick_sap_user()
        user_info = SAP_USERS[username]
        tcode = random.choice(user_info["tcodes"])
        tcode_info = TCODE_CATALOG.get(tcode)

        if not tcode_info:
            continue

        desc, doc_prefix, category = tcode_info
        dialog_type = "DIA"

        # Generate document number if applicable
        doc_number = ""
        details = ""

        if doc_prefix:
            doc_number = _next_doc_number(doc_prefix, year, doc_counter)

        # Category-specific details
        if tcode == "VA01" and order_queue:
            # Correlate with order_registry
            order = order_queue.pop(0)
            doc_number = _next_doc_number("SO", year, doc_counter)
            items = len(order.get("products", []))
            total = order.get("cart_total", 0)
            cust_id = order.get("customer_id", "CUST-00000")
            details = f"Sales order for customer {cust_id}, {items} items, total ${total:.2f}"
        elif tcode == "VA02":
            details = random.choice([
                "Changed delivery date", "Updated quantity",
                "Added discount condition", "Changed shipping point",
            ])
        elif tcode == "MIGO":
            mat = random.choice(MATERIAL_IDS)
            mat_info = MATERIAL_MASTER[mat]
            qty = random.randint(50, 500)
            movement = random.choice(["101", "201", "301", "261"])
            mvt_desc = {"101": "GR for PO", "201": "GI for cost center",
                        "301": "Stock transfer", "261": "GI for production order"}
            doc_number = _next_doc_number("GM", year, doc_counter)
            details = f"Mvt {movement} ({mvt_desc.get(movement, 'Movement')}), material {mat} \"{mat_info['description']}\", qty {qty}"
        elif tcode == "FB01":
            amount = round(random.uniform(500, 25000), 2)
            posting_type = random.choice([
                "Revenue recognition", "Cost allocation", "Accrual posting",
                "Vendor invoice", "Intercompany transfer",
            ])
            doc_number = _next_doc_number("DOC", year, doc_counter)
            details = f"GL posting: {posting_type} ${amount:,.2f}"
        elif tcode == "F-28":
            amount = round(random.uniform(100, 50000), 2)
            doc_number = _next_doc_number("PAY", year, doc_counter)
            details = f"Payment received ${amount:,.2f}"
        elif tcode == "MM02":
            mat = random.choice(MATERIAL_IDS)
            mat_info = MATERIAL_MASTER[mat]
            old_price = mat_info["price"]
            change_pct = random.uniform(-0.10, 0.15)
            new_price = round(old_price * (1 + change_pct), 2)
            details = f"Price changed from ${old_price:.2f} to ${new_price:.2f} for {mat} \"{mat_info['description']}\""
        elif tcode == "MM01":
            doc_number = _next_doc_number("M", year, doc_counter)
            details = "New material created"
        elif tcode == "VL01N":
            doc_number = _next_doc_number("DL", year, doc_counter)
            details = f"Delivery created, shipping point BOS1"
        elif tcode == "VF01":
            amount = round(random.uniform(30, 500), 2)
            doc_number = _next_doc_number("INV", year, doc_counter)
            details = f"Billing document ${amount:,.2f}"
        elif tcode in ("VA03", "MM03", "ME23N", "MMBE", "MB52",
                        "FBL1N", "FBL3N", "FBL5N", "FAGLL03", "KSB1",
                        "SE16", "S_ALR_87013611"):
            # Display/report transactions — no document, no details
            details = "Display only"
            doc_number = ""
        elif tcode == "FK01":
            doc_number = _next_doc_number("V", year, doc_counter)
            details = f"Vendor created: {random.choice(VENDORS)[1]}"
        elif tcode == "VD01":
            doc_number = _next_doc_number("C", year, doc_counter)
            details = "Customer master created"
        elif tcode == "VD02":
            details = random.choice([
                "Updated credit limit", "Changed payment terms",
                "Updated address", "Changed account group",
            ])
        elif tcode == "ME21N":
            vendor = random.choice(VENDORS)
            amount = round(random.uniform(1000, 50000), 2)
            doc_number = _next_doc_number("PO", year, doc_counter)
            details = f"PO to {vendor[1]} ({vendor[2]}), ${amount:,.2f}"
        elif tcode in ("SM37", "SM21", "SM50", "SM66", "RZ20", "ST22"):
            details = "System monitoring"
            dialog_type = "DIA"
        elif tcode == "SU01":
            details = random.choice([
                "User lock/unlock", "Password reset",
                "Role assignment changed", "User activity review",
            ])
        elif tcode == "STMS":
            doc_number = _next_doc_number("TR", year, doc_counter)
            details = random.choice([
                "Transport imported to production",
                "Transport released from development",
                "Transport queue reviewed",
            ])
        elif tcode == "FS00":
            details = "G/L account maintenance"

        status = "S"  # Success
        # ~2% failure rate
        if random.random() < 0.02:
            status = "E"
            details = random.choice([
                "Authorization check failed for object S_TCODE",
                "Authorization check failed for object F_BKPF_BUK",
                "Document locked by another user",
                "Material master locked",
                "Number range exhausted",
            ])

        events.append(_sap_event(ts, dialog_type, username, tcode, status, desc, doc_number, details))

    return events


def generate_user_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate user activity events (login/logout/failed login)."""
    events = []
    count = calc_natural_events(BASE_USER_EVENTS, base_date, day, hour, "auth")

    if is_weekend(date_add(base_date, day)):
        count = max(1, count // 5)

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = _fmt_ts(base_date, day, hour, minute, second)

        event_type = random.choices(
            ["login", "logout", "failed_login", "password_change", "auth_check_fail"],
            weights=[40, 35, 12, 3, 10],
        )[0]

        if event_type == "login":
            username = _pick_sap_user()
            dialog = random.choices(["DIA", "RFC"], weights=[80, 20])[0]
            terminal = f"T{random.randint(1000, 9999)}"
            events.append(_sap_event(
                ts, dialog, username, "LOGIN", "S",
                "User Login", "", f"Client {SAP_CLIENT}, terminal {terminal}"
            ))
        elif event_type == "logout":
            username = _pick_sap_user()
            events.append(_sap_event(
                ts, "DIA", username, "LOGOUT", "S",
                "User Logout", "", f"Client {SAP_CLIENT}, session duration {random.randint(5, 480)} min"
            ))
        elif event_type == "failed_login":
            # Use SAP user or random string for truly failed
            if random.random() < 0.7:
                username = _pick_sap_user()
            else:
                username = random.choice(["admin", "test.user", "sap_admin", "root"])
            reason = random.choice([
                "Password logon no longer possible - too many failed attempts",
                "Password is incorrect",
                "User is locked",
                "User does not exist",
            ])
            events.append(_sap_event(
                ts, "DIA", username, "LOGIN", "E",
                "Failed Login", "", f"Client {SAP_CLIENT}, reason: {reason}"
            ))
        elif event_type == "password_change":
            username = _pick_sap_user()
            events.append(_sap_event(
                ts, "DIA", username, "SU01", "S",
                "Password Changed", "", f"Password changed by user"
            ))
        elif event_type == "auth_check_fail":
            username = _pick_sap_user()
            auth_obj = random.choice([
                "S_TCODE", "F_BKPF_BUK", "M_BEST_WRK", "V_VBAK_VKO",
                "S_PROGRAM", "S_RFC", "S_BTCH_JOB",
            ])
            events.append(_sap_event(
                ts, "DIA", username, "AUTH_CHECK", "E",
                "Authorization Check Failed", "",
                f"Object: {auth_obj}, user attempted unauthorized action"
            ))

    return events


def generate_inventory_events(base_date: str, day: int, hour: int,
                              doc_counter: dict) -> List[str]:
    """Generate inventory movement events."""
    events = []
    dt = date_add(base_date, day)
    year = dt.year
    count = calc_natural_events(BASE_INVENTORY_EVENTS, base_date, day, hour, "default")

    if is_weekend(dt):
        count = max(0, count // 6)  # Almost no warehouse activity on weekends

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = _fmt_ts(base_date, day, hour, minute, second)
        username = _pick_sap_user("MM_USER")

        mat = random.choice(MATERIAL_IDS)
        mat_info = MATERIAL_MASTER[mat]
        qty = random.randint(10, 200)

        movement = random.choices(
            ["101", "201", "301", "261", "501", "601"],
            weights=[30, 15, 10, 20, 15, 10],
        )[0]

        mvt_descriptions = {
            "101": ("Goods Receipt for PO", "GR"),
            "201": ("Goods Issue to Cost Center", "GI"),
            "301": ("Stock Transfer Between Plants", "ST"),
            "261": ("Goods Issue for Production", "GI"),
            "501": ("Receipt Without PO", "GR"),
            "601": ("Goods Issue for Delivery", "GI"),
        }

        desc_text, gi_gr = mvt_descriptions.get(movement, ("Goods Movement", "GM"))
        doc_number = _next_doc_number("GM", year, doc_counter)

        status = "S"
        details = f"Mvt {movement}: {desc_text}, {mat} \"{mat_info['description']}\", qty {qty}, storage loc BOS1"

        # ~1% inventory discrepancy
        if random.random() < 0.01:
            status = "W"  # Warning
            details += ", VARIANCE DETECTED: qty mismatch with count"

        events.append(_sap_event(ts, "DIA", username, "MIGO", status, desc_text, doc_number, details))

    return events


def generate_financial_events(base_date: str, day: int, hour: int,
                              doc_counter: dict) -> List[str]:
    """Generate financial posting events."""
    events = []
    dt = date_add(base_date, day)
    year = dt.year
    count = calc_natural_events(BASE_FINANCIAL_EVENTS, base_date, day, hour, "default")

    if is_weekend(dt):
        count = 0  # No finance postings on weekends

    for _ in range(count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = _fmt_ts(base_date, day, hour, minute, second)
        username = _pick_sap_user("FI_USER")

        posting_type = random.choices(
            ["invoice", "payment", "gl_journal", "cost_allocation", "vendor_payment"],
            weights=[30, 20, 25, 15, 10],
        )[0]

        if posting_type == "invoice":
            amount = round(random.uniform(50, 5000), 2)
            doc_number = _next_doc_number("INV", year, doc_counter)
            events.append(_sap_event(
                ts, "DIA", username, "VF01", "S",
                "Create Invoice", doc_number,
                f"Invoice posted ${amount:,.2f}, revenue account 400000"
            ))
        elif posting_type == "payment":
            amount = round(random.uniform(100, 25000), 2)
            doc_number = _next_doc_number("PAY", year, doc_counter)
            events.append(_sap_event(
                ts, "DIA", username, "F-28", "S",
                "Incoming Payment", doc_number,
                f"Payment received ${amount:,.2f}, clearing account 100000"
            ))
        elif posting_type == "gl_journal":
            amount = round(random.uniform(500, 50000), 2)
            doc_number = _next_doc_number("DOC", year, doc_counter)
            events.append(_sap_event(
                ts, "DIA", username, "FB01", "S",
                "Post Document", doc_number,
                f"GL journal entry ${amount:,.2f}"
            ))
        elif posting_type == "cost_allocation":
            amount = round(random.uniform(1000, 20000), 2)
            doc_number = _next_doc_number("DOC", year, doc_counter)
            cc = random.choice(["CC-1000", "CC-2000", "CC-3000", "CC-4000"])
            events.append(_sap_event(
                ts, "DIA", username, "FB01", "S",
                "Post Document", doc_number,
                f"Cost center allocation ${amount:,.2f} to {cc}"
            ))
        elif posting_type == "vendor_payment":
            vendor = random.choice(VENDORS)
            amount = round(random.uniform(500, 30000), 2)
            doc_number = _next_doc_number("PAY", year, doc_counter)
            events.append(_sap_event(
                ts, "DIA", username, "F-28", "S",
                "Vendor Payment", doc_number,
                f"Payment to {vendor[1]} ${amount:,.2f}"
            ))

    return events


def generate_batch_events(base_date: str, day: int, hour: int,
                          doc_counter: dict) -> List[str]:
    """Generate background batch job events (nightly MRP, reports, etc.)."""
    events = []
    dt = date_add(base_date, day)
    year = dt.year

    # MRP run — every night at 2 AM
    if hour == 2:
        second = random.randint(0, 30)
        ts_start = _fmt_ts(base_date, day, 2, 0, second)
        planned_orders = random.randint(5, 25)
        duration = random.randint(8, 25)
        events.append(_sap_event(
            ts_start, "BTC", "sap.batch", "SM37", "S",
            "Background Job Started", "MRP_NIGHTLY",
            f"MRP run started, scope: all materials"
        ))
        ts_end = _fmt_ts(base_date, day, 2, duration, random.randint(0, 59))
        events.append(_sap_event(
            ts_end, "BTC", "sap.batch", "SM37", "S",
            "Background Job Completed", "MRP_NIGHTLY",
            f"MRP run completed, {planned_orders} planned orders created, duration {duration} min"
        ))

    # Posting period close — first business day of each "month" (day 0 in our timeline)
    if day == 0 and hour == 3:
        ts = _fmt_ts(base_date, day, 3, 0, random.randint(0, 59))
        events.append(_sap_event(
            ts, "BTC", "sap.batch", "SM37", "S",
            "Background Job Completed", "PERIOD_CLOSE",
            "Posting period close completed for period 12/2025"
        ))

    # Report generation — 5 AM daily
    if hour == 5:
        ts = _fmt_ts(base_date, day, 5, random.randint(0, 15), random.randint(0, 59))
        reports = random.randint(3, 8)
        events.append(_sap_event(
            ts, "BTC", "sap.batch", "SM37", "S",
            "Background Job Completed", "DAILY_REPORTS",
            f"Daily report generation completed, {reports} reports generated"
        ))

    # Inventory recount — every Sunday at 4 AM
    if dt.weekday() == 6 and hour == 4:
        ts = _fmt_ts(base_date, day, 4, random.randint(0, 30), random.randint(0, 59))
        items = random.randint(50, 200)
        variances = random.randint(0, 5)
        events.append(_sap_event(
            ts, "BTC", "sap.batch", "SM37", "S",
            "Background Job Completed", "INVENTORY_RECOUNT",
            f"Weekly inventory recount: {items} items counted, {variances} variances found"
        ))

    return events


def generate_system_events(base_date: str, day: int, hour: int) -> List[str]:
    """Generate system administration events (1-3 per day)."""
    events = []
    dt = date_add(base_date, day)

    if is_weekend(dt):
        return events

    # Transport imports — business hours, ~1-2 per day
    if hour in (10, 14) and random.random() < 0.4:
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = _fmt_ts(base_date, day, hour, minute, second)
        username = _pick_sap_user("BASIS")
        transport_id = f"DEVK9{random.randint(10000, 99999)}"
        desc = random.choice([
            "Customizing transport imported",
            "Workbench transport imported",
            "Configuration change imported",
        ])
        events.append(_sap_event(
            ts, "DIA", username, "STMS", "S",
            "Transport Import", transport_id, desc
        ))

    # System parameter changes — very rare
    if hour == 11 and random.random() < 0.1:
        ts = _fmt_ts(base_date, day, 11, random.randint(0, 59), random.randint(0, 59))
        username = _pick_sap_user("BASIS")
        param = random.choice([
            "rdisp/wp_no_dia", "rdisp/wp_no_btc",
            "login/fails_to_user_lock", "rfc/reject_expired_passwd",
        ])
        events.append(_sap_event(
            ts, "DIA", username, "RZ20", "S",
            "System Parameter Change", "",
            f"Parameter {param} modified"
        ))

    return events


# =============================================================================
# ORDER CORRELATION
# =============================================================================

def load_order_queue(base_date: str, days: int) -> List[Dict]:
    """Load orders from order_registry.json, sorted by timestamp."""
    registry_path = get_output_path("web", "order_registry.json")
    orders = []

    if registry_path.exists():
        with open(registry_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        orders.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        # Sort by timestamp
        orders.sort(key=lambda o: o.get("timestamp", ""))

    return orders


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_sap_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    quiet: bool = False,
) -> int:
    """
    Generate SAP S/4HANA audit log events.

    Returns total event count.
    """
    if output_dir:
        output_path = Path(output_dir) / "sap_audit.log"
    else:
        output_path = get_output_path("erp", "sap_audit.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Load correlated orders
    order_queue = load_order_queue(start_date, days)
    if not quiet:
        print(f"  SAP: Loaded {len(order_queue)} orders from registry for correlation")

    # Distribute orders across hours proportionally
    # We'll feed orders into VA01 events as they come
    hourly_order_queues: Dict[str, list] = {}
    for order in order_queue:
        ts = order.get("timestamp", "")
        if ts:
            # Extract hour key: "day-hour"
            try:
                odt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                base_dt = datetime.strptime(start_date, "%Y-%m-%d")
                day_offset = (odt - base_dt).days
                if 0 <= day_offset < days:
                    key = f"{day_offset}-{odt.hour}"
                    if key not in hourly_order_queues:
                        hourly_order_queues[key] = []
                    hourly_order_queues[key].append(order)
            except (ValueError, TypeError):
                continue

    doc_counter: Dict[str, int] = {}
    total_events = 0

    with open(output_path, "w") as f:
        for day in range(days):
            for hour in range(24):
                all_events = []

                # Get orders for this hour
                hour_key = f"{day}-{hour}"
                hour_orders = hourly_order_queues.get(hour_key, [])

                # Transaction executions (correlated with orders)
                all_events.extend(generate_tcode_events(
                    start_date, day, hour, doc_counter, hour_orders
                ))

                # User activity
                all_events.extend(generate_user_events(
                    start_date, day, hour
                ))

                # Inventory movements
                all_events.extend(generate_inventory_events(
                    start_date, day, hour, doc_counter
                ))

                # Financial postings
                all_events.extend(generate_financial_events(
                    start_date, day, hour, doc_counter
                ))

                # Batch jobs
                all_events.extend(generate_batch_events(
                    start_date, day, hour, doc_counter
                ))

                # System events
                all_events.extend(generate_system_events(
                    start_date, day, hour
                ))

                # Sort by timestamp for chronological output
                all_events.sort()

                for event in all_events:
                    f.write(event + "\n")

                total_events += len(all_events)

    if not quiet:
        print(f"  SAP: Generated {total_events:,} events → {output_path}")

    return total_events


# =============================================================================
# CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SAP audit log events")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()

    count = generate_sap_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        quiet=args.quiet,
    )
    if not args.quiet:
        print(f"\nTotal: {count:,} SAP audit log events")
