#!/usr/bin/env python3
"""
Configuration module for Splunk Log Generators.
Contains all shared constants and default settings.
"""

from datetime import date
from pathlib import Path
from dataclasses import dataclass

# =============================================================================
# DEFAULT SETTINGS
# =============================================================================

DEFAULT_START_DATE = "2026-01-01"
DEFAULT_DAYS = 31
DEFAULT_SCALE = 1.0

# Meraki health metrics interval (minutes between samples)
# Lower = more data, Higher = less data
# 5 min = ~137K events/day, 15 min = ~46K events/day, 30 min = ~23K events/day
DEFAULT_MERAKI_HEALTH_INTERVAL = 5

# =============================================================================
# OUTPUT CONFIGURATION
# =============================================================================

# Base output directory (relative to script location)
# Production mode writes here (where Splunk inputs.conf reads from)
OUTPUT_BASE_PRODUCTION = Path(__file__).parent.parent / "output"

# Default output base — can be overridden by set_output_base()
OUTPUT_BASE = OUTPUT_BASE_PRODUCTION

# Output subdirectories
OUTPUT_DIRS = {
    "network": OUTPUT_BASE / "network",
    "cloud": OUTPUT_BASE / "cloud",
    "windows": OUTPUT_BASE / "windows",
    "linux": OUTPUT_BASE / "linux",
    "web": OUTPUT_BASE / "web",
    "retail": OUTPUT_BASE / "retail",
    "servicebus": OUTPUT_BASE / "servicebus",
    "itsm": OUTPUT_BASE / "itsm",
    "erp": OUTPUT_BASE / "erp",
}

# Output filenames (with subdirectory paths for organized structure)
# Network
FILE_CISCO_ASA = "cisco_asa/cisco_asa.log"
FILE_MERAKI = "meraki/meraki.log"  # Deprecated - use individual files below
FILE_MERAKI_MX = "meraki/meraki_mx_appliance.json"
FILE_MERAKI_MR = "meraki/meraki_mr_wireless.json"
FILE_MERAKI_MS = "meraki/meraki_ms_switch.json"
FILE_MERAKI_MV = "meraki/meraki_mv_camera.json"
FILE_MERAKI_MT = "meraki/meraki_mt_sensor.json"

# Cloud
FILE_AWS_CLOUDTRAIL = "aws/aws_cloudtrail.json"
FILE_GCP_AUDIT = "gcp/gcp_audit.json"
FILE_ENTRAID_SIGNIN = "entraid/entraid_signin.json"
FILE_ENTRAID_AUDIT = "entraid/entraid_audit.json"
FILE_EXCHANGE = "microsoft/exchange_message_trace.json"

# Webex
FILE_WEBEX = "webex/webex_events.json"
FILE_WEBEX_TA_MEETINGUSAGE = "webex/webex_ta_meetingusage.json"
FILE_WEBEX_TA_ATTENDEE = "webex/webex_ta_attendee.json"
FILE_WEBEX_API_MEETINGS = "webex/webex_api_meetings.json"
FILE_WEBEX_API_ADMIN_AUDIT = "webex/webex_api_admin_audit.json"
FILE_WEBEX_API_SECURITY_AUDIT = "webex/webex_api_security_audit.json"
FILE_WEBEX_API_QUALITIES = "webex/webex_api_meeting_qualities.json"
FILE_WEBEX_API_CALL_HISTORY = "webex/webex_api_call_history.json"

# Cisco Catalyst (IOS-XE)
FILE_CATALYST_SYSLOG = "cisco_catalyst/cisco_catalyst_syslog.log"

# Cisco ACI
FILE_ACI_FAULT = "cisco_aci/cisco_aci_fault.json"
FILE_ACI_EVENT = "cisco_aci/cisco_aci_event.json"
FILE_ACI_AUDIT = "cisco_aci/cisco_aci_audit.json"

# Cisco Catalyst Center
FILE_CATALYST_CENTER_DEVICE = "catalyst_center/catalyst_center_devicehealth.json"
FILE_CATALYST_CENTER_NETWORK = "catalyst_center/catalyst_center_networkhealth.json"
FILE_CATALYST_CENTER_CLIENT = "catalyst_center/catalyst_center_clienthealth.json"
FILE_CATALYST_CENTER_ISSUES = "catalyst_center/catalyst_center_issues.json"

# Cisco Secure Access (Umbrella)
FILE_SECURE_ACCESS_DNS = "cisco_secure_access/cisco_secure_access_dns.csv"
FILE_SECURE_ACCESS_PROXY = "cisco_secure_access/cisco_secure_access_proxy.csv"
FILE_SECURE_ACCESS_FIREWALL = "cisco_secure_access/cisco_secure_access_firewall.csv"
FILE_SECURE_ACCESS_AUDIT = "cisco_secure_access/cisco_secure_access_audit.csv"

# Retail / Web
FILE_ACCESS_LOG = "access_combined.log"
FILE_ORDERS = "orders.json"

# =============================================================================
# GENERATOR OUTPUT FILES MAPPING
# =============================================================================

# Generator name → list of output files (relative to output/)
# Used by main_generate.py --show-files to display actual file paths
GENERATOR_OUTPUT_FILES = {
    # Network
    "asa": ["network/cisco_asa/cisco_asa.log"],
    "catalyst": ["network/cisco_catalyst/cisco_catalyst_syslog.log"],
    "aci": [
        "network/cisco_aci/cisco_aci_fault.json",
        "network/cisco_aci/cisco_aci_event.json",
        "network/cisco_aci/cisco_aci_audit.json",
    ],
    "meraki": [
        "network/meraki/meraki_mx_appliance.json",
        "network/meraki/meraki_mr_wireless.json",
        "network/meraki/meraki_mr_health.json",
        "network/meraki/meraki_ms_switch.json",
        "network/meraki/meraki_ms_health.json",
        "network/meraki/meraki_mv_camera.json",
        "network/meraki/meraki_mt_sensor.json",
    ],
    # Cloud
    "aws": ["cloud/aws/aws_cloudtrail.json"],
    "aws_guardduty": ["cloud/aws/aws_guardduty.json"],
    "aws_billing": ["cloud/aws/aws_billing_cur.csv"],
    "gcp": ["cloud/gcp/gcp_audit.json"],
    "entraid": [
        "cloud/entraid/entraid_signin.json",
        "cloud/entraid/entraid_audit.json",
        "cloud/entraid/entraid_risk_detection.json",
    ],
    "exchange": ["cloud/microsoft/exchange_message_trace.json"],
    "office_audit": ["cloud/microsoft/office_audit.json"],
    "secure_access": [
        "cloud/cisco_secure_access/cisco_secure_access_dns.csv",
        "cloud/cisco_secure_access/cisco_secure_access_proxy.csv",
        "cloud/cisco_secure_access/cisco_secure_access_firewall.csv",
        "cloud/cisco_secure_access/cisco_secure_access_audit.csv",
    ],
    "catalyst_center": [
        "cloud/catalyst_center/catalyst_center_devicehealth.json",
        "cloud/catalyst_center/catalyst_center_networkhealth.json",
        "cloud/catalyst_center/catalyst_center_clienthealth.json",
        "cloud/catalyst_center/catalyst_center_issues.json",
    ],
    # Webex (3 generators, same subfolder)
    "webex": ["cloud/webex/webex_events.json"],
    "webex_ta": [
        "cloud/webex/webex_ta_meetingusage.json",
        "cloud/webex/webex_ta_attendee.json",
    ],
    "webex_api": [
        "cloud/webex/webex_api_meetings.json",
        "cloud/webex/webex_api_admin_audit.json",
        "cloud/webex/webex_api_security_audit.json",
        "cloud/webex/webex_api_meeting_qualities.json",
        "cloud/webex/webex_api_call_history.json",
    ],
    # Windows
    "perfmon": [
        "windows/perfmon_processor.log",
        "windows/perfmon_memory.log",
        "windows/perfmon_disk.log",
        "windows/perfmon_network.log",
    ],
    "wineventlog": [
        "windows/wineventlog_security.log",
        "windows/wineventlog_system.log",
        "windows/wineventlog_application.log",
    ],
    "mssql": ["windows/mssql_errorlog.log"],
    "sysmon": ["windows/sysmon_operational.log"],
    # Linux
    "linux": [
        "linux/cpu.log",
        "linux/vmstat.log",
        "linux/df.log",
        "linux/iostat.log",
        "linux/interfaces.log",
        "linux/auth.log",
    ],
    # Web / Retail
    "access": ["web/access_combined.log"],
    "orders": ["retail/orders.json"],
    "servicebus": ["servicebus/servicebus_events.json"],
    # ITSM
    "servicenow": [
        "itsm/servicenow_incidents.log",
        "itsm/servicenow_cmdb.log",
        "itsm/servicenow_change.log",
    ],
    # ERP
    "sap": ["erp/sap_audit.log"],
}

# =============================================================================
# VOLUME CONFIGURATION
# =============================================================================

# Weekend traffic factors by source type (percentage of weekday traffic)
VOLUME_WEEKEND_FACTORS = {
    "default": 25,      # Generic default: 25%
    "cloud": 30,        # AWS/GCP/Azure: 30% (automated jobs)
    "auth": 20,         # Entra ID signin: 20% (critical only)
    "firewall": 80,     # ASA: 80% (e-commerce web traffic + automated systems)
    "email": 15,        # Exchange: 15% (minimal email)
    "web": 110,         # Access logs: 110% (e-commerce has MORE weekend traffic!)
    "windows": 25,      # WinEventLog: 25%
}

# Monday multiplier (post-weekend catch-up)
VOLUME_MONDAY_BOOST = 115  # 115% = 15% more traffic on Mondays

# Day-to-day noise range (percentage variation)
VOLUME_DAILY_NOISE_MIN = -15
VOLUME_DAILY_NOISE_MAX = 15

# =============================================================================
# HOUR ACTIVITY LEVELS
# =============================================================================

# Activity level per hour (0-100) for weekdays
HOUR_ACTIVITY_WEEKDAY = {
    0: 10, 1: 10, 2: 10, 3: 10, 4: 10, 5: 10,  # Night
    6: 20,                                       # Early birds
    7: 40,                                       # Morning ramp-up
    8: 70,                                       # Work starts
    9: 100, 10: 100, 11: 100,                   # Peak morning
    12: 85,                                      # Lunch dip (mild)
    13: 90, 14: 90, 15: 90,                     # Afternoon peak
    16: 70,                                      # Wind down
    17: 50,                                      # End of day
    18: 30,                                      # After hours
    19: 20, 20: 20, 21: 20,                     # Evening
    22: 15, 23: 15,                             # Late night
}

# Activity level per hour (0-100) for weekends - enterprise/office traffic
HOUR_ACTIVITY_WEEKEND = {
    0: 5, 1: 5, 2: 5, 3: 5, 4: 5, 5: 5, 6: 5,
    7: 10, 8: 10, 9: 10,
    10: 15, 11: 15, 12: 15, 13: 15, 14: 15,
    15: 10, 16: 10, 17: 10, 18: 10,
    19: 5, 20: 5, 21: 5, 22: 5, 23: 5,
}

# Activity level per hour (0-100) for weekends - e-commerce/consumer traffic
# People sleep in, browse mid-day, and shop in the evening
HOUR_ACTIVITY_WEEKEND_ECOMMERCE = {
    0: 15, 1: 10, 2: 8, 3: 5, 4: 5, 5: 5, 6: 8,     # Late night/early morning
    7: 15, 8: 25, 9: 40,                             # Morning ramp-up (slower than weekday)
    10: 60, 11: 75, 12: 80,                          # Late morning peak
    13: 85, 14: 90, 15: 95,                          # Afternoon shopping
    16: 100, 17: 100, 18: 100,                       # Peak: after dinner
    19: 95, 20: 90, 21: 80,                          # Evening prime time
    22: 50, 23: 30,                                  # Late night tapering
}

# Activity level per hour (0-100) for weekends - firewall (perimeter)
# Mix of e-commerce web traffic (high) and enterprise traffic (low)
# Weighted ~60% e-commerce, ~40% enterprise since web is the main traffic source
HOUR_ACTIVITY_WEEKEND_FIREWALL = {
    0: 12, 1: 8, 2: 7, 3: 5, 4: 5, 5: 5, 6: 7,      # Night - minimal
    7: 13, 8: 20, 9: 30,                             # Morning ramp-up
    10: 45, 11: 55, 12: 55,                          # Late morning
    13: 60, 14: 65, 15: 65,                          # Afternoon
    16: 70, 17: 70, 18: 70,                          # Evening peak
    19: 65, 20: 60, 21: 50,                          # Prime time
    22: 35, 23: 20,                                  # Late night
}


def ensure_output_dirs():
    """Create output directories if they don't exist."""
    for dir_path in OUTPUT_DIRS.values():
        dir_path.mkdir(parents=True, exist_ok=True)


def get_output_path(category: str, filename: str) -> Path:
    """Get the full output path for a given category and filename.

    Supports nested subdirectories in filename, e.g.:
        get_output_path("cloud", "webex/webex_events.json")
        -> output/cloud/webex/webex_events.json
    """
    ensure_output_dirs()
    full_path = OUTPUT_DIRS.get(category, OUTPUT_BASE) / filename
    # Create subdirectory if filename contains nested path
    full_path.parent.mkdir(parents=True, exist_ok=True)
    return full_path


def set_output_base(base_path: Path):
    """
    Redirect all generator output to a different base directory.

    Called by main_generate.py to switch between test mode (output/tmp/)
    and production mode (output/). Must be called BEFORE any generator
    calls get_output_path().

    All generators use get_output_path() which reads OUTPUT_BASE/OUTPUT_DIRS,
    so changing these globals redirects ALL output without modifying generators.
    """
    global OUTPUT_BASE, OUTPUT_DIRS
    OUTPUT_BASE = base_path
    OUTPUT_DIRS = {
        "network": OUTPUT_BASE / "network",
        "cloud": OUTPUT_BASE / "cloud",
        "windows": OUTPUT_BASE / "windows",
        "linux": OUTPUT_BASE / "linux",
        "web": OUTPUT_BASE / "web",
        "retail": OUTPUT_BASE / "retail",
        "servicebus": OUTPUT_BASE / "servicebus",
        "itsm": OUTPUT_BASE / "itsm",
        "erp": OUTPUT_BASE / "erp",
    }


def move_output_to_production(quiet: bool = False) -> dict:
    """Move generated files from output/tmp/ to output/ for Splunk ingestion.

    Always generates to output/tmp/ first (safe staging area), then moves
    completed files atomically to output/ where Splunk's inputs.conf monitors.
    Uses shutil.move() which calls os.rename() on same filesystem (atomic on POSIX).

    Returns:
        dict with keys:
            moved   - list of relative paths successfully moved
            skipped - list of relative paths not found in staging
            errors  - list of error message strings
    """
    import shutil
    import os

    staging_base = OUTPUT_BASE_PRODUCTION / "tmp"
    production_base = OUTPUT_BASE_PRODUCTION

    # Build complete file list from GENERATOR_OUTPUT_FILES + order_registry.json
    all_files = []
    for files in GENERATOR_OUTPUT_FILES.values():
        all_files.extend(files)
    # order_registry.json is monitored by Splunk but not in GENERATOR_OUTPUT_FILES
    if "web/order_registry.json" not in all_files:
        all_files.append("web/order_registry.json")

    result = {"moved": [], "skipped": [], "errors": []}

    for rel_path in all_files:
        src = staging_base / rel_path
        dest = production_base / rel_path

        if not src.exists():
            result["skipped"].append(rel_path)
            continue

        try:
            os.makedirs(dest.parent, exist_ok=True)
            shutil.move(str(src), str(dest))
            result["moved"].append(rel_path)
        except Exception as e:
            result["errors"].append(f"{rel_path}: {e}")

    # Clean up empty subdirectories in staging (but keep staging_base itself)
    if staging_base.exists():
        for dirpath, dirnames, filenames in os.walk(str(staging_base), topdown=False):
            dirpath = Path(dirpath)
            if dirpath != staging_base and not any(dirpath.iterdir()):
                try:
                    dirpath.rmdir()
                except OSError:
                    pass

    return result


# =============================================================================
# CONFIG CLASS
# =============================================================================

@dataclass
class Config:
    """Configuration container for generators."""
    start_date: str = DEFAULT_START_DATE
    days: int = DEFAULT_DAYS
    scale: float = DEFAULT_SCALE
    demo_id_enabled: bool = True
    scenarios: str = "all"
