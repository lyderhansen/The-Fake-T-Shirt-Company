#!/usr/bin/env python3
"""
Configuration module for Splunk Log Generators.
Contains all shared constants and default settings.
"""

from datetime import date
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# =============================================================================
# DEFAULT SETTINGS
# =============================================================================

DEFAULT_START_DATE = "2026-01-01"
DEFAULT_DAYS = 14
DEFAULT_SCALE = 1.0

# Meraki health metrics interval (minutes between samples)
# Lower = more data, Higher = less data
# 5 min = ~137K events/day, 15 min = ~46K events/day, 30 min = ~23K events/day
DEFAULT_MERAKI_HEALTH_INTERVAL = 5

# =============================================================================
# OUTPUT CONFIGURATION
# =============================================================================

# Base output directory (relative to script location)
OUTPUT_BASE = Path(__file__).parent.parent / "output"

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
}

# Output filenames
FILE_CISCO_ASA = "cisco_asa.log"
FILE_AWS_CLOUDTRAIL = "aws_cloudtrail.json"
FILE_GCP_AUDIT = "gcp_audit.json"
FILE_ENTRAID_SIGNIN = "entraid_signin.json"
FILE_ENTRAID_AUDIT = "entraid_audit.json"
FILE_EXCHANGE = "exchange_message_trace.json"
FILE_ACCESS_LOG = "access_combined.log"
FILE_ORDERS = "orders.json"
FILE_MERAKI = "meraki.log"  # Deprecated - use individual files below
FILE_MERAKI_MX = "meraki_mx_appliance.json"  # Dashboard API JSON format
FILE_MERAKI_MR = "meraki_mr_wireless.json"   # Dashboard API JSON format
FILE_MERAKI_MS = "meraki_ms_switch.json"     # Dashboard API JSON format
FILE_MERAKI_MV = "meraki_mv_camera.json"     # Dashboard API JSON format
FILE_MERAKI_MT = "meraki_mt_sensor.json"     # Dashboard API JSON format
FILE_WEBEX = "webex_events.json"
FILE_WEBEX_TA_MEETINGUSAGE = "webex_meetingusage.json"  # TA format: cisco:webex:meetings:history:meetingusagehistory
FILE_WEBEX_TA_ATTENDEE = "webex_attendee.json"         # TA format: cisco:webex:meetings:history:meetingattendeehistory
# Webex REST API format (ta_cisco_webex_add_on_for_splunk)
FILE_WEBEX_API_MEETINGS = "webex_meetings.json"              # cisco:webex:meetings
FILE_WEBEX_API_ADMIN_AUDIT = "webex_admin_audit.json"        # cisco:webex:admin:audit:events
FILE_WEBEX_API_SECURITY_AUDIT = "webex_security_audit.json"  # cisco:webex:security:audit:events
FILE_WEBEX_API_QUALITIES = "webex_meeting_qualities.json"    # cisco:webex:meeting:qualities
FILE_WEBEX_API_CALL_HISTORY = "webex_call_history.json"      # cisco:webex:call:detailed_history

# =============================================================================
# GENERATOR OUTPUT FILES MAPPING
# =============================================================================

# Generator name → list of output files (relative to output/)
# Used by main_generate.py --show-files to display actual file paths
GENERATOR_OUTPUT_FILES = {
    "asa": ["network/cisco_asa.log"],
    "aws": ["cloud/aws_cloudtrail.json"],
    "gcp": ["cloud/gcp_audit.json"],
    "entraid": ["cloud/entraid_signin.json", "cloud/entraid_audit.json"],
    "exchange": ["cloud/exchange_message_trace.json"],
    "access": ["web/access_combined.log"],
    "orders": ["retail/orders.json"],
    "servicebus": ["servicebus/servicebus_events.json"],
    "meraki": [
        "network/meraki_mx_appliance.json",
        "network/meraki_mr_wireless.json",
        "network/meraki_mr_health.json",
        "network/meraki_ms_switch.json",
        "network/meraki_ms_health.json",
        "network/meraki_mv_camera.json",
        "network/meraki_mt_sensor.json",
    ],
    "webex": ["cloud/webex_events.json"],
    "webex_ta": ["cloud/webex_ta_meetingusage.json", "cloud/webex_ta_attendee.json"],
    "webex_api": [
        "cloud/webex_api_meetings.json",
        "cloud/webex_api_admin_audit.json",
        "cloud/webex_api_security_audit.json",
        "cloud/webex_api_meeting_qualities.json",
        "cloud/webex_api_call_history.json",
    ],
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
    "linux": [
        "linux/vmstat.log",
        "linux/df.log",
        "linux/iostat.log",
        "linux/interfaces.log",
    ],
    "servicenow": ["itsm/servicenow_incidents.log"],
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
    12: 60,                                      # Lunch dip
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
    """Get the full output path for a given category and filename."""
    ensure_output_dirs()
    return OUTPUT_DIRS.get(category, OUTPUT_BASE) / filename


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
    output_base: Optional[Path] = None

    def __post_init__(self):
        if self.output_base is None:
            self.output_base = OUTPUT_BASE
