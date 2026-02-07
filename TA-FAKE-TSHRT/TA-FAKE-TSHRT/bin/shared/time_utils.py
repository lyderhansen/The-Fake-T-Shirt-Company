#!/usr/bin/env python3
"""
Time utilities for log generation.
Handles timestamps, date calculations, and volume multipliers.
"""

from datetime import datetime, timedelta
from typing import Optional
import hashlib

from .config import (
    DEFAULT_START_DATE,
    VOLUME_WEEKEND_FACTORS,
    VOLUME_MONDAY_BOOST,
    VOLUME_DAILY_NOISE_MIN,
    VOLUME_DAILY_NOISE_MAX,
    HOUR_ACTIVITY_WEEKDAY,
    HOUR_ACTIVITY_WEEKEND,
    HOUR_ACTIVITY_WEEKEND_ECOMMERCE,
    HOUR_ACTIVITY_WEEKEND_FIREWALL,
)


# =============================================================================
# DATE UTILITIES
# =============================================================================

def parse_date(date_str: str) -> datetime:
    """Parse a date string (YYYY-MM-DD) to datetime."""
    return datetime.strptime(date_str, "%Y-%m-%d")


def date_add(base_date: str, days: int) -> datetime:
    """Add days to a base date."""
    return parse_date(base_date) + timedelta(days=days)


def is_weekend(dt: datetime) -> bool:
    """Check if a datetime is on a weekend (Saturday=5, Sunday=6)."""
    return dt.weekday() >= 5


def day_of_week(dt: datetime) -> int:
    """Get day of week (0=Monday, 6=Sunday) - Python standard."""
    return dt.weekday()


# =============================================================================
# TIMESTAMP FORMATTERS
# =============================================================================

def ts_syslog(base_date: str, day: int, hour: int, minute: int, second: int,
              ms: Optional[int] = None) -> str:
    """
    Generate Cisco ASA syslog timestamp format: "Jan 05 2026 14:30:45.123"
    Includes year and milliseconds for more realistic ASA logs.
    """
    import random
    if ms is None:
        ms = random.randint(0, 999)
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%b %d %Y %H:%M:%S')}.{ms:03d}"


def ts_iso(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """
    Generate ISO 8601 timestamp: "2026-01-01T14:30:45Z"
    Used by AWS CloudTrail and similar services.
    """
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def ts_iso_ms(base_date: str, day: int, hour: int, minute: int, second: int,
              ms: Optional[int] = None) -> str:
    """
    Generate ISO 8601 timestamp with milliseconds: "2026-01-01T14:30:45.123Z"
    """
    import random
    if ms is None:
        ms = random.randint(0, 999)
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ms:03d}Z"


def ts_gcp(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """
    Generate GCP audit timestamp with microseconds: "2026-01-01T14:30:45.123456Z"
    """
    import random
    us = random.randint(0, 999999)
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{us:06d}Z"


def ts_perfmon(base_date: str, day: int, hour: int, minute: int, second: int,
               ms: Optional[int] = None) -> str:
    """
    Generate Windows Perfmon timestamp: "01/01/2026 14:30:45.123"
    """
    import random
    if ms is None:
        ms = random.randint(0, 999)
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%m/%d/%Y %H:%M:%S')}.{ms:03d}"


def ts_winevent(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """
    Generate Windows Event Log timestamp: "01/01/2026 14:30:45 PM"
    """
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%m/%d/%Y %I:%M:%S %p")


def ts_linux(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """
    Generate Linux metrics timestamp: "2026-01-01 14:30:45"
    """
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ts_exchange(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """
    Generate Exchange message tracking timestamp: "2026-01-01T14:30:45.1234567Z"
    """
    import random
    ticks = random.randint(1000000, 9999999)
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{ticks}Z"


# =============================================================================
# VOLUME MULTIPLIER FUNCTIONS
# =============================================================================

def get_hour_activity_level(hour: int, is_weekend: bool = False,
                            source_type: str = "default") -> int:
    """
    Get activity level (0-100) for a given hour.

    For most sources, weekend hours have much lower activity.
    For e-commerce (web), weekends have high activity with different pattern
    (later start, evening peak).
    For firewall, weekends have moderate activity (mix of web and enterprise).

    Args:
        hour: Hour of day (0-23)
        is_weekend: Whether this is a weekend day
        source_type: Type of log source ("web" uses e-commerce pattern)
    """
    if is_weekend:
        # E-commerce has different weekend pattern (shopping peaks in evening)
        if source_type == "web":
            return HOUR_ACTIVITY_WEEKEND_ECOMMERCE.get(hour, 15)
        # Firewall has mix of e-commerce and enterprise traffic
        if source_type == "firewall":
            return HOUR_ACTIVITY_WEEKEND_FIREWALL.get(hour, 20)
        return HOUR_ACTIVITY_WEEKEND.get(hour, 5)
    return HOUR_ACTIVITY_WEEKDAY.get(hour, 10)


def get_weekday_multiplier(day_of_week: int, source_type: str = "default") -> int:
    """
    Get multiplier based on day of week.

    Args:
        day_of_week: 0=Monday, 6=Sunday (Python standard)
        source_type: cloud, auth, firewall, email, web, windows

    Returns:
        Multiplier as percentage (e.g., 100 = normal, 40 = 40% of normal)
    """
    weekend_factor = VOLUME_WEEKEND_FACTORS.get(source_type,
                                                  VOLUME_WEEKEND_FACTORS["default"])

    if day_of_week == 0:  # Monday
        return VOLUME_MONDAY_BOOST
    elif day_of_week >= 5:  # Saturday or Sunday
        return weekend_factor
    else:  # Tuesday-Friday
        return 100


def get_daily_noise(base_date: str, day: int) -> int:
    """
    Get deterministic daily noise based on date.
    Returns a value between VOLUME_DAILY_NOISE_MIN and VOLUME_DAILY_NOISE_MAX.
    Uses hash for reproducibility.
    """
    dt = date_add(base_date, day)
    date_str = dt.strftime("%Y%m%d")

    # Create deterministic hash
    hash_val = int(hashlib.md5(date_str.encode()).hexdigest()[:8], 16)

    # Map to noise range
    noise_range = VOLUME_DAILY_NOISE_MAX - VOLUME_DAILY_NOISE_MIN + 1
    noise = (hash_val % noise_range) + VOLUME_DAILY_NOISE_MIN

    return noise


def get_volume_multiplier(base_date: str, day: int, hour: int,
                          source_type: str = "default") -> int:
    """
    Calculate volume multiplier for a specific hour.

    Combines:
    - Time-of-day variation (business hours peak, e-commerce weekend pattern)
    - Weekend reduction/boost (configurable per source type)
    - Monday spike (post-weekend catch-up)
    - Day-to-day random noise (±15%)

    Args:
        base_date: Start date string (YYYY-MM-DD)
        day: Day offset from base_date
        hour: Hour of day (0-23)
        source_type: Type of log source for weekend factor

    Returns:
        Multiplier as percentage (e.g., 85 = 85% of base volume)
    """
    dt = date_add(base_date, day)
    is_wknd = is_weekend(dt)
    dow = day_of_week(dt)

    # 1. Hour-based activity level (0-100)
    # Pass source_type to get correct weekend pattern (e-commerce vs enterprise)
    hour_mult = get_hour_activity_level(hour, is_wknd, source_type)

    # 2. Weekday multiplier (weekend reduction/boost, Monday boost)
    weekday_mult = get_weekday_multiplier(dow, source_type)

    # 3. Daily noise (±15%)
    daily_noise = get_daily_noise(base_date, day)
    noise_mult = 100 + daily_noise

    # Combine all factors
    combined = (hour_mult * weekday_mult * noise_mult) // 10000

    # Ensure minimum of 1% to avoid zero events
    return max(1, combined)


def calc_natural_events(base_events: int, base_date: str, day: int, hour: int,
                        source_type: str = "default") -> int:
    """
    Calculate actual event count for an hour based on natural volume variation.

    Args:
        base_events: Base events per peak hour (10 AM weekday = 100%)
        base_date: Start date string
        day: Day offset
        hour: Hour of day
        source_type: Type of log source

    Returns:
        Adjusted event count for this specific hour
    """
    mult = get_volume_multiplier(base_date, day, hour, source_type)
    events = (base_events * mult) // 100

    # Ensure at least 1 event if base > 0
    if base_events > 0 and events < 1:
        events = 1

    return events


# =============================================================================
# ATTACK TIMELINE HELPERS
# =============================================================================

# Attack phases (relative to start date, 0-indexed days)
PHASE_RECON_START = 0
PHASE_RECON_END = 2
PHASE_INITIAL_ACCESS = 4
PHASE_LATERAL_START = 5
PHASE_LATERAL_END = 7
PHASE_PERSISTENCE_START = 8
PHASE_PERSISTENCE_END = 10
PHASE_EXFIL_START = 11
PHASE_EXFIL_END = 13


def get_phase(day: int) -> str:
    """Get the attack phase name for a given day."""
    if PHASE_EXFIL_START <= day <= PHASE_EXFIL_END:
        return "exfil"
    elif PHASE_PERSISTENCE_START <= day <= PHASE_PERSISTENCE_END:
        return "persistence"
    elif PHASE_LATERAL_START <= day <= PHASE_LATERAL_END:
        return "lateral"
    elif day == PHASE_INITIAL_ACCESS:
        return "initial_access"
    elif PHASE_RECON_START <= day <= PHASE_RECON_END:
        return "recon"
    else:
        return "baseline"


def is_phase(phase: str, day: int) -> bool:
    """Check if a day is in a specific attack phase."""
    return get_phase(day) == phase


# =============================================================================
# TIME UTILS CLASS
# =============================================================================

class TimeUtils:
    """
    TimeUtils class that wraps timestamp functions with a fixed base date.
    Used by scenario classes for generating timestamps.
    """

    def __init__(self, base_date: str = DEFAULT_START_DATE):
        self.base_date = base_date

    def ts_syslog(self, day: int, hour: int, minute: int, second: int, ms: int = None) -> str:
        """Generate syslog timestamp with optional milliseconds."""
        return ts_syslog(self.base_date, day, hour, minute, second, ms)

    def ts_iso(self, day: int, hour: int, minute: int, second: int) -> str:
        """Generate ISO 8601 timestamp."""
        return ts_iso(self.base_date, day, hour, minute, second)

    def ts_iso_ms(self, day: int, hour: int, minute: int, second: int, ms: int = None) -> str:
        """Generate ISO 8601 timestamp with milliseconds."""
        return ts_iso_ms(self.base_date, day, hour, minute, second, ms)

    def ts_gcp(self, day: int, hour: int, minute: int, second: int) -> str:
        """Generate GCP audit timestamp."""
        return ts_gcp(self.base_date, day, hour, minute, second)

    def ts_perfmon(self, day: int, hour: int, minute: int, second: int, ms: int = None) -> str:
        """Generate Windows Perfmon timestamp."""
        return ts_perfmon(self.base_date, day, hour, minute, second, ms)

    def ts_winevent(self, day: int, hour: int, minute: int, second: int) -> str:
        """Generate Windows Event Log timestamp."""
        return ts_winevent(self.base_date, day, hour, minute, second)

    def ts_linux(self, day: int, hour: int, minute: int, second: int) -> str:
        """Generate Linux metrics timestamp."""
        return ts_linux(self.base_date, day, hour, minute, second)

    def ts_exchange(self, day: int, hour: int, minute: int, second: int) -> str:
        """Generate Exchange message tracking timestamp."""
        return ts_exchange(self.base_date, day, hour, minute, second)


if __name__ == "__main__":
    # Test the functions
    print("Testing time_utils.py")
    print("=" * 50)

    base = "2026-01-01"

    print(f"\nTimestamp formats for {base}, day=0, 14:30:45:")
    print(f"  Syslog:   {ts_syslog(base, 0, 14, 30, 45, 123)}")
    print(f"  ISO:      {ts_iso(base, 0, 14, 30, 45)}")
    print(f"  ISO+ms:   {ts_iso_ms(base, 0, 14, 30, 45)}")
    print(f"  GCP:      {ts_gcp(base, 0, 14, 30, 45)}")
    print(f"  Perfmon:  {ts_perfmon(base, 0, 14, 30, 45)}")
    print(f"  WinEvent: {ts_winevent(base, 0, 14, 30, 45)}")
    print(f"  Linux:    {ts_linux(base, 0, 14, 30, 45)}")
    print(f"  Exchange: {ts_exchange(base, 0, 14, 30, 45)}")

    print(f"\nVolume multipliers (base=100 events, firewall):")
    for day in range(7):
        dt = date_add(base, day)
        weekday_name = dt.strftime("%A")
        mult_10am = get_volume_multiplier(base, day, 10, "firewall")
        mult_3am = get_volume_multiplier(base, day, 3, "firewall")
        print(f"  Day {day} ({weekday_name[:3]}): 10AM={mult_10am:3d}%, 3AM={mult_3am:3d}%")

    print(f"\ncalc_natural_events (base=100, firewall):")
    print(f"  Thu 10AM: {calc_natural_events(100, base, 0, 10, 'firewall')} events")
    print(f"  Sat 10AM: {calc_natural_events(100, base, 2, 10, 'firewall')} events")
    print(f"  Mon 10AM: {calc_natural_events(100, base, 4, 10, 'firewall')} events")
