#!/usr/bin/env python3
"""
Template for creating new log generators.

INSTRUCTIONS:
1. Copy this file: cp _template_generator.py generate_<source>.py
2. Replace all instances of:
   - SOURCENAME with your source name (e.g., "paloalto", "crowdstrike")
   - CATEGORY with output category ("network", "cloud", "windows", "linux", "web", "retail", "itsm")
3. Implement generate_single_event() for your log format
4. Register in main_generate.py:
   - Import: from generators.generate_xxx import generate_xxx_logs
   - Add to GENERATORS dict
   - Add to appropriate SOURCE_GROUPS
5. Test: python3 generators/generate_xxx.py --days=1 --quiet
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import (
    ts_iso,           # "2026-01-05T14:30:45Z" - for JSON logs
    ts_iso_ms,        # "2026-01-05T14:30:45.123Z" - for JSON with milliseconds
    ts_syslog,        # "Jan 05 2026 14:30:45" - for syslog format
    ts_perfmon,       # "01/05/2026 14:30:45.123" - for Windows
    calc_natural_events,
    date_add,
)
from shared.company import (
    USERS,
    SERVERS,
    get_internal_ip,
    get_external_ip,
    get_dmz_ip,
    get_us_ip,
    TENANT,
)
from scenarios.registry import expand_scenarios


def generate_SOURCENAME_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate SOURCENAME logs.

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume multiplier (1.0 = normal)
        scenarios: Comma-separated scenario names or "none"/"all"
        output_file: Override output path (optional)
        quiet: Suppress progress output

    Returns:
        int: Number of events generated
    """
    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Determine output path
    if output_file:
        output_path = Path(output_file)
    else:
        # Change CATEGORY to: "network", "cloud", "windows", "linux", "web", "retail", "itsm"
        output_path = get_output_path("CATEGORY", "SOURCENAME.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Progress header
    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  SOURCENAME Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events: List[Any] = []
    demo_id_count = 0

    # Adjust base volume (events per peak hour)
    # Typical values: firewall=500, cloud=100, auth=50, web=200
    base_events_per_hour = int(100 * scale)

    # Initialize scenario instances (if applicable)
    # Example:
    # if "exfil" in active_scenarios:
    #     from scenarios.security.exfil import ExfilScenario
    #     exfil_scenario = ExfilScenario(config, company, time_utils)
    # else:
    #     exfil_scenario = None

    # Main generation loop
    for day in range(days):
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [SOURCENAME] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # Calculate natural volume variation
            # Categories: "firewall", "cloud", "auth", "web", "email"
            hour_count = calc_natural_events(
                base_events_per_hour, start_date, day, hour, "CATEGORY"
            )

            # Generate baseline events
            for _ in range(hour_count):
                event = generate_single_event(start_date, day, hour)
                all_events.append(event)

            # Add scenario events (if applicable)
            # Example:
            # if exfil_scenario:
            #     scenario_events = exfil_scenario.SOURCENAME_hour(day, hour)
            #     all_events.extend(scenario_events)
            #     demo_id_count += len(scenario_events)

    # Sort by timestamp
    # For dict events (JSON):
    all_events.sort(key=lambda x: x.get("timestamp", "") if isinstance(x, dict) else x)
    # For string events (syslog), they sort naturally if timestamp is at start

    # Write to file
    with open(output_path, "w") as f:
        for event in all_events:
            if isinstance(event, dict):
                # JSON lines format
                f.write(json.dumps(event) + "\n")
            else:
                # Plain text (syslog, etc.)
                f.write(event + "\n")

    # Final summary
    if not quiet:
        print(f"  [SOURCENAME] Complete! {len(all_events):,} events written",
              file=sys.stderr)
        if demo_id_count:
            print(f"          └─ demo_id events: {demo_id_count:,}", file=sys.stderr)

    return len(all_events)


def generate_single_event(start_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate a single event.

    Modify this function to match your log format.

    Args:
        start_date: Base date
        day: Day offset (0-indexed)
        hour: Hour (0-23)

    Returns:
        Event as dict (for JSON) or string (for syslog)
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)

    # Choose a random user for the event
    user = random.choice(USERS)

    # Example JSON event structure
    # Modify fields to match your source format
    event = {
        "timestamp": ts_iso(start_date, day, hour, minute, second),
        "source_ip": get_internal_ip(),
        "dest_ip": get_external_ip(),
        "user": user["username"],
        "action": random.choice(["login", "logout", "access", "modify"]),
        "status": random.choice(["success", "success", "success", "failure"]),
        # Add source-specific fields here
    }

    return event

    # Alternative: Syslog format (return string instead)
    # timestamp = ts_syslog(start_date, day, hour, minute, second)
    # return f"{timestamp} hostname program: message content src={src} dst={dst}"


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate SOURCENAME logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --days=7                    Generate 7 days of logs
  %(prog)s --days=14 --scenarios=exfil Generate with exfil scenario
  %(prog)s --scale=2.0                 Double the event volume
  %(prog)s --quiet                     Suppress progress output
        """
    )
    parser.add_argument(
        "--start-date",
        default=DEFAULT_START_DATE,
        help=f"Start date YYYY-MM-DD (default: {DEFAULT_START_DATE})"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"Number of days (default: {DEFAULT_DAYS})"
    )
    parser.add_argument(
        "--scale",
        type=float,
        default=DEFAULT_SCALE,
        help=f"Volume scale factor (default: {DEFAULT_SCALE})"
    )
    parser.add_argument(
        "--scenarios",
        default="none",
        help="Scenarios: none, exfil, all, or comma-separated list"
    )
    parser.add_argument(
        "--output",
        help="Output file path (overrides default)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )

    args = parser.parse_args()

    count = generate_SOURCENAME_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )

    # Print count to stdout (for scripting)
    print(count)


if __name__ == "__main__":
    main()
