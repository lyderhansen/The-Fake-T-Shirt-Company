#!/usr/bin/env python3
"""
Cisco Webex Meetings TA-Compatible Log Generator.
Generates JSON events matching the Splunk TA for Cisco Webex Meetings format.

Based on: https://github.com/splunk/ta-cisco-webex-meetings-add-on-for-splunk

Sourcetypes generated:
  - cisco:webex:meetings:history:meetingusagehistory (1 record per meeting)
  - cisco:webex:meetings:history:meetingattendeehistory (1 record per attendee)

Timestamp format: MM/DD/YYYY HH:MM:SS
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add, get_hour_activity_level, is_weekend
from shared.company import (
    USERS, get_random_user, LOCATIONS, get_users_by_location, NETWORK_CONFIG,
    TENANT,
)
from shared.meeting_schedule import _meeting_schedule
from scenarios.registry import expand_scenarios

# =============================================================================
# TA FORMAT CONSTANTS
# =============================================================================

WEBEX_SITE_URL = "theFakeTshirtCompany.webex.com"

# Meeting types (MC = Meeting Center)
MEETING_TYPES = ["MC", "TC", "EC", "SC"]  # Meeting, Training, Event, Support

# Client types for attendees
CLIENT_TYPES = [
    "Webex Desktop",
    "Webex Mobile (iOS)",
    "Webex Mobile (Android)",
    "Web Browser",
    "Cisco Room Device",
    "Phone (PSTN)",
]

CLIENT_OS = [
    "Windows 10",
    "Windows 11",
    "macOS 13",
    "macOS 14",
    "iOS 17",
    "Android 14",
    "ChromeOS",
]

# Meeting templates for realistic names
MEETING_TEMPLATES = [
    {"name": "Team Standup", "duration": (15, 20), "participants": (3, 8)},
    {"name": "Project Review", "duration": (45, 60), "participants": (4, 12)},
    {"name": "Sprint Planning", "duration": (90, 120), "participants": (5, 15)},
    {"name": "1:1 Meeting", "duration": (25, 30), "participants": (2, 2)},
    {"name": "All Hands", "duration": (55, 60), "participants": (15, 40)},
    {"name": "Training Session", "duration": (60, 90), "participants": (6, 16)},
    {"name": "Client Call", "duration": (30, 45), "participants": (2, 6)},
    {"name": "Budget Review", "duration": (45, 60), "participants": (3, 8)},
    {"name": "Design Review", "duration": (40, 50), "participants": (3, 10)},
    {"name": "Interview", "duration": (45, 60), "participants": (2, 5)},
    {"name": "Vendor Meeting", "duration": (45, 60), "participants": (3, 8)},
    {"name": "Board Meeting", "duration": (90, 120), "participants": (6, 15)},
    {"name": "Executive Sync", "duration": (25, 30), "participants": (2, 6)},
    {"name": "Tech Deep Dive", "duration": (60, 90), "participants": (3, 8)},
    {"name": "Sales Pipeline", "duration": (45, 60), "participants": (4, 10)},
    {"name": "Weekly Status", "duration": (25, 30), "participants": (5, 12)},
    {"name": "Quarterly Review", "duration": (60, 90), "participants": (8, 20)},
    {"name": "Product Demo", "duration": (30, 45), "participants": (3, 8)},
]

# External domains for external attendees
EXTERNAL_DOMAINS = [
    "clientcorp.com",
    "partnertech.io",
    "vendor-systems.com",
    "consultant-group.net",
    "enterprise-solutions.com",
]

# Scenario-related users for demo_id tagging
EXFIL_USERS = {"jessica.brown", "alex.miller"}


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class MeetingRecord:
    """Represents a single meeting with all data needed for TA records."""
    conf_id: str
    meeting_key: str
    conf_name: str
    host_name: str
    host_email: str
    host_webex_id: str
    start_time: datetime
    end_time: datetime
    location: str
    meeting_type: str = "MC"
    attendees: List[Dict] = field(default_factory=list)
    demo_id: Optional[str] = None

    @property
    def duration_mins(self) -> int:
        return int((self.end_time - self.start_time).total_seconds() / 60)

    @property
    def total_participants(self) -> int:
        return len(self.attendees) + 1  # +1 for host

    @property
    def peak_attendee(self) -> int:
        # Simulate peak (usually same or slightly less than total)
        return max(1, self.total_participants - random.randint(0, 2))


@dataclass
class AttendeeRecord:
    """Represents a single attendee in a meeting."""
    name: str
    email: str
    join_time: datetime
    leave_time: datetime
    ip_address: str
    client_type: str
    client_os: str
    is_external: bool = False
    is_host: bool = False


# =============================================================================
# TIMESTAMP UTILITIES
# =============================================================================

def ts_webex_ta(dt: datetime) -> str:
    """Format timestamp for Webex TA: MM/DD/YYYY HH:MM:SS"""
    return dt.strftime("%m/%d/%Y %H:%M:%S")


def generate_conf_id() -> str:
    """Generate a Webex conference ID."""
    return str(random.randint(100000000, 999999999))


def generate_meeting_key() -> str:
    """Generate a Webex meeting key."""
    return str(random.randint(100000000, 999999999))


def get_user_ip(location: str) -> str:
    """Get a random internal IP for a location."""
    prefix = NETWORK_CONFIG.get(location, {}).get("prefix", "10.10")
    return f"{prefix}.30.{random.randint(10, 250)}"


# =============================================================================
# RECORD GENERATION FUNCTIONS
# =============================================================================

def create_meeting_usage_record(meeting: MeetingRecord) -> dict:
    """Generate meeting usage history record (TA format).

    Sourcetype: cisco:webex:meetings:history:meetingusagehistory
    """
    # Calculate telephony/VoIP splits
    total_people_mins = meeting.duration_mins * meeting.total_participants
    voip_pct = random.uniform(0.7, 0.95)
    telephony_pct = 1 - voip_pct

    voip_mins = int(total_people_mins * voip_pct)
    telephony_mins = total_people_mins - voip_mins

    # Count call types
    call_in_toll = random.randint(0, 3)
    call_in_tollfree = random.randint(0, 2)
    call_out_domestic = random.randint(0, 1)
    call_out_intl = 0

    record = {
        "confID": meeting.conf_id,
        "confName": meeting.conf_name,
        "meetingKey": meeting.meeting_key,
        "hostName": meeting.host_name,
        "hostEmail": meeting.host_email,
        "hostWebExID": meeting.host_webex_id,
        "meetingStartTime": ts_webex_ta(meeting.start_time),
        "meetingEndTime": ts_webex_ta(meeting.end_time),
        "duration": str(meeting.duration_mins),
        "totalParticipants": str(meeting.total_participants),
        "peakAttendee": str(meeting.peak_attendee),
        "totalPeopleMinutes": str(total_people_mins),
        "totalVoipMinutes": str(voip_mins),
        "totalTelephonyMinutes": str(telephony_mins),
        "totalCallInTollfree": str(call_in_tollfree),
        "totalCallInToll": str(call_in_toll),
        "totalCallOutDomestic": str(call_out_domestic),
        "totalCallOutInternational": str(call_out_intl),
        "meetingType": meeting.meeting_type,
        "timeZoneID": "4",  # Eastern Time
        "siteUrl": WEBEX_SITE_URL,
    }

    if meeting.demo_id:
        record["demo_id"] = meeting.demo_id

    return record


def create_attendee_record(
    meeting: MeetingRecord,
    attendee: AttendeeRecord,
) -> dict:
    """Generate attendee history record (TA format).

    Sourcetype: cisco:webex:meetings:history:meetingattendeehistory
    """
    duration_mins = int((attendee.leave_time - attendee.join_time).total_seconds() / 60)

    # Determine participant type
    if attendee.is_host:
        participant_type = "HOST"
    elif attendee.is_external:
        participant_type = "GUEST"
    else:
        participant_type = "ATTENDEE"

    record = {
        "confID": meeting.conf_id,
        "confName": meeting.conf_name,
        "meetingKey": meeting.meeting_key,
        "attendeeName": attendee.name,
        "attendeeEmail": attendee.email,
        "joinTime": ts_webex_ta(attendee.join_time),
        "leaveTime": ts_webex_ta(attendee.leave_time),
        "duration": str(duration_mins),
        "ipAddress": attendee.ip_address,
        "clientType": attendee.client_type,
        "clientOS": attendee.client_os,
        "participantType": participant_type,
        "voipDuration": str(duration_mins) if "Phone" not in attendee.client_type else "0",
        "hostName": meeting.host_name,
        "hostEmail": meeting.host_email,
        "siteUrl": WEBEX_SITE_URL,
    }

    if meeting.demo_id:
        record["demo_id"] = meeting.demo_id

    return record


# =============================================================================
# MEETING SIMULATION
# =============================================================================

def _lookup_user_by_email(email: str):
    """Look up a User object by email address. Returns None if not found."""
    username = email.split("@")[0] if "@" in email else email
    return USERS.get(username)


def _convert_scheduled_meeting(scheduled_meeting, active_scenarios: List[str], day: int) -> Optional[MeetingRecord]:
    """Convert a ScheduledMeeting from the shared schedule to a MeetingRecord.

    This ensures webex_ta records match the same meetings that appear in
    webex device events, Exchange calendar invites, and Meraki sensor data.
    """
    # Skip ghost meetings (no-shows don't produce TA records)
    if scheduled_meeting.is_ghost:
        return None
    # Skip walk-ins (no Webex booking)
    if scheduled_meeting.is_walkin:
        return None

    # Determine host info
    host_email = scheduled_meeting.organizer_email
    host_name = scheduled_meeting.organizer_name
    host_username = host_email.split("@")[0] if "@" in host_email else ""

    # Determine demo_id
    demo_id = None
    if "exfil" in active_scenarios and day <= 13:
        if host_username in EXFIL_USERS:
            demo_id = "exfil"

    # Build attendee records from the shared participant list
    attendees = []
    location = scheduled_meeting.location_code

    # Host as first attendee
    host_join = scheduled_meeting.start_time - timedelta(minutes=random.randint(1, 5))
    host_leave = scheduled_meeting.end_time + timedelta(minutes=random.randint(0, 2))
    attendees.append(AttendeeRecord(
        name=host_name,
        email=host_email,
        join_time=host_join,
        leave_time=host_leave,
        ip_address=get_user_ip(location),
        client_type=random.choice(CLIENT_TYPES[:4]),
        client_os=random.choice(CLIENT_OS[:4]),
        is_external=False,
        is_host=True,
    ))

    # Other participants from the shared schedule
    for p_email in scheduled_meeting.participants:
        if p_email == host_email:
            continue  # Skip host (already added)

        user = _lookup_user_by_email(p_email)
        is_external = user is None or f"@{TENANT}" not in p_email

        if user:
            name = user.display_name
            ip_address = get_user_ip(user.location)
        else:
            # External participant
            name = p_email.split("@")[0].replace(".", " ").title()
            ip_address = f"{random.randint(50, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

        # Join/leave with realistic variance
        join_offset = random.choice([
            timedelta(seconds=random.randint(-60, 60)),
            timedelta(seconds=random.randint(-60, 60)),
            timedelta(minutes=random.randint(1, 5)),
            timedelta(minutes=random.randint(-3, 0)),
        ])
        leave_offset = random.choice([
            timedelta(seconds=random.randint(-30, 30)),
            timedelta(seconds=random.randint(-30, 30)),
            timedelta(minutes=random.randint(-10, -1)),
            timedelta(minutes=random.randint(0, 2)),
        ])
        join_time = scheduled_meeting.start_time + join_offset
        leave_time = scheduled_meeting.end_time + leave_offset
        if join_time > leave_time:
            join_time = scheduled_meeting.start_time
            leave_time = scheduled_meeting.end_time

        attendees.append(AttendeeRecord(
            name=name,
            email=p_email,
            join_time=join_time,
            leave_time=leave_time,
            ip_address=ip_address,
            client_type=random.choice(CLIENT_TYPES),
            client_os=random.choice(CLIENT_OS),
            is_external=is_external,
            is_host=False,
        ))

    return MeetingRecord(
        conf_id=generate_conf_id(),
        meeting_key=generate_meeting_key(),
        conf_name=scheduled_meeting.meeting_title,
        host_name=host_name,
        host_email=host_email,
        host_webex_id=host_username,
        start_time=scheduled_meeting.start_time,
        end_time=scheduled_meeting.end_time,
        location=location,
        meeting_type=random.choice(MEETING_TYPES),
        attendees=attendees,
        demo_id=demo_id,
    )


def _get_scheduled_meetings_for_day(day: int, location: str) -> list:
    """Get all meetings for a specific day and location from the shared schedule."""
    meetings = []
    for key, scheduled_list in _meeting_schedule.items():
        loc_code, room = key.split(":", 1)
        if loc_code != location:
            continue
        for m in scheduled_list:
            # Check if meeting is on the right day by comparing dates
            if m.start_time.day == (day + 1) or m.start_time.timetuple().tm_yday == day + 1:
                # More robust: compare the actual date
                pass
            meetings.append(m)
    return meetings


def generate_meetings_for_day(
    base_date: str,
    day: int,
    location: str,
    scale: float,
    active_scenarios: List[str],
) -> List[MeetingRecord]:
    """Generate all meetings for a single day at a location.

    If the shared meeting schedule is populated (by generate_webex.py in Phase 1),
    reads from it to produce correlated records. Otherwise falls back to
    independent generation for standalone use.
    """
    meetings = []
    dt = date_add(base_date, day)

    # Try shared schedule first (populated by generate_webex.py)
    if _meeting_schedule:
        target_date = dt.date() if hasattr(dt, 'date') else dt
        for key, scheduled_list in _meeting_schedule.items():
            loc_code = key.split(":", 1)[0]
            if loc_code != location:
                continue
            for scheduled in scheduled_list:
                meeting_date = scheduled.start_time.date() if hasattr(scheduled.start_time, 'date') else scheduled.start_time
                if meeting_date == target_date:
                    meeting = _convert_scheduled_meeting(scheduled, active_scenarios, day)
                    if meeting:
                        meetings.append(meeting)
        return meetings

    # Fallback: independent generation (when running standalone without webex)
    is_wknd = is_weekend(dt)
    location_users = get_users_by_location(location)
    if not location_users:
        return meetings

    if is_wknd:
        base_meetings = random.randint(3, 6)
    else:
        base_meetings = random.randint(9, 17)

    num_meetings = int(base_meetings * scale)

    for _ in range(num_meetings):
        meeting = generate_single_meeting(
            dt, location, location_users, active_scenarios, day
        )
        if meeting:
            meetings.append(meeting)

    return meetings


def generate_single_meeting(
    base_dt: datetime,
    location: str,
    location_users: list,
    active_scenarios: List[str],
    day: int,
) -> Optional[MeetingRecord]:
    """Generate a single meeting with attendees."""
    # Pick meeting template
    template = random.choice(MEETING_TEMPLATES)

    # Random start hour during business hours
    hour = random.randint(8, 17)
    minute = random.choice([0, 15, 30, 45])

    start_time = base_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)

    # Duration from template
    duration_mins = random.randint(template["duration"][0], template["duration"][1])
    end_time = start_time + timedelta(minutes=duration_mins)

    # Don't let meetings run past 7 PM
    if end_time.hour >= 19:
        end_time = end_time.replace(hour=18, minute=30)
        duration_mins = int((end_time - start_time).total_seconds() / 60)

    if duration_mins < 5:
        return None

    # Pick host
    host = random.choice(location_users)

    # Determine demo_id
    demo_id = None
    if "exfil" in active_scenarios and day <= 13:
        if host.username in EXFIL_USERS:
            demo_id = "exfil"

    # Generate attendees
    num_attendees = random.randint(template["participants"][0], template["participants"][1])
    attendees = generate_attendees(
        start_time, end_time, location, location_users, host, num_attendees
    )

    meeting = MeetingRecord(
        conf_id=generate_conf_id(),
        meeting_key=generate_meeting_key(),
        conf_name=template["name"],
        host_name=host.display_name,
        host_email=f"{host.username}@{TENANT}",
        host_webex_id=host.username,
        start_time=start_time,
        end_time=end_time,
        location=location,
        meeting_type=random.choice(MEETING_TYPES),
        attendees=attendees,
        demo_id=demo_id,
    )

    return meeting


def generate_attendees(
    meeting_start: datetime,
    meeting_end: datetime,
    location: str,
    location_users: list,
    host,
    num_attendees: int,
) -> List[AttendeeRecord]:
    """Generate attendee records for a meeting."""
    attendees = []

    # Host joins first
    host_join = meeting_start - timedelta(minutes=random.randint(1, 5))
    host_leave = meeting_end + timedelta(minutes=random.randint(0, 2))

    attendees.append(AttendeeRecord(
        name=host.display_name,
        email=f"{host.username}@{TENANT}",
        join_time=host_join,
        leave_time=host_leave,
        ip_address=get_user_ip(location),
        client_type=random.choice(CLIENT_TYPES[:4]),  # Desktop/web for host
        client_os=random.choice(CLIENT_OS[:4]),
        is_external=False,
        is_host=True,
    ))

    # Other attendees
    used_users = {host.username}
    for i in range(min(num_attendees - 1, len(location_users) - 1)):
        # Pick an attendee
        available_users = [u for u in location_users if u.username not in used_users]
        if not available_users:
            break

        attendee = random.choice(available_users)
        used_users.add(attendee.username)

        # External attendees (10% chance)
        is_external = random.random() < 0.10

        if is_external:
            domain = random.choice(EXTERNAL_DOMAINS)
            first_name = random.choice(["Chris", "Alex", "Sam", "Jordan", "Taylor"])
            last_name = random.choice(["Smith", "Johnson", "Williams", "Brown", "Jones"])
            email = f"{first_name.lower()}.{last_name.lower()}@{domain}"
            name = f"{first_name} {last_name}"
            ip_address = f"{random.randint(50, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            name = attendee.display_name
            email = f"{attendee.username}@{TENANT}"
            ip_address = get_user_ip(location)

        # Join time (most join on time or slightly late)
        join_offset = random.choice([
            timedelta(seconds=random.randint(-60, 60)),  # On time
            timedelta(seconds=random.randint(-60, 60)),  # On time
            timedelta(minutes=random.randint(1, 5)),     # Late
            timedelta(minutes=random.randint(-3, 0)),    # Early
        ])
        join_time = meeting_start + join_offset

        # Leave time (most stay until end)
        leave_offset = random.choice([
            timedelta(seconds=random.randint(-30, 30)),  # On time
            timedelta(seconds=random.randint(-30, 30)),  # On time
            timedelta(minutes=random.randint(-10, -1)),  # Early
            timedelta(minutes=random.randint(0, 2)),     # Stay late
        ])
        leave_time = meeting_end + leave_offset

        # Ensure valid times
        if join_time > leave_time:
            join_time = meeting_start
            leave_time = meeting_end

        attendees.append(AttendeeRecord(
            name=name,
            email=email,
            join_time=join_time,
            leave_time=leave_time,
            ip_address=ip_address,
            client_type=random.choice(CLIENT_TYPES),
            client_os=random.choice(CLIENT_OS),
            is_external=is_external,
            is_host=False,
        ))

    return attendees


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_webex_ta_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Webex TA-compatible logs.

    Generates two output files:
    - webex_ta_meetingusage.json (cisco:webex:meetings:history:meetingusagehistory)
    - webex_ta_attendee.json (cisco:webex:meetings:history:meetingattendeehistory)
    """

    # Output paths
    if output_file:
        output_dir = Path(output_file).parent
    else:
        output_dir = get_output_path("cloud", "webex/dummy.json").parent
    output_dir.mkdir(parents=True, exist_ok=True)

    meetingusage_file = output_dir / "webex_ta_meetingusage.json"
    attendee_file = output_dir / "webex_ta_attendee.json"

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Location weights
    location_weights = {
        "BOS": 1.0,
        "ATL": 0.5,
        "AUS": 0.4,
    }

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Webex Meetings TA Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_dir}/webex_ta_*.json", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Collect all records
    meeting_usage_records = []
    attendee_records = []

    for day in range(days):
        dt = date_add(start_date, day)

        if not quiet:
            print(f"  [Webex TA] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for location, loc_scale in location_weights.items():
            # Generate meetings for this day/location
            meetings = generate_meetings_for_day(
                start_date, day, location, scale * loc_scale, active_scenarios
            )

            for meeting in meetings:
                # Create meeting usage record
                meeting_usage_records.append(create_meeting_usage_record(meeting))

                # Create attendee records
                for attendee in meeting.attendees:
                    attendee_records.append(create_attendee_record(meeting, attendee))

        if not quiet:
            print(f"  [Webex TA] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort by timestamp
    meeting_usage_records.sort(key=lambda x: x["meetingStartTime"])
    attendee_records.sort(key=lambda x: x["joinTime"])

    # Write files
    with open(meetingusage_file, "w") as f:
        for record in meeting_usage_records:
            f.write(json.dumps(record) + "\n")

    with open(attendee_file, "w") as f:
        for record in attendee_records:
            f.write(json.dumps(record) + "\n")

    total_records = len(meeting_usage_records) + len(attendee_records)

    if not quiet:
        print(f"  [Webex TA] Complete! {total_records:,} records written:", file=sys.stderr)
        print(f"    - {meetingusage_file.name}: {len(meeting_usage_records):,} meeting records", file=sys.stderr)
        print(f"    - {attendee_file.name}: {len(attendee_records):,} attendee records", file=sys.stderr)

    return total_records


def main():
    parser = argparse.ArgumentParser(description="Generate Webex TA-compatible logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", "-o")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_webex_ta_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
