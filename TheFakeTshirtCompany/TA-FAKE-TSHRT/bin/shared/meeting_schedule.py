#!/usr/bin/env python3
"""
Shared meeting schedule module for Webex/Meraki correlation.

This module maintains a global meeting schedule that:
1. Webex populates when generating meeting events
2. Meraki reads when generating door/camera sensor events

This ensures realistic correlation where:
- Door opens 2-5 minutes before meeting starts
- Temperature rises during meetings
- Door opens when people leave after meeting ends
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import hashlib
import random

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE
from shared.time_utils import date_add, is_weekend


@dataclass
class ScheduledMeeting:
    """Represents a scheduled meeting with timing information."""
    room: str                    # Room name (e.g., "Zelda")
    location_code: str           # BOS, ATL, AUS
    device_id: str               # WEBEX-BOS-2F-ZELDA
    start_time: datetime         # Actual meeting start time
    end_time: datetime           # Actual meeting end time
    scheduled_start: datetime    # Originally scheduled time
    participant_count: int       # Number of participants
    is_ghost: bool = False       # No-show meeting
    late_start_mins: int = 0     # How late it started
    meeting_title: str = ""      # Meeting title for logging
    is_walkin: bool = False      # Walk-in (no Webex booking)
    is_after_hours: bool = False # After-hours activity
    # New fields for Exchange calendar integration
    organizer_email: str = ""    # organizer@theFakeTshirtCompany.com
    organizer_name: str = ""     # "John Smith"
    participants: List[str] = field(default_factory=list)  # List of participant emails


@dataclass
class RecurringMeetingTemplate:
    """Template for a recurring meeting with fixed organizer and participants."""
    meeting_type: str           # Name matching MEETING_TYPES (or custom title)
    organizer_username: str     # Fixed organizer from company.py USERS
    room: str                   # Room name from MEETING_ROOMS (e.g., "Link", "Zelda")
    location: str               # BOS, ATL, AUS
    recurrence: str             # "daily", "weekly_mon", "biweekly", "monthly_1st_mon", etc.
    preferred_hour: int         # Start hour (24h)
    preferred_minute: int       # Start minute
    core_participants: List[str]  # Usernames always invited
    rotation_pool: List[str]    # Usernames randomly drawn per occurrence
    rotation_count: int         # How many from rotation_pool per occurrence
    cancellation_rate: float    # 0.0-0.10 probability of skip
    title_override: str = ""    # Custom title (else uses meeting_type)


# =============================================================================
# RECURRING MEETINGS REGISTRY (~25 fixed meetings across 3 sites + cross-site)
# =============================================================================

RECURRING_MEETINGS: List[RecurringMeetingTemplate] = [
    # -------------------------------------------------------------------------
    # Boston HQ (BOS) — 12 meetings
    # -------------------------------------------------------------------------
    RecurringMeetingTemplate(
        meeting_type="Executive Sync",
        organizer_username="john.smith",
        room="Link", location="BOS",
        recurrence="daily", preferred_hour=8, preferred_minute=30,
        core_participants=["sarah.wilson", "mike.johnson", "jennifer.davis",
                           "richard.chen", "margaret.taylor"],
        rotation_pool=["david.robinson", "claire.roberts", "olivia.moore"],
        rotation_count=1, cancellation_rate=0.05,
    ),
    RecurringMeetingTemplate(
        meeting_type="All Hands",
        organizer_username="john.smith",
        room="Link", location="BOS",
        recurrence="monthly_1st_mon", preferred_hour=10, preferred_minute=0,
        core_participants=["sarah.wilson", "mike.johnson", "jennifer.davis",
                           "richard.chen", "margaret.taylor", "david.robinson"],
        rotation_pool=["robert.wilson", "nicholas.lewis", "matthew.hall",
                        "olivia.moore", "christian.walker", "amelia.phillips",
                        "skylar.johnson", "harper.murphy", "brandon.turner"],
        rotation_count=6, cancellation_rate=0.02,
    ),
    RecurringMeetingTemplate(
        meeting_type="Board Meeting",
        organizer_username="john.smith",
        room="Link", location="BOS",
        recurrence="monthly_3rd_tue", preferred_hour=14, preferred_minute=0,
        core_participants=["sarah.wilson", "mike.johnson", "jennifer.davis",
                           "claire.roberts"],
        rotation_pool=["richard.chen", "margaret.taylor", "david.robinson"],
        rotation_count=2, cancellation_rate=0.02,
    ),
    RecurringMeetingTemplate(
        meeting_type="Budget Review",
        organizer_username="sarah.wilson",
        room="Zelda", location="BOS",
        recurrence="weekly_mon", preferred_hour=14, preferred_minute=0,
        core_participants=["robert.wilson", "alex.miller", "michael.lewis"],
        rotation_pool=["ella.white", "jennifer.davis"],
        rotation_count=1, cancellation_rate=0.05,
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="robert.wilson",
        room="Mario", location="BOS",
        recurrence="daily", preferred_hour=9, preferred_minute=0,
        core_participants=["alex.miller", "michael.lewis", "ella.white"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="Finance Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="nicholas.lewis",
        room="Luigi", location="BOS",
        recurrence="daily", preferred_hour=9, preferred_minute=30,
        core_participants=["amelia.phillips", "nathan.hall", "matthew.wood"],
        rotation_pool=["brandon.turner"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="Engineering Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Sprint Planning",
        organizer_username="nicholas.lewis",
        room="Sonic", location="BOS",
        recurrence="biweekly", preferred_hour=10, preferred_minute=0,
        core_participants=["amelia.phillips", "nathan.hall", "matthew.wood",
                           "brandon.turner", "richard.chen"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.03,
    ),
    RecurringMeetingTemplate(
        meeting_type="Sales Pipeline",
        organizer_username="matthew.hall",
        room="Zelda", location="BOS",
        recurrence="weekly_mon", preferred_hour=10, preferred_minute=0,
        core_participants=["harper.murphy", "ava.bell", "scott.morgan",
                           "derek.stone"],
        rotation_pool=["margaret.taylor"],
        rotation_count=1, cancellation_rate=0.05,
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="olivia.moore",
        room="Samus", location="BOS",
        recurrence="daily", preferred_hour=9, preferred_minute=15,
        core_participants=["skylar.johnson", "scarlett.nelson", "ryan.green"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="Marketing Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="david.robinson",
        room="Yoshi", location="BOS",
        recurrence="daily", preferred_hour=9, preferred_minute=0,
        core_participants=["christian.walker", "patrick.gonzalez",
                           "stephanie.barnes", "nicole.simmons"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="IT Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Tech Deep Dive",
        organizer_username="richard.chen",
        room="Sonic", location="BOS",
        recurrence="weekly_fri", preferred_hour=14, preferred_minute=0,
        core_participants=["nicholas.lewis", "matthew.wood"],
        rotation_pool=["amelia.phillips", "nathan.hall", "brandon.turner"],
        rotation_count=2, cancellation_rate=0.05,
    ),
    RecurringMeetingTemplate(
        meeting_type="1:1 Meeting",
        organizer_username="mike.johnson",
        room="Kirby", location="BOS",
        recurrence="weekly_tue", preferred_hour=11, preferred_minute=0,
        core_participants=["nicholas.lewis"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.08,
        title_override="1:1 CTO/Eng Mgr",
    ),
    # -------------------------------------------------------------------------
    # Atlanta Hub (ATL) — 6 meetings
    # -------------------------------------------------------------------------
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="jessica.brown",
        room="Kratos", location="ATL",
        recurrence="daily", preferred_hour=9, preferred_minute=0,
        core_participants=["nicholas.kelly", "samuel.wright", "keith.butler",
                           "marcus.williams"],
        rotation_pool=["nina.patel"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="ATL IT Operations",
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="marcus.williams",
        room="Ryu", location="ATL",
        recurrence="daily", preferred_hour=8, preferred_minute=0,
        core_participants=["nina.patel"],
        rotation_pool=["nicholas.kelly", "samuel.wright", "keith.butler"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="NOC Briefing",
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="darren.hayes",
        room="Megaman", location="ATL",
        recurrence="daily", preferred_hour=9, preferred_minute=30,
        core_participants=["crystal.price", "jamal.thomas", "whitney.morris"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="ATL Engineering Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Sprint Planning",
        organizer_username="darren.hayes",
        room="Lara", location="ATL",
        recurrence="biweekly", preferred_hour=10, preferred_minute=0,
        core_participants=["crystal.price", "jamal.thomas", "whitney.morris"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.03,
        title_override="ATL Sprint Planning",
    ),
    RecurringMeetingTemplate(
        meeting_type="Sales Pipeline",
        organizer_username="dewayne.johnson",
        room="Chief", location="ATL",
        recurrence="weekly_mon", preferred_hour=10, preferred_minute=0,
        core_participants=["patricia.woods", "rodney.allen"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="ATL Sales Pipeline",
    ),
    RecurringMeetingTemplate(
        meeting_type="All Hands",
        organizer_username="jessica.brown",
        room="Cortana", location="ATL",
        recurrence="monthly_1st_wed", preferred_hour=10, preferred_minute=0,
        core_participants=["darren.hayes", "dewayne.johnson", "marcus.williams"],
        rotation_pool=["nicholas.kelly", "samuel.wright", "keith.butler",
                        "nina.patel", "crystal.price", "jamal.thomas",
                        "whitney.morris", "patricia.woods", "rodney.allen"],
        rotation_count=5, cancellation_rate=0.02,
        title_override="ATL All Hands",
    ),
    # -------------------------------------------------------------------------
    # Austin Office (AUS) — 4 meetings
    # -------------------------------------------------------------------------
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="zoey.collins",
        room="Fox", location="AUS",
        recurrence="daily", preferred_hour=9, preferred_minute=0,
        core_participants=["brooklyn.white", "zoey.young", "austin.miller",
                           "dallas.smith"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="AUS Sales Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Team Standup",
        organizer_username="amelia.collins",
        room="Crash", location="AUS",
        recurrence="daily", preferred_hour=9, preferred_minute=30,
        core_participants=["jackson.moore", "logan.taylor", "aiden.johnson"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="AUS Engineering Standup",
    ),
    RecurringMeetingTemplate(
        meeting_type="Sales Pipeline",
        organizer_username="zoey.collins",
        room="Doom", location="AUS",
        recurrence="weekly_mon", preferred_hour=10, preferred_minute=0,
        core_participants=["taylor.campbell", "brooklyn.white", "zoey.young"],
        rotation_pool=["austin.miller", "dallas.smith"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="AUS Sales Pipeline",
    ),
    RecurringMeetingTemplate(
        meeting_type="All Hands",
        organizer_username="taylor.campbell",
        room="Doom", location="AUS",
        recurrence="monthly_1st_thu", preferred_hour=10, preferred_minute=0,
        core_participants=["zoey.collins", "amelia.collins"],
        rotation_pool=["brooklyn.white", "zoey.young", "austin.miller",
                        "dallas.smith", "jackson.moore", "logan.taylor",
                        "aiden.johnson", "casey.tran"],
        rotation_count=5, cancellation_rate=0.02,
        title_override="AUS All Hands",
    ),
    # -------------------------------------------------------------------------
    # Cross-Site — 3 meetings (hosted from BOS)
    # -------------------------------------------------------------------------
    RecurringMeetingTemplate(
        meeting_type="Executive Sync",
        organizer_username="mike.johnson",
        room="Link", location="BOS",
        recurrence="weekly_wed", preferred_hour=10, preferred_minute=0,
        core_participants=["richard.chen", "nicholas.lewis", "darren.hayes",
                           "amelia.collins"],
        rotation_pool=[], rotation_count=0, cancellation_rate=0.05,
        title_override="CTO Staff Meeting",
    ),
    RecurringMeetingTemplate(
        meeting_type="Sales Pipeline",
        organizer_username="margaret.taylor",
        room="Zelda", location="BOS",
        recurrence="weekly_tue", preferred_hour=14, preferred_minute=0,
        core_participants=["matthew.hall", "dewayne.johnson", "taylor.campbell",
                           "zoey.collins"],
        rotation_pool=["harper.murphy", "derek.stone"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="Global Sales Review",
    ),
    RecurringMeetingTemplate(
        meeting_type="Executive Sync",
        organizer_username="david.robinson",
        room="Yoshi", location="BOS",
        recurrence="weekly_thu", preferred_hour=11, preferred_minute=0,
        core_participants=["jessica.brown", "casey.tran"],
        rotation_pool=["christian.walker", "nicole.simmons"],
        rotation_count=1, cancellation_rate=0.05,
        title_override="IT Directors Sync",
    ),
]


# =============================================================================
# MEETING TYPES AND SCHEDULING CONSTANTS
# =============================================================================

MEETING_TYPES = [
    {"name": "Team Standup", "duration_mins": 15, "participants": (3, 8), "recurring": True},
    {"name": "Project Review", "duration_mins": 60, "participants": (4, 12), "recurring": False},
    {"name": "Sprint Planning", "duration_mins": 120, "participants": (5, 15), "recurring": True},
    {"name": "1:1 Meeting", "duration_mins": 30, "participants": (2, 2), "recurring": True},
    {"name": "All Hands", "duration_mins": 60, "participants": (20, 50), "recurring": True},
    {"name": "Training Session", "duration_mins": 90, "participants": (6, 16), "recurring": False},
    {"name": "Client Call", "duration_mins": 45, "participants": (2, 6), "recurring": False},
    {"name": "Budget Review", "duration_mins": 60, "participants": (3, 8), "recurring": False},
    {"name": "Design Review", "duration_mins": 45, "participants": (3, 10), "recurring": False},
    {"name": "Interview", "duration_mins": 60, "participants": (2, 5), "recurring": False},
    {"name": "Vendor Meeting", "duration_mins": 60, "participants": (3, 8), "recurring": False},
    {"name": "Board Meeting", "duration_mins": 120, "participants": (6, 15), "recurring": True},
    {"name": "Executive Sync", "duration_mins": 30, "participants": (2, 6), "recurring": True},
    {"name": "Tech Deep Dive", "duration_mins": 90, "participants": (3, 8), "recurring": False},
    {"name": "Sales Pipeline", "duration_mins": 60, "participants": (4, 10), "recurring": True},
]

EXTERNAL_DOMAINS = [
    "clientcorp.com",
    "partnertech.io",
    "vendor-systems.com",
    "consultant-group.net",
    "enterprise-solutions.com",
]

# Users whose meetings get demo_id=exfil tags
EXFIL_USERS = {"jessica.brown", "alex.miller"}


# =============================================================================
# MEETING BEHAVIOR HELPERS
# =============================================================================

def should_tag_meeting_exfil(organizer_username: str, day: int, active_scenarios: list) -> Optional[str]:
    """Determine if a meeting should get exfil demo_id based on organizer and day."""
    if "exfil" not in active_scenarios:
        return None
    if day > 13:
        return None
    if organizer_username in EXFIL_USERS:
        return "exfil"
    return None


def is_ghost_meeting() -> bool:
    """Check if this meeting will be a no-show (ghost meeting)."""
    from shared.company import MEETING_BEHAVIOR
    return random.random() < MEETING_BEHAVIOR.get("ghost_meeting_probability", 0.15)


def get_late_start_delay() -> int:
    """Get late start delay in minutes (0 if not late)."""
    from shared.company import MEETING_BEHAVIOR
    if random.random() < MEETING_BEHAVIOR.get("late_start_probability", 0.20):
        min_delay = MEETING_BEHAVIOR.get("late_start_min_minutes", 5)
        max_delay = MEETING_BEHAVIOR.get("late_start_max_minutes", 15)
        return random.randint(min_delay, max_delay)
    return 0


def is_overfilled_meeting() -> bool:
    """Check if this meeting will exceed room capacity."""
    from shared.company import MEETING_BEHAVIOR
    return random.random() < MEETING_BEHAVIOR.get("overfilled_probability", 0.05)


def should_have_afterhours_activity(day: int, hour: int, days: int) -> bool:
    """Check if there should be after-hours activity (legitimate overtime).

    Placed on specific days (3, 7) to create investigatable but non-malicious events.
    """
    from shared.company import MEETING_BEHAVIOR
    afterhours_days = [3, 7]
    if day not in afterhours_days:
        return False
    start_hour = MEETING_BEHAVIOR.get("afterhours_start_hour", 20)
    end_hour = MEETING_BEHAVIOR.get("afterhours_end_hour", 23)
    if not (start_hour <= hour <= end_hour):
        return False
    return random.random() < MEETING_BEHAVIOR.get("afterhours_probability", 0.02) * 10


# =============================================================================
# PARTICIPANT SELECTION HELPERS
# =============================================================================

def _pick_random_participants(
    location: str,
    organizer_user,
    count: int,
    meeting_type: dict,
) -> List[str]:
    """Pick random participants for an ad-hoc meeting.

    Returns list of participant email addresses (not including organizer).
    20% chance of external participants for Client Call/Vendor Meeting/Interview types.
    """
    from shared.company import get_users_by_location, get_random_user

    location_users = get_users_by_location(location)
    participant_emails = []

    for _ in range(count):
        is_external = (
            random.random() < 0.2
            and meeting_type["name"] in ["Client Call", "Vendor Meeting", "Interview"]
        )
        if is_external:
            domain = random.choice(EXTERNAL_DOMAINS)
            first_names = ["Michael", "Jennifer", "David", "Sarah", "Robert", "Emily", "James", "Lisa"]
            last_names = ["Anderson", "Thompson", "Garcia", "Martinez", "Davis", "Wilson", "Taylor", "Brown"]
            name = f"{random.choice(first_names)}.{random.choice(last_names)}".lower()
            participant_emails.append(f"{name}@{domain}")
        else:
            if location_users and random.random() < 0.7:
                p_user = random.choice(location_users)
            else:
                p_user = get_random_user()
            participant_emails.append(f"{p_user.username}@theFakeTshirtCompany.com")

    return participant_emails


# =============================================================================
# RECURRING MEETING RESOLUTION FUNCTIONS
# =============================================================================

def _matches_recurrence(recurrence: str, day_date: datetime, day_offset: int) -> bool:
    """Check if a recurrence pattern matches a given date."""
    wd = day_date.weekday()  # 0=Mon, 6=Sun

    if recurrence == "daily":
        return wd < 5  # weekdays only
    elif recurrence == "weekly_mon":
        return wd == 0
    elif recurrence == "weekly_tue":
        return wd == 1
    elif recurrence == "weekly_wed":
        return wd == 2
    elif recurrence == "weekly_thu":
        return wd == 3
    elif recurrence == "weekly_fri":
        return wd == 4
    elif recurrence == "weekly_mwf":
        return wd in (0, 2, 4)
    elif recurrence == "weekly_tue_thu":
        return wd in (1, 3)
    elif recurrence == "biweekly":
        # Every other Monday (even weeks from start)
        return wd == 0 and (day_offset // 7) % 2 == 0
    elif recurrence.startswith("monthly_"):
        # Parse "monthly_1st_mon", "monthly_3rd_tue", "monthly_1st_wed", etc.
        parts = recurrence.split("_")
        if len(parts) == 3:
            ordinal_map = {"1st": 1, "2nd": 2, "3rd": 3, "4th": 4}
            day_map = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4}
            target_ordinal = ordinal_map.get(parts[1])
            target_weekday = day_map.get(parts[2])
            if target_ordinal is None or target_weekday is None:
                return False
            if wd != target_weekday:
                return False
            # Check if this is the nth occurrence of this weekday in the month
            week_of_month = (day_date.day - 1) // 7 + 1
            return week_of_month == target_ordinal
    return False


def get_recurring_meetings_for_day(day_date: datetime, day_offset: int) -> List[RecurringMeetingTemplate]:
    """Get all recurring meetings scheduled for a given day.

    Filters by recurrence pattern and skips weekends.
    Returns templates for all locations (scheduling is done per-device in the caller).
    """
    if day_date.weekday() >= 5:  # Skip weekends
        return []

    return [
        t for t in RECURRING_MEETINGS
        if _matches_recurrence(t.recurrence, day_date, day_offset)
    ]


def resolve_recurring_participants(
    template: RecurringMeetingTemplate,
    day_date: datetime,
) -> Tuple:
    """Resolve a recurring meeting template into organizer + participant list.

    Returns:
        (organizer_user, participant_users) where organizer_user is a User object
        and participant_users is a list of User objects (core + rotation - absent).
    """
    from shared.company import USERS

    organizer = USERS.get(template.organizer_username)
    if not organizer:
        return None, []

    # Deterministic seed for this meeting + date (reproducible rotation/absence)
    seed_str = f"{template.meeting_type}:{template.title_override}:{day_date.isoformat()}"
    seed = int(hashlib.sha256(seed_str.encode()).hexdigest()[:8], 16)
    rng = random.Random(seed)

    # Resolve core participants (with 5% per-person absence rate)
    participants = []
    for username in template.core_participants:
        user = USERS.get(username)
        if not user:
            continue
        # 5% chance of absence per core participant (date-seeded)
        if rng.random() < 0.05:
            continue
        participants.append(user)

    # Resolve rotation pool
    if template.rotation_pool and template.rotation_count > 0:
        pool_users = [USERS[u] for u in template.rotation_pool if u in USERS]
        count = min(template.rotation_count, len(pool_users))
        if count > 0:
            rotation_picks = rng.sample(pool_users, count)
            participants.extend(rotation_picks)

    return organizer, participants


# =============================================================================
# SCHEDULE MEETING (creates ScheduledMeeting without generating events)
# =============================================================================

def _schedule_meeting(
    start_ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_type: dict,
    organizer_user,
    is_ghost: bool,
    late_start_mins: int,
    is_overfilled: bool,
    location: str,
    preset_participants: Optional[List] = None,
    demo_id: Optional[str] = None,
) -> ScheduledMeeting:
    """Create and register a ScheduledMeeting without generating events."""
    from shared.company import MEETING_BEHAVIOR

    duration_mins = meeting_type["duration_mins"]

    # Ghost meeting - register as booked-but-empty
    if is_ghost:
        ghost_email = f"{organizer_user.username}@theFakeTshirtCompany.com"
        meeting = ScheduledMeeting(
            room=device_info.get("room", ""),
            location_code=location,
            device_id=device_id,
            start_time=start_ts,
            end_time=start_ts + timedelta(minutes=duration_mins),
            scheduled_start=start_ts,
            participant_count=0,
            is_ghost=True,
            late_start_mins=0,
            meeting_title=meeting_type.get("name", "Meeting") + " (No-show)",
            organizer_email=ghost_email,
            organizer_name=organizer_user.display_name,
            participants=[],
        )
        add_meeting(meeting)
        return meeting

    # Apply late start
    actual_start = start_ts + timedelta(minutes=late_start_mins) if late_start_mins else start_ts

    # Determine participants
    organizer_email = f"{organizer_user.username}@theFakeTshirtCompany.com"

    if preset_participants is not None:
        participant_count = len(preset_participants) + 1  # +1 for organizer
        participant_emails = [f"{u.username}@theFakeTshirtCompany.com" for u in preset_participants]
    else:
        min_p, max_p = meeting_type["participants"]
        capacity = device_info.get("capacity", max_p)
        effective_max = min(max_p, capacity)
        effective_min = min(min_p, effective_max)  # clamp to avoid empty range
        if is_overfilled:
            extra = random.randint(2, MEETING_BEHAVIOR.get("overfilled_max_extra", 5))
            participant_count = min(random.randint(effective_min, max_p) + extra, capacity + 3)
        else:
            participant_count = random.randint(effective_min, effective_max)
        participant_emails = _pick_random_participants(
            location, organizer_user, participant_count - 1, meeting_type,
        )

    # Calculate actual duration with variance
    actual_duration = int(duration_mins * random.uniform(0.85, 1.15))
    end_time = actual_start + timedelta(minutes=actual_duration)

    # Include organizer email in participants list
    all_participant_emails = [organizer_email] + participant_emails

    meeting = ScheduledMeeting(
        room=device_info.get("room", ""),
        location_code=location,
        device_id=device_id,
        start_time=actual_start,
        end_time=end_time,
        scheduled_start=start_ts,
        participant_count=participant_count,
        is_ghost=False,
        late_start_mins=late_start_mins,
        meeting_title=meeting_type.get("name", "Meeting"),
        organizer_email=organizer_email,
        organizer_name=organizer_user.display_name,
        participants=all_participant_emails,
    )
    add_meeting(meeting)
    return meeting


# Global meeting schedule - populated by build_meeting_schedule(), read by consumers
_meeting_schedule: Dict[str, List[ScheduledMeeting]] = {}

# Walk-in meetings - populated by Meraki generator (no Webex events)
_walkin_schedule: Dict[str, List[ScheduledMeeting]] = {}

# After-hours activity - specific days and times
AFTER_HOURS_CONFIG = {
    "days": [2, 6],  # Day 3 and 7 (0-indexed)
    "rooms": {
        "BOS": ["Yoshi", "Kirby"],
        "ATL": ["Pikachu"],
    },
    "hours": [(20, 23)],  # 20:00-23:00
}


def clear_schedule():
    """Clear the meeting schedule (call at start of generation).

    Note: Use .clear() instead of assigning new dict to preserve references
    in other modules that imported _meeting_schedule.
    """
    _meeting_schedule.clear()


def add_meeting(meeting: ScheduledMeeting):
    """Add a meeting to the schedule."""
    key = f"{meeting.location_code}:{meeting.room}"
    if key not in _meeting_schedule:
        _meeting_schedule[key] = []
    _meeting_schedule[key].append(meeting)


def get_meetings_for_room(location_code: str, room: str) -> List[ScheduledMeeting]:
    """Get all meetings for a specific room."""
    key = f"{location_code}:{room}"
    return _meeting_schedule.get(key, [])


def get_meetings_for_hour(location_code: str, room: str,
                          target_date: datetime, hour: int) -> List[ScheduledMeeting]:
    """Get active (non-ghost) meetings during a specific hour for a room."""
    meetings = get_meetings_for_room(location_code, room)
    result = []

    hour_start = target_date.replace(hour=hour, minute=0, second=0, microsecond=0)
    hour_end = hour_start + timedelta(hours=1)

    for meeting in meetings:
        # Check if meeting overlaps with this hour
        if meeting.is_ghost:
            continue  # Ghost meetings don't generate sensor activity

        # Meeting overlaps if it starts before hour ends AND ends after hour starts
        if meeting.start_time < hour_end and meeting.end_time > hour_start:
            result.append(meeting)

    return result


def get_ghost_meetings_for_hour(location_code: str, room: str,
                                 target_date: datetime, hour: int) -> List[ScheduledMeeting]:
    """Get ghost (no-show) meetings during a specific hour for a room.

    Ghost meetings are booked but no one showed up. Sensors should show:
    - No door activity (room stays empty)
    - Baseline temperature (no body heat)
    - Camera shows empty room
    """
    meetings = get_meetings_for_room(location_code, room)
    result = []

    hour_start = target_date.replace(hour=hour, minute=0, second=0, microsecond=0)
    hour_end = hour_start + timedelta(hours=1)

    for meeting in meetings:
        if not meeting.is_ghost:
            continue  # Only ghost meetings

        # Meeting overlaps if it starts before hour ends AND ends after hour starts
        if meeting.start_time < hour_end and meeting.end_time > hour_start:
            result.append(meeting)

    return result


def is_room_booked_but_empty(location_code: str, room: str,
                              current_time: datetime) -> bool:
    """Check if room is booked but empty (ghost meeting in progress)."""
    meetings = get_meetings_for_room(location_code, room)

    for meeting in meetings:
        if meeting.is_ghost:
            if meeting.start_time <= current_time <= meeting.end_time:
                return True
    return False


def get_door_events_for_meeting(meeting: ScheduledMeeting) -> List[Dict]:
    """
    Generate door event timing for a meeting.

    Returns list of dicts with:
    - time: datetime when door opens/closes
    - status: "open" or "closed"
    - reason: "arrival", "participant", "departure"
    """
    if meeting.is_ghost:
        return []

    events = []

    # First person arrives 2-5 minutes before meeting
    first_arrival = meeting.start_time - timedelta(minutes=random.randint(2, 5))
    events.append({
        "time": first_arrival,
        "status": "open",
        "reason": "arrival"
    })
    events.append({
        "time": first_arrival + timedelta(seconds=random.randint(30, 90)),
        "status": "closed",
        "reason": "arrival"
    })

    # Additional arrivals (1-3 more door open/close cycles in first 5 min)
    if meeting.participant_count > 2:
        extra_arrivals = min(random.randint(1, 3), meeting.participant_count - 1)
        for i in range(extra_arrivals):
            arrival_offset = random.randint(0, 300)  # 0-5 min after meeting start
            arrival_time = meeting.start_time + timedelta(seconds=arrival_offset)
            events.append({
                "time": arrival_time,
                "status": "open",
                "reason": "participant"
            })
            events.append({
                "time": arrival_time + timedelta(seconds=random.randint(20, 60)),
                "status": "closed",
                "reason": "participant"
            })

    # Mid-meeting door activity (bathroom breaks, late arrivals) - ~20% chance per 30 min
    meeting_duration = (meeting.end_time - meeting.start_time).total_seconds() / 60
    mid_events = int(meeting_duration / 30 * 0.2)
    for _ in range(mid_events):
        if random.random() < 0.2:
            mid_offset = random.randint(300, int(meeting_duration * 60) - 300)
            mid_time = meeting.start_time + timedelta(seconds=mid_offset)
            events.append({
                "time": mid_time,
                "status": "open",
                "reason": "mid_meeting"
            })
            events.append({
                "time": mid_time + timedelta(seconds=random.randint(30, 120)),
                "status": "closed",
                "reason": "mid_meeting"
            })

    # People leaving at end (1-3 door cycles)
    departure_cycles = min(random.randint(1, 3), meeting.participant_count)
    for i in range(departure_cycles):
        departure_offset = random.randint(0, 180)  # 0-3 min after meeting end
        departure_time = meeting.end_time + timedelta(seconds=departure_offset)
        events.append({
            "time": departure_time,
            "status": "open",
            "reason": "departure"
        })
        events.append({
            "time": departure_time + timedelta(seconds=random.randint(20, 60)),
            "status": "closed",
            "reason": "departure"
        })

    # Sort by time
    events.sort(key=lambda x: x["time"])

    return events


def calculate_room_temperature(
    room_config: dict,
    meeting: Optional[ScheduledMeeting],
    current_time: datetime,
    base_temp: float = 21.0
) -> float:
    """
    Calculate realistic room temperature based on meeting activity.

    Factors:
    - Sun exposure (time of day)
    - People in room (body heat)
    - Meeting duration (accumulated heat)
    """
    temp = base_temp

    # Sun exposure bonus
    sun_hours = room_config.get("sun_hours", [])
    sun_boost = room_config.get("sun_temp_boost", 0)
    if current_time.hour in sun_hours:
        temp += sun_boost

    # If no meeting or ghost meeting, return base temp with sun
    if not meeting or meeting.is_ghost:
        return round(temp + random.uniform(-0.3, 0.3), 1)

    # Check if meeting is active at current_time
    if current_time < meeting.start_time or current_time > meeting.end_time:
        return round(temp + random.uniform(-0.3, 0.3), 1)

    # Body heat: +0.3°C per person, max +3°C
    body_heat = min(meeting.participant_count * 0.3, 3.0)
    temp += body_heat

    # Duration heat: +0.5°C per 30 min, max +1.5°C
    minutes_in = (current_time - meeting.start_time).total_seconds() / 60
    duration_heat = min(minutes_in / 30 * 0.5, 1.5)
    temp += duration_heat

    # Random noise
    temp += random.uniform(-0.3, 0.3)

    return round(temp, 1)


def get_all_rooms() -> List[str]:
    """Get list of all rooms with scheduled meetings."""
    rooms = set()
    for key in _meeting_schedule.keys():
        loc, room = key.split(":", 1)
        rooms.add(room)
    return list(rooms)


# =============================================================================
# WALK-IN MEETINGS (Unbooked room usage)
# =============================================================================

def clear_walkin_schedule():
    """Clear the walk-in schedule."""
    _walkin_schedule.clear()


def add_walkin(walkin: ScheduledMeeting):
    """Add a walk-in meeting to the schedule.

    Avoids duplicates by checking if a walk-in already exists for the same hour.
    """
    key = f"{walkin.location_code}:{walkin.room}"
    if key not in _walkin_schedule:
        _walkin_schedule[key] = []

    # Check for duplicate (same room, same hour)
    for existing in _walkin_schedule[key]:
        if existing.start_time.hour == walkin.start_time.hour and \
           existing.start_time.date() == walkin.start_time.date():
            return  # Already have a walk-in for this hour

    _walkin_schedule[key].append(walkin)


def get_walkins_for_hour(location_code: str, room: str,
                          target_date: datetime, hour: int) -> List[ScheduledMeeting]:
    """Get walk-in meetings for a specific hour.

    Walk-in meetings have sensor activity but no Webex events:
    - Door opens/closes
    - Camera detects people
    - Temperature rises
    - NO Webex meeting_started event
    """
    key = f"{location_code}:{room}"
    walkins = _walkin_schedule.get(key, [])

    hour_start = target_date.replace(hour=hour, minute=0, second=0, microsecond=0)
    hour_end = hour_start + timedelta(hours=1)

    return [
        w for w in walkins
        if w.start_time < hour_end and w.end_time > hour_start
    ]


def should_generate_walkin(location_code: str, room: str,
                            target_date: datetime, hour: int,
                            probability: float = 0.10) -> bool:
    """Check if we should generate a walk-in meeting for this hour.

    ~10% of business hours have unbooked room usage.
    Only during business hours (9-17) when no scheduled meeting.
    """
    if not (9 <= hour <= 17):
        return False

    # Check if there's already a scheduled meeting
    from shared.meeting_schedule import get_meetings_for_hour, get_ghost_meetings_for_hour
    scheduled = get_meetings_for_hour(location_code, room, target_date, hour)
    ghosts = get_ghost_meetings_for_hour(location_code, room, target_date, hour)

    if scheduled or ghosts:
        return False

    # Check if walk-in already exists
    existing = get_walkins_for_hour(location_code, room, target_date, hour)
    if existing:
        return False

    return random.random() < probability


def generate_walkin_meeting(location_code: str, room: str,
                             target_date: datetime, hour: int) -> Optional[ScheduledMeeting]:
    """Generate a walk-in meeting for the given time slot.

    Walk-in meetings are shorter (15-45 min) and have fewer people (1-4).
    """
    if not should_generate_walkin(location_code, room, target_date, hour):
        return None

    # Random start within the hour
    start_minute = random.randint(5, 45)
    duration_mins = random.randint(15, 45)

    start_time = target_date.replace(hour=hour, minute=start_minute, second=0, microsecond=0)
    end_time = start_time + timedelta(minutes=duration_mins)

    walkin = ScheduledMeeting(
        room=room,
        location_code=location_code,
        device_id="",  # No Webex device
        start_time=start_time,
        end_time=end_time,
        scheduled_start=start_time,
        participant_count=random.randint(1, 4),
        is_ghost=False,
        is_walkin=True,
        meeting_title="Walk-in (Unbooked)",
    )

    add_walkin(walkin)
    return walkin


# =============================================================================
# AFTER-HOURS ACTIVITY
# =============================================================================

def is_after_hours_day(day: int) -> bool:
    """Check if this day has after-hours activity."""
    return day in AFTER_HOURS_CONFIG["days"]


def get_after_hours_rooms(location_code: str) -> List[str]:
    """Get rooms that have after-hours activity for a location."""
    return AFTER_HOURS_CONFIG["rooms"].get(location_code, [])


def is_after_hours_time(hour: int) -> bool:
    """Check if this hour is within after-hours period."""
    for start_hour, end_hour in AFTER_HOURS_CONFIG["hours"]:
        if start_hour <= hour < end_hour:
            return True
    return False


def should_generate_after_hours(location_code: str, room: str,
                                  day: int, hour: int) -> bool:
    """Check if after-hours activity should be generated."""
    if not is_after_hours_day(day):
        return False

    if not is_after_hours_time(hour):
        return False

    if room not in get_after_hours_rooms(location_code):
        return False

    return True


def generate_after_hours_activity(location_code: str, room: str,
                                   target_date: datetime, hour: int) -> Optional[ScheduledMeeting]:
    """Generate after-hours activity for legitimate overtime work.

    Creates sensor activity showing:
    - 1-2 people working late
    - Door activity
    - Possible impromptu Webex call
    """
    # Only first hour of after-hours gets the "arrival"
    if hour == 20:
        start_minute = random.randint(10, 30)
    else:
        # Continue from previous hour
        start_minute = 0

    # Determine end time - could be this hour or extend
    if hour == 22:
        # Last hour - person leaves
        end_minute = random.randint(15, 50)
        duration_mins = end_minute
    else:
        # Full hour activity
        duration_mins = 60 - start_minute

    start_time = target_date.replace(hour=hour, minute=start_minute, second=0, microsecond=0)
    end_time = start_time + timedelta(minutes=duration_mins)

    after_hours = ScheduledMeeting(
        room=room,
        location_code=location_code,
        device_id="",
        start_time=start_time,
        end_time=end_time,
        scheduled_start=start_time,
        participant_count=random.randint(1, 2),
        is_ghost=False,
        is_walkin=False,
        is_after_hours=True,
        meeting_title="After-hours work",
    )

    return after_hours


def get_schedule_stats() -> dict:
    """Get statistics about the meeting schedule (for debugging)."""
    total_meetings = sum(len(m) for m in _meeting_schedule.values())
    ghost_meetings = sum(
        1 for meetings in _meeting_schedule.values()
        for m in meetings if m.is_ghost
    )
    rooms_with_meetings = len(_meeting_schedule)

    return {
        "total_meetings": total_meetings,
        "ghost_meetings": ghost_meetings,
        "actual_meetings": total_meetings - ghost_meetings,
        "rooms_with_meetings": rooms_with_meetings,
    }


# =============================================================================
# BUILD MEETING SCHEDULE (main entry point — replaces generate_webex_logs)
# =============================================================================

def build_meeting_schedule(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    quiet: bool = False,
) -> int:
    """Build the shared meeting schedule for all collaboration generators.

    Populates _meeting_schedule with recurring meetings, ad-hoc meetings,
    walk-ins, and after-hours activity. Must run before any consumer
    generator (exchange, meraki, webex_ta, webex_api).

    Returns total number of scheduled meetings.
    """
    from shared.company import (
        USERS, MEETING_ROOMS, MEETING_BEHAVIOR,
        get_users_by_location, get_random_user,
    )
    from scenarios.registry import expand_scenarios

    clear_schedule()
    clear_walkin_schedule()

    active_scenarios = expand_scenarios(scenarios)

    # Build room_to_device lookup from MEETING_ROOMS
    # MEETING_ROOMS has room name -> config with "device" key pointing to device ID
    room_to_device = {}
    for room_name, room_info in MEETING_ROOMS.items():
        device_id = room_info.get("device")
        if device_id:
            room_to_device[room_name] = (device_id, room_info)

    total_meetings = 0
    current_date = datetime.strptime(start_date, "%Y-%m-%d")

    for day_offset in range(days):
        day_date = current_date + timedelta(days=day_offset)
        weekend = day_date.weekday() >= 5

        if weekend:
            continue  # No meetings on weekends

        # Schedule per location
        for location in ["BOS", "ATL", "AUS"]:
            location_rooms = {
                k: v for k, v in MEETING_ROOMS.items()
                if v.get("location") == location and v.get("device")
            }
            location_users = get_users_by_location(location)

            # Phase A: Recurring meetings first (consistent organizer/participants)
            occupied_slots = {}  # {device_id: set(hours)}
            recurring_today = get_recurring_meetings_for_day(day_date, day_offset)

            for template in recurring_today:
                # Only process templates for this location
                if template.location != location:
                    continue

                # Cancellation check (date-seeded)
                cancel_seed = f"{template.meeting_type}:{template.title_override}:cancel:{day_date.isoformat()}"
                cancel_rng = random.Random(hash(cancel_seed))
                if cancel_rng.random() < template.cancellation_rate:
                    continue

                # Look up device for this room
                if template.room not in room_to_device:
                    continue
                device_id, device_info = room_to_device[template.room]

                organizer, participants = resolve_recurring_participants(template, day_date)
                if organizer is None:
                    continue

                meeting_start = day_date.replace(
                    hour=template.preferred_hour,
                    minute=template.preferred_minute,
                    second=0,
                )

                # Find matching meeting type dict for duration/participant range
                meeting_type_dict = next(
                    (m for m in MEETING_TYPES if m["name"] == template.meeting_type),
                    {"name": template.meeting_type, "duration_mins": 30,
                     "participants": (2, 20), "recurring": True},
                )
                if template.title_override:
                    meeting_type_dict = {**meeting_type_dict, "name": template.title_override}

                demo_id = should_tag_meeting_exfil(
                    organizer.username, day_offset, active_scenarios,
                )
                ghost = is_ghost_meeting()
                late_delay = get_late_start_delay()

                _schedule_meeting(
                    start_ts=meeting_start,
                    device_id=device_id,
                    device_info=device_info,
                    meeting_type=meeting_type_dict,
                    organizer_user=organizer,
                    is_ghost=ghost,
                    late_start_mins=late_delay,
                    is_overfilled=False,
                    location=location,
                    preset_participants=participants,
                    demo_id=demo_id,
                )

                # Mark occupied hours (including multi-hour meetings)
                duration_mins = meeting_type_dict.get("duration_mins", 30)
                hours_occupied = max(1, (duration_mins + 59) // 60)
                for h in range(hours_occupied):
                    occupied_slots.setdefault(device_id, set()).add(
                        template.preferred_hour + h,
                    )
                total_meetings += 1

            # Phase B: Ad-hoc meetings per device
            for room_name, room_info in location_rooms.items():
                device_id = room_info.get("device")
                if not device_id:
                    continue

                room_type = room_info.get("room_type", "Conference Room")

                # Meetings per day based on room type
                if room_type == "Boardroom":
                    base_meetings = random.randint(2, 5)
                elif room_type == "Training Room":
                    base_meetings = random.randint(1, 3)
                elif room_type in ["Huddle Space", "Small Meeting Room"]:
                    base_meetings = random.randint(4, 8)
                elif room_type == "Demo Lab":
                    base_meetings = random.randint(2, 4)
                else:
                    base_meetings = random.randint(3, 6)

                num_meetings = int(base_meetings * scale)

                # Filter out hours already used by recurring meetings
                all_hours = list(range(8, 18))
                device_occupied = occupied_slots.get(device_id, set())
                available_hours = [h for h in all_hours if h not in device_occupied]
                random.shuffle(available_hours)

                for i in range(min(num_meetings, len(available_hours))):
                    hour = available_hours[i]
                    minute = random.randint(0, 45)
                    meeting_start = day_date.replace(hour=hour, minute=minute, second=0)

                    # Select meeting type appropriate for room
                    if room_type == "Boardroom":
                        suitable_types = [m for m in MEETING_TYPES if m["participants"][1] >= 8]
                    elif room_type in ["Huddle Space", "Small Meeting Room"]:
                        suitable_types = [m for m in MEETING_TYPES if m["participants"][1] <= 6]
                    elif room_type == "Training Room":
                        suitable_types = [m for m in MEETING_TYPES if "Training" in m["name"] or m["participants"][1] >= 6]
                    else:
                        suitable_types = MEETING_TYPES

                    meeting_type = random.choice(suitable_types)
                    organizer = random.choice(location_users) if location_users else get_random_user()

                    ghost = is_ghost_meeting()
                    late_delay = get_late_start_delay()
                    overfilled = is_overfilled_meeting()
                    demo_id = should_tag_meeting_exfil(organizer.username, day_offset, active_scenarios)

                    _schedule_meeting(
                        start_ts=meeting_start,
                        device_id=device_id,
                        device_info=room_info,
                        meeting_type=meeting_type,
                        organizer_user=organizer,
                        is_ghost=ghost,
                        late_start_mins=late_delay,
                        is_overfilled=overfilled,
                        location=location,
                        demo_id=demo_id,
                    )
                    total_meetings += 1

            # Phase C: Walk-ins (~10% of rooms during business hours)
            for room_name, room_info in location_rooms.items():
                for hour in range(9, 18):
                    walkin = generate_walkin_meeting(location, room_name, day_date, hour)
                    if walkin:
                        total_meetings += 1

        # After-hours activity (legitimate overtime work, not exfil related)
        from shared.company import MEETING_BEHAVIOR as _mb
        preferred_rooms = _mb.get("afterhours_preferred_rooms", ["Yoshi", "Kirby", "Pikachu"])

        for room_name in preferred_rooms:
            if room_name not in room_to_device:
                continue
            device_id, device_info = room_to_device[room_name]
            location = device_info.get("location", "BOS")

            for hour in range(20, 24):
                if should_have_afterhours_activity(day_offset, hour, days):
                    after_hours = generate_after_hours_activity(
                        location, room_name, day_date, hour,
                    )
                    if after_hours:
                        add_meeting(after_hours)
                        total_meetings += 1

    if not quiet:
        stats = get_schedule_stats()
        import sys
        print(f"  Meeting schedule built: {stats['total_meetings']} meetings "
              f"({stats['actual_meetings']} active, {stats['ghost_meetings']} ghost)",
              file=sys.stderr)

    return total_meetings
