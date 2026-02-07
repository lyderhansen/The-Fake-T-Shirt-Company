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
from typing import Dict, List, Optional
import random


@dataclass
class ScheduledMeeting:
    """Represents a scheduled meeting with timing information."""
    room: str                    # Room name (e.g., "Faneuil")
    location_code: str           # BOS, ATL, AUS
    device_id: str               # WEBEX-BOS-FANEUIL
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


# Global meeting schedule - populated by Webex, read by Meraki
_meeting_schedule: Dict[str, List[ScheduledMeeting]] = {}

# Walk-in meetings - populated by Meraki generator (no Webex events)
_walkin_schedule: Dict[str, List[ScheduledMeeting]] = {}

# After-hours activity - specific days and times
AFTER_HOURS_CONFIG = {
    "days": [2, 6],  # Day 3 and 7 (0-indexed)
    "rooms": {
        "BOS": ["Back Bay", "North End"],
        "ATL": ["Buckhead"],
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


if __name__ == "__main__":
    # Test the module
    from datetime import datetime

    print("Meeting Schedule Module Test")
    print("=" * 40)

    # Add a test meeting
    test_meeting = ScheduledMeeting(
        room="Faneuil",
        location_code="BOS",
        device_id="WEBEX-BOS-FANEUIL",
        start_time=datetime(2026, 1, 1, 9, 0, 0),
        end_time=datetime(2026, 1, 1, 10, 0, 0),
        scheduled_start=datetime(2026, 1, 1, 9, 0, 0),
        participant_count=6,
        meeting_title="Test Meeting"
    )

    add_meeting(test_meeting)

    print(f"\nSchedule stats: {get_schedule_stats()}")

    print(f"\nMeetings for Faneuil:")
    for m in get_meetings_for_room("BOS", "Faneuil"):
        print(f"  {m.start_time} - {m.end_time}: {m.meeting_title} ({m.participant_count} people)")

    print(f"\nDoor events for meeting:")
    for event in get_door_events_for_meeting(test_meeting):
        print(f"  {event['time'].strftime('%H:%M:%S')} - door {event['status']} ({event['reason']})")

    # Test temperature
    room_config = {
        "sun_hours": [13, 14, 15, 16, 17],
        "sun_temp_boost": 4.0,
    }

    print(f"\nTemperature during meeting:")
    for hour in [8, 9, 10, 14]:
        test_time = datetime(2026, 1, 1, hour, 30, 0)
        temp = calculate_room_temperature(room_config, test_meeting, test_time)
        print(f"  {hour:02d}:30 - {temp}°C")
