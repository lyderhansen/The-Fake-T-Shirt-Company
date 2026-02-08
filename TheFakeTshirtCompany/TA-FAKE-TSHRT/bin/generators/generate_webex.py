#!/usr/bin/env python3
"""
Cisco Webex Collaboration Device Log Generator.
Generates JSON events for Webex Room Kit, Board, and Desk devices.

Locations:
  - Boston HQ (BOS): 8 conference rooms + 2 huddle spaces
  - Atlanta Hub (ATL): 6 conference rooms
  - Austin Office (AUS): 3 conference rooms + 1 demo space

Event types:
  - Meeting events: start, join, leave, end
  - Device health: CPU, memory, peripheral status
  - Call quality: audio MOS, video loss, jitter
  - Room analytics: people count, ambient noise
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
import uuid

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add, get_hour_activity_level, is_weekend
from shared.company import (
    USERS, get_random_user, LOCATIONS, get_users_by_location,
    MEETING_ROOMS, MEETING_BEHAVIOR, get_problem_rooms,
)
from shared.meeting_schedule import (
    ScheduledMeeting, add_meeting, clear_schedule, get_schedule_stats
)
from scenarios.registry import expand_scenarios

# =============================================================================
# SCENARIO-RELATED USERS (for demo_id tagging)
# =============================================================================
# Only meetings involving these users get demo_id tags
EXFIL_USERS = {"jessica.brown", "alex.miller"}

def should_tag_meeting_exfil(organizer_username: str, day: int, active_scenarios: list) -> Optional[str]:
    """Determine if a meeting should get exfil demo_id based on organizer and day."""
    if "exfil" not in active_scenarios:
        return None
    # Exfil scenario: day 1-14 (0-indexed: 0-13)
    if day > 13:
        return None
    if organizer_username in EXFIL_USERS:
        return "exfil"
    return None


# =============================================================================
# WEBEX DEVICE CONFIGURATION - MULTI-SITE
# =============================================================================

# Device model specifications
WEBEX_MODELS = {
    "Room Kit Pro": {
        "type": "video_conferencing",
        "max_participants": 20,
        "cameras": 2,
        "displays": 3,
        "microphones": 8,
        "touch_panel": "Room Navigator",
        "capabilities": ["video", "whiteboard", "wireless_share", "ultrasound"],
    },
    "Room Kit": {
        "type": "video_conferencing",
        "max_participants": 14,
        "cameras": 1,
        "displays": 2,
        "microphones": 4,
        "touch_panel": "Touch 10",
        "capabilities": ["video", "wireless_share", "ultrasound"],
    },
    "Room Kit Mini": {
        "type": "video_conferencing",
        "max_participants": 6,
        "cameras": 1,
        "displays": 1,
        "microphones": 4,
        "touch_panel": "Touch 10",
        "capabilities": ["video", "wireless_share"],
    },
    "Board 85 Pro": {
        "type": "interactive_whiteboard",
        "max_participants": 20,
        "cameras": 1,
        "displays": 1,
        "microphones": 12,
        "touch_panel": "integrated",
        "screen_size": 85,
        "capabilities": ["video", "whiteboard", "wireless_share", "touch", "annotation"],
    },
    "Board 55": {
        "type": "interactive_whiteboard",
        "max_participants": 8,
        "cameras": 1,
        "displays": 1,
        "microphones": 8,
        "touch_panel": "integrated",
        "screen_size": 55,
        "capabilities": ["video", "whiteboard", "wireless_share", "touch", "annotation"],
    },
    "Desk Pro": {
        "type": "personal_device",
        "max_participants": 4,
        "cameras": 1,
        "displays": 1,
        "microphones": 3,
        "touch_panel": "integrated",
        "screen_size": 27,
        "capabilities": ["video", "wireless_share", "usb_passthrough"],
    },
}

# Webex devices per location (from OFFICE_LAYOUTS.md)
WEBEX_DEVICES = {
    # Boston HQ - 10 devices
    "WEBEX-BOS-CAMBRIDGE": {
        "model": "Room Kit Pro",
        "location": "BOS",
        "floor": 3,
        "room": "Cambridge",
        "room_type": "Boardroom",
        "capacity": 20,
        "additional_equipment": ["Board 85 Pro"],
        "serial": "FOC2345X001",
    },
    "WEBEX-BOS-FANEUIL": {
        "model": "Room Kit",
        "location": "BOS",
        "floor": 2,
        "room": "Faneuil",
        "room_type": "Conference Room",
        "capacity": 12,
        "additional_equipment": ["Board 55"],
        "serial": "FOC2345X002",
    },
    "WEBEX-BOS-QUINCY": {
        "model": "Room Kit",
        "location": "BOS",
        "floor": 2,
        "room": "Quincy",
        "room_type": "Conference Room",
        "capacity": 8,
        "additional_equipment": [],
        "serial": "FOC2345X003",
    },
    "WEBEX-BOS-NORTHEND": {
        "model": "Desk Pro",
        "location": "BOS",
        "floor": 2,
        "room": "North End",
        "room_type": "Huddle Space",
        "capacity": 4,
        "additional_equipment": [],
        "serial": "FOC2345X004",
    },
    "WEBEX-BOS-BACKBAY": {
        "model": "Room Kit Mini",
        "location": "BOS",
        "floor": 3,
        "room": "Back Bay",
        "room_type": "Small Meeting Room",
        "capacity": 6,
        "additional_equipment": [],
        "serial": "FOC2345X005",
    },
    "WEBEX-BOS-LAB": {
        "model": "Board 55",
        "location": "BOS",
        "floor": 3,
        "room": "Engineering Lab",
        "room_type": "Collaboration Space",
        "capacity": 8,
        "additional_equipment": [],
        "serial": "FOC2345X006",
    },
    "WEBEX-BOS-HARBOR": {
        "model": "Desk Pro",
        "location": "BOS",
        "floor": 1,
        "room": "Harbor",
        "room_type": "Visitor Meeting Room",
        "capacity": 6,
        "additional_equipment": [],
        "serial": "FOC2345X007",
    },
    "WEBEX-BOS-BEACON": {
        "model": "Room Kit Mini",
        "location": "BOS",
        "floor": 1,
        "room": "Beacon",
        "room_type": "Visitor Meeting Room",
        "capacity": 4,
        "additional_equipment": [],
        "serial": "FOC2345X008",
    },
    # Atlanta Hub - 7 devices
    "WEBEX-ATL-PEACHTREE": {
        "model": "Room Kit Pro",
        "location": "ATL",
        "floor": 1,
        "room": "Peachtree",
        "room_type": "Training Room",
        "capacity": 16,
        "additional_equipment": [],
        "serial": "FOC2345X101",
    },
    "WEBEX-ATL-MIDTOWN": {
        "model": "Room Kit",
        "location": "ATL",
        "floor": 2,
        "room": "Midtown",
        "room_type": "Conference Room",
        "capacity": 10,
        "additional_equipment": ["Board 55"],
        "serial": "FOC2345X102",
    },
    "WEBEX-ATL-NOC": {
        "model": "Room Kit",
        "location": "ATL",
        "floor": 1,
        "room": "NOC",
        "room_type": "Operations Center",
        "capacity": 6,
        "additional_equipment": [],
        "serial": "FOC2345X103",
    },
    "WEBEX-ATL-BUCKHEAD": {
        "model": "Desk Pro",
        "location": "ATL",
        "floor": 1,
        "room": "Buckhead",
        "room_type": "Huddle Space",
        "capacity": 4,
        "additional_equipment": [],
        "serial": "FOC2345X104",
    },
    "WEBEX-ATL-DECATUR": {
        "model": "Desk Pro",
        "location": "ATL",
        "floor": 2,
        "room": "Decatur",
        "room_type": "Huddle Space",
        "capacity": 4,
        "additional_equipment": [],
        "serial": "FOC2345X105",
    },
    "WEBEX-ATL-INNOVATION": {
        "model": "Board 55",
        "location": "ATL",
        "floor": 2,
        "room": "Innovation Lab",
        "room_type": "Collaboration Space",
        "capacity": 8,
        "additional_equipment": [],
        "serial": "FOC2345X106",
    },
    # Austin Office - 4 devices
    "WEBEX-AUS-CONGRESS": {
        "model": "Room Kit",
        "location": "AUS",
        "floor": 1,
        "room": "Congress",
        "room_type": "Main Conference Room",
        "capacity": 12,
        "additional_equipment": ["Board 55"],
        "serial": "FOC2345X201",
    },
    "WEBEX-AUS-6THSTREET": {
        "model": "Room Kit Mini",
        "location": "AUS",
        "floor": 1,
        "room": "6th Street",
        "room_type": "Small Meeting Room",
        "capacity": 6,
        "additional_equipment": [],
        "serial": "FOC2345X202",
    },
    "WEBEX-AUS-LIVEOAK": {
        "model": "Room Kit",
        "location": "AUS",
        "floor": 1,
        "room": "Live Oak",
        "room_type": "Demo Lab",
        "capacity": 8,
        "additional_equipment": [],
        "serial": "FOC2345X203",
    },
}

# Meeting types for realistic scheduling
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

# External meeting participants (domain names for external attendees)
EXTERNAL_DOMAINS = [
    "clientcorp.com",
    "partnertech.io",
    "vendor-systems.com",
    "consultant-group.net",
    "enterprise-solutions.com",
]


# =============================================================================
# MEETING BEHAVIOR HELPERS
# =============================================================================

def is_ghost_meeting() -> bool:
    """Check if this meeting will be a no-show (ghost meeting)."""
    return random.random() < MEETING_BEHAVIOR.get("ghost_meeting_probability", 0.15)


def is_walkin_meeting() -> bool:
    """Check if this is an unbooked walk-in meeting."""
    return random.random() < MEETING_BEHAVIOR.get("walkin_meeting_probability", 0.10)


def get_late_start_delay() -> int:
    """Get late start delay in minutes (0 if not late)."""
    if random.random() < MEETING_BEHAVIOR.get("late_start_probability", 0.20):
        min_delay = MEETING_BEHAVIOR.get("late_start_min_minutes", 5)
        max_delay = MEETING_BEHAVIOR.get("late_start_max_minutes", 15)
        return random.randint(min_delay, max_delay)
    return 0


def is_overfilled_meeting() -> bool:
    """Check if this meeting will exceed room capacity."""
    return random.random() < MEETING_BEHAVIOR.get("overfilled_probability", 0.05)


def get_room_config(room_name: str) -> Optional[dict]:
    """Get MEETING_ROOMS config for a room by name."""
    return MEETING_ROOMS.get(room_name)


def is_problem_room(room_name: str) -> bool:
    """Check if this room has known quality issues."""
    room_config = get_room_config(room_name)
    if room_config:
        return room_config.get("quality_profile") == "problematic"
    return False


def get_problem_room_quality_chance(room_name: str, participant_count: int) -> float:
    """Get chance of quality issues for a problem room.

    Higher participant count increases issues for bandwidth-limited rooms.
    """
    room_config = get_room_config(room_name)
    if not room_config:
        return 0.0

    if room_config.get("quality_profile") != "problematic":
        return 0.0

    base_prob = room_config.get("issue_probability", 0.30)

    # Scale up based on participant count for bandwidth issues
    issues = room_config.get("issues", [])
    if "bandwidth_limited" in issues and participant_count > 6:
        base_prob = min(0.80, base_prob * (1 + (participant_count - 6) * 0.1))

    return base_prob


def should_have_afterhours_activity(day: int, hour: int, days: int) -> bool:
    """Check if there should be after-hours activity (legitimate overtime).

    Placed on specific days (3, 7) to create investigatable but non-malicious events.
    NOT related to exfil scenario.
    """
    afterhours_days = [3, 7]  # Day 3 or 7 of the run
    if day not in afterhours_days:
        return False

    start_hour = MEETING_BEHAVIOR.get("afterhours_start_hour", 20)
    end_hour = MEETING_BEHAVIOR.get("afterhours_end_hour", 23)

    if not (start_hour <= hour <= end_hour):
        return False

    return random.random() < MEETING_BEHAVIOR.get("afterhours_probability", 0.02) * 10  # Higher chance on these days


# =============================================================================
# EVENT GENERATION FUNCTIONS
# =============================================================================

def generate_meeting_id() -> str:
    """Generate a Webex meeting ID."""
    return f"{random.randint(100, 999)}-{random.randint(100, 999)}-{random.randint(100, 999)}"


def generate_call_id() -> str:
    """Generate a unique call/session ID."""
    return str(uuid.uuid4())[:8].upper()


def webex_meeting_start(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    organizer: str,
    meeting_title: str,
    scheduled_duration_mins: int,
    expected_participants: int,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate meeting start event."""
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "meeting_started",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "floor": device_info["floor"],
        "meeting_id": meeting_id,
        "call_id": generate_call_id(),
        "organizer": organizer,
        "organizer_email": f"{organizer.lower().replace(' ', '.')}@theFakeTshirtCompany.com",
        "meeting_title": meeting_title,
        "scheduled_duration_mins": scheduled_duration_mins,
        "expected_participants": expected_participants,
        "connection_type": random.choice(["cloud", "on_prem_bridge", "direct"]),
        "encryption": "AES-256-GCM",
        "layout": random.choice(["speaker", "grid", "overlay", "prominent"]),
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_participant_join(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    participant: str,
    participant_email: str,
    join_method: str,
    is_external: bool = False,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate participant join event."""
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "participant_joined",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "meeting_id": meeting_id,
        "participant_name": participant,
        "participant_email": participant_email,
        "participant_type": "external" if is_external else "internal",
        "join_method": join_method,  # room_device, webex_app, browser, phone
        "video_enabled": random.choice([True, True, True, False]),  # 75% video
        "audio_enabled": True,
        "muted_on_entry": join_method == "phone",
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_participant_leave(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    participant: str,
    participant_email: str,
    duration_mins: int,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate participant leave event."""
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "participant_left",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "meeting_id": meeting_id,
        "participant_name": participant,
        "participant_email": participant_email,
        "session_duration_mins": duration_mins,
        "leave_reason": random.choice(["user_action", "meeting_ended", "network_issue", "timeout"]),
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_meeting_end(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    actual_duration_mins: int,
    total_participants: int,
    peak_participants: int,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate meeting end event."""
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "meeting_ended",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "meeting_id": meeting_id,
        "actual_duration_mins": actual_duration_mins,
        "total_participants": total_participants,
        "peak_concurrent_participants": peak_participants,
        "recording_enabled": random.random() < 0.3,  # 30% recorded
        "transcription_enabled": random.random() < 0.2,  # 20% transcribed
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_quality_metrics(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    demo_id: Optional[str] = None,
    degraded: bool = False,
    room_issues: Optional[List[str]] = None,
) -> dict:
    """Generate call quality metrics event.

    Args:
        room_issues: List of known room issues like ["wifi_congestion", "old_equipment"]
                    or ["bandwidth_limited", "echo_issues"]
    """
    # Check for problem room specific issues
    echo_detected = False

    if degraded or room_issues:
        # Base degraded metrics
        audio_mos = round(random.uniform(2.0, 3.2), 2)
        video_packet_loss = round(random.uniform(2.0, 8.0), 2)
        jitter = random.randint(30, 100)
        latency = random.randint(150, 400)

        # Room-specific issues
        if room_issues:
            if "wifi_congestion" in room_issues:
                # WiFi issues cause jitter and packet loss
                jitter = random.randint(40, 80)
                video_packet_loss = round(random.uniform(3.0, 8.0), 2)
                latency = random.randint(80, 200)

            if "old_equipment" in room_issues:
                # Old equipment: lower quality overall
                audio_mos = round(random.uniform(2.5, 3.2), 2)

            if "bandwidth_limited" in room_issues:
                # Bandwidth issues: high latency, reduced quality
                latency = random.randint(150, 300)
                video_packet_loss = round(random.uniform(2.0, 6.0), 2)

            if "echo_issues" in room_issues:
                echo_detected = True
                audio_mos = round(random.uniform(2.8, 3.5), 2)
    else:
        audio_mos = round(random.uniform(3.8, 4.5), 2)
        video_packet_loss = round(random.uniform(0.0, 0.5), 2)
        jitter = random.randint(5, 25)
        latency = random.randint(20, 80)

    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "quality_metrics",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "meeting_id": meeting_id,
        "audio": {
            "mos_score": audio_mos,
            "packet_loss_pct": round(random.uniform(0.0, 0.3), 2) if not degraded and not room_issues else round(random.uniform(1.0, 5.0), 2),
            "jitter_ms": jitter,
            "codec": "Opus",
            "echo_detected": echo_detected,
        },
        "video": {
            "resolution": "1080p" if not degraded and not room_issues else random.choice(["720p", "480p"]),
            "framerate": 30 if not degraded and not room_issues else random.choice([15, 24]),
            "packet_loss_pct": video_packet_loss,
            "bitrate_kbps": random.randint(2000, 4000) if not degraded and not room_issues else random.randint(500, 1500),
            "codec": "H.264",
        },
        "network": {
            "latency_ms": latency,
            "jitter_ms": jitter,
            "bandwidth_estimate_kbps": random.randint(5000, 15000) if not degraded and not room_issues else random.randint(1000, 4000),
        },
        "quality_rating": "good" if audio_mos >= 3.8 else "fair" if audio_mos >= 3.0 else "poor",
    }

    # Add room issues to event for debugging/analysis
    if room_issues:
        event["room_issues"] = room_issues

    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_device_health(
    ts: datetime,
    device_id: str,
    device_info: dict,
    demo_id: Optional[str] = None,
    issue: Optional[str] = None,
) -> dict:
    """Generate device health/status event."""
    model_specs = WEBEX_MODELS.get(device_info["model"], {})

    # Normal or degraded health
    if issue:
        cpu_usage = random.randint(70, 95)
        memory_usage = random.randint(75, 95)
        peripheral_status = {"camera": "ok", "microphone": "ok", "display": "ok"}
        if issue == "camera":
            peripheral_status["camera"] = "error"
        elif issue == "audio":
            peripheral_status["microphone"] = "degraded"
        elif issue == "display":
            peripheral_status["display"] = "not_detected"
        overall_status = "degraded"
    else:
        cpu_usage = random.randint(5, 35)
        memory_usage = random.randint(20, 50)
        peripheral_status = {"camera": "ok", "microphone": "ok", "display": "ok"}
        overall_status = "healthy"

    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "device_health",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "firmware_version": "RoomOS 11.2.1",
        "uptime_hours": random.randint(24, 720),  # 1-30 days
        "system_metrics": {
            "cpu_usage_pct": cpu_usage,
            "memory_usage_pct": memory_usage,
            "temperature_c": random.randint(35, 50),
        },
        "peripheral_status": peripheral_status,
        "network_status": {
            "connected": True,
            "ip_address": f"10.{10 + {'BOS': 0, 'ATL': 10, 'AUS': 20}[device_info['location']]}.60.{random.randint(10, 50)}",
            "wifi_signal_dbm": None if device_info.get("wired", True) else random.randint(-60, -40),
        },
        "overall_status": overall_status,
    }
    if issue:
        event["active_issue"] = issue
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_room_analytics(
    ts: datetime,
    device_id: str,
    device_info: dict,
    demo_id: Optional[str] = None,
    in_meeting: bool = False,
) -> dict:
    """Generate room analytics event (people count, ambient noise)."""
    capacity = device_info.get("capacity", 10)

    if in_meeting:
        people_count = random.randint(2, min(capacity, 12))
        ambient_noise = random.randint(40, 55)  # Moderate during meeting
    else:
        # Empty or pass-through
        people_count = random.choice([0, 0, 0, 1, 1, 2])  # Mostly empty
        ambient_noise = random.randint(25, 40)  # Quiet

    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "room_analytics",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "room_capacity": capacity,
        "people_count": people_count,
        "occupancy_pct": round((people_count / capacity) * 100, 1) if capacity > 0 else 0,
        "ambient_noise_db": ambient_noise,
        "air_quality": random.choice(["good", "good", "good", "moderate"]),
        "engagement_score": random.randint(70, 95) if in_meeting else None,
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def webex_wireless_share(
    ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_id: str,
    user: str,
    user_email: str,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate wireless share event."""
    event = {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "wireless_share_started",
        "device_id": device_id,
        "device_serial": device_info["serial"],
        "device_model": device_info["model"],
        "location": LOCATIONS[device_info["location"]]["full_name"],
        "location_code": device_info["location"],
        "room": device_info["room"],
        "meeting_id": meeting_id,
        "user": user,
        "user_email": user_email,
        "share_method": random.choice(["airplay", "miracast", "webex_share", "hdmi_ingest"]),
        "content_type": random.choice(["screen", "application", "document"]),
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MAIN GENERATION LOGIC
# =============================================================================

def generate_meeting_events(
    start_ts: datetime,
    device_id: str,
    device_info: dict,
    meeting_type: dict,
    organizer_user: dict,
    demo_id: Optional[str] = None,
    is_ghost: bool = False,
    late_start_mins: int = 0,
    is_overfilled: bool = False,
) -> List[dict]:
    """Generate complete set of events for a single meeting.

    Args:
        is_ghost: If True, meeting was scheduled but no one shows up (no events)
        late_start_mins: Minutes the meeting actually starts late
        is_overfilled: If True, more participants than capacity
    """
    events = []
    duration_mins = meeting_type["duration_mins"]

    # Calculate scheduled end time (for ghost meeting registration)
    scheduled_end_ts = start_ts + timedelta(minutes=duration_mins)

    # Ghost meeting - register in schedule but return empty events
    # This allows Meraki to know the room was booked but no one showed up
    # Note: Ghost meetings still need organizer for calendar correlation (invite was sent)
    if is_ghost:
        ghost_organizer_email = f"{organizer_user.username}@theFakeTshirtCompany.com"
        ghost_meeting = ScheduledMeeting(
            room=device_info.get("room", ""),
            location_code=device_info.get("location", ""),
            device_id=device_id,
            start_time=start_ts,
            end_time=scheduled_end_ts,
            scheduled_start=start_ts,
            participant_count=0,  # No one showed up
            is_ghost=True,
            late_start_mins=0,
            meeting_title=meeting_type.get("name", "Meeting") + " (No-show)",
            organizer_email=ghost_organizer_email,
            organizer_name=organizer_user.display_name,
            participants=[],  # No participants showed up
        )
        add_meeting(ghost_meeting)
        return events

    meeting_id = generate_meeting_id()
    min_participants, max_participants = meeting_type["participants"]

    # Calculate actual participants
    capacity = device_info.get("capacity", 20)
    num_participants = random.randint(min_participants, max_participants)

    if is_overfilled:
        # Add extra people beyond capacity
        extra = random.randint(2, MEETING_BEHAVIOR.get("overfilled_max_extra", 5))
        num_participants = min(num_participants + extra, capacity + 3)
    else:
        num_participants = min(num_participants, capacity)

    # Adjust start time for late meetings
    actual_start_ts = start_ts + timedelta(minutes=late_start_mins)

    # Calculate actual duration (with variance)
    actual_duration = int(duration_mins * random.uniform(0.85, 1.15))
    actual_end_ts = actual_start_ts + timedelta(minutes=actual_duration)

    organizer_name = organizer_user.display_name
    organizer_email = f"{organizer_user.username}@theFakeTshirtCompany.com"

    # Note: ScheduledMeeting is registered AFTER participants are collected
    # so we can populate the participants list for Exchange calendar integration

    # Get room config for potential issues
    room_name = device_info.get("room", "")
    room_config = get_room_config(room_name)
    room_issues = None
    has_quality_issues = False

    # Check if this is a problem room and should have issues this time
    if room_config and room_config.get("quality_profile") == "problematic":
        issue_chance = get_problem_room_quality_chance(room_name, num_participants)
        if random.random() < issue_chance:
            room_issues = room_config.get("issues", [])
            has_quality_issues = True

    # Meeting start
    events.append(webex_meeting_start(
        ts=actual_start_ts,
        device_id=device_id,
        device_info=device_info,
        meeting_id=meeting_id,
        organizer=organizer_name,
        meeting_title=meeting_type["name"],
        scheduled_duration_mins=duration_mins,
        expected_participants=num_participants,
        demo_id=demo_id,
    ))

    # Get participants (mix of internal and external)
    location = device_info["location"]
    location_users = get_users_by_location(location)

    # Organizer joins first via room device
    events.append(webex_participant_join(
        ts=actual_start_ts + timedelta(seconds=random.randint(5, 30)),
        device_id=device_id,
        device_info=device_info,
        meeting_id=meeting_id,
        participant=organizer_name,
        participant_email=organizer_email,
        join_method="room_device",
        demo_id=demo_id,
    ))

    # Other participants join
    participants_data = [(organizer_name, organizer_email, 0)]  # Track join times
    join_methods = ["webex_app", "webex_app", "webex_app", "browser", "phone"]

    for i in range(num_participants - 1):
        join_offset = random.randint(30, 300)  # 0.5-5 minutes after start

        # 20% external participants for client/vendor meetings
        is_external = random.random() < 0.2 and meeting_type["name"] in ["Client Call", "Vendor Meeting", "Interview"]

        if is_external:
            domain = random.choice(EXTERNAL_DOMAINS)
            first_names = ["Michael", "Jennifer", "David", "Sarah", "Robert", "Emily", "James", "Lisa"]
            last_names = ["Anderson", "Thompson", "Garcia", "Martinez", "Davis", "Wilson", "Taylor", "Brown"]
            participant_name = f"{random.choice(first_names)} {random.choice(last_names)}"
            participant_email = f"{participant_name.lower().replace(' ', '.')}@{domain}"
        else:
            # Internal participant from any location
            if location_users and random.random() < 0.7:  # 70% from same location
                p_user = random.choice(location_users)
            else:
                p_user = get_random_user()
            participant_name = p_user.display_name
            participant_email = f"{p_user.username}@theFakeTshirtCompany.com"

        events.append(webex_participant_join(
            ts=actual_start_ts + timedelta(seconds=join_offset),
            device_id=device_id,
            device_info=device_info,
            meeting_id=meeting_id,
            participant=participant_name,
            participant_email=participant_email,
            join_method=random.choice(join_methods),
            is_external=is_external,
            demo_id=demo_id,
        ))
        participants_data.append((participant_name, participant_email, join_offset))

    # Register meeting in shared schedule for Meraki and Exchange correlation
    # Now we have all participant data collected
    participant_emails = [email for _, email, _ in participants_data]
    scheduled_meeting = ScheduledMeeting(
        room=device_info.get("room", ""),
        location_code=device_info.get("location", ""),
        device_id=device_id,
        start_time=actual_start_ts,
        end_time=actual_end_ts,
        scheduled_start=start_ts,
        participant_count=num_participants,
        is_ghost=False,
        late_start_mins=late_start_mins,
        meeting_title=meeting_type.get("name", "Meeting"),
        organizer_email=organizer_email,
        organizer_name=organizer_name,
        participants=participant_emails,
    )
    add_meeting(scheduled_meeting)

    # Quality metrics during meeting (every 5 minutes)
    # actual_duration already calculated above for meeting schedule
    quality_checks = actual_duration // 5
    for i in range(max(1, quality_checks)):
        metric_ts = actual_start_ts + timedelta(minutes=5 * (i + 1))
        if metric_ts < actual_start_ts + timedelta(minutes=actual_duration):
            # Use room_issues if this is a problem room with issues this session
            events.append(webex_quality_metrics(
                ts=metric_ts,
                device_id=device_id,
                device_info=device_info,
                meeting_id=meeting_id,
                demo_id=demo_id,
                degraded=has_quality_issues or random.random() < 0.05,
                room_issues=room_issues if has_quality_issues else None,
            ))

    # Room analytics during meeting
    events.append(webex_room_analytics(
        ts=actual_start_ts + timedelta(minutes=random.randint(2, min(10, actual_duration))),
        device_id=device_id,
        device_info=device_info,
        demo_id=demo_id,
        in_meeting=True,
    ))

    # Wireless share event (30% of meetings)
    if random.random() < 0.3 and actual_duration > 5:
        share_user = random.choice(participants_data)
        events.append(webex_wireless_share(
            ts=actual_start_ts + timedelta(minutes=random.randint(3, max(4, actual_duration - 2))),
            device_id=device_id,
            device_info=device_info,
            meeting_id=meeting_id,
            user=share_user[0],
            user_email=share_user[1],
            demo_id=demo_id,
        ))

    # Participants leave (some early, most at end)
    end_ts = actual_start_ts + timedelta(minutes=actual_duration)
    peak_participants = len(participants_data)

    for p_name, p_email, join_offset in participants_data:
        if random.random() < 0.1:  # 10% leave early
            leave_offset = random.randint(
                int(actual_duration * 0.5),
                int(actual_duration * 0.9)
            )
        else:
            leave_offset = actual_duration + random.randint(0, 30)  # At end or slightly after

        session_duration = (leave_offset * 60 - join_offset) // 60  # Minutes in meeting
        events.append(webex_participant_leave(
            ts=actual_start_ts + timedelta(minutes=leave_offset),
            device_id=device_id,
            device_info=device_info,
            meeting_id=meeting_id,
            participant=p_name,
            participant_email=p_email,
            duration_mins=max(1, session_duration),
            demo_id=demo_id,
        ))

    # Meeting end
    events.append(webex_meeting_end(
        ts=end_ts + timedelta(seconds=random.randint(30, 120)),
        device_id=device_id,
        device_info=device_info,
        meeting_id=meeting_id,
        actual_duration_mins=actual_duration,
        total_participants=len(participants_data),
        peak_participants=peak_participants,
        demo_id=demo_id,
    ))

    return events


def generate_webex_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Webex collaboration device logs."""

    # Clear shared meeting schedule (for Meraki correlation)
    clear_schedule()

    # Parse scenarios (demo_id is now set per-meeting based on organizer)
    active_scenarios = expand_scenarios(scenarios)

    # Output setup
    if output_file is None:
        output_path = get_output_path("cloud", "webex_events.json")
    else:
        output_path = Path(output_file)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print("=" * 60)
        print("Cisco Webex Collaboration Device Log Generator")
        print("=" * 60)
        print(f"Locations: {', '.join(LOCATIONS.keys())}")
        print(f"Devices: {len(WEBEX_DEVICES)}")
        print(f"Date range: {start_date} + {days} days")
        print(f"Scale: {scale}")
        print(f"Scenarios: {scenarios}")
        print("-" * 60)

    events = []
    current_date = datetime.strptime(start_date, "%Y-%m-%d")

    for day_offset in range(days):
        day_date = current_date + timedelta(days=day_offset)
        day_str = day_date.strftime("%Y-%m-%d")
        weekend = is_weekend(day_date)

        if not quiet:
            print(f"  Day {day_offset + 1}/{days}: {day_str} ({'weekend' if weekend else 'weekday'})", end="\r")

        # Generate meetings for each device
        for device_id, device_info in WEBEX_DEVICES.items():
            location = device_info["location"]
            capacity = device_info.get("capacity", 10)
            room_type = device_info.get("room_type", "Conference Room")

            # Meetings per day based on room type and capacity
            if weekend:
                base_meetings = random.randint(0, 1)  # Rare weekend meetings
            elif room_type == "Boardroom":
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

            # Generate meetings spread across business hours (8 AM - 6 PM)
            meeting_hours = list(range(8, 18))
            random.shuffle(meeting_hours)

            for i in range(min(num_meetings, len(meeting_hours))):
                hour = meeting_hours[i]
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

                # Get organizer from location
                location_users = get_users_by_location(location)
                organizer = random.choice(location_users) if location_users else get_random_user()

                # Check for meeting variations
                ghost = is_ghost_meeting()
                late_delay = get_late_start_delay()
                overfilled = is_overfilled_meeting()

                # Determine demo_id based on organizer (only exfil-related users on day 1-14)
                meeting_demo_id = should_tag_meeting_exfil(organizer.username, day_offset, active_scenarios)

                # Generate meeting events
                meeting_events = generate_meeting_events(
                    start_ts=meeting_start,
                    device_id=device_id,
                    device_info=device_info,
                    meeting_type=meeting_type,
                    organizer_user=organizer,
                    demo_id=meeting_demo_id,
                    is_ghost=ghost,
                    late_start_mins=late_delay,
                    is_overfilled=overfilled,
                )
                events.extend(meeting_events)

            # Device health checks (every 4 hours) - no demo_id (not scenario-specific)
            for hour in [6, 10, 14, 18, 22]:
                if hour < 6 and weekend:
                    continue
                health_ts = day_date.replace(hour=hour, minute=random.randint(0, 5))
                # Small chance of device issues
                issue = None
                if random.random() < 0.02:  # 2% chance
                    issue = random.choice(["camera", "audio", "display"])
                events.append(webex_device_health(
                    ts=health_ts,
                    device_id=device_id,
                    device_info=device_info,
                    demo_id=None,  # Device health is not scenario-specific
                    issue=issue,
                ))

            # Room analytics when not in meeting (hourly during business hours) - no demo_id
            for hour in range(7, 20):
                if weekend and hour not in range(10, 16):
                    continue
                analytics_ts = day_date.replace(hour=hour, minute=random.randint(30, 59))
                events.append(webex_room_analytics(
                    ts=analytics_ts,
                    device_id=device_id,
                    device_info=device_info,
                    demo_id=None,  # Room analytics is not scenario-specific
                    in_meeting=False,
                ))

        # After-hours activity (legitimate overtime work, not exfil related)
        # Only on specific days (3, 7) in preferred smaller rooms
        preferred_rooms = MEETING_BEHAVIOR.get("afterhours_preferred_rooms", ["Back Bay", "North End", "Buckhead"])

        for device_id, device_info in WEBEX_DEVICES.items():
            room_name = device_info.get("room", "")
            if room_name not in preferred_rooms:
                continue

            for hour in range(20, 24):
                if should_have_afterhours_activity(day_offset, hour, days):
                    location_users = get_users_by_location(device_info["location"])
                    if not location_users:
                        continue

                    overtime_user = random.choice(location_users)
                    afterhours_ts = day_date.replace(hour=hour, minute=random.randint(15, 45))

                    # Generate a short ad-hoc meeting (no demo_id - this is NOT exfil related)
                    adhoc_meeting_type = {"name": "Ad-hoc Call", "duration_mins": 30, "participants": (1, 2), "recurring": False}

                    meeting_events = generate_meeting_events(
                        start_ts=afterhours_ts,
                        device_id=device_id,
                        device_info=device_info,
                        meeting_type=adhoc_meeting_type,
                        organizer_user=overtime_user,
                        demo_id=None,  # NOT related to any scenario
                    )
                    events.extend(meeting_events)

    # Sort events by timestamp
    events.sort(key=lambda x: x["timestamp"])

    # Write output
    with open(output_path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    if not quiet:
        print(f"\n{'=' * 60}")
        print(f"[Webex] Complete! {len(events):,} events written to {output_path}")

    return len(events)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate Cisco Webex collaboration device logs"
    )
    parser.add_argument(
        "--start-date",
        default=DEFAULT_START_DATE,
        help=f"Start date (default: {DEFAULT_START_DATE})",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        help=f"Number of days (default: {DEFAULT_DAYS})",
    )
    parser.add_argument(
        "--scale",
        type=float,
        default=DEFAULT_SCALE,
        help=f"Volume scale factor (default: {DEFAULT_SCALE})",
    )
    parser.add_argument(
        "--scenarios",
        default="none",
        help="Scenarios to include: none, exfil, all",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: output/cloud/webex_events.json)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output",
    )

    args = parser.parse_args()

    generate_webex_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )


if __name__ == "__main__":
    main()
