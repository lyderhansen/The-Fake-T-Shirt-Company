#!/usr/bin/env python3
"""
Cisco Webex Add-on for Splunk (REST API) Log Generator.
Generates JSON events matching the Splunk TA for Cisco Webex format.

Based on: https://github.com/splunk/ta_cisco_webex_add_on_for_splunk

Sourcetypes generated:
  - cisco:webex:meetings (scheduled meetings)
  - cisco:webex:admin:audit:events (admin audit events)
  - cisco:webex:security:audit:events (login/logout events)
  - cisco:webex:meeting:qualities (meeting quality metrics)
  - cisco:webex:call:detailed_history (call detail records)

Timestamp format: ISO 8601 (YYYY-MM-DDTHH:MM:SS.sssZ)
"""

import argparse
import base64
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add, get_hour_activity_level, is_weekend
from shared.company import (
    USERS, get_random_user, LOCATIONS, get_users_by_location, NETWORK_CONFIG,
    TENANT, ORG_NAME, TENANT_ID,
)
from shared.meeting_schedule import _meeting_schedule
from scenarios.registry import expand_scenarios

# =============================================================================
# CONSTANTS
# =============================================================================

WEBEX_SITE_URL = "theFakeTshirtCompany.webex.com"
WEBEX_ORG_ID = base64.b64encode(f"ciscospark://us/ORGANIZATION/{TENANT_ID}".encode()).decode()

# Meeting templates
MEETING_TEMPLATES = [
    {"name": "Team Standup", "agenda": "Daily sync meeting", "duration": (15, 20), "participants": (3, 8)},
    {"name": "Project Review", "agenda": "Review project progress and blockers", "duration": (45, 60), "participants": (4, 12)},
    {"name": "Sprint Planning", "agenda": "Plan upcoming sprint tasks", "duration": (90, 120), "participants": (5, 15)},
    {"name": "1:1 Meeting", "agenda": "Weekly one-on-one discussion", "duration": (25, 30), "participants": (2, 2)},
    {"name": "All Hands", "agenda": "Company-wide update meeting", "duration": (55, 60), "participants": (15, 40)},
    {"name": "Training Session", "agenda": "Skills development session", "duration": (60, 90), "participants": (6, 16)},
    {"name": "Client Call", "agenda": "Client meeting and updates", "duration": (30, 45), "participants": (2, 6)},
    {"name": "Budget Review", "agenda": "Quarterly budget review", "duration": (45, 60), "participants": (3, 8)},
    {"name": "Design Review", "agenda": "Review design proposals", "duration": (40, 50), "participants": (3, 10)},
    {"name": "Weekly Status", "agenda": "Weekly team status update", "duration": (25, 30), "participants": (5, 12)},
]

# Admin audit event categories and actions
ADMIN_AUDIT_CATEGORIES = {
    "USERS": [
        ("User created", "created user"),
        ("User updated", "updated user settings for"),
        ("User deactivated", "deactivated user"),
        ("User reactivated", "reactivated user"),
    ],
    "GROUPS": [
        ("Group created", "created group"),
        ("Group updated", "updated group"),
        ("Group member added", "added member to group"),
        ("Group member removed", "removed member from group"),
    ],
    "MEETINGS": [
        ("Meeting settings updated", "updated meeting settings"),
        ("Recording deleted", "deleted meeting recording"),
        ("Meeting policy changed", "changed meeting policy for"),
    ],
    "COMPLIANCE": [
        ("Retention policy updated", "updated retention policy"),
        ("Data export requested", "requested data export for"),
        ("Legal hold applied", "applied legal hold on"),
    ],
    "DEVICES": [
        ("Device registered", "registered device"),
        ("Device removed", "removed device"),
        ("Device settings changed", "changed settings for device"),
    ],
}

# Security audit event types (logins)
SECURITY_AUDIT_EVENTS = [
    ("LOGINS", "A user logged in", "logged into organization"),
    ("LOGINS", "A user logged out", "logged out of organization"),
    ("LOGINS", "Login failed", "failed login attempt for organization"),
]

# Correlated client profiles: (clientType, osType, osVersions, hardwareTypes, networkTypes, weight)
_CLIENT_PROFILES = [
    {
        "clientType": "Webex Desktop", "osType": "Windows",
        "osVersions": ["10.0.19045", "10.0.22621", "10.0.22631"],
        "hardwareTypes": ["Dell Latitude 5520", "Lenovo ThinkPad X1", "HP EliteBook 840"],
        "networkTypes": ["wifi", "ethernet"], "weight": 35,
    },
    {
        "clientType": "Webex Desktop", "osType": "macOS",
        "osVersions": ["13.6.1", "14.2.1", "14.3.0"],
        "hardwareTypes": ["MacBook Pro", "MacBook Air", "Mac Studio"],
        "networkTypes": ["wifi", "ethernet"], "weight": 20,
    },
    {
        "clientType": "Webex Mobile (iOS)", "osType": "iOS",
        "osVersions": ["17.2.1", "17.3.0", "17.4.0"],
        "hardwareTypes": ["iPhone 14", "iPhone 15 Pro", "iPad Pro"],
        "networkTypes": ["wifi", "cellular"], "weight": 15,
    },
    {
        "clientType": "Webex Mobile (Android)", "osType": "Android",
        "osVersions": ["13", "14"],
        "hardwareTypes": ["Samsung Galaxy S23", "Google Pixel 8", "Samsung Galaxy A54"],
        "networkTypes": ["wifi", "cellular"], "weight": 10,
    },
    {
        "clientType": "Web Browser", "osType": "Windows",
        "osVersions": ["10.0.19045", "10.0.22621", "10.0.22631"],
        "hardwareTypes": ["Dell Latitude 5520", "Lenovo ThinkPad X1", "HP EliteBook 840"],
        "networkTypes": ["wifi", "ethernet"], "weight": 12,
    },
    {
        "clientType": "Web Browser", "osType": "macOS",
        "osVersions": ["13.6.1", "14.2.1", "14.3.0"],
        "hardwareTypes": ["MacBook Pro", "MacBook Air"],
        "networkTypes": ["wifi", "ethernet"], "weight": 8,
    },
]

# Flat client type list for call history records
_CALL_CLIENT_TYPES = ["Webex Desktop", "Webex Mobile (iOS)", "Webex Mobile (Android)", "Web Browser"]
CLIENT_VERSIONS = ["43.12.0.1234", "43.11.0.5678", "43.10.0.9012", "44.1.0.3456"]
NETWORK_TYPES = ["wifi", "ethernet", "cellular"]
SERVER_REGIONS = ["US East", "US West", "EU West", "APAC"]


def _pick_client_profile() -> dict:
    """Pick a correlated client profile (clientType + OS + hardware)."""
    weights = [p["weight"] for p in _CLIENT_PROFILES]
    return random.choices(_CLIENT_PROFILES, weights=weights, k=1)[0]

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

# Exfil scenario users
EXFIL_USERS = {"jessica.brown", "alex.miller"}

# Admin users for audit events
ADMIN_USERS = {"mike.johnson", "jessica.brown", "david.chen"}


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())


def generate_webex_id(prefix: str = "PEOPLE") -> str:
    """Generate a Webex-style base64-encoded ID.

    Webex IDs are base64-encoded ciscospark:// URIs.
    e.g. ciscospark://us/PEOPLE/<uuid> → base64 encoded string.
    """
    uri = f"ciscospark://us/{prefix}/{generate_uuid()}"
    return base64.b64encode(uri.encode()).decode()


def ts_iso8601(dt: datetime) -> str:
    """Format timestamp as ISO 8601 with milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def ts_iso8601_simple(dt: datetime) -> str:
    """Format timestamp as ISO 8601 without milliseconds."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_user_ip(user) -> str:
    """Get user's IP address."""
    return user.ip_address


def get_public_ip() -> str:
    """Generate a realistic public IP."""
    return f"203.0.113.{random.randint(1, 254)}"


# =============================================================================
# MEETING RECORD GENERATION
# =============================================================================

def generate_meeting_record(
    user,
    start_time: datetime,
    end_time: datetime,
    template: dict,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate a meeting record (cisco:webex:meetings)."""
    meeting_number = str(random.randint(100000000, 999999999))

    record = {
        "id": generate_uuid(),
        "meetingNumber": meeting_number,
        "title": template["name"],
        "agenda": template["agenda"],
        "meetingType": "scheduledMeeting",
        "state": "ended",
        "timezone": "America/New_York",
        "start": ts_iso8601_simple(start_time),
        "end": ts_iso8601_simple(end_time),
        "hostUserId": generate_webex_id("PEOPLE"),
        "hostDisplayName": user.display_name,
        "hostEmail": f"{user.username}@{TENANT}",
        "hostKey": str(random.randint(100000, 999999)),
        "siteUrl": WEBEX_SITE_URL,
        "webLink": f"https://{WEBEX_SITE_URL}/meet/{user.username}",
        "sipAddress": f"{meeting_number}@{WEBEX_SITE_URL}",
        "enabledJoinBeforeHost": random.choice([True, False]),
        "joinBeforeHostMinutes": random.choice([5, 10, 15]),
        "enabledAutoRecordMeeting": random.choice([True, False]),
    }

    if demo_id:
        record["demo_id"] = demo_id

    return record


# =============================================================================
# ADMIN AUDIT EVENT GENERATION
# =============================================================================

def generate_admin_audit_event(
    actor_user,
    target_user,
    event_time: datetime,
    category: str,
    action: Tuple[str, str],
    demo_id: Optional[str] = None,
) -> dict:
    """Generate an admin audit event (cisco:webex:admin:audit:events)."""
    event_description, action_verb = action

    record = {
        "id": generate_uuid(),
        "actorId": generate_webex_id("PEOPLE"),
        "actorOrgId": WEBEX_ORG_ID,
        "created": ts_iso8601(event_time),
        "data": {
            "actorName": actor_user.display_name,
            "actorEmail": f"{actor_user.username}@{TENANT}",
            "actorOrgName": ORG_NAME,
            "actorIp": get_user_ip(actor_user),
            "actorUserAgent": random.choice(USER_AGENTS),
            "adminRoles": ["Full_Admin"] if actor_user.username in ADMIN_USERS else ["User"],
            "eventCategory": category,
            "eventDescription": event_description,
            "targetId": generate_webex_id("PEOPLE") if target_user else generate_uuid(),
            "targetType": "USER" if target_user else "SETTING",
            "targetName": target_user.display_name if target_user else "System Setting",
            "targetOrgId": WEBEX_ORG_ID,
            "targetOrgName": ORG_NAME,
            "trackingId": f"ATLAS_{generate_uuid()}",
            "actionText": f"{actor_user.display_name} {action_verb} {target_user.display_name if target_user else ''}"
        }
    }

    if demo_id:
        record["demo_id"] = demo_id

    return record


# =============================================================================
# SECURITY AUDIT EVENT GENERATION
# =============================================================================

def generate_security_audit_event(
    user,
    event_time: datetime,
    event_type: Tuple[str, str, str],
    success: bool = True,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate a security audit event (cisco:webex:security:audit:events)."""
    category, description, action_verb = event_type

    record = {
        "id": generate_uuid(),
        "created": ts_iso8601(event_time),
        "actorId": generate_webex_id("PEOPLE"),
        "actorOrgId": WEBEX_ORG_ID,
        "data": {
            "actorName": user.display_name,
            "actorEmail": f"{user.username}@{TENANT}",
            "actorOrgName": ORG_NAME,
            "actorIp": get_user_ip(user),
            "actorUserAgent": random.choice(USER_AGENTS),
            "eventCategory": category,
            "eventDescription": description,
            "actionText": f"{user.display_name} {action_verb} {ORG_NAME}",
            "trackingId": f"ATLAS_{generate_uuid()}"
        }
    }

    if demo_id:
        record["demo_id"] = demo_id

    return record


# =============================================================================
# MEETING QUALITY GENERATION
# =============================================================================

def generate_quality_metrics(duration_mins: int) -> Tuple[List[dict], List[dict]]:
    """Generate audio and video quality metrics arrays."""
    # Generate samples every 60 seconds
    num_samples = max(1, duration_mins)

    audio_in = [{
        "samplingInterval": 60,
        "packetLoss": [round(random.uniform(0, 2), 1) for _ in range(num_samples)],
        "latency": [random.randint(30, 80) for _ in range(num_samples)],
        "jitter": [random.randint(2, 15) for _ in range(num_samples)],
        "codec": random.choice(["opus", "G.722", "G.711"]),
        "transportType": random.choice(["UDP", "TCP"])
    }]

    video_in = [{
        "samplingInterval": 60,
        "packetLoss": [round(random.uniform(0, 3), 1) for _ in range(num_samples)],
        "latency": [random.randint(40, 100) for _ in range(num_samples)],
        "jitter": [random.randint(5, 20) for _ in range(num_samples)],
        "resolutionHeight": [random.choice([720, 1080]) for _ in range(num_samples)],
        "frameRate": [random.choice([24, 30]) for _ in range(num_samples)],
        "mediaBitRate": [random.randint(1500, 4000) for _ in range(num_samples)],
        "codec": random.choice(["H.264", "VP8", "VP9"]),
        "transportType": random.choice(["UDP", "TCP"])
    }]

    return audio_in, video_in


def generate_meeting_quality_record(
    user,
    meeting_id: str,
    join_time: datetime,
    leave_time: datetime,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate a meeting quality record (cisco:webex:meeting:qualities)."""
    duration_mins = int((leave_time - join_time).total_seconds() / 60)

    # Pick correlated client profile (clientType + OS + hardware)
    profile = _pick_client_profile()

    audio_in, video_in = generate_quality_metrics(duration_mins)

    record = {
        "meetingInstanceId": meeting_id,
        "webexUserName": user.display_name,
        "webexUserEmail": f"{user.username}@{TENANT}",
        "joinTime": ts_iso8601(join_time),
        "leaveTime": ts_iso8601(leave_time),
        "joinMeetingTime": str(random.randint(3, 15)),
        "clientType": profile["clientType"],
        "clientVersion": random.choice(CLIENT_VERSIONS),
        "osType": profile["osType"],
        "osVersion": random.choice(profile["osVersions"]),
        "hardwareType": random.choice(profile["hardwareTypes"]),
        "speakerName": "Speakers (Realtek Audio)",
        "networkType": random.choice(profile["networkTypes"]),
        "localIP": get_user_ip(user),
        "publicIP": get_public_ip(),
        "camera": random.choice(["Integrated Webcam", "Logitech C920", "Logitech Brio"]),
        "microphone": "Microphone (Realtek Audio)",
        "serverRegion": random.choice(SERVER_REGIONS),
        "participantId": generate_uuid(),
        "participantSessionId": generate_uuid(),
        "audioIn": audio_in,
        "videoIn": video_in,
        "resources": {
            "processAverageCPU": [random.randint(10, 30) for _ in range(min(5, duration_mins))],
            "processMaxCPU": [random.randint(25, 50) for _ in range(min(5, duration_mins))],
            "systemAverageCPU": [random.randint(30, 60) for _ in range(min(5, duration_mins))],
            "systemMaxCPU": [random.randint(50, 80) for _ in range(min(5, duration_mins))]
        }
    }

    if demo_id:
        record["demo_id"] = demo_id

    return record


# =============================================================================
# CALL HISTORY GENERATION
# =============================================================================

def generate_call_history_record(
    caller_user,
    called_user,
    start_time: datetime,
    duration_secs: int,
    demo_id: Optional[str] = None,
) -> dict:
    """Generate a call history record (cisco:webex:call:detailed_history)."""
    answered = random.random() > 0.1  # 90% answer rate

    record = {
        "Call ID": f"SSE{random.randint(10**18, 10**19 - 1)}@{get_user_ip(caller_user)}",
        "Call outcome": "Success" if answered else "NoAnswer",
        "Call outcome reason": "Normal" if answered else "NoAnswer",
        "Call type": random.choice(["SIP_ENTERPRISE", "SIP_NATIONAL", "WEBEX_CALLING"]),
        "Called line ID": called_user.display_name,
        "Called number": f"+1555{random.randint(1000000, 9999999)}",
        "Calling line ID": caller_user.display_name,
        "Calling number": f"+1555{random.randint(1000000, 9999999)}",
        "Client type": random.choice(_CALL_CLIENT_TYPES),
        "Client version": random.choice(CLIENT_VERSIONS),
        "Correlation ID": generate_uuid(),
        "Department ID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"dept:{caller_user.department}")),
        "Device MAC": caller_user.mac_address.replace(":", ""),  # Webex API format: no colons
        "Dialed digits": f"555{random.randint(1000, 9999)}",
        "Direction": "ORIGINATING",
        "Duration": duration_secs if answered else 0,
        "Start time": ts_iso8601(start_time),
        "Answer time": ts_iso8601(start_time + timedelta(seconds=random.randint(5, 20))) if answered else "",
        "Answer indicator": "Yes" if answered else "No",
        "Answered": str(answered).lower(),
        "User": f"{caller_user.username}@{TENANT}",
        "User type": "User"
    }

    if demo_id:
        record["demo_id"] = demo_id

    return record


# =============================================================================
# DAILY EVENT GENERATION
# =============================================================================

def generate_events_for_day(
    base_date: str,
    day: int,
    scale: float,
    active_scenarios: List[str],
) -> Tuple[List[dict], List[dict], List[dict], List[dict], List[dict]]:
    """Generate all event types for a single day."""
    meetings = []
    admin_audits = []
    security_audits = []
    meeting_qualities = []
    call_histories = []

    dt = date_add(base_date, day)
    is_wknd = is_weekend(dt)

    # Determine demo_id for exfil scenario
    demo_id = "exfil" if "exfil" in active_scenarios and day <= 13 else None

    # === Security Audit Events (Logins) ===
    # Generate login events for all users during work hours
    if is_wknd:
        login_count = int(random.randint(22, 44) * scale)
    else:
        login_count = int(random.randint(165, 275) * scale)

    for _ in range(login_count):
        user = get_random_user()
        hour = random.choices(
            range(6, 22),
            weights=[5, 20, 40, 50, 50, 50, 30, 50, 50, 50, 40, 20, 15, 10, 5, 5]
        )[0]
        minute = random.randint(0, 59)
        login_time = dt.replace(hour=hour, minute=minute, second=random.randint(0, 59))

        # Login event
        event_type = SECURITY_AUDIT_EVENTS[0]  # Login
        user_demo_id = demo_id if user.username in EXFIL_USERS else None
        security_audits.append(generate_security_audit_event(
            user, login_time, event_type, success=True, demo_id=user_demo_id
        ))

        # Logout event (later in the day)
        logout_hour = min(22, hour + random.randint(4, 10))
        logout_time = dt.replace(hour=logout_hour, minute=random.randint(0, 59))
        event_type = SECURITY_AUDIT_EVENTS[1]  # Logout
        security_audits.append(generate_security_audit_event(
            user, logout_time, event_type, success=True, demo_id=user_demo_id
        ))

    # === Admin Audit Events ===
    if not is_wknd:
        admin_count = int(random.randint(11, 33) * scale)

        # During exfil lateral movement phase (days 5-7), Jessica does more admin actions
        if demo_id and 5 <= day <= 7:
            admin_count += 20

        for _ in range(admin_count):
            # Pick admin user (weighted towards real admins)
            admin_users_list = [u for u in USERS.values() if u.username in ADMIN_USERS]
            if admin_users_list:
                actor = random.choice(admin_users_list)
            else:
                actor = get_random_user()

            target = get_random_user()

            # Pick random category and action
            category = random.choice(list(ADMIN_AUDIT_CATEGORIES.keys()))
            action = random.choice(ADMIN_AUDIT_CATEGORIES[category])

            hour = random.randint(8, 18)
            event_time = dt.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

            actor_demo_id = demo_id if actor.username in EXFIL_USERS else None
            admin_audits.append(generate_admin_audit_event(
                actor, target, event_time, category, action, demo_id=actor_demo_id
            ))

    # === Meetings ===
    # Agenda lookup for meeting titles from shared schedule
    _AGENDA_MAP = {t["name"]: t["agenda"] for t in MEETING_TEMPLATES}
    _DEFAULT_AGENDA = "Scheduled meeting"

    # Try shared schedule first (populated by generate_webex.py in Phase 1)
    if _meeting_schedule:
        target_date = dt.date() if hasattr(dt, 'date') else dt
        for key, scheduled_list in _meeting_schedule.items():
            for scheduled in scheduled_list:
                # Filter to this day
                meeting_date = scheduled.start_time.date() if hasattr(scheduled.start_time, 'date') else scheduled.start_time
                if meeting_date != target_date:
                    continue
                # Skip ghosts and walk-ins
                if scheduled.is_ghost or scheduled.is_walkin:
                    continue

                # Look up host user
                host_username = scheduled.organizer_email.split("@")[0] if scheduled.organizer_email else ""
                host_user = USERS.get(host_username)
                if not host_user:
                    continue

                # Build meeting record from shared schedule data
                meeting_demo_id = demo_id if host_username in EXFIL_USERS else None
                agenda = _AGENDA_MAP.get(scheduled.meeting_title, _DEFAULT_AGENDA)
                template_for_record = {"name": scheduled.meeting_title, "agenda": agenda}
                meeting_record = generate_meeting_record(
                    host_user, scheduled.start_time, scheduled.end_time,
                    template_for_record, demo_id=meeting_demo_id
                )
                meetings.append(meeting_record)

                # Generate quality records for participants from shared schedule
                participants_for_quality = [host_user]
                used_usernames = {host_username}
                for p_email in scheduled.participants:
                    p_username = p_email.split("@")[0] if "@" in p_email else p_email
                    if p_username == host_username:
                        continue
                    p_user = USERS.get(p_username)
                    if p_user and p_username not in used_usernames:
                        participants_for_quality.append(p_user)
                        used_usernames.add(p_username)

                for participant in participants_for_quality:
                    join_offset = timedelta(minutes=random.randint(-3, 5))
                    leave_offset = timedelta(minutes=random.randint(-5, 3))
                    join_time = scheduled.start_time + join_offset
                    leave_time = scheduled.end_time + leave_offset

                    if join_time < leave_time:
                        part_demo_id = demo_id if participant.username in EXFIL_USERS else None
                        meeting_qualities.append(generate_meeting_quality_record(
                            participant, meeting_record["id"], join_time, leave_time, demo_id=part_demo_id
                        ))
    else:
        # Fallback: independent generation (when running standalone without webex)
        if is_wknd:
            meeting_count = int(random.randint(3, 6) * scale)
        else:
            meeting_count = int(random.randint(22, 44) * scale)

        for _ in range(meeting_count):
            user = get_random_user()
            template = random.choice(MEETING_TEMPLATES)

            hour = random.randint(8, 17)
            minute = random.choice([0, 15, 30, 45])
            start_time = dt.replace(hour=hour, minute=minute, second=0)

            duration_mins = random.randint(template["duration"][0], template["duration"][1])
            end_time = start_time + timedelta(minutes=duration_mins)

            meeting_demo_id = demo_id if user.username in EXFIL_USERS else None
            meeting_record = generate_meeting_record(user, start_time, end_time, template, demo_id=meeting_demo_id)
            meetings.append(meeting_record)

            # Generate quality records for participants
            num_participants = random.randint(template["participants"][0], template["participants"][1])
            participants = [user]
            used_usernames = {user.username}

            for _ in range(num_participants - 1):
                participant = get_random_user()
                if participant.username not in used_usernames:
                    participants.append(participant)
                    used_usernames.add(participant.username)

            for participant in participants:
                join_offset = timedelta(minutes=random.randint(-3, 5))
                leave_offset = timedelta(minutes=random.randint(-5, 3))
                join_time = start_time + join_offset
                leave_time = end_time + leave_offset

                if join_time < leave_time:
                    part_demo_id = demo_id if participant.username in EXFIL_USERS else None
                    meeting_qualities.append(generate_meeting_quality_record(
                        participant, meeting_record["id"], join_time, leave_time, demo_id=part_demo_id
                    ))

    # === Call History ===
    if not is_wknd:
        call_count = int(random.randint(33, 77) * scale)

        for _ in range(call_count):
            caller = get_random_user()
            called = get_random_user()

            if caller.username != called.username:
                hour = random.randint(8, 18)
                start_time = dt.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
                duration = random.randint(30, 600)  # 30 seconds to 10 minutes

                call_demo_id = demo_id if caller.username in EXFIL_USERS else None
                call_histories.append(generate_call_history_record(
                    caller, called, start_time, duration, demo_id=call_demo_id
                ))

    return meetings, admin_audits, security_audits, meeting_qualities, call_histories


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_webex_api_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    progress_callback=None,
    quiet: bool = False,
) -> int:
    """Generate Webex REST API logs.

    Generates five output files:
    - webex_api_meetings.json (cisco:webex:meetings)
    - webex_api_admin_audit.json (cisco:webex:admin:audit:events)
    - webex_api_security_audit.json (cisco:webex:security:audit:events)
    - webex_api_meeting_qualities.json (cisco:webex:meeting:qualities)
    - webex_api_call_history.json (cisco:webex:call:detailed_history)
    """

    # Output paths
    if output_file:
        output_dir = Path(output_file).parent
    else:
        output_dir = get_output_path("cloud", "webex/dummy.json").parent
    output_dir.mkdir(parents=True, exist_ok=True)

    meetings_file = output_dir / "webex_api_meetings.json"
    admin_audit_file = output_dir / "webex_api_admin_audit.json"
    security_audit_file = output_dir / "webex_api_security_audit.json"
    meeting_qualities_file = output_dir / "webex_api_meeting_qualities.json"
    call_history_file = output_dir / "webex_api_call_history.json"

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Webex Add-on (REST API) Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_dir}/webex_api_*.json", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Collect all records
    all_meetings = []
    all_admin_audits = []
    all_security_audits = []
    all_meeting_qualities = []
    all_call_histories = []

    for day in range(days):
        if progress_callback:
            progress_callback("webex_api", day + 1, days)
        dt = date_add(start_date, day)

        if not quiet:
            print(f"  [Webex API] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        meetings, admin_audits, security_audits, meeting_qualities, call_histories = generate_events_for_day(
            start_date, day, scale, active_scenarios
        )

        all_meetings.extend(meetings)
        all_admin_audits.extend(admin_audits)
        all_security_audits.extend(security_audits)
        all_meeting_qualities.extend(meeting_qualities)
        all_call_histories.extend(call_histories)

        if not quiet:
            print(f"  [Webex API] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort by timestamp
    all_meetings.sort(key=lambda x: x["start"])
    all_admin_audits.sort(key=lambda x: x["created"])
    all_security_audits.sort(key=lambda x: x["created"])
    all_meeting_qualities.sort(key=lambda x: x["joinTime"])
    all_call_histories.sort(key=lambda x: x["Start time"])

    # Write files
    with open(meetings_file, "w") as f:
        for record in all_meetings:
            f.write(json.dumps(record) + "\n")

    with open(admin_audit_file, "w") as f:
        for record in all_admin_audits:
            f.write(json.dumps(record) + "\n")

    with open(security_audit_file, "w") as f:
        for record in all_security_audits:
            f.write(json.dumps(record) + "\n")

    with open(meeting_qualities_file, "w") as f:
        for record in all_meeting_qualities:
            f.write(json.dumps(record) + "\n")

    with open(call_history_file, "w") as f:
        for record in all_call_histories:
            f.write(json.dumps(record) + "\n")

    total_records = (
        len(all_meetings) + len(all_admin_audits) + len(all_security_audits) +
        len(all_meeting_qualities) + len(all_call_histories)
    )
    file_counts = {
        "cloud/webex/webex_api_meetings.json": len(all_meetings),
        "cloud/webex/webex_api_admin_audit.json": len(all_admin_audits),
        "cloud/webex/webex_api_security_audit.json": len(all_security_audits),
        "cloud/webex/webex_api_meeting_qualities.json": len(all_meeting_qualities),
        "cloud/webex/webex_api_call_history.json": len(all_call_histories),
    }

    if not quiet:
        print(f"  [Webex API] Complete! {total_records:,} records written:", file=sys.stderr)
        print(f"    - {meetings_file.name}: {len(all_meetings):,} meetings", file=sys.stderr)
        print(f"    - {admin_audit_file.name}: {len(all_admin_audits):,} admin audit events", file=sys.stderr)
        print(f"    - {security_audit_file.name}: {len(all_security_audits):,} security audit events", file=sys.stderr)
        print(f"    - {meeting_qualities_file.name}: {len(all_meeting_qualities):,} quality records", file=sys.stderr)
        print(f"    - {call_history_file.name}: {len(all_call_histories):,} call records", file=sys.stderr)

    return {"total": total_records, "files": file_counts}


def main():
    parser = argparse.ArgumentParser(description="Generate Webex REST API logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", "-o")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_webex_api_logs(
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
