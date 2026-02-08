#!/usr/bin/env python3
"""
Exchange Message Tracking Log Generator.
Generates realistic email flow logs in JSON format with natural volume variation.

Includes exfil scenario support:
  - Phishing campaign targeting Jessica Brown (IT Admin)
  - Credential harvesting and mailbox compromise
  - Auto-forwarding rule for ongoing exfiltration

Output format: JSON (one event per line)
Splunk sourcetype: ms:o365:reporting:messagetrace
"""

import argparse
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import Config, DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import TimeUtils, ts_iso, date_add, calc_natural_events
from shared.company import (
    Company, TENANT, USERS, USER_KEYS, get_random_user,
    EXTERNAL_MAIL_DOMAINS, PARTNER_DOMAINS,
    EMAIL_SUBJECTS_INTERNAL, EMAIL_SUBJECTS_EXTERNAL,
    get_internal_ip, LOCATIONS,
)
from shared.meeting_schedule import (
    ScheduledMeeting, _meeting_schedule, get_meetings_for_room, get_all_rooms
)
from scenarios.security import ExfilScenario, RansomwareAttemptScenario
from scenarios.registry import expand_scenarios

# =============================================================================
# EXCHANGE CONFIGURATION
# =============================================================================

EVENT_IDS = ["Receive", "Send", "Deliver", "Failed", "Deferred"]
CONNECTORS = ["Inbound from Internet", "Outbound to Internet", "Internal"]
SOURCE_CONTEXTS = ["SMTP", "STOREDRIVER", "ROUTING"]

# Exchange server IPs (Boston mail servers)
EXCHANGE_SERVER_IPS = ["10.10.20.50", "10.10.20.51"]

# Distribution lists for company-wide and team announcements
DISTRIBUTION_LISTS = [
    ("all-company", "All Employees", 175),
    ("boston-all", "Boston Office", 93),
    ("atlanta-all", "Atlanta Office", 43),
    ("austin-all", "Austin Office", 39),
    ("engineering", "Engineering Team", 45),
    ("sales", "Sales Team", 35),
    ("finance", "Finance Team", 15),
    ("it-team", "IT Team", 12),
    ("hr-team", "HR Team", 8),
    ("marketing", "Marketing Team", 10),
]

# Announcement subjects for distribution list emails
ANNOUNCEMENT_SUBJECTS = [
    "Company Update: Q1 2026 Results",
    "Reminder: Mandatory Training Due",
    "Office Closure Notice - Presidents Day",
    "New Policy Update: Remote Work Guidelines",
    "Town Hall Meeting Reminder - This Friday",
    "Benefits Enrollment Deadline Approaching",
    "IT Maintenance Window - Saturday Night",
    "Welcome Our New Team Members!",
    "Quarterly Business Review Summary",
    "Important: Security Awareness Training",
    "Holiday Party Details",
    "Parking Lot Closure Notice",
]

# External system notifications (automated alerts from cloud/tools)
SYSTEM_NOTIFICATIONS = [
    ("alerts@aws.amazon.com", "AWS", ["CloudWatch Alert: High CPU", "Cost Alert: Budget threshold", "Security Finding: S3 bucket"]),
    ("noreply@azure.microsoft.com", "Azure", ["DevOps Build: Pipeline succeeded", "Security Alert: Suspicious login", "Resource Alert: Quota warning"]),
    ("jira@atlassian.net", "Jira", ["Issue assigned to you", "Sprint started: Sprint 15", "Comment added to PROJ-123"]),
    ("noreply@github.com", "GitHub", ["PR merged: Fix authentication bug", "CI failed: main branch", "Security advisory: Dependency update"]),
    ("splunk-alerts@theFakeTshirtCompany.com", "Splunk", ["Alert triggered: High error rate", "Report ready: Weekly metrics", "Scheduled search completed"]),
    ("noreply@servicenow.com", "ServiceNow", ["Incident assigned: INC0012345", "Change request approved", "Task overdue notice"]),
    ("noreply@slack.com", "Slack", ["Missed messages in #general", "Someone mentioned you in #engineering", "Weekly summary"]),
]

# HR/Admin senders for announcements
HR_SENDERS = ["hr", "communications", "it-helpdesk", "ceo-office", "facilities"]

# Calendar response types with weights
CALENDAR_RESPONSES = [
    ("Accepted", 70),
    ("Tentative", 20),
    ("Declined", 10),
]

# OOO users per day (~3-5% of employees)
OOO_PERCENTAGE = 0.04


# =============================================================================
# EVENT GENERATORS
# =============================================================================

def generate_message_id(domain: str = None) -> str:
    """Generate realistic message ID."""
    d = domain or TENANT
    return f"<{uuid.uuid4().hex[:16]}@{d}>"


def internal_message(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate internal email event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    sender = get_random_user()
    recipient = get_random_user()
    while recipient.username == sender.username:
        recipient = get_random_user()

    subject = random.choice(EMAIL_SUBJECTS_INTERNAL)
    msg_id = generate_message_id()
    size = random.randint(5000, 500000)

    return {
        "Received": ts,
        "SenderAddress": sender.email,
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Internal",
    }


def inbound_message(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate inbound email event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    domain = random.choice(EXTERNAL_MAIL_DOMAINS + PARTNER_DOMAINS)
    sender = f"{random.choice(['info', 'support', 'sales', 'noreply'])}@{domain}"
    recipient = get_random_user()

    subject = random.choice(EMAIL_SUBJECTS_EXTERNAL) + str(random.randint(1000, 9999))
    msg_id = generate_message_id(domain)
    size = random.randint(2000, 2000000)

    return {
        "Received": ts,
        "SenderAddress": sender,
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Inbound",
        "ConnectorId": "Inbound from Internet",
        "SourceContext": "External inbound",
    }


def outbound_message(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate outbound email event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    sender = get_random_user()
    domain = random.choice(EXTERNAL_MAIL_DOMAINS + PARTNER_DOMAINS)
    recipient = f"{random.choice(['contact', 'info', 'orders'])}@{domain}"

    subject = random.choice(EMAIL_SUBJECTS_INTERNAL)
    msg_id = generate_message_id()
    size = random.randint(5000, 1000000)

    return {
        "Received": ts,
        "SenderAddress": sender.email,
        "RecipientAddress": recipient,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Outbound",
        "ConnectorId": "Outbound to Internet",
        "SourceContext": "External outbound",
    }


def calendar_invite(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate calendar invite event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    sender = get_random_user()
    recipient = get_random_user()
    while recipient.username == sender.username:
        recipient = get_random_user()

    subjects = ["Team Meeting", "1:1 Sync", "Project Review", "Training Session", "All Hands"]
    subject = random.choice(subjects)
    msg_id = generate_message_id()
    size = random.randint(10000, 50000)

    return {
        "Received": ts,
        "SenderAddress": sender.email,
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Calendar",
        "ContentType": "text/calendar",
    }


def system_notification(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate system notification event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    recipient = get_random_user()
    subjects = [
        "Your password will expire in 14 days",
        "New device sign-in detected",
        "Weekly digest",
        "Storage quota warning",
    ]
    subject = random.choice(subjects)
    msg_id = generate_message_id(f"notifications.{TENANT}")
    size = random.randint(2000, 10000)

    return {
        "Received": ts,
        "SenderAddress": f"noreply@{TENANT}",
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "System notification",
    }


def spam_filtered(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate spam/filtered email event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    domains = ["suspicious-domain.xyz", "marketing-blast.biz", "unknown-sender.net"]
    sender = f"{random.choice(['offer', 'deal', 'winner'])}@{random.choice(domains)}"
    recipient = get_random_user()

    subjects = ["You've won!", "Urgent action required", "Limited time offer", "Claim your prize"]
    subject = random.choice(subjects)
    msg_id = generate_message_id("spam")
    size = random.randint(5000, 50000)

    return {
        "Received": ts,
        "SenderAddress": sender,
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "FilteredAsSpam",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Inbound",
        "ConnectorId": "Inbound from Internet",
        "SourceContext": "External inbound",
        "SpamScore": str(random.randint(6, 9)),
        "SCL": str(random.randint(6, 9)),
    }


def distribution_list_email(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate distribution list / announcement email."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    dl_name, dl_desc, member_count = random.choice(DISTRIBUTION_LISTS)
    sender_prefix = random.choice(HR_SENDERS)
    subject = random.choice(ANNOUNCEMENT_SUBJECTS)

    msg_id = generate_message_id()
    size = random.randint(10000, 100000)

    return {
        "Received": ts,
        "SenderAddress": f"{sender_prefix}@{TENANT}",
        "RecipientAddress": f"{dl_name}@{TENANT}",
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Announcement",
        "RecipientCount": str(member_count),
    }


def external_system_notification(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate external system notification (AWS, Azure, Jira, etc.)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    sender_email, system_name, subject_templates = random.choice(SYSTEM_NOTIFICATIONS)
    recipient = get_random_user()
    subject = random.choice(subject_templates)

    # Extract domain for message ID
    domain = sender_email.split("@")[1] if "@" in sender_email else "system.local"
    msg_id = generate_message_id(domain)
    size = random.randint(3000, 25000)

    # Internal systems vs external
    is_internal = TENANT in sender_email
    directionality = "Intra-org" if is_internal else "Inbound"

    return {
        "Received": ts,
        "SenderAddress": sender_email,
        "RecipientAddress": recipient.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS) if is_internal else f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": directionality,
        "SourceContext": "System notification",
        "SystemName": system_name,
    }


def auto_reply_ooo(base_date: str, day: int, hour: int, ooo_users: set) -> Dict[str, Any]:
    """Generate Out of Office auto-reply."""
    if not ooo_users:
        return None

    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    # OOO user sending the auto-reply
    ooo_user = random.choice(list(ooo_users))

    # Original sender (could be internal or external)
    if random.random() < 0.7:
        original_sender = get_random_user()
        recipient_addr = original_sender.email
    else:
        domain = random.choice(EXTERNAL_MAIL_DOMAINS)
        recipient_addr = f"contact@{domain}"

    msg_id = generate_message_id()
    size = random.randint(2000, 8000)

    return {
        "Received": ts,
        "SenderAddress": f"{ooo_user}@{TENANT}",
        "RecipientAddress": recipient_addr,
        "Subject": "Automatic reply: Out of Office",
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Outbound" if TENANT not in recipient_addr else "Intra-org",
        "SourceContext": "AutoReply",
    }


def calendar_response(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate calendar response (Accept/Tentative/Decline)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    # Responder
    responder = get_random_user()
    # Original organizer
    organizer = get_random_user()
    while organizer.username == responder.username:
        organizer = get_random_user()

    # Pick response type based on weights
    response_type = random.choices(
        [r[0] for r in CALENDAR_RESPONSES],
        weights=[r[1] for r in CALENDAR_RESPONSES]
    )[0]

    meeting_subjects = ["Team Meeting", "1:1 Sync", "Project Review", "Sprint Planning", "All Hands", "Training Session"]
    meeting_title = random.choice(meeting_subjects)
    subject = f"{response_type}: {meeting_title}"

    msg_id = generate_message_id()
    size = random.randint(5000, 15000)

    return {
        "Received": ts,
        "SenderAddress": responder.email,
        "RecipientAddress": organizer.email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Calendar-Response",
        "ContentType": "text/calendar",
        "ResponseType": response_type,
    }


# =============================================================================
# MEETING SCHEDULE INTEGRATION (Webex correlation)
# =============================================================================

def generate_meeting_emails_for_day(base_date: str, day: int) -> List[Dict[str, Any]]:
    """Generate calendar invite and response emails based on Webex meeting schedule.

    For each meeting in the schedule:
    - Generate invite email from organizer to each participant (same day or day before)
    - Generate response emails from participants (same day)
    - Ghost meetings: invites sent but no responses (people didn't show up)

    Note: For simplicity, invites are sent on meeting day or day before (realistic for
    internal/ad-hoc meetings). Response emails are generated on meeting day.
    """
    events = []

    # Iterate through all meetings in the schedule
    for room_key, meetings in _meeting_schedule.items():
        for meeting in meetings:
            # Skip walk-in meetings (no calendar invite)
            if meeting.is_walkin or meeting.is_after_hours:
                continue

            # Calculate meeting day
            meeting_day = (meeting.start_time - date_add(base_date, 0)).days

            # Invites sent on meeting day or day before (0 or 1 day before)
            invite_day_offset = random.choice([0, 0, 0, 1])  # 75% same day, 25% day before
            invite_day = meeting_day - invite_day_offset

            # Only generate if invite_day matches current day and meeting has organizer
            if invite_day == day and meeting.organizer_email and meeting.participants:
                # Generate invites to all participants (excluding organizer)
                for participant_email in meeting.participants:
                    if participant_email and participant_email != meeting.organizer_email:
                        invite = generate_meeting_invite_event(
                            base_date, day, meeting, participant_email
                        )
                        if invite:
                            events.append(invite)

            # Generate responses on the meeting day (not for ghost meetings)
            if meeting_day == day and not meeting.is_ghost and meeting.participants:
                for participant_email in meeting.participants:
                    if participant_email and participant_email != meeting.organizer_email:
                        response = generate_meeting_response_event(
                            base_date, day, meeting, participant_email
                        )
                        if response:
                            events.append(response)

    return events


def generate_meeting_invite_event(base_date: str, day: int,
                                   meeting: ScheduledMeeting,
                                   participant_email: str) -> Dict[str, Any]:
    """Generate a meeting invite email for a specific participant."""
    hour = random.randint(8, 17)
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    # Include room info in subject for Webex room meetings
    room_info = f" - {meeting.room}" if meeting.room else ""
    subject = f"Meeting Invite: {meeting.meeting_title}{room_info}"

    msg_id = generate_message_id()
    size = random.randint(15000, 50000)  # Calendar items with ICS attachment

    return {
        "Received": ts,
        "SenderAddress": meeting.organizer_email,
        "RecipientAddress": participant_email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Calendar",
        "ContentType": "text/calendar",
        "MeetingTitle": meeting.meeting_title,
        "MeetingRoom": meeting.room,
        "MeetingLocation": meeting.location_code,
    }


def generate_meeting_response_event(base_date: str, day: int,
                                     meeting: ScheduledMeeting,
                                     participant_email: str) -> Dict[str, Any]:
    """Generate a meeting response email from a participant."""
    hour = random.randint(8, 17)
    minute, second = random.randint(0, 59), random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    # Pick response type based on weights
    response_type = random.choices(
        [r[0] for r in CALENDAR_RESPONSES],
        weights=[r[1] for r in CALENDAR_RESPONSES]
    )[0]

    subject = f"{response_type}: {meeting.meeting_title}"

    msg_id = generate_message_id()
    size = random.randint(5000, 15000)

    return {
        "Received": ts,
        "SenderAddress": participant_email,
        "RecipientAddress": meeting.organizer_email,
        "Subject": subject,
        "Status": "Delivered",
        "ToIP": random.choice(EXCHANGE_SERVER_IPS),
        "FromIP": random.choice(EXCHANGE_SERVER_IPS),
        "Size": size,
        "MessageId": msg_id,
        "MessageTraceId": str(uuid.uuid4()),
        "Organization": TENANT,
        "Directionality": "Intra-org",
        "SourceContext": "Calendar-Response",
        "ContentType": "text/calendar",
        "ResponseType": response_type,
        "MeetingTitle": meeting.meeting_title,
    }


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int,
                           ooo_users: set = None) -> List[Dict[str, Any]]:
    """Generate baseline events for one hour.

    Updated event distribution for realistic email volume:
    - 35% Internal email
    - 20% Inbound external
    - 15% Outbound external
    - 8% Distribution list / announcements
    - 7% External system notifications
    - 7% Calendar invites (basic, non-Webex)
    - 5% Calendar responses
    - 2% Auto-replies (OOO)
    - 1% Spam filtered
    """
    events = []

    if ooo_users is None:
        ooo_users = set()

    for _ in range(event_count):
        event_type = random.randint(1, 100)

        if event_type <= 35:
            # Internal email
            events.append(internal_message(base_date, day, hour))
        elif event_type <= 55:
            # Inbound external
            events.append(inbound_message(base_date, day, hour))
        elif event_type <= 70:
            # Outbound external
            events.append(outbound_message(base_date, day, hour))
        elif event_type <= 78:
            # Distribution list / announcements
            events.append(distribution_list_email(base_date, day, hour))
        elif event_type <= 85:
            # External system notifications (AWS, Azure, Jira, etc.)
            events.append(external_system_notification(base_date, day, hour))
        elif event_type <= 92:
            # Calendar invites (basic, for non-Webex meetings)
            events.append(calendar_invite(base_date, day, hour))
        elif event_type <= 97:
            # Calendar responses
            events.append(calendar_response(base_date, day, hour))
        elif event_type <= 99:
            # Auto-replies (OOO)
            ooo_event = auto_reply_ooo(base_date, day, hour, ooo_users)
            if ooo_event:
                events.append(ooo_event)
            else:
                # Fallback to internal message if no OOO users
                events.append(internal_message(base_date, day, hour))
        else:
            # Spam filtered
            events.append(spam_filtered(base_date, day, hour))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_exchange_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Exchange message tracking logs in JSON format."""

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "exchange_message_trace.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_exfil = "exfil" in active_scenarios
    include_ransomware = "ransomware_attempt" in active_scenarios

    # Initialize scenarios if needed
    config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
    company = Company()
    time_utils = TimeUtils(start_date)

    exfil_scenario = None
    if include_exfil:
        exfil_scenario = ExfilScenario(config, company, time_utils)

    ransomware_scenario = None
    if include_ransomware:
        ransomware_scenario = RansomwareAttemptScenario(demo_id_enabled=True)

    # 8x increase from 50 to 400 for realistic email volume
    # ~175 employees sending/receiving 20-30 emails/day each
    base_events_per_peak_hour = int(400 * scale)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Exchange Message Tracking Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events = []
    scenario_events_json = []  # Scenario events come as JSON strings from exfil

    # Initialize OOO users (~4% of employees per day, refreshed daily)
    all_usernames = [u.username for u in USERS.values()]

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [Exchange] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        # Select OOO users for this day (~4% of employees)
        ooo_count = max(1, int(len(all_usernames) * OOO_PERCENTAGE))
        ooo_users = set(random.sample(all_usernames, ooo_count))

        # Generate meeting-related emails from Webex schedule (if schedule populated)
        if _meeting_schedule:
            meeting_emails = generate_meeting_emails_for_day(start_date, day)
            all_events.extend(meeting_emails)

        # Generate day-level scenario events
        if include_exfil and exfil_scenario:
            scenario_events_json.extend(exfil_scenario.exchange_day(day))

        for hour in range(24):
            hour_events = calc_natural_events(base_events_per_peak_hour, start_date, day, hour, "email")
            all_events.extend(generate_baseline_hour(start_date, day, hour, hour_events, ooo_users))

            # Generate hour-level scenario events
            if include_exfil and exfil_scenario:
                scenario_events_json.extend(exfil_scenario.exchange_hour(day, hour))

            # Ransomware scenario - phishing email
            if include_ransomware and ransomware_scenario:
                ransomware_events = ransomware_scenario.exchange_hour(day, hour, time_utils)
                for event in ransomware_events:
                    scenario_events_json.append(json.dumps(event))

        if not quiet:
            print(f"  [Exchange] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort baseline events by timestamp
    all_events.sort(key=lambda x: x["Received"])

    # Write all output to single JSON file
    with open(output_path, "w") as f:
        # Write baseline events
        for event in all_events:
            f.write(json.dumps(event) + "\n")
        # Append scenario events (already JSON strings)
        for event_json in scenario_events_json:
            f.write(event_json + "\n")

    total_events = len(all_events) + len(scenario_events_json)

    if not quiet:
        print(f"  [Exchange] Complete! {total_events:,} events written", file=sys.stderr)

    return total_events


def main():
    parser = argparse.ArgumentParser(description="Generate Exchange message tracking logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_exchange_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
