#!/usr/bin/env python3
"""
ServiceNow Incident Generator

Generates realistic IT support incidents in key-value format.
Correlates with existing scenarios (cpu_runaway, memory_leak, firewall_misconfig).

Output format: Key-value pairs (one event per line)
Splunk sourcetype: servicenow:incident

Example output:
sys_updated_on="2026-01-12T08:15:00Z" number="INC0012345" state="New" short_description="SQL Server performance degradation" ...
"""

import argparse
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add
from shared.company import USERS, SERVERS, LOCATIONS, USER_KEYS, TENANT

# =============================================================================
# CONSTANTS
# =============================================================================

FILE_SERVICENOW = "servicenow_incidents.log"

# Incident volume
BASE_INCIDENTS_PER_DAY = 20  # ~175 employees
MONDAY_MULTIPLIER = 1.3
WEEKEND_INCIDENTS = 5

# Incident states
STATES = ["New", "In Progress", "On Hold", "Resolved", "Closed"]

# Priorities (1 = Critical, 5 = Planning)
PRIORITIES = {
    1: {"name": "Critical", "resolve_hours": (1, 4), "weight": 5},
    2: {"name": "High", "resolve_hours": (2, 8), "weight": 15},
    3: {"name": "Moderate", "resolve_hours": (4, 24), "weight": 40},
    4: {"name": "Low", "resolve_hours": (8, 48), "weight": 30},
    5: {"name": "Planning", "resolve_hours": (24, 168), "weight": 10},
}

# =============================================================================
# ASSIGNMENT GROUPS
# =============================================================================

ASSIGNMENT_GROUPS = {
    "Service Desk": {
        "members": ["helpdesk.agent1", "helpdesk.agent2", "helpdesk.agent3"],
        "display": ["HD Agent 1", "HD Agent 2", "HD Agent 3"],
    },
    "Desktop Support": {
        "members": ["desktop.tech1", "desktop.tech2"],
        "display": ["Desktop Tech 1", "Desktop Tech 2"],
    },
    "Network Operations": {
        "members": ["network.admin", "network.eng1"],
        "display": ["Network Admin", "Network Engineer"],
    },
    "Database Admins": {
        "members": ["dba.admin1", "dba.admin2"],
        "display": ["DBA Admin 1", "DBA Admin 2"],
    },
    "Application Support": {
        "members": ["app.support1", "app.support2"],
        "display": ["App Support 1", "App Support 2"],
    },
    "Security Operations": {
        "members": ["sec.analyst1", "sec.analyst2"],
        "display": ["Security Analyst 1", "Security Analyst 2"],
    },
    "Linux Admins": {
        "members": ["linux.admin1", "linux.admin2"],
        "display": ["Linux Admin 1", "Linux Admin 2"],
    },
}

# =============================================================================
# INCIDENT TEMPLATES
# =============================================================================

INCIDENT_TEMPLATES = {
    "hardware": {
        "weight": 25,
        "assignment_group": "Desktop Support",
        "incidents": [
            {"short": "Laptop not powering on", "subcategory": "Laptop", "priority": 3},
            {"short": "Docking station not detecting monitors", "subcategory": "Docking Station", "priority": 4},
            {"short": "Keyboard not responding", "subcategory": "Peripheral", "priority": 4},
            {"short": "Mouse double-clicking issue", "subcategory": "Peripheral", "priority": 5},
            {"short": "Laptop battery not charging", "subcategory": "Laptop", "priority": 3},
            {"short": "Laptop screen flickering", "subcategory": "Laptop", "priority": 3},
            {"short": "Headset microphone not working", "subcategory": "Peripheral", "priority": 4},
            {"short": "Printer not printing", "subcategory": "Printer", "priority": 4},
            {"short": "Webcam not detected", "subcategory": "Peripheral", "priority": 4},
            {"short": "External monitor no signal", "subcategory": "Monitor", "priority": 3},
        ],
    },
    "software": {
        "weight": 30,
        "assignment_group": "Application Support",
        "incidents": [
            {"short": "Microsoft Teams crashing on startup", "subcategory": "Collaboration", "priority": 2},
            {"short": "Outlook not syncing emails", "subcategory": "Email", "priority": 2},
            {"short": "Excel macro not running", "subcategory": "Office", "priority": 4},
            {"short": "Adobe Acrobat license expired", "subcategory": "License", "priority": 3},
            {"short": "VPN client disconnecting frequently", "subcategory": "VPN", "priority": 2},
            {"short": "Zoom meeting crashes when sharing screen", "subcategory": "Collaboration", "priority": 3},
            {"short": "OneDrive sync stuck", "subcategory": "Cloud Storage", "priority": 3},
            {"short": "Software installation request", "subcategory": "Installation", "priority": 5},
            {"short": "Application running slow", "subcategory": "Performance", "priority": 3},
            {"short": "Browser extensions causing issues", "subcategory": "Browser", "priority": 4},
        ],
    },
    "network": {
        "weight": 15,
        "assignment_group": "Network Operations",
        "incidents": [
            {"short": "Cannot connect to VPN", "subcategory": "VPN", "priority": 2},
            {"short": "Slow internet connection", "subcategory": "Connectivity", "priority": 3},
            {"short": "Wi-Fi keeps dropping", "subcategory": "Wireless", "priority": 3},
            {"short": "Cannot access shared network drive", "subcategory": "File Share", "priority": 2},
            {"short": "Network printer offline", "subcategory": "Printer", "priority": 4},
            {"short": "Website not loading", "subcategory": "Connectivity", "priority": 3},
            {"short": "VPN connection slow", "subcategory": "VPN", "priority": 3},
        ],
    },
    "account": {
        "weight": 20,
        "assignment_group": "Service Desk",
        "incidents": [
            {"short": "Password reset request", "subcategory": "Password", "priority": 4},
            {"short": "Account locked out", "subcategory": "Account", "priority": 2},
            {"short": "Cannot access shared drive - permissions", "subcategory": "Permissions", "priority": 3},
            {"short": "MFA not working", "subcategory": "Authentication", "priority": 2},
            {"short": "New employee account setup", "subcategory": "Onboarding", "priority": 3},
            {"short": "Request for elevated permissions", "subcategory": "Permissions", "priority": 4},
            {"short": "SSO login failing", "subcategory": "Authentication", "priority": 2},
            {"short": "Email distribution list access request", "subcategory": "Email", "priority": 5},
        ],
    },
    "infrastructure": {
        "weight": 10,
        "assignment_group": "Database Admins",
        "incidents": [
            {"short": "Server not responding to ping", "subcategory": "Server", "priority": 1},
            {"short": "Database connection timeout", "subcategory": "Database", "priority": 2},
            {"short": "Application service down", "subcategory": "Application", "priority": 1},
            {"short": "Disk space warning on server", "subcategory": "Storage", "priority": 3},
            {"short": "Scheduled job failed", "subcategory": "Automation", "priority": 3},
            {"short": "SSL certificate expiring soon", "subcategory": "Security", "priority": 3},
        ],
    },
}

# =============================================================================
# SCENARIO-SPECIFIC INCIDENTS
# =============================================================================

SCENARIO_INCIDENTS = {
    "cpu_runaway": {
        "days": [10, 11],  # Day 11-12 (0-indexed)
        "incidents": [
            {
                "short": "SQL Server performance degradation on SQL-PROD-01",
                "category": "Infrastructure",
                "subcategory": "Database",
                "priority": 1,
                "cmdb_ci": "SQL-PROD-01",
                "assignment_group": "Database Admins",
                "description": "Users reporting extremely slow database queries. Multiple applications affected.",
                "close_notes": "Killed stuck backup job SPID 67, restarted SQL Server service. Root cause: backup job entered infinite loop.",
            },
            {
                "short": "Application timeout errors - database queries failing",
                "category": "Software",
                "subcategory": "Application",
                "priority": 2,
                "assignment_group": "Application Support",
                "description": "Multiple users reporting timeout errors when accessing business applications.",
                "close_notes": "Related to SQL-PROD-01 performance issue. Resolved when database was fixed.",
            },
            {
                "short": "Business application unresponsive",
                "category": "Software",
                "subcategory": "Application",
                "priority": 2,
                "assignment_group": "Application Support",
                "description": "ERP system extremely slow, users cannot complete daily tasks.",
                "close_notes": "Cascading effect from SQL server issue. Resolved after DB restart.",
            },
        ],
    },
    "memory_leak": {
        "days": [5, 6, 7, 8, 9],  # Days 6-10 (0-indexed), escalating severity
        "incidents": [
            {
                "short": "Website slow to load",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Customer-facing website experiencing slow response times.",
                "close_notes": "Memory leak in web application. Server restarted, dev team notified for fix.",
            },
            {
                "short": "Customer complaints - checkout page unresponsive",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Multiple customer complaints about checkout failures. Revenue impact.",
                "close_notes": "Related to memory leak on WEB-01. Emergency restart resolved immediate issue.",
            },
            {
                "short": "Web server high memory usage alert",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Monitoring alert: WEB-01 memory usage above 90%.",
                "close_notes": "Memory leak confirmed. Scheduled restart resolved. Patch being developed.",
            },
            {
                "short": "Web server swap usage critical",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "WEB-01 swap usage at 8GB and climbing. System becoming unresponsive.",
                "close_notes": "Memory leak causing excessive swapping. Restart scheduled.",
            },
            {
                "short": "Application timeouts on WEB-01",
                "category": "Infrastructure",
                "subcategory": "Application",
                "priority": 2,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "Multiple application timeout errors. Users reporting 504 Gateway Timeout.",
                "close_notes": "Related to memory exhaustion. System restart restored service.",
            },
            {
                "short": "CRITICAL: WEB-01 memory at 98% - OOM imminent",
                "category": "Infrastructure",
                "subcategory": "Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Linux Admins",
                "description": "URGENT: WEB-01 memory usage at 98%, swap at 25GB. OOM killer activation expected. Immediate action required.",
                "close_notes": "OOM killer activated at 14:00. Server crashed and was restarted. Root cause: memory leak in web application. Permanent fix deployed.",
            },
        ],
    },
    "firewall_misconfig": {
        "days": [6],  # Day 7 (0-indexed)
        "hours": [10, 11],  # 10:00-12:00
        "incidents": [
            {
                "short": "External users cannot access company website",
                "category": "Network",
                "subcategory": "Firewall",
                "priority": 1,
                "assignment_group": "Network Operations",
                "description": "All external traffic to company website being blocked. Customer impact confirmed.",
                "close_notes": "Firewall rule misconfiguration. ACL blocking inbound traffic to web server IP. Rolled back change.",
            },
            {
                "short": "Customer reports - 403 Forbidden errors on website",
                "category": "Network",
                "subcategory": "Firewall",
                "priority": 1,
                "assignment_group": "Network Operations",
                "description": "Sales team receiving customer calls about website access denied errors.",
                "close_notes": "Related to firewall misconfiguration. Fixed by reverting ACL change.",
            },
        ],
    },
    "ransomware_attempt": {
        "days": [7],  # Day 8 (0-indexed) - attack day
        "hours": [14, 15],  # 14:00-15:00 when incident created
        "incidents": [
            {
                "short": "CRITICAL: Malware detected on AUS-WS-BWHITE01",
                "category": "Security",
                "subcategory": "Malware",
                "priority": 1,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Security Operations",
                "description": "Windows Defender detected malware 'Trojan:Win32/Emotet.RPK!MTB' on workstation. User reported suspicious email attachment.",
                "close_notes": "Ransomware dropper detected and blocked by EDR. Endpoint isolated, reimaged. User education scheduled.",
            },
            {
                "short": "Endpoint AUS-WS-BWHITE01 isolated - security incident",
                "category": "Security",
                "subcategory": "Incident Response",
                "priority": 1,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Security Operations",
                "description": "Meraki network isolation triggered for compromised endpoint. Lateral movement attempts detected to 10.30.30.21, 10.30.30.22, 10.30.30.40.",
                "close_notes": "Forensic analysis complete. No data exfiltration confirmed. Endpoint reimaged. User Brooklyn White received security awareness training.",
            },
            {
                "short": "User workstation reimaging request - post security incident",
                "category": "Hardware",
                "subcategory": "Laptop",
                "priority": 2,
                "cmdb_ci": "AUS-WS-BWHITE01",
                "assignment_group": "Desktop Support",
                "description": "Workstation AUS-WS-BWHITE01 needs reimaging following security incident INC-SEC-2026-001.",
                "close_notes": "Fresh Windows image applied. User profile restored from backup. Endpoint verified clean.",
            },
        ],
    },
    "certificate_expiry": {
        "days": [11],  # Day 12 (0-indexed) - certificate expires at midnight
        "hours": [6, 7],  # 06:00-07:00 when NOC notices and incident created
        "incidents": [
            {
                "short": "CRITICAL: SSL certificate expired - website down",
                "category": "Infrastructure",
                "subcategory": "Certificate",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Network Operations",
                "description": "Wildcard SSL certificate for *.theFakeTshirtCompany.com expired at midnight. Customers unable to access website. All HTTPS connections failing with certificate errors.",
                "close_notes": "Emergency certificate renewal completed. New wildcard certificate installed on WEB-01 and WEB-02. Services restored at 07:00. Root cause: certificate renewal reminder was missed. Implemented automated monitoring.",
            },
            {
                "short": "Customer complaints - cannot access website",
                "category": "Infrastructure",
                "subcategory": "Web Server",
                "priority": 1,
                "cmdb_ci": "WEB-01",
                "assignment_group": "Service Desk",
                "description": "Multiple customer calls reporting 'Your connection is not private' error when accessing theFakeTshirtCompany.com. Started around midnight.",
                "close_notes": "Related to SSL certificate expiry (parent incident). Certificate renewed, website accessible.",
            },
            {
                "short": "Implement SSL certificate expiry monitoring",
                "category": "Infrastructure",
                "subcategory": "Certificate",
                "priority": 3,
                "assignment_group": "Network Operations",
                "description": "Post-incident task: Set up automated SSL certificate expiry monitoring with 30/14/7 day alerts to prevent future outages.",
                "close_notes": "Implemented certificate monitoring using Nagios/PRTG. Alerts configured for 30, 14, 7, and 1 day before expiry. Added to runbook.",
            },
        ],
    },
    "disk_filling": {
        "days": [7, 10, 12],  # Day 8 (warning), Day 11 (critical), Day 13 (emergency)
        "incidents": [
            {
                "short": "Disk space warning on MON-ATL-01",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 3,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "Monitoring alert: MON-ATL-01 disk usage above 75%. Server hosts critical monitoring services.",
                "close_notes": "Identified excessive logging from monitoring agents. Implemented log rotation policy.",
            },
            {
                "short": "CRITICAL: Disk space critical on MON-ATL-01",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 2,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "MON-ATL-01 disk usage at 88%. Monitoring services may fail if not addressed.",
                "close_notes": "Emergency cleanup performed. Archived old logs to backup storage.",
            },
            {
                "short": "EMERGENCY: Server MON-ATL-01 disk nearly full",
                "category": "Infrastructure",
                "subcategory": "Storage",
                "priority": 1,
                "cmdb_ci": "MON-ATL-01",
                "assignment_group": "Linux Admins",
                "description": "CRITICAL: MON-ATL-01 at 96% disk capacity. Monitoring services impacted. Alerting may be degraded.",
                "close_notes": "Expanded disk volume, migrated historical logs to new storage array. RCA scheduled for next week.",
            },
        ],
    },
}

# =============================================================================
# CLOSE CODES AND NOTES
# =============================================================================

CLOSE_CODES = ["Solved", "Workaround", "Not Reproducible", "Duplicate", "No Action Required"]

GENERIC_CLOSE_NOTES = {
    "hardware": [
        "Replaced defective hardware component",
        "Reseated connections, issue resolved",
        "Updated drivers, hardware functioning normally",
        "Device replaced under warranty",
        "Cleaned hardware, issue resolved",
    ],
    "software": [
        "Reinstalled application, issue resolved",
        "Updated to latest version",
        "Cleared cache and temporary files",
        "Reset user profile settings",
        "Applied vendor patch",
    ],
    "network": [
        "Reset network configuration",
        "VPN profile recreated",
        "Network cable replaced",
        "DHCP lease renewed",
        "DNS cache flushed",
    ],
    "account": [
        "Password reset completed",
        "Account unlocked",
        "Permissions granted as requested",
        "MFA reset and reconfigured",
        "Group membership updated",
    ],
    "infrastructure": [
        "Service restarted successfully",
        "Disk space cleared",
        "Scheduled task reconfigured",
        "Certificate renewed",
        "Server rebooted to apply updates",
    ],
}

WORK_NOTES = [
    "Investigating reported issue",
    "Contacted user for more details",
    "Reproduced the issue in test environment",
    "Escalating to next level support",
    "Awaiting vendor response",
    "Applied temporary workaround",
    "Testing fix in progress",
    "User confirmed issue resolved",
    "Monitoring for recurrence",
    "Scheduled follow-up with user",
]

# =============================================================================
# INCIDENT TRACKING
# =============================================================================

_incident_counter = 0


def get_next_incident_number() -> str:
    """Generate next incident number."""
    global _incident_counter
    _incident_counter += 1
    return f"INC{_incident_counter:07d}"


def reset_incident_counter():
    """Reset incident counter (for testing)."""
    global _incident_counter
    _incident_counter = 0


# =============================================================================
# HELPERS
# =============================================================================

def format_kv_line(fields: Dict) -> str:
    """Format a dictionary as a key-value line."""
    parts = []
    for key, value in fields.items():
        if value is not None:
            # Escape quotes in string values
            if isinstance(value, str):
                value = value.replace('"', '\\"')
                parts.append(f'{key}="{value}"')
            else:
                parts.append(f'{key}={value}')
    return " ".join(parts)


def get_random_user() -> Tuple[str, str]:
    """Get random user (username, display_name)."""
    username = random.choice(USER_KEYS)
    user = USERS[username]
    email = f"{username}@{TENANT}"
    return email, user.display_name


def get_random_location() -> str:
    """Get random location name."""
    loc_code = random.choice(list(LOCATIONS.keys()))
    return LOCATIONS[loc_code]["name"]


def get_priority() -> int:
    """Get weighted random priority."""
    weights = [PRIORITIES[p]["weight"] for p in range(1, 6)]
    return random.choices(range(1, 6), weights=weights)[0]


def get_category() -> Tuple[str, Dict]:
    """Get weighted random category and its config."""
    categories = list(INCIDENT_TEMPLATES.keys())
    weights = [INCIDENT_TEMPLATES[c]["weight"] for c in categories]
    category = random.choices(categories, weights=weights)[0]
    return category.title(), INCIDENT_TEMPLATES[category]


def get_assignment_member(group_name: str) -> Tuple[str, str]:
    """Get random member from assignment group (email, display_name)."""
    group = ASSIGNMENT_GROUPS.get(group_name, ASSIGNMENT_GROUPS["Service Desk"])
    idx = random.randint(0, len(group["members"]) - 1)
    member = group["members"][idx]
    display = group["display"][idx]
    return f"{member}@{TENANT}", display


# =============================================================================
# INCIDENT LIFECYCLE GENERATOR
# =============================================================================

@dataclass
class Incident:
    """Represents a ServiceNow incident."""
    number: str
    short_description: str
    description: str
    category: str
    subcategory: str
    priority: int
    urgency: int
    impact: int
    caller_id: str
    caller_name: str
    assignment_group: str
    assigned_to: Optional[str]
    assigned_to_name: Optional[str]
    cmdb_ci: Optional[str]
    location: str
    opened_at: datetime
    demo_id: Optional[str] = None
    close_notes: Optional[str] = None


def generate_incident_lifecycle(incident: Incident, base_date: datetime) -> List[str]:
    """
    Generate all events for an incident lifecycle.
    Returns list of key-value formatted lines.
    """
    events = []

    # Calculate resolution time based on priority
    resolve_min, resolve_max = PRIORITIES[incident.priority]["resolve_hours"]
    resolve_hours = random.uniform(resolve_min, resolve_max)

    # Event 1: New (incident created)
    fields = {
        "sys_updated_on": incident.opened_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "New",
        "short_description": incident.short_description,
        "description": incident.description,
        "category": incident.category,
        "subcategory": incident.subcategory,
        "priority": incident.priority,
        "urgency": incident.urgency,
        "impact": incident.impact,
        "caller_id": incident.caller_id,
        "caller_name": incident.caller_name,
        "assignment_group": incident.assignment_group,
        "location": incident.location,
    }
    if incident.cmdb_ci:
        fields["cmdb_ci"] = incident.cmdb_ci
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Event 2: Assigned (5-30 min later)
    assign_delay = random.randint(5, 30)
    assign_time = incident.opened_at + timedelta(minutes=assign_delay)
    assigned_to, assigned_name = get_assignment_member(incident.assignment_group)

    fields = {
        "sys_updated_on": assign_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "In Progress",
        "assigned_to": assigned_to,
        "assigned_to_name": assigned_name,
        "work_notes": random.choice(WORK_NOTES[:5]),  # Investigation notes
    }
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Event 3: Work notes update (30-60 min later, optional for longer incidents)
    if resolve_hours > 2:
        update_delay = random.randint(30, 90)
        update_time = assign_time + timedelta(minutes=update_delay)

        fields = {
            "sys_updated_on": update_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number": incident.number,
            "state": "In Progress",
            "work_notes": random.choice(WORK_NOTES[3:]),  # Progress notes
        }
        if incident.demo_id:
            fields["demo_id"] = incident.demo_id
        events.append(format_kv_line(fields))

    # Event 4: Resolved
    resolved_time = incident.opened_at + timedelta(hours=resolve_hours)

    # Get close notes
    if incident.close_notes:
        close_notes = incident.close_notes
    else:
        category_lower = incident.category.lower()
        if category_lower in GENERIC_CLOSE_NOTES:
            close_notes = random.choice(GENERIC_CLOSE_NOTES[category_lower])
        else:
            close_notes = random.choice(GENERIC_CLOSE_NOTES["software"])

    fields = {
        "sys_updated_on": resolved_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "Resolved",
        "resolved_by": assigned_to,
        "resolved_by_name": assigned_name,
        "close_code": random.choice(CLOSE_CODES[:2]),  # Mostly Solved/Workaround
        "close_notes": close_notes,
    }
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    # Event 5: Closed (1-24 hours after resolved)
    close_delay = random.randint(1, 24)
    closed_time = resolved_time + timedelta(hours=close_delay)

    fields = {
        "sys_updated_on": closed_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "number": incident.number,
        "state": "Closed",
    }
    if incident.demo_id:
        fields["demo_id"] = incident.demo_id
    events.append(format_kv_line(fields))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_normal_incidents(base_date: datetime, day: int, count: int) -> List[str]:
    """Generate normal (non-scenario) incidents for a day."""
    events = []

    for _ in range(count):
        # Random time during business hours (7am - 6pm) with some after-hours
        if random.random() < 0.85:
            hour = random.randint(7, 17)
        else:
            hour = random.choice([6, 18, 19, 20])
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        incident_time = datetime(
            base_date.year, base_date.month, base_date.day,
            hour, minute, second
        ) + timedelta(days=day)

        # Get category and template
        category, config = get_category()
        template = random.choice(config["incidents"])

        # Get caller
        caller_email, caller_name = get_random_user()

        # Create incident
        incident = Incident(
            number=get_next_incident_number(),
            short_description=template["short"],
            description=f"User reported: {template['short']}",
            category=category,
            subcategory=template.get("subcategory", "General"),
            priority=template.get("priority", get_priority()),
            urgency=template.get("priority", get_priority()),
            impact=random.randint(2, 4),
            caller_id=caller_email,
            caller_name=caller_name,
            assignment_group=config["assignment_group"],
            assigned_to=None,
            assigned_to_name=None,
            cmdb_ci=None,
            location=get_random_location(),
            opened_at=incident_time,
            demo_id=None,
        )

        events.extend(generate_incident_lifecycle(incident, base_date))

    return events


def generate_scenario_incidents(base_date: datetime, day: int, scenarios: str) -> List[str]:
    """Generate scenario-related incidents for a day."""
    events = []

    if scenarios == "none":
        return events

    # Check each scenario
    # Parse comma-separated scenarios into a set
    scenario_set = set(s.strip() for s in scenarios.split(",")) if "," in scenarios else {scenarios}

    for scenario_name, config in SCENARIO_INCIDENTS.items():
        # Skip if scenario not enabled
        # Allow individual scenario names or category names
        if scenario_name in scenario_set:
            pass  # Exact match - proceed
        elif "all" in scenario_set:
            pass  # All scenarios enabled
        elif "attack" in scenario_set and scenario_name in ["exfil", "ransomware_attempt"]:
            pass  # Attack category
        elif "ops" in scenario_set and scenario_name in ["cpu_runaway", "memory_leak", "disk_filling"]:
            pass  # Ops category
        elif "network" in scenario_set and scenario_name in ["firewall_misconfig", "certificate_expiry"]:
            pass  # Network category
        else:
            continue  # Skip this scenario

        # Check if this day is active for the scenario
        if day not in config["days"]:
            continue

        # Check hour restrictions if any
        if "hours" in config:
            # Only generate during specific hours
            hour = random.choice(config["hours"])
        else:
            # Business hours
            hour = random.randint(8, 16)

        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        incident_time = datetime(
            base_date.year, base_date.month, base_date.day,
            hour, minute, second
        ) + timedelta(days=day)

        # Generate 1-2 incidents from this scenario
        num_incidents = random.randint(1, min(2, len(config["incidents"])))
        selected = random.sample(config["incidents"], num_incidents)

        for template in selected:
            caller_email, caller_name = get_random_user()

            incident = Incident(
                number=get_next_incident_number(),
                short_description=template["short"],
                description=template.get("description", f"User reported: {template['short']}"),
                category=template.get("category", "Infrastructure"),
                subcategory=template.get("subcategory", "General"),
                priority=template.get("priority", 1),
                urgency=template.get("priority", 1),
                impact=1 if template.get("priority", 2) <= 2 else 2,
                caller_id=caller_email,
                caller_name=caller_name,
                assignment_group=template.get("assignment_group", "Service Desk"),
                assigned_to=None,
                assigned_to_name=None,
                cmdb_ci=template.get("cmdb_ci"),
                location="Boston HQ",  # Most infrastructure is in Boston
                opened_at=incident_time,
                demo_id=scenario_name,
                close_notes=template.get("close_notes"),
            )

            events.extend(generate_incident_lifecycle(incident, base_date))

    return events


def generate_servicenow_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "all",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """
    Generate ServiceNow incident logs.

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume scale factor
        scenarios: Scenario filter (none, exfil, all, attack, ops, network)
        output_file: Output file path (default: output/itsm/servicenow_incidents.log)
        quiet: Suppress progress output

    Returns:
        Total number of events generated
    """
    # Reset counter for fresh run
    reset_incident_counter()

    # Parse start date
    base_date = datetime.strptime(start_date, "%Y-%m-%d")

    # Determine output path
    if output_file is None:
        output_file = get_output_path("itsm", FILE_SERVICENOW)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_events = []

    for day in range(days):
        current_date = base_date + timedelta(days=day)
        weekday = current_date.weekday()

        # Calculate incident count for this day
        if weekday >= 5:  # Weekend
            day_count = WEEKEND_INCIDENTS
        elif weekday == 0:  # Monday
            day_count = int(BASE_INCIDENTS_PER_DAY * MONDAY_MULTIPLIER)
        else:
            day_count = BASE_INCIDENTS_PER_DAY

        # Apply scale
        day_count = int(day_count * scale)

        # Add some randomness
        day_count = max(1, day_count + random.randint(-3, 3))

        # Generate normal incidents
        events = generate_normal_incidents(base_date, day, day_count)
        all_events.extend(events)

        # Generate scenario incidents
        scenario_events = generate_scenario_incidents(base_date, day, scenarios)
        all_events.extend(scenario_events)

        if not quiet:
            print(f"  Day {day + 1}: {len(events) + len(scenario_events)} events")

    # Sort all events by sys_updated_on
    def get_timestamp(event: str) -> str:
        # Extract sys_updated_on from key-value line
        if 'sys_updated_on="' in event:
            start = event.find('sys_updated_on="') + 16
            end = event.find('"', start)
            return event[start:end]
        return ""

    all_events.sort(key=get_timestamp)

    # Write to file
    with open(output_file, 'w') as f:
        for event in all_events:
            f.write(event + "\n")

    if not quiet:
        print(f"  Total: {len(all_events)} events written to {output_file}")

    return len(all_events)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="ServiceNow Incident Generator")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Number of days")
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE, help="Volume scale factor")
    parser.add_argument("--scenarios", default="all", help="Scenarios: none, all, attack, ops, network")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")

    args = parser.parse_args()

    if not args.quiet:
        print(f"Generating ServiceNow incidents...")
        print(f"  Start date: {args.start_date}")
        print(f"  Days: {args.days}")
        print(f"  Scale: {args.scale}")
        print(f"  Scenarios: {args.scenarios}")

    count = generate_servicenow_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )

    if not args.quiet:
        print(f"Done! Generated {count} events.")


if __name__ == "__main__":
    main()
