#!/usr/bin/env python3
"""
Microsoft 365 Unified Audit Log Generator.
Generates realistic M365 audit events for SharePoint, OneDrive, and Teams.

Workloads:
  - SharePoint (RecordType 6): ~25% of events - Team site documents
  - OneDrive (RecordType 7): ~35% of events - Personal files, sync
  - MicrosoftTeams (RecordType 25): ~40% of events - Messages, file sharing

Includes scenario support:
  - exfil: Alex Miller (Finance) accesses/downloads sensitive files via SharePoint
  - ransomware_attempt: Brooklyn White (Sales) rapid file access/modification

Output format: JSON (one event per line)
Splunk sourcetype: FAKE:o365:management:activity
"""

import argparse
import json
import random
import sys
import uuid
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import Config, DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import TimeUtils, ts_iso, date_add, calc_natural_events
from shared.company import (
    Company, TENANT, TENANT_ID, ORG_NAME_LOWER,
    USERS, USER_KEYS, get_random_user, get_internal_ip,
    COMP_USER, COMP_EMAIL, COMP_WS_IP,
    THREAT_IP,
    LOCATIONS,
)
from scenarios.registry import expand_scenarios, get_phase


# =============================================================================
# OFFICE 365 CONFIGURATION
# =============================================================================

# Organization ID (Azure AD tenant)
ORG_ID = TENANT_ID

# SharePoint base URL
SP_BASE_URL = f"https://{ORG_NAME_LOWER}.sharepoint.com"

# SharePoint sites with department access mapping
SHAREPOINT_SITES = [
    {"name": "All Company", "url_slug": "/sites/AllCompany", "departments": None},  # None = all
    {"name": "HR Portal", "url_slug": "/sites/HRPortal", "departments": ["HR", "Executive"]},
    {"name": "IT Resources", "url_slug": "/sites/ITResources", "departments": ["IT", "Engineering"]},
    {"name": "Finance Team", "url_slug": "/sites/FinanceTeam", "departments": ["Finance", "Executive"]},
    {"name": "Engineering", "url_slug": "/sites/Engineering", "departments": ["Engineering", "IT"]},
    {"name": "Sales Team", "url_slug": "/sites/SalesTeam", "departments": ["Sales"]},
    {"name": "Marketing", "url_slug": "/sites/Marketing", "departments": ["Marketing"]},
    {"name": "Product Catalog", "url_slug": "/sites/ProductCatalog", "departments": ["Engineering", "Marketing"]},
]

# File patterns per department
DEPARTMENT_FILES = {
    "Finance": [
        ("Q4-Budget-2026.xlsx", "xlsx"), ("Monthly-Revenue-Report.xlsx", "xlsx"),
        ("AP-Invoice-Batch.xlsx", "xlsx"), ("Tax-Filing-Draft.pdf", "pdf"),
        ("Annual-Forecast-2026.xlsx", "xlsx"), ("Expense-Report-Template.xlsx", "xlsx"),
        ("Board-Financial-Summary.pdf", "pdf"), ("Payroll-Reconciliation.xlsx", "xlsx"),
        ("Cash-Flow-Analysis.xlsx", "xlsx"), ("Budget-Variance-Report.pdf", "pdf"),
    ],
    "Sales": [
        ("Customer-Proposal-Template.pptx", "pptx"), ("Q1-Sales-Deck.pptx", "pptx"),
        ("Price-List-2026.pdf", "pdf"), ("Customer-Onboarding-Guide.pdf", "pdf"),
        ("Territory-Map.pptx", "pptx"), ("Sales-Pipeline-Review.pptx", "pptx"),
        ("Competitive-Analysis.pdf", "pdf"), ("Demo-Slides.pptx", "pptx"),
    ],
    "Engineering": [
        ("API-Spec-v3.md", "md"), ("Architecture-Diagram.json", "json"),
        ("Release-Notes-2026.docx", "docx"), ("Database-Schema.md", "md"),
        ("Deployment-Runbook.md", "md"), ("Performance-Test-Results.json", "json"),
        ("Security-Review.docx", "docx"), ("Sprint-Retrospective.docx", "docx"),
    ],
    "HR": [
        ("Employee-Handbook-2026.docx", "docx"), ("PTO-Policy.pdf", "pdf"),
        ("Benefits-Guide.pdf", "pdf"), ("Onboarding-Checklist.docx", "docx"),
        ("Compensation-Bands.xlsx", "xlsx"), ("Interview-Template.docx", "docx"),
        ("Performance-Review-Form.docx", "docx"), ("Code-of-Conduct.pdf", "pdf"),
    ],
    "Marketing": [
        ("Brand-Guidelines-2026.pptx", "pptx"), ("Campaign-Assets.png", "png"),
        ("Social-Media-Calendar.xlsx", "xlsx"), ("Press-Release-Draft.pdf", "pdf"),
        ("Product-Launch-Plan.pptx", "pptx"), ("Email-Template.html", "html"),
        ("Marketing-Budget.xlsx", "xlsx"), ("Analytics-Report.pdf", "pdf"),
    ],
    "IT": [
        ("Network-Topology.pdf", "pdf"), ("Disaster-Recovery-Plan.docx", "docx"),
        ("Patch-Schedule.xlsx", "xlsx"), ("Vendor-Contacts.xlsx", "xlsx"),
        ("Security-Policy.pdf", "pdf"), ("Asset-Inventory.xlsx", "xlsx"),
    ],
    "Executive": [
        ("Board-Deck-Q1.pptx", "pptx"), ("Strategic-Plan-2026.pdf", "pdf"),
        ("Investor-Update.pptx", "pptx"), ("Executive-Summary.docx", "docx"),
    ],
    "Legal": [
        ("NDA-Template.docx", "docx"), ("Contract-Review.pdf", "pdf"),
        ("Compliance-Report.pdf", "pdf"), ("IP-Portfolio.xlsx", "xlsx"),
    ],
    "Operations": [
        ("Warehouse-Layout.pdf", "pdf"), ("Shipping-SOP.docx", "docx"),
        ("Inventory-Report.xlsx", "xlsx"), ("Vendor-Agreement.pdf", "pdf"),
    ],
}

# Default files for departments without specific patterns
DEFAULT_FILES = [
    ("Meeting-Notes.docx", "docx"), ("Project-Plan.xlsx", "xlsx"),
    ("Status-Report.pdf", "pdf"), ("Presentation.pptx", "pptx"),
]

# SharePoint/OneDrive operations with weights
SP_OPERATIONS = [
    ("FileAccessed", 40), ("FileModified", 25), ("FileDownloaded", 15),
    ("FileUploaded", 8), ("FileCheckedOut", 4), ("FileCheckedIn", 3),
    ("FileDeleted", 3), ("SharingSet", 2),
]

OD_OPERATIONS = [
    ("FileAccessed", 35), ("FileModified", 30), ("FileSyncUploadedFull", 15),
    ("FileDownloaded", 10), ("FileUploaded", 5), ("FileDeleted", 3),
    ("SharingSet", 2),
]

TEAMS_OPERATIONS = [
    ("MessageSent", 50), ("ChannelFileUploaded", 20), ("ChannelFileAccessed", 15),
    ("MemberAdded", 5), ("MeetingCreated", 5), ("TeamCreated", 3),
    ("TeamDeleted", 2),
]

# Teams channels per department
TEAMS_CHANNELS = {
    "Finance": ["General", "Budget-Planning", "Month-End-Close", "Expense-Reports"],
    "Sales": ["General", "Pipeline", "Deals", "Customer-Success"],
    "Engineering": ["General", "Code-Reviews", "Incidents", "Architecture"],
    "HR": ["General", "Recruiting", "Benefits", "Announcements"],
    "Marketing": ["General", "Campaigns", "Content", "Analytics"],
    "IT": ["General", "Helpdesk", "Infrastructure", "Security"],
    "Executive": ["General", "Strategy", "Board-Updates"],
    "Legal": ["General", "Contracts", "Compliance"],
    "Operations": ["General", "Shipping", "Inventory"],
}

# User agents for realistic browser/app usage
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0)",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Excel 16.0)",
    "Microsoft SkyDriveSync 23.235.1118 ship; Windows NT 10.0 (22621)",
    "OneDrive/23.235.1118",
]

# Baseline failure rate for file operations (~3%)
_M365_FAILURE_RATE = 0.03

# Failure reasons for M365 operations
_M365_FAILURE_REASONS = [
    "FileNotFound",
    "AccessDenied",
    "FileLocked",
    "QuotaExceeded",
    "VirusDetected",
    "BlockedByPolicy",
]

# External domains for sharing invitations
_EXTERNAL_SHARE_DOMAINS = [
    "partner-company.com", "consulting-group.net", "vendor-solutions.com",
    "agency-creative.com", "client-org.net",
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _m365_maybe_inject_failure(event: Dict[str, Any]) -> Dict[str, Any]:
    """Potentially mark an M365 file operation as failed (~3% chance).

    Only applies to file operations (not team management or messages).
    """
    operation = event.get("Operation", "")
    # Only fail file operations
    file_ops = {"FileAccessed", "FileModified", "FileDownloaded", "FileUploaded",
                "FileSyncUploadedFull", "FileCheckedOut", "FileCheckedIn",
                "ChannelFileUploaded", "ChannelFileAccessed"}
    if operation not in file_ops:
        return event

    if random.random() > _M365_FAILURE_RATE:
        return event

    event["ResultStatus"] = "Failed"
    event["ResultStatusDetail"] = random.choice(_M365_FAILURE_REASONS)
    return event


def _weighted_choice(choices: List[Tuple[str, int]]) -> str:
    """Pick from weighted choices."""
    items, weights = zip(*choices)
    return random.choices(items, weights=weights, k=1)[0]


def _generate_user_key(username: str) -> str:
    """Generate a deterministic numeric PUID for a user."""
    h = hashlib.md5(username.encode()).hexdigest()[:16]
    return h.upper()


def _get_site_for_user(user) -> dict:
    """Get a SharePoint site appropriate for this user's department."""
    eligible = [s for s in SHAREPOINT_SITES
                if s["departments"] is None or user.department in s["departments"]]
    if not eligible:
        eligible = [SHAREPOINT_SITES[0]]  # Fall back to All Company
    return random.choice(eligible)


def _get_files_for_department(department: str) -> List[Tuple[str, str]]:
    """Get file list for a department."""
    return DEPARTMENT_FILES.get(department, DEFAULT_FILES)


def _get_channels_for_department(department: str) -> List[str]:
    """Get Teams channels for a department."""
    return TEAMS_CHANNELS.get(department, ["General", "Random"])


# =============================================================================
# EVENT GENERATORS
# =============================================================================

def generate_sharepoint_event(start_date: str, day: int, hour: int,
                              user=None, operation: str = None,
                              demo_id: str = None) -> Dict[str, Any]:
    """Generate a SharePoint file operation event (RecordType 6)."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(start_date, day, hour, minute, second)

    if user is None:
        user = get_random_user()
    if operation is None:
        operation = _weighted_choice(SP_OPERATIONS)

    site = _get_site_for_user(user)
    files = _get_files_for_department(user.department)
    filename, ext = random.choice(files)
    site_url = f"{SP_BASE_URL}{site['url_slug']}"
    object_id = f"{site_url}/Shared Documents/{filename}"

    event = {
        "Id": str(uuid.uuid4()),
        "RecordType": 6,
        "CreationTime": ts,
        "Operation": operation,
        "OrganizationId": ORG_ID,
        "UserType": 0,
        "UserKey": _generate_user_key(user.username),
        "Workload": "SharePoint",
        "UserId": user.email,
        "ClientIP": user.ip_address,
        "ResultStatus": "Succeeded",
        "ObjectId": object_id,
        "SiteUrl": site_url,
        "SourceRelativeUrl": "Shared Documents",
        "SourceFileName": filename,
        "SourceFileExtension": ext,
        "ItemType": "File",
        "EventSource": "SharePoint",
        "UserAgent": random.choice(USER_AGENTS),
    }

    if demo_id:
        event["demo_id"] = demo_id

    # Inject baseline failures (only for non-scenario events)
    if not demo_id:
        event = _m365_maybe_inject_failure(event)

    return event


def generate_onedrive_event(start_date: str, day: int, hour: int,
                            user=None, operation: str = None,
                            demo_id: str = None) -> Dict[str, Any]:
    """Generate a OneDrive file operation event (RecordType 7)."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(start_date, day, hour, minute, second)

    if user is None:
        user = get_random_user()
    if operation is None:
        operation = _weighted_choice(OD_OPERATIONS)

    files = _get_files_for_department(user.department)
    filename, ext = random.choice(files)
    onedrive_url = f"{SP_BASE_URL}/personal/{user.username.replace('.', '_')}_{ORG_NAME_LOWER}_com"
    object_id = f"{onedrive_url}/Documents/{filename}"

    event = {
        "Id": str(uuid.uuid4()),
        "RecordType": 7,
        "CreationTime": ts,
        "Operation": operation,
        "OrganizationId": ORG_ID,
        "UserType": 0,
        "UserKey": _generate_user_key(user.username),
        "Workload": "OneDrive",
        "UserId": user.email,
        "ClientIP": user.ip_address,
        "ResultStatus": "Succeeded",
        "ObjectId": object_id,
        "SiteUrl": onedrive_url,
        "SourceRelativeUrl": "Documents",
        "SourceFileName": filename,
        "SourceFileExtension": ext,
        "ItemType": "File",
        "EventSource": "SharePoint",
        "UserAgent": random.choice(USER_AGENTS),
    }

    if demo_id:
        event["demo_id"] = demo_id

    # Inject baseline failures (only for non-scenario events)
    if not demo_id:
        event = _m365_maybe_inject_failure(event)

    return event


def generate_teams_event(start_date: str, day: int, hour: int,
                         user=None, operation: str = None,
                         demo_id: str = None) -> Dict[str, Any]:
    """Generate a Microsoft Teams event (RecordType 25)."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(start_date, day, hour, minute, second)

    if user is None:
        user = get_random_user()
    if operation is None:
        operation = _weighted_choice(TEAMS_OPERATIONS)

    channels = _get_channels_for_department(user.department)
    team_name = f"{user.department} Team"
    channel_name = random.choice(channels)

    event = {
        "Id": str(uuid.uuid4()),
        "RecordType": 25,
        "CreationTime": ts,
        "Operation": operation,
        "OrganizationId": ORG_ID,
        "UserType": 0,
        "UserKey": _generate_user_key(user.username),
        "Workload": "MicrosoftTeams",
        "UserId": user.email,
        "ClientIP": user.ip_address,
        "ResultStatus": "Succeeded",
        "TeamName": team_name,
        "ChannelName": channel_name,
        "CommunicationType": "Channel" if operation in ("MessageSent", "ChannelFileUploaded", "ChannelFileAccessed") else "OneOnOne",
    }

    # Add Members for team management operations
    if operation in ("MemberAdded", "TeamCreated", "TeamDeleted"):
        event["Members"] = [{"UPN": user.email, "Role": 1}]

    # Add file info for file operations in Teams
    if operation in ("ChannelFileUploaded", "ChannelFileAccessed"):
        files = _get_files_for_department(user.department)
        filename, ext = random.choice(files)
        event["SourceFileName"] = filename
        event["SourceFileExtension"] = ext

    if demo_id:
        event["demo_id"] = demo_id

    # Inject baseline failures for file operations in Teams (only for non-scenario events)
    if not demo_id:
        event = _m365_maybe_inject_failure(event)

    return event


def generate_sharing_invitation(start_date: str, day: int, hour: int,
                                 user=None, demo_id: str = None) -> Dict[str, Any]:
    """Generate a SharingInvitationCreated event (external sharing)."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(start_date, day, hour, minute, second)

    if user is None:
        user = get_random_user()

    site = _get_site_for_user(user)
    files = _get_files_for_department(user.department)
    filename, ext = random.choice(files)
    site_url = f"{SP_BASE_URL}{site['url_slug']}"
    object_id = f"{site_url}/Shared Documents/{filename}"

    # External recipient
    ext_domain = random.choice(_EXTERNAL_SHARE_DOMAINS)
    ext_first = random.choice(["john", "jane", "mark", "lisa", "david", "sarah", "mike", "emma"])
    ext_email = f"{ext_first}@{ext_domain}"

    event = {
        "Id": str(uuid.uuid4()),
        "RecordType": 14,  # SharePointSharingOperation
        "CreationTime": ts,
        "Operation": "SharingInvitationCreated",
        "OrganizationId": ORG_ID,
        "UserType": 0,
        "UserKey": _generate_user_key(user.username),
        "Workload": "SharePoint",
        "UserId": user.email,
        "ClientIP": user.ip_address,
        "ResultStatus": "Succeeded",
        "ObjectId": object_id,
        "SiteUrl": site_url,
        "SourceRelativeUrl": "Shared Documents",
        "SourceFileName": filename,
        "SourceFileExtension": ext,
        "ItemType": "File",
        "EventSource": "SharePoint",
        "UserAgent": random.choice(USER_AGENTS),
        "TargetUserOrGroupName": ext_email,
        "TargetUserOrGroupType": "Guest",
    }

    if demo_id:
        event["demo_id"] = demo_id

    return event


# =============================================================================
# SCENARIO EVENT GENERATORS
# =============================================================================

def _exfil_events_for_hour(start_date: str, day: int, hour: int) -> List[Dict[str, Any]]:
    """Generate exfil scenario events for M365.

    Timeline:
        Day 4 (Initial Access): 5-8 FileAccessed on Finance SharePoint from threat IP
        Days 5-7 (Lateral): Accessing HR Portal, Engineering, Executive docs
        Days 8-10 (Persistence): SharingSet on Finance docs to external email
        Days 11-13 (Exfil): Bulk FileDownloaded (40-80/night, 01:00-05:00)
    """
    events = []
    phase = get_phase(day)
    alex = USERS.get(COMP_USER)
    jessica = USERS.get("jessica.brown")  # Initial compromise - lateral movement

    if not alex:
        return events

    if phase == "initial_access" and day == 4:
        # Day 4: Initial access to Finance SharePoint
        if 9 <= hour <= 17:
            count = random.randint(1, 2)
            for _ in range(count):
                event = generate_sharepoint_event(
                    start_date, day, hour,
                    user=alex, operation="FileAccessed", demo_id="exfil"
                )
                # Override ClientIP with threat actor IP
                event["ClientIP"] = THREAT_IP
                # Target Finance site specifically
                event["SiteUrl"] = f"{SP_BASE_URL}/sites/FinanceTeam"
                finance_files = _get_files_for_department("Finance")
                fname, fext = random.choice(finance_files)
                event["ObjectId"] = f"{SP_BASE_URL}/sites/FinanceTeam/Shared Documents/{fname}"
                event["SourceFileName"] = fname
                event["SourceFileExtension"] = fext
                events.append(event)

    elif phase == "lateral" and 5 <= day <= 7:
        # Days 5-7: jessica.brown (compromised IT admin) accesses other department sites
        # Attacker uses jessica's credentials for lateral movement before pivoting to alex
        if jessica and 10 <= hour <= 16:
            if random.random() < 0.3:  # ~30% chance per eligible hour
                lateral_sites = [
                    ("HR Portal", "/sites/HRPortal", "HR"),
                    ("Finance Team", "/sites/FinanceTeam", "Finance"),
                    ("Engineering", "/sites/Engineering", "Engineering"),
                    ("All Company", "/sites/AllCompany", "Executive"),
                ]
                site_name, site_slug, dept = random.choice(lateral_sites)
                event = generate_sharepoint_event(
                    start_date, day, hour,
                    user=jessica, operation="FileDownloaded", demo_id="exfil"
                )
                event["ClientIP"] = THREAT_IP
                event["SiteUrl"] = f"{SP_BASE_URL}{site_slug}"
                files = _get_files_for_department(dept)
                fname, fext = random.choice(files)
                event["ObjectId"] = f"{SP_BASE_URL}{site_slug}/Shared Documents/{fname}"
                event["SourceFileName"] = fname
                event["SourceFileExtension"] = fext
                events.append(event)

    elif phase == "persistence" and 8 <= day <= 10:
        # Days 8-10: External sharing of Finance documents
        if hour == 14 and random.random() < 0.5:
            event = generate_sharepoint_event(
                start_date, day, hour,
                user=alex, operation="SharingSet", demo_id="exfil"
            )
            event["ClientIP"] = THREAT_IP
            event["SiteUrl"] = f"{SP_BASE_URL}/sites/FinanceTeam"
            finance_files = _get_files_for_department("Finance")
            fname, fext = random.choice(finance_files)
            event["ObjectId"] = f"{SP_BASE_URL}/sites/FinanceTeam/Shared Documents/{fname}"
            event["SourceFileName"] = fname
            event["SourceFileExtension"] = fext
            event["TargetUserOrGroupName"] = "external-partner@protonmail.com"
            event["TargetUserOrGroupType"] = "Guest"
            events.append(event)

        # Data staging: alex.miller uploading Finance docs to personal OneDrive
        if 13 <= hour <= 17 and random.random() < 0.25:
            event = generate_onedrive_event(
                start_date, day, hour,
                user=alex, operation="FileUploaded", demo_id="exfil"
            )
            event["ClientIP"] = THREAT_IP
            finance_files = _get_files_for_department("Finance")
            fname, fext = random.choice(finance_files)
            alex_od = f"{SP_BASE_URL}/personal/alex_miller_{ORG_NAME_LOWER}_com"
            event["SiteUrl"] = alex_od
            event["ObjectId"] = f"{alex_od}/Documents/staging/{fname}"
            event["SourceRelativeUrl"] = "Documents/staging"
            event["SourceFileName"] = fname
            event["SourceFileExtension"] = fext
            events.append(event)

    elif phase == "exfil" and 11 <= day <= 13:
        # Days 11-13: Bulk downloads during night (01:00-05:00)
        if 1 <= hour <= 5:
            # SharePoint bulk downloads: 8-16 per hour = 40-80 per night
            count = random.randint(8, 16)
            for _ in range(count):
                event = generate_sharepoint_event(
                    start_date, day, hour,
                    user=alex, operation="FileDownloaded", demo_id="exfil"
                )
                event["ClientIP"] = THREAT_IP
                event["SiteUrl"] = f"{SP_BASE_URL}/sites/FinanceTeam"
                finance_files = _get_files_for_department("Finance")
                fname, fext = random.choice(finance_files)
                event["ObjectId"] = f"{SP_BASE_URL}/sites/FinanceTeam/Shared Documents/{fname}"
                event["SourceFileName"] = fname
                event["SourceFileExtension"] = fext
                events.append(event)

            # OneDrive sync: staged files being synced out (3-6 per hour)
            od_count = random.randint(3, 6)
            for _ in range(od_count):
                event = generate_onedrive_event(
                    start_date, day, hour,
                    user=alex, operation="FileSyncDownloadedFull", demo_id="exfil"
                )
                event["ClientIP"] = THREAT_IP
                finance_files = _get_files_for_department("Finance")
                fname, fext = random.choice(finance_files)
                alex_od = f"{SP_BASE_URL}/personal/alex_miller_{ORG_NAME_LOWER}_com"
                event["SiteUrl"] = alex_od
                event["ObjectId"] = f"{alex_od}/Documents/staging/{fname}"
                event["SourceFileName"] = fname
                event["SourceFileExtension"] = fext
                events.append(event)

    return events


def _ransomware_events_for_hour(start_date: str, day: int, hour: int) -> List[Dict[str, Any]]:
    """Generate ransomware_attempt scenario events for M365.

    Timeline:
        Day 7 (0-indexed = Day 8 calendar), 15:35-15:40:
            10-15 rapid FileAccessed + FileModified on OneDrive (encryption attempt)
        Day 7, 15:40: Activity stops (EDR blocks)
        Day 8 (0-indexed = Day 9), 09:00-11:00:
            IT admin restores Brooklyn's files (FileRestored)
    """
    events = []
    brooklyn = USERS.get("brooklyn.white")
    jessica = USERS.get("jessica.brown")  # IT admin for recovery

    if not brooklyn:
        return events

    # Day 7 (0-indexed) = Day 8 on calendar, hour 15 = attack window
    if day == 7 and hour == 15:
        # Rapid file access + modification (encryption attempt)
        count = random.randint(10, 15)
        for i in range(count):
            # Alternate between access and modify to simulate encryption
            op = "FileAccessed" if i % 3 == 0 else "FileModified"
            event = generate_onedrive_event(
                start_date, day, hour,
                user=brooklyn, operation=op, demo_id="ransomware_attempt"
            )
            # Override minute to cluster around 15:35-15:40
            minute = 35 + (i // 3)
            second = random.randint(0, 59)
            event["CreationTime"] = ts_iso(start_date, day, hour, minute, second)
            events.append(event)

    # Day 8 (0-indexed) = Day 9 calendar, recovery window
    elif day == 8 and 9 <= hour <= 11 and jessica:
        # IT admin restoring files
        if random.random() < 0.6:
            count = random.randint(3, 6)
            for _ in range(count):
                event = generate_onedrive_event(
                    start_date, day, hour,
                    user=jessica, operation="FileRestored", demo_id="ransomware_attempt"
                )
                # Point to Brooklyn's OneDrive
                brooklyn_od = f"{SP_BASE_URL}/personal/brooklyn_white_{ORG_NAME_LOWER}_com"
                event["SiteUrl"] = brooklyn_od
                files = _get_files_for_department("Sales")
                fname, fext = random.choice(files)
                event["ObjectId"] = f"{brooklyn_od}/Documents/{fname}"
                event["SourceFileName"] = fname
                event["SourceFileExtension"] = fext
                events.append(event)

    return events


def _phishing_test_events_for_hour(start_date: str, day: int, hour: int) -> List[Dict[str, Any]]:
    """Generate phishing_test scenario events for M365 Unified Audit Log.

    Uses deterministic seed to select the SAME clickers as PhishingTestScenario.

    Timeline:
        Day 20-21 (0-indexed): SafeLinks URL click events (RecordType 146)
            When employees click the phishing sim link, M365 Defender SafeLinks
            logs the URL check event.
        Day 22: Admin review events (ashley.griffin reviews campaign results)
    """
    events = []

    # Only active days 20-22
    if day < 20 or day > 22:
        return events

    # Import the helper to get deterministic clicker set + timing
    try:
        from scenarios.security.phishing_test import PhishingTestScenario, PhishingTestConfig
    except ImportError:
        return events

    cfg = PhishingTestConfig()

    # Day 20-21: SafeLinks click events for clickers
    if day in (20, 21):
        # Reconstruct clickers with same seed
        scenario = PhishingTestScenario(demo_id_enabled=True)

        for username, click_day, click_hour, click_minute in scenario.clickers:
            if day != click_day or hour != click_hour:
                continue

            user = USERS.get(username)
            if not user:
                continue

            second = random.randint(0, 59)
            ts = ts_iso(start_date, day, click_hour, click_minute, second)

            # SafeLinks URL click event (RecordType 146 = ThreatIntelligenceUrl)
            event = {
                "CreationTime": ts,
                "Id": str(uuid.uuid4()),
                "Operation": "SafeLinksUrlClicked",
                "OrganizationId": ORG_ID,
                "RecordType": 146,
                "UserKey": _generate_user_key(username),
                "UserType": 0,
                "Workload": "ThreatIntelligence",
                "UserId": user.email,
                "SourceFileName": cfg.sim_subject,
                "ObjectId": cfg.sim_url,
                "ClientIP": user.ip_address,
                "UserAgent": random.choice(USER_AGENTS[:3]),  # Browser UAs only
                "ResultStatus": "Allowed",
                "ResultStatusDetail": "PhishingSimulation",
                "demo_id": "phishing_test",
            }
            events.append(event)

    # Day 22: Admin review events (ashley.griffin reviews results in Admin portal)
    elif day == 22 and 10 <= hour <= 11:
        admin_user = USERS.get(cfg.operator_user)
        if admin_user and hour == 10:
            # 3 admin portal review events
            admin_ops = [
                ("SecurityComplianceSearch", "Phishing simulation results export"),
                ("ViewReport", "Attack simulation training report"),
                ("AdminActivity", "Phishing campaign results review"),
            ]
            for i, (op, obj_id) in enumerate(admin_ops):
                minute = 15 + i * 8
                ts = ts_iso(start_date, day, hour, minute, random.randint(0, 59))
                event = {
                    "CreationTime": ts,
                    "Id": str(uuid.uuid4()),
                    "Operation": op,
                    "OrganizationId": ORG_ID,
                    "RecordType": 18,  # SecurityComplianceCenterEOPCmdlet
                    "UserKey": _generate_user_key(cfg.operator_user),
                    "UserType": 2,  # Admin
                    "Workload": "SecurityComplianceCenter",
                    "UserId": admin_user.email,
                    "ObjectId": obj_id,
                    "ClientIP": cfg.operator_ip,
                    "ResultStatus": "Succeeded",
                    "demo_id": "phishing_test",
                }
                events.append(event)

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_office_audit_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Microsoft 365 Unified Audit Log events.

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
    include_exfil = "exfil" in active_scenarios
    include_ransomware = "ransomware_attempt" in active_scenarios
    include_phishing_test = "phishing_test" in active_scenarios

    # Determine output path
    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "microsoft/office_audit.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Progress header
    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Microsoft 365 Audit Log Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events: List[Dict[str, Any]] = []
    demo_id_count = 0

    # Base events per peak hour (~170 at scale 1.0)
    # Breakdown: SharePoint 25%, OneDrive 35%, Teams 40%
    base_events_per_hour = int(170 * scale)

    # Workload distribution weights
    workload_weights = [
        ("sharepoint", 25),
        ("onedrive", 35),
        ("teams", 40),
    ]

    # Main generation loop
    for day in range(days):
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [M365 Audit] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # Calculate natural volume variation
            hour_count = calc_natural_events(
                base_events_per_hour, start_date, day, hour, "cloud"
            )

            # Generate baseline events distributed across workloads
            for _ in range(hour_count):
                workload = _weighted_choice(workload_weights)

                if workload == "sharepoint":
                    # ~3% of SharePoint events are external sharing invitations
                    if random.random() < 0.03:
                        event = generate_sharing_invitation(start_date, day, hour)
                    else:
                        event = generate_sharepoint_event(start_date, day, hour)
                elif workload == "onedrive":
                    event = generate_onedrive_event(start_date, day, hour)
                else:
                    event = generate_teams_event(start_date, day, hour)

                all_events.append(event)

            # Add scenario events
            if include_exfil:
                exfil_events = _exfil_events_for_hour(start_date, day, hour)
                all_events.extend(exfil_events)
                demo_id_count += len(exfil_events)

            if include_ransomware:
                ransom_events = _ransomware_events_for_hour(start_date, day, hour)
                all_events.extend(ransom_events)
                demo_id_count += len(ransom_events)

            if include_phishing_test:
                pt_events = _phishing_test_events_for_hour(start_date, day, hour)
                all_events.extend(pt_events)
                demo_id_count += len(pt_events)

    # Sort by CreationTime
    all_events.sort(key=lambda x: x.get("CreationTime", ""))

    # Write to file
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    # Final summary
    if not quiet:
        failed_count = sum(1 for e in all_events if e.get("ResultStatus") == "Failed")
        sharing_count = sum(1 for e in all_events if e.get("Operation") == "SharingInvitationCreated")
        print(f"  [M365 Audit] Complete! {len(all_events):,} events written",
              file=sys.stderr)
        print(f"          failures: {failed_count:,} ({failed_count * 100 // max(len(all_events), 1)}%) | sharing invites: {sharing_count:,}", file=sys.stderr)
        if demo_id_count:
            print(f"          demo_id events: {demo_id_count:,}", file=sys.stderr)

    return len(all_events)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate Microsoft 365 Unified Audit Log events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --days=7                          Generate 7 days of logs
  %(prog)s --days=14 --scenarios=exfil       Generate with exfil scenario
  %(prog)s --days=14 --scenarios=all         Generate with all scenarios
  %(prog)s --scale=2.0                       Double the event volume
  %(prog)s --quiet                           Suppress progress output
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
        help="Scenarios: none, exfil, ransomware_attempt, all, or comma-separated list"
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

    count = generate_office_audit_logs(
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
