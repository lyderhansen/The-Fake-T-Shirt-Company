#!/usr/bin/env python3
"""
Entra ID (Azure AD) Log Generator.
Generates sign-in and audit logs with natural volume variation.

Includes:
- Successful sign-ins with MFA variations (Authenticator, phone, TOTP, previously satisfied)
- Failed sign-ins with various error codes (50053, 50058, 70011 added)
- Service principal sign-ins (non-interactive, ~15/hour)
- Background spray noise from world IPs
- Audit events (user management, group management, policy updates)
- Operational events (CA policy updates, password resets, cert updates, lockouts)
"""

import argparse
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path, Config
from shared.time_utils import ts_iso, ts_iso_ms, date_add, calc_natural_events, TimeUtils
from shared.company import (
    TENANT, TENANT_ID, USERS, USER_KEYS, ENTRA_APPS,
    ENTRA_APP_CATALOG, ENTRA_GROUP_DEFINITIONS, ENTRA_ROLE_ASSIGNMENTS,
    get_random_user, get_us_ip, get_world_ip, Company,
    get_user_groups, get_user_app_licenses, get_user_roles,
)
from scenarios.registry import expand_scenarios

# =============================================================================
# ENTRA ID CONFIGURATION
# =============================================================================

ENTRA_APP_LIST = list(ENTRA_APPS.keys())
# Client app type + browser combinations (platform-correlated)
_CLIENT_PROFILES = [
    # (clientAppUsed, browser, operatingSystem, weight)
    ("Browser", "Chrome 120.0", "Windows 11", 25),
    ("Browser", "Edge 120.0", "Windows 11", 15),
    ("Browser", "Chrome 120.0", "Windows 10", 10),
    ("Browser", "Edge 120.0", "Windows 10", 5),
    ("Browser", "Chrome 120.0", "macOS", 10),
    ("Browser", "Safari 17.2", "macOS", 8),
    ("Mobile Apps and Desktop clients", None, "Windows 11", 10),
    ("Mobile Apps and Desktop clients", None, "Windows 10", 5),
    ("Mobile Apps and Desktop clients", None, "macOS", 5),
    ("Mobile Apps and Desktop clients", None, "iOS", 3),
    ("Mobile Apps and Desktop clients", None, "Android", 2),
    ("Other clients", None, "Windows 10", 2),
]
_CLIENT_PROFILE_WEIGHTS = [p[3] for p in _CLIENT_PROFILES]

def _pick_client_profile():
    """Pick a correlated client app type, browser and OS."""
    profile = random.choices(_CLIENT_PROFILES, weights=_CLIENT_PROFILE_WEIGHTS, k=1)[0]
    return {
        "clientAppUsed": profile[0],
        "browser": profile[1],
        "operatingSystem": profile[2],
    }

# Legacy constants kept for backward compatibility
CLIENT_APP_TYPES = ["Browser", "Mobile Apps and Desktop clients", "Other clients"]
DEVICE_PLATFORMS = ["Windows 11", "Windows 10", "macOS", "iOS", "Android"]
BROWSERS = ["Chrome 120.0", "Edge 120.0", "Safari 17.2", "Firefox 121.0"]

# Error codes for failed sign-ins
ERROR_CODES = [
    (50126, "Invalid username or password"),
    (50076, "MFA required"),
    (50074, "Strong authentication required"),
    (53003, "Blocked by Conditional Access"),
    (50053, "Account is locked"),
    (50058, "Silent sign-in interrupted - user needs to sign in again"),
    (70011, "Invalid scope - the app requested a scope that was not granted"),
]

# Geographies for spray noise
SPRAY_GEOS = [
    ("RU", "Moscow", "45.155"),
    ("CN", "Beijing", "103.21"),
    ("BR", "Sao Paulo", "186.90"),
    ("IN", "Mumbai", "102.67"),
    ("US", "Ashburn", "37.19"),
    ("DE", "Frankfurt", "91.231"),
    ("FR", "Paris", "5.44"),
]

# Admin accounts for audit events
# Service accounts use fixed IDs; real employees resolve from USERS dict at runtime.
# Using Boston management subnet (10.10.10.x) and Atlanta IT subnet (10.20.30.x)
ADMIN_ACCOUNTS = {
    "sec.admin":     ("user-sec-admin-id",  "Security Admin",   "10.10.10.50"),
    "helpdesk":      ("user-helpdesk-id",   "Helpdesk Admin",   "10.10.10.51"),
    "it.admin":      ("user-it-admin-id",   "IT Admin",         "10.20.30.10"),   # Atlanta IT
    "mike.johnson":  (None, None, None),    # CTO — resolve from USERS
    "jessica.brown": (None, None, None),    # IT Admin — resolve from USERS
    "sarah.wilson":  (None, None, None),    # CFO — resolve from USERS
    "ad.sync":       ("user-adsync-id",     "AD Connect Sync",  "10.10.20.10"),   # DC-BOS-01
}

# Weighted admin selection for baseline events (routine ops done by these admins)
_BASELINE_ADMIN_KEYS = ["it.admin", "it.admin", "it.admin", "helpdesk", "helpdesk", "ad.sync"]


def _resolve_admin(admin_key: str):
    """Resolve admin account info. Returns (id, display_name, ip).

    For service accounts, returns static values from ADMIN_ACCOUNTS.
    For real employees, resolves from USERS dict.
    """
    entry = ADMIN_ACCOUNTS.get(admin_key)
    if entry and entry[0] is not None:
        return entry
    # Try to resolve from USERS
    user = USERS.get(admin_key)
    if user:
        return (user.entra_object_id, user.display_name, user.ip_address)
    return ("admin-id", "Admin", "10.10.10.50")

# Exfil scenario users - for demo_id tagging
EXFIL_USERS = {"jessica.brown", "alex.miller"}

# Self-Service Password Reset (SSPR) verification steps
SSPR_VERIFICATION_STEPS = [
    "Verify email",
    "Verify mobile app notification",
    "Verify mobile app code",
    "Verify office phone",
    "Answer security questions",
]

# Identity Protection Risk Event Types
RISK_EVENT_TYPES = [
    ("unfamiliarFeatures", "Sign-in with unfamiliar properties"),
    ("anonymizedIPAddress", "Sign-in from an anonymous IP address"),
    ("impossibleTravel", "Impossible travel"),
    ("maliciousIPAddress", "Sign-in from a malicious IP address"),
    ("suspiciousBrowser", "Suspicious browser"),
    ("passwordSpray", "Password spray attack"),
    ("leakedCredentials", "Leaked credentials"),
]

# Risk levels
RISK_LEVELS = ["low", "medium", "high"]

# Risk states
RISK_STATES = ["atRisk", "confirmedSafe", "remediated", "dismissed"]


def should_tag_signin_exfil(username: str, day: int, active_scenarios: list) -> bool:
    """Check if signin should get exfil demo_id.

    Jessica Brown: Day 4-14 (initial access via phishing)
    Alex Miller: Day 5-14 (credentials stolen)
    """
    if "exfil" not in active_scenarios:
        return False
    if username not in EXFIL_USERS:
        return False
    # Exfil scenario: day 1-14 (0-indexed: 0-13)
    if day > 13:
        return False
    # Jessica: day 4-14 (0-indexed: 3-13) - initial access via phishing
    if username == "jessica.brown" and day >= 3:
        return True
    # Alex: day 5-14 (0-indexed: 4-13) - credentials stolen
    if username == "alex.miller" and day >= 4:
        return True
    return False


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def rand_uuid() -> str:
    """Generate random UUID."""
    return str(uuid.uuid4())


def get_mfa_details() -> Dict[str, Any]:
    """Get MFA method and authentication details.

    Distribution:
    - 35% Authenticator push notification
    - 20% Previously satisfied (trusted device / claim)
    - 15% Phone call
    - 15% FIDO2 security key (passwordless)
    - 15% TOTP verification code
    """
    mfa_type = random.randint(1, 20)

    if mfa_type <= 7:
        # 35% - Authenticator push notification
        return {
            "mfaDetail": {
                "authMethod": "Microsoft Authenticator",
                "authDetail": "Notification approved"
            },
            "authenticationDetails": [
                {"authenticationMethod": "Password", "succeeded": True},
                {"authenticationMethod": "Microsoft Authenticator", "succeeded": True,
                 "authenticationMethodDetail": "Notification approved"}
            ]
        }
    elif mfa_type <= 11:
        # 20% - MFA satisfied by claim (recent auth, trusted device)
        return {
            "mfaDetail": {
                "authMethod": "Previously satisfied",
                "authDetail": "MFA requirement satisfied by claim in the token"
            },
            "authenticationDetails": [
                {"authenticationMethod": "Password", "succeeded": True},
                {"authenticationMethod": "Previously satisfied", "succeeded": True,
                 "authenticationMethodDetail": "MFA requirement satisfied by claim in the token"}
            ]
        }
    elif mfa_type <= 14:
        # 15% - Phone call
        return {
            "mfaDetail": {
                "authMethod": "Phone call",
                "authDetail": "Call answered"
            },
            "authenticationDetails": [
                {"authenticationMethod": "Password", "succeeded": True},
                {"authenticationMethod": "Phone call", "succeeded": True,
                 "authenticationMethodDetail": "Call answered"}
            ]
        }
    elif mfa_type <= 17:
        # 15% - FIDO2 security key
        return {
            "mfaDetail": {
                "authMethod": "FIDO2 security key",
                "authDetail": "Security key verified"
            },
            "authenticationDetails": [
                {"authenticationMethod": "FIDO2 security key", "succeeded": True,
                 "authenticationMethodDetail": "Security key verified"}
            ]
        }
    else:
        # 15% - TOTP verification code
        return {
            "mfaDetail": {
                "authMethod": "Mobile app verification code",
                "authDetail": "Code verified"
            },
            "authenticationDetails": [
                {"authenticationMethod": "Password", "succeeded": True},
                {"authenticationMethod": "Mobile app verification code", "succeeded": True,
                 "authenticationMethodDetail": "Code verified"}
            ]
        }


# =============================================================================
# SIGN-IN EVENT GENERATORS
# =============================================================================

def signin_success(base_date: str, day: int, hour: int, minute: int = None, second: int = None,
                   active_scenarios: list = None) -> str:
    """Generate successful sign-in event with MFA details."""
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)

    user = get_random_user()
    app_name = random.choice(ENTRA_APP_LIST)
    app_id = ENTRA_APPS[app_name]
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()
    ip = user.get_ip()

    mfa = get_mfa_details()
    client = _pick_client_profile()

    device_detail = {
        "deviceId": user.entra_device_id,
        "displayName": user.device_name,
        "operatingSystem": client["operatingSystem"],
        "isCompliant": True,
        "isManaged": True,
    }
    if client["browser"]:
        device_detail["browser"] = client["browser"]

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "SignInLogs",
        "tenantId": TENANT_ID,
        "resultType": "0",
        "callerIpAddress": ip,
        "correlationId": cid,
        "identity": user.display_name,
        "Level": 4,
        "location": user.country,
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "userDisplayName": user.display_name,
            "userPrincipalName": user.email,
            "userId": user.entra_object_id,
            "appId": app_id,
            "appDisplayName": app_name,
            "ipAddress": ip,
            "clientAppUsed": client["clientAppUsed"],
            "conditionalAccessStatus": "success",
            "isInteractive": True,
            "authenticationRequirement": "multiFactorAuthentication",
            "tokenIssuerType": "AzureAD",
            "riskLevelAggregated": "none",
            "riskLevelDuringSignIn": "none",
            "riskState": "none",
            "riskDetail": "none",
            "status": {"errorCode": 0},
            "deviceDetail": device_detail,
            "location": {
                "city": user.city,
                "countryOrRegion": user.country
            },
            "mfaDetail": mfa["mfaDetail"],
            "authenticationDetails": mfa["authenticationDetails"]
        }
    }

    # Add demo_id for exfil scenario users
    if active_scenarios and should_tag_signin_exfil(user.username, day, active_scenarios):
        event["demo_id"] = "exfil"

    return json.dumps(event)


def signin_failed(base_date: str, day: int, hour: int, minute: int = None, second: int = None) -> str:
    """Generate failed sign-in event."""
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)

    user = get_random_user()
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()
    ip = user.get_ip()

    error_code, error_msg = random.choice(ERROR_CODES)
    client = _pick_client_profile()

    device_detail = {
        "deviceId": user.entra_device_id,
        "displayName": user.device_name,
        "operatingSystem": client["operatingSystem"],
    }
    if client["browser"]:
        device_detail["browser"] = client["browser"]

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "SignInLogs",
        "tenantId": TENANT_ID,
        "resultType": str(error_code),
        "resultDescription": error_msg,
        "callerIpAddress": ip,
        "correlationId": cid,
        "identity": user.display_name,
        "Level": 4,
        "location": user.country,
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "userDisplayName": user.display_name,
            "userPrincipalName": user.email,
            "userId": user.entra_object_id,
            "appId": "00000002-0000-0ff1-ce00-000000000000",
            "appDisplayName": "Office 365 Exchange Online",
            "ipAddress": ip,
            "clientAppUsed": client["clientAppUsed"],
            "conditionalAccessStatus": "failure",
            "isInteractive": True,
            "authenticationRequirement": "multiFactorAuthentication",
            "tokenIssuerType": "AzureAD",
            "riskState": "none",
            "riskDetail": "none",
            "status": {"errorCode": error_code, "failureReason": error_msg},
            "deviceDetail": device_detail,
            "location": {
                "city": user.city,
                "countryOrRegion": user.country
            }
        }
    }

    return json.dumps(event)


def signin_blocked_by_ca(base_date: str, day: int, hour: int, minute: int = None,
                         username: str = None, client_ip: str = None,
                         app_name: str = "Microsoft Office",
                         policy_name: str = "Block legacy authentication",
                         demo_id: str = None) -> str:
    """Generate Conditional Access blocked signin event."""
    minute = minute if minute is not None else random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()

    # Get user info
    if username:
        user_display = username.replace(".", " ").title()
        user_email = f"{username}@{TENANT}"
        ip = client_ip or get_us_ip()
        city = "Unknown"
        country = "US"
    else:
        user = get_random_user()
        user_display = user.display_name
        user_email = user.email
        ip = client_ip or user.get_ip()
        city = user.city
        country = user.country

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "SignInLogs",
        "tenantId": TENANT_ID,
        "resultType": "53003",
        "resultDescription": "Blocked by Conditional Access",
        "callerIpAddress": ip,
        "correlationId": cid,
        "identity": user_display,
        "Level": 4,
        "location": country,
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "userDisplayName": user_display,
            "userPrincipalName": user_email,
            "ipAddress": ip,
            "appDisplayName": app_name,
            "clientAppUsed": "Other clients",
            "conditionalAccessStatus": "failure",
            "isInteractive": True,
            "riskState": "none",
            "status": {
                "errorCode": 53003,
                "failureReason": "Blocked by Conditional Access"
            },
            "appliedConditionalAccessPolicies": [
                {
                    "id": rand_uuid(),
                    "displayName": policy_name,
                    "result": "failure",
                    "conditionsSatisfied": "none",
                    "conditionsNotSatisfied": "application"
                }
            ],
            "location": {
                "city": city,
                "countryOrRegion": country
            }
        }
    }

    if demo_id:
        event["demo_id"] = demo_id

    return json.dumps(event)


def signin_from_threat_ip(base_date: str, day: int, hour: int, minute: int,
                          username: str, threat_ip: str,
                          success: bool = False,
                          demo_id: str = None) -> str:
    """Generate signin event from known threat IP."""
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()

    user_display = username.replace(".", " ").title()
    user_email = f"{username}@{TENANT}"

    if success:
        result_type = "0"
        result_desc = "Success"
        error_code = 0
    else:
        result_type = "50126"
        result_desc = "Invalid username or password"
        error_code = 50126

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "SignInLogs",
        "tenantId": TENANT_ID,
        "resultType": result_type,
        "resultDescription": result_desc,
        "callerIpAddress": threat_ip,
        "correlationId": cid,
        "identity": user_display,
        "Level": 4,
        "location": "DE",  # Frankfurt - threat actor location
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "userDisplayName": user_display,
            "userPrincipalName": user_email,
            "ipAddress": threat_ip,
            "appDisplayName": "Microsoft Office",
            "clientAppUsed": "Browser",
            "conditionalAccessStatus": "success" if success else "notApplied",
            "isInteractive": True,
            "riskState": "atRisk",
            "riskLevelDuringSignIn": "medium",
            "status": {
                "errorCode": error_code,
                "failureReason": result_desc if not success else None
            },
            "location": {
                "city": "Frankfurt",
                "countryOrRegion": "DE"
            }
        }
    }

    if demo_id:
        event["demo_id"] = demo_id

    return json.dumps(event)


def signin_spray_noise(base_date: str, day: int, hour: int) -> str:
    """Generate background spray noise from random world IPs."""
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()

    targets = ["admin", "ceo", "finance", "hr", "it.support", "john.smith", "jane.doe", "test"]
    target = random.choice(targets)

    geo = random.choice(SPRAY_GEOS)
    cc, city, ip_prefix = geo
    ip = f"{ip_prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "SignInLogs",
        "tenantId": TENANT_ID,
        "resultType": "50126",
        "resultDescription": "Invalid username or password",
        "callerIpAddress": ip,
        "correlationId": cid,
        "identity": f"{target}@{TENANT}",
        "Level": 4,
        "location": cc,
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "userDisplayName": target,
            "userPrincipalName": f"{target}@{TENANT}",
            "ipAddress": ip,
            "clientAppUsed": "Browser",
            "conditionalAccessStatus": "notApplied",
            "isInteractive": True,
            "riskState": "none",
            "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
            "deviceDetail": {
                "operatingSystem": "Android 13",
                "isCompliant": False,
                "isManaged": False
            },
            "location": {
                "city": city,
                "countryOrRegion": cc
            }
        }
    }

    return json.dumps(event)


def generate_signin_hour(base_date: str, day: int, hour: int, event_count: int,
                        active_scenarios: list = None) -> List[str]:
    """Generate sign-in events for one hour (interactive + service principal)."""
    events = []

    for _ in range(event_count):
        if random.random() < 0.95:
            events.append(signin_success(base_date, day, hour, active_scenarios=active_scenarios))
        else:
            events.append(signin_failed(base_date, day, hour))

    # Occasional spray noise (25% chance per hour)
    if random.random() < 0.25:
        events.append(signin_spray_noise(base_date, day, hour))

    # Service principal sign-ins (~15/hour, constant — machines don't sleep)
    sp_count = random.randint(10, 20)
    for _ in range(sp_count):
        events.append(signin_service_principal(base_date, day, hour))

    return events


# =============================================================================
# SERVICE PRINCIPAL SIGN-INS (non-interactive)
# =============================================================================

# Service principals (automated app identities that sign in to Entra ID)
SERVICE_PRINCIPALS = [
    {
        "appDisplayName": "SAP S/4HANA Connector",
        "appId": "sp-sap-connector-id",
        "servicePrincipalId": "sp-sap-001",
        "ipAddress": "10.10.20.60",       # SAP-PROD-01
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": "00000003-0000-0000-c000-000000000000",
    },
    {
        "appDisplayName": "Veeam Backup Agent",
        "appId": "sp-veeam-backup-id",
        "servicePrincipalId": "sp-veeam-001",
        "ipAddress": "10.20.20.20",       # BACKUP-ATL-01
        "resourceDisplayName": "Azure Storage",
        "resourceId": "e406a681-f3d4-42a8-90b6-c2b029497af1",
    },
    {
        "appDisplayName": "Splunk Cloud Forwarder",
        "appId": "sp-splunk-fwd-id",
        "servicePrincipalId": "sp-splunk-001",
        "ipAddress": "10.20.20.30",       # MON-ATL-01
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": "00000003-0000-0000-c000-000000000000",
    },
    {
        "appDisplayName": "GitHub Actions CI/CD",
        "appId": "sp-github-cicd-id",
        "servicePrincipalId": "sp-github-001",
        "ipAddress": "10.20.20.30",       # MON-ATL-01
        "resourceDisplayName": "Azure DevOps",
        "resourceId": "499b84ac-1321-427f-aa17-267ca6975798",
    },
    {
        "appDisplayName": "Nagios Monitoring Agent",
        "appId": "sp-nagios-mon-id",
        "servicePrincipalId": "sp-nagios-001",
        "ipAddress": "10.20.20.30",       # MON-ATL-01
        "resourceDisplayName": "Microsoft Graph",
        "resourceId": "00000003-0000-0000-c000-000000000000",
    },
]

# Service principal sign-in error codes (rare failures)
SP_ERROR_CODES = [
    (0, "Success"),
    (0, "Success"),
    (0, "Success"),
    (0, "Success"),
    (0, "Success"),           # 5x success = ~83% success rate
    (7000215, "Invalid client secret provided"),
    (7000222, "Client certificate expired"),
]


def signin_service_principal(base_date: str, day: int, hour: int) -> str:
    """Generate service principal (non-interactive) sign-in event.

    Service principals sign in constantly — automated jobs, API calls,
    background services. These are machine-to-machine auth events.
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)
    cid = rand_uuid()

    sp = random.choice(SERVICE_PRINCIPALS)
    error_code, error_msg = random.choice(SP_ERROR_CODES)
    success = error_code == 0

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Sign-in activity",
        "category": "ServicePrincipalSignInLogs",
        "tenantId": TENANT_ID,
        "resultType": str(error_code),
        "callerIpAddress": sp["ipAddress"],
        "correlationId": cid,
        "identity": sp["appDisplayName"],
        "Level": 4,
        "location": "US",
        "properties": {
            "id": cid,
            "createdDateTime": ts,
            "appId": sp["appId"],
            "appDisplayName": sp["appDisplayName"],
            "servicePrincipalId": sp["servicePrincipalId"],
            "servicePrincipalName": sp["appDisplayName"],
            "ipAddress": sp["ipAddress"],
            "resourceDisplayName": sp["resourceDisplayName"],
            "resourceId": sp["resourceId"],
            "isInteractive": False,
            "tokenIssuerType": "AzureAD",
            "riskState": "none",
            "status": {
                "errorCode": error_code,
                "failureReason": error_msg if not success else None
            },
            "location": {
                "city": "Internal",
                "countryOrRegion": "US"
            },
            "authenticationDetails": [
                {
                    "authenticationMethod": "Client secret" if success else "Client certificate",
                    "succeeded": success,
                }
            ]
        }
    }

    if not success:
        event["resultDescription"] = error_msg

    return json.dumps(event)


# =============================================================================
# AUDIT EVENT GENERATORS
# =============================================================================

def audit_base(ts: str, category: str, activity: str, admin_key: str, target_json: Dict,
               target_username: str = None, day: int = None,
               active_scenarios: list = None) -> str:
    """Generate base audit event."""
    admin_id, admin_name, admin_ip = _resolve_admin(admin_key)
    audit_id = f"audit-{random.randint(10000, 99999)}"

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": activity,
        "category": "AuditLogs",
        "tenantId": TENANT_ID,
        "resultType": "Success",
        "callerIpAddress": admin_ip,
        "correlationId": audit_id,
        "identity": admin_name,
        "Level": 4,
        "properties": {
            "id": audit_id,
            "category": category,
            "activityDisplayName": activity,
            "activityDateTime": ts,
            "loggedByService": "Core Directory",
            "operationType": "Update",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "id": admin_id,
                    "displayName": admin_name,
                    "userPrincipalName": f"{admin_key}@{TENANT}",
                    "ipAddress": admin_ip
                }
            },
            "targetResources": [target_json]
        }
    }

    # Add demo_id for exfil scenario if target is Jessica/Alex
    if active_scenarios and target_username and day is not None:
        if should_tag_signin_exfil(target_username, day, active_scenarios):
            event["demo_id"] = "exfil"

    return json.dumps(event)


# =============================================================================
# ENRICHED AUDIT EVENT GENERATORS (with real group/app/role details)
# =============================================================================

def audit_add_member_to_group(base_date: str, day: int, hour: int, minute: int = None,
                               target_user=None, group_name: str = None,
                               admin_key: str = None, demo_id: str = None,
                               active_scenarios: list = None) -> str:
    """Add user to Entra security group — with real group name and user details."""
    if minute is None:
        minute = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    if admin_key is None:
        admin_key = random.choice(_BASELINE_ADMIN_KEYS)

    # Pick a real user and group
    if target_user is None:
        target_user = get_random_user()
    if group_name is None:
        group_name = random.choice(list(ENTRA_GROUP_DEFINITIONS.keys()))

    # Generate deterministic group ID
    group_id = str(uuid.uuid5(uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef0123456789"), f"group:{group_name}"))

    target = {
        "id": target_user.entra_object_id,
        "displayName": target_user.display_name,
        "type": "User",
        "userPrincipalName": target_user.email,
        "modifiedProperties": [
            {"displayName": "Group.DisplayName", "newValue": f'"{group_name}"'},
            {"displayName": "Group.ObjectID", "newValue": f'"{group_id}"'},
        ]
    }
    event_str = audit_base(ts, "GroupManagement", "Add member to group", admin_key, target,
                           target_username=target_user.username, day=day,
                           active_scenarios=active_scenarios)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_remove_member_from_group(base_date: str, day: int, hour: int, minute: int = None,
                                    target_user=None, group_name: str = None,
                                    admin_key: str = None, demo_id: str = None,
                                    active_scenarios: list = None) -> str:
    """Remove user from Entra security group — with real group name and user details."""
    if minute is None:
        minute = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    if admin_key is None:
        admin_key = random.choice(_BASELINE_ADMIN_KEYS)

    if target_user is None:
        target_user = get_random_user()
    if group_name is None:
        group_name = random.choice(list(ENTRA_GROUP_DEFINITIONS.keys()))

    group_id = str(uuid.uuid5(uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef0123456789"), f"group:{group_name}"))

    target = {
        "id": target_user.entra_object_id,
        "displayName": target_user.display_name,
        "type": "User",
        "userPrincipalName": target_user.email,
        "modifiedProperties": [
            {"displayName": "Group.DisplayName", "oldValue": f'"{group_name}"'},
            {"displayName": "Group.ObjectID", "oldValue": f'"{group_id}"'},
        ]
    }
    event_str = audit_base(ts, "GroupManagement", "Remove member from group", admin_key, target,
                           target_username=target_user.username, day=day,
                           active_scenarios=active_scenarios)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_update_user(base_date: str, day: int, hour: int, minute: int = None,
                      target_user=None, attribute: str = None,
                      old_value: str = None, new_value: str = None,
                      admin_key: str = None, demo_id: str = None,
                      active_scenarios: list = None) -> str:
    """Update user attribute in Entra ID — with modifiedProperties old→new values."""
    if minute is None:
        minute = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    if admin_key is None:
        admin_key = random.choice(_BASELINE_ADMIN_KEYS)

    if target_user is None:
        target_user = get_random_user()

    # Pick a realistic attribute change if not specified
    if attribute is None:
        _ATTR_CHANGES = [
            ("JobTitle", "Analyst", "Senior Analyst"),
            ("JobTitle", "Engineer", "Senior Engineer"),
            ("Department", "Engineering", "IT"),
            ("Department", "Sales", "Marketing"),
            ("Manager", "old.manager", "new.manager"),
            ("MobilePhone", "+1-555-0100", "+1-555-0200"),
            ("OfficeLocation", "Floor 1", "Floor 2"),
            ("CompanyName", "The FAKE T-Shirt Company", "The FAKE T-Shirt Company"),
        ]
        attr_choice = random.choice(_ATTR_CHANGES)
        attribute = attr_choice[0]
        old_value = attr_choice[1]
        new_value = attr_choice[2]

    target = {
        "id": target_user.entra_object_id,
        "displayName": target_user.display_name,
        "type": "User",
        "userPrincipalName": target_user.email,
        "modifiedProperties": [
            {"displayName": attribute, "oldValue": f'"{old_value}"', "newValue": f'"{new_value}"'},
        ]
    }
    event_str = audit_base(ts, "UserManagement", "Update user", admin_key, target,
                           target_username=target_user.username, day=day,
                           active_scenarios=active_scenarios)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_assign_license(base_date: str, day: int, hour: int, minute: int = None,
                         target_user=None, app_name: str = None,
                         admin_key: str = None, demo_id: str = None,
                         active_scenarios: list = None) -> str:
    """Assign application license/role to user — with real app name from catalog."""
    if minute is None:
        minute = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    if admin_key is None:
        admin_key = random.choice(_BASELINE_ADMIN_KEYS)

    if target_user is None:
        target_user = get_random_user()
    if app_name is None:
        # Pick from non-all_users apps (interesting assignments)
        _dept_apps = [name for name, info in ENTRA_APP_CATALOG.items()
                      if not info.get("all_users")]
        app_name = random.choice(_dept_apps) if _dept_apps else "Microsoft Office 365"

    app_id = ENTRA_APP_CATALOG.get(app_name, {}).get("id", "app-unknown-001")

    target = {
        "id": target_user.entra_object_id,
        "displayName": target_user.display_name,
        "type": "User",
        "userPrincipalName": target_user.email,
        "modifiedProperties": [
            {"displayName": "AppRole.DisplayName", "newValue": f'"User"'},
            {"displayName": "AppRole.Value", "newValue": f'"Default Access"'},
            {"displayName": "Application.DisplayName", "newValue": f'"{app_name}"'},
            {"displayName": "Application.ObjectID", "newValue": f'"{app_id}"'},
        ]
    }
    event_str = audit_base(ts, "ApplicationManagement", "Add app role assignment to user", admin_key, target,
                           target_username=target_user.username, day=day,
                           active_scenarios=active_scenarios)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


# Legacy function kept for backward compatibility (scenarios may call it)
def audit_user_management(base_date: str, day: int, hour: int,
                          active_scenarios: list = None) -> str:
    """Generate random user management audit event (legacy wrapper)."""
    # Delegate to specific enriched functions
    event_type = random.choices(
        ["group_add", "group_remove", "update_user", "license"],
        weights=[35, 15, 35, 15], k=1
    )[0]

    if event_type == "group_add":
        return audit_add_member_to_group(base_date, day, hour, active_scenarios=active_scenarios)
    elif event_type == "group_remove":
        return audit_remove_member_from_group(base_date, day, hour, active_scenarios=active_scenarios)
    elif event_type == "update_user":
        return audit_update_user(base_date, day, hour, active_scenarios=active_scenarios)
    else:
        return audit_assign_license(base_date, day, hour, active_scenarios=active_scenarios)


# =============================================================================
# OPERATIONAL EVENTS (scheduled/routine)
# =============================================================================

def audit_ca_policy(base_date: str, day: int) -> str:
    """Generate Conditional Access policy update."""
    ts = ts_iso(base_date, day, 10, random.randint(0, 30), random.randint(0, 59))
    target = {
        "id": "policy-ca-001",
        "displayName": "Require MFA for admins",
        "type": "Policy",
        "modifiedProperties": [
            {"displayName": "State", "oldValue": "Enabled", "newValue": "Enabled"}
        ]
    }
    return audit_base(ts, "Policy", "Update conditional access policy", "sec.admin", target)


def audit_password_reset(base_date: str, day: int,
                         active_scenarios: list = None) -> str:
    """Generate password reset event."""
    ts = ts_iso(base_date, day, 14, random.randint(0, 30), random.randint(0, 59))
    user = get_random_user()
    target = {
        "id": user.entra_object_id,
        "displayName": user.display_name,
        "type": "User",
        "userPrincipalName": user.email,
        "modifiedProperties": [
            {"displayName": "PasswordProfile", "newValue": "********"}
        ]
    }
    return audit_base(ts, "UserManagement", "Reset user password", "helpdesk", target,
                      target_username=user.username, day=day,
                      active_scenarios=active_scenarios)


def audit_cert_update(base_date: str, day: int) -> str:
    """Generate certificate update event."""
    ts = ts_iso(base_date, day, 9, random.randint(0, 30), random.randint(0, 59))
    target = {
        "id": "cert-signing-001",
        "displayName": "Token Signing Certificate",
        "type": "Other",
        "modifiedProperties": [
            {"displayName": "NotAfter", "newValue": "2027-01-01T00:00:00Z"}
        ]
    }
    return audit_base(ts, "ApplicationManagement", "Update certificate", "it.admin", target)


# =============================================================================
# NEW AUDIT OPERATIONS (for scenario support)
# =============================================================================

def audit_add_application(base_date: str, day: int, hour: int, minute: int,
                          app_name: str = "DataSync Service",
                          admin_key: str = "it.admin",
                          demo_id: str = None) -> str:
    """Generate Add application event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    app_id = rand_uuid()
    target = {
        "id": app_id,
        "displayName": app_name,
        "type": "Application",
        "modifiedProperties": [
            {"displayName": "AppId", "newValue": app_id},
            {"displayName": "DisplayName", "newValue": app_name}
        ]
    }
    event_str = audit_base(ts, "ApplicationManagement", "Add application", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_add_service_principal_credentials(base_date: str, day: int, hour: int, minute: int,
                                            app_name: str = "DataSync Service",
                                            admin_key: str = "it.admin",
                                            demo_id: str = None) -> str:
    """Generate Add service principal credentials event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    sp_id = rand_uuid()
    target = {
        "id": sp_id,
        "displayName": app_name,
        "type": "ServicePrincipal",
        "modifiedProperties": [
            {"displayName": "KeyCredentials", "newValue": "[Added Key]"},
            {"displayName": "KeyType", "newValue": "AsymmetricX509Cert"}
        ]
    }
    event_str = audit_base(ts, "ApplicationManagement", "Add service principal credentials", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_add_member_to_role(base_date: str, day: int, hour: int, minute: int,
                             target_user: str = "svc-datasync",
                             role_name: str = "Application Administrator",
                             admin_key: str = "sec.admin",
                             demo_id: str = None) -> str:
    """Generate Add member to role event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    target = {
        "id": rand_uuid(),
        "displayName": target_user,
        "type": "User",
        "userPrincipalName": f"{target_user}@{TENANT}",
        "modifiedProperties": [
            {"displayName": "Role.DisplayName", "newValue": role_name},
            {"displayName": "Role.WellKnownObject", "newValue": "DirectoryRole"}
        ]
    }
    event_str = audit_base(ts, "RoleManagement", "Add member to role", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_remove_member_from_role(base_date: str, day: int, hour: int, minute: int,
                                  target_user: str = None,
                                  role_name: str = "Global Administrator",
                                  admin_key: str = "sec.admin",
                                  demo_id: str = None) -> str:
    """Generate Remove member from role event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    user = get_random_user() if not target_user else None
    target = {
        "id": rand_uuid(),
        "displayName": target_user or (user.display_name if user else "Unknown"),
        "type": "User",
        "modifiedProperties": [
            {"displayName": "Role.DisplayName", "oldValue": role_name},
            {"displayName": "Role.WellKnownObject", "oldValue": "DirectoryRole"}
        ]
    }
    event_str = audit_base(ts, "RoleManagement", "Remove member from role", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_consent_to_application(base_date: str, day: int, hour: int, minute: int,
                                 app_name: str = "DataSync Service",
                                 user_email: str = None,
                                 admin_key: str = "sec.admin",
                                 demo_id: str = None) -> str:
    """Generate Consent to application event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    target = {
        "id": rand_uuid(),
        "displayName": app_name,
        "type": "ServicePrincipal",
        "modifiedProperties": [
            {"displayName": "ConsentContext.IsAdminConsent", "newValue": "True"},
            {"displayName": "DelegatedPermissions", "newValue": "User.Read Mail.Read Files.Read.All"}
        ]
    }
    event_str = audit_base(ts, "ApplicationManagement", "Consent to application", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_revoke_signin_sessions(base_date: str, day: int, hour: int, minute: int,
                                 target_user: str = None,
                                 admin_key: str = "sec.admin",
                                 demo_id: str = None) -> str:
    """Generate Revoke sign in sessions event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    user = get_random_user() if not target_user else None
    user_display = target_user or (user.display_name if user else "Unknown User")
    user_email = f"{target_user}@{TENANT}" if target_user else (user.email if user else f"unknown@{TENANT}")
    target = {
        "id": rand_uuid(),
        "displayName": user_display,
        "type": "User",
        "userPrincipalName": user_email
    }
    event_str = audit_base(ts, "UserManagement", "Revoke sign in sessions", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_user_registered_security_info(base_date: str, day: int, hour: int, minute: int,
                                        target_user: str = None,
                                        method: str = "Authenticator App",
                                        demo_id: str = None) -> str:
    """Generate User registered security info event."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    user = get_random_user() if not target_user else None
    user_display = target_user or (user.display_name if user else "Unknown User")
    user_email = f"{target_user}@{TENANT}" if target_user else (user.email if user else f"unknown@{TENANT}")

    # Build event manually since this is a self-service action
    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "User registered security info",
        "category": "AuditLogs",
        "tenantId": TENANT_ID,
        "resultType": "Success",
        "callerIpAddress": get_us_ip(),
        "correlationId": rand_uuid(),
        "identity": user_display,
        "Level": 4,
        "properties": {
            "id": rand_uuid(),
            "category": "UserManagement",
            "activityDisplayName": "User registered security info",
            "activityDateTime": ts,
            "loggedByService": "Authentication Methods",
            "operationType": "Add",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "id": rand_uuid(),
                    "displayName": user_display,
                    "userPrincipalName": user_email
                }
            },
            "targetResources": [{
                "id": rand_uuid(),
                "displayName": method,
                "type": "Other",
                "modifiedProperties": [
                    {"displayName": "MethodType", "newValue": method}
                ]
            }]
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return json.dumps(event)


def audit_delete_authentication_method(base_date: str, day: int, hour: int, minute: int,
                                       target_user: str,
                                       method: str = "Authenticator App",
                                       admin_key: str = "helpdesk",
                                       demo_id: str = None) -> str:
    """Generate Admin deleted authentication method for user (MFA reset).

    Logged when an admin removes an authentication method (e.g., Authenticator App)
    from a user account. This is a key step in MFA bypass attacks.
    """
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    target = {
        "id": rand_uuid(),
        "displayName": target_user,
        "type": "User",
        "userPrincipalName": f"{target_user}@{TENANT}",
        "modifiedProperties": [
            {"displayName": "StrongAuthenticationMethod", "oldValue": method, "newValue": ""},
            {"displayName": "StrongAuthenticationPhoneAppDetail", "oldValue": "[Redacted]", "newValue": ""}
        ]
    }
    event_str = audit_base(ts, "UserManagement", "Admin deleted authentication method for user",
                           admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_confirm_user_compromised(base_date: str, day: int, hour: int, minute: int,
                                   target_user: str,
                                   admin_key: str = "sec.admin",
                                   demo_id: str = None) -> str:
    """Generate Confirm user compromised event (Identity Protection)."""
    ts = ts_iso(base_date, day, hour, minute, random.randint(0, 59))
    target = {
        "id": rand_uuid(),
        "displayName": target_user,
        "type": "User",
        "userPrincipalName": f"{target_user}@{TENANT}",
        "modifiedProperties": [
            {"displayName": "RiskState", "oldValue": "atRisk", "newValue": "confirmedCompromised"},
            {"displayName": "RiskLevel", "newValue": "high"}
        ]
    }
    event_str = audit_base(ts, "UserManagement", "Confirm user compromised", admin_key, target)
    if demo_id:
        event = json.loads(event_str)
        event["demo_id"] = demo_id
        return json.dumps(event)
    return event_str


def audit_sspr_flow(base_date: str, day: int, hour: int, minute: int = None,
                    target_user: str = None,
                    step: str = None,
                    success: bool = True,
                    demo_id: str = None) -> str:
    """Generate Self-service password reset flow activity progress event.

    This audit event tracks the progress of a user through the SSPR flow,
    including verification steps like email, phone, authenticator app, etc.
    """
    if minute is None:
        minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    user = get_random_user() if not target_user else None
    user_display = target_user or (user.display_name if user else "Unknown User")
    user_email = f"{target_user}@{TENANT}" if target_user else (user.email if user else f"unknown@{TENANT}")
    user_id = user.entra_object_id if user else rand_uuid()

    if step is None:
        step = random.choice(SSPR_VERIFICATION_STEPS)

    result = "success" if success else "failure"
    result_type = "Success" if success else "Failure"

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Self-service password reset flow activity progress",
        "category": "AuditLogs",
        "tenantId": TENANT_ID,
        "resultType": result_type,
        "callerIpAddress": get_us_ip(),
        "correlationId": rand_uuid(),
        "identity": user_display,
        "Level": 4,
        "properties": {
            "id": rand_uuid(),
            "category": "UserManagement",
            "activityDisplayName": "Self-service password reset flow activity progress",
            "activityDateTime": ts,
            "loggedByService": "Self-service Password Management",
            "operationType": "Update",
            "result": result,
            "initiatedBy": {
                "user": {
                    "id": user_id,
                    "displayName": user_display,
                    "userPrincipalName": user_email
                }
            },
            "targetResources": [{
                "id": user_id,
                "displayName": user_display,
                "type": "User",
                "userPrincipalName": user_email,
                "modifiedProperties": [
                    {"displayName": "StepTitle", "newValue": step},
                    {"displayName": "StepResult", "newValue": result}
                ]
            }],
            "additionalDetails": [
                {"key": "StepTitle", "value": step},
                {"key": "StepResult", "value": result}
            ]
        }
    }

    if demo_id:
        event["demo_id"] = demo_id

    return json.dumps(event)


def audit_sspr_reset(base_date: str, day: int, hour: int, minute: int = None,
                     target_user: str = None,
                     demo_id: str = None) -> str:
    """Generate Reset password (self-service) event.

    This audit event is generated when a user successfully completes
    a self-service password reset.
    """
    if minute is None:
        minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    user = get_random_user() if not target_user else None
    user_display = target_user or (user.display_name if user else "Unknown User")
    user_email = f"{target_user}@{TENANT}" if target_user else (user.email if user else f"unknown@{TENANT}")
    user_id = user.entra_object_id if user else rand_uuid()

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Reset password (self-service)",
        "category": "AuditLogs",
        "tenantId": TENANT_ID,
        "resultType": "Success",
        "callerIpAddress": get_us_ip(),
        "correlationId": rand_uuid(),
        "identity": user_display,
        "Level": 4,
        "properties": {
            "id": rand_uuid(),
            "category": "UserManagement",
            "activityDisplayName": "Reset password (self-service)",
            "activityDateTime": ts,
            "loggedByService": "Self-service Password Management",
            "operationType": "Update",
            "result": "success",
            "initiatedBy": {
                "user": {
                    "id": user_id,
                    "displayName": user_display,
                    "userPrincipalName": user_email
                }
            },
            "targetResources": [{
                "id": user_id,
                "displayName": user_display,
                "type": "User",
                "userPrincipalName": user_email,
                "modifiedProperties": [
                    {"displayName": "PasswordProfile", "newValue": "********"}
                ]
            }]
        }
    }

    if demo_id:
        event["demo_id"] = demo_id

    return json.dumps(event)


# =============================================================================
# IDENTITY PROTECTION / RISK DETECTION EVENTS
# =============================================================================

def risk_detection(base_date: str, day: int, hour: int, minute: int = None,
                   target_user: str = None,
                   risk_event_type: str = None,
                   risk_level: str = None,
                   risk_state: str = "atRisk",
                   detection_timing: str = "realtime",
                   source_ip: str = None,
                   demo_id: str = None) -> str:
    """Generate Identity Protection risk detection event.

    This event is generated when Azure Identity Protection detects
    a risky sign-in or user behavior pattern.
    """
    if minute is None:
        minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_iso(base_date, day, hour, minute, second)

    user = get_random_user() if not target_user else None
    user_display = target_user or (user.display_name if user else "Unknown User")
    user_email = f"{target_user}@{TENANT}" if target_user else (user.email if user else f"unknown@{TENANT}")
    user_id = user.entra_object_id if user else rand_uuid()

    if risk_event_type is None:
        risk_event_type, risk_description = random.choice(RISK_EVENT_TYPES)
    else:
        # Find description for the given type
        risk_description = next(
            (desc for evt_type, desc in RISK_EVENT_TYPES if evt_type == risk_event_type),
            "Risk detected"
        )

    if risk_level is None:
        risk_level = random.choice(RISK_LEVELS)

    ip = source_ip or get_world_ip()

    event = {
        "time": ts,
        "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
        "operationName": "Risk detection",
        "category": "RiskDetection",
        "tenantId": TENANT_ID,
        "resultType": "Success",
        "callerIpAddress": ip,
        "correlationId": rand_uuid(),
        "identity": user_display,
        "Level": 4,
        "properties": {
            "id": rand_uuid(),
            "requestId": rand_uuid(),
            "correlationId": rand_uuid(),
            "riskEventType": risk_event_type,
            "riskEventTypes": [risk_event_type],
            "riskType": risk_event_type,
            "riskLevel": risk_level,
            "riskState": risk_state,
            "riskDetail": risk_description,
            "source": "IdentityProtection",
            "detectionTimingType": detection_timing,
            "activity": "signin",
            "activityDateTime": ts,
            "detectedDateTime": ts,
            "lastUpdatedDateTime": ts,
            "userId": user_id,
            "userDisplayName": user_display,
            "userPrincipalName": user_email,
            "ipAddress": ip,
            "location": {
                "city": "Unknown",
                "countryOrRegion": "Unknown",
                "state": "Unknown"
            },
            "additionalInfo": json.dumps([
                {"Key": "riskReasons", "Value": f"[\"{risk_description}\"]"},
                {"Key": "alertUrl", "Value": f"https://portal.azure.com/#blade/Microsoft_AAD_IAM/RiskyUsersBlade/userId/{user_id}"}
            ])
        }
    }

    if demo_id:
        event["demo_id"] = demo_id

    return json.dumps(event)


def signin_lockout(base_date: str, day: int) -> List[str]:
    """Generate account lockout events (legitimate user)."""
    events = []
    user = get_random_user()
    ip = user.get_ip()

    for i in range(3):
        ts = ts_iso(base_date, day, 9, 10 + i, random.randint(0, 59))
        cid = rand_uuid()

        event = {
            "time": ts,
            "resourceId": f"/tenants/{TENANT_ID}/providers/Microsoft.aadiam",
            "operationName": "Sign-in activity",
            "category": "SignInLogs",
            "tenantId": TENANT_ID,
            "resultType": "50053",
            "resultDescription": "Account is locked",
            "callerIpAddress": ip,
            "correlationId": cid,
            "identity": user.display_name,
            "Level": 4,
            "location": user.country,
            "properties": {
                "id": cid,
                "createdDateTime": ts,
                "userDisplayName": user.display_name,
                "userPrincipalName": user.email,
                "userId": user.entra_object_id,
                "appId": "00000002-0000-0ff1-ce00-000000000000",
                "appDisplayName": "Office 365 Exchange Online",
                "ipAddress": ip,
                "clientAppUsed": "Browser",
                "authenticationRequirement": "multiFactorAuthentication",
                "tokenIssuerType": "AzureAD",
                "riskState": "none",
                "riskDetail": "none",
                "status": {"errorCode": 50053, "failureReason": "User account is locked"},
                "deviceDetail": {
                    "deviceId": user.entra_device_id,
                    "displayName": user.device_name
                },
                "location": {
                    "city": user.city,
                    "countryOrRegion": user.country
                }
            }
        }
        events.append(json.dumps(event))

    return events


def generate_audit_day(base_date: str, day: int, base_count: int,
                       active_scenarios: list = None) -> List[str]:
    """Generate enriched audit events for one day.

    base_count scales all event categories proportionally (default 200 at scale=1.0).
    At base_count=200, produces ~150-250 events/day for a 175-employee tenant.

    Event distribution (all with real group/app/role/attribute details):
    - Group membership changes: 15-25/day (add + occasional remove)
    - User attribute updates: 10-20/day (title, department, manager, phone, office)
    - License/app assignments: 3-6/day
    - Directory role changes: 1-2/day
    - Password resets: 8-15/day
    - CA policy updates: weekly
    - Certificate updates: bi-weekly
    - SSPR flows: 30-50/day
    - App consent/registration: 5-10/day
    """
    events = []
    # Scale factor relative to baseline of 200
    sf = max(0.1, base_count / 200.0)

    # ---- Group membership changes (15-25 per day) ----
    group_count = random.randint(int(15 * sf), max(int(15 * sf) + 1, int(25 * sf)))
    for _ in range(group_count):
        hour = random.randint(8, 17)
        user = get_random_user()
        # 75% adds, 25% removes
        if random.random() < 0.75:
            # Pick a group the user should logically belong to
            user_groups = get_user_groups(user)
            group = random.choice(user_groups) if user_groups else random.choice(list(ENTRA_GROUP_DEFINITIONS.keys()))
            events.append(audit_add_member_to_group(
                base_date, day, hour, target_user=user, group_name=group,
                active_scenarios=active_scenarios
            ))
        else:
            # Remove from a non-essential group
            all_groups = list(ENTRA_GROUP_DEFINITIONS.keys())
            group = random.choice(all_groups)
            events.append(audit_remove_member_from_group(
                base_date, day, hour, target_user=user, group_name=group,
                active_scenarios=active_scenarios
            ))

    # ---- User attribute updates (10-20 per day) ----
    attr_count = random.randint(int(10 * sf), max(int(10 * sf) + 1, int(20 * sf)))
    for _ in range(attr_count):
        hour = random.randint(9, 16)
        events.append(audit_update_user(
            base_date, day, hour, active_scenarios=active_scenarios
        ))

    # ---- License/app assignments (3-6 per day) ----
    license_count = random.randint(int(3 * sf), max(int(3 * sf) + 1, int(6 * sf)))
    for _ in range(license_count):
        hour = random.randint(9, 15)
        events.append(audit_assign_license(
            base_date, day, hour, active_scenarios=active_scenarios
        ))

    # ---- Directory role changes (1-2 per day) ----
    role_count = random.randint(max(1, int(1 * sf)), max(1, int(2 * sf)))
    for _ in range(role_count):
        hour = random.randint(10, 14)
        # Pick a real role and member
        role_names = list(ENTRA_ROLE_ASSIGNMENTS.keys())
        role = random.choice(role_names)
        members = ENTRA_ROLE_ASSIGNMENTS[role]
        if members:
            member_key = random.choice(members)
            member_user = USERS.get(member_key)
            if member_user:
                events.append(audit_add_member_to_role(
                    base_date, day, hour, random.randint(0, 59),
                    target_user=member_user.display_name, role_name=role,
                    admin_key="sec.admin"
                ))

    # ---- Password resets (8-15 per day) ----
    reset_count = random.randint(int(8 * sf), max(int(8 * sf) + 1, int(15 * sf)))
    for _ in range(reset_count):
        events.append(audit_password_reset(base_date, day, active_scenarios))

    # ---- Operational events (periodic) ----
    # CA policy update every ~7 days
    if day % 7 == 1:
        events.append(audit_ca_policy(base_date, day))

    # Certificate update every ~10 days
    if day % 10 == 6:
        events.append(audit_cert_update(base_date, day))

    # ---- SSPR flow events (~30-50 per day, during business hours) ----
    sspr_count = random.randint(int(30 * sf), max(int(30 * sf) + 1, int(50 * sf)))
    for _ in range(sspr_count):
        hour = random.randint(8, 17)
        # Generate a flow sequence: verification step(s) followed by reset
        if random.random() < 0.7:  # 70% success rate
            # Successful flow: 1-2 verification steps + reset
            num_steps = random.randint(1, 2)
            for step_i in range(num_steps):
                minute = random.randint(0, 55)
                events.append(audit_sspr_flow(base_date, day, hour, minute + step_i))
            events.append(audit_sspr_reset(base_date, day, hour, minute + num_steps + 1))
        else:
            # Failed flow: verification step(s) that don't complete
            num_steps = random.randint(1, 3)
            for step_i in range(num_steps):
                minute = random.randint(0, 55)
                success = step_i < num_steps - 1  # Last step fails
                events.append(audit_sspr_flow(base_date, day, hour, minute + step_i, success=success))

    # ---- App consent/registration events (5-10 per day) ----
    consent_count = random.randint(int(5 * sf), max(int(5 * sf) + 1, int(10 * sf)))
    for _ in range(consent_count):
        hour = random.randint(9, 17)
        events.append(audit_assign_license(
            base_date, day, hour, active_scenarios=active_scenarios
        ))

    return events


def generate_risk_detection_day(base_date: str, day: int, active_scenarios: list = None) -> List[str]:
    """Generate risk detection events for one day."""
    events = []

    # Baseline risk detections (1-3 per day, low/medium risk)
    baseline_count = random.randint(1, 3)
    for _ in range(baseline_count):
        hour = random.randint(0, 23)
        # Baseline uses lower risk levels
        risk_level = random.choice(["low", "low", "medium"])
        events.append(risk_detection(base_date, day, hour, risk_level=risk_level))

    # Exfil scenario risk detections are now generated per-hour by
    # ExfilScenario.entraid_risk_hour() and injected in the main loop.
    # This provides phase-specific risk types aligned with the attack timeline.

    return events


def generate_signin_day_events(base_date: str, day: int) -> List[str]:
    """Generate day-specific sign-in events."""
    events = []

    # Account lockout on day 9
    if day == 9:
        events.extend(signin_lockout(base_date, day))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_entraid_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_signin: str = None,
    output_audit: str = None,
    output_risk: str = None,
    quiet: bool = False,
) -> int:
    """Generate Entra ID logs.

    When exfil scenario is active, includes attack events from ExfilScenario.

    Generates three log types:
    - Sign-in logs (azure:aad:signin) - operationName: "Sign-in activity"
    - Audit logs (azure:aad:audit) - various operationNames including SSPR
    - Risk detection logs (azure:aad:riskdetection) - operationName: "Risk detection"
    """

    signin_path = Path(output_signin) if output_signin else get_output_path("cloud", "entraid/entraid_signin.json")
    audit_path = Path(output_audit) if output_audit else get_output_path("cloud", "entraid/entraid_audit.json")
    risk_path = Path(output_risk) if output_risk else get_output_path("cloud", "entraid/entraid_risk_detection.json")

    signin_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    risk_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Initialize scenario support objects
    config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
    company = Company()
    time_utils = TimeUtils(start_date)

    # Initialize exfil scenario if active
    exfil_scenario = None
    if "exfil" in active_scenarios:
        try:
            from scenarios.security.exfil import ExfilScenario
            exfil_scenario = ExfilScenario(config, company, time_utils)
        except ImportError:
            pass  # Scenario not available

    # Initialize phishing test scenario if active
    phishing_test_scenario = None
    if "phishing_test" in active_scenarios:
        try:
            from scenarios.security.phishing_test import PhishingTestScenario
            phishing_test_scenario = PhishingTestScenario(demo_id_enabled=True)
        except ImportError:
            pass

    signin_base = int(35 * scale)
    audit_per_day = max(3, int(200 * scale))

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Entra ID Log Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {signin_path.parent}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    signin_events = []
    audit_events = []
    risk_events = []

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [Entra] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        # Sign-in events
        for hour in range(24):
            hour_events = calc_natural_events(signin_base, start_date, day, hour, "auth")
            signin_events.extend(generate_signin_hour(start_date, day, hour, hour_events, active_scenarios))

            # Exfil scenario signin events (failed logins from threat IP, CA blocks, etc.)
            if exfil_scenario:
                exfil_signin = exfil_scenario.entraid_signin_hour(day, hour)
                for e in exfil_signin:
                    if isinstance(e, str):
                        signin_events.append(e)
                    else:
                        signin_events.append(json.dumps(e))

            # Phishing test scenario signin events (credential submitters on sim platform)
            if phishing_test_scenario:
                pt_signin = phishing_test_scenario.entraid_signin_hour(day, hour)
                for e in pt_signin:
                    if isinstance(e, str):
                        signin_events.append(e)
                    else:
                        signin_events.append(json.dumps(e))

        # Day-specific sign-in events
        signin_events.extend(generate_signin_day_events(start_date, day))

        # Audit events (baseline + SSPR)
        audit_events.extend(generate_audit_day(start_date, day, audit_per_day, active_scenarios))

        # Risk detection events
        risk_events.extend(generate_risk_detection_day(start_date, day, active_scenarios))

        # Exfil scenario risk detection events (phase-specific: spray, impossible travel, etc.)
        if exfil_scenario:
            for hour in range(24):
                exfil_risk = exfil_scenario.entraid_risk_hour(day, hour)
                for e in exfil_risk:
                    if isinstance(e, str):
                        risk_events.append(e)
                    else:
                        risk_events.append(json.dumps(e))

        # Exfil scenario audit events (app creation, role assignment, consent, etc.)
        if exfil_scenario:
            for hour in range(24):
                exfil_audit = exfil_scenario.entraid_audit_hour(day, hour)
                for e in exfil_audit:
                    if isinstance(e, str):
                        audit_events.append(e)
                    else:
                        audit_events.append(json.dumps(e))

        if not quiet:
            print(f"  [Entra] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort events
    signin_events.sort()
    audit_events.sort()
    risk_events.sort()

    # Write output
    with open(signin_path, "w") as f:
        for event in signin_events:
            f.write(event + "\n")

    with open(audit_path, "w") as f:
        for event in audit_events:
            f.write(event + "\n")

    with open(risk_path, "w") as f:
        for event in risk_events:
            f.write(event + "\n")

    total = len(signin_events) + len(audit_events) + len(risk_events)
    file_counts = {
        "cloud/entraid/entraid_signin.json": len(signin_events),
        "cloud/entraid/entraid_audit.json": len(audit_events),
        "cloud/entraid/entraid_risk_detection.json": len(risk_events),
    }

    if not quiet:
        # Count exfil events
        exfil_signin = sum(1 for e in signin_events if '"demo_id": "exfil"' in e or '"demo_id":"exfil"' in e)
        exfil_audit = sum(1 for e in audit_events if '"demo_id": "exfil"' in e or '"demo_id":"exfil"' in e)
        exfil_risk = sum(1 for e in risk_events if '"demo_id": "exfil"' in e or '"demo_id":"exfil"' in e)
        print(f"  [Entra] Complete! {total:,} events ({len(signin_events):,} signin, {len(audit_events):,} audit, {len(risk_events):,} risk)", file=sys.stderr)
        if exfil_signin or exfil_audit or exfil_risk:
            print(f"          exfil events: {exfil_signin} signin, {exfil_audit} audit, {exfil_risk} risk", file=sys.stderr)

    return {"total": total, "files": file_counts}


def main():
    parser = argparse.ArgumentParser(description="Generate Entra ID logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output-signin")
    parser.add_argument("--output-audit")
    parser.add_argument("--output-risk")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_entraid_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_signin=args.output_signin,
        output_audit=args.output_audit, output_risk=args.output_risk,
        quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
