#!/usr/bin/env python3
"""
AWS CloudTrail Log Generator.
Generates realistic AWS CloudTrail events with natural volume variation.

Field validation fixes applied:
  - principalId: Deterministic per user (from company.py)
  - accessKeyId: Deterministic per user (from company.py)
  - sourceIPAddress: User's office IP (consistent per user)
  - userAgent: Varied per user (Console, CLI, SDK)
  - userIdentity.type: AssumedRole for Lambda/EC2 service calls
  - readOnly: Boolean based on event type
  - managementEvent: True for management events
  - resources: ARN array on all events
  - sessionContext: Added for AssumedRole events
  - recipientAccountId: Already present (verified)
"""

import argparse
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path, Config
from shared.time_utils import ts_iso, date_add, calc_natural_events, TimeUtils
from shared.company import (
    AWS_ACCOUNT_ID, AWS_REGION, ORG_NAME_LOWER,
    USERS, USER_KEYS, get_random_user, Company,
    _AWS_USER_AGENT_PROFILES,
)
from scenarios.registry import expand_scenarios

# =============================================================================
# AWS CONFIGURATION
# =============================================================================

# Service accounts (automated systems — use AssumedRole identity)
AWS_SERVICE_ROLES = {
    "svc-backup": {
        "role_name": "BackupServiceRole",
        "session_name": "backup-automation",
    },
    "svc-deployment": {
        "role_name": "DeploymentPipelineRole",
        "session_name": "codepipeline-deploy",
    },
    "data-pipeline": {
        "role_name": "DataPipelineRole",
        "session_name": "glue-etl-job",
    },
}

# Human IAM users (use IAMUser identity — picked from company.py users)
AWS_HUMAN_USERS = [
    "david.robinson",    # IT Director
    "jessica.brown",     # IT Administrator
    "angela.james",      # Cloud Engineer
    "carlos.martinez",   # DevOps Engineer
    "brandon.turner",    # DevOps Engineer
    "patrick.gonzalez",  # Systems Administrator
]

AWS_BUCKETS = [f"{ORG_NAME_LOWER}-prod-data", f"{ORG_NAME_LOWER}-backups", f"{ORG_NAME_LOWER}-logs"]
AWS_LAMBDAS = ["process-orders", "send-notifications", "data-transform", "api-handler"]
AWS_EC2_INSTANCES = ["i-0abc123def456", "i-0def789abc012", "i-0123456789abc"]

# Read-only event names (Get*, List*, Describe*, Head*)
_READ_ONLY_PREFIXES = ("Get", "List", "Describe", "Head", "Lookup")

# Baseline error definitions (3-5% of events)
# Format: (errorCode, errorMessage, applicable_event_names)
_AWS_BASELINE_ERRORS = [
    ("AccessDenied", "Access Denied", ["GetObject", "PutObject", "DeleteObject", "Invoke"]),
    ("NoSuchKey", "The specified key does not exist.", ["GetObject", "DeleteObject"]),
    ("NoSuchBucket", "The specified bucket does not exist", ["GetObject", "PutObject"]),
    ("Throttling", "Rate exceeded", ["DescribeInstances", "ListUsers", "Invoke", "GetObject"]),
    ("UnauthorizedAccess", "User is not authorized to perform this operation", ["CreateAccessKey", "DeleteAccessKey", "AssumeRole"]),
]
_BASELINE_ERROR_RATE = 0.04  # 4% of baseline events fail


def _maybe_inject_error(event: Dict[str, Any], event_name: str) -> Dict[str, Any]:
    """Potentially inject an error into a baseline event (~4% chance)."""
    if random.random() > _BASELINE_ERROR_RATE:
        return event

    # Find applicable errors for this event type
    applicable = [(code, msg) for code, msg, events in _AWS_BASELINE_ERRORS
                   if event_name in events]
    if not applicable:
        return event

    error_code, error_msg = random.choice(applicable)
    event["errorCode"] = error_code
    event["errorMessage"] = error_msg
    # Failed events have no responseElements
    event["responseElements"] = None
    return event


def _is_read_only(event_name: str) -> bool:
    """Determine if an event is read-only based on its name."""
    return event_name.startswith(_READ_ONLY_PREFIXES)


def should_tag_exfil(day: int, event_name: str, active_scenarios: list) -> bool:
    """Check if event should get exfil demo_id.

    Exfil scenario:
    - Staging phase (day 8-10): GetObject, PutObject, ListBucket
    - Exfil phase (day 11-14): GetObject (large downloads)
    """
    if "exfil" not in active_scenarios:
        return False
    # Exfil scenario: day 8-14 (0-indexed: 7-13)
    if day < 7 or day > 13:
        return False
    # Tag S3 operations during staging/exfil phase
    return event_name in ["GetObject", "PutObject", "ListBucket"]

# =============================================================================
# EVENT GENERATORS
# =============================================================================

def _pick_human_user() -> "User":
    """Pick a random human AWS user from company.py."""
    username = random.choice(AWS_HUMAN_USERS)
    return USERS[username]


def aws_iam_user_event(base_date: str, day: int, hour: int, minute: int, second: int,
                       event_name: str, event_source: str, user) -> Dict[str, Any]:
    """Create CloudTrail event with IAMUser identity (human users)."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": user.aws_principal_id,
            "arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user.username}",
            "accountId": AWS_ACCOUNT_ID,
            "accessKeyId": user.aws_access_key_id,
            "userName": user.username,
        },
        "eventTime": ts_iso(base_date, day, hour, minute, second),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": AWS_REGION,
        "sourceIPAddress": user.ip_address,
        "userAgent": user.aws_user_agent,
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "recipientAccountId": AWS_ACCOUNT_ID,
        "readOnly": _is_read_only(event_name),
        "managementEvent": True,
    }


def aws_assumed_role_event(base_date: str, day: int, hour: int, minute: int, second: int,
                           event_name: str, event_source: str,
                           role_name: str, session_name: str) -> Dict[str, Any]:
    """Create CloudTrail event with AssumedRole identity (service accounts)."""
    role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{role_name}"
    assumed_role_arn = f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/{role_name}/{session_name}"
    # AssumedRole principalId format: AROA... : session-name
    role_id = f"AROA{uuid.uuid5(uuid.NAMESPACE_DNS, role_name).hex[:16].upper()}"

    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"{role_id}:{session_name}",
            "arn": assumed_role_arn,
            "accountId": AWS_ACCOUNT_ID,
            "accessKeyId": f"ASIA{uuid.uuid5(uuid.NAMESPACE_DNS, f'sts:{role_name}').hex[:16].upper()}",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role_id,
                    "arn": role_arn,
                    "accountId": AWS_ACCOUNT_ID,
                    "userName": role_name,
                },
                "attributes": {
                    "creationDate": ts_iso(base_date, day, hour, 0, 0),
                    "mfaAuthenticated": "false",
                },
            },
        },
        "eventTime": ts_iso(base_date, day, hour, minute, second),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": AWS_REGION,
        "sourceIPAddress": f"{event_source}",  # Service-initiated calls show the service
        "userAgent": f"{event_source}",
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "recipientAccountId": AWS_ACCOUNT_ID,
        "readOnly": _is_read_only(event_name),
        "managementEvent": True,
    }


def aws_s3_get_object(base_date: str, day: int, hour: int, active_scenarios: list = None) -> Dict[str, Any]:
    """Generate S3 GetObject event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    bucket = random.choice(AWS_BUCKETS)
    key = f"data/{random.choice(['reports', 'exports', 'logs'])}/file_{random.randint(1000, 9999)}.json"

    event = aws_iam_user_event(base_date, day, hour, minute, second, "GetObject", "s3.amazonaws.com", user)
    event["requestParameters"] = {"bucketName": bucket, "key": key}
    event["responseElements"] = None
    event["resources"] = [
        {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
        {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}", "accountId": AWS_ACCOUNT_ID},
    ]

    if active_scenarios and should_tag_exfil(day, "GetObject", active_scenarios):
        event["demo_id"] = "exfil"

    return _maybe_inject_error(event, "GetObject")


def aws_s3_put_object(base_date: str, day: int, hour: int, active_scenarios: list = None) -> Dict[str, Any]:
    """Generate S3 PutObject event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)

    # 60% human uploads, 40% service (backup/pipeline)
    if random.random() < 0.6:
        user = _pick_human_user()
        event = aws_iam_user_event(base_date, day, hour, minute, second, "PutObject", "s3.amazonaws.com", user)
    else:
        svc = random.choice(list(AWS_SERVICE_ROLES.values()))
        event = aws_assumed_role_event(base_date, day, hour, minute, second, "PutObject", "s3.amazonaws.com",
                                       svc["role_name"], svc["session_name"])

    bucket = random.choice(AWS_BUCKETS)
    key = f"uploads/{random.choice(['daily', 'hourly'])}/data_{random.randint(1000, 9999)}.csv"
    event["requestParameters"] = {"bucketName": bucket, "key": key}
    event["responseElements"] = {"x-amz-server-side-encryption": "AES256"}
    event["resources"] = [
        {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
        {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}", "accountId": AWS_ACCOUNT_ID},
    ]

    if active_scenarios and should_tag_exfil(day, "PutObject", active_scenarios):
        event["demo_id"] = "exfil"

    return _maybe_inject_error(event, "PutObject")


def aws_s3_delete_object(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate S3 DeleteObject event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    bucket = random.choice(AWS_BUCKETS)
    key = f"data/{random.choice(['temp', 'old', 'archive'])}/file_{random.randint(1000, 9999)}.json"

    event = aws_iam_user_event(base_date, day, hour, minute, second, "DeleteObject", "s3.amazonaws.com", user)
    event["requestParameters"] = {"bucketName": bucket, "key": key}
    event["responseElements"] = None
    event["resources"] = [
        {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
        {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}", "accountId": AWS_ACCOUNT_ID},
    ]
    return _maybe_inject_error(event, "DeleteObject")


def aws_ec2_describe(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate EC2 DescribeInstances event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    instance_id = random.choice(AWS_EC2_INSTANCES)

    # 70% human (IT/DevOps checking instances), 30% service (monitoring)
    if random.random() < 0.7:
        user = _pick_human_user()
        event = aws_iam_user_event(base_date, day, hour, minute, second, "DescribeInstances", "ec2.amazonaws.com", user)
    else:
        svc = AWS_SERVICE_ROLES["svc-deployment"]
        event = aws_assumed_role_event(base_date, day, hour, minute, second, "DescribeInstances", "ec2.amazonaws.com",
                                       svc["role_name"], svc["session_name"])

    event["requestParameters"] = {"instancesSet": {"items": [{"instanceId": instance_id}]}}
    event["responseElements"] = None
    event["resources"] = [
        {"type": "AWS::EC2::Instance", "ARN": f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_ID}:instance/{instance_id}"},
    ]
    return _maybe_inject_error(event, "DescribeInstances")


def aws_lambda_invoke(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Lambda Invoke event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    func = random.choice(AWS_LAMBDAS)

    # Lambda invocations are mostly service-initiated (80%)
    if random.random() < 0.2:
        user = _pick_human_user()
        event = aws_iam_user_event(base_date, day, hour, minute, second, "Invoke", "lambda.amazonaws.com", user)
    else:
        svc = AWS_SERVICE_ROLES["data-pipeline"]
        event = aws_assumed_role_event(base_date, day, hour, minute, second, "Invoke", "lambda.amazonaws.com",
                                       svc["role_name"], svc["session_name"])

    event["requestParameters"] = {"functionName": func, "invocationType": "RequestResponse"}
    event["responseElements"] = None
    event["resources"] = [
        {"type": "AWS::Lambda::Function", "ARN": f"arn:aws:lambda:{AWS_REGION}:{AWS_ACCOUNT_ID}:function:{func}"},
    ]
    return _maybe_inject_error(event, "Invoke")


def aws_iam_list_users(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate IAM ListUsers event (read-only, management)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    event = aws_iam_user_event(base_date, day, hour, minute, second, "ListUsers", "iam.amazonaws.com", user)
    event["requestParameters"] = None
    event["responseElements"] = None
    return event


def aws_sts_get_caller_identity(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate STS GetCallerIdentity event (common verification call)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    event = aws_iam_user_event(base_date, day, hour, minute, second, "GetCallerIdentity", "sts.amazonaws.com", user)
    event["requestParameters"] = None
    event["responseElements"] = {
        "userId": user.aws_principal_id,
        "account": AWS_ACCOUNT_ID,
        "arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user.username}",
    }
    return event


def aws_sts_assume_role(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate STS AssumeRole event (service account role assumption)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    svc_key = random.choice(list(AWS_SERVICE_ROLES.keys()))
    svc = AWS_SERVICE_ROLES[svc_key]

    # 60% service-initiated, 40% human-initiated
    if random.random() < 0.4:
        user = _pick_human_user()
        event = aws_iam_user_event(base_date, day, hour, minute, second, "AssumeRole", "sts.amazonaws.com", user)
    else:
        event = aws_assumed_role_event(base_date, day, hour, minute, second, "AssumeRole", "sts.amazonaws.com",
                                       svc["role_name"], svc["session_name"])

    role_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{svc['role_name']}"
    event["requestParameters"] = {
        "roleArn": role_arn,
        "roleSessionName": svc["session_name"],
        "durationSeconds": 3600,
    }
    event["responseElements"] = {
        "credentials": {
            "accessKeyId": f"ASIA{uuid.uuid5(uuid.NAMESPACE_DNS, f'sts:{svc_key}').hex[:16].upper()}",
            "expiration": ts_iso(base_date, day, hour + 1 if hour < 23 else 23, minute, second),
        },
        "assumedRoleUser": {
            "assumedRoleId": f"AROA{uuid.uuid5(uuid.NAMESPACE_DNS, svc['role_name']).hex[:16].upper()}:{svc['session_name']}",
            "arn": f"arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/{svc['role_name']}/{svc['session_name']}",
        },
    }
    return _maybe_inject_error(event, "AssumeRole")


def aws_console_login(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate ConsoleLogin event (AWS Management Console sign-in)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()

    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": user.aws_principal_id,
            "arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user.username}",
            "accountId": AWS_ACCOUNT_ID,
            "userName": user.username,
        },
        "eventTime": ts_iso(base_date, day, hour, minute, second),
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": AWS_REGION,
        "sourceIPAddress": user.ip_address,
        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsConsoleSignIn",
        "recipientAccountId": AWS_ACCOUNT_ID,
        "readOnly": False,
        "managementEvent": True,
    }

    # ~5% of console logins fail
    if random.random() < 0.05:
        event["responseElements"] = {"ConsoleLogin": "Failure"}
        event["additionalEventData"] = {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={AWS_REGION}",
            "MobileVersion": "No",
            "MFAUsed": "No",
        }
        event["errorMessage"] = "Failed authentication"
    else:
        event["responseElements"] = {"ConsoleLogin": "Success"}
        event["additionalEventData"] = {
            "LoginTo": f"https://console.aws.amazon.com/console/home?region={AWS_REGION}",
            "MobileVersion": "No",
            "MFAUsed": random.choice(["Yes", "Yes", "Yes", "No"]),  # 75% MFA
        }

    return event


def aws_iam_create_access_key(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate IAM CreateAccessKey event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    target_user = random.choice(AWS_HUMAN_USERS)

    event = aws_iam_user_event(base_date, day, hour, minute, second, "CreateAccessKey", "iam.amazonaws.com", user)
    event["requestParameters"] = {"userName": target_user}
    event["responseElements"] = {
        "accessKey": {
            "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
            "status": "Active",
            "userName": target_user,
        }
    }
    return _maybe_inject_error(event, "CreateAccessKey")


def aws_iam_delete_access_key(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate IAM DeleteAccessKey event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = _pick_human_user()
    target_user = random.choice(AWS_HUMAN_USERS)

    event = aws_iam_user_event(base_date, day, hour, minute, second, "DeleteAccessKey", "iam.amazonaws.com", user)
    event["requestParameters"] = {
        "userName": target_user,
        "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
    }
    event["responseElements"] = None
    return _maybe_inject_error(event, "DeleteAccessKey")


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int,
                          active_scenarios: list = None) -> List[Dict[str, Any]]:
    """Generate baseline events for one hour.

    Event distribution (updated with new event types):
    - 20% S3 GetObject
    - 15% S3 PutObject
    - 3%  S3 DeleteObject (cleanup, lifecycle)
    - 12% EC2 DescribeInstances
    - 18% Lambda Invoke
    - 8%  IAM ListUsers
    - 7%  STS GetCallerIdentity
    - 8%  STS AssumeRole (service role assumptions)
    - 5%  ConsoleLogin (human console sign-ins)
    - 2%  IAM CreateAccessKey (key rotation)
    - 2%  IAM DeleteAccessKey (key rotation)
    """
    events = []

    for _ in range(event_count):
        event_type = random.randint(1, 100)

        if event_type <= 20:
            events.append(aws_s3_get_object(base_date, day, hour, active_scenarios))
        elif event_type <= 35:
            events.append(aws_s3_put_object(base_date, day, hour, active_scenarios))
        elif event_type <= 38:
            events.append(aws_s3_delete_object(base_date, day, hour))
        elif event_type <= 50:
            events.append(aws_ec2_describe(base_date, day, hour))
        elif event_type <= 68:
            events.append(aws_lambda_invoke(base_date, day, hour))
        elif event_type <= 76:
            events.append(aws_iam_list_users(base_date, day, hour))
        elif event_type <= 83:
            events.append(aws_sts_get_caller_identity(base_date, day, hour))
        elif event_type <= 91:
            events.append(aws_sts_assume_role(base_date, day, hour))
        elif event_type <= 96:
            events.append(aws_console_login(base_date, day, hour))
        elif event_type <= 98:
            events.append(aws_iam_create_access_key(base_date, day, hour))
        else:
            events.append(aws_iam_delete_access_key(base_date, day, hour))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_aws_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate AWS CloudTrail logs.

    When exfil scenario is active, includes attack events from ExfilScenario:
    - Day 5: CreateUser, AttachUserPolicy (backdoor IAM user)
    - Days 11-13: GetObject from sensitive bucket (data exfiltration)
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "aws/aws_cloudtrail.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

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

    base_events_per_peak_hour = int(15 * scale)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  AWS CloudTrail Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events = []

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [AWS] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for hour in range(24):
            hour_events = calc_natural_events(base_events_per_peak_hour, start_date, day, hour, "cloud")
            all_events.extend(generate_baseline_hour(start_date, day, hour, hour_events, active_scenarios))

            # Exfil scenario AWS events
            if exfil_scenario:
                exfil_events = exfil_scenario.aws_hour(day, hour)
                for e in exfil_events:
                    if isinstance(e, str):
                        all_events.append(json.loads(e))
                    else:
                        all_events.append(e)

        if not quiet:
            print(f"  [AWS] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort by eventTime
    all_events.sort(key=lambda x: x["eventTime"])

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    if not quiet:
        # Count exfil events and errors
        exfil_count = sum(1 for e in all_events if e.get("demo_id") == "exfil")
        error_count = sum(1 for e in all_events if "errorCode" in e or
                          (e.get("responseElements", {}) or {}).get("ConsoleLogin") == "Failure")
        print(f"  [AWS] Complete! {len(all_events):,} events written", file=sys.stderr)
        print(f"        errors: {error_count:,} ({error_count * 100 // max(len(all_events), 1)}%)", file=sys.stderr)
        if exfil_count:
            print(f"        exfil events: {exfil_count}", file=sys.stderr)

    return len(all_events)


def main():
    parser = argparse.ArgumentParser(description="Generate AWS CloudTrail logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_aws_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
