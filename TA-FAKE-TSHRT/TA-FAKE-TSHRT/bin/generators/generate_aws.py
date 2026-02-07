#!/usr/bin/env python3
"""
AWS CloudTrail Log Generator.
Generates realistic AWS CloudTrail events with natural volume variation.
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
    USERS, USER_KEYS, get_random_user, get_internal_ip, Company,
)
from scenarios.registry import expand_scenarios

# =============================================================================
# AWS CONFIGURATION
# =============================================================================

AWS_USERS = ["svc-backup", "svc-deployment", "admin-ops", "data-pipeline"]
AWS_BUCKETS = [f"{ORG_NAME_LOWER}-prod-data", f"{ORG_NAME_LOWER}-backups", f"{ORG_NAME_LOWER}-logs"]
AWS_LAMBDAS = ["process-orders", "send-notifications", "data-transform", "api-handler"]
AWS_EC2_INSTANCES = ["i-0abc123def456", "i-0def789abc012", "i-0123456789abc"]


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

def aws_base_event(base_date: str, day: int, hour: int, minute: int, second: int,
                   event_name: str, event_source: str, user: str) -> Dict[str, Any]:
    """Create base CloudTrail event structure."""
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"AIDA{uuid.uuid4().hex[:16].upper()}",
            "arn": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/{user}",
            "accountId": AWS_ACCOUNT_ID,
            "userName": user,
        },
        "eventTime": ts_iso(base_date, day, hour, minute, second),
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": AWS_REGION,
        "sourceIPAddress": get_internal_ip(),
        "userAgent": "aws-cli/2.13.0 Python/3.11.4",
        "requestID": str(uuid.uuid4()),
        "eventID": str(uuid.uuid4()),
        "eventType": "AwsApiCall",
        "recipientAccountId": AWS_ACCOUNT_ID,
    }


def aws_s3_get_object(base_date: str, day: int, hour: int, active_scenarios: list = None) -> Dict[str, Any]:
    """Generate S3 GetObject event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = random.choice(AWS_USERS)
    bucket = random.choice(AWS_BUCKETS)
    key = f"data/{random.choice(['reports', 'exports', 'logs'])}/file_{random.randint(1000, 9999)}.json"

    event = aws_base_event(base_date, day, hour, minute, second, "GetObject", "s3.amazonaws.com", user)
    event["requestParameters"] = {"bucketName": bucket, "key": key}
    event["responseElements"] = None
    event["resources"] = [
        {"type": "AWS::S3::Object", "ARN": f"arn:aws:s3:::{bucket}/{key}"},
        {"type": "AWS::S3::Bucket", "ARN": f"arn:aws:s3:::{bucket}"},
    ]

    if active_scenarios and should_tag_exfil(day, "GetObject", active_scenarios):
        event["demo_id"] = "exfil"

    return event


def aws_s3_put_object(base_date: str, day: int, hour: int, active_scenarios: list = None) -> Dict[str, Any]:
    """Generate S3 PutObject event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = random.choice(AWS_USERS)
    bucket = random.choice(AWS_BUCKETS)
    key = f"uploads/{random.choice(['daily', 'hourly'])}/data_{random.randint(1000, 9999)}.csv"

    event = aws_base_event(base_date, day, hour, minute, second, "PutObject", "s3.amazonaws.com", user)
    event["requestParameters"] = {"bucketName": bucket, "key": key}
    event["responseElements"] = {"x-amz-server-side-encryption": "AES256"}

    if active_scenarios and should_tag_exfil(day, "PutObject", active_scenarios):
        event["demo_id"] = "exfil"

    return event


def aws_ec2_describe(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate EC2 DescribeInstances event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = random.choice(AWS_USERS)

    event = aws_base_event(base_date, day, hour, minute, second, "DescribeInstances", "ec2.amazonaws.com", user)
    event["requestParameters"] = {"instancesSet": {"items": [{"instanceId": random.choice(AWS_EC2_INSTANCES)}]}}
    event["responseElements"] = None
    return event


def aws_lambda_invoke(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Lambda Invoke event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    user = random.choice(AWS_USERS)
    func = random.choice(AWS_LAMBDAS)

    event = aws_base_event(base_date, day, hour, minute, second, "Invoke", "lambda.amazonaws.com", user)
    event["requestParameters"] = {"functionName": func, "invocationType": "RequestResponse"}
    event["responseElements"] = None
    return event


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int,
                          active_scenarios: list = None) -> List[Dict[str, Any]]:
    """Generate baseline events for one hour."""
    events = []

    for _ in range(event_count):
        event_type = random.randint(1, 100)

        if event_type <= 30:
            events.append(aws_s3_get_object(base_date, day, hour, active_scenarios))
        elif event_type <= 50:
            events.append(aws_s3_put_object(base_date, day, hour, active_scenarios))
        elif event_type <= 70:
            events.append(aws_ec2_describe(base_date, day, hour))
        else:
            events.append(aws_lambda_invoke(base_date, day, hour))

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
        output_path = get_output_path("cloud", "aws_cloudtrail.json")

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
        # Count exfil events
        exfil_count = sum(1 for e in all_events if e.get("demo_id") == "exfil")
        print(f"  [AWS] Complete! {len(all_events):,} events written", file=sys.stderr)
        if exfil_count:
            print(f"          exfil events: {exfil_count}", file=sys.stderr)

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
