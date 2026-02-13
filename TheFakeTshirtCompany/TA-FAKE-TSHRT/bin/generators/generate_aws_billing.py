#!/usr/bin/env python3
"""
AWS Billing Cost & Usage Report (CUR) Generator.
Generates realistic daily AWS billing records in CUR CSV format, with
scenario-driven cost spikes for DDoS (EC2/S3 data transfer) and exfil
(S3 request/transfer anomalies).

Baseline daily spend: ~$180/day across EC2, S3, Lambda, RDS, CloudTrail,
CloudWatch, Config, and WAF.

Scenario impacts:
  - ddos_attack (days 18-19): EC2 DataTransfer 4x, S3 Requests 2x, WAF 3x
  - exfil (days 11-13): S3 GetRequests 1.3x, S3 DataTransfer-Out 1.5x
"""

import argparse
import csv
import hashlib
import io
import random
import sys
import uuid
from datetime import timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add
from shared.company import AWS_ACCOUNT_ID, AWS_REGION
from scenarios.registry import expand_scenarios

# =============================================================================
# CUR CONFIGURATION
# =============================================================================

# CUR CSV columns (simplified from full 125-column CUR to ~19 practical fields)
CUR_COLUMNS = [
    "identity/LineItemId",
    "identity/TimeInterval",
    "bill/BillingPeriodStartDate",
    "bill/BillingPeriodEndDate",
    "bill/PayerAccountId",
    "lineItem/UsageAccountId",
    "lineItem/LineItemType",
    "lineItem/UsageStartDate",
    "lineItem/UsageEndDate",
    "lineItem/ProductCode",
    "lineItem/UsageType",
    "lineItem/Operation",
    "lineItem/UsageAmount",
    "lineItem/UnblendedCost",
    "lineItem/UnblendedRate",
    "lineItem/LineItemDescription",
    "product/region",
    "product/serviceName",
    "resourceTags/user:Name",
    "resourceTags/user:Environment",
    "demo_id",
]

# =============================================================================
# BILLING LINE ITEMS — Baseline daily costs
# =============================================================================
# Each entry: (ProductCode, UsageType, Operation, BaseAmount, BaseRate,
#              Description, ServiceName, ResourceTag, Environment)
# BaseAmount = daily usage quantity, BaseRate = $ per unit

BILLING_LINE_ITEMS = [
    # --- EC2 ---
    ("AmazonEC2", "BoxUsage:t3.large", "RunInstances",
     72.0, 0.0832, "Linux/UNIX t3.large On-Demand",
     "Amazon Elastic Compute Cloud", "web-prod", "production"),

    ("AmazonEC2", "BoxUsage:t3.medium", "RunInstances",
     48.0, 0.0416, "Linux/UNIX t3.medium On-Demand",
     "Amazon Elastic Compute Cloud", "app-prod", "production"),

    ("AmazonEC2", "BoxUsage:t3.xlarge", "RunInstances",
     24.0, 0.1664, "Linux/UNIX t3.xlarge On-Demand",
     "Amazon Elastic Compute Cloud", "rds-equiv", "production"),

    ("AmazonEC2", "DataTransfer-Out-Bytes", "RunInstances",
     50.0, 0.09, "Data Transfer Out - US East",
     "Amazon Elastic Compute Cloud", "web-prod", "production"),

    ("AmazonEC2", "EBS:VolumeUsage.gp3", "CreateVolume",
     600.0, 0.08, "EBS gp3 Volume Usage per GB-month",
     "Amazon Elastic Compute Cloud", "ebs-storage", "production"),

    # --- S3 ---
    ("AmazonS3", "TimedStorage-ByteHrs", "StandardStorage",
     500.0, 0.023, "S3 Standard Storage per GB-month",
     "Amazon Simple Storage Service", "prod-data", "production"),

    ("AmazonS3", "Requests-Tier1", "PutObject",
     5000.0, 0.000005, "PUT/COPY/POST/LIST Requests",
     "Amazon Simple Storage Service", "prod-data", "production"),

    ("AmazonS3", "Requests-Tier2", "GetObject",
     25000.0, 0.0000004, "GET/SELECT Requests",
     "Amazon Simple Storage Service", "prod-data", "production"),

    ("AmazonS3", "DataTransfer-Out-Bytes", "GetObject",
     20.0, 0.09, "S3 Data Transfer Out - US East",
     "Amazon Simple Storage Service", "prod-data", "production"),

    # --- Lambda ---
    ("AWSLambda", "Lambda-GB-Second", "Invoke",
     150000.0, 0.0000166667, "Lambda Duration GB-Seconds",
     "AWS Lambda", "process-orders", "production"),

    ("AWSLambda", "Request", "Invoke",
     500000.0, 0.0000002, "Lambda Requests",
     "AWS Lambda", "process-orders", "production"),

    # --- RDS (equivalent to our MSSQL) ---
    ("AmazonRDS", "InstanceUsage:db.t3.xlarge", "CreateDBInstance",
     24.0, 0.272, "RDS db.t3.xlarge Single-AZ",
     "Amazon Relational Database Service", "sql-prod", "production"),

    ("AmazonRDS", "RDS:StorageIOUsage", "ReadIO",
     2000000.0, 0.0000001, "RDS I/O Requests",
     "Amazon Relational Database Service", "sql-prod", "production"),

    # --- Supporting services ---
    ("AWSCloudTrail", "TrailDelivery", "LookupEvents",
     500000.0, 0.000002, "CloudTrail Event Delivery",
     "AWS CloudTrail", "audit-trail", "production"),

    ("AmazonCloudWatch", "MetricMonitorUsage", "MetricStorage",
     500.0, 0.01, "CloudWatch Custom Metrics",
     "Amazon CloudWatch", "monitoring", "production"),

    ("AWSConfig", "ConfigurationItemRecorded", "ConfigRules",
     200.0, 0.003, "Config Rule Evaluations",
     "AWS Config", "compliance", "production"),

    # --- WAF (protects WEB-01) ---
    ("AWSWAF", "WebACL-Requests", "Evaluate",
     1000000.0, 0.0000006, "WAF Web ACL Requests",
     "AWS WAF", "waf-webacl", "production"),
]

# =============================================================================
# SCENARIO MULTIPLIERS
# =============================================================================

# DDoS attack (days 18-19): massive traffic spike
DDOS_MULTIPLIERS = {
    "AmazonEC2:DataTransfer-Out-Bytes": 4.0,    # 4x egress from flooded servers
    "AmazonEC2:BoxUsage:t3.large": 1.5,          # Auto-scaling spins up more instances
    "AmazonS3:Requests-Tier2": 2.0,              # More cache misses hitting S3
    "AmazonS3:DataTransfer-Out-Bytes": 3.0,      # S3 egress from static assets
    "AWSLambda:Lambda-GB-Second": 2.0,            # Lambda retries under load
    "AWSLambda:Request": 2.5,                     # More invocations
    "AWSWAF:WebACL-Requests": 5.0,                # WAF evaluating attack traffic
    "AmazonCloudWatch:MetricMonitorUsage": 1.5,   # More alarm evaluations
}

# Exfil (days 11-13): subtle S3 access anomaly from off-hours data theft
EXFIL_MULTIPLIERS = {
    "AmazonS3:Requests-Tier2": 1.3,              # Extra GetObject from data theft
    "AmazonS3:DataTransfer-Out-Bytes": 1.5,      # Data exfil egress
}


# =============================================================================
# HELPERS
# =============================================================================

def _daily_noise(base_date: str, day: int, seed_suffix: str = "") -> float:
    """Deterministic daily noise factor (0.90 - 1.10) for natural variation."""
    dt = date_add(base_date, day)
    hash_input = f"{dt.strftime('%Y%m%d')}:billing:{seed_suffix}"
    hash_val = int(hashlib.md5(hash_input.encode()).hexdigest()[:8], 16)
    # Map to 0.90 - 1.10
    return 0.90 + (hash_val % 2001) / 10000.0


def _weekend_factor(base_date: str, day: int) -> float:
    """Weekend billing reduction — cloud infra runs 24/7 but usage drops."""
    dt = date_add(base_date, day)
    if dt.weekday() >= 5:  # Saturday, Sunday
        return 0.75  # 25% less usage on weekends (infra cost stays, usage drops)
    return 1.0


def _line_item_id(base_date: str, day: int, index: int) -> str:
    """Generate deterministic line item ID."""
    dt = date_add(base_date, day)
    seed = f"{dt.strftime('%Y%m%d')}:{index}"
    return hashlib.sha256(seed.encode()).hexdigest()[:32]


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_aws_billing_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate AWS Cost & Usage Report (CUR) billing data.

    Produces daily billing records per service/usage-type with scenario-driven
    cost spikes for DDoS (days 18-19) and exfil (days 11-13).

    Returns:
        Total number of billing line items generated.
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "aws/aws_billing_cur.csv")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  AWS Billing CUR Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_rows: List[Dict[str, str]] = []
    total_baseline_cost = 0.0
    total_scenario_cost = 0.0

    for day in range(days):
        dt = date_add(start_date, day)
        day_str = dt.strftime("%Y-%m-%d")
        next_day_str = (dt + timedelta(days=1)).strftime("%Y-%m-%d")

        # Billing period = calendar month containing this day
        billing_start = dt.replace(day=1).strftime("%Y-%m-%dT00:00:00Z")
        billing_end_dt = (dt.replace(day=28) + timedelta(days=4)).replace(day=1)
        billing_end = billing_end_dt.strftime("%Y-%m-%dT00:00:00Z")

        # Time interval for this day
        time_interval = f"{day_str}T00:00:00Z/{next_day_str}T00:00:00Z"

        # Weekend factor
        wknd = _weekend_factor(start_date, day)

        if not quiet:
            print(f"  [Billing] Day {day + 1}/{days} ({day_str})...", file=sys.stderr, end="\r")

        for idx, item in enumerate(BILLING_LINE_ITEMS):
            (product_code, usage_type, operation, base_amount, base_rate,
             description, service_name, resource_tag, environment) = item

            # Deterministic per-line-item noise
            noise = _daily_noise(start_date, day, f"{product_code}:{usage_type}")

            # Calculate usage amount with noise and weekend factor
            usage_amount = base_amount * noise * wknd * scale

            # Build lookup key for scenario multipliers
            multiplier_key = f"{product_code}:{usage_type}"
            demo_id = ""

            # Apply DDoS multipliers (days 18-19, 0-indexed 17-18)
            if "ddos_attack" in active_scenarios and 17 <= day <= 18:
                ddos_mult = DDOS_MULTIPLIERS.get(multiplier_key, 1.0)
                if ddos_mult > 1.0:
                    usage_amount *= ddos_mult
                    demo_id = "ddos_attack"

            # Apply exfil multipliers (days 11-13, 0-indexed 10-12)
            if "exfil" in active_scenarios and 10 <= day <= 12:
                exfil_mult = EXFIL_MULTIPLIERS.get(multiplier_key, 1.0)
                if exfil_mult > 1.0:
                    usage_amount *= exfil_mult
                    # Only tag if not already tagged by ddos
                    if not demo_id:
                        demo_id = "exfil"

            # Calculate cost
            cost = usage_amount * base_rate

            # Track costs for summary
            if demo_id:
                total_scenario_cost += cost
            else:
                total_baseline_cost += cost

            row = {
                "identity/LineItemId": _line_item_id(start_date, day, idx),
                "identity/TimeInterval": time_interval,
                "bill/BillingPeriodStartDate": billing_start,
                "bill/BillingPeriodEndDate": billing_end,
                "bill/PayerAccountId": AWS_ACCOUNT_ID,
                "lineItem/UsageAccountId": AWS_ACCOUNT_ID,
                "lineItem/LineItemType": "Usage",
                "lineItem/UsageStartDate": f"{day_str}T00:00:00Z",
                "lineItem/UsageEndDate": f"{next_day_str}T00:00:00Z",
                "lineItem/ProductCode": product_code,
                "lineItem/UsageType": usage_type,
                "lineItem/Operation": operation,
                "lineItem/UsageAmount": f"{usage_amount:.6f}",
                "lineItem/UnblendedCost": f"{cost:.10f}",
                "lineItem/UnblendedRate": f"{base_rate:.10f}",
                "lineItem/LineItemDescription": description,
                "product/region": AWS_REGION,
                "product/serviceName": service_name,
                "resourceTags/user:Name": resource_tag,
                "resourceTags/user:Environment": environment,
                "demo_id": demo_id,
            }
            all_rows.append(row)

        if not quiet:
            print(f"  [Billing] Day {day + 1}/{days} ({day_str})... done", file=sys.stderr)

    # Write CSV output
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CUR_COLUMNS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(all_rows)

    if not quiet:
        total_cost = total_baseline_cost + total_scenario_cost
        avg_daily = total_cost / max(days, 1)
        ddos_days = sum(1 for d in range(days) if 17 <= d <= 18 and "ddos_attack" in active_scenarios)
        exfil_days = sum(1 for d in range(days) if 10 <= d <= 12 and "exfil" in active_scenarios)

        print(f"  [Billing] Complete! {len(all_rows):,} line items written", file=sys.stderr)
        print(f"        Total cost: ${total_cost:,.2f} over {days} days", file=sys.stderr)
        print(f"        Avg daily:  ${avg_daily:,.2f}/day", file=sys.stderr)
        if ddos_days:
            print(f"        DDoS spike: {ddos_days} days affected", file=sys.stderr)
        if exfil_days:
            print(f"        Exfil cost: {exfil_days} days affected", file=sys.stderr)

    total = len(all_rows)
    return {"total": total, "files": {"cloud/aws/aws_billing_cur.csv": total}}


def main():
    parser = argparse.ArgumentParser(description="Generate AWS Billing CUR data")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_aws_billing_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
