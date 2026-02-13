#!/usr/bin/env python3
"""
GCP Audit Log Generator.
Generates realistic GCP audit events with natural volume variation.
Includes both admin_activity and data_access audit logs.

Services (7): Compute Engine, Cloud Storage, Cloud Functions, BigQuery, IAM,
              Cloud Logging, Storage (bucket-level)
Event types (15): See generate_baseline_hour() for full distribution.
Scenarios: exfil (Days 7-13), cpu_runaway (Days 11-12)
"""

import argparse
import json
import random
import sys
import uuid
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path, Config
from shared.time_utils import ts_gcp, date_add, calc_natural_events, TimeUtils
from shared.company import GCP_PROJECT, GCP_REGION, ORG_NAME_LOWER, get_internal_ip, Company
from scenarios.registry import expand_scenarios

# Log types
LOG_TYPE_ADMIN_ACTIVITY = "activity"
LOG_TYPE_DATA_ACCESS = "data_access"

# =============================================================================
# GCP CONFIGURATION
# =============================================================================

GCP_SERVICE_ACCOUNTS = [
    f"svc-compute@{GCP_PROJECT}.iam.gserviceaccount.com",
    f"svc-storage@{GCP_PROJECT}.iam.gserviceaccount.com",
    f"svc-functions@{GCP_PROJECT}.iam.gserviceaccount.com",
]
GCP_BUCKETS = [f"{ORG_NAME_LOWER}-data", f"{ORG_NAME_LOWER}-backups", f"{ORG_NAME_LOWER}-exports"]
GCP_FUNCTIONS = ["processData", "sendAlerts", "transformRecords"]
GCP_INSTANCES = ["instance-prod-1", "instance-prod-2", "instance-web-1"]

# Zone mapping per resource type (for realistic zone variation)
_RESOURCE_ZONES = {
    "gce_instance": [f"{GCP_REGION}-a", f"{GCP_REGION}-b", f"{GCP_REGION}-c"],
    "gcs_bucket": [GCP_REGION],                # Regional, no zone suffix
    "cloud_function": [f"{GCP_REGION}"],        # Regional
    "bigquery_dataset": ["US"],                  # Multi-region
}

# User agent profiles for GCP API callers
_GCP_USER_AGENTS = [
    "google-cloud-sdk/462.0.1 gcloud/462.0.1",                                    # gcloud CLI
    "Mozilla/5.0 (compatible; Google-Cloud-Console)",                               # GCP Console
    "google-api-python-client/2.108.0 Python/3.11.6 Linux/5.15.0-91-generic",     # Python SDK
    "google-api-go-client/0.5 Cloud-SDK/462.0.1",                                  # Go SDK
    "google-cloud-sdk/462.0.1 gcloud/terraform",                                   # Terraform
]


def should_tag_exfil(day: int, method_name: str, active_scenarios: list) -> bool:
    """Check if event should get exfil demo_id.

    Exfil scenario: Days 8-14 are staging/exfil phase.
    Tag storage access events during this period.
    """
    if "exfil" not in active_scenarios:
        return False
    # Staging: day 7-9 (0-indexed), Exfil: day 10-13
    if day < 7 or day > 13:
        return False
    # Tag storage access, list, and delete operations
    return method_name in [
        "storage.objects.get", "storage.objects.list",
        "storage.objects.create", "storage.objects.delete",
    ]


# GCP baseline error definitions (3% of events)
# Format: (gRPC code, message, applicable_methods)
_GCP_BASELINE_ERRORS = [
    (7, "PERMISSION_DENIED: The caller does not have permission", [
        "storage.objects.get", "storage.objects.create", "storage.objects.delete",
        "v1.compute.instances.list", "iam.serviceAccounts.keys.create",
        "google.iam.admin.v1.SetIamPolicy",
        "google.logging.v2.LoggingServiceV2.ListLogEntries",
    ]),
    (5, "NOT_FOUND: The specified resource was not found", [
        "storage.objects.get", "storage.objects.delete", "storage.buckets.get",
        "v1.compute.instances.get",
        "google.cloud.functions.v1.CloudFunctionsService.CallFunction",
        "google.cloud.bigquery.v2.TableDataService.List",
    ]),
    (8, "RESOURCE_EXHAUSTED: Quota exceeded", [
        "jobservice.jobcompleted", "v1.compute.instances.start",
        "google.cloud.functions.v1.CloudFunctionsService.CallFunction",
        "google.cloud.bigquery.v2.TableDataService.List",
        "google.logging.v2.LoggingServiceV2.WriteLogEntries",
    ]),
    (16, "UNAUTHENTICATED: Request had invalid authentication credentials", [
        "storage.objects.get", "storage.objects.create", "iam.serviceAccounts.keys.create",
        "google.logging.v2.LoggingServiceV2.ListLogEntries",
    ]),
]
_GCP_BASELINE_ERROR_RATE = 0.03  # 3% of baseline events fail


def _gcp_maybe_inject_error(event: Dict[str, Any], method_name: str) -> Dict[str, Any]:
    """Potentially inject an error into a GCP baseline event (~3% chance)."""
    if random.random() > _GCP_BASELINE_ERROR_RATE:
        return event

    # Find applicable errors for this method
    applicable = [(code, msg) for code, msg, methods in _GCP_BASELINE_ERRORS
                   if method_name in methods]
    if not applicable:
        return event

    error_code, error_msg = random.choice(applicable)
    event["protoPayload"]["status"] = {"code": error_code, "message": error_msg}
    event["protoPayload"]["authorizationInfo"][0]["granted"] = False
    event["severity"] = "ERROR"
    return event


# =============================================================================
# EVENT GENERATORS
# =============================================================================

def gcp_base_event(base_date: str, day: int, hour: int, minute: int, second: int,
                   method_name: str, service_name: str, principal: str,
                   log_type: str = LOG_TYPE_ADMIN_ACTIVITY,
                   resource_type: str = "gce_instance") -> Dict[str, Any]:
    """Create base GCP audit log structure.

    Args:
        log_type: Either LOG_TYPE_ADMIN_ACTIVITY or LOG_TYPE_DATA_ACCESS
        resource_type: GCP resource type (gce_instance, gcs_bucket, cloud_function, bigquery_dataset)

    Field validation fixes applied:
        - zone: Varies per resource type (compute=zone, storage=region, BQ=multi-region)
        - callerSuppliedUserAgent: Varied (Console, gcloud, Python SDK, Go SDK, Terraform)
        - authorizationInfo: Added with permission, resource, granted
        - status: Added {code: 0, message: ""}
        - receiveTimestamp: Added (event timestamp + small offset)
        - severity: INFO for success (configurable for errors)
    """
    # Determine zone/location based on resource type
    zone_options = _RESOURCE_ZONES.get(resource_type, [f"{GCP_REGION}-a"])
    zone = random.choice(zone_options)

    # Vary user agent
    user_agent = random.choice(_GCP_USER_AGENTS)

    # Derive permission from method name (e.g., "storage.objects.get" → "storage.objects.get")
    permission = method_name

    ts = ts_gcp(base_date, day, hour, minute, second)

    # receiveTimestamp = event time + small pipeline delay (50-500ms)
    try:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    receive_dt = dt + timedelta(milliseconds=random.randint(50, 500))
    receive_ts = receive_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    return {
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service_name,
            "methodName": method_name,
            "authenticationInfo": {"principalEmail": principal},
            "authorizationInfo": [
                {
                    "permission": permission,
                    "resource": f"projects/{GCP_PROJECT}",
                    "granted": True,
                }
            ],
            "requestMetadata": {
                "callerIp": get_internal_ip(),
                "callerSuppliedUserAgent": user_agent,
            },
            "resourceName": f"projects/{GCP_PROJECT}",
            "status": {"code": 0, "message": ""},
        },
        "insertId": uuid.uuid4().hex[:16],
        "resource": {
            "type": resource_type,
            "labels": {"project_id": GCP_PROJECT, "zone": zone},
        },
        "timestamp": ts,
        "receiveTimestamp": receive_ts,
        "severity": "INFO",
        "logName": f"projects/{GCP_PROJECT}/logs/cloudaudit.googleapis.com%2F{log_type}",
    }


def gcp_compute_list(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Compute Engine list instances event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "v1.compute.instances.list", "compute.googleapis.com", principal,
                           resource_type="gce_instance")
    return _gcp_maybe_inject_error(event, "v1.compute.instances.list")


def gcp_storage_get(base_date: str, day: int, hour: int, active_scenarios: list = None,
                    log_type: str = LOG_TYPE_ADMIN_ACTIVITY) -> Dict[str, Any]:
    """Generate Cloud Storage get object event.

    Args:
        log_type: Use LOG_TYPE_DATA_ACCESS for actual data reads
    """
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    bucket = random.choice(GCP_BUCKETS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "storage.objects.get", "storage.googleapis.com", principal,
                           log_type=log_type, resource_type="gcs_bucket")
    event["protoPayload"]["resourceName"] = f"projects/_/buckets/{bucket}/objects/data_{random.randint(1000, 9999)}.json"

    if active_scenarios and should_tag_exfil(day, "storage.objects.get", active_scenarios):
        event["demo_id"] = "exfil"

    return _gcp_maybe_inject_error(event, "storage.objects.get")


def gcp_storage_create(base_date: str, day: int, hour: int, active_scenarios: list = None) -> Dict[str, Any]:
    """Generate Cloud Storage create object event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    bucket = random.choice(GCP_BUCKETS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "storage.objects.create", "storage.googleapis.com", principal,
                           resource_type="gcs_bucket")
    event["protoPayload"]["resourceName"] = f"projects/_/buckets/{bucket}/objects/upload_{random.randint(1000, 9999)}.csv"

    if active_scenarios and should_tag_exfil(day, "storage.objects.create", active_scenarios):
        event["demo_id"] = "exfil"

    return _gcp_maybe_inject_error(event, "storage.objects.create")


def gcp_function_call(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Cloud Functions call event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    func = random.choice(GCP_FUNCTIONS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.cloud.functions.v1.CloudFunctionsService.CallFunction",
                           "cloudfunctions.googleapis.com", principal,
                           resource_type="cloud_function")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}/locations/{GCP_REGION}/functions/{func}"
    return _gcp_maybe_inject_error(event, "google.cloud.functions.v1.CloudFunctionsService.CallFunction")


def gcp_compute_start_stop(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Compute Engine start/stop instance event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    instance = random.choice(GCP_INSTANCES)
    action = random.choice(["start", "stop"])
    method = f"v1.compute.instances.{action}"

    event = gcp_base_event(base_date, day, hour, minute, second,
                           method, "compute.googleapis.com", principal,
                           resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}/zones/{GCP_REGION}-a/instances/{instance}"
    return _gcp_maybe_inject_error(event, f"v1.compute.instances.{action}")


def gcp_iam_sa_key_create(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate IAM service account key creation event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    target_sa = random.choice(GCP_SERVICE_ACCOUNTS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.iam.admin.v1.CreateServiceAccountKey",
                           "iam.googleapis.com", principal,
                           resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}/serviceAccounts/{target_sa}"
    return _gcp_maybe_inject_error(event, "iam.serviceAccounts.keys.create")


def gcp_bigquery_query(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate BigQuery query event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "jobservice.jobcompleted", "bigquery.googleapis.com", principal,
                           resource_type="bigquery_dataset")
    event["protoPayload"]["serviceData"] = {
        "jobCompletedEvent": {
            "job": {
                "jobStatistics": {"totalBilledBytes": str(random.randint(1000000, 100000000))},
            }
        }
    }
    return _gcp_maybe_inject_error(event, "jobservice.jobcompleted")


def gcp_logging_write(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Cloud Logging WriteLogEntries event (apps writing logs)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    log_name = random.choice([
        f"projects/{GCP_PROJECT}/logs/cloudfunctions.googleapis.com%2Fcloud-functions",
        f"projects/{GCP_PROJECT}/logs/compute.googleapis.com%2Factivity_log",
        f"projects/{GCP_PROJECT}/logs/run.googleapis.com%2Frequests",
    ])

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.logging.v2.LoggingServiceV2.WriteLogEntries",
                           "logging.googleapis.com", principal,
                           resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = log_name
    event["protoPayload"]["request"] = {
        "logName": log_name,
        "entries": [{}] * random.randint(1, 10),
    }
    return _gcp_maybe_inject_error(event, "google.logging.v2.LoggingServiceV2.WriteLogEntries")


def gcp_logging_list(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Cloud Logging ListLogEntries event (monitoring/ops querying logs)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.logging.v2.LoggingServiceV2.ListLogEntries",
                           "logging.googleapis.com", principal,
                           log_type=LOG_TYPE_DATA_ACCESS, resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}"
    event["protoPayload"]["request"] = {
        "resourceNames": [f"projects/{GCP_PROJECT}"],
        "filter": random.choice([
            "severity>=ERROR",
            'resource.type="cloud_function"',
            'resource.type="gce_instance"',
            "timestamp>=\"2026-01-01T00:00:00Z\"",
        ]),
        "pageSize": random.choice([100, 500, 1000]),
    }
    return _gcp_maybe_inject_error(event, "google.logging.v2.LoggingServiceV2.ListLogEntries")


def gcp_storage_delete(base_date: str, day: int, hour: int,
                       active_scenarios: list = None) -> Dict[str, Any]:
    """Generate Cloud Storage delete object event (lifecycle cleanup)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    bucket = random.choice(GCP_BUCKETS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "storage.objects.delete", "storage.googleapis.com", principal,
                           resource_type="gcs_bucket")
    event["protoPayload"]["resourceName"] = (
        f"projects/_/buckets/{bucket}/objects/archive_{random.randint(1000, 9999)}.json"
    )

    if active_scenarios and should_tag_exfil(day, "storage.objects.delete", active_scenarios):
        event["demo_id"] = "exfil"

    return _gcp_maybe_inject_error(event, "storage.objects.delete")


def gcp_storage_bucket_get(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate Cloud Storage get bucket metadata event."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    bucket = random.choice(GCP_BUCKETS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "storage.buckets.get", "storage.googleapis.com", principal,
                           resource_type="gcs_bucket")
    event["protoPayload"]["resourceName"] = f"projects/_/buckets/{bucket}"
    return _gcp_maybe_inject_error(event, "storage.buckets.get")


def gcp_bigquery_tabledata_list(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate BigQuery tabledata.list event (reading table data/export)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    dataset = random.choice(["analytics", "reporting", "warehouse"])
    table = random.choice(["daily_orders", "customer_metrics", "product_performance", "revenue_summary"])

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.cloud.bigquery.v2.TableDataService.List",
                           "bigquery.googleapis.com", principal,
                           log_type=LOG_TYPE_DATA_ACCESS, resource_type="bigquery_dataset")
    event["protoPayload"]["resourceName"] = (
        f"projects/{GCP_PROJECT}/datasets/{dataset}/tables/{table}"
    )
    return _gcp_maybe_inject_error(event, "google.cloud.bigquery.v2.TableDataService.List")


def gcp_iam_set_policy(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Generate IAM SetIamPolicy event (normal role grants/revokes)."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    principal = random.choice(GCP_SERVICE_ACCOUNTS)
    target_sa = random.choice(GCP_SERVICE_ACCOUNTS)

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.iam.admin.v1.SetIamPolicy",
                           "iam.googleapis.com", principal,
                           resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}/serviceAccounts/{target_sa}"
    event["protoPayload"]["request"] = {
        "policy": {
            "bindings": [{
                "role": random.choice([
                    "roles/storage.objectViewer",
                    "roles/bigquery.dataViewer",
                    "roles/logging.viewer",
                    "roles/compute.viewer",
                ]),
                "members": [f"serviceAccount:{target_sa}"],
            }],
        },
    }
    return _gcp_maybe_inject_error(event, "google.iam.admin.v1.SetIamPolicy")


# =============================================================================
# SCENARIO-SPECIFIC EVENT GENERATORS
# =============================================================================

def gcp_logging_list_exfil(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Exfil scenario: attacker checks audit logs for detection (Day 10, late night).

    The attacker uses the compromised SA to query Cloud Logging, checking if
    their SA creation (Day 8) triggered any alerts. This is a real-world
    'checking for detection' pattern.
    """
    minute = random.randint(0, 15)
    second = random.randint(0, 59)
    mal_sa = f"svc-gcs-sync@{GCP_PROJECT}.iam.gserviceaccount.com"

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.logging.v2.LoggingServiceV2.ListLogEntries",
                           "logging.googleapis.com", mal_sa,
                           log_type=LOG_TYPE_DATA_ACCESS, resource_type="gce_instance")
    event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}"
    event["protoPayload"]["requestMetadata"]["callerIp"] = "185.220.101.42"
    event["protoPayload"]["request"] = {
        "resourceNames": [f"projects/{GCP_PROJECT}"],
        "filter": 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"',
        "pageSize": 100,
    }
    event["demo_id"] = "exfil"
    return event


def gcp_bigquery_export_exfil(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Exfil scenario: attacker exports customer data from BigQuery (Day 12, 03:00).

    A second exfil channel -- beyond GCS object downloads, the attacker queries
    BigQuery for customer/order data and reads the results. Cross-correlates with
    order data and the GCS exfil happening the same nights.
    """
    minute = random.randint(10, 30)
    second = random.randint(0, 59)
    mal_sa = f"svc-gcs-sync@{GCP_PROJECT}.iam.gserviceaccount.com"

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "google.cloud.bigquery.v2.TableDataService.List",
                           "bigquery.googleapis.com", mal_sa,
                           log_type=LOG_TYPE_DATA_ACCESS, resource_type="bigquery_dataset")
    event["protoPayload"]["resourceName"] = (
        f"projects/{GCP_PROJECT}/datasets/warehouse/tables/customer_database"
    )
    event["protoPayload"]["requestMetadata"]["callerIp"] = "185.220.101.42"
    event["demo_id"] = "exfil"
    return event


def gcp_storage_delete_exfil(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Exfil scenario: attacker deletes staging files to cover tracks (Day 13, 05:00).

    After data theft (Days 11-12), the attacker removes staging/temporary files
    from the exports bucket. Correlates with the end of exfil activity.
    """
    minute = random.randint(0, 30)
    second = random.randint(0, 59)
    mal_sa = f"svc-gcs-sync@{GCP_PROJECT}.iam.gserviceaccount.com"
    staging_file = random.choice([
        "staging/export_batch_001.tar.gz",
        "staging/export_batch_002.tar.gz",
        "staging/customer_dump.csv.enc",
        "staging/financial_extract.xlsx.enc",
        "staging/temp_sync_manifest.json",
    ])

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "storage.objects.delete", "storage.googleapis.com", mal_sa,
                           resource_type="gcs_bucket")
    event["protoPayload"]["resourceName"] = (
        f"projects/_/buckets/{ORG_NAME_LOWER}-exports/objects/{staging_file}"
    )
    event["protoPayload"]["requestMetadata"]["callerIp"] = "185.220.101.42"
    event["demo_id"] = "exfil"
    return event


def gcp_bigquery_error_cpu_runaway(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """CPU runaway scenario: BigQuery data pipeline fails (Days 11-12).

    When SQL-PROD-01 is stuck at 100% CPU, the BigQuery data pipeline that
    pulls from the production database fails with RESOURCE_EXHAUSTED. This
    creates a GCP-visible symptom of an on-prem infrastructure issue.
    """
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    principal = f"svc-compute@{GCP_PROJECT}.iam.gserviceaccount.com"
    table = random.choice(["daily_orders", "customer_metrics", "inventory_sync"])

    event = gcp_base_event(base_date, day, hour, minute, second,
                           "jobservice.jobcompleted", "bigquery.googleapis.com", principal,
                           resource_type="bigquery_dataset")
    event["protoPayload"]["resourceName"] = (
        f"projects/{GCP_PROJECT}/datasets/warehouse/tables/{table}"
    )
    event["protoPayload"]["status"] = {
        "code": 8,
        "message": "RESOURCE_EXHAUSTED: Data source connection failed - upstream database unavailable",
    }
    event["protoPayload"]["serviceData"] = {
        "jobCompletedEvent": {
            "job": {
                "jobStatus": {"state": "DONE", "errorResult": {
                    "reason": "resourcesExceeded",
                    "message": "Data source connection timeout after 300s",
                }},
                "jobStatistics": {"totalBilledBytes": "0"},
            }
        }
    }
    event["severity"] = "ERROR"
    event["demo_id"] = "cpu_runaway"
    return event


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int,
                          active_scenarios: list = None) -> List[Dict[str, Any]]:
    """Generate baseline events for one hour.

    Event distribution (15 event types across 7 services):
    - 14% compute.instances.list          (admin_activity)  Compute Engine
    - 10% storage.objects.get             (admin_activity)  Cloud Storage
    - 18% storage.objects.get             (data_access)     Cloud Storage
    -  7% storage.objects.create          (admin_activity)  Cloud Storage
    -  3% storage.objects.delete          (admin_activity)  Cloud Storage     NEW
    -  3% storage.buckets.get             (admin_activity)  Cloud Storage     NEW
    - 11% Cloud Functions call            (admin_activity)  Cloud Functions
    - 10% BigQuery jobcompleted           (admin_activity)  BigQuery
    -  3% BigQuery tabledata.list         (data_access)     BigQuery          NEW
    -  4% compute.instances.start/stop    (admin_activity)  Compute Engine
    -  2% IAM SA key create               (admin_activity)  IAM
    -  2% IAM SetIamPolicy                (admin_activity)  IAM               NEW
    -  4% compute.instances.get           (data_access)     Compute Engine
    -  6% WriteLogEntries                 (admin_activity)  Cloud Logging     NEW
    -  3% ListLogEntries                  (data_access)     Cloud Logging     NEW
    """
    events = []

    for _ in range(event_count):
        r = random.randint(1, 100)

        if r <= 14:
            events.append(gcp_compute_list(base_date, day, hour))
        elif r <= 24:
            events.append(gcp_storage_get(base_date, day, hour, active_scenarios,
                                         log_type=LOG_TYPE_ADMIN_ACTIVITY))
        elif r <= 42:
            events.append(gcp_storage_get(base_date, day, hour, active_scenarios,
                                         log_type=LOG_TYPE_DATA_ACCESS))
        elif r <= 49:
            events.append(gcp_storage_create(base_date, day, hour, active_scenarios))
        elif r <= 52:
            events.append(gcp_storage_delete(base_date, day, hour, active_scenarios))
        elif r <= 55:
            events.append(gcp_storage_bucket_get(base_date, day, hour))
        elif r <= 66:
            events.append(gcp_function_call(base_date, day, hour))
        elif r <= 76:
            events.append(gcp_bigquery_query(base_date, day, hour))
        elif r <= 79:
            events.append(gcp_bigquery_tabledata_list(base_date, day, hour))
        elif r <= 83:
            events.append(gcp_compute_start_stop(base_date, day, hour))
        elif r <= 85:
            events.append(gcp_iam_sa_key_create(base_date, day, hour))
        elif r <= 87:
            events.append(gcp_iam_set_policy(base_date, day, hour))
        elif r <= 91:
            # Compute get (data_access)
            minute, second = random.randint(0, 59), random.randint(0, 59)
            principal = random.choice(GCP_SERVICE_ACCOUNTS)
            instance = random.choice(GCP_INSTANCES)
            event = gcp_base_event(base_date, day, hour, minute, second,
                                   "v1.compute.instances.get", "compute.googleapis.com", principal,
                                   log_type=LOG_TYPE_DATA_ACCESS, resource_type="gce_instance")
            event["protoPayload"]["resourceName"] = f"projects/{GCP_PROJECT}/zones/{GCP_REGION}-a/instances/{instance}"
            events.append(_gcp_maybe_inject_error(event, "v1.compute.instances.get"))
        elif r <= 97:
            events.append(gcp_logging_write(base_date, day, hour))
        else:
            events.append(gcp_logging_list(base_date, day, hour))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_gcp_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate GCP audit logs.

    Generates both admin_activity and data_access audit logs.
    When exfil scenario is active, includes attack events from ExfilScenario.
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "gcp/gcp_audit.json")

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

    base_events_per_peak_hour = int(150 * scale)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  GCP Audit Log Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events = []

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [GCP] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for hour in range(24):
            # Baseline events
            hour_events = calc_natural_events(base_events_per_peak_hour, start_date, day, hour, "cloud")
            all_events.extend(generate_baseline_hour(start_date, day, hour, hour_events, active_scenarios))

            # Exfil scenario events from ExfilScenario (SA key creation, storage exfil)
            if exfil_scenario:
                exfil_events = exfil_scenario.gcp_hour(day, hour)
                for e in exfil_events:
                    if isinstance(e, str):
                        event = json.loads(e)
                        # Remove None demo_id if present
                        if event.get("demo_id") is None:
                            event.pop("demo_id", None)
                        all_events.append(event)
                    else:
                        all_events.append(e)

            # ----- Scenario hooks (beyond ExfilScenario) -----

            # Exfil: attacker checks audit logs for detection (Day 10, 22:00)
            if "exfil" in active_scenarios and day == 9 and hour == 22:
                all_events.append(gcp_logging_list_exfil(start_date, day, hour))

            # Exfil: BigQuery data export - second exfil channel (Day 12, 03:00)
            if "exfil" in active_scenarios and day == 11 and hour == 3:
                all_events.append(gcp_bigquery_export_exfil(start_date, day, hour))

            # Exfil: attacker deletes staging files to cover tracks (Day 13, 05:00)
            if "exfil" in active_scenarios and day == 12 and hour == 5:
                for _ in range(random.randint(2, 4)):
                    all_events.append(gcp_storage_delete_exfil(start_date, day, hour))

            # CPU runaway: BigQuery pipeline errors (Days 11-12, business hours)
            if "cpu_runaway" in active_scenarios and 10 <= day <= 11 and hour in (9, 10, 11):
                all_events.append(gcp_bigquery_error_cpu_runaway(start_date, day, hour))

        if not quiet:
            print(f"  [GCP] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    if not quiet:
        # Count by log type
        admin_count = sum(1 for e in all_events if "activity" in e.get("logName", ""))
        data_access_count = sum(1 for e in all_events if "data_access" in e.get("logName", ""))
        error_count = sum(1 for e in all_events if e.get("severity") == "ERROR")

        # Count unique method names
        methods = Counter(e.get("protoPayload", {}).get("methodName", "unknown") for e in all_events)

        # Count scenario events
        scenario_counts = Counter(e.get("demo_id") for e in all_events if e.get("demo_id"))

        print(f"  [GCP] Complete! {len(all_events):,} events written", file=sys.stderr)
        print(f"        admin_activity: {admin_count:,} | data_access: {data_access_count:,}", file=sys.stderr)
        print(f"        errors: {error_count:,} ({error_count * 100 // max(len(all_events), 1)}%)"
              f" | methods: {len(methods)}", file=sys.stderr)
        if scenario_counts:
            scenario_str = ", ".join(f"{k}: {v}" for k, v in sorted(scenario_counts.items()))
            print(f"        scenarios: {scenario_str}", file=sys.stderr)

    return len(all_events)


def main():
    parser = argparse.ArgumentParser(description="Generate GCP audit logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_gcp_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
