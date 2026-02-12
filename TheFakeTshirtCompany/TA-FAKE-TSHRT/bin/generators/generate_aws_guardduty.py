#!/usr/bin/env python3
"""
AWS GuardDuty Findings Generator.
Generates realistic AWS GuardDuty findings with baseline noise and scenario-injected
high-severity detections for exfil and ransomware scenarios.

Baseline findings (3-8 per day):
  - Recon:EC2/PortProbeUnprotectedPort (severity 2.0)
  - UnauthorizedAccess:S3/TorIPCaller (severity 3.0)
  - Policy:IAMUser/RootCredentialUsage (severity 1.0)
  - Recon:EC2/Portscan (severity 2.0)

Scenario findings:
  - exfil (days 8-13): IAM persistence + S3 exfiltration
  - ransomware_attempt (day 8): EC2 malicious IP communication
"""

import argparse
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import ts_iso, date_add
from shared.company import (
    AWS_ACCOUNT_ID, AWS_REGION, ORG_NAME_LOWER,
    USERS, THREAT_IP,
)
from scenarios.registry import expand_scenarios

# =============================================================================
# GUARDDUTY CONFIGURATION
# =============================================================================

_DETECTOR_ID = "abc123guarddutydetector"

_EC2_INSTANCES = ["i-0abc123def456", "i-0def789abc012", "i-0123456789abc"]

_EC2_INSTANCE_DETAILS = {
    "i-0abc123def456": {
        "instanceId": "i-0abc123def456",
        "instanceType": "t3.large",
        "launchTime": "2025-11-15T08:30:00Z",
        "platform": None,
        "availabilityZone": "us-east-1a",
        "imageId": "ami-0abcdef1234567890",
        "imageDescription": "Amazon Linux 2023 AMI",
        "networkInterfaces": [{
            "ipv6Addresses": [],
            "networkInterfaceId": "eni-0abc123def456",
            "privateDnsName": "ip-172-16-1-10.ec2.internal",
            "privateIpAddress": "172.16.1.10",
            "publicDnsName": "ec2-52-90-100-10.compute-1.amazonaws.com",
            "publicIp": "52.90.100.10",
            "subnetId": "subnet-0abc123",
            "vpcId": "vpc-0abc123",
            "securityGroups": [{"groupName": "web-servers", "groupId": "sg-0abc123"}],
        }],
        "productCodes": [],
        "tags": [{"key": "Name", "value": "WEB-01"}, {"key": "Environment", "value": "Production"}],
    },
    "i-0def789abc012": {
        "instanceId": "i-0def789abc012",
        "instanceType": "r5.xlarge",
        "launchTime": "2025-11-15T08:32:00Z",
        "platform": "windows",
        "availabilityZone": "us-east-1b",
        "imageId": "ami-0def789abc012345",
        "imageDescription": "Windows Server 2022 Base",
        "networkInterfaces": [{
            "ipv6Addresses": [],
            "networkInterfaceId": "eni-0def789abc012",
            "privateDnsName": "ip-10-10-20-30.ec2.internal",
            "privateIpAddress": "10.10.20.30",
            "publicDnsName": "",
            "publicIp": "",
            "subnetId": "subnet-0def789",
            "vpcId": "vpc-0abc123",
            "securityGroups": [{"groupName": "database-servers", "groupId": "sg-0def789"}],
        }],
        "productCodes": [],
        "tags": [{"key": "Name", "value": "SQL-PROD-01"}, {"key": "Environment", "value": "Production"}],
    },
    "i-0123456789abc": {
        "instanceId": "i-0123456789abc",
        "instanceType": "t3.medium",
        "launchTime": "2025-11-15T08:35:00Z",
        "platform": None,
        "availabilityZone": "us-east-1a",
        "imageId": "ami-0abcdef1234567890",
        "imageDescription": "Amazon Linux 2023 AMI",
        "networkInterfaces": [{
            "ipv6Addresses": [],
            "networkInterfaceId": "eni-0123456789abc",
            "privateDnsName": "ip-10-10-20-40.ec2.internal",
            "privateIpAddress": "10.10.20.40",
            "publicDnsName": "ec2-52-90-100-40.compute-1.amazonaws.com",
            "publicIp": "52.90.100.40",
            "subnetId": "subnet-0abc123",
            "vpcId": "vpc-0abc123",
            "securityGroups": [{"groupName": "app-servers", "groupId": "sg-01234abc"}],
        }],
        "productCodes": [],
        "tags": [{"key": "Name", "value": "APP-BOS-01"}, {"key": "Environment", "value": "Production"}],
    },
}

# Random internet IPs for port probing / scanning sources
_SCANNER_IPS = [
    "45.33.32.156", "91.189.91.38", "185.125.190.56", "104.236.198.48",
    "159.89.173.104", "178.128.169.7", "206.189.85.18", "167.172.43.52",
    "64.227.115.12", "142.93.12.203", "198.51.100.42", "203.0.113.99",
]

# Known Tor exit node IPs (simulated)
_TOR_EXIT_IPS = [
    "162.247.74.27", "185.220.100.252", "185.220.100.253", "23.129.64.130",
    "109.70.100.2", "176.10.99.200", "199.249.230.163", "204.85.191.30",
]

# AWS service role names for random baseline findings
_SERVICE_ROLES = [
    "BackupServiceRole", "DataPipelineRole", "DeploymentPipelineRole",
    "LambdaExecutionRole", "MonitoringRole",
]


# =============================================================================
# FINDING BUILDERS
# =============================================================================

def _build_finding_base(base_date: str, day: int, hour: int, minute: int, second: int,
                        finding_type: str, severity: float, title: str,
                        description: str) -> Dict[str, Any]:
    """Build the common GuardDuty finding skeleton."""
    finding_id = str(uuid.uuid4())
    timestamp = ts_iso(base_date, day, hour, minute, second)

    return {
        "schemaVersion": "2.0",
        "accountId": AWS_ACCOUNT_ID,
        "region": AWS_REGION,
        "partition": "aws",
        "id": finding_id,
        "arn": f"arn:aws:guardduty:{AWS_REGION}:{AWS_ACCOUNT_ID}:detector/{_DETECTOR_ID}/finding/{finding_id}",
        "type": finding_type,
        "severity": severity,
        "title": title,
        "description": description,
        "resource": {},
        "service": {
            "serviceName": "guardduty",
            "detectorId": _DETECTOR_ID,
            "action": {},
            "resourceRole": "TARGET",
            "additionalInfo": {},
            "count": 1,
            "eventFirstSeen": timestamp,
            "eventLastSeen": timestamp,
        },
        "updatedAt": timestamp,
        "createdAt": timestamp,
    }


def _instance_resource(instance_id: str) -> Dict[str, Any]:
    """Build resource block for EC2 instance findings."""
    details = _EC2_INSTANCE_DETAILS.get(instance_id, _EC2_INSTANCE_DETAILS[_EC2_INSTANCES[0]])
    return {
        "resourceType": "Instance",
        "instanceDetails": details,
    }


def _access_key_resource(username: str, access_key_id: str,
                         principal_id: str = None) -> Dict[str, Any]:
    """Build resource block for IAM/AccessKey findings."""
    return {
        "resourceType": "AccessKey",
        "accessKeyDetails": {
            "accessKeyId": access_key_id,
            "principalId": principal_id or f"AIDA{uuid.uuid5(uuid.NAMESPACE_DNS, username).hex[:16].upper()}",
            "userType": "IAMUser",
            "userName": username,
        },
    }


def _port_probe_action(source_ip: str, port: int) -> Dict[str, Any]:
    """Build PORT_PROBE action block."""
    return {
        "actionType": "PORT_PROBE",
        "portProbeAction": {
            "portProbeDetails": [{
                "localPortDetails": {
                    "port": port,
                    "portName": _port_name(port),
                },
                "remoteIpDetails": _remote_ip_details(source_ip),
            }],
            "blocked": False,
        },
    }


def _network_connection_action(direction: str, remote_ip: str, remote_port: int,
                                local_port: int = None, protocol: str = "TCP",
                                blocked: bool = False) -> Dict[str, Any]:
    """Build NETWORK_CONNECTION action block."""
    action = {
        "actionType": "NETWORK_CONNECTION",
        "networkConnectionAction": {
            "connectionDirection": direction,
            "remoteIpDetails": _remote_ip_details(remote_ip),
            "remotePortDetails": {
                "port": remote_port,
                "portName": _port_name(remote_port),
            },
            "protocol": protocol,
            "blocked": blocked,
        },
    }
    if local_port is not None:
        action["networkConnectionAction"]["localPortDetails"] = {
            "port": local_port,
            "portName": _port_name(local_port),
        }
    return action


def _aws_api_call_action(api: str, service_name: str, caller_type: str = "Remote",
                          source_ip: str = None) -> Dict[str, Any]:
    """Build AWS_API_CALL action block."""
    action = {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {
            "api": api,
            "serviceName": service_name,
            "callerType": caller_type,
        },
    }
    if source_ip:
        action["awsApiCallAction"]["remoteIpDetails"] = _remote_ip_details(source_ip)
    return action


def _remote_ip_details(ip: str) -> Dict[str, Any]:
    """Build remoteIpDetails block for an IP address."""
    ip_hash = hash(ip) & 0xFFFFFFFF
    countries = [
        ("US", "United States", "New York", 40.7128, -74.0060),
        ("DE", "Germany", "Frankfurt", 50.1109, 8.6821),
        ("RU", "Russia", "Moscow", 55.7558, 37.6173),
        ("CN", "China", "Beijing", 39.9042, 116.4074),
        ("NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
        ("RO", "Romania", "Bucharest", 44.4268, 26.1025),
        ("BR", "Brazil", "Sao Paulo", -23.5505, -46.6333),
    ]

    # Threat IP always maps to Germany
    if ip == THREAT_IP:
        country = ("DE", "Germany", "Frankfurt", 50.1109, 8.6821)
    else:
        country = countries[ip_hash % len(countries)]

    org_names = [
        "AS-CHOOPA", "DIGITALOCEAN-ASN", "OVH SAS", "HETZNER-AS",
        "AMAZON-02", "LINODE-AP", "VULTR-AS",
    ]

    return {
        "ipAddressV4": ip,
        "organization": {
            "asn": str(10000 + (ip_hash % 50000)),
            "asnOrg": org_names[ip_hash % len(org_names)],
            "isp": org_names[ip_hash % len(org_names)],
            "org": org_names[ip_hash % len(org_names)],
        },
        "country": {
            "countryCode": country[0],
            "countryName": country[1],
        },
        "city": {
            "cityName": country[2],
        },
        "geoLocation": {
            "lat": country[3],
            "lon": country[4],
        },
    }


def _port_name(port: int) -> str:
    """Return common port name for a given port number."""
    port_names = {
        22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
        6379: "REDIS", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
        9200: "ELASTICSEARCH",
    }
    return port_names.get(port, "Unknown")


# =============================================================================
# BASELINE FINDING GENERATORS
# =============================================================================

def _baseline_port_probe(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Recon:EC2/PortProbeUnprotectedPort - Internet scanning of EC2 instances."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    instance_id = random.choice(_EC2_INSTANCES)
    source_ip = random.choice(_SCANNER_IPS)
    probed_port = random.choice([22, 23, 80, 443, 445, 3389, 8080, 8443, 9200])

    finding = _build_finding_base(
        base_date, day, hour, minute, second,
        finding_type="Recon:EC2/PortProbeUnprotectedPort",
        severity=2.0,
        title=f"Unprotected port on EC2 instance {instance_id} is being probed",
        description=(
            f"EC2 instance {instance_id} has an unprotected port {probed_port} "
            f"which is being probed by a known scanner at {source_ip}."
        ),
    )
    finding["resource"] = _instance_resource(instance_id)
    finding["service"]["action"] = _port_probe_action(source_ip, probed_port)
    finding["service"]["count"] = random.randint(1, 5)
    return finding


def _baseline_tor_s3(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """UnauthorizedAccess:S3/TorIPCaller - Tor exit node S3 API call."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    tor_ip = random.choice(_TOR_EXIT_IPS)
    role_name = random.choice(_SERVICE_ROLES)
    access_key = f"AKIA{uuid.uuid5(uuid.NAMESPACE_DNS, role_name).hex[:16].upper()}"

    finding = _build_finding_base(
        base_date, day, hour, minute, second,
        finding_type="UnauthorizedAccess:S3/TorIPCaller",
        severity=3.0,
        title="S3 API was invoked from a Tor exit node IP address",
        description=(
            f"An S3 API ListBuckets was invoked from Tor exit node IP {tor_ip}. "
            "Tor exit node traffic to S3 may indicate unauthorized reconnaissance."
        ),
    )
    finding["resource"] = _access_key_resource(role_name, access_key)
    finding["service"]["action"] = _aws_api_call_action(
        api="ListBuckets", service_name="s3.amazonaws.com",
        caller_type="Remote", source_ip=tor_ip,
    )
    return finding


def _baseline_root_credential(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Policy:IAMUser/RootCredentialUsage - Root account console sign-in check."""
    minute, second = random.randint(0, 59), random.randint(0, 59)

    finding = _build_finding_base(
        base_date, day, hour, minute, second,
        finding_type="Policy:IAMUser/RootCredentialUsage",
        severity=1.0,
        title="Root credentials were used to make an API request",
        description=(
            "Root account credentials were used to make a ConsoleLogin API call. "
            "It is recommended to use IAM users or roles instead of root credentials."
        ),
    )
    finding["resource"] = _access_key_resource(
        "root", f"AKIA{uuid.uuid5(uuid.NAMESPACE_DNS, 'root').hex[:16].upper()}",
    )
    finding["service"]["action"] = _aws_api_call_action(
        api="ConsoleLogin", service_name="signin.amazonaws.com",
        caller_type="Remote",
        source_ip=random.choice(["73.158.42.100", "68.45.123.80", "24.12.88.150"]),
    )
    return finding


def _baseline_portscan(base_date: str, day: int, hour: int) -> Dict[str, Any]:
    """Recon:EC2/Portscan - Internal or external port scan detected."""
    minute, second = random.randint(0, 59), random.randint(0, 59)
    instance_id = random.choice(_EC2_INSTANCES)
    scanner_ip = random.choice(_SCANNER_IPS)
    scanned_port = random.choice([22, 80, 443, 445, 3306, 3389, 5432, 8080])

    finding = _build_finding_base(
        base_date, day, hour, minute, second,
        finding_type="Recon:EC2/Portscan",
        severity=2.0,
        title=f"EC2 instance {instance_id} is performing outbound port scans",
        description=(
            f"EC2 instance {instance_id} is being used to perform port scans "
            f"against remote host {scanner_ip}. This may indicate compromised behavior."
        ),
    )
    finding["resource"] = _instance_resource(instance_id)
    finding["service"]["action"] = _network_connection_action(
        direction="OUTBOUND", remote_ip=scanner_ip, remote_port=scanned_port,
        local_port=random.randint(32768, 65535),
    )
    finding["service"]["count"] = random.randint(5, 25)
    return finding


# Baseline generators weighted
_BASELINE_GENERATORS = [
    (_baseline_port_probe, 30),
    (_baseline_tor_s3, 25),
    (_baseline_root_credential, 20),
    (_baseline_portscan, 25),
]


def _pick_baseline_generator():
    """Pick a baseline finding generator using weighted random selection."""
    total = sum(w for _, w in _BASELINE_GENERATORS)
    r = random.randint(1, total)
    cumulative = 0
    for gen, weight in _BASELINE_GENERATORS:
        cumulative += weight
        if r <= cumulative:
            return gen
    return _BASELINE_GENERATORS[0][0]


# =============================================================================
# SCENARIO FINDING GENERATORS
# =============================================================================

def _exfil_day8_malicious_ip_caller(base_date: str, day: int) -> Dict[str, Any]:
    """UnauthorizedAccess:IAMUser/MaliciousIPCaller - Backdoor IAM user creation from threat IP."""
    alex = USERS["alex.miller"]

    finding = _build_finding_base(
        base_date, day, 10, random.randint(0, 30), random.randint(0, 59),
        finding_type="UnauthorizedAccess:IAMUser/MaliciousIPCaller",
        severity=8.0,
        title="API CreateUser was invoked from a known malicious IP address",
        description=(
            f"IAM principal alex.miller invoked CreateUser from IP {THREAT_IP}, "
            "which is associated with known malicious activity. This may indicate "
            "compromised credentials being used to establish persistence."
        ),
    )
    finding["resource"] = _access_key_resource(
        "alex.miller", alex.aws_access_key_id, alex.aws_principal_id,
    )
    finding["service"]["action"] = _aws_api_call_action(
        api="CreateUser", service_name="iam.amazonaws.com",
        caller_type="Remote", source_ip=THREAT_IP,
    )
    finding["demo_id"] = "exfil"
    return finding


def _exfil_day8_user_permissions(base_date: str, day: int) -> Dict[str, Any]:
    """Persistence:IAMUser/UserPermissions - Attaching admin policy for persistence."""
    alex = USERS["alex.miller"]

    finding = _build_finding_base(
        base_date, day, 10, random.randint(31, 59), random.randint(0, 59),
        finding_type="Persistence:IAMUser/UserPermissions",
        severity=7.0,
        title="Principal alex.miller invoked AttachUserPolicy to establish persistence",
        description=(
            "IAM principal alex.miller attached AdministratorAccess policy to newly created "
            "user svc-datasync. This behavior is consistent with an attacker establishing "
            "persistent access through a backdoor IAM user."
        ),
    )
    finding["resource"] = _access_key_resource(
        "alex.miller", alex.aws_access_key_id, alex.aws_principal_id,
    )
    finding["service"]["action"] = _aws_api_call_action(
        api="AttachUserPolicy", service_name="iam.amazonaws.com",
        caller_type="Remote", source_ip=THREAT_IP,
    )
    finding["demo_id"] = "exfil"
    return finding


def _exfil_s3_anomalous(base_date: str, day: int) -> Dict[str, Any]:
    """Exfiltration:S3/AnomalousBehavior - Data exfiltration from financial bucket."""
    finding = _build_finding_base(
        base_date, day, 3, random.randint(0, 59), random.randint(0, 59),
        finding_type="Exfiltration:S3/AnomalousBehavior",
        severity=8.0,
        title=f"S3 API calls indicate data exfiltration from bucket {ORG_NAME_LOWER}-financial-reports",
        description=(
            f"Anomalous S3 GetObject activity detected from IAM user svc-datasync "
            f"on bucket {ORG_NAME_LOWER}-financial-reports. The volume and pattern of "
            "data access is significantly higher than the established baseline and "
            "may indicate data exfiltration."
        ),
    )
    finding["resource"] = _access_key_resource(
        "svc-datasync", "AKIAMALICIOUS001", "AIDAMALICIOUS001",
    )
    finding["service"]["action"] = _aws_api_call_action(
        api="GetObject", service_name="s3.amazonaws.com",
        caller_type="Remote", source_ip=THREAT_IP,
    )
    finding["service"]["count"] = random.randint(15, 40)

    # eventFirstSeen is start of exfil window, eventLastSeen is current
    first_seen = ts_iso(base_date, day, 2, 0, 0)
    last_seen = ts_iso(base_date, day, 4, 59, 59)
    finding["service"]["eventFirstSeen"] = first_seen
    finding["service"]["eventLastSeen"] = last_seen

    finding["demo_id"] = "exfil"
    return finding


def _ransomware_malicious_ip(base_date: str, day: int) -> Dict[str, Any]:
    """UnauthorizedAccess:EC2/MaliciousIPCaller - EC2 communicating with known malicious IP."""
    instance_id = _EC2_INSTANCES[0]  # WEB-01

    finding = _build_finding_base(
        base_date, day, 14, random.randint(0, 59), random.randint(0, 59),
        finding_type="UnauthorizedAccess:EC2/MaliciousIPCaller",
        severity=5.0,
        title=f"EC2 instance {instance_id} is communicating with a known malicious IP",
        description=(
            f"EC2 instance {instance_id} is communicating with known malicious IP "
            f"{THREAT_IP} on port 445 (SMB). This may indicate a ransomware infection "
            "attempt or lateral movement activity."
        ),
    )
    finding["resource"] = _instance_resource(instance_id)
    finding["service"]["action"] = _network_connection_action(
        direction="OUTBOUND", remote_ip=THREAT_IP, remote_port=445,
        local_port=random.randint(49152, 65535),
    )
    finding["demo_id"] = "ransomware_attempt"
    return finding


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_aws_guardduty_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate AWS GuardDuty findings.

    Produces 3-8 low-severity baseline findings per day plus scenario-injected
    high-severity findings for exfil (days 8-13) and ransomware (day 8).
    """

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("cloud", "aws/aws_guardduty.json")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)

    # Scale baseline volume: 3-8 findings/day at scale=1.0
    baseline_min = max(1, int(3 * scale))
    baseline_max = max(baseline_min, int(8 * scale))

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  AWS GuardDuty Findings Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_findings: List[Dict[str, Any]] = []

    for day in range(days):
        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [GuardDuty] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        # --- Baseline findings: pick N random hours and generate 1 finding each ---
        num_baseline = random.randint(baseline_min, baseline_max)
        baseline_hours = sorted(random.sample(range(24), min(num_baseline, 24)))

        for hour in baseline_hours:
            gen_func = _pick_baseline_generator()
            finding = gen_func(start_date, day, hour)
            all_findings.append(finding)

        # --- Exfil scenario findings (days 8-13, 0-indexed 7-12) ---
        if "exfil" in active_scenarios:
            # Day 8 (index 7): IAM persistence findings
            if day == 7:
                all_findings.append(_exfil_day8_malicious_ip_caller(start_date, day))
                all_findings.append(_exfil_day8_user_permissions(start_date, day))

            # Days 11-13 (index 10-12): S3 exfiltration findings
            if 10 <= day <= 12:
                all_findings.append(_exfil_s3_anomalous(start_date, day))

        # --- Ransomware scenario finding (day 8, 0-indexed 7) ---
        if "ransomware_attempt" in active_scenarios and day == 7:
            all_findings.append(_ransomware_malicious_ip(start_date, day))

        if not quiet:
            dt = date_add(start_date, day)
            print(f"  [GuardDuty] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort by createdAt timestamp
    all_findings.sort(key=lambda x: x["createdAt"])

    # Write output (NDJSON)
    with open(output_path, "w") as f:
        for finding in all_findings:
            f.write(json.dumps(finding) + "\n")

    if not quiet:
        exfil_count = sum(1 for f in all_findings if f.get("demo_id") == "exfil")
        ransom_count = sum(1 for f in all_findings if f.get("demo_id") == "ransomware_attempt")
        baseline_count = sum(1 for f in all_findings if "demo_id" not in f)
        print(f"  [GuardDuty] Complete! {len(all_findings):,} findings written", file=sys.stderr)
        print(f"        baseline: {baseline_count:,}", file=sys.stderr)
        if exfil_count:
            print(f"        exfil findings: {exfil_count}", file=sys.stderr)
        if ransom_count:
            print(f"        ransomware findings: {ransom_count}", file=sys.stderr)

    return len(all_findings)


def main():
    parser = argparse.ArgumentParser(description="Generate AWS GuardDuty findings")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_aws_guardduty_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
