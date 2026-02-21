#!/usr/bin/env python3
"""
Cisco Catalyst Center (formerly DNA Center) log generator.

Generates 4 JSON output files matching Catalyst Center Assurance API format:
  - catalyst_center_devicehealth.json: ~864/day (3 switches x 288 polls)
  - catalyst_center_networkhealth.json: ~576/day (2 sites x 288 polls)
  - catalyst_center_clienthealth.json: ~100/day (aggregated per-site)
  - catalyst_center_issues.json: ~10-30/day (detected problems)

Architecture: On-prem Catalyst Center at Boston, managing 3 Catalyst switches.
Provides health scores, issues, compliance for wired campus.

Formats verified against Cisco Catalyst Center API v2 and
Splunk Add-on for Cisco DNA Center (Splunkbase #7858).
"""

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import (
    calc_natural_events,
    date_add,
    is_weekend,
)
from scenarios.registry import expand_scenarios, is_scenario_active_day

# =============================================================================
# CATALYST CENTER CONFIGURATION
# =============================================================================

# Managed switches (must match generate_catalyst.py)
MANAGED_DEVICES = [
    {
        "name": "CAT-BOS-DIST-01",
        "model": "C9300-48UXM",
        "ipAddress": "10.10.10.30",
        "macAddress": "aa:bb:cc:dd:ee:01",
        "uuid": "a1b2c3d4-0001",
        "osVersion": "17.12.4",
        "deviceFamily": "Switches and Hubs",
        "deviceType": "Cisco Catalyst 9300 Switch",
        "location": "/global/Boston-HQ/Floor-3",
        "site": "BOS",
    },
    {
        "name": "CAT-BOS-DIST-02",
        "model": "C9300-48UXM",
        "ipAddress": "10.10.10.31",
        "macAddress": "aa:bb:cc:dd:ee:02",
        "uuid": "a1b2c3d4-0002",
        "osVersion": "17.12.4",
        "deviceFamily": "Switches and Hubs",
        "deviceType": "Cisco Catalyst 9300 Switch",
        "location": "/global/Boston-HQ/Floor-2",
        "site": "BOS",
    },
    {
        "name": "CAT-ATL-DIST-01",
        "model": "C9300-48UXM",
        "ipAddress": "10.20.10.30",
        "macAddress": "aa:bb:cc:dd:ee:03",
        "uuid": "a1b2c3d4-0003",
        "osVersion": "17.12.4",
        "deviceFamily": "Switches and Hubs",
        "deviceType": "Cisco Catalyst 9300 Switch",
        "location": "/global/Atlanta-Hub/Floor-1",
        "site": "ATL",
    },
]

# Sites
SITES = {
    "BOS": {"siteId": "site-bos-001", "name": "Boston-HQ", "devices": 2, "wired_clients": 20, "wireless_clients": 73},
    "ATL": {"siteId": "site-atl-001", "name": "Atlanta-Hub", "devices": 1, "wired_clients": 10, "wireless_clients": 33},
}

# Issue templates
ISSUE_TEMPLATES = [
    # (issueName, issueCategory, description_template, severity, priority, entity, weight)
    ("network_device_high_cpu", "Utilization", "High CPU utilization detected on {device}", "HIGH", "P2", "NETWORK_DEVICE", 3),
    ("network_device_high_memory", "Utilization", "High memory utilization detected on {device}", "MEDIUM", "P3", "NETWORK_DEVICE", 2),
    ("interface_input_errors", "Availability", "Interface input errors detected on {device} {iface}", "MEDIUM", "P3", "NETWORK_DEVICE", 4),
    ("interface_output_errors", "Availability", "Interface output errors detected on {device} {iface}", "MEDIUM", "P3", "NETWORK_DEVICE", 3),
    ("device_unreachable", "Availability", "Device {device} is unreachable", "HIGH", "P1", "NETWORK_DEVICE", 1),
    ("wireless_client_connection_fail", "Connected", "Wireless client connection failures on {device}", "LOW", "P4", "SWITCH", 5),
    ("poe_power_budget", "Device", "PoE power budget exceeded on {device}", "MEDIUM", "P3", "SWITCH", 2),
    ("spanning_tree_topology_change", "Availability", "Spanning tree topology change detected on {device}", "LOW", "P4", "SWITCH", 3),
    ("client_onboarding_failure", "Onboarding", "Client onboarding failures detected at {site}", "MEDIUM", "P3", "CLIENT", 4),
    ("application_experience_issue", "Application", "Application experience degradation at {site}", "LOW", "P4", "CLIENT", 2),
]

# Suggested actions for issues
SUGGESTED_ACTIONS = {
    "network_device_high_cpu": [
        {"message": "Check for routing loops or excessive traffic", "steps": []},
        {"message": "Review running processes with 'show processes cpu sorted'", "steps": []},
    ],
    "network_device_high_memory": [
        {"message": "Check memory usage with 'show memory statistics'", "steps": []},
        {"message": "Review buffer allocations and fragmentation", "steps": []},
    ],
    "interface_input_errors": [
        {"message": "Check cable integrity and SFP module", "steps": []},
        {"message": "Review interface counters for CRC or alignment errors", "steps": []},
    ],
    "device_unreachable": [
        {"message": "Verify network connectivity to device", "steps": []},
        {"message": "Check SNMP and SSH credentials", "steps": []},
    ],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _iso_ts(start_date: str, day: int, hour: int,
            minute: int = 0, second: int = 0) -> str:
    """Generate ISO 8601 timestamp: '2026-01-05T14:00:00.000Z'."""
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.000Z"


def _epoch_ms(start_date: str, day: int, hour: int,
              minute: int = 0, second: int = 0) -> int:
    """Generate epoch timestamp in milliseconds."""
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return int(dt.timestamp() * 1000)


def _time_with_offset(start_date: str, day: int, hour: int,
                      minute: int = 0) -> str:
    """Generate timestamp with +0000 offset: '2026-01-05T14:00:00.000+0000'."""
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=0)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.000+0000"


def _sort_key(start_date: str, day: int, hour: int,
              minute: int = 0, second: int = 0) -> str:
    """Generate sortable timestamp key."""
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y%m%d%H%M%S")


def _jitter(value: float, pct: float = 5.0) -> float:
    """Add small random jitter to a value."""
    delta = value * pct / 100.0
    return round(value + random.uniform(-delta, delta), 1)


def _health_score_seed(start_date: str, day: int, hour: int,
                       device_name: str) -> int:
    """Deterministic seed for consistent health scores."""
    seed_str = f"{start_date}-{day}-{hour}-{device_name}"
    return int(hashlib.md5(seed_str.encode()).hexdigest()[:8], 16)


# =============================================================================
# DEVICE HEALTH GENERATOR
# =============================================================================

def _generate_device_health(start_date: str, day: int, hour: int,
                            minute: int, device: dict,
                            health_override: dict = None,
                            demo_id: str = "") -> tuple:
    """Generate device health poll for one switch at one 5-min interval."""
    rng = random.Random(_health_score_seed(start_date, day, hour, device["name"]) + minute)

    # Baseline healthy values
    cpu_util = rng.uniform(15, 35)
    mem_util = rng.uniform(35, 55)
    avg_temp = rng.uniform(35, 42)
    max_temp = avg_temp + rng.uniform(2, 6)
    overall_health = 10
    cpu_health = 9 if cpu_util < 50 else (7 if cpu_util < 70 else 4)
    mem_health = 10 if mem_util < 60 else (7 if mem_util < 80 else 3)
    link_health = 10
    iface_err_health = 10
    reachability = "REACHABLE"
    issue_count = 0

    # Apply overrides (from scenario functions)
    if health_override:
        cpu_util = health_override.get("cpuUtilization", cpu_util)
        mem_util = health_override.get("memoryUtilization", mem_util)
        overall_health = health_override.get("overallHealth", overall_health)
        cpu_health = health_override.get("cpuHealth", cpu_health)
        mem_health = health_override.get("memoryUtilizationHealth", mem_health)
        link_health = health_override.get("interDeviceLinkAvailHealth", link_health)
        iface_err_health = health_override.get("interfaceLinkErrHealth", iface_err_health)
        reachability = health_override.get("reachabilityHealth", reachability)
        issue_count = health_override.get("issueCount", issue_count)

    ts = _iso_ts(start_date, day, hour, minute)
    sk = _sort_key(start_date, day, hour, minute)

    event = {
        "name": device["name"],
        "model": device["model"],
        "ipAddress": device["ipAddress"],
        "macAddress": device["macAddress"],
        "uuid": device["uuid"],
        "osVersion": device["osVersion"],
        "deviceFamily": device["deviceFamily"],
        "deviceType": device["deviceType"],
        "location": device["location"],
        "overallHealth": overall_health,
        "issueCount": issue_count,
        "cpuHealth": cpu_health,
        "cpuUlitilization": round(cpu_util, 1),  # Real API typo
        "cpuUtilization": round(cpu_util, 1),
        "memoryUtilization": round(mem_util, 1),
        "memoryUtilizationHealth": mem_health,
        "interDeviceLinkAvailHealth": link_health,
        "interfaceLinkErrHealth": iface_err_health,
        "reachabilityHealth": reachability,
        "avgTemperature": round(avg_temp, 1),
        "maxTemperature": round(max_temp, 1),
        "freeMemoryBuffer": round(rng.uniform(20000, 60000), 1),
        "freeMemoryBufferHealth": 10 if mem_util < 60 else (9 if mem_util < 75 else 7),
        "packetPool": round(rng.uniform(70, 90), 1),
        "packetPoolHealth": 10 if cpu_util < 50 else (9 if cpu_util < 70 else 7),
        "timestamp": ts,
        "demo_id": demo_id,
    }

    return sk, event


# =============================================================================
# NETWORK HEALTH GENERATOR
# =============================================================================

def _generate_network_health(start_date: str, day: int, hour: int,
                             minute: int, site_code: str,
                             health_override: dict = None,
                             demo_id: str = "") -> tuple:
    """Generate network health poll for one site at one 5-min interval."""
    site = SITES[site_code]
    rng = random.Random(_health_score_seed(start_date, day, hour, site_code) + minute)

    total_count = site["devices"]
    good_count = total_count
    bad_count = 0
    fair_count = 0

    # Apply overrides
    if health_override:
        good_count = health_override.get("goodCount", good_count)
        bad_count = health_override.get("badCount", bad_count)
        fair_count = health_override.get("fairCount", fair_count)

    healthy = good_count
    unhealthy = bad_count + fair_count
    health_score = int((healthy / total_count) * 100) if total_count > 0 else 0
    good_pct = round((good_count / total_count) * 100, 1) if total_count > 0 else 0.0

    avg_cpu = rng.uniform(18, 30)
    avg_mem = rng.uniform(38, 50)

    if health_override:
        health_score = health_override.get("healthScore", health_score)
        avg_cpu = health_override.get("avgCpu", avg_cpu)
        avg_mem = health_override.get("avgMem", avg_mem)

    ts = _iso_ts(start_date, day, hour, minute)
    time_str = _time_with_offset(start_date, day, hour, minute)
    sk = _sort_key(start_date, day, hour, minute)

    event = {
        "time": time_str,
        "healthScore": health_score,
        "totalCount": total_count,
        "goodCount": good_count,
        "badCount": bad_count,
        "fairCount": fair_count,
        "noHealthCount": 0,
        "unmonCount": 0,
        "monitoredDevices": total_count,
        "monitoredHealthyDevices": healthy,
        "monitoredUnHealthyDevices": unhealthy,
        "healthDistribution": [
            {
                "category": "Distribution",
                "totalCount": total_count,
                "healthScore": health_score,
                "goodPercentage": good_pct,
                "goodCount": good_count,
                "badCount": bad_count,
                "fairCount": fair_count,
                "kpiMetrics": [
                    {"key": "cpu", "value": str(round(avg_cpu, 1))},
                    {"key": "memory", "value": str(round(avg_mem, 1))},
                ],
            }
        ],
        # Real API typo: "Distirubution" instead of "Distribution"
        "healthDistirubution": [
            {
                "category": "Distribution",
                "totalCount": total_count,
                "healthScore": health_score,
                "goodPercentage": good_pct,
                "goodCount": good_count,
                "badCount": bad_count,
                "fairCount": fair_count,
            }
        ],
        "timestamp": ts,
        "demo_id": demo_id,
    }

    return sk, event


# =============================================================================
# CLIENT HEALTH GENERATOR
# =============================================================================

def _generate_client_health(start_date: str, day: int, hour: int,
                            site_code: str,
                            health_override: dict = None,
                            demo_id: str = "") -> tuple:
    """Generate client health snapshot for a site."""
    site = SITES[site_code]
    rng = random.Random(_health_score_seed(start_date, day, hour, site_code) + 999)

    wired = site["wired_clients"]
    wireless = site["wireless_clients"]
    total = wired + wireless

    # Baseline distribution
    good_pct = rng.uniform(80, 95)
    fair_pct = rng.uniform(3, 10)
    poor_pct = max(0, 100 - good_pct - fair_pct - 5)  # Leave room for idle/nodata
    idle_pct = rng.uniform(2, 5)
    nodata_pct = max(0, 100 - good_pct - fair_pct - poor_pct - idle_pct)

    good_count = int(total * good_pct / 100)
    fair_count = int(total * fair_pct / 100)
    poor_count = int(total * poor_pct / 100)
    idle_count = int(total * idle_pct / 100)
    nodata_count = total - good_count - fair_count - poor_count - idle_count

    score_value = int(good_pct)
    wired_score = rng.randint(90, 100)
    wireless_score = rng.randint(80, 95)

    # Apply overrides
    if health_override:
        score_value = health_override.get("scoreValue", score_value)
        poor_count = health_override.get("poorCount", poor_count)
        good_count = health_override.get("goodCount", good_count)
        wireless_score = health_override.get("wirelessScore", wireless_score)

    start_epoch = _epoch_ms(start_date, day, hour)
    end_epoch = start_epoch + 3600000  # 1 hour later

    ts = _iso_ts(start_date, day, hour)
    sk = _sort_key(start_date, day, hour)

    event = {
        "siteId": site["siteId"],
        "scoreDetail": [
            {
                "scoreCategory": {"scoreCategory": "CLIENT_TYPE", "value": "ALL"},
                "scoreValue": score_value,
                "clientCount": total,
                "starttime": start_epoch,
                "endtime": end_epoch,
                "scoreList": [
                    {"scoreCategory": {"scoreCategory": "SCORE_TYPE", "value": "POOR"}, "scoreValue": -1, "clientCount": poor_count},
                    {"scoreCategory": {"scoreCategory": "SCORE_TYPE", "value": "FAIR"}, "scoreValue": -1, "clientCount": fair_count},
                    {"scoreCategory": {"scoreCategory": "SCORE_TYPE", "value": "GOOD"}, "scoreValue": -1, "clientCount": good_count},
                    {"scoreCategory": {"scoreCategory": "SCORE_TYPE", "value": "IDLE"}, "scoreValue": -1, "clientCount": idle_count},
                    {"scoreCategory": {"scoreCategory": "SCORE_TYPE", "value": "NODATA"}, "scoreValue": -1, "clientCount": nodata_count},
                ],
            },
            {
                "scoreCategory": {"scoreCategory": "CLIENT_TYPE", "value": "WIRED"},
                "scoreValue": wired_score,
                "clientCount": wired,
            },
            {
                "scoreCategory": {"scoreCategory": "CLIENT_TYPE", "value": "WIRELESS"},
                "scoreValue": wireless_score,
                "clientCount": wireless,
            },
        ],
        "timestamp": ts,
        "demo_id": demo_id,
    }

    return sk, event


# =============================================================================
# ISSUE GENERATOR
# =============================================================================

_issue_counter = [0]

def _generate_issue(start_date: str, day: int, hour: int,
                    template_override: tuple = None,
                    device_override: dict = None,
                    descr_override: str = None,
                    severity_override: str = None,
                    demo_id: str = "") -> tuple:
    """Generate a Catalyst Center issue event."""
    _issue_counter[0] += 1

    if template_override:
        name, category, descr_tmpl, severity, priority, entity, _ = template_override
    else:
        tmpl = random.choices(ISSUE_TEMPLATES, weights=[t[-1] for t in ISSUE_TEMPLATES], k=1)[0]
        name, category, descr_tmpl, severity, priority, entity, _ = tmpl

    device = device_override or random.choice(MANAGED_DEVICES)
    iface = f"GigabitEthernet1/0/{random.randint(1, 48)}"
    site = SITES.get(device.get("site", "BOS"), SITES["BOS"])

    descr = descr_override or descr_tmpl.format(
        device=device["name"], iface=iface, site=site["name"],
    )

    if severity_override:
        severity = severity_override

    ts = _iso_ts(start_date, day, hour, random.randint(0, 59), random.randint(0, 59))
    issue_ts = _epoch_ms(start_date, day, hour, random.randint(0, 59))
    sk = _sort_key(start_date, day, hour, random.randint(0, 59), random.randint(0, 59))

    actions = SUGGESTED_ACTIONS.get(name, [{"message": "Investigate the issue", "steps": []}])

    # Real API typo fields: "occurence" instead of "occurrence"
    last_occurence_ts = _epoch_ms(start_date, day, hour, random.randint(0, 59))

    event = {
        "issueId": f"AWf2-issue-{_issue_counter[0]:04d}",
        "issueSource": "Assurance",
        "issueCategory": category,
        "issueName": name,
        "issueDescription": descr,
        "issueEntity": entity,
        "issueEntityValue": device["uuid"],
        "issueSeverity": severity,
        "issuePriority": priority,
        "issueSummary": descr,
        "issueTimestamp": issue_ts,
        "status": "active",
        "issue_occurence_count": random.randint(1, 5),
        "last_occurence_time": last_occurence_ts,
        "suggestedActions": actions,
        "impactedHosts": [],
        "timestamp": ts,
        "demo_id": demo_id,
    }

    return sk, event


# =============================================================================
# SCENARIO INTEGRATION
# =============================================================================

def _ddos_device_health_override(day: int, hour: int) -> Optional[dict]:
    """DDoS scenario: health drops on all switches Days 17-18, hours 10-20."""
    if not (17 <= day <= 18 and 10 <= hour <= 20):
        return None
    # Ramp: worse during peak hours
    severity = min(1.0, (hour - 10) / 5.0) if day == 17 else max(0.0, 1.0 - (hour - 10) / 10.0)
    cpu = 40 + severity * 55  # 40-95%
    return {
        "cpuUtilization": cpu,
        "overallHealth": max(1, int(10 - severity * 8)),
        "cpuHealth": max(1, int(9 - severity * 7)),
        "interfaceLinkErrHealth": max(3, int(10 - severity * 5)),
        "issueCount": int(severity * 3),
    }


def _ddos_network_health_override(day: int, hour: int, site_code: str) -> Optional[dict]:
    """DDoS: network health drops for BOS site."""
    if site_code != "BOS" or not (17 <= day <= 18 and 10 <= hour <= 20):
        return None
    severity = min(1.0, (hour - 10) / 5.0) if day == 17 else max(0.0, 1.0 - (hour - 10) / 10.0)
    return {
        "healthScore": max(30, int(100 - severity * 70)),
        "goodCount": max(0, 2 - int(severity * 2)),
        "badCount": min(2, int(severity * 2)),
        "fairCount": 0,
        "avgCpu": 40 + severity * 50,
    }


def _cpu_runaway_device_health_override(day: int, hour: int, device: dict) -> Optional[dict]:
    """CPU runaway scenario: switch carrying SQL-PROD-01 traffic affected Days 10-11."""
    if device["name"] != "CAT-BOS-DIST-01":
        return None
    if not (10 <= day <= 11):
        return None
    if day == 10 and hour < 14:
        return None
    if day == 11 and hour > 10:
        return None  # Fixed at 10:30 on Day 12 (day=11)

    # Gradual ramp from Day 10 14:00 to Day 11 10:00
    if day == 10:
        progress = (hour - 14) / 10.0
    else:
        progress = 1.0 - (10 - hour) / 10.0

    cpu = 50 + progress * 45
    return {
        "cpuUtilization": cpu,
        "overallHealth": max(2, int(10 - progress * 7)),
        "cpuHealth": max(1, int(9 - progress * 7)),
        "memoryUtilizationHealth": max(5, int(10 - progress * 3)),
        "issueCount": max(1, int(progress * 3)),
    }


def _memory_leak_client_health_override(day: int, hour: int, site_code: str) -> Optional[dict]:
    """Memory leak scenario: client health degrades for BOS Days 6-9 as WEB-01 affects service."""
    if site_code != "BOS" or not (6 <= day <= 9):
        return None
    # Gradual degradation
    progress = (day - 6) / 3.0  # 0.0 to 1.0
    return {
        "scoreValue": max(55, int(92 - progress * 35)),
        "poorCount": int(progress * 15),
        "wirelessScore": max(60, int(90 - progress * 25)),
    }


def _generate_ddos_issues(start_date: str, day: int, hour: int) -> List[tuple]:
    """DDoS issues: interface and CPU problems Days 17-18."""
    events = []
    if not (17 <= day <= 18 and 10 <= hour <= 20):
        return events
    if random.random() < 0.15:
        device = random.choice(MANAGED_DEVICES[:2])  # BOS devices
        events.append(_generate_issue(
            start_date, day, hour,
            descr_override=f"High CPU utilization detected on {device['name']} during DDoS event",
            severity_override="HIGH",
            device_override=device,
            demo_id="ddos_attack",
        ))
    if random.random() < 0.2:
        device = random.choice(MANAGED_DEVICES[:2])
        events.append(_generate_issue(
            start_date, day, hour,
            descr_override=f"Interface input errors detected on {device['name']} GigabitEthernet1/0/1 during DDoS event",
            severity_override="HIGH",
            device_override=device,
            demo_id="ddos_attack",
        ))
    return events


def _generate_cpu_runaway_issues(start_date: str, day: int, hour: int) -> List[tuple]:
    """CPU runaway issues on CAT-BOS-DIST-01 Days 10-11."""
    events = []
    if not (10 <= day <= 11):
        return events
    if day == 10 and hour < 14:
        return events
    if day == 11 and hour > 10:
        return events
    if random.random() < 0.2:
        events.append(_generate_issue(
            start_date, day, hour,
            descr_override=f"High CPU utilization detected on CAT-BOS-DIST-01 (SQL backup job impact)",
            severity_override="HIGH",
            device_override=MANAGED_DEVICES[0],
            demo_id="cpu_runaway",
        ))
    return events


# =============================================================================
# MAIN GENERATOR FUNCTION
# =============================================================================

def generate_catalyst_center_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    progress_callback=None,
    quiet: bool = False,
) -> int:
    """Generate Cisco Catalyst Center logs (device/network/client health + issues).

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume multiplier (1.0 = normal)
        scenarios: Comma-separated scenario names or "none"/"all"
        output_file: Override output path (ignored for multi-file)
        quiet: Suppress progress output

    Returns:
        int: Total number of events generated across all files
    """
    active_scenarios = expand_scenarios(scenarios)

    device_path = get_output_path("cloud", "catalyst_center/catalyst_center_devicehealth.json")
    network_path = get_output_path("cloud", "catalyst_center/catalyst_center_networkhealth.json")
    client_path = get_output_path("cloud", "catalyst_center/catalyst_center_clienthealth.json")
    issues_path = get_output_path("cloud", "catalyst_center/catalyst_center_issues.json")

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Catalyst Center Generator (Health + Issues)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {device_path.parent}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    device_events: List[tuple] = []
    network_events: List[tuple] = []
    client_events: List[tuple] = []
    issue_events: List[tuple] = []
    demo_id_count = 0

    # Health polling interval: 5 minutes = 12 polls per hour
    poll_minutes = list(range(0, 60, 5))  # [0, 5, 10, ..., 55]

    for day in range(days):
        if progress_callback:
            progress_callback("catalyst_center", day + 1, days)
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [CatCenter] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # ---- Device Health (5-min polls, 3 devices) ----
            for minute in poll_minutes:
                for device in MANAGED_DEVICES:
                    health_override = None
                    demo_id = ""

                    # Scenario overrides
                    if "ddos_attack" in active_scenarios and is_scenario_active_day("ddos_attack", day):
                        override = _ddos_device_health_override(day, hour)
                        if override:
                            health_override = override
                            demo_id = "ddos_attack"

                    if "cpu_runaway" in active_scenarios and is_scenario_active_day("cpu_runaway", day):
                        override = _cpu_runaway_device_health_override(day, hour, device)
                        if override:
                            health_override = override
                            demo_id = "cpu_runaway"

                    device_events.append(_generate_device_health(
                        start_date, day, hour, minute, device,
                        health_override=health_override, demo_id=demo_id,
                    ))
                    if demo_id:
                        demo_id_count += 1

            # ---- Network Health (5-min polls, 2 sites) ----
            for minute in poll_minutes:
                for site_code in SITES:
                    health_override = None
                    demo_id = ""

                    if "ddos_attack" in active_scenarios and is_scenario_active_day("ddos_attack", day):
                        override = _ddos_network_health_override(day, hour, site_code)
                        if override:
                            health_override = override
                            demo_id = "ddos_attack"

                    network_events.append(_generate_network_health(
                        start_date, day, hour, minute, site_code,
                        health_override=health_override, demo_id=demo_id,
                    ))
                    if demo_id:
                        demo_id_count += 1

            # ---- Client Health (hourly, during active hours or reduced at night) ----
            # Business hours: every hour for both sites
            # Off-hours: every 3 hours
            if 7 <= hour <= 20 or hour % 3 == 0:
                for site_code in SITES:
                    health_override = None
                    demo_id = ""

                    if "memory_leak" in active_scenarios and is_scenario_active_day("memory_leak", day):
                        override = _memory_leak_client_health_override(day, hour, site_code)
                        if override:
                            health_override = override
                            demo_id = "memory_leak"

                    client_events.append(_generate_client_health(
                        start_date, day, hour, site_code,
                        health_override=health_override, demo_id=demo_id,
                    ))
                    if demo_id:
                        demo_id_count += 1

            # ---- Issues (baseline: ~1-2 per day during business hours) ----
            if 8 <= hour <= 17 and not is_weekend(day_date):
                if random.random() < 0.02 * scale:
                    issue_events.append(_generate_issue(start_date, day, hour))

            # Scenario issues
            if "ddos_attack" in active_scenarios and is_scenario_active_day("ddos_attack", day):
                ddos_issues = _generate_ddos_issues(start_date, day, hour)
                issue_events.extend(ddos_issues)
                demo_id_count += len(ddos_issues)

            if "cpu_runaway" in active_scenarios and is_scenario_active_day("cpu_runaway", day):
                cpu_issues = _generate_cpu_runaway_issues(start_date, day, hour)
                issue_events.extend(cpu_issues)
                demo_id_count += len(cpu_issues)

    # Sort by timestamp key
    device_events.sort(key=lambda x: x[0])
    network_events.sort(key=lambda x: x[0])
    client_events.sort(key=lambda x: x[0])
    issue_events.sort(key=lambda x: x[0])

    # Write files
    def _write_json(path: Path, events: List[tuple]):
        with open(path, "w") as f:
            for _, ev in events:
                f.write(json.dumps(ev) + "\n")

    _write_json(device_path, device_events)
    _write_json(network_path, network_events)
    _write_json(client_path, client_events)
    _write_json(issues_path, issue_events)

    total = len(device_events) + len(network_events) + len(client_events) + len(issue_events)
    file_counts = {
        "cloud/catalyst_center/catalyst_center_devicehealth.json": len(device_events),
        "cloud/catalyst_center/catalyst_center_networkhealth.json": len(network_events),
        "cloud/catalyst_center/catalyst_center_clienthealth.json": len(client_events),
        "cloud/catalyst_center/catalyst_center_issues.json": len(issue_events),
    }

    if not quiet:
        print(f"  [CatCenter] Complete! {total:,} total events written", file=sys.stderr)
        print(f"          Device Health: {len(device_events):,} events -> {device_path.name}", file=sys.stderr)
        print(f"          Network Health: {len(network_events):,} events -> {network_path.name}", file=sys.stderr)
        print(f"          Client Health: {len(client_events):,} events -> {client_path.name}", file=sys.stderr)
        print(f"          Issues: {len(issue_events):,} events -> {issues_path.name}", file=sys.stderr)
        if demo_id_count:
            print(f"          demo_id events: {demo_id_count:,}", file=sys.stderr)

    return {"total": total, "files": file_counts}


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generate Cisco Catalyst Center logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", help="Output path override")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_catalyst_center_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
