#!/usr/bin/env python3
"""
Cisco ACI (Application Centric Infrastructure) log generator.

Generates 3 JSON output files matching APIC REST API format:
  - cisco_aci_fault.json (faultInst): ~500-1000/day
  - cisco_aci_event.json (eventRecord): ~2000-3500/day
  - cisco_aci_audit.json (aaaModLR): ~30-50/day

Architecture: Small ACI fabric for a 175-person company
  Boston DC: 2 spines (N9K-C9336C-FX2), 4 leafs (N9K-C93180YC-FX), 1 APIC
  Atlanta: 1 spine, 2 leafs (shared APIC in Boston)

Formats verified against Cisco APIC REST API documentation and
Splunk Add-on for Cisco ACI.
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
from shared.company import (
    USERS,
    SERVERS,
    TENANT,
)
from scenarios.registry import expand_scenarios, is_scenario_active_day

# =============================================================================
# ACI FABRIC CONFIGURATION
# =============================================================================

ACI_FABRIC = {
    "BOS": {
        "apic": {
            "name": "APIC-BOS-01",
            "ip": "10.10.10.20",
            "dn": "topology/pod-1/node-1",
        },
        "spines": [
            {"name": "SPINE-BOS-01", "id": 101, "model": "N9K-C9336C-FX2", "dn": "topology/pod-1/node-101"},
            {"name": "SPINE-BOS-02", "id": 102, "model": "N9K-C9336C-FX2", "dn": "topology/pod-1/node-102"},
        ],
        "leafs": [
            {"name": "LEAF-BOS-01", "id": 201, "model": "N9K-C93180YC-FX", "dn": "topology/pod-1/node-201"},
            {"name": "LEAF-BOS-02", "id": 202, "model": "N9K-C93180YC-FX", "dn": "topology/pod-1/node-202"},
            {"name": "LEAF-BOS-03", "id": 203, "model": "N9K-C93180YC-FX", "dn": "topology/pod-1/node-203"},
            {"name": "LEAF-BOS-04", "id": 204, "model": "N9K-C93180YC-FX", "dn": "topology/pod-1/node-204"},
        ],
        "epgs": [
            {"name": "EPG-Servers", "dn": "uni/tn-TShirtCo-Prod/ap-DataCenter/epg-Servers", "vlan": 100},
            {"name": "EPG-DBServers", "dn": "uni/tn-TShirtCo-Prod/ap-DataCenter/epg-DBServers", "vlan": 200},
            {"name": "EPG-WebDMZ", "dn": "uni/tn-TShirtCo-Prod/ap-DataCenter/epg-WebDMZ", "vlan": 300},
            {"name": "EPG-Management", "dn": "uni/tn-TShirtCo-Prod/ap-DataCenter/epg-Management", "vlan": 400},
            {"name": "EPG-Backup", "dn": "uni/tn-TShirtCo-Prod/ap-DataCenter/epg-Backup", "vlan": 500},
        ],
    },
    "ATL": {
        "spines": [
            {"name": "SPINE-ATL-01", "id": 301, "model": "N9K-C9336C-FX2", "dn": "topology/pod-2/node-301"},
        ],
        "leafs": [
            {"name": "LEAF-ATL-01", "id": 401, "model": "N9K-C93180YC-FX", "dn": "topology/pod-2/node-401"},
            {"name": "LEAF-ATL-02", "id": 402, "model": "N9K-C93180YC-FX", "dn": "topology/pod-2/node-402"},
        ],
        "epgs": [
            {"name": "EPG-ATLServers", "dn": "uni/tn-TShirtCo-Prod/ap-Atlanta/epg-ATLServers", "vlan": 100},
            {"name": "EPG-ATLBackup", "dn": "uni/tn-TShirtCo-Prod/ap-Atlanta/epg-ATLBackup", "vlan": 200},
            {"name": "EPG-ATLMonitor", "dn": "uni/tn-TShirtCo-Prod/ap-Atlanta/epg-ATLMonitor", "vlan": 300},
        ],
    },
}

# All nodes (for event generation)
ALL_NODES = []
for site in ACI_FABRIC.values():
    for spine in site.get("spines", []):
        ALL_NODES.append(spine)
    for leaf in site.get("leafs", []):
        ALL_NODES.append(leaf)

ALL_EPGS = []
for site in ACI_FABRIC.values():
    ALL_EPGS.extend(site.get("epgs", []))

# ACI admin users
ACI_ADMINS = ["admin", "patrick.gonzalez", "jessica.brown", "david.robinson"]

# Tenant names
TENANTS = ["TShirtCo-Prod", "TShirtCo-Dev", "common", "infra", "mgmt"]

# =============================================================================
# FAULT CONFIGURATION
# =============================================================================

# Fault codes, severities, and descriptions (verified from APIC docs)
FAULT_TEMPLATES = [
    # (code, severity, cause, type, subject, domain, descr_template, weight)
    ("F0546", "warning", "port-failure", "communications", "port-down", "access",
     "Port is down, reason:{reason}, used by:{usage}", 15),
    ("F0532", "minor", "port-failure", "communications", "link-down", "access",
     "Link is down on interface {iface}", 10),
    ("F0475", "warning", "threshold-crossed", "operational", "health-score", "health",
     "Health score for {entity} dropped below threshold: {score}", 8),
    ("F1394", "info", "resolution", "config", "endpoint-attach", "access",
     "Endpoint {mac} learned on {leaf} port {iface}", 20),
    ("F0103", "cleared", "resolution", "equipment", "psu-ok", "equipment",
     "PSU operational on {node}", 5),
    ("F0058", "critical", "equipment-failure", "equipment", "fan-failure", "equipment",
     "Fan tray failure detected on {node}", 1),
    ("F0454", "major", "threshold-crossed", "operational", "high-cpu", "resource",
     "CPU utilization on {node} exceeds threshold: {pct}%", 3),
    ("F0533", "warning", "protocol-failure", "communications", "bgp-down", "infra",
     "BGP session to {peer} is down", 4),
    ("F2480", "info", "transition", "config", "contract-hit", "tenant",
     "Contract {contract} rule matched: {action}", 15),
    ("F0467", "minor", "threshold-crossed", "operational", "memory-high", "resource",
     "Memory utilization on {node} exceeds threshold: {pct}%", 3),
    ("F1584", "warning", "resolution", "config", "ep-move", "access",
     "Endpoint {mac} moved from {port1} to {port2}", 6),
]

FAULT_SEVERITIES = ["critical", "major", "minor", "warning", "info", "cleared"]
FAULT_LIFECYCLES = ["soaking", "soaking-clearing", "raised", "raised-clearing", "retaining"]
FAULT_REASONS = ["sfp-missing", "link-not-connected", "admin-down", "err-disabled", "link-failure"]
FAULT_USAGES = ["discovery", "infra", "fabric-member", "none"]

# =============================================================================
# EVENT CONFIGURATION
# =============================================================================

EVENT_TEMPLATES = [
    # (code, cause, severity, ind, descr_template, weight)
    ("E4208219", "link-state-change", "info", "modification",
     "Link State of Fabric Link is set to {state}", 20),
    ("E4210150", "endpoint-learning", "info", "creation",
     "Endpoint {mac} learned on node {node_id} interface {iface}", 25),
    ("E4210151", "endpoint-aging", "info", "deletion",
     "Endpoint {mac} aged out on node {node_id}", 15),
    ("E4209252", "contract-match", "info", "modification",
     "Contract rule matched on {epg}: {action} {proto} {src}->{dst}", 10),
    ("E4208028", "admin-state-change", "info", "modification",
     "Admin state of interface {iface} changed to {state}", 5),
    ("E4207462", "health-change", "warning", "modification",
     "Health score of {entity} changed from {old_score} to {new_score}", 8),
    ("E4205030", "config-change", "info", "modification",
     "Configuration of {object} was modified", 5),
    ("E4218661", "fault-raised", "warning", "creation",
     "Fault {fault_code} raised on {node}", 5),
    ("E4218662", "fault-cleared", "info", "deletion",
     "Fault {fault_code} cleared on {node}", 5),
]

# =============================================================================
# AUDIT CONFIGURATION
# =============================================================================

AUDIT_OPERATIONS = [
    # (object_type, descr_template, weight)
    ("fvTenant", "Tenant {tenant} modified", 5),
    ("fvBD", "Bridge Domain {bd} modified in tenant {tenant}", 8),
    ("fvAEPg", "EPG {epg} modified in tenant {tenant}", 10),
    ("vzBrCP", "Contract {contract} modified in tenant {tenant}", 5),
    ("fabricNode", "Fabric node {node} configuration changed", 3),
    ("infraAccPortP", "Access port profile modified", 4),
    ("fvSubnet", "Subnet {subnet} modified in BD {bd}", 3),
    ("aaaUser", "User {user} account modified", 2),
    ("aaaLogin", "Admin login from {src_ip}", 10),
    ("configSnapshot", "Configuration snapshot created", 3),
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _weighted_choice(items: list) -> Any:
    """Pick from items where last element is weight."""
    weights = [i[-1] for i in items]
    return random.choices(items, weights=weights, k=1)[0]


def _iso_ts(start_date: str, day: int, hour: int,
            minute: int = None, second: int = None) -> str:
    """Generate ISO 8601 timestamp with timezone: '2026-01-05T14:23:45.000+00:00'."""
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.000+00:00"


def _sort_ts(start_date: str, day: int, hour: int,
             minute: int = None, second: int = None) -> str:
    """Generate sortable timestamp key."""
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    return dt.strftime("%Y%m%d%H%M%S")


def _random_mac() -> str:
    """Generate random MAC (lowercase, colon-sep, Cisco format)."""
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _random_iface(node: dict) -> str:
    """Generate a random interface DN for a node."""
    if "LEAF" in node["name"]:
        port = random.randint(1, 48)
        return f"eth1/{port}"
    else:
        port = random.randint(1, 36)
        return f"eth1/{port}"


def _event_id_counter():
    """Simple auto-incrementing event ID generator."""
    base = 4294968500
    counter = [0]
    def next_id():
        counter[0] += 1
        return base + counter[0]
    return next_id

_next_event_id = _event_id_counter()
_next_fault_id = _event_id_counter()
_next_audit_id = _event_id_counter()


# =============================================================================
# FAULT GENERATOR
# =============================================================================

def _generate_fault(start_date: str, day: int, hour: int,
                    severity_override: str = None,
                    node_override: dict = None,
                    descr_override: str = None,
                    demo_id: str = "") -> Dict[str, Any]:
    """Generate a single ACI fault (faultInst) JSON object."""
    template = _weighted_choice(FAULT_TEMPLATES)
    code, severity, cause, ftype, subject, domain, descr_tmpl, _ = template

    if severity_override:
        severity = severity_override

    node = node_override or random.choice(ALL_NODES)
    iface = _random_iface(node)
    mac = _random_mac()
    reason = random.choice(FAULT_REASONS)
    usage = random.choice(FAULT_USAGES)
    pct = random.randint(75, 99)
    peer = f"10.{random.randint(10, 20)}.{random.randint(10, 20)}.{random.randint(1, 254)}"
    port1 = f"eth1/{random.randint(1, 24)}"
    port2 = f"eth1/{random.randint(25, 48)}"
    leaf = node["name"]
    contract = random.choice(["Web-to-DB", "App-to-DB", "Mgmt-Access", "Backup-Policy"])
    action = random.choice(["permit", "deny", "redirect"])
    score = random.randint(50, 90)
    entity = random.choice(ALL_EPGS)["name"]

    descr = descr_override or descr_tmpl.format(
        reason=reason, usage=usage, iface=iface, mac=mac, leaf=leaf,
        node=node["name"], pct=pct, peer=peer, port1=port1, port2=port2,
        contract=contract, action=action, score=score, entity=entity,
    )

    ts = _iso_ts(start_date, day, hour)
    lc = random.choice(FAULT_LIFECYCLES) if severity != "cleared" else "retaining"
    fault_id = _next_fault_id()

    dn = f"{node['dn']}/sys/phys-[{iface}]/phys/fault-{code}"

    fault = {
        "faultInst": {
            "attributes": {
                "dn": dn,
                "code": code,
                "severity": severity,
                "origSeverity": severity,
                "prevSeverity": severity,
                "highestSeverity": severity,
                "lc": lc,
                "cause": cause,
                "type": ftype,
                "subject": subject,
                "domain": domain,
                "descr": descr,
                "created": ts,
                "lastTransition": ts,
                "modTs": "never",
                "occur": str(random.randint(1, 5)),
                "ack": "no",
                "rule": f"{subject}-rule",
                "changeSet": "",
                "rn": f"fault-{code}",
                "status": "",
                "childAction": "",
                "uid": "",
            }
        }
    }

    fault["demo_id"] = demo_id

    sort_key = _sort_ts(start_date, day, hour)
    return sort_key, fault


def _generate_event(start_date: str, day: int, hour: int,
                    node_override: dict = None,
                    descr_override: str = None,
                    demo_id: str = "") -> Dict[str, Any]:
    """Generate a single ACI event (eventRecord) JSON object."""
    template = _weighted_choice(EVENT_TEMPLATES)
    code, cause, severity, ind, descr_tmpl, _ = template

    node = node_override or random.choice(ALL_NODES)
    iface = _random_iface(node)
    mac = _random_mac()
    state = random.choice(["ok", "down", "up", "active"])
    epg = random.choice(ALL_EPGS)
    action = random.choice(["permit", "deny"])
    proto = random.choice(["tcp", "udp", "icmp"])
    src = f"10.{random.randint(10, 30)}.{random.randint(20, 40)}.{random.randint(1, 254)}"
    dst = f"10.{random.randint(10, 30)}.{random.randint(20, 40)}.{random.randint(1, 254)}"
    old_score = random.randint(70, 100)
    new_score = random.randint(50, old_score)
    fault_code = random.choice(["F0546", "F0532", "F0454", "F0467"])
    obj = random.choice(["fvBD", "fvAEPg", "vzBrCP", "infraAccPortP"])
    entity = epg["name"]

    descr = descr_override or descr_tmpl.format(
        state=state, mac=mac, node_id=node["id"], iface=iface,
        epg=epg["name"], action=action, proto=proto, src=src, dst=dst,
        old_score=old_score, new_score=new_score, fault_code=fault_code,
        node=node["name"], object=obj, entity=entity,
    )

    ts = _iso_ts(start_date, day, hour)
    event_id = _next_event_id()

    affected = node["dn"]
    change_set = f"state:{state}"

    event = {
        "eventRecord": {
            "attributes": {
                "dn": f"subj-[{affected}]/rec-{event_id}",
                "affected": affected,
                "cause": cause,
                "changeSet": change_set,
                "code": code,
                "created": ts,
                "descr": descr,
                "id": str(event_id),
                "ind": ind,
                "severity": severity,
                "trig": "oper",
                "user": "",
                "modTs": "never",
                "rn": f"rec-{event_id}",
                "status": "",
                "childAction": "",
            }
        }
    }

    event["demo_id"] = demo_id

    sort_key = _sort_ts(start_date, day, hour)
    return sort_key, event


def _generate_audit(start_date: str, day: int, hour: int,
                    admin_override: str = None,
                    descr_override: str = None,
                    demo_id: str = "") -> Dict[str, Any]:
    """Generate a single ACI audit (aaaModLR) JSON object."""
    template = _weighted_choice(AUDIT_OPERATIONS)
    obj_type, descr_tmpl, _ = template

    admin = admin_override or random.choice(ACI_ADMINS)
    tenant = random.choice(TENANTS[:2])  # Mostly Prod and Dev
    bd = random.choice(["BD-Servers", "BD-Users", "BD-Web", "BD-Mgmt"])
    epg = random.choice(ALL_EPGS)["name"]
    contract = random.choice(["Web-to-DB", "App-to-DB", "Mgmt-Access"])
    node = random.choice(ALL_NODES)["name"]
    subnet = f"10.{random.randint(10, 30)}.{random.randint(20, 40)}.0/24"
    src_ip = random.choice(["10.10.10.20", "10.10.30.182", "10.10.30.183", "10.20.30.15"])
    user = admin

    descr = descr_override or descr_tmpl.format(
        tenant=tenant, bd=bd, epg=epg, contract=contract,
        node=node, subnet=subnet, src_ip=src_ip, user=user,
    )

    ts = _iso_ts(start_date, day, hour)
    audit_id = _next_audit_id()
    affected = f"uni/tn-{tenant}"
    tx_id = str(random.randint(576460752303423000, 576460752303424000))

    audit = {
        "aaaModLR": {
            "attributes": {
                "affected": affected,
                "cause": "transition",
                "changeSet": f"type:{obj_type}",
                "code": "E4206326",
                "created": ts,
                "descr": descr,
                "id": str(audit_id),
                "ind": "modification",
                "severity": "info",
                "trig": "config",
                "txId": tx_id,
                "user": admin,
                "modTs": "never",
                "rn": f"mod-{audit_id}",
                "status": "",
                "childAction": "",
            }
        }
    }

    audit["demo_id"] = demo_id

    sort_key = _sort_ts(start_date, day, hour)
    return sort_key, audit


# =============================================================================
# SCENARIO INTEGRATION
# =============================================================================

def _generate_exfil_faults(start_date: str, day: int, hour: int) -> List[tuple]:
    """ACI faults for exfil scenario: contract denies, endpoint anomalies Days 5-7."""
    events = []
    if 5 <= day <= 7 and hour in (10, 14, 22):
        if random.random() < 0.5:
            leaf = ACI_FABRIC["BOS"]["leafs"][0]  # LEAF-BOS-01
            events.append(_generate_fault(
                start_date, day, hour,
                severity_override="warning",
                node_override=leaf,
                descr_override="Endpoint anomaly: unexpected MAC movement detected on EPG-Servers",
                demo_id="exfil"
            ))
    return events


def _generate_exfil_events(start_date: str, day: int, hour: int) -> List[tuple]:
    """ACI events for exfil scenario: contract denies Days 5-7."""
    events = []
    if 5 <= day <= 7 and 9 <= hour <= 17:
        if random.random() < 0.3:
            node = random.choice(ACI_FABRIC["BOS"]["leafs"])
            events.append(_generate_event(
                start_date, day, hour,
                node_override=node,
                descr_override=f"Contract rule matched on EPG-Servers: deny tcp 10.10.20.40->10.10.20.30 (lateral movement)",
                demo_id="exfil"
            ))
    return events


def _generate_ddos_faults(start_date: str, day: int, hour: int) -> List[tuple]:
    """ACI faults for ddos_attack: border leaf traffic spike Days 17-18."""
    events = []
    if 17 <= day <= 18 and 10 <= hour <= 20:
        if random.random() < 0.4:
            leaf = ACI_FABRIC["BOS"]["leafs"][2]  # LEAF-BOS-03 (border)
            events.append(_generate_fault(
                start_date, day, hour,
                severity_override="major",
                node_override=leaf,
                descr_override=f"CPU utilization on {leaf['name']} exceeds threshold: {random.randint(85, 98)}%",
                demo_id="ddos_attack"
            ))
    return events


def _generate_cpu_runaway_faults(start_date: str, day: int, hour: int) -> List[tuple]:
    """ACI faults for cpu_runaway: EPG-DBServers congestion Days 10-11."""
    events = []
    if 10 <= day <= 11 and 8 <= hour <= 16:
        if random.random() < 0.3:
            leaf = ACI_FABRIC["BOS"]["leafs"][1]  # LEAF-BOS-02 (DB servers)
            events.append(_generate_fault(
                start_date, day, hour,
                severity_override="warning",
                node_override=leaf,
                descr_override="Health score for EPG-DBServers dropped below threshold: 65",
                demo_id="cpu_runaway"
            ))
    return events


# =============================================================================
# MAIN GENERATOR FUNCTION
# =============================================================================

def generate_aci_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Cisco ACI logs (fault, event, audit).

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

    fault_path = get_output_path("network", "cisco_aci/cisco_aci_fault.json")
    event_path = get_output_path("network", "cisco_aci/cisco_aci_event.json")
    audit_path = get_output_path("network", "cisco_aci/cisco_aci_audit.json")

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco ACI Generator (Fault + Event + Audit)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {fault_path.parent}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    fault_events: List[tuple] = []
    event_events: List[tuple] = []
    audit_events: List[tuple] = []
    demo_id_count = 0

    # Volume: faults ~35/hr peak, events ~150/hr peak, audit ~2/hr peak
    fault_base = int(35 * scale)
    event_base = int(150 * scale)

    for day in range(days):
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [ACI] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # Faults
            fault_count = calc_natural_events(fault_base, start_date, day, hour, "cloud")
            for _ in range(fault_count):
                fault_events.append(_generate_fault(start_date, day, hour))

            # Events
            event_count = calc_natural_events(event_base, start_date, day, hour, "cloud")
            for _ in range(event_count):
                event_events.append(_generate_event(start_date, day, hour))

            # Audit (business hours, ~2/hr)
            if 8 <= hour <= 17 and not is_weekend(day_date):
                if random.random() < 0.2 * scale:
                    audit_events.append(_generate_audit(start_date, day, hour))

            # Scenario events
            if "exfil" in active_scenarios and is_scenario_active_day("exfil", day):
                exfil_f = _generate_exfil_faults(start_date, day, hour)
                fault_events.extend(exfil_f)
                demo_id_count += len(exfil_f)
                exfil_e = _generate_exfil_events(start_date, day, hour)
                event_events.extend(exfil_e)
                demo_id_count += len(exfil_e)

            if "ddos_attack" in active_scenarios and is_scenario_active_day("ddos_attack", day):
                ddos_f = _generate_ddos_faults(start_date, day, hour)
                fault_events.extend(ddos_f)
                demo_id_count += len(ddos_f)

            if "cpu_runaway" in active_scenarios and is_scenario_active_day("cpu_runaway", day):
                cpu_f = _generate_cpu_runaway_faults(start_date, day, hour)
                fault_events.extend(cpu_f)
                demo_id_count += len(cpu_f)

    # Sort by timestamp key
    fault_events.sort(key=lambda x: x[0])
    event_events.sort(key=lambda x: x[0])
    audit_events.sort(key=lambda x: x[0])

    # Write files
    def _write_json(path: Path, events: List[tuple]):
        with open(path, "w") as f:
            for _, ev in events:
                f.write(json.dumps(ev) + "\n")

    _write_json(fault_path, fault_events)
    _write_json(event_path, event_events)
    _write_json(audit_path, audit_events)

    total = len(fault_events) + len(event_events) + len(audit_events)

    if not quiet:
        print(f"  [ACI] Complete! {total:,} total events written", file=sys.stderr)
        print(f"          Faults: {len(fault_events):,} events -> {fault_path.name}", file=sys.stderr)
        print(f"          Events: {len(event_events):,} events -> {event_path.name}", file=sys.stderr)
        print(f"          Audit:  {len(audit_events):,} events -> {audit_path.name}", file=sys.stderr)
        if demo_id_count:
            print(f"          demo_id events: {demo_id_count:,}", file=sys.stderr)

    return total


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generate Cisco ACI logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", help="Output path override")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_aci_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
