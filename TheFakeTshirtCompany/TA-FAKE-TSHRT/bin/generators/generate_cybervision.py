#!/usr/bin/env python3
"""
Cisco Cyber Vision generator — synthetic OT/ICS telemetry for the Detroit
Printing & Fulfillment Plant (DET location).

Produces 8 sourcetypes matching the Cisco Cyber Vision REST API schema,
as ingested by Splunk TA-cisco_cybervision (which passes raw JSON through):

  1. cisco:cybervision:devices         - Asset inventory snapshots (PLC, HMI, switch, ...)
  2. cisco:cybervision:components      - Sub-components (modules, IO cards)
  3. cisco:cybervision:events          - Security/operational events
  4. cisco:cybervision:flows           - OT network flows (Modbus, S7, CIP, OPC UA, ...)
  5. cisco:cybervision:activities      - Control system activities / protocol usage
  6. cisco:cybervision:vulnerabilities - CVE catalog (static)
  7. cisco:cybervision:sensors         - CV sensor status heartbeats
  8. cisco:cybervision:syslog          - CEF syslog (security alerts)

The Detroit plant models a small IEC 62443 segmented OT environment:
  Zone-1: Printing line (PLCs, HMIs, robotic arms, drives)
  Zone-2: Packaging & utilities (PLCs, VFDs)
  OT-Mgmt: Engineering workstations, Historian, SCADA, CV sensors

Baseline only — no scenario injection yet.
"""

import argparse
import hashlib
import json
import random
import sys
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import (
    ts_iso,
    ts_iso_ms,
    ts_syslog,
    date_add,
    calc_natural_events,
    get_daily_noise,
    is_weekend,
)
from scenarios.registry import expand_scenarios, is_scenario_active_day

# =============================================================================
# CV CENTER (SIMULATED APPLIANCE)
# =============================================================================

CV_CENTER_HOST = "cv-center-det-01.faketshirtcompany.com"
CV_CENTER_VERSION = "5.1.2"
CV_CENTER_VENDOR = "Cisco"
CV_CENTER_PRODUCT = "Cyber Vision"

# Deterministic UUID namespace for this plant
_CV_NS = uuid.UUID("c4b00001-0000-0000-0000-000000000000")


def _uuid(tag: str) -> str:
    return str(uuid.uuid5(_CV_NS, tag))


def _mac(tag: str) -> str:
    h = hashlib.sha256(tag.encode()).hexdigest()
    # Use realistic OT OUIs (Siemens 00:1B:1B, Rockwell 00:00:BC, Schneider 00:00:54)
    oui_list = ["00:1B:1B", "00:00:BC", "00:00:54", "00:80:F4", "00:A0:91", "00:0E:8C"]
    oui = oui_list[int(h[0:2], 16) % len(oui_list)]
    return f"{oui}:{h[2:4]}:{h[4:6]}:{h[6:8]}".upper()


# =============================================================================
# OT ASSET INVENTORY — DETROIT PLANT
# =============================================================================
#
# Each entry: (label, ip, device_type, vendor, model, fw_version, zone_label,
#              purdue_level, criticalness, risk_score, vuln_cve_ids)
#
# Zones: "Zone-1-Printing", "Zone-2-Packaging", "OT-Mgmt"
# Purdue levels: 0=process, 1=control, 2=supervisory, 3=operations
# Criticalness: 0=informational, 1=low, 2=medium, 3=high, 4=critical
# Risk score: 0-100

OT_INVENTORY = [
    # ------------------------------------------------------------------
    # Zone-1 Printing Line — PLCs, HMIs, drives, robotic arms
    # ------------------------------------------------------------------
    ("PLC-PRINT-01",   "10.40.100.10", "PLC",                "Siemens",    "S7-1500 CPU 1516-3 PN/DP", "V2.9.2",  "Zone-1-Printing",  1, 4, 82, ["CVE-2023-38380", "CVE-2022-38465"]),
    ("PLC-PRINT-02",   "10.40.100.11", "PLC",                "Siemens",    "S7-1200 CPU 1215C",        "V4.5.1",  "Zone-1-Printing",  1, 3, 48, ["CVE-2022-38465"]),
    ("PLC-CUTTER-01",  "10.40.100.12", "PLC",                "Rockwell",   "ControlLogix 1756-L83E",   "33.013",  "Zone-1-Printing",  1, 4, 88, ["CVE-2023-3595",  "CVE-2022-1161"]),
    ("HMI-PRINT-01",   "10.40.100.20", "HMI",                "Siemens",    "SIMATIC HMI TP1200 Comfort","V16.0",  "Zone-1-Printing",  2, 3, 41, ["CVE-2022-43393"]),
    ("HMI-CUTTER-01",  "10.40.100.21", "HMI",                "Rockwell",   "PanelView Plus 7 1500",    "11.00",   "Zone-1-Printing",  2, 2, 33, []),
    ("ROBOT-ARM-01",   "10.40.100.30", "Robot Controller",   "ABB",        "IRC5 M2004",               "5.15.04", "Zone-1-Printing",  1, 3, 55, ["CVE-2022-40299"]),
    ("ROBOT-ARM-02",   "10.40.100.31", "Robot Controller",   "ABB",        "IRC5 M2004",               "5.15.04", "Zone-1-Printing",  1, 3, 55, ["CVE-2022-40299"]),
    ("DRIVE-PRINT-01", "10.40.100.40", "Variable Frequency Drive", "ABB",  "ACS880-01",                "2.85",    "Zone-1-Printing",  0, 2, 28, []),
    ("DRIVE-CUTTER-01","10.40.100.41", "Variable Frequency Drive", "Siemens","SINAMICS G120",          "4.7.15",  "Zone-1-Printing",  0, 2, 30, []),
    ("IO-PRINT-01",    "10.40.100.50", "IO Module",          "Siemens",    "ET 200SP",                 "V4.2",    "Zone-1-Printing",  0, 1, 15, []),

    # ------------------------------------------------------------------
    # Zone-2 Packaging & Utilities
    # ------------------------------------------------------------------
    ("PLC-PACK-01",    "10.40.101.10", "PLC",                "Schneider",  "Modicon M580 BMEP584040",  "SV3.20",  "Zone-2-Packaging", 1, 3, 52, ["CVE-2023-6408"]),
    ("HMI-PACK-01",    "10.40.101.20", "HMI",                "Schneider",  "Harmony GTU HMIDT952",     "1.5.11",  "Zone-2-Packaging", 2, 2, 36, []),
    ("PLC-UTIL-01",    "10.40.101.11", "PLC",                "Siemens",    "S7-1200 CPU 1214C",        "V4.5.1",  "Zone-2-Packaging", 1, 2, 39, ["CVE-2022-38465"]),
    ("DRIVE-CONV-01",  "10.40.101.40", "Variable Frequency Drive", "Schneider","Altivar ATV930",       "1.8IE30", "Zone-2-Packaging", 0, 1, 22, []),

    # ------------------------------------------------------------------
    # OT Management Segment — Engineering WS, Historian, SCADA, CV Sensors
    # ------------------------------------------------------------------
    ("ENG-WS-01",      "10.40.20.50",  "Engineering Station","Microsoft",  "Windows 10 IoT LTSC",      "21H2",    "OT-Mgmt",          3, 3, 58, ["CVE-2023-36884"]),
    ("ENG-WS-02",      "10.40.20.51",  "Engineering Station","Microsoft",  "Windows 10 IoT LTSC",      "21H2",    "OT-Mgmt",          3, 3, 58, ["CVE-2023-36884"]),
    ("HIST-DET-01",    "10.40.20.30",  "Historian",          "AVEVA",      "Historian 2020 R2",        "2020R2",  "OT-Mgmt",          3, 3, 44, []),
    ("SCADA-DET-01",   "10.40.20.31",  "SCADA Server",       "AVEVA",      "InTouch OMI 2020 R2",      "2020R2",  "OT-Mgmt",          3, 4, 49, []),
    ("IE3400-DET-01",  "10.40.102.10", "Industrial Switch",  "Cisco",      "Catalyst IE3400-8T2S",     "17.9.4",  "OT-Mgmt",          2, 2, 18, []),
    ("IE3400-DET-02",  "10.40.102.11", "Industrial Switch",  "Cisco",      "Catalyst IE3400-8T2S",     "17.9.4",  "OT-Mgmt",          2, 2, 18, []),
    ("IE3400-DET-03",  "10.40.102.12", "Industrial Switch",  "Cisco",      "Catalyst IE3400-8T2S",     "17.9.4",  "OT-Mgmt",          2, 2, 18, []),
]

# Cyber Vision sensors (run embedded in IE3400 or on IC3000)
CV_SENSORS = [
    {
        "id": _uuid("sensor-det-01"),
        "name": "CV-SENSOR-DET-01",
        "model": "IE3400-8T2S",          # Sensor embedded in switch
        "serial_number": "FCW2540A1B2",
        "ip": "10.40.102.10",
        "status": "CONNECTED",
        "latitude": 42.3314,
        "longitude": -83.0458,
    },
    {
        "id": _uuid("sensor-det-02"),
        "name": "CV-SENSOR-DET-02",
        "model": "IC3000-2C2F-K9",       # Standalone compute sensor
        "serial_number": "FCW2540C3D4",
        "ip": "10.40.102.20",
        "status": "CONNECTED",
        "latitude": 42.3314,
        "longitude": -83.0458,
    },
    {
        # Spare sensor used for staging — not actively enrolled.
        # Populates the "Inactive Sensors" dashboard panel.
        "id": _uuid("sensor-det-03-spare"),
        "name": "CV-SENSOR-DET-03",
        "model": "IC3000-2C2F-K9",
        "serial_number": "FCW2540E5F6",
        "ip": "10.40.102.21",
        "status": "DISCONNECTED",
        "latitude": 42.3314,
        "longitude": -83.0458,
    },
]

# =============================================================================
# CVE CATALOG (used by vulnerabilities sourcetype and nested in devices)
# =============================================================================

CVE_CATALOG = {
    "CVE-2023-38380": {
        "cvss": 7.5,
        "title": "Siemens SIMATIC S7-1500 Denial of Service",
        "summary": "A vulnerability in SIMATIC S7-1500 CPU firmware allows a remote attacker to cause a denial-of-service condition by sending specially crafted packets.",
        "solution": "Update firmware to V2.9.4 or later.",
    },
    "CVE-2022-38465": {
        "cvss": 9.3,
        "title": "Siemens SIMATIC hardcoded cryptographic key",
        "summary": "The affected products use a hardcoded cryptographic key which could allow an attacker to decrypt protected configuration data.",
        "solution": "Update firmware and rotate project passwords. Refer to Siemens SSA-568427.",
    },
    "CVE-2023-3595": {
        "cvss": 9.8,
        "title": "Rockwell ControlLogix remote code execution",
        "summary": "A vulnerability in the 1756-EN2T/EN2F/EN2TR/EN3TR/EN2TXT communication modules allows remote code execution through crafted CIP messages.",
        "solution": "Apply firmware update per Rockwell advisory SD1677.",
    },
    "CVE-2022-1161": {
        "cvss": 7.7,
        "title": "Rockwell Logix textual program modification",
        "summary": "An attacker with network access could modify user-readable program code without detection by exploiting trust in the engineering workstation.",
        "solution": "Enable controller change detection and restrict engineering workstation access.",
    },
    "CVE-2022-43393": {
        "cvss": 7.3,
        "title": "Siemens SIMATIC HMI Comfort Panels path traversal",
        "summary": "A path traversal vulnerability in the Comfort Panel web server allows unauthenticated file read.",
        "solution": "Update HMI firmware to V16.0.0.1 or later.",
    },
    "CVE-2022-40299": {
        "cvss": 6.5,
        "title": "ABB IRC5 robot controller information disclosure",
        "summary": "Improper access control in the RobotWare web interface allows retrieval of sensitive controller information without authentication.",
        "solution": "Upgrade RobotWare and restrict network access to the controller.",
    },
    "CVE-2023-6408": {
        "cvss": 8.2,
        "title": "Schneider Modicon M580 session hijacking",
        "summary": "Weak session handling in the M580 CPU web interface allows session hijacking on the OT network.",
        "solution": "Update firmware to SV3.30 or later, enable HTTPS only.",
    },
    "CVE-2023-36884": {
        "cvss": 8.8,
        "title": "Microsoft Windows Office and HTML RCE",
        "summary": "A remote code execution vulnerability exists when an attacker convinces a user to open a crafted Microsoft Office document.",
        "solution": "Apply Microsoft security updates.",
    },
}

# =============================================================================
# OT PROTOCOLS & TAGS
# =============================================================================

# (protocol_name, typical_dst_port, weight)
OT_PROTOCOLS = [
    ("Modbus TCP",    502,  30),
    ("S7Plus",        102,  25),
    ("EtherNet/IP",   44818, 20),
    ("OPC UA",        4840, 10),
    ("Profinet",      34962, 8),
    ("HTTPS",         443,  4),
    ("SSH",           22,   2),
    ("RDP",           3389, 1),
]

ACTIVITY_CATEGORIES = [
    # (category_label, tag_label, weight)
    # Note: "Protocol" category is reserved for the protocol tag that each
    # activity carries as a SECOND tag (Modbus TCP, S7Plus, ...). Action
    # categories use "Control System Behavior" to stay out of that namespace.
    ("Control System Behavior", "Read Var",          30),
    ("Control System Behavior", "Write Var",         15),
    ("Control System Behavior", "Start CPU",          2),
    ("Control System Behavior", "Stop CPU",           1),
    ("Control System Behavior", "Program Download",   2),
    ("Control System Behavior", "Program Upload",     3),
    ("Control System Behavior", "Firmware Upload",    1),
    ("Control System Behavior", "Config Change",      3),
    ("IT Behavior",             "HTTP Request",       5),
    ("IT Behavior",             "SSH Session",        2),
    ("IT Behavior",             "RDP Session",        1),
]

# Detroit plant operators CV attributes for operator-initiated events
# (matches real CV behavior — events for program upload/download, mode change,
#  policy change include "by First Last (email)" attribution from SMB/AD context)
CV_OPERATORS = [
    ("Ryan",  "Campbell", "ryan.campbell@faketshirtcompany.com"),
    ("Ethan", "Rivera",   "ethan.rivera@faketshirtcompany.com"),
    ("Jason", "Reed",     "jason.reed@faketshirtcompany.com"),
    ("David", "Miller",   "david.miller@faketshirtcompany.com"),
]

def _operator_suffix() -> str:
    first, last, email = random.choice(CV_OPERATORS)
    return f" by {first} {last} ({email})"

# Operational & security event templates (for cisco:cybervision:events)
# (type, family, category, severity, message_template, has_operator)
# has_operator=True: the TA's EXTRACT-user regex will pick up "by First Last ("
# pattern from the message body and populate the user/first_name/last_name fields.
EVENT_TEMPLATES = [
    # Operational (family=Operational, severity 0-1)
    ("new_device",       "Operational", "Inventory",       0, "New device '{label}' detected on interface {iface}", False),
    ("variable_access",  "Operational", "Behavior",        0, "Variable access from {src_label} ({src}:{sport}) -> {dst_label} ({dst}:{dport})", False),
    ("program_upload",   "Operational", "Control",         1, "Program upload from {src_label} ({src}:{sport}) -> {dst_label} ({dst}:{dport}){user_suffix}", True),
    ("controller_mode",  "Operational", "Control",         1, "Controller mode change detected on {dst_label} ({dst}){user_suffix}", True),
    ("firmware_mismatch","Operational", "Configuration",   1, "Firmware version mismatch reported on {dst_label} ({dst})", False),
    # Security (family=Security, severity 1-3)
    ("unauthorized_device","Security","Intrusion",         2, "Unauthorized device '{src_label}' ({src}) detected on {zone}", False),
    ("policy_violation",  "Security","Policy Violation",   2, "Policy violation: unexpected protocol {proto} from {src_label} ({src}:{sport}) -> {dst_label} ({dst}:{dport})", False),
    ("suspicious_scan",   "Security","Intrusion",          2, "Suspicious port scan activity from {src}:{sport} -> {dst}:{dport}", False),
    ("cleartext_cred",    "Security","Weak Credentials",   1, "Cleartext credential observed on {proto} session {src}:{sport} -> {dst}:{dport}{user_suffix}", True),
    ("ids_alert",         "Security","Intrusion Detection",3, "Snort IDS rule match: Modbus unauthorized function code from {src}:{sport} -> {dst}:{dport}", False),
]

# =============================================================================
# HELPERS
# =============================================================================

def _epoch_ms(base_date: str, day: int, hour: int, minute: int, second: int) -> int:
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second, microsecond=0)
    return int(dt.timestamp() * 1000)


def _criticalness_label(n: int) -> str:
    return {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}[n]


def _zone_to_group(zone: str) -> Tuple[str, str, int]:
    """Return (group_id, group_label, criticalness) for a zone."""
    mapping = {
        "Zone-1-Printing":  ("grp-det-zone1", "Printing Line - Zone 1", 3),
        "Zone-2-Packaging": ("grp-det-zone2", "Packaging & Utilities - Zone 2", 2),
        "OT-Mgmt":          ("grp-det-mgmt",  "OT Management", 2),
    }
    return mapping.get(zone, ("grp-det-other", zone, 1))


def _device_tags(device_type: str, zone: str, vendor: str, model: str, fw: str) -> List[dict]:
    """Tags mirror Cybervision's human-readable 'OT Tags' feature."""
    tags = []
    # Device-type tag
    tags.append({
        "id": _uuid(f"tag-type-{device_type}"),
        "label": device_type.replace(" ", "-").lower(),
        "category": {"id": _uuid("cat-device"), "label": f"Device - {device_type}"},
    })
    # Zone tag
    tags.append({
        "id": _uuid(f"tag-zone-{zone}"),
        "label": zone.lower(),
        "category": {"id": _uuid("cat-zone"), "label": "Zone"},
    })
    # Vendor metadata (extracted by props.conf EXTRACT-asset_vendor)
    tags.append({
        "id": _uuid(f"tag-vendor-{vendor}"),
        "key": "vendor-name",
        "value": vendor,
        "label": vendor.lower(),
        "category": {"id": _uuid("cat-vendor"), "label": "Vendor"},
    })
    tags.append({
        "id": _uuid(f"tag-model-{model}"),
        "key": "model-ref",
        "value": model,
        "label": model.lower().replace(" ", "-"),
        "category": {"id": _uuid("cat-model"), "label": "Model"},
    })
    tags.append({
        "id": _uuid(f"tag-fw-{fw}"),
        "key": "fw-version",
        "value": fw,
        "label": fw.lower(),
        "category": {"id": _uuid("cat-firmware"), "label": "Firmware"},
    })
    return tags


def _build_device_event(entry: tuple, last_activity_ms: int, first_activity_ms: int) -> dict:
    (label, ip, dtype, vendor, model, fw, zone, purdue, crit, risk, cves) = entry
    group_id, group_label, _ = _zone_to_group(zone)
    vulns = []
    for cve in cves:
        info = CVE_CATALOG.get(cve, {})
        vulns.append({
            "id": _uuid(f"vuln-{label}-{cve}"),
            "cve": cve,
            "CVSS": info.get("cvss", 5.0),
            "cvss": info.get("cvss", 5.0),
            "title": info.get("title", cve),
            "summary": info.get("summary", ""),
            "solution": info.get("solution", ""),
            "links": [{"id": _uuid(f"link-{cve}"), "link": f"https://nvd.nist.gov/vuln/detail/{cve}"}],
        })

    # Simulate weak / default credentials on a realistic subset:
    # ~40% of PLCs/HMIs have default creds (common posture finding),
    # plus the SCADA/Historian pair usually has at least one reused password.
    # Deterministic per-device via label hash so results are reproducible.
    _label_hash = int(hashlib.sha256(label.encode()).hexdigest()[:4], 16)
    if dtype in ("PLC", "HMI", "Robot Controller"):
        cred_count = 2 if (_label_hash % 10) < 4 else 0
    elif dtype in ("SCADA Server", "Historian"):
        cred_count = 1 if (_label_hash % 10) < 6 else 0
    else:
        cred_count = 0

    # Build dns/nt_host hostnames for Windows-based OT assets.
    # Real CV resolves these from SMB/NetBIOS/DNS passive observation.
    if dtype in ("Engineering Station", "Historian", "SCADA Server"):
        dns_list = [f"{label.lower()}.faketshirtcompany.com"]
        nt_host_list = [label]
    else:
        dns_list = []
        nt_host_list = []

    return {
        "id": _uuid(f"device-{label}"),
        "label": label,
        "ip": [ip],
        "mac": [_mac(label)],
        "dns": dns_list,
        "nt_host": nt_host_list,
        "deviceType": dtype,
        "customLabel": f"Detroit plant / {zone}",
        "creationTime": first_activity_ms,
        "firstActivity": first_activity_ms,
        "lastActivity": last_activity_ms,
        "riskScore": risk,
        "credentialsCount": cred_count,
        "externalCommunicationsCount": random.randint(0, 3),
        "vulnerabilitiesCount": len(cves),
        "purdueLevel": purdue,
        "group": {"id": group_id, "label": group_label, "criticalness": crit},
        "tags": _device_tags(dtype, zone, vendor, model, fw),
        "components": [],
        "vulnerabilities": vulns,
    }


def _build_component_event(device_entry: tuple, comp_idx: int, last_activity_ms: int) -> dict:
    (label, ip, dtype, vendor, model, fw, zone, purdue, crit, risk, cves) = device_entry
    group_id, group_label, _ = _zone_to_group(zone)
    comp_label = f"{label}-MOD{comp_idx:02d}"
    # Components inherit an IP in the same subnet
    last_octet = int(ip.rsplit(".", 1)[1]) + 100 + comp_idx
    comp_ip = f"{ip.rsplit('.', 1)[0]}.{last_octet}"
    return {
        "id": _uuid(f"component-{comp_label}"),
        "label": comp_label,
        "ip": comp_ip,
        "mac": _mac(comp_label),
        "deviceType": "Module",
        "parentDevice": label,
        "firstActivity": last_activity_ms - 86400 * 1000 * 30,
        "lastActivity": last_activity_ms,
        "customLabel": f"Submodule of {label}",
        "group": {"id": group_id, "label": group_label, "criticalness": crit},
        "tags": [
            {"id": _uuid(f"ct-{comp_label}"), "label": "module",
             "category": {"id": _uuid("cat-module"), "label": "Device - Module"}},
            {"id": _uuid(f"cv-{vendor}"), "key": "vendor-name", "value": vendor,
             "label": vendor.lower(),
             "category": {"id": _uuid("cat-vendor"), "label": "Vendor"}},
        ],
    }


def _pick_flow_pair() -> Tuple[tuple, tuple]:
    """Pick a realistic (src, dst) OT flow pair."""
    # 80% weighted: HMI <-> PLC, Engineering WS <-> PLC, Historian <-> PLC
    roles = {
        "HMI":                 [e for e in OT_INVENTORY if e[2] == "HMI"],
        "PLC":                 [e for e in OT_INVENTORY if e[2] == "PLC"],
        "Engineering Station": [e for e in OT_INVENTORY if e[2] == "Engineering Station"],
        "Historian":           [e for e in OT_INVENTORY if e[2] == "Historian"],
        "SCADA Server":        [e for e in OT_INVENTORY if e[2] == "SCADA Server"],
        "Robot Controller":    [e for e in OT_INVENTORY if e[2] == "Robot Controller"],
        "VFD":                 [e for e in OT_INVENTORY if e[2] == "Variable Frequency Drive"],
    }
    patterns = [
        ("HMI", "PLC", 40),
        ("Historian", "PLC", 20),
        ("SCADA Server", "PLC", 15),
        ("Engineering Station", "PLC", 10),
        ("PLC", "VFD", 8),
        ("PLC", "Robot Controller", 5),
        ("Engineering Station", "HMI", 2),
    ]
    total = sum(w for *_, w in patterns)
    r = random.randint(1, total)
    cum = 0
    src_role = dst_role = None
    for s, d, w in patterns:
        cum += w
        if r <= cum:
            src_role, dst_role = s, d
            break
    src_list = roles.get(src_role, [])
    dst_list = roles.get(dst_role, [])
    if not src_list or not dst_list:
        src_list = dst_list = OT_INVENTORY
    return random.choice(src_list), random.choice(dst_list)


def _pick_protocol() -> Tuple[str, int]:
    total = sum(w for _, _, w in OT_PROTOCOLS)
    r = random.randint(1, total)
    cum = 0
    for name, port, w in OT_PROTOCOLS:
        cum += w
        if r <= cum:
            return name, port
    return OT_PROTOCOLS[0][0], OT_PROTOCOLS[0][1]


def _pick_activity() -> Tuple[str, str]:
    total = sum(w for _, _, w in ACTIVITY_CATEGORIES)
    r = random.randint(1, total)
    cum = 0
    for cat, label, w in ACTIVITY_CATEGORIES:
        cum += w
        if r <= cum:
            return cat, label
    return ACTIVITY_CATEGORIES[0][0], ACTIVITY_CATEGORIES[0][1]


def _pick_event_template() -> tuple:
    # Weight: mostly operational, occasional security
    if random.random() < 0.15:
        return random.choice([t for t in EVENT_TEMPLATES if t[1] == "Security"])
    return random.choice([t for t in EVENT_TEMPLATES if t[1] == "Operational"])


# =============================================================================
# SCENARIO: Rogue Contractor Laptop (OT)
# =============================================================================
#
# Story (Day 8, 14:00-16:30):
#   An external contractor arrives at the Detroit plant for PLC maintenance
#   and plugs an unauthorized laptop directly into Zone-1 production, violating
#   policy. CV detects the new device, observes aggressive scanning, sees a
#   program upload/download attempt targeting PLC-PRINT-01 (blocked by policy),
#   and alerts via CEF syslog.
#
# All injected events carry demo_id="ot_rogue_device" for easy filtering.

ROGUE_LAPTOP = {
    "label":    "CONTRACTOR-LAPTOP-01",
    "ip":       "10.40.100.200",
    "mac":      "5C:F9:38:8B:4A:22",
    "vendor":   "Dell",
    "model":    "Latitude 5540",
    "zone":     "Zone-1-Printing",
    "purdue":   3,
    "device_type": "Engineering Laptop",
}

# Target PLC the contractor is messing with
ROGUE_TARGET = "PLC-PRINT-01"


def _inject_rogue_device_scenario(
    start_date: str,
    day: int,
    devices_list: list, components_list: list, events_list: list,
    flows_list: list, activities_list: list, syslog_list: list,
    first_activity_ms: int,
) -> int:
    """Inject the rogue contractor laptop scenario into the event streams.

    Mutates the passed lists in-place. Returns total count of injected events.
    """
    injected = 0
    dm = "ot_rogue_device"

    # Lookup the target PLC entry
    target_entry = next((e for e in OT_INVENTORY if e[0] == ROGUE_TARGET), OT_INVENTORY[0])
    target_label, target_ip = target_entry[0], target_entry[1]
    target_zone = target_entry[6]

    # Build a synthetic "device record" for the rogue laptop (detection snapshot)
    rogue_last_ms = _epoch_ms(start_date, day, 14, 0, 5)
    rogue_device = {
        "id": _uuid(f"device-{ROGUE_LAPTOP['label']}"),
        "label": ROGUE_LAPTOP["label"],
        "ip":  [ROGUE_LAPTOP["ip"]],
        "mac": [ROGUE_LAPTOP["mac"]],
        "deviceType": ROGUE_LAPTOP["device_type"],
        "customLabel": "UNAUTHORIZED - contractor laptop - POLICY VIOLATION",
        "creationTime":  rogue_last_ms,
        "firstActivity": rogue_last_ms,
        "lastActivity":  _epoch_ms(start_date, day, 16, 30, 0),
        "riskScore": 95,
        "credentialsCount": 0,
        "externalCommunicationsCount": 0,
        "vulnerabilitiesCount": 0,
        "purdueLevel": ROGUE_LAPTOP["purdue"],
        "group": {"id": "grp-det-unknown", "label": "Unknown / Unauthorized", "criticalness": 4},
        "tags": [
            {"id": _uuid("tag-rogue-type"), "label": "engineering-laptop",
             "category": {"id": _uuid("cat-device"), "label": "Device - Engineering Laptop"}},
            {"id": _uuid("tag-rogue-zone"), "label": ROGUE_LAPTOP["zone"].lower(),
             "category": {"id": _uuid("cat-zone"), "label": "Zone"}},
            {"id": _uuid("tag-rogue-vendor"), "key": "vendor-name", "value": ROGUE_LAPTOP["vendor"],
             "label": "dell",
             "category": {"id": _uuid("cat-vendor"), "label": "Vendor"}},
            {"id": _uuid("tag-rogue-model"), "key": "model-ref", "value": ROGUE_LAPTOP["model"],
             "label": "latitude-5540",
             "category": {"id": _uuid("cat-model"), "label": "Model"}},
            {"id": _uuid("tag-rogue-unauth"), "label": "unauthorized",
             "category": {"id": _uuid("cat-policy"), "label": "Policy"}},
        ],
        "components": [],
        "vulnerabilities": [],
        "demo_id": dm,
    }
    devices_list.append(rogue_device)
    injected += 1

    rogue_left  = {"id": rogue_device["id"], "label": ROGUE_LAPTOP["label"], "ip": ROGUE_LAPTOP["ip"]}
    target_right = {"id": _uuid(f"device-{target_label}"), "label": target_label, "ip": target_ip}

    def _add_event(hour, minute, second, etype, family, category, severity, message):
        nonlocal injected
        ts_iso_str = ts_iso(start_date, day, hour, minute, second)
        ts_ms = _epoch_ms(start_date, day, hour, minute, second)
        events_list.append({
            "id": _uuid(f"scen-event-{day}-{hour}-{minute}-{second}-{etype}"),
            "type": etype, "family": family, "category": category,
            "severity": severity, "message": message,
            "creation_time": ts_iso_str,
            "signature": f'signature "{category} - {etype}"',
            "src":        ROGUE_LAPTOP["ip"],
            "dest":       target_ip,
            "src_label":  ROGUE_LAPTOP["label"],
            "dest_label": target_label,
            "proto":      "Modbus TCP",
            "short_message": f"{etype}: {ROGUE_LAPTOP['label']} -> {target_label}",
            "demo_id": dm,
        })
        # CEF syslog twin for security events
        if family == "Security":
            syslog_ts = ts_syslog(start_date, day, hour, minute, second)
            cat_tok = category.replace(" ", "_")
            cef = (
                f"{syslog_ts} {CV_CENTER_HOST} "
                f"CEF:0|{CV_CENTER_VENDOR}|{CV_CENTER_PRODUCT}|{CV_CENTER_VERSION}|"
                f"{1500 + abs(hash(etype)) % 50}|{category}|{severity}|"
                f"msg={message} severity_id={severity} "
                f"src={ROGUE_LAPTOP['ip']} dst={target_ip} proto=Modbus_TCP "
                f"cmp_a={ROGUE_LAPTOP['label']} cmp_b={target_label} SCVVulnsNumber=0 "
                f"cat={cat_tok} demo_id={dm}"
            )
            syslog_list.append((ts_ms, cef))
        injected += 1

    def _add_flow(hour, minute, second, dst_entry, proto, dport, bytes_count, pkts):
        nonlocal injected
        ts_ms = _epoch_ms(start_date, day, hour, minute, second)
        flows_list.append({
            "id": _uuid(f"scen-flow-{day}-{hour}-{minute}-{second}-{dst_entry[0]}-{random.random()}"),
            "srcPort":   random.randint(49152, 65535),
            "dstPort":   dport,
            "bytesCount": bytes_count,
            "packetsCount": pkts,
            "protocol":  proto,
            "firstSeen": ts_ms - random.randint(1000, 60000),
            "lastActivity": ts_ms,
            "left":  rogue_left,
            "right": {"id": _uuid(f"device-{dst_entry[0]}"), "label": dst_entry[0], "ip": dst_entry[1]},
            "tag":   {"id": _uuid(f"tag-proto-{proto}"), "label": proto},
            "demo_id": dm,
        })
        injected += 1

    def _add_activity(hour, minute, second, dst_entry, cat, label):
        nonlocal injected
        ts_ms = _epoch_ms(start_date, day, hour, minute, second)
        activities_list.append({
            "id": _uuid(f"scen-act-{day}-{hour}-{minute}-{second}-{label}-{random.random()}"),
            "lastActivity": ts_ms,
            "left":  rogue_left,
            "right": {"id": _uuid(f"device-{dst_entry[0]}"), "label": dst_entry[0], "ip": dst_entry[1]},
            "tags": [{
                "id": _uuid(f"scen-tag-{label}"), "label": label,
                "category": {"id": _uuid(f"cat-act-{cat}"), "label": cat},
            }],
            "demo_id": dm,
        })
        injected += 1

    # ---------------- Phase 1: 14:00 — device detection ----------------
    _add_event(14, 0, 5,  "new_device",          "Operational", "Inventory", 0,
               f"New device '{ROGUE_LAPTOP['label']}' ({ROGUE_LAPTOP['ip']}) detected on interface GigabitEthernet1/0/7 in {target_zone}")
    _add_event(14, 0, 12, "unauthorized_device", "Security",    "Intrusion", 2,
               f"Unauthorized device '{ROGUE_LAPTOP['label']}' ({ROGUE_LAPTOP['ip']}) detected on {target_zone}")

    # ---------------- Phase 2: 14:05-14:20 — network scanning ----------------
    # Scan all PLCs in Zone-1 on Modbus/S7/CIP ports
    plcs = [e for e in OT_INVENTORY if e[2] == "PLC" and e[6].startswith("Zone-")]
    for scan_min in range(5, 21):
        for plc in plcs:
            for proto, dport in [("Modbus TCP", 502), ("S7Plus", 102), ("EtherNet/IP", 44818)]:
                _add_flow(14, scan_min, random.randint(0, 59), plc, proto, dport,
                          random.randint(60, 400), random.randint(1, 4))
    _add_event(14, 5, 0, "suspicious_scan", "Security", "Intrusion", 2,
               f"Suspicious port scan activity from {ROGUE_LAPTOP['ip']} targeting multiple PLCs in {target_zone}")
    _add_event(14, 18, 0, "suspicious_scan", "Security", "Intrusion", 2,
               f"Repeated port scan activity from {ROGUE_LAPTOP['ip']} - {len(plcs)} PLCs probed on Modbus/S7/CIP")

    # ---------------- Phase 3: 14:25 — variable access on target PLC ----------------
    for i in range(12):
        _add_activity(14, 25 + i // 4, random.randint(0, 59), target_entry, "Protocol", "Read Var")
        _add_flow(14, 25 + i // 4, random.randint(0, 59), target_entry, "Modbus TCP", 502,
                  random.randint(500, 2000), random.randint(5, 20))
    _add_event(14, 25, 30, "variable_access", "Operational", "Behavior", 1,
               f"Variable access from {ROGUE_LAPTOP['label']} ({ROGUE_LAPTOP['ip']}) to {target_label} ({target_ip})")

    # ---------------- Phase 4: 14:40 — program upload attempt ----------------
    _add_activity(14, 40, 12, target_entry, "Protocol", "Program Upload")
    _add_flow(14, 40, 12, target_entry, "S7Plus", 102, 52400, 85)
    _add_event(14, 40, 15, "program_upload", "Operational", "Control", 2,
               f"Program upload from {ROGUE_LAPTOP['label']} ({ROGUE_LAPTOP['ip']}) to {target_label} ({target_ip}:102)")

    # ---------------- Phase 5: 15:10 — program download BLOCKED ----------------
    _add_activity(15, 10, 0, target_entry, "Protocol", "Program Download")
    _add_event(15, 10, 5, "policy_violation", "Security", "Policy Violation", 3,
               f"BLOCKED: Policy violation - unauthorized program download from {ROGUE_LAPTOP['label']} ({ROGUE_LAPTOP['ip']}) -> {target_label} ({target_ip}:102)")
    _add_event(15, 10, 8, "ids_alert", "Security", "Intrusion Detection", 3,
               f"Snort IDS rule match: S7Plus unauthorized program modification from {ROGUE_LAPTOP['ip']} -> {target_ip}")

    # ---------------- Phase 6: 15:30 — cleartext credential ----------------
    _add_event(15, 30, 0, "cleartext_cred", "Security", "Weak Credentials", 1,
               f"Cleartext credential observed on Modbus TCP session {ROGUE_LAPTOP['ip']}:51284 -> {target_ip}:502")

    # ---------------- Phase 7: 16:00 — manual disconnect by operations team ----------------
    _add_event(16, 0, 0, "controller_mode", "Operational", "Inventory", 1,
               f"Device '{ROGUE_LAPTOP['label']}' ({ROGUE_LAPTOP['ip']}) disconnected from network (manual action by Operations)")

    # Continued background scanning flows during 14:00-16:00 (lower volume than peak scan)
    for hour in range(14, 17):
        for _ in range(20):
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            plc = random.choice(plcs) if plcs else target_entry
            _add_flow(hour, minute, second, plc, "Modbus TCP", 502,
                      random.randint(200, 1500), random.randint(2, 10))

    return injected


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_cybervision_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    progress_callback=None,
    quiet: bool = False,
) -> dict:
    """Generate Cisco Cyber Vision OT telemetry for the Detroit plant.

    Returns:
        dict with {"total": int, "files": {path: count}}
    """
    devices_path        = get_output_path("ot", "cybervision/cybervision_devices.json")
    components_path     = get_output_path("ot", "cybervision/cybervision_components.json")
    events_path         = get_output_path("ot", "cybervision/cybervision_events.json")
    flows_path          = get_output_path("ot", "cybervision/cybervision_flows.json")
    activities_path     = get_output_path("ot", "cybervision/cybervision_activities.json")
    vulnerabilities_path= get_output_path("ot", "cybervision/cybervision_vulnerabilities.json")
    sensors_path        = get_output_path("ot", "cybervision/cybervision_sensors.json")
    syslog_path         = get_output_path("ot", "cybervision/cybervision_syslog.log")

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Cyber Vision Generator (Detroit Plant)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Assets: {len(OT_INVENTORY)} devices, {len(CV_SENSORS)} sensors", file=sys.stderr)
        print(f"  Output: {devices_path.parent}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    devices_events:    List[dict] = []
    components_events: List[dict] = []
    events_events:     List[dict] = []
    flows_events:      List[dict] = []
    activities_events: List[dict] = []
    vuln_events:       List[dict] = []
    sensor_events:     List[dict] = []
    syslog_events:     List[Tuple[int, str]] = []

    # First activity (30 days before start)
    first_activity_ms = _epoch_ms(start_date, -30, 0, 0, 0)

    # Parse active scenarios (supports "all", "none", category names, comma list)
    active_scenarios = set(expand_scenarios(scenarios))
    rogue_active = "ot_rogue_device" in active_scenarios
    scenario_stats = {"ot_rogue_device": 0}

    for day in range(days):
        if progress_callback:
            progress_callback("cybervision", day + 1, days)
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [CyberVision] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        # Daily variation: ±15% deterministic noise, shared across all sourcetypes
        noise_pct = get_daily_noise(start_date, day)           # -15 .. +15
        noise_factor = 1.0 + noise_pct / 100.0
        # Weekends: OT runs at reduced capacity (~60%)
        weekend_factor = 0.6 if is_weekend(day_date) else 1.0
        volume_factor = scale * noise_factor * weekend_factor

        # -----------------------------------------------------------------
        # DEVICES — two snapshots per device per day (morning + afternoon)
        # -----------------------------------------------------------------
        for entry in OT_INVENTORY:
            for snapshot_hour in (8, 16):
                last_ms = _epoch_ms(start_date, day, snapshot_hour,
                                    random.randint(0, 59), random.randint(0, 59))
                devices_events.append(_build_device_event(entry, last_ms, first_activity_ms))

        # -----------------------------------------------------------------
        # COMPONENTS — PLCs/robots have 2-4 IO modules, emitted once per day
        # -----------------------------------------------------------------
        comp_entries = [e for e in OT_INVENTORY if e[2] in ("PLC", "Robot Controller")]
        for entry in comp_entries:
            n_modules = random.randint(2, 4)
            for i in range(1, n_modules + 1):
                last_ms = _epoch_ms(start_date, day, 12, random.randint(0, 59), random.randint(0, 59))
                components_events.append(_build_component_event(entry, i, last_ms))

        # -----------------------------------------------------------------
        # VULNERABILITIES — CVE catalog only (mirrors /api/3.0/vulnerabilities).
        # The real Cybervision /vulnerabilities endpoint returns the catalog
        # of known CVEs, NOT per-device data. Per-device vulnerability context
        # comes from the embedded vulnerabilities[] array on device events.
        # One event per unique CVE, emitted once at the start of each day so
        # the catalog is present in every time window the dashboards query.
        # -----------------------------------------------------------------
        ts_ms = _epoch_ms(start_date, day, 6, 0, 0)
        for cve, info in CVE_CATALOG.items():
            cvss = info.get("cvss", 5.0)
            sev_str = ("Critical" if cvss >= 9.0 else
                       "High"     if cvss >= 7.0 else
                       "Medium"   if cvss >= 4.0 else
                       "Low")
            vuln_events.append({
                "id":        _uuid(f"vuln-catalog-{cve}-{day}"),
                "host":      CV_CENTER_HOST,
                "cve":       cve,
                "cvss":      cvss,
                "CVSS":      cvss,
                "severity":  sev_str,
                "title":     info.get("title", cve),
                "summary":   info.get("summary", ""),
                "solution":  info.get("solution", ""),
                "affectedComponent": info.get("affectedComponent", "Firmware"),
                "publishTime": ts_ms,
                "links": [{"id": _uuid(f"link-{cve}"),
                           "link": f"https://nvd.nist.gov/vuln/detail/{cve}"}],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "lastActivity": ts_ms,
            })

        # -----------------------------------------------------------------
        # SENSORS — hourly heartbeat per CV sensor.
        # Active sensors report every hour. The spare DISCONNECTED sensor
        # reports once per day with a stale lastReceivedSysinfo so the
        # "Inactive Sensors" dashboard panel populates.
        # -----------------------------------------------------------------
        for sensor in CV_SENSORS:
            is_connected = sensor["status"] == "CONNECTED"
            enroll_status = "ENROLLED" if is_connected else "NOT_ENROLLED"
            heartbeat_hours = range(24) if is_connected else (0,)
            # Stale sysinfo for inactive sensors (frozen at 3 days before start)
            stale_sysinfo_ms = _epoch_ms(start_date, -3, 12, 0, 0)
            for hour in heartbeat_hours:
                ts_ms = _epoch_ms(start_date, day, hour, 0, 0)
                last_sysinfo = ts_ms if is_connected else stale_sysinfo_ms
                sensor_events.append({
                    "id":          sensor["id"],
                    "name":        sensor["name"],
                    "model":       sensor["model"],
                    "serialNumber":sensor["serial_number"],
                    "ip":          sensor["ip"],
                    "latitude":    sensor["latitude"],
                    "longitude":   sensor["longitude"],
                    "creationTime":_epoch_ms(start_date, -30, 0, 0, 0),
                    "status": {
                        "operationalStatus": sensor["status"],
                        "enrollmentStatus":  enroll_status,
                        "lastReceivedSysinfo": last_sysinfo,
                    },
                    "lastActivity": ts_ms,
                })

        # -----------------------------------------------------------------
        # FLOWS — continuous OT polling traffic
        # OT runs 24/7; flat curve (80% night, 100% day), no office-hours dip
        # Weekday target: ~12k/day, weekend ~7k/day
        # -----------------------------------------------------------------
        flow_hourly_base = int(500 * volume_factor)   # flows per hour
        for hour in range(24):
            hourly_mult = 1.00 if 6 <= hour <= 21 else 0.80
            hour_count = int(flow_hourly_base * hourly_mult * random.uniform(0.9, 1.1))
            for _ in range(hour_count):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                src, dst = _pick_flow_pair()
                proto, dport = _pick_protocol()
                sport = random.randint(49152, 65535)
                ts_ms = _epoch_ms(start_date, day, hour, minute, second)
                flows_events.append({
                    "id":         _uuid(f"flow-{day}-{hour}-{minute}-{second}-{random.random()}"),
                    "srcPort":    sport,
                    "dstPort":    dport,
                    "bytesCount": random.randint(200, 120000),
                    "packetsCount": random.randint(2, 400),
                    "protocol":   proto,
                    "firstSeen":  ts_ms - random.randint(1000, 60000),
                    "lastActivity": ts_ms,
                    "left":  {"id": _uuid(f"device-{src[0]}"), "label": src[0], "ip": src[1]},
                    "right": {"id": _uuid(f"device-{dst[0]}"), "label": dst[0], "ip": dst[1]},
                    "tag":   {"id": _uuid(f"tag-proto-{proto}"), "label": proto},
                })

        # -----------------------------------------------------------------
        # ACTIVITIES — aggregated per src/dst pair
        # Target: ~1,800/day weekday, ~1,100/day weekend
        # -----------------------------------------------------------------
        act_hourly_base = int(80 * volume_factor)    # ~80/hour average
        for hour in range(24):
            hourly_mult = 1.00 if 6 <= hour <= 21 else 0.80
            hour_count = int(act_hourly_base * hourly_mult * random.uniform(0.9, 1.1))
            for _ in range(hour_count):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                src, dst = _pick_flow_pair()
                cat, label = _pick_activity()
                proto, _dport = _pick_protocol()
                ts_ms = _epoch_ms(start_date, day, hour, minute, second)
                # Each activity carries TWO tags: one for the action (Read Var,
                # Program Download, ...) and one for the protocol (Modbus TCP,
                # S7Plus, ...). Dashboards that group by "tags{}.category.label"
                # = Protocol will see real protocol names in tags{}.label.
                activities_events.append({
                    "id":  _uuid(f"act-{day}-{hour}-{minute}-{second}-{random.random()}"),
                    "lastActivity": ts_ms,
                    "left":  {"id": _uuid(f"device-{src[0]}"), "label": src[0], "ip": src[1]},
                    "right": {"id": _uuid(f"device-{dst[0]}"), "label": dst[0], "ip": dst[1]},
                    "tags": [
                        {
                            "id":    _uuid(f"tag-act-{label}"),
                            "label": label,
                            "category": {"id": _uuid(f"cat-act-{cat}"), "label": cat},
                        },
                        {
                            "id":    _uuid(f"tag-proto-{proto}"),
                            "label": proto,
                            "category": {"id": _uuid("cat-proto"), "label": "Protocol"},
                        },
                    ],
                })

        # -----------------------------------------------------------------
        # EVENTS — ~140/day weekday, ~85/day weekend
        # -----------------------------------------------------------------
        n_events = max(10, int(140 * volume_factor + random.randint(-15, 15)))
        for _ in range(n_events):
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            tmpl = _pick_event_template()
            etype, family, category, severity, message_tmpl, has_operator = tmpl
            src, dst = _pick_flow_pair()
            proto, dport = _pick_protocol()
            sport = random.randint(49152, 65535)
            iface = f"GigabitEthernet1/0/{random.randint(1, 24)}"
            user_suffix = _operator_suffix() if has_operator else ""
            message = message_tmpl.format(
                label=dst[0], iface=iface,
                src_label=src[0], src=src[1], sport=sport,
                dst_label=dst[0], dst=dst[1], dport=dport,
                proto=proto, zone=dst[6],
                user_suffix=user_suffix,
            )
            ts_iso_str = ts_iso(start_date, day, hour, minute, second)
            events_events.append({
                "id":       _uuid(f"event-{day}-{hour}-{minute}-{second}-{random.random()}"),
                "type":     etype,
                "family":   family,
                "category": category,
                "severity": severity,
                "message":  message,
                "creation_time": ts_iso_str,
                "signature": f'signature "{category} - {etype}"',
                # Explicit fields so KV_MODE=json populates dashboards
                # (the TA's regex extractions don't match our message format)
                "src":       src[1],
                "src_port":  sport,
                "dest":      dst[1],
                "dest_port": dport,
                "src_label": src[0],
                "dest_label":dst[0],
                "proto":     proto,
                "short_message": f"{etype}: {src[0]} -> {dst[0]}",
            })

            # Security events AND high-severity operational events get CEF syslog
            if family == "Security" or severity >= 1:
                ts_ms = _epoch_ms(start_date, day, hour, minute, second)
                syslog_ts = ts_syslog(start_date, day, hour, minute, second)
                event_class_id = 1000 + abs(hash(etype)) % 100
                cat_tok = category.replace(" ", "_")   # CEF k=v splits on whitespace
                proto_tok = proto.replace(" ", "_")
                cef = (
                    f"{syslog_ts} {CV_CENTER_HOST} "
                    f"CEF:0|{CV_CENTER_VENDOR}|{CV_CENTER_PRODUCT}|{CV_CENTER_VERSION}|"
                    f"{event_class_id}|{category}|{severity}|"
                    f"msg={message} severity_id={severity} "
                    f"src={src[1]} spt={sport} dst={dst[1]} dpt={dport} proto={proto_tok} "
                    f"cmp_a={src[0]} cmp_b={dst[0]} SCVVulnsNumber={random.randint(0, 3)} "
                    f"cat={cat_tok}"
                )
                syslog_events.append((ts_ms, cef))

        # -----------------------------------------------------------------
        # SCENARIO: Rogue contractor laptop in Zone-1 (Day 8 afternoon)
        # -----------------------------------------------------------------
        if rogue_active and is_scenario_active_day("ot_rogue_device", day):
            injected = _inject_rogue_device_scenario(
                start_date, day,
                devices_events, components_events, events_events,
                flows_events, activities_events, syslog_events,
                first_activity_ms,
            )
            scenario_stats["ot_rogue_device"] += injected

    # Sort
    devices_events.sort(key=lambda e: e["lastActivity"])
    components_events.sort(key=lambda e: e["lastActivity"])
    flows_events.sort(key=lambda e: e["lastActivity"])
    activities_events.sort(key=lambda e: e["lastActivity"])
    events_events.sort(key=lambda e: e["creation_time"])
    vuln_events.sort(key=lambda e: e["lastActivity"])
    sensor_events.sort(key=lambda e: e["lastActivity"])
    syslog_events.sort(key=lambda x: x[0])

    # Write files
    def _write_json(path: Path, events: List[dict]):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")

    _write_json(devices_path,         devices_events)
    _write_json(components_path,      components_events)
    _write_json(events_path,          events_events)
    _write_json(flows_path,           flows_events)
    _write_json(activities_path,      activities_events)
    _write_json(vulnerabilities_path, vuln_events)
    _write_json(sensors_path,         sensor_events)

    with open(syslog_path, "w") as f:
        for _, line in syslog_events:
            f.write(line + "\n")

    file_counts = {
        "ot/cybervision/cybervision_devices.json":         len(devices_events),
        "ot/cybervision/cybervision_components.json":      len(components_events),
        "ot/cybervision/cybervision_events.json":          len(events_events),
        "ot/cybervision/cybervision_flows.json":           len(flows_events),
        "ot/cybervision/cybervision_activities.json":      len(activities_events),
        "ot/cybervision/cybervision_vulnerabilities.json": len(vuln_events),
        "ot/cybervision/cybervision_sensors.json":         len(sensor_events),
        "ot/cybervision/cybervision_syslog.log":           len(syslog_events),
    }
    total = sum(file_counts.values())

    if not quiet:
        print(f"  [CyberVision] Complete! {total:,} total events written", file=sys.stderr)
        for path, count in file_counts.items():
            print(f"          {Path(path).name:42s} {count:>7,}", file=sys.stderr)
        for scen, cnt in scenario_stats.items():
            if cnt:
                print(f"          └─ scenario '{scen}': {cnt:,} events", file=sys.stderr)

    return {"total": total, "files": file_counts}


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generate Cisco Cyber Vision OT logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", help="(ignored for multi-file generator)")
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()

    result = generate_cybervision_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(result)


if __name__ == "__main__":
    main()
