#!/usr/bin/env python3
"""
Cisco Meraki Log Generator - Multi-Site Edition.
Generates Dashboard API JSON events for MX (firewall/SD-WAN), MR (access points),
MS (switches), MV (cameras), and MT (sensors).

Format: Meraki Dashboard API JSON (from getNetworkEvents)
Sourcetype: cisco:meraki:events

Locations:
  - Boston HQ (BOS): 3 floors, primary data center
  - Atlanta Hub (ATL): 2 floors, IT operations / data center
  - Austin Office (AUS): 1 floor, sales/engineering

Event types:
  MX (appliance): firewall, urls, security_event (IDS), vpn, sd_wan events
  MR (wireless): 802.11 association/disassociation, 802.1X auth, wireless events
  MS (switch): port status, STP, 802.1X port auth
  MV (camera): motion detection, person detection, analytics
  MT (sensor): temperature, humidity, door open/close, water leak
"""

import argparse
import json
import random
import sys
import time as time_module
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Union
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import date_add, get_hour_activity_level, is_weekend
from shared.company import (
    USERS, USER_KEYS, get_random_user, LOCATIONS, NETWORK_CONFIG, NETWORK_IDS,
    THREAT_IP, COMP_USER, COMP_WS_IP, JESSICA_WS_IP,
    get_users_by_location, MEETING_ROOMS, MEETING_BEHAVIOR,
    get_random_mac, KNOWN_MAC_OUIS,
)
from shared.meeting_schedule import (
    get_meetings_for_room, get_meetings_for_hour, get_door_events_for_meeting,
    calculate_room_temperature, get_schedule_stats,
    get_ghost_meetings_for_hour, is_room_booked_but_empty,
    # Walk-in and after-hours
    should_generate_walkin, generate_walkin_meeting, get_walkins_for_hour,
    should_generate_after_hours, generate_after_hours_activity,
    clear_walkin_schedule,
)
from scenarios.registry import expand_scenarios
from scenarios.security import RansomwareAttemptScenario
from shared.time_utils import TimeUtils

# =============================================================================
# MERAKI DEVICE CONFIGURATION - MULTI-SITE
# =============================================================================

# MX Security Appliances / SD-WAN
MERAKI_MX_DEVICES = {
    # Boston HQ - HA Pair
    "MX-BOS-01": {
        "model": "MX450",
        "serial": "Q2BOS-0001-0001",
        "location": "BOS",
        "role": "primary",
        "wan_ip": "203.0.113.1",
        "wan1_provider": "Comcast",
        "wan2_provider": "AT&T",
        "ha_peer": "MX-BOS-02",
    },
    "MX-BOS-02": {
        "model": "MX450",
        "serial": "Q2BOS-0001-0002",
        "location": "BOS",
        "role": "secondary",
        "wan_ip": "203.0.113.2",
        "wan1_provider": "Comcast",
        "wan2_provider": "AT&T",
        "ha_peer": "MX-BOS-01",
    },
    # Atlanta Hub
    "MX-ATL-01": {
        "model": "MX250",
        "serial": "Q2ATL-0001-0001",
        "location": "ATL",
        "role": "primary",
        "wan_ip": "203.0.113.20",
        "wan1_provider": "AT&T",
        "wan2_provider": "Spectrum",
        "ha_peer": None,
    },
    # Austin Office
    "MX-AUS-01": {
        "model": "MX85",
        "serial": "Q2AUS-0001-0001",
        "location": "AUS",
        "role": "primary",
        "wan_ip": "203.0.113.30",
        "wan1_provider": "Verizon",
        "wan2_provider": None,
        "ha_peer": None,
    },
}

# MR Access Points - Per Location
MERAKI_MR_DEVICES = {
    # Boston HQ - Floor 1
    "AP-BOS-1F-01": {"model": "MR46", "location": "BOS", "floor": 1, "area": "Reception", "mac": "00:18:0A:B0:01:01"},
    "AP-BOS-1F-02": {"model": "MR46", "location": "BOS", "floor": 1, "area": "Lobby", "mac": "00:18:0A:B0:01:02"},
    "AP-BOS-1F-03": {"model": "MR46", "location": "BOS", "floor": 1, "area": "Operations", "mac": "00:18:0A:B0:01:03"},
    "AP-BOS-1F-04": {"model": "MR46", "location": "BOS", "floor": 1, "area": "Shipping", "mac": "00:18:0A:B0:01:04"},
    "AP-BOS-1F-05": {"model": "MR46", "location": "BOS", "floor": 1, "area": "Break Room", "mac": "00:18:0A:B0:01:05"},
    # Boston HQ - Floor 2
    "AP-BOS-2F-01": {"model": "MR46", "location": "BOS", "floor": 2, "area": "Finance East", "mac": "00:18:0A:B0:02:01"},
    "AP-BOS-2F-02": {"model": "MR46", "location": "BOS", "floor": 2, "area": "Finance West", "mac": "00:18:0A:B0:02:02"},
    "AP-BOS-2F-03": {"model": "MR46", "location": "BOS", "floor": 2, "area": "Marketing", "mac": "00:18:0A:B0:02:03"},
    "AP-BOS-2F-04": {"model": "MR46", "location": "BOS", "floor": 2, "area": "HR", "mac": "00:18:0A:B0:02:04"},
    "AP-BOS-2F-05": {"model": "MR46", "location": "BOS", "floor": 2, "area": "Cafeteria", "mac": "00:18:0A:B0:02:05"},
    # Boston HQ - Floor 3
    "AP-BOS-3F-01": {"model": "MR46", "location": "BOS", "floor": 3, "area": "Exec Reception", "mac": "00:18:0A:B0:03:01"},
    "AP-BOS-3F-02": {"model": "MR46", "location": "BOS", "floor": 3, "area": "CEO Office", "mac": "00:18:0A:B0:03:02"},
    "AP-BOS-3F-03": {"model": "MR46", "location": "BOS", "floor": 3, "area": "Engineering East", "mac": "00:18:0A:B0:03:03"},
    "AP-BOS-3F-04": {"model": "MR46", "location": "BOS", "floor": 3, "area": "Engineering West", "mac": "00:18:0A:B0:03:04"},
    "AP-BOS-3F-05": {"model": "MR46", "location": "BOS", "floor": 3, "area": "Legal", "mac": "00:18:0A:B0:03:05"},
    "AP-BOS-3F-06": {"model": "MR46", "location": "BOS", "floor": 3, "area": "Break Room 3F", "mac": "00:18:0A:B0:03:06"},
    # Atlanta Hub - Floor 1
    "AP-ATL-1F-01": {"model": "MR46", "location": "ATL", "floor": 1, "area": "Reception", "mac": "00:18:0A:A0:01:01"},
    "AP-ATL-1F-02": {"model": "MR46", "location": "ATL", "floor": 1, "area": "IT Ops East", "mac": "00:18:0A:A0:01:02"},
    "AP-ATL-1F-03": {"model": "MR46", "location": "ATL", "floor": 1, "area": "IT Ops West", "mac": "00:18:0A:A0:01:03"},
    "AP-ATL-1F-04": {"model": "MR46", "location": "ATL", "floor": 1, "area": "Training Lab", "mac": "00:18:0A:A0:01:04"},
    "AP-ATL-1F-05": {"model": "MR46", "location": "ATL", "floor": 1, "area": "Staging", "mac": "00:18:0A:A0:01:05"},
    "AP-ATL-1F-06": {"model": "MR46", "location": "ATL", "floor": 1, "area": "Break Room", "mac": "00:18:0A:A0:01:06"},
    # Atlanta Hub - Floor 2
    "AP-ATL-2F-01": {"model": "MR46", "location": "ATL", "floor": 2, "area": "Engineering", "mac": "00:18:0A:A0:02:01"},
    "AP-ATL-2F-02": {"model": "MR46", "location": "ATL", "floor": 2, "area": "Engineering 2", "mac": "00:18:0A:A0:02:02"},
    "AP-ATL-2F-03": {"model": "MR46", "location": "ATL", "floor": 2, "area": "HR/Ops", "mac": "00:18:0A:A0:02:03"},
    "AP-ATL-2F-04": {"model": "MR46", "location": "ATL", "floor": 2, "area": "Sales/Marketing", "mac": "00:18:0A:A0:02:04"},
    "AP-ATL-2F-05": {"model": "MR46", "location": "ATL", "floor": 2, "area": "Phone Booths", "mac": "00:18:0A:A0:02:05"},
    "AP-ATL-2F-06": {"model": "MR46", "location": "ATL", "floor": 2, "area": "Break Room 2F", "mac": "00:18:0A:A0:02:06"},
    # Austin Office - Floor 1
    "AP-AUS-1F-01": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Reception", "mac": "00:18:0A:C0:01:01"},
    "AP-AUS-1F-02": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Sales East", "mac": "00:18:0A:C0:01:02"},
    "AP-AUS-1F-03": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Sales West", "mac": "00:18:0A:C0:01:03"},
    "AP-AUS-1F-04": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Engineering East", "mac": "00:18:0A:C0:01:04"},
    "AP-AUS-1F-05": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Engineering West", "mac": "00:18:0A:C0:01:05"},
    "AP-AUS-1F-06": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Break Room", "mac": "00:18:0A:C0:01:06"},
    "AP-AUS-1F-07": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Phone Booths", "mac": "00:18:0A:C0:01:07"},
    "AP-AUS-1F-08": {"model": "MR46", "location": "AUS", "floor": 1, "area": "Game Room", "mac": "00:18:0A:C0:01:08"},
}

# MS Switches - Per Location
MERAKI_MS_DEVICES = {
    # Boston HQ - Core
    "MS-BOS-CORE-01": {"model": "MS425-32", "location": "BOS", "floor": 3, "role": "core", "ports": 32},
    "MS-BOS-CORE-02": {"model": "MS425-32", "location": "BOS", "floor": 3, "role": "core", "ports": 32},
    # Boston HQ - Access
    "MS-BOS-1F-IDF1": {"model": "MS225-48", "location": "BOS", "floor": 1, "role": "access", "ports": 48},
    "MS-BOS-2F-IDF1": {"model": "MS225-48", "location": "BOS", "floor": 2, "role": "access", "ports": 48},
    "MS-BOS-3F-IDF1": {"model": "MS225-48", "location": "BOS", "floor": 3, "role": "access", "ports": 48},
    # Atlanta Hub - Core/DC
    "MS-ATL-DC-01": {"model": "MS425-32", "location": "ATL", "floor": 1, "role": "dc_core", "ports": 32},
    "MS-ATL-DC-02": {"model": "MS425-32", "location": "ATL", "floor": 1, "role": "dc_core", "ports": 32},
    # Atlanta Hub - Access
    "MS-ATL-1F-IDF1": {"model": "MS225-48", "location": "ATL", "floor": 1, "role": "access", "ports": 48},
    "MS-ATL-2F-IDF1": {"model": "MS225-48", "location": "ATL", "floor": 2, "role": "access", "ports": 48},
    # Austin Office
    "MS-AUS-01": {"model": "MS250-48", "location": "AUS", "floor": 1, "role": "core", "ports": 48},
    "MS-AUS-02": {"model": "MS225-24", "location": "AUS", "floor": 1, "role": "access", "ports": 24},
}

# MV Cameras - Per Location
MERAKI_MV_DEVICES = {
    # Boston HQ
    "CAM-BOS-1F-01": {"model": "MV12", "location": "BOS", "floor": 1, "area": "Security/Lobby", "type": "indoor"},
    "CAM-BOS-1F-03": {"model": "MV12", "location": "BOS", "floor": 1, "area": "Server Room", "type": "indoor"},
    "CAM-BOS-3F-01": {"model": "MV12", "location": "BOS", "floor": 3, "area": "Boardroom", "type": "indoor"},
    "CAM-BOS-3F-02": {"model": "MV12", "location": "BOS", "floor": 3, "area": "Boardroom 2", "type": "indoor"},
    "CAM-BOS-3F-03": {"model": "MV32", "location": "BOS", "floor": 3, "area": "MDF", "type": "indoor_wide"},
    "CAM-BOS-3F-04": {"model": "MV32", "location": "BOS", "floor": 3, "area": "MDF Entrance", "type": "indoor_wide"},
    "CAM-BOS-EXT-01": {"model": "MV72", "location": "BOS", "floor": 0, "area": "Loading Dock", "type": "outdoor"},
    "CAM-BOS-EXT-02": {"model": "MV72", "location": "BOS", "floor": 0, "area": "Parking Entrance", "type": "outdoor"},
    # Atlanta Hub
    "CAM-ATL-1F-01": {"model": "MV12", "location": "ATL", "floor": 1, "area": "Lobby", "type": "indoor"},
    "CAM-ATL-DC-01": {"model": "MV32", "location": "ATL", "floor": 1, "area": "DC Row A", "type": "indoor_wide"},
    "CAM-ATL-DC-02": {"model": "MV32", "location": "ATL", "floor": 1, "area": "DC Row B", "type": "indoor_wide"},
    "CAM-ATL-DC-03": {"model": "MV32", "location": "ATL", "floor": 1, "area": "DC Entrance", "type": "indoor_wide"},
    "CAM-ATL-DC-04": {"model": "MV32", "location": "ATL", "floor": 1, "area": "DC Cage", "type": "indoor_wide"},
    "CAM-ATL-1F-05": {"model": "MV12", "location": "ATL", "floor": 1, "area": "IDF", "type": "indoor"},
    "CAM-ATL-EXT-01": {"model": "MV72", "location": "ATL", "floor": 0, "area": "Parking", "type": "outdoor"},
    # Austin Office
    "CAM-AUS-1F-01": {"model": "MV12", "location": "AUS", "floor": 1, "area": "Entrance", "type": "indoor"},
    "CAM-AUS-1F-02": {"model": "MV12", "location": "AUS", "floor": 1, "area": "Server Room", "type": "indoor"},
    "CAM-AUS-EXT-01": {"model": "MV72", "location": "AUS", "floor": 0, "area": "Parking Front", "type": "outdoor"},
    "CAM-AUS-EXT-02": {"model": "MV72", "location": "AUS", "floor": 0, "area": "Parking Back", "type": "outdoor"},
}

# MT Sensors - Per Location (Server Rooms / Data Centers)
MERAKI_MT_DEVICES = {
    # Boston HQ
    "MT-BOS-1F-TEMP-01": {"model": "MT10", "location": "BOS", "floor": 1, "area": "Server Room", "type": "temperature"},
    "MT-BOS-1F-DOOR-01": {"model": "MT20", "location": "BOS", "floor": 1, "area": "Server Room", "type": "door"},
    "MT-BOS-MDF-TEMP-01": {"model": "MT10", "location": "BOS", "floor": 3, "area": "MDF", "type": "temperature"},
    "MT-BOS-MDF-HUMID-01": {"model": "MT11", "location": "BOS", "floor": 3, "area": "MDF", "type": "humidity"},
    "MT-BOS-MDF-DOOR-01": {"model": "MT20", "location": "BOS", "floor": 3, "area": "MDF", "type": "door"},
    # Atlanta Hub - Data Center (comprehensive monitoring)
    "MT-ATL-DC-TEMP-01": {"model": "MT10", "location": "ATL", "floor": 1, "area": "DC Row A Front", "type": "temperature"},
    "MT-ATL-DC-TEMP-02": {"model": "MT10", "location": "ATL", "floor": 1, "area": "DC Row A Back", "type": "temperature"},
    "MT-ATL-DC-TEMP-03": {"model": "MT10", "location": "ATL", "floor": 1, "area": "DC Row B Front", "type": "temperature"},
    "MT-ATL-DC-TEMP-04": {"model": "MT10", "location": "ATL", "floor": 1, "area": "DC Row B Back", "type": "temperature"},
    "MT-ATL-DC-HUMID-01": {"model": "MT11", "location": "ATL", "floor": 1, "area": "DC Row A", "type": "humidity"},
    "MT-ATL-DC-HUMID-02": {"model": "MT11", "location": "ATL", "floor": 1, "area": "DC Row B", "type": "humidity"},
    "MT-ATL-DC-DOOR-01": {"model": "MT20", "location": "ATL", "floor": 1, "area": "DC Entrance", "type": "door"},
    # Austin Office
    "MT-AUS-TEMP-01": {"model": "MT10", "location": "AUS", "floor": 1, "area": "Server Room", "type": "temperature"},
    "MT-AUS-DOOR-01": {"model": "MT20", "location": "AUS", "floor": 1, "area": "Server Room", "type": "door"},
}


# =============================================================================
# MEETING ROOM SENSOR HELPERS
# =============================================================================

def get_meeting_room_sensors() -> Dict[str, dict]:
    """Get all meeting room sensors from MEETING_ROOMS config."""
    sensors = {}
    for room_name, room_config in MEETING_ROOMS.items():
        # Temperature sensor
        if room_config.get("has_temp_sensor") and room_config.get("temp_sensor_id"):
            sensor_id = room_config["temp_sensor_id"]
            sensors[sensor_id] = {
                "model": "MT10",
                "location": room_config["location"],
                "floor": room_config.get("floor", 1),
                "area": room_name,
                "type": "temperature",
                "room_name": room_name,
                "room_config": room_config,
            }

        # Door sensor
        if room_config.get("has_door_sensor") and room_config.get("door_sensor_id"):
            sensor_id = room_config["door_sensor_id"]
            sensors[sensor_id] = {
                "model": "MT20",
                "location": room_config["location"],
                "floor": room_config.get("floor", 1),
                "area": room_name,
                "type": "door",
                "room_name": room_name,
                "room_config": room_config,
            }

    return sensors


def calculate_room_temperature(room_config: dict, hour: int, people_count: int = 0,
                               meeting_duration_mins: int = 0) -> float:
    """Calculate realistic room temperature based on multiple factors.

    Factors:
    - Base temperature from room config
    - Sun exposure (time of day dependent)
    - Body heat from people (+0.3°C per person, max +3°C)
    - Long meeting duration (+0.5°C per 30 min, max +1.5°C)
    - Random noise (±0.3°C)
    """
    base_temp = room_config.get("base_temp", 21.0)
    temp = base_temp

    # Sun exposure boost
    sun_hours = room_config.get("sun_hours", [])
    sun_boost = room_config.get("sun_temp_boost", 0.0)
    if hour in sun_hours:
        temp += sun_boost

    # Body heat from people
    if people_count > 0:
        rise_per_person = MEETING_BEHAVIOR.get("temp_rise_per_person", 0.3)
        max_rise_people = MEETING_BEHAVIOR.get("temp_rise_max_from_people", 3.0)
        temp += min(people_count * rise_per_person, max_rise_people)

    # Long meeting duration effect
    if meeting_duration_mins > 0:
        rise_per_30min = MEETING_BEHAVIOR.get("temp_rise_per_30min", 0.5)
        max_rise_duration = MEETING_BEHAVIOR.get("temp_rise_max_from_duration", 1.5)
        temp += min((meeting_duration_mins / 30) * rise_per_30min, max_rise_duration)

    # Random noise
    temp += random.uniform(-0.3, 0.3)

    return round(temp, 1)

# SSIDs
MERAKI_SSIDS = [
    {"name": "FakeTShirtCo-Corp", "vap": 0, "auth": "802.1X"},
    {"name": "FakeTShirtCo-Guest", "vap": 1, "auth": "PSK"},
    {"name": "FakeTShirtCo-IoT", "vap": 2, "auth": "PSK"},
    {"name": "FakeTShirtCo-Voice", "vap": 3, "auth": "802.1X"},
]

# IDS Signatures (real Snort SID ranges with matched dest ports)
# Each signature includes target ports for realistic port-signature correlation
IDS_SIGNATURES = [
    {"sig": "1:41944:2", "priority": 1, "msg": "BROWSER-IE Microsoft Edge scripting engine security bypass attempt", "ports": [80, 443, 8080]},
    {"sig": "1:39867:3", "priority": 3, "msg": "INDICATOR-COMPROMISE Suspicious .tk dns query", "ports": [53, 443]},
    {"sig": "1:40688:5", "priority": 2, "msg": "MALWARE-CNC Win.Trojan.Agent outbound connection", "ports": [443, 8443, 4443]},
    {"sig": "1:49897:1", "priority": 3, "msg": "POLICY-OTHER Cryptocurrency mining pool DNS request", "ports": [53, 443, 3333]},
    {"sig": "1:31408:9", "priority": 2, "msg": "SERVER-WEBAPP SQL injection attempt", "ports": [80, 443, 8080, 8443]},
    {"sig": "1:19559:7", "priority": 1, "msg": "INDICATOR-SCAN Nmap TCP scan detected", "ports": [22, 23, 80, 443, 445, 3389]},
    {"sig": "1:42834:3", "priority": 2, "msg": "MALWARE-CNC Possible data exfiltration via DNS", "ports": [53, 443]},
    {"sig": "1:45550:2", "priority": 1, "msg": "EXPLOIT-KIT Angler EK landing page detected", "ports": [80, 443]},
    {"sig": "1:38907:4", "priority": 2, "msg": "FILE-OTHER Suspicious executable download", "ports": [80, 443, 8080]},
    {"sig": "1:24017:6", "priority": 2, "msg": "SERVER-WEBAPP directory traversal attempt", "ports": [80, 443, 8080, 8443]},
    {"sig": "1:2100498:8", "priority": 3, "msg": "GPL ATTACK_RESPONSE id check returned root", "ports": [22, 23]},
    {"sig": "1:2002911:6", "priority": 2, "msg": "ET SCAN Potential SSH Scan", "ports": [22]},
]

# SD-WAN VPN Peers
SDWAN_PEERS = [
    ("MX-BOS-01", "MX-ATL-01"),
    ("MX-BOS-01", "MX-AUS-01"),
    ("MX-ATL-01", "MX-AUS-01"),
]


# =============================================================================
# TIMESTAMP UTILITIES
# =============================================================================

def ts_meraki(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate Meraki Dashboard API ISO8601 timestamp with microseconds."""
    dt = datetime.strptime(base_date, "%Y-%m-%d")
    dt = dt + timedelta(days=day, hours=hour, minutes=minute, seconds=second)
    # Add random microseconds for uniqueness
    micros = random.randint(0, 999999)
    dt = dt.replace(microsecond=micros)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts_meraki_from_dt(dt: datetime) -> str:
    """Generate Meraki Dashboard API ISO8601 timestamp from datetime object."""
    # Add random microseconds for uniqueness
    micros = random.randint(0, 999999)
    dt = dt.replace(microsecond=micros)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def generate_mac() -> str:
    """Generate random MAC address with known vendor OUI prefix."""
    return get_random_mac()


def get_random_internal_ip(location: str = None) -> str:
    """Get random internal IP for a location."""
    if location:
        prefix = NETWORK_CONFIG[location]["prefix"]
        return f"{prefix}.30.{random.randint(10, 250)}"
    prefixes = ["10.10.30", "10.20.30", "10.30.30"]
    prefix = random.choice(prefixes)
    return f"{prefix}.{random.randint(10, 250)}"


def get_random_external_ip() -> str:
    """Get random external IP (legitimate traffic)."""
    ext_ips = [
        "13.107.42.14", "52.169.118.173", "52.239.228.100",
        "140.82.121.4", "172.217.14.78", "54.239.28.85", "35.186.224.25",
    ]
    if random.random() < 0.3:
        return random.choice(ext_ips)
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def get_mx_for_location(location: str) -> str:
    """Get primary MX device for a location."""
    for name, dev in MERAKI_MX_DEVICES.items():
        if dev["location"] == location and dev["role"] == "primary":
            return name
    return list(MERAKI_MX_DEVICES.keys())[0]


def get_aps_for_location(location: str) -> List[str]:
    """Get all APs for a location."""
    return [name for name, dev in MERAKI_MR_DEVICES.items() if dev["location"] == location]


def get_switches_for_location(location: str) -> List[str]:
    """Get all switches for a location."""
    return [name for name, dev in MERAKI_MS_DEVICES.items() if dev["location"] == location]


def get_cameras_for_location(location: str) -> List[str]:
    """Get all cameras for a location."""
    return [name for name, dev in MERAKI_MV_DEVICES.items() if dev["location"] == location]


def get_sensors_for_location(location: str) -> List[str]:
    """Get all sensors for a location."""
    return [name for name, dev in MERAKI_MT_DEVICES.items() if dev["location"] == location]


def get_meeting_room_cameras() -> Dict[str, dict]:
    """Get cameras associated with meeting rooms from MEETING_ROOMS config."""
    cameras = {}
    for room_name, room_config in MEETING_ROOMS.items():
        if room_config.get("has_camera") and room_config.get("camera_id"):
            camera_id = room_config["camera_id"]
            cameras[camera_id] = {
                "model": "MV12",  # Default model
                "location": room_config["location"],
                "floor": room_config.get("floor", 1),
                "area": room_name,
                "type": "indoor",
                "room_name": room_name,
                "room_config": room_config,
            }
    return cameras


# =============================================================================
# MX FIREWALL / SD-WAN EVENTS (Dashboard API JSON)
# =============================================================================

def mx_firewall_event(ts: str, device: str, src: str, dst: str,
                      protocol: str, sport: int, dport: int,
                      action: str = "allow", mac: str = None,
                      location: str = None, demo_id: str = None) -> dict:
    """Generate MX firewall flow event (Dashboard API format)."""
    if mac is None:
        mac = generate_mac()
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    pattern = "allow all" if action == "allow" else "deny all"

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "firewall",
        "description": f"Firewall flow {action}ed",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "src": src,
            "dst": dst,
            "mac": mac,
            "protocol": protocol,
            "sport": str(sport),
            "dport": str(dport),
            "pattern": pattern
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_url_event(ts: str, device: str, src_ip: str, src_port: int,
                 dst_ip: str, dst_port: int, mac: str, url: str,
                 method: str = "GET", agent: str = None,
                 location: str = None, demo_id: str = None) -> dict:
    """Generate MX URL logging event (Dashboard API format)."""
    if agent is None:
        agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "url",
        "description": f"URL request: {method} {url}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "clientMac": mac,
        "eventData": {
            "src": f"{src_ip}:{src_port}",
            "dst": f"{dst_ip}:{dst_port}",
            "method": method,
            "url": url,
            "agent": agent
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_ids_event(ts: str, device: str, signature: dict, src_ip: str,
                 src_port: int, dst_ip: str, dst_port: int,
                 protocol: str = "tcp", direction: str = "ingress",
                 dst_mac: str = None, demo_id: str = None,
                 location: str = None) -> dict:
    """Generate MX IDS alert event (getNetworkApplianceSecurityEvents format)."""
    if dst_mac is None:
        dst_mac = generate_mac()
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    device_mac = MERAKI_MX_DEVICES.get(device, {}).get("mac", "00:18:0A:01:02:03")
    if not device_mac:
        device_mac = "00:18:0A:01:02:03"

    # Parse signature ID for ruleId
    sig_parts = signature['sig'].split(':')
    gid = sig_parts[0] if len(sig_parts) > 0 else "1"
    sid = sig_parts[1] if len(sig_parts) > 1 else "0"

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "security_event",
        "subtype": "ids_alert",
        "description": signature['msg'],
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "deviceMac": device_mac,
        "clientMac": dst_mac,
        "eventData": {
            "srcIp": src_ip,
            "srcPort": str(src_port),
            "destIp": dst_ip,
            "destPort": str(dst_port),
            "protocol": protocol,
            "direction": direction,
            "priority": str(signature['priority']),
            "classification": str(random.randint(1, 5)),
            "blocked": random.random() < 0.3,
            "message": signature['msg'],
            "signature": signature['sig'],
            "ruleId": f"meraki:intrusion/snort/GID/{gid}/SID/{sid}"
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_vpn_event(ts: str, device: str, vpn_type: str, connectivity: str,
                 peer_ip: str = None, location: str = None,
                 demo_id: str = None) -> dict:
    """Generate MX VPN connectivity event (Dashboard API format)."""
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "vpn_connectivity_change",
        "description": "VPN tunnel status changed",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "vpn_type": vpn_type,
            "connectivity": connectivity
        }
    }
    if peer_ip:
        event["eventData"]["peer_contact"] = f"{peer_ip}:51856"
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_sdwan_health_event(ts: str, device: str, wan: str, latency_ms: float,
                          jitter_ms: float, loss_pct: float, status: str,
                          location: str = None, demo_id: str = None) -> dict:
    """Generate MX SD-WAN health metrics event (Dashboard API format)."""
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "sd_wan_health",
        "description": f"SD-WAN {wan} health: {status}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "wan": wan,
            "latency_ms": round(latency_ms, 1),
            "jitter_ms": round(jitter_ms, 1),
            "loss_pct": round(loss_pct, 2),
            "status": status
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_sdwan_failover_event(ts: str, device: str, primary_wan: str,
                            backup_wan: str, reason: str,
                            location: str = None, demo_id: str = None) -> dict:
    """Generate MX SD-WAN path failover event (Dashboard API format)."""
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "sd_wan_failover",
        "description": f"SD-WAN failover from {primary_wan} to {backup_wan}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "from_wan": primary_wan,
            "to_wan": backup_wan,
            "reason": reason
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_vpn_tunnel_event(ts: str, device: str, peer: str, status: str,
                        uptime: int = None, location: str = None,
                        demo_id: str = None) -> dict:
    """Generate MX site-to-site VPN tunnel status event (Dashboard API format)."""
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "vpn_tunnel_status",
        "description": f"VPN tunnel to {peer}: {status}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "peer": peer,
            "status": status
        }
    }
    if uptime is not None:
        event["eventData"]["uptime_seconds"] = uptime
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_content_filtering_event(ts: str, device: str, client_ip: str,
                                client_mac: str, url: str, category: str,
                                action: str = "blocked",
                                location: str = None, demo_id: str = None) -> dict:
    """Generate MX content filtering event (Dashboard API format).

    Logs when web content is blocked due to content filtering policy.
    """
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "security_event",
        "subtype": "content_filtering",
        "description": f"Content filtering: {action} {category}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "clientMac": client_mac,
        "eventData": {
            "clientIp": client_ip,
            "url": url,
            "category": category,
            "action": action
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_amp_malware_event(ts: str, device: str, client_ip: str,
                         client_mac: str, file_name: str, file_hash: str,
                         disposition: str, threat_name: str = None,
                         location: str = None, demo_id: str = None) -> dict:
    """Generate MX AMP (Advanced Malware Protection) event (Dashboard API format).

    Logs when AMP detects and blocks malware.
    """
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "security_event",
        "subtype": "amp_malware_blocked",
        "description": f"AMP malware blocked: {threat_name or file_name}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "clientMac": client_mac,
        "eventData": {
            "clientIp": client_ip,
            "fileName": file_name,
            "fileHash": file_hash,
            "disposition": disposition  # "malicious", "clean", "unknown"
        }
    }
    if threat_name:
        event["eventData"]["threatName"] = threat_name
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mx_client_isolation_event(ts: str, device: str, client_ip: str,
                               client_mac: str, reason: str,
                               action: str = "isolated",
                               location: str = None, demo_id: str = None) -> dict:
    """Generate MX client isolation event (Dashboard API format).

    Logs when a client is isolated due to security policy violation.
    """
    loc = location or MERAKI_MX_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "security_event",
        "subtype": "client_isolation",
        "description": f"Client {action}: {reason}",
        "category": "appliance",
        "deviceSerial": device,
        "deviceName": device,
        "clientMac": client_mac,
        "eventData": {
            "clientIp": client_ip,
            "reason": reason,
            "action": action  # "isolated", "released"
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MR ACCESS POINT EVENTS (Dashboard API JSON)
# =============================================================================

def mr_association_event(ts: str, device: str, client_mac: str,
                         ssid: str, channel: int, rssi: int,
                         radio: int = 1, vap: int = 0, aid: int = None,
                         client_ip: str = None,
                         location: str = None, demo_id: str = None) -> dict:
    """Generate MR 802.11 association event (Dashboard API format)."""
    if aid is None:
        aid = random.randint(1000000000, 9999999999)
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "association",
        "description": "802.11 association",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "ssidNumber": vap,
        "eventData": {
            "radio": str(radio),
            "vap": str(vap),
            "channel": str(channel),
            "rssi": str(rssi),
            "aid": str(aid)
        }
    }
    if client_ip:
        event["clientIp"] = client_ip
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_disassociation_event(ts: str, device: str, client_mac: str,
                            reason: int, duration: float,
                            radio: int = 1, vap: int = 0,
                            client_ip: str = None,
                            location: str = None, demo_id: str = None) -> dict:
    """Generate MR 802.11 disassociation event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "disassociation",
        "description": "802.11 disassociation",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "radio": str(radio),
            "vap": str(vap),
            "reason": str(reason),
            "duration": f"{duration:.2f}"
        }
    }
    if client_ip:
        event["clientIp"] = client_ip
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_8021x_success_event(ts: str, device: str, identity: str,
                           client_mac: str, vap: int = 0, radio: int = 1,
                           client_ip: str = None,
                           location: str = None, demo_id: str = None) -> dict:
    """Generate MR 802.1X EAP success event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "8021x_eap_success",
        "description": "802.1X EAP authentication succeeded",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "identity": identity,
            "vap": str(vap),
            "radio": str(radio)
        }
    }
    if client_ip:
        event["clientIp"] = client_ip
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_8021x_failure_event(ts: str, device: str, identity: str,
                           client_mac: str, vap: int = 0, radio: int = 1,
                           client_ip: str = None,
                           location: str = None, demo_id: str = None) -> dict:
    """Generate MR 802.1X EAP failure event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "8021x_eap_failure",
        "description": "802.1X EAP authentication failed",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "identity": identity,
            "vap": str(vap),
            "radio": str(radio)
        }
    }
    if client_ip:
        event["clientIp"] = client_ip
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_wpa_auth_event(ts: str, device: str, client_mac: str,
                      vap: int = 0, radio: int = 1, aid: int = None,
                      client_ip: str = None,
                      location: str = None, demo_id: str = None) -> dict:
    """Generate MR WPA authentication event (Dashboard API format)."""
    if aid is None:
        aid = random.randint(1000000000, 9999999999)
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "wpa_auth",
        "description": "WPA authentication",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "radio": str(radio),
            "vap": str(vap),
            "aid": str(aid)
        }
    }
    if client_ip:
        event["clientIp"] = client_ip
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_rogue_ssid_event(ts: str, device: str, rogue_ssid: str,
                        rogue_bssid: str, channel: int, rssi: int,
                        location: str = None, demo_id: str = None) -> dict:
    """Generate MR Air Marshal rogue SSID detection event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "rogue_ssid_detected",
        "description": f"Rogue SSID detected: {rogue_ssid}",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "ssid": rogue_ssid,
            "bssid": rogue_bssid,
            "channel": str(channel),
            "rssi": str(rssi)
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MR ACCESS POINT HEALTH EVENTS (Dashboard API JSON)
# =============================================================================

# Rooms with known issues (for training/demo purposes)
PROBLEM_AP_AREAS = {
    "AP-BOS-1F-04": {"issue": "high_interference", "snr_penalty": -8, "util_boost": 15},  # Shipping - near metal
    "AP-BOS-2F-03": {"issue": "high_density", "snr_penalty": -5, "util_boost": 20},       # Marketing - many devices
    "AP-ATL-1F-04": {"issue": "coverage_edge", "snr_penalty": -10, "rssi_penalty": -15},  # Training Lab - far corner
    "AP-AUS-1F-08": {"issue": "interference", "snr_penalty": -6, "util_boost": 10},       # Game Room - Bluetooth
}

# Health alert types for MR devices
MR_HEALTH_ALERT_TYPES = [
    ("high_channel_utilization", "performance", "warning", "High channel utilization detected"),
    ("client_connectivity_issues", "connectivity", "warning", "Multiple clients experiencing connectivity issues"),
    ("interference_detected", "performance", "info", "RF interference detected on channel"),
    ("ap_offline", "connectivity", "error", "Access point offline"),
    ("high_latency", "performance", "warning", "Average latency exceeds 60ms threshold"),
    ("poor_signal_quality", "performance", "warning", "SNR below 27dB threshold"),
    ("packet_loss", "performance", "warning", "Packet loss above 3% threshold"),
    ("dfs_event", "rf", "info", "DFS channel change event"),
]


def mr_health_score_event(ts: str, device: str,
                          performance_score: int, onboarding_score: int,
                          location: str = None, demo_id: str = None) -> dict:
    """Generate MR AP health scores (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "ap_health_score",
        "description": f"AP health score: {performance_score}%",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "performance": {"latest": performance_score},
            "onboarding": {"latest": onboarding_score}
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_signal_quality_event(ts: str, device: str,
                            snr: int, rssi: int,
                            location: str = None, demo_id: str = None) -> dict:
    """Generate MR signal quality metrics (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "signal_quality",
        "description": "Wireless signal quality metrics",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "snr": snr,
            "rssi": rssi
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_channel_utilization_event(ts: str, device: str,
                                  utilization_total: float,
                                  utilization_80211: float,
                                  utilization_non80211: float,
                                  band: str = "5",
                                  location: str = None, demo_id: str = None) -> dict:
    """Generate MR channel utilization metrics (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "channel_utilization",
        "description": f"Channel utilization: {utilization_total:.1f}%",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "band": band,
            "utilizationTotal": round(utilization_total, 2),
            "utilization80211": round(utilization_80211, 2),
            "utilizationNon80211": round(utilization_non80211, 2)
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_latency_stats_event(ts: str, device: str,
                           background_avg_ms: float, best_effort_avg_ms: float,
                           video_avg_ms: float, voice_avg_ms: float,
                           location: str = None, demo_id: str = None) -> dict:
    """Generate MR wireless latency stats (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "latency_stats",
        "description": "Wireless latency statistics",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "latencyStats": {
                "backgroundTraffic": {"avg": round(background_avg_ms, 2)},
                "bestEffortTraffic": {"avg": round(best_effort_avg_ms, 2)},
                "videoTraffic": {"avg": round(video_avg_ms, 2)},
                "voiceTraffic": {"avg": round(voice_avg_ms, 2)}
            }
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_client_health_event(ts: str, device: str, client_mac: str,
                           performance_latest: int, performance_current: int,
                           onboarding_latest: int,
                           location: str = None, demo_id: str = None) -> dict:
    """Generate MR client health score event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "client_health_score",
        "description": f"Client health: {performance_current}%",
        "category": "wireless",
        "clientMac": client_mac,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "performance": {
                "latest": performance_latest,
                "currentConnection": performance_current
            },
            "onboarding": {"latest": onboarding_latest}
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_health_alert_event(ts: str, device: str,
                          alert_id: str, alert_type: str, category: str,
                          severity: str, description: str,
                          location: str = None, demo_id: str = None) -> dict:
    """Generate MR health alert event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "health_alert",
        "description": description,
        "category": category,
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "alertId": alert_id,
            "alertType": alert_type,
            "severity": severity
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mr_application_health_event(ts: str, device: str,
                                 wan_goodput_bps: int, lan_goodput_bps: int,
                                 wan_latency_ms: float, lan_latency_ms: float,
                                 wan_loss_pct: float, lan_loss_pct: float,
                                 num_clients: int,
                                 location: str = None, demo_id: str = None) -> dict:
    """Generate network insight application health event (Dashboard API format)."""
    loc = location or MERAKI_MR_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "application_health",
        "description": "Application health metrics",
        "category": "wireless",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "wanGoodput": wan_goodput_bps,
            "lanGoodput": lan_goodput_bps,
            "wanLatencyMs": round(wan_latency_ms, 1),
            "lanLatencyMs": round(lan_latency_ms, 1),
            "wanLossPercent": round(wan_loss_pct, 2),
            "lanLossPercent": round(lan_loss_pct, 2),
            "numClients": num_clients
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MS SWITCH EVENTS (Dashboard API JSON)
# =============================================================================

def ms_port_status_event(ts: str, device: str, port: int,
                         status: str, speed: str = None, prev_status: str = None,
                         location: str = None, demo_id: str = None) -> dict:
    """Generate MS port status change event (Dashboard API format)."""
    loc = location or MERAKI_MS_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    if prev_status:
        description = f"Port {port} status changed from {prev_status} to {status}"
    elif speed:
        description = f"Port {port} status {status} speed {speed}"
    else:
        description = f"Port {port} status {status}"

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "port_status",
        "description": description,
        "category": "switch",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "port": str(port),
            "status": status
        }
    }
    if prev_status:
        event["eventData"]["previous_status"] = prev_status
    if speed:
        event["eventData"]["speed"] = speed
    if demo_id:
        event["demo_id"] = demo_id
    return event


def ms_stp_event(ts: str, device: str, port: int, role: str, state: str,
                 prev_role: str = None, location: str = None,
                 demo_id: str = None) -> dict:
    """Generate MS spanning tree event (Dashboard API format)."""
    loc = location or MERAKI_MS_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    if prev_role:
        description = f"Port {port} changed STP role from {prev_role} to {role}"
    else:
        description = f"Port {port} STP role {role} state {state}"

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "stp_change",
        "description": description,
        "category": "switch",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "port": str(port),
            "role": role,
            "state": state
        }
    }
    if prev_role:
        event["eventData"]["previous_role"] = prev_role
    if demo_id:
        event["demo_id"] = demo_id
    return event


def ms_8021x_port_auth_event(ts: str, device: str, port: int,
                             identity: str, status: str,
                             location: str = None, demo_id: str = None) -> dict:
    """Generate MS 802.1X port authentication event (Dashboard API format)."""
    loc = location or MERAKI_MS_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "8021x_auth",
        "description": f"802.1X port auth: {status}",
        "category": "switch",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "port": str(port),
            "identity": identity,
            "status": status
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MV CAMERA EVENTS (Dashboard API JSON)
# =============================================================================

def mv_motion_event(ts: str, device: str, zone: str, confidence: float,
                    location: str = None, area: str = None,
                    model: str = "MV12", demo_id: str = None) -> dict:
    """Generate MV motion detection event (Dashboard API format)."""
    loc = location or MERAKI_MV_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "motion_detected",
        "description": "Motion detected in zone",
        "category": "camera",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "zone": zone,
            "confidence": round(confidence, 2)
        }
    }
    if area:
        event["eventData"]["area"] = area
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mv_person_detection_event(ts: str, device: str, count: int, zone: str,
                              location: str = None, area: str = None,
                              model: str = "MV12", demo_id: str = None) -> dict:
    """Generate MV person detection event (Dashboard API format)."""
    loc = location or MERAKI_MV_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "person_detected",
        "description": f"{count} person(s) detected",
        "category": "camera",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "zone": zone,
            "people_count": count
        }
    }
    if area:
        event["eventData"]["area"] = area
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mv_analytics_event(ts: str, device: str, people_count: int,
                       dwell_time_avg: float, location: str = None,
                       area: str = None, model: str = "MV12",
                       demo_id: str = None) -> dict:
    """Generate MV analytics summary event (Dashboard API format)."""
    loc = location or MERAKI_MV_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "analytics",
        "description": "Room analytics",
        "category": "camera",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "people_count": people_count,
            "dwell_time_avg_seconds": round(dwell_time_avg, 1)
        }
    }
    if area:
        event["eventData"]["area"] = area
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mv_health_event(ts: str, device: str, status: str, disk_usage_pct: float,
                    recording: bool, model: str = "MV12",
                    location: str = None, demo_id: str = None) -> dict:
    """Generate MV camera health event (Dashboard API format)."""
    loc = location or MERAKI_MV_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "health_status",
        "description": f"Camera health: {status}",
        "category": "camera",
        "deviceSerial": device,
        "deviceName": device,
        "eventData": {
            "status": status,
            "disk_usage_pct": round(disk_usage_pct, 1),
            "recording": recording
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# MT SENSOR EVENTS (Dashboard API JSON - getOrganizationSensorAlerts format)
# =============================================================================

def mt_temperature_event(ts: str, device: str, celsius: float,
                         alert: bool = False, location: str = None,
                         area: str = None, model: str = "MT10",
                         demo_id: str = None) -> dict:
    """Generate MT temperature reading event (Dashboard API / Sensor Alerts format)."""
    loc = location or MERAKI_MT_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    fahrenheit = (celsius * 9 / 5) + 32
    sensor_area = area or MERAKI_MT_DEVICES.get(device, {}).get("area", "Unknown")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "sensor_reading",
        "description": "Temperature reading",
        "category": "sensor",
        "deviceSerial": device,
        "deviceName": device,
        "sensor": {
            "name": sensor_area,
            "serial": device,
            "model": model
        },
        "trigger": {
            "metric": "temperature",
            "temperature": {
                "fahrenheit": round(fahrenheit, 1),
                "celsius": round(celsius, 1)
            }
        },
        "alertFired": alert
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mt_humidity_event(ts: str, device: str, value: float,
                      alert: bool = False, location: str = None,
                      area: str = None, model: str = "MT11",
                      demo_id: str = None) -> dict:
    """Generate MT humidity reading event (Dashboard API / Sensor Alerts format)."""
    loc = location or MERAKI_MT_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    sensor_area = area or MERAKI_MT_DEVICES.get(device, {}).get("area", "Unknown")

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "sensor_reading",
        "description": "Humidity reading",
        "category": "sensor",
        "deviceSerial": device,
        "deviceName": device,
        "sensor": {
            "name": sensor_area,
            "serial": device,
            "model": model
        },
        "trigger": {
            "metric": "humidity",
            "humidity": {
                "value": round(value, 1),
                "unit": "percent"
            }
        },
        "alertFired": alert
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mt_door_event(ts: str, device: str, status: str,
                  location: str = None, area: str = None,
                  model: str = "MT20", demo_id: str = None) -> dict:
    """Generate MT door sensor status change event (Dashboard API format)."""
    loc = location or MERAKI_MT_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    sensor_area = area or MERAKI_MT_DEVICES.get(device, {}).get("area", "Unknown")
    is_open = status.lower() in ["open", "opened"]

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "door_open" if is_open else "door_close",
        "description": "Door opened" if is_open else "Door closed",
        "category": "sensor",
        "deviceSerial": device,
        "deviceName": device,
        "sensor": {
            "name": sensor_area,
            "serial": device,
            "model": model
        },
        "trigger": {
            "metric": "door",
            "door": {
                "open": is_open
            }
        }
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


def mt_water_leak_event(ts: str, device: str, status: str,
                        location: str = None, area: str = None,
                        model: str = "MT14", demo_id: str = None) -> dict:
    """Generate MT water leak detection event (Dashboard API format)."""
    loc = location or MERAKI_MT_DEVICES.get(device, {}).get("location", "BOS")
    network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
    sensor_area = area or MERAKI_MT_DEVICES.get(device, {}).get("area", "Unknown")
    detected = status.lower() in ["detected", "wet", "leak"]

    event = {
        "occurredAt": ts,
        "networkId": network_id,
        "type": "water_detected" if detected else "water_clear",
        "description": "Water leak detected" if detected else "Water leak cleared",
        "category": "sensor",
        "deviceSerial": device,
        "deviceName": device,
        "sensor": {
            "name": sensor_area,
            "serial": device,
            "model": model
        },
        "trigger": {
            "metric": "water_leak",
            "waterDetection": {
                "detected": detected
            }
        },
        "alertFired": detected
    }
    if demo_id:
        event["demo_id"] = demo_id
    return event


# =============================================================================
# BASELINE GENERATORS
# =============================================================================

def generate_mx_baseline_hour(base_date: str, day: int, hour: int,
                              location: str, events_per_hour: int) -> List[dict]:
    """Generate baseline MX firewall/SD-WAN events for one hour at a location.

    Event types:
    - firewall: Standard firewall allow/deny events (60%)
    - url: URL logging events (22%)
    - vpn: VPN connectivity events (5%)
    - sdwan_health: SD-WAN health metrics (10%)
    - security_event: IDS, content filtering, AMP, client isolation (3%)
    """
    events = []
    mx_device = get_mx_for_location(location)
    mx_info = MERAKI_MX_DEVICES[mx_device]

    # Content filtering categories
    blocked_categories = [
        "Gambling", "Adult Content", "Malware", "Phishing",
        "Botnets", "Proxy Avoidance", "Social Networking",
        "Streaming Media", "File Sharing"
    ]

    # Malware threat names
    malware_threats = [
        "Win.Trojan.Agent", "Doc.Dropper.Generic", "Win.Ransomware.Locky",
        "JS.Downloader.Generic", "Win.Packed.Generic", "PDF.Exploit.CVE-2017-11882"
    ]

    # Client isolation reasons
    isolation_reasons = [
        "Multiple failed authentication attempts",
        "Malware activity detected",
        "Policy violation",
        "Excessive bandwidth usage",
        "ARP spoofing detected"
    ]

    for _ in range(events_per_hour):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = ts_meraki(base_date, day, hour, minute, second)

        event_type = random.choices(
            ["firewall", "url", "vpn", "sdwan_health", "security_event"],
            weights=[60, 22, 5, 10, 3]
        )[0]

        if event_type == "firewall":
            src = get_random_internal_ip(location)
            dst = get_random_external_ip()
            protocol = random.choice(["tcp", "udp"])
            sport = random.randint(1024, 65535)
            dport = random.choice([80, 443, 53, 8080, 3389, 22, 25, 587])
            action = "allow" if random.random() < 0.95 else "deny"
            events.append(mx_firewall_event(ts, mx_device, src, dst, protocol, sport, dport, action))

        elif event_type == "url":
            src_ip = get_random_internal_ip(location)
            src_port = random.randint(1024, 65535)
            dst_ip = get_random_external_ip()
            dst_port = random.choice([80, 443, 8080])
            mac = generate_mac()
            url = random.choice([
                f"http://www.example{random.randint(1,100)}.com/page",
                f"https://cdn.example.com/assets/{random.randint(1000,9999)}",
                f"https://api.service.com/v1/data",
                "https://www.google.com/search?q=test",
                "https://www.microsoft.com/en-us/",
                "https://github.com/",
                "https://slack.com/",
            ])
            events.append(mx_url_event(ts, mx_device, src_ip, src_port, dst_ip, dst_port, mac, url))

        elif event_type == "vpn":
            vpn_type = random.choice(["site-to-site", "client"])
            connectivity = random.choice(["true", "true", "true", "false"])
            peer_ip = get_random_external_ip() if vpn_type == "site-to-site" else None
            events.append(mx_vpn_event(ts, mx_device, vpn_type, connectivity, peer_ip))

        elif event_type == "sdwan_health":
            wan = random.choice(["wan1", "wan2"]) if mx_info.get("wan2_provider") else "wan1"
            latency = random.uniform(5, 50)
            jitter = random.uniform(0.5, 10)
            loss = random.uniform(0, 0.5) if random.random() < 0.9 else random.uniform(1, 5)
            status = "active" if loss < 2 else "degraded"
            events.append(mx_sdwan_health_event(ts, mx_device, wan, latency, jitter, loss, status))

        elif event_type == "security_event":
            # Sub-types of security events
            sec_subtype = random.choices(
                ["content_filtering", "amp_malware", "client_isolation"],
                weights=[60, 25, 15]
            )[0]

            client_ip = get_random_internal_ip(location)
            client_mac = generate_mac()

            if sec_subtype == "content_filtering":
                category = random.choice(blocked_categories)
                blocked_url = random.choice([
                    f"http://bad-site-{random.randint(1,999)}.tk/",
                    f"http://free-streaming.xyz/movie/{random.randint(100,999)}",
                    f"http://proxy-bypass.net/{random.randint(1,99)}",
                    "http://casino-online.ru/play",
                    f"http://torrent-downloads.cc/file{random.randint(1,9999)}",
                ])
                events.append(mx_content_filtering_event(
                    ts, mx_device, client_ip, client_mac, blocked_url, category, "blocked"
                ))

            elif sec_subtype == "amp_malware":
                threat_name = random.choice(malware_threats)
                file_name = random.choice([
                    f"invoice_{random.randint(1000,9999)}.doc",
                    f"report_{random.randint(100,999)}.pdf",
                    f"setup_{random.randint(1,99)}.exe",
                    "update.js",
                    f"image_{random.randint(1,99)}.jpg.exe",
                ])
                file_hash = ''.join(random.choices('0123456789abcdef', k=64))
                events.append(mx_amp_malware_event(
                    ts, mx_device, client_ip, client_mac, file_name, file_hash,
                    "malicious", threat_name
                ))

            elif sec_subtype == "client_isolation":
                reason = random.choice(isolation_reasons)
                events.append(mx_client_isolation_event(
                    ts, mx_device, client_ip, client_mac, reason, "isolated"
                ))

    return events


def generate_mr_baseline_hour(base_date: str, day: int, hour: int,
                              location: str, events_per_hour: int) -> List[dict]:
    """Generate baseline MR wireless events for one hour at a location."""
    events = []
    aps = get_aps_for_location(location)
    if not aps:
        return events

    location_users = get_users_by_location(location)

    for _ in range(events_per_hour):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = ts_meraki(base_date, day, hour, minute, second)

        ap = random.choice(aps)
        client_mac = generate_mac()
        ssid_info = random.choice(MERAKI_SSIDS)

        # Generate client IP based on location
        client_ip = get_random_internal_ip(location)

        # Event types - core wireless events only
        # Health metrics (signal quality, channel utilization, etc.) are now
        # generated separately in generate_mr_health_metrics() for consistent coverage
        event_type = random.choices(
            ["association", "disassociation", "8021x", "wpa"],
            weights=[40, 20, 25, 15]
        )[0]

        channel = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161])
        rssi = random.randint(20, 70)
        radio = 0 if channel <= 11 else 1

        # Get problem room info for degraded metrics
        problem = PROBLEM_AP_AREAS.get(ap, {})

        if event_type == "association":
            events.append(mr_association_event(
                ts, ap, client_mac, ssid_info["name"], channel, rssi, radio, ssid_info["vap"],
                client_ip=client_ip
            ))
        elif event_type == "disassociation":
            reason = random.choice([1, 3, 4, 8, 23])
            duration = random.uniform(60, 28800)
            events.append(mr_disassociation_event(
                ts, ap, client_mac, reason, duration, radio, ssid_info["vap"],
                client_ip=client_ip
            ))
        elif event_type == "8021x":
            if ssid_info["auth"] == "802.1X" and location_users:
                user = random.choice(location_users)
                identity = f"{user.username}@theFakeTshirtCompany.com"
                # Use the user's actual IP if available
                user_ip = user.ip if hasattr(user, 'ip') and user.ip else client_ip
                if random.random() < 0.95:
                    events.append(mr_8021x_success_event(
                        ts, ap, identity, client_mac, ssid_info["vap"], radio,
                        client_ip=user_ip
                    ))
                else:
                    events.append(mr_8021x_failure_event(
                        ts, ap, identity, client_mac, ssid_info["vap"], radio,
                        client_ip=user_ip
                    ))
        elif event_type == "wpa":
            if ssid_info["auth"] == "PSK":
                events.append(mr_wpa_auth_event(
                    ts, ap, client_mac, ssid_info["vap"], radio,
                    client_ip=client_ip
                ))

    return events


def generate_mr_health_metrics(base_date: str, day: int, hour: int,
                                location: str, interval: int = 5) -> List[dict]:
    """Generate periodic MR wireless health metrics for one hour at a location.

    This generates health data at the specified interval per AP, providing consistent
    coverage for signal quality, channel utilization, latency, and health scores.
    Output goes to a separate file with sourcetype cisco:meraki:wireless:health.

    Args:
        interval: Minutes between samples (5, 10, 15, or 30). Default: 5
                  5 min = 12 samples/hour, 15 min = 4 samples/hour, 30 min = 2 samples/hour
    """
    events = []
    aps = get_aps_for_location(location)
    if not aps:
        return events

    # Generate health reports at specified interval per AP
    for minute in range(0, 60, interval):
        for ap in aps:
            # Add small random offset within the 5-minute window
            actual_minute = minute + random.randint(0, 2)
            second = random.randint(0, 59)
            ts = ts_meraki(base_date, day, hour, actual_minute if actual_minute < 60 else 59, second)

            # Get problem room info for degraded metrics
            problem = PROBLEM_AP_AREAS.get(ap, {})
            ap_info = MERAKI_MR_DEVICES.get(ap, {})
            loc = ap_info.get("location", "BOS")
            network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")

            # Time-based activity factor
            is_business_hours = 8 <= hour <= 18
            activity_factor = 1.0 if is_business_hours else 0.3

            # Base metrics adjusted for problem rooms and time
            base_snr = random.randint(27, 42) if not problem else random.randint(18, 32)
            snr = max(10, base_snr + problem.get("snr_penalty", 0))
            rssi = random.randint(-65, -35) + problem.get("rssi_penalty", 0)

            # Channel and band
            channel = random.choice([1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161])
            band = "2.4" if channel <= 11 else "5"

            # Channel utilization
            base_util = 15 if not is_business_hours else 35
            util_total = random.uniform(base_util, base_util + 20) + problem.get("util_boost", 0)
            util_total = min(util_total, 95)  # Cap at 95%
            util_80211 = util_total * random.uniform(0.6, 0.85)
            util_non80211 = util_total - util_80211

            # Latency metrics
            base_latency = 15 if is_business_hours else 8
            latency_mult = 1.5 if problem else 1.0

            # Health scores
            base_perf = 85 if not problem else 65
            perf_score = random.randint(max(0, base_perf - 10), min(100, base_perf + 15))
            onboard_score = random.randint(80, 100)

            # Client count varies by time
            base_clients = 8 if is_business_hours else 2
            client_count = random.randint(max(0, base_clients - 3), base_clients + 5)

            # Create consolidated health metrics event
            event = {
                "occurredAt": ts,
                "networkId": network_id,
                "type": "wireless_health",
                "description": f"AP health metrics: {perf_score}%",
                "category": "wireless",
                "deviceSerial": ap,
                "deviceName": ap,
                "deviceModel": ap_info.get("model", "MR46"),
                "floor": ap_info.get("floor", 1),
                "area": ap_info.get("area", "Unknown"),
                "eventData": {
                    "healthScore": {
                        "performance": perf_score,
                        "onboarding": onboard_score
                    },
                    "signalQuality": {
                        "snr": snr,
                        "rssi": rssi
                    },
                    "channelUtilization": {
                        "band": band,
                        "channel": channel,
                        "utilizationTotal": round(util_total, 2),
                        "utilization80211": round(util_80211, 2),
                        "utilizationNon80211": round(util_non80211, 2)
                    },
                    "latencyStats": {
                        "backgroundTraffic": {"avg": round(random.uniform(base_latency * latency_mult, base_latency * 3 * latency_mult), 2)},
                        "bestEffortTraffic": {"avg": round(random.uniform(base_latency * 0.8 * latency_mult, base_latency * 2 * latency_mult), 2)},
                        "videoTraffic": {"avg": round(random.uniform(base_latency * 0.5 * latency_mult, base_latency * 1.5 * latency_mult), 2)},
                        "voiceTraffic": {"avg": round(random.uniform(base_latency * 0.3 * latency_mult, base_latency * latency_mult), 2)}
                    },
                    "clientCount": client_count
                }
            }

            # Add problem indicator if applicable
            if problem:
                event["eventData"]["knownIssue"] = problem.get("issue", "unknown")

            events.append(event)

    return events


def generate_ms_baseline_hour(base_date: str, day: int, hour: int,
                              location: str, events_per_hour: int) -> List[dict]:
    """Generate baseline MS switch events for one hour at a location."""
    events = []
    switches = get_switches_for_location(location)
    if not switches:
        return events

    for _ in range(events_per_hour):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = ts_meraki(base_date, day, hour, minute, second)

        switch = random.choice(switches)
        switch_info = MERAKI_MS_DEVICES[switch]
        port = random.randint(1, switch_info["ports"])

        event_type = random.choices(
            ["port_status", "stp", "8021x"],
            weights=[60, 20, 20]
        )[0]

        if event_type == "port_status":
            status = random.choices(["up", "down"], weights=[90, 10])[0]
            if status == "up":
                # Use speed notation from real Meraki logs (100fdx, 1000fdx, etc.)
                speed_val = random.choice([100, 1000, 10000])
                speed = f"{speed_val}fdx"
                prev_status = "down"
            else:
                speed = None
                prev_status = random.choice(["100fdx", "1000fdx", "10000fdx"])
            events.append(ms_port_status_event(ts, switch, port, status, speed, prev_status))
        elif event_type == "stp":
            role = random.choice(["designated", "root", "alternate", "backup"])
            state = random.choice(["forwarding", "blocking", "listening", "learning"])
            prev_role = random.choice(["designated", "root", "alternate", "backup"])
            events.append(ms_stp_event(ts, switch, port, role, state, prev_role))
        elif event_type == "8021x":
            identity = f"user{random.randint(1, 100)}@theFakeTshirtCompany.com"
            status = random.choices(["success", "failure"], weights=[90, 10])[0]
            events.append(ms_8021x_port_auth_event(ts, switch, port, identity, status))

    return events


def generate_ms_port_health(base_date: str, day: int, hour: int,
                            location: str, interval: int = 5) -> List[dict]:
    """Generate periodic MS switch port health metrics for one hour at a location.

    This generates port status data at the specified interval per switch (all ports),
    providing consistent coverage for speed, duplex, traffic, and PoE metrics.
    Output goes to a separate file with sourcetype cisco:meraki:switch:health.

    Based on Meraki Dashboard API: getDeviceSwitchPortsStatuses

    Args:
        interval: Minutes between samples (5, 10, 15, or 30). Default: 5
                  5 min = 12 samples/hour, 15 min = 4 samples/hour, 30 min = 2 samples/hour
    """
    events = []
    switches = get_switches_for_location(location)
    if not switches:
        return events

    # Generate health reports at specified interval per switch
    for minute in range(0, 60, interval):
        for switch in switches:
            switch_info = MERAKI_MS_DEVICES.get(switch, {})
            num_ports = switch_info.get("ports", 48)
            loc = switch_info.get("location", "BOS")
            network_id = NETWORK_IDS.get(loc, "N_FakeTShirtCo_BOS")
            role = switch_info.get("role", "access")

            # Add small random offset within the 5-minute window
            actual_minute = minute + random.randint(0, 2)
            second = random.randint(0, 59)
            ts = ts_meraki(base_date, day, hour, actual_minute if actual_minute < 60 else 59, second)

            # Time-based activity factor
            is_business_hours = 8 <= hour <= 18

            # Generate status for each port
            for port in range(1, num_ports + 1):
                # Determine port characteristics based on port number and switch role
                is_uplink = port <= 4 and role in ["core", "dc_core"]

                # Port status - most ports are connected during business hours
                if is_uplink:
                    # Uplinks are always connected
                    status = "Connected"
                    speed = "10 Gbps" if role == "dc_core" else "1 Gbps"
                elif is_business_hours:
                    # ~70% of access ports connected during business hours
                    status = random.choices(["Connected", "Disconnected"], weights=[70, 30])[0]
                    speed = random.choice(["100 Mbps", "1 Gbps"]) if status == "Connected" else None
                else:
                    # ~30% connected after hours
                    status = random.choices(["Connected", "Disconnected"], weights=[30, 70])[0]
                    speed = random.choice(["100 Mbps", "1 Gbps"]) if status == "Connected" else None

                # Build port status event
                event = {
                    "occurredAt": ts,
                    "networkId": network_id,
                    "type": "port_status_health",
                    "description": f"Port {port} status: {status}",
                    "category": "switch",
                    "deviceSerial": switch,
                    "deviceName": switch,
                    "deviceModel": switch_info.get("model", "MS225-48"),
                    "floor": switch_info.get("floor", 1),
                    "role": role,
                    "eventData": {
                        "portId": str(port),
                        "enabled": True,
                        "status": status,
                        "isUplink": is_uplink,
                    }
                }

                if status == "Connected":
                    # Add connection details
                    event["eventData"]["speed"] = speed
                    event["eventData"]["duplex"] = "full"

                    # Traffic data - higher for uplinks
                    if is_uplink:
                        base_traffic = random.randint(100000, 500000)  # 100-500 MB
                        traffic_kbps = random.randint(50000, 200000)   # 50-200 Mbps
                    else:
                        base_traffic = random.randint(1000, 50000)     # 1-50 MB
                        traffic_kbps = random.randint(100, 10000)      # 0.1-10 Mbps

                    event["eventData"]["usageInKb"] = {
                        "total": base_traffic,
                        "sent": int(base_traffic * random.uniform(0.4, 0.6)),
                        "recv": int(base_traffic * random.uniform(0.4, 0.6))
                    }
                    event["eventData"]["trafficInKbps"] = {
                        "total": traffic_kbps,
                        "sent": int(traffic_kbps * random.uniform(0.4, 0.6)),
                        "recv": int(traffic_kbps * random.uniform(0.4, 0.6))
                    }

                    # Client count (only for access ports)
                    if not is_uplink:
                        event["eventData"]["clientCount"] = random.randint(1, 3)

                    # PoE power usage (for access switches with PoE devices)
                    if role == "access" and random.random() < 0.3:  # 30% of ports have PoE devices
                        event["eventData"]["poe"] = {
                            "isAllocated": True
                        }
                        event["eventData"]["powerUsageInWh"] = round(random.uniform(2, 15), 2)

                    # Occasional warnings (rare)
                    if random.random() < 0.02:  # 2% chance
                        event["eventData"]["warnings"] = [random.choice([
                            "High utilization",
                            "Speed/duplex mismatch detected",
                            "STP topology change"
                        ])]

                events.append(event)

    return events


def generate_mv_baseline_hour(base_date: str, day: int, hour: int,
                              location: str, events_per_hour: int) -> List[dict]:
    """Generate baseline MV camera events for one hour at a location."""
    events = []
    cameras = get_cameras_for_location(location)
    if not cameras:
        return events

    for _ in range(events_per_hour):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = ts_meraki(base_date, day, hour, minute, second)

        camera = random.choice(cameras)
        cam_info = MERAKI_MV_DEVICES[camera]

        event_type = random.choices(
            ["motion", "person", "analytics", "health"],
            weights=[40, 30, 20, 10]
        )[0]

        if event_type == "motion":
            confidence = random.uniform(0.6, 0.99)
            events.append(mv_motion_event(
                ts, camera, cam_info["area"], confidence,
                location=location, area=cam_info["area"],
                model=cam_info.get("model", "MV12")
            ))
        elif event_type == "person":
            # Realistic person counts based on time
            if 8 <= hour <= 18:  # Business hours
                count = random.randint(1, 10)
            else:
                count = random.randint(0, 2)
            events.append(mv_person_detection_event(
                ts, camera, count, cam_info["area"],
                location=location, area=cam_info["area"],
                model=cam_info.get("model", "MV12")
            ))
        elif event_type == "analytics":
            people_count = random.randint(5, 50) if 8 <= hour <= 18 else random.randint(0, 5)
            dwell_time = random.uniform(30, 300)
            events.append(mv_analytics_event(
                ts, camera, people_count, dwell_time,
                location=location, area=cam_info["area"],
                model=cam_info.get("model", "MV12")
            ))
        elif event_type == "health":
            status = "healthy" if random.random() < 0.95 else "degraded"
            disk_usage = random.uniform(20, 80)
            events.append(mv_health_event(
                ts, camera, status, disk_usage, True,
                model=cam_info.get("model", "MV12")
            ))

    return events


def generate_mt_baseline_hour(base_date: str, day: int, hour: int,
                              location: str, events_per_hour: int) -> List[dict]:
    """Generate baseline MT sensor events for one hour at a location."""
    events = []
    sensors = get_sensors_for_location(location)
    if not sensors:
        return events

    # Group sensors by type
    temp_sensors = [s for s in sensors if MERAKI_MT_DEVICES[s]["type"] == "temperature"]
    humid_sensors = [s for s in sensors if MERAKI_MT_DEVICES[s]["type"] == "humidity"]
    door_sensors = [s for s in sensors if MERAKI_MT_DEVICES[s]["type"] == "door"]

    # Temperature readings every 5 minutes (12 per hour per sensor)
    for sensor in temp_sensors:
        sensor_info = MERAKI_MT_DEVICES[sensor]
        for interval in range(12):
            minute = interval * 5 + random.randint(0, 2)
            if minute >= 60:
                minute = 59
            second = random.randint(0, 59)
            ts = ts_meraki(base_date, day, hour, minute, second)
            # Normal server room temp: 18-24C
            temp = random.uniform(19, 23)
            alert = temp > 27  # Alert if too hot
            events.append(mt_temperature_event(
                ts, sensor, temp, alert=alert,
                location=location, area=sensor_info.get("area"),
                model=sensor_info.get("model", "MT10")
            ))

    # Humidity readings every 5 minutes
    for sensor in humid_sensors:
        sensor_info = MERAKI_MT_DEVICES[sensor]
        for interval in range(12):
            minute = interval * 5 + random.randint(0, 2)
            if minute >= 60:
                minute = 59
            second = random.randint(0, 59)
            ts = ts_meraki(base_date, day, hour, minute, second)
            # Normal humidity: 40-55%
            humidity = random.uniform(42, 52)
            alert = humidity < 30 or humidity > 70  # Alert if out of range
            events.append(mt_humidity_event(
                ts, sensor, humidity, alert=alert,
                location=location, area=sensor_info.get("area"),
                model=sensor_info.get("model", "MT11")
            ))

    # Door events - only during business hours, occasional
    for sensor in door_sensors:
        sensor_info = MERAKI_MT_DEVICES[sensor]
        if 7 <= hour <= 19:  # Business hours
            # Random door openings during the hour
            door_events_count = random.randint(0, 3)
            for _ in range(door_events_count):
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                ts = ts_meraki(base_date, day, hour, minute, second)
                events.append(mt_door_event(
                    ts, sensor, "open",
                    location=location, area=sensor_info.get("area"),
                    model=sensor_info.get("model", "MT20")
                ))

                # Close shortly after (use datetime to handle hour boundary)
                open_dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
                close_delay = timedelta(seconds=random.randint(30, 150))  # 30 sec to 2.5 min
                close_dt = open_dt + close_delay
                # Generate close event (always)
                close_ts = ts_meraki_from_dt(close_dt)
                events.append(mt_door_event(
                    close_ts, sensor, "closed",
                    location=location, area=sensor_info.get("area"),
                    model=sensor_info.get("model", "MT20")
                ))

    return events


def generate_meeting_room_sensors_hour(base_date: str, day: int, hour: int,
                                        location: str, is_meeting_active: bool = False,
                                        people_count: int = 0,
                                        meeting_duration: int = 0) -> List[dict]:
    """Generate sensor events for meeting rooms with correlation to Webex meetings.

    Uses shared meeting schedule (populated by Webex generator) to create
    door sensor and temperature sensor events that correlate with actual meetings:
    - Door opens 2-5 min before meeting starts
    - Temperature rises during meeting based on participants
    - Door opens when meeting ends
    """
    events = []

    # Get meeting room sensors
    room_sensors = get_meeting_room_sensors()

    # Filter sensors by location code (BOS, ATL, AUS)
    location_code = location
    location_sensors = {k: v for k, v in room_sensors.items() if v["location"] == location_code}

    # Get current hour datetime for comparison
    hour_start_dt = date_add(base_date, day).replace(hour=hour, minute=0, second=0, microsecond=0)
    hour_end_dt = hour_start_dt + timedelta(hours=1)

    for sensor_id, sensor_info in location_sensors.items():
        room_config = sensor_info.get("room_config", {})
        room_name = sensor_info.get("room_name", "Unknown")
        sensor_type = sensor_info["type"]

        # Get meetings for this room from shared schedule
        room_meetings = get_meetings_for_room(location_code, room_name)

        # Filter to meetings active during this hour (exclude ghosts)
        hour_meetings = [
            m for m in room_meetings
            if not m.is_ghost and m.start_time < hour_end_dt and m.end_time > hour_start_dt
        ]

        # Generate walk-in meetings for unbooked rooms (10% probability)
        # Only try to generate if no scheduled meetings for this hour
        # Note: generate_walkin_meeting internally calls should_generate_walkin which handles the probability
        if not hour_meetings:
            generate_walkin_meeting(location_code, room_name, hour_start_dt, hour)
            # Walk-in was added to schedule by generate_walkin_meeting (if probability passed)

        # Get all walk-in meetings for this hour (could have been generated previously)
        walkin_meetings = get_walkins_for_hour(location_code, room_name, hour_start_dt, hour)

        # Check for after-hours activity
        after_hours_activity = None
        if should_generate_after_hours(location_code, room_name, day, hour):
            after_hours_activity = generate_after_hours_activity(
                location_code, room_name, hour_start_dt, hour
            )

        # Combine all activity sources
        all_activity = hour_meetings + walkin_meetings
        if after_hours_activity:
            all_activity.append(after_hours_activity)

        # Temperature sensors - report every 5 minutes
        if sensor_type == "temperature":
            for interval in range(12):  # 12 intervals of 5 min per hour
                minute = interval * 5 + random.randint(0, 2)
                if minute >= 60:
                    minute = 59
                second = random.randint(0, 59)
                ts = ts_meraki(base_date, day, hour, minute, second)
                current_dt = hour_start_dt.replace(minute=minute, second=second)

                # Find if any activity is happening at this moment
                active_meeting = None
                for activity in all_activity:
                    if activity.start_time <= current_dt <= activity.end_time:
                        active_meeting = activity
                        break

                if active_meeting:
                    # Calculate duration so far
                    duration_so_far = int((current_dt - active_meeting.start_time).total_seconds() / 60)
                    temp = calculate_room_temperature(
                        room_config, hour,
                        people_count=active_meeting.participant_count,
                        meeting_duration_mins=duration_so_far
                    )
                else:
                    # No activity - baseline temp with sun effect
                    temp = calculate_room_temperature(room_config, hour, people_count=0, meeting_duration_mins=0)

                # Determine if alert
                alert = temp > 27

                events.append(mt_temperature_event(
                    ts, sensor_id, temp, alert=alert,
                    location=location_code, area=room_name,
                    model=sensor_info.get("model", "MT10")
                ))

        # Door sensors - use meeting schedule for correlated events
        elif sensor_type == "door":
            # Business hours door events
            if 7 <= hour <= 19:
                # Get door events from scheduled meetings
                for meeting in hour_meetings:
                    door_events_list = get_door_events_for_meeting(meeting)

                    # Filter door events to this hour and add them
                    for door_event in door_events_list:
                        event_dt = door_event["time"]
                        # Check if event falls within this hour
                        if hour_start_dt <= event_dt < hour_end_dt:
                            ts = ts_meraki_from_dt(event_dt)
                            events.append(mt_door_event(
                                ts, sensor_id, door_event["status"],
                                location=location_code, area=room_name,
                                model=sensor_info.get("model", "MT20")
                            ))

                # Walk-in meetings - door opens without scheduled meeting
                for walkin in walkin_meetings:
                    # Arrival
                    arrival_ts = ts_meraki_from_dt(walkin.start_time)
                    events.append(mt_door_event(
                        arrival_ts, sensor_id, "open",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))
                    close_dt = walkin.start_time + timedelta(seconds=random.randint(30, 90))
                    events.append(mt_door_event(
                        ts_meraki_from_dt(close_dt), sensor_id, "closed",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

                    # Departure
                    departure_ts = ts_meraki_from_dt(walkin.end_time)
                    events.append(mt_door_event(
                        departure_ts, sensor_id, "open",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))
                    close_dt = walkin.end_time + timedelta(seconds=random.randint(20, 60))
                    events.append(mt_door_event(
                        ts_meraki_from_dt(close_dt), sensor_id, "closed",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

                # Random background activity (bathroom breaks, checking room)
                random_door_events_count = random.randint(0, 2)
                for _ in range(random_door_events_count):
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    ts = ts_meraki(base_date, day, hour, minute, second)
                    events.append(mt_door_event(
                        ts, sensor_id, "open",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

                    # Close shortly after
                    open_dt = hour_start_dt.replace(minute=minute, second=second)
                    close_delay = timedelta(seconds=random.randint(30, 150))
                    close_dt = open_dt + close_delay
                    close_ts = ts_meraki_from_dt(close_dt)
                    events.append(mt_door_event(
                        close_ts, sensor_id, "closed",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

            # After-hours door activity
            if after_hours_activity:
                if hour == 20:  # Arrival hour
                    arrival_ts = ts_meraki_from_dt(after_hours_activity.start_time)
                    events.append(mt_door_event(
                        arrival_ts, sensor_id, "open",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))
                    close_dt = after_hours_activity.start_time + timedelta(seconds=random.randint(30, 90))
                    events.append(mt_door_event(
                        ts_meraki_from_dt(close_dt), sensor_id, "closed",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

                if hour == 22:  # Departure hour
                    departure_ts = ts_meraki_from_dt(after_hours_activity.end_time)
                    events.append(mt_door_event(
                        departure_ts, sensor_id, "open",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))
                    close_dt = after_hours_activity.end_time + timedelta(seconds=random.randint(20, 60))
                    events.append(mt_door_event(
                        ts_meraki_from_dt(close_dt), sensor_id, "closed",
                        location=location_code, area=room_name,
                        model=sensor_info.get("model", "MT20")
                    ))

    return events


def generate_meeting_room_cameras_hour(base_date: str, day: int, hour: int,
                                        location: str) -> List[dict]:
    """Generate camera events for meeting rooms with correlation to Webex meetings.

    Meeting room cameras detect:
    - Person entry/exit around meeting times
    - People count during meetings
    - Motion when room is in use
    - Empty room during ghost meetings (no-shows)

    Uses shared meeting schedule for correlation with Webex events.
    """
    events = []

    # Parse base_date for meeting schedule lookup
    from datetime import datetime
    target_date = datetime.strptime(base_date, "%Y-%m-%d")
    target_date = target_date.replace(hour=hour, minute=0, second=0, microsecond=0)

    # Get meeting room cameras
    room_cameras = get_meeting_room_cameras()

    # Filter by location
    location_cameras = {k: v for k, v in room_cameras.items() if v["location"] == location}

    for camera_id, camera_info in location_cameras.items():
        room_config = camera_info.get("room_config", {})
        room_name = camera_info.get("room_name", "Unknown")
        capacity = room_config.get("capacity", 10)
        location_code = camera_info.get("location", location)

        # Check for actual meetings from shared schedule
        actual_meetings = get_meetings_for_hour(location_code, room_name, target_date, hour)

        # Check for ghost meetings (no-shows)
        ghost_meetings = get_ghost_meetings_for_hour(location_code, room_name, target_date, hour)

        # Handle actual meetings - people present
        for meeting in actual_meetings:
            meeting_people_count = meeting.participant_count
            cam_model = camera_info.get("model", "MV12")

            # Person detection when people arrive
            if meeting.start_time.hour == hour or (meeting.start_time.hour == hour - 1 and meeting.start_time.minute >= 55):
                # Arrival detection - a few minutes before meeting starts
                arrival_offset = random.randint(-5, 2)
                arrival_minute = (meeting.start_time.minute + arrival_offset) % 60
                ts_arrival = ts_meraki(base_date, day, hour, arrival_minute, random.randint(0, 59))
                events.append(mv_person_detection_event(
                    ts_arrival, camera_id, meeting_people_count, room_name,
                    location=location_code, area=room_name, model=cam_model
                ))

            # Motion during meeting (every 10-15 min)
            motion_intervals = random.randint(2, 4)
            for _ in range(motion_intervals):
                motion_minute = random.randint(5, 55)
                ts_motion = ts_meraki(base_date, day, hour, motion_minute, random.randint(0, 59))
                events.append(mv_motion_event(
                    ts_motion, camera_id, room_name, random.uniform(0.6, 0.95),
                    location=location_code, area=room_name, model=cam_model
                ))

            # Room analytics (people count during meeting)
            analytics_minute = random.randint(10, 45)
            ts_analytics = ts_meraki(base_date, day, hour, analytics_minute, random.randint(0, 59))
            meeting_duration = (meeting.end_time - meeting.start_time).total_seconds()
            events.append(mv_analytics_event(
                ts_analytics, camera_id, meeting_people_count, meeting_duration,
                location=location_code, area=room_name, model=cam_model
            ))

        # Handle ghost meetings - room booked but empty
        cam_model = camera_info.get("model", "MV12")
        for ghost in ghost_meetings:
            # Room analytics showing empty room during scheduled meeting time
            analytics_minute = random.randint(10, 45)
            ts_analytics = ts_meraki(base_date, day, hour, analytics_minute, random.randint(0, 59))

            # Generate analytics event showing ZERO people (ghost meeting indicator)
            events.append(mv_analytics_event(
                ts_analytics, camera_id, 0, 0,  # people_count=0, dwell_time=0
                location=location_code, area=room_name, model=cam_model
            ))

            # Occasional very brief motion (cleaning staff, someone peeking in)
            if random.random() < 0.15:
                brief_minute = random.randint(0, 59)
                ts_brief = ts_meraki(base_date, day, hour, brief_minute, random.randint(0, 59))
                events.append(mv_motion_event(
                    ts_brief, camera_id, room_name, random.uniform(0.2, 0.4),  # Low confidence
                    location=location_code, area=room_name, model=cam_model
                ))

        # Handle walk-in meetings (no Webex booking)
        walkins = get_walkins_for_hour(location_code, room_name, target_date, hour)
        cam_model = camera_info.get("model", "MV12")
        for walkin in walkins:
            walkin_people_count = walkin.participant_count  # Usually 1-4 for walk-ins

            # Person detection when people arrive
            if walkin.start_time.hour == hour:
                arrival_minute = walkin.start_time.minute
                ts_arrival = ts_meraki(base_date, day, hour, arrival_minute, random.randint(0, 59))
                events.append(mv_person_detection_event(
                    ts_arrival, camera_id, walkin_people_count, room_name,
                    location=location_code, area=room_name, model=cam_model
                ))

            # Motion during walk-in (shorter meetings, less motion events)
            if random.random() < 0.7:
                # Calculate valid minute range for motion
                start_min = walkin.start_time.minute if walkin.start_time.hour == hour else 0
                end_min = walkin.end_time.minute if walkin.end_time.hour == hour else 59
                # Ensure valid range (start <= end)
                if start_min > end_min:
                    start_min, end_min = end_min, start_min
                if start_min == end_min:
                    end_min = min(start_min + 10, 59)
                motion_minute = random.randint(start_min, end_min)
                ts_motion = ts_meraki(base_date, day, hour, motion_minute, random.randint(0, 59))
                events.append(mv_motion_event(
                    ts_motion, camera_id, room_name, random.uniform(0.6, 0.9),
                    location=location_code, area=room_name, model=cam_model
                ))

            # Room analytics for walk-in
            if walkin.start_time.hour == hour:
                analytics_minute = min(walkin.start_time.minute + random.randint(5, 15), 59)
                ts_analytics = ts_meraki(base_date, day, hour, analytics_minute, random.randint(0, 59))
                duration = (walkin.end_time - walkin.start_time).total_seconds()
                events.append(mv_analytics_event(
                    ts_analytics, camera_id, walkin_people_count, duration,
                    location=location_code, area=room_name, model=cam_model
                ))

        # Handle after-hours activity (legitimate overtime)
        cam_model = camera_info.get("model", "MV12")
        if should_generate_after_hours(location_code, room_name, day, hour):
            after_hours_activity = generate_after_hours_activity(location_code, room_name, target_date, hour)
            if after_hours_activity and after_hours_activity.start_time.hour == hour:
                after_hours_people = after_hours_activity.participant_count  # Usually 1-2

                # Person detection when someone arrives to work late
                arrival_minute = after_hours_activity.start_time.minute
                ts_arrival = ts_meraki(base_date, day, hour, arrival_minute, random.randint(0, 59))
                events.append(mv_person_detection_event(
                    ts_arrival, camera_id, after_hours_people, room_name,
                    location=location_code, area=room_name, model=cam_model
                ))

                # Motion during after-hours work
                for _ in range(random.randint(1, 3)):
                    motion_minute = random.randint(arrival_minute, 59)
                    ts_motion = ts_meraki(base_date, day, hour, motion_minute, random.randint(0, 59))
                    events.append(mv_motion_event(
                        ts_motion, camera_id, room_name, random.uniform(0.5, 0.85),
                        location=location_code, area=room_name, model=cam_model
                    ))

                # Analytics showing 1-2 people working late
                analytics_minute = min(arrival_minute + random.randint(10, 30), 59)
                ts_analytics = ts_meraki(base_date, day, hour, analytics_minute, random.randint(0, 59))
                duration = (after_hours_activity.end_time - after_hours_activity.start_time).total_seconds()
                events.append(mv_analytics_event(
                    ts_analytics, camera_id, after_hours_people, duration,
                    location=location_code, area=room_name, model=cam_model
                ))

        # No scheduled meetings - random background activity
        cam_model = camera_info.get("model", "MV12")
        if not actual_meetings and not ghost_meetings and not walkins:
            # Business hours activity
            if 8 <= hour <= 18:
                # Occasional pass-by when room is empty
                if random.random() < 0.2:
                    minute = random.randint(0, 59)
                    ts = ts_meraki(base_date, day, hour, minute, random.randint(0, 59))
                    events.append(mv_motion_event(
                        ts, camera_id, room_name, random.uniform(0.4, 0.7),
                        location=location_code, area=room_name, model=cam_model
                    ))

                    # Occasionally detect 1-2 people checking the room
                    if random.random() < 0.5:
                        events.append(mv_person_detection_event(
                            ts, camera_id, random.randint(1, 2), room_name,
                            location=location_code, area=room_name, model=cam_model
                        ))

            # Off-hours - very rare activity
            elif 6 <= hour <= 20:
                if random.random() < 0.05:  # 5% chance of activity
                    minute = random.randint(0, 59)
                    ts = ts_meraki(base_date, day, hour, minute, random.randint(0, 59))
                    events.append(mv_motion_event(
                        ts, camera_id, room_name, random.uniform(0.5, 0.8),
                        location=location_code, area=room_name, model=cam_model
                    ))

        # Camera health check (every few hours)
        if hour in [6, 12, 18]:
            health_ts = ts_meraki(base_date, day, hour, random.randint(0, 10), random.randint(0, 59))
            status = "healthy" if random.random() < 0.98 else "degraded"
            disk_usage = random.uniform(30, 70)
            events.append(mv_health_event(
                health_ts, camera_id, status, disk_usage, True,
                model=camera_info.get("model", "MV12")
            ))

    return events


# =============================================================================
# SD-WAN VPN TUNNEL EVENTS
# =============================================================================

def generate_sdwan_tunnel_events(base_date: str, day: int) -> List[dict]:
    """Generate SD-WAN VPN tunnel status events."""
    events = []

    # Tunnel status check every hour
    for hour in range(24):
        for mx_a, mx_b in SDWAN_PEERS:
            minute = random.randint(0, 5)
            second = random.randint(0, 59)
            ts = ts_meraki(base_date, day, hour, minute, second)

            # Tunnels are usually up
            if random.random() < 0.98:
                uptime = day * 86400 + hour * 3600 + random.randint(0, 3600)
                events.append(mx_vpn_tunnel_event(ts, mx_a, mx_b, "up", uptime))
            else:
                # Occasional tunnel flap
                events.append(mx_vpn_tunnel_event(ts, mx_a, mx_b, "down"))
                # Comes back up
                ts_up = ts_meraki(base_date, day, hour, minute + random.randint(1, 5), random.randint(0, 59))
                events.append(mx_vpn_tunnel_event(ts_up, mx_a, mx_b, "up", random.randint(60, 300)))

    return events


# =============================================================================
# SCENARIO EVENTS
# =============================================================================

def generate_ids_alert(base_date: str, day: int, hour: int, location: str) -> List[dict]:
    """Generate IDS alert events (for attack scenarios)."""
    events = []

    # Only generate during specific attack phases (days 4-13)
    if day < 4 or day > 13:
        return events

    # Low probability per hour
    if random.random() > 0.15:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_meraki(base_date, day, hour, minute, second)

    # Get appropriate MX for the scenario
    # Initial compromise in Atlanta, then lateral to Boston
    if day >= 4 and day <= 6:
        mx_device = "MX-ATL-01"
        src_ip = THREAT_IP
        dst_ip = JESSICA_WS_IP
        direction = "ingress"
    elif day >= 7 and day <= 10:
        mx_device = "MX-BOS-01"
        src_ip = JESSICA_WS_IP  # Lateral movement from Jessica's machine
        dst_ip = COMP_WS_IP
        direction = "ingress"
    else:
        mx_device = get_mx_for_location(location)
        src_ip = get_random_internal_ip(location)
        dst_ip = get_random_external_ip()
        direction = "egress"

    signature = random.choice(IDS_SIGNATURES)
    src_port = random.randint(1024, 65535)
    # Use port matched to signature type
    dst_port = random.choice(signature.get("ports", [80, 443]))

    event = mx_ids_event(ts, mx_device, signature, src_ip, src_port, dst_ip, dst_port,
                         "tcp", direction, demo_id="exfil")
    events.append(event)

    return events


def generate_rogue_ap_detection(base_date: str, day: int, hour: int, location: str) -> List[dict]:
    """Generate rogue AP detection events."""
    events = []

    if hour < 8 or hour > 18:
        return events
    if random.random() > 0.02:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_meraki(base_date, day, hour, minute, second)

    aps = get_aps_for_location(location)
    if not aps:
        return events

    ap = random.choice(aps)
    rogue_ssid = random.choice(["Free_WiFi", "FakeTShirtCo-Corp", "Guest", "linksys", "xfinitywifi"])
    rogue_bssid = generate_mac()
    channel = random.choice([1, 6, 11])
    rssi = random.randint(15, 40)

    events.append(mr_rogue_ssid_event(ts, ap, rogue_ssid, rogue_bssid, channel, rssi))

    return events


def generate_after_hours_motion(base_date: str, day: int, hour: int, include_exfil: bool) -> List[dict]:
    """Generate suspicious after-hours motion events for MDF/DC cameras."""
    events = []

    # Only during off-hours and during exfil scenario days
    if hour >= 7 and hour <= 20:
        return events
    if not include_exfil or day < 10 or day > 13:
        return events

    # Low probability
    if random.random() > 0.1:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_meraki(base_date, day, hour, minute, second)

    # Target server room cameras
    suspicious_cameras = ["CAM-BOS-3F-03", "CAM-BOS-3F-04", "CAM-ATL-DC-03"]
    camera = random.choice(suspicious_cameras)

    if camera in MERAKI_MV_DEVICES:
        cam_info = MERAKI_MV_DEVICES[camera]
        events.append(mv_motion_event(
            ts, camera, cam_info["area"], random.uniform(0.8, 0.99),
            location=cam_info.get("location"), area=cam_info["area"],
            model=cam_info.get("model", "MV12"), demo_id="exfil"
        ))
        events.append(mv_person_detection_event(
            ts, camera, 1, cam_info["area"],
            location=cam_info.get("location"), area=cam_info["area"],
            model=cam_info.get("model", "MV12"), demo_id="exfil"
        ))

    return events


def generate_dc_temp_spike(base_date: str, day: int, hour: int, demo_id: str = None) -> List[dict]:
    """Generate temperature spike events for ops scenario."""
    events = []

    # This could be linked to a memory_leak or cpu_runaway scenario
    # For now, just occasional spikes
    if random.random() > 0.01:
        return events

    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    ts = ts_meraki(base_date, day, hour, minute, second)

    # Pick a DC temp sensor
    dc_temp_sensors = [s for s in MERAKI_MT_DEVICES.keys() if "DC-TEMP" in s or "MDF-TEMP" in s]
    if not dc_temp_sensors:
        return events

    sensor = random.choice(dc_temp_sensors)
    sensor_info = MERAKI_MT_DEVICES[sensor]
    # Elevated temperature
    temp = random.uniform(26, 30)
    alert = temp > 27  # Alert if too hot

    events.append(mt_temperature_event(
        ts, sensor, temp, alert=alert,
        location=sensor_info.get("location"), area=sensor_info.get("area"),
        model=sensor_info.get("model", "MT10"), demo_id=demo_id
    ))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_meraki_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
    health_interval: int = 5,
    mr_health_enabled: bool = True,
    ms_health_enabled: bool = True,
) -> int:
    """Generate Cisco Meraki logs for all locations.

    Uses Meraki Dashboard API JSON format (from getNetworkEvents).
    Sourcetype: cisco:meraki:events

    Args:
        health_interval: Minutes between health metric samples (5, 10, 15, or 30)
        mr_health_enabled: Generate MR AP health metrics (default: True)
        ms_health_enabled: Generate MS port health metrics (default: True)

    Writes separate JSON files for each device type:
    - meraki_mx_appliance.json - MX security appliances / SD-WAN
    - meraki_mr_wireless.json - MR access points (wireless events)
    - meraki_mr_health.json - MR AP health metrics (configurable interval)
                             Sourcetype: cisco:meraki:wireless:health
    - meraki_ms_switch.json - MS switches (events)
    - meraki_ms_health.json - MS switch port health (configurable interval)
                             Sourcetype: cisco:meraki:switch:health
    - meraki_mv_camera.json - MV smart cameras
    - meraki_mt_sensor.json - MT sensors (temp, door, humidity)
    """

    # Output paths for each device type
    if output_file:
        output_dir = Path(output_file).parent
    else:
        # get_output_path returns full path, so use dummy filename and get parent
        output_dir = get_output_path("network", "dummy.log").parent
    output_dir.mkdir(parents=True, exist_ok=True)

    output_files = {
        "mx": output_dir / "meraki_mx_appliance.json",     # Dashboard API JSON
        "mr": output_dir / "meraki_mr_wireless.json",      # Dashboard API JSON
        "mr_health": output_dir / "meraki_mr_health.json", # Periodic AP health metrics
        "ms": output_dir / "meraki_ms_switch.json",        # Dashboard API JSON
        "ms_health": output_dir / "meraki_ms_health.json", # Periodic port health metrics
        "mv": output_dir / "meraki_mv_camera.json",        # Dashboard API JSON
        "mt": output_dir / "meraki_mt_sensor.json",        # Dashboard API JSON
    }

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_exfil = "exfil" in active_scenarios
    include_ransomware = "ransomware_attempt" in active_scenarios

    # Initialize scenarios
    time_utils = TimeUtils(start_date)
    ransomware_scenario = None
    if include_ransomware:
        ransomware_scenario = RansomwareAttemptScenario(demo_id_enabled=True)

    # Base events per peak hour (scale affects volume)
    # Per location scaling
    location_scale = {
        "BOS": 1.0,   # Largest office
        "ATL": 0.5,   # Medium office
        "AUS": 0.4,   # Smallest office
    }

    if not quiet:
        # Calculate estimated health events
        mr_health_per_day = (36 * (60 // health_interval) * 24) if mr_health_enabled else 0
        ms_health_per_day = (440 * (60 // health_interval) * 24) if ms_health_enabled else 0
        total_health = mr_health_per_day + ms_health_per_day
        health_status = []
        if mr_health_enabled:
            health_status.append(f"MR:{mr_health_per_day:,}/day")
        if ms_health_enabled:
            health_status.append(f"MS:{ms_health_per_day:,}/day")
        health_str = ", ".join(health_status) if health_status else "disabled"

        print("=" * 70, file=sys.stderr)
        print(f"  Cisco Meraki Generator - Multi-Site Edition", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Locations: {', '.join(LOCATIONS.keys())}", file=sys.stderr)
        print(f"  MX: {len(MERAKI_MX_DEVICES)} | MR: {len(MERAKI_MR_DEVICES)} | MS: {len(MERAKI_MS_DEVICES)}", file=sys.stderr)
        print(f"  MV: {len(MERAKI_MV_DEVICES)} | MT: {len(MERAKI_MT_DEVICES)}", file=sys.stderr)
        print(f"  Health: {health_interval}min interval ({health_str})", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_dir}/meraki_*.json (7 JSON files)", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Separate event lists per device type
    mx_events = []         # MX firewall/SD-WAN
    mr_events = []         # MR wireless events (associations, auth, etc.)
    mr_health_events = []  # MR periodic AP health metrics
    ms_events = []         # MS switch events
    ms_health_events = []  # MS periodic port health metrics
    mv_events = []         # MV camera
    mt_events = []         # MT sensor

    for day in range(days):
        dt = date_add(start_date, day)
        is_wknd = is_weekend(dt)

        if not quiet:
            print(f"  [Meraki] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        # Generate SD-WAN tunnel events for the day (MX events)
        mx_events.extend(generate_sdwan_tunnel_events(start_date, day))

        for hour in range(24):
            activity = get_hour_activity_level(hour, is_wknd)
            hour_mult = activity / 100.0

            for location, loc_scale in location_scale.items():
                # Calculate events for this hour at this location
                mx_count = int(80 * scale * loc_scale * hour_mult)
                mr_count = int(50 * scale * loc_scale * hour_mult)
                ms_count = int(15 * scale * loc_scale * hour_mult)
                mv_count = int(20 * scale * loc_scale * hour_mult)
                mt_count = 1  # Sensors report regularly regardless of activity

                # Generate baseline events - each goes to its respective list
                mx_events.extend(generate_mx_baseline_hour(start_date, day, hour, location, mx_count))
                mr_events.extend(generate_mr_baseline_hour(start_date, day, hour, location, mr_count))
                if mr_health_enabled:
                    mr_health_events.extend(generate_mr_health_metrics(start_date, day, hour, location, health_interval))
                ms_events.extend(generate_ms_baseline_hour(start_date, day, hour, location, ms_count))
                if ms_health_enabled:
                    ms_health_events.extend(generate_ms_port_health(start_date, day, hour, location, health_interval))
                mv_events.extend(generate_mv_baseline_hour(start_date, day, hour, location, mv_count))
                mt_events.extend(generate_mt_baseline_hour(start_date, day, hour, location, mt_count))

                # Generate meeting room sensor events (correlated with Webex) - MT events
                mt_events.extend(generate_meeting_room_sensors_hour(start_date, day, hour, location))

                # Generate meeting room camera events (correlated with meetings) - MV events
                mv_events.extend(generate_meeting_room_cameras_hour(start_date, day, hour, location))

                # Generate scenario events
                if include_exfil:
                    # IDS alerts go to MX
                    mx_events.extend(generate_ids_alert(start_date, day, hour, location))
                    # After-hours motion detection goes to MV
                    mv_events.extend(generate_after_hours_motion(start_date, day, hour, include_exfil))

                # Always generate these (rare events)
                # Rogue AP detection goes to MR
                mr_events.extend(generate_rogue_ap_detection(start_date, day, hour, location))
                # DC temp spike goes to MT
                mt_events.extend(generate_dc_temp_spike(start_date, day, hour))

                # Ransomware scenario - returns dict with mx and mr events (Austin only)
                if include_ransomware and ransomware_scenario and location == "AUS":
                    ransomware_events = ransomware_scenario.meraki_hour(day, hour, time_utils)
                    mx_events.extend(ransomware_events.get("mx", []))
                    mr_events.extend(ransomware_events.get("mr", []))

        if not quiet:
            print(f"  [Meraki] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Sort and write each device type to its file (all JSON now)
    def sort_key_json(event: dict) -> str:
        """Extract timestamp from JSON event for sorting.
        Uses occurredAt (Dashboard API format) or ts (IDS events)."""
        return event.get("occurredAt", event.get("ts", ""))

    # All devices now use JSON format (Dashboard API)
    all_events = {
        "mx": mx_events,
        "mr": mr_events,
        "mr_health": mr_health_events,
        "ms": ms_events,
        "ms_health": ms_health_events,
        "mv": mv_events,
        "mt": mt_events,
    }

    total_events = 0

    # Write all files as JSON (one JSON object per line)
    for device_type, events in all_events.items():
        events.sort(key=sort_key_json)
        output_path = output_files[device_type]
        with open(output_path, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")
        total_events += len(events)

    if not quiet:
        print(f"  [Meraki] Complete! {total_events:,} events written to 7 JSON files:", file=sys.stderr)
        for device_type in ["mx", "mr", "mr_health", "ms", "ms_health", "mv", "mt"]:
            print(f"    - {output_files[device_type].name}: {len(all_events[device_type]):,} events", file=sys.stderr)

    return total_events


def main():
    parser = argparse.ArgumentParser(description="Generate Cisco Meraki logs (Multi-Site)")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", "-o")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_meraki_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_file=args.output, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
