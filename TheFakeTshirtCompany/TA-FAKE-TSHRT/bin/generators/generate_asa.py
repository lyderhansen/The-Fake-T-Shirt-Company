#!/usr/bin/env python3
"""
Cisco ASA Firewall Log Generator.
Generates realistic ASA syslog events with natural volume variation.

The ASA (FW-EDGE-01) is the PERIMETER firewall for the entire organization.
ALL external traffic flows through this firewall, making it critical for
detecting exfiltration, C2 callbacks, and external attacks.

Network Architecture:
    INTERNET
       │
       ▼
    FW-EDGE-01 (ASA 5525-X) ◄── This generator
       │
    ┌──┴──┐
    │     │
   DMZ  Internal
         │
    ┌────┼────┐
  BOS  ATL  AUS  (via Meraki SD-WAN)

Includes:
- TCP sessions (Built + Teardown with correlated connection IDs)
- DNS queries (external + internal DNS via DCs)
- NAT translations
- VPN sessions
- SSL handshakes
- Admin commands
- Background scan noise (external port scans DENIED)
- Internal ACL deny events (misconfigured workstations, rogue traffic)
- DC-specific traffic (Kerberos 88, LDAP 389/636, DNS 53, SMB 445)
- New server traffic (SAP, BASTION)
- ICMP baseline (monitoring health checks)
- Hub-spoke site-to-site (BOS=70% hub, ATL/AUS spokes)
- Operational events (maintenance, capacity, interface flapping, cert warnings)
- C2 beacon traffic (for exfil scenario)
- Large data transfer detection (for exfil scenario)

Usage:
    python3 generate_asa.py --days=14 --scale=1.0 --scenarios=exfil
"""

import argparse
import json
import random
import sys
from pathlib import Path
from typing import List, Dict, TextIO

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import Config, DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import TimeUtils, ts_syslog, date_add, calc_natural_events
from shared.company import Company, ASA_PERIMETER, DNS_SERVERS, THREAT_IP, TENANT
from shared.company import (
    ASA_WEB_PORTS, ASA_SCAN_PORTS, ASA_TEARDOWN_REASONS, ASA_EXT_ACLS, ASA_INT_ACLS,
    VPN_USERS, USERS, SERVERS, INTERNAL_DNS_SERVERS,
    get_internal_ip, get_us_ip, get_external_ip, get_dmz_ip, get_world_ip,
)

# Use the perimeter ASA hostname consistently
ASA_HOSTNAME = ASA_PERIMETER["hostname"]  # FW-EDGE-01

# Syslog PRI calculation: PRI = Facility × 8 + Severity
# Cisco ASA uses local4 (facility 20)
ASA_FACILITY = 20  # local4

def asa_pri(severity: int) -> str:
    """
    Calculate syslog PRI header for ASA logs.

    Cisco ASA severity levels:
    - 6 = info (%ASA-6-*)
    - 5 = notice (%ASA-5-*)
    - 4 = warning (%ASA-4-*)
    - 3 = error (%ASA-3-*)
    - 1 = alert (%ASA-1-*)

    Returns: "<PRI>" string, e.g., "<166>" for local4.info
    """
    pri = ASA_FACILITY * 8 + severity
    return f"<{pri}>"

# Import scenarios
from scenarios.security import ExfilScenario, RansomwareAttemptScenario
from scenarios.ops import MemoryLeakScenario, CpuRunawayScenario
from scenarios.network import FirewallMisconfigScenario, CertificateExpiryScenario, DdosAttackScenario
from scenarios.registry import expand_scenarios, source_needed_for_scenarios


# =============================================================================
# VPN POOL (cached IPs per user for consistency)
# =============================================================================

VPN_POOL = {}

def init_vpn_pool():
    """Initialize VPN IP pool using deterministic VPN IPs from company.py.

    Each VPN-enabled user gets their deterministic vpn_ip (10.250.0.x) plus
    a random "connecting from" external IP. The vpn_ip is shared across
    generators for cross-correlation (e.g., ASA <-> Secure Access).
    """
    global VPN_POOL
    VPN_POOL = {}
    for username in VPN_USERS:
        user = USERS[username]
        VPN_POOL[username] = {
            "vpn_ip": user.vpn_ip,          # Deterministic assigned VPN IP
            "home_ip": user.get_home_ip(),   # Random "connecting from" IP
        }


# =============================================================================
# BASELINE EVENT GENERATORS
# =============================================================================

def asa_tcp_session(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate a complete TCP session (Built + Teardown with same connection ID)."""
    events = []

    cid = random.randint(100000, 999999)
    src = get_internal_ip()
    sp = random.randint(49152, 65535)
    dst = get_external_ip()
    dp = random.choice(ASA_WEB_PORTS)
    reason = random.choice(ASA_TEARDOWN_REASONS)

    # Realistic byte distribution:
    # 40% small (1-50 KB), 35% medium (50-500 KB), 20% large (500 KB-5 MB), 5% downloads (5-50 MB)
    category = random.randint(1, 100)
    if category <= 40:
        bytes_val = random.randint(1000, 50000)
    elif category <= 75:
        bytes_val = random.randint(50000, 500000)
    elif category <= 95:
        bytes_val = random.randint(500000, 5000000)
    else:
        bytes_val = random.randint(5000000, 50000000)

    # Calculate duration based on bytes (~500 Mbps throughput)
    bytes_per_sec = 62500000
    base_duration = max(1, bytes_val // bytes_per_sec)
    min_duration = random.randint(1, 30)
    jitter = base_duration * random.randint(-20, 20) // 100
    duration_secs = max(1, base_duration + min_duration + jitter)

    # Calculate teardown time
    total_start_secs = minute * 60 + second
    total_end_secs = total_start_secs + duration_secs
    end_min = min(59, total_end_secs // 60)
    end_sec = total_end_secs % 60 if end_min < 59 else 59

    # Format duration
    dur_mins = duration_secs // 60
    dur_secs = duration_secs % 60
    dur = f"0:{dur_mins}:{dur_secs}"

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    # 50% outbound, 50% inbound to DMZ
    pri6 = asa_pri(6)  # info
    if random.random() < 0.5:
        events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built outbound TCP connection {cid} for inside:{src}/{sp} ({src}/{sp}) to outside:{dst}/{dp} ({dst}/{dp})")
        events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for inside:{src}/{sp} to outside:{dst}/{dp} duration {dur} bytes {bytes_val} {reason}")
    else:
        us = get_us_ip()
        dmz = get_dmz_ip()
        events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for outside:{us}/{sp} ({us}/{sp}) to dmz:{dmz}/{dp} ({dmz}/{dp})")
        events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for outside:{us}/{sp} to dmz:{dmz}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


def asa_dns_query(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate DNS query (UDP Built + Teardown)."""
    events = []

    cid = random.randint(100000, 999999)
    src = get_internal_ip()
    sp = random.randint(49152, 65535)
    dns = random.choice(DNS_SERVERS)

    duration_secs = random.randint(0, 2)
    end_sec = second + duration_secs
    end_min = minute
    if end_sec >= 60:
        end_min = min(59, minute + 1)
        end_sec = end_sec - 60

    bytes_val = random.randint(64, 464)

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    pri6 = asa_pri(6)  # info
    events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302015: Built outbound UDP connection {cid} for inside:{src}/{sp} ({src}/{sp}) to outside:{dns}/53 ({dns}/53)")
    events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302016: Teardown UDP connection {cid} for outside:{dns}/53 to inside:{src}/{sp} duration 0:0:{duration_secs} bytes {bytes_val}")

    return events


def asa_nat(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate NAT translation event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    src = get_internal_ip()
    sp = random.randint(49152, 65535)
    nat = f"203.0.113.{random.randint(1, 10)}"

    pri5 = asa_pri(5)  # notice - NAT events use severity 5
    if random.random() < 0.5:
        return f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-305011: Built dynamic TCP translation from inside:{src}/{sp} to outside:{nat}/{sp}"
    else:
        dur = f"0:{random.randint(0, 10)}:{random.randint(0, 59)}"
        return f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-305012: Teardown dynamic TCP translation from inside:{src}/{sp} to outside:{nat}/{sp} duration {dur}"


def asa_vpn(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate VPN session event.

    Uses deterministic VPN IPs from company.py for cross-generator correlation.
    The IP field in ASA VPN logs is the assigned VPN pool IP (10.250.0.x),
    which matches InternalIp in Secure Access logs for remote users.
    """
    ts = ts_syslog(base_date, day, hour, minute, second)
    username = random.choice(VPN_USERS)
    pool_entry = VPN_POOL.get(username, {"vpn_ip": f"10.250.0.{random.randint(10, 209)}", "home_ip": get_us_ip()})
    vpn_ip = pool_entry["vpn_ip"]

    pri6 = asa_pri(6)  # info
    if random.random() > 0.33:
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-722022: Group <Remote-Workers> User <{username}@{TENANT}> IP <{vpn_ip}> TCP connection established without compression"
    else:
        dur = f"0:{random.randint(0, 59)}:{random.randint(0, 59)}"
        xmt = random.randint(1000000, 20000000)
        rcv = random.randint(1000000, 50000000)
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-722023: Group <Remote-Workers> User <{username}@{TENANT}> IP <{vpn_ip}> Session disconnected. Session Type: SSL, Duration: {dur}, Bytes xmt: {xmt}, Bytes rcv: {rcv}"


def asa_ssl(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate SSL handshake event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    ip = get_us_ip()
    port = random.randint(49152, 65535)

    pri6 = asa_pri(6)  # info
    if random.random() < 0.5:
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-725001: Starting SSL handshake with client outside:{ip}/{port} for TLSv1.2 session"
    else:
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-725002: Device completed SSL handshake with client outside:{ip}/{port}"


def asa_admin(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate admin command event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    cmds = ["show version", "show conn count", "show cpu usage", "show memory"]
    admins = ["noc-admin", "backup-svc", "monitor-svc"]

    pri5 = asa_pri(5)  # notice
    return f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-111008: User '{random.choice(admins)}' executed the '{random.choice(cmds)}' command"


def asa_deny_external(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate denied external connection."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    srcip = get_world_ip()
    acl = random.choice(ASA_EXT_ACLS)
    tgt = get_internal_ip()
    port = random.choice(ASA_SCAN_PORTS)
    sport = random.randint(40000, 50000)

    pri4 = asa_pri(4)  # warning
    return f'{pri4}{ts} {ASA_HOSTNAME} %ASA-4-106023: Deny tcp src outside:{srcip}/{sport} dst inside:{tgt}/{port} by access-group "{acl}" [0x0, 0x0]'


# =============================================================================
# DC-SPECIFIC TRAFFIC (Kerberos, LDAP, DNS, SMB)
# =============================================================================

# Domain controller IPs for all sites
DC_IPS = {
    "BOS": ["10.10.20.10", "10.10.20.11"],  # DC-BOS-01, DC-BOS-02
    "ATL": ["10.20.20.10"],                   # DC-ATL-01
}

# DC service ports and protocols
DC_SERVICES = [
    (88, "TCP", "Kerberos"),     # Kerberos authentication
    (389, "TCP", "LDAP"),        # LDAP queries
    (636, "TCP", "LDAPS"),       # LDAP over TLS
    (53, "UDP", "DNS"),          # Internal DNS
    (445, "TCP", "SMB"),         # Group Policy, file shares
    (135, "TCP", "RPC"),         # RPC endpoint mapper
    (3268, "TCP", "GC"),         # Global Catalog
]

# DC service weights — Kerberos and LDAP dominate
DC_SERVICE_WEIGHTS = [30, 25, 10, 15, 10, 5, 5]


def asa_dc_traffic(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate domain controller traffic (Kerberos, LDAP, DNS, SMB).

    Workstations and servers constantly talk to DCs for authentication,
    group policy, and DNS resolution. This is the backbone of AD traffic.
    """
    events = []

    # Pick a source (any internal host) and destination DC
    src_site = random.choices(["BOS", "ATL", "AUS"], weights=[60, 25, 15])[0]
    src = get_internal_ip(src_site)
    sp = random.randint(49152, 65535)

    # DCs are mostly in BOS, some traffic goes to ATL DC
    if src_site == "ATL" and random.random() < 0.7:
        dc_ip = random.choice(DC_IPS["ATL"])
        dst_site = "ATL"
    else:
        dc_ip = random.choice(DC_IPS["BOS"])
        dst_site = "BOS"

    service = random.choices(DC_SERVICES, weights=DC_SERVICE_WEIGHTS)[0]
    dp, proto, svc_name = service

    cid = random.randint(100000, 999999)

    # DC traffic is generally small and fast
    bytes_val = random.randint(200, 50000)
    duration_secs = random.randint(0, 5)

    total_start_secs = minute * 60 + second
    total_end_secs = total_start_secs + duration_secs
    end_min = min(59, total_end_secs // 60)
    end_sec = total_end_secs % 60 if end_min < 59 else 59

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    pri6 = asa_pri(6)

    if proto == "UDP":
        events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302015: Built outbound UDP connection {cid} for inside:{src}/{sp} ({src}/{sp}) to inside:{dc_ip}/{dp} ({dc_ip}/{dp})")
        events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302016: Teardown UDP connection {cid} for inside:{dc_ip}/{dp} to inside:{src}/{sp} duration 0:0:{duration_secs} bytes {bytes_val}")
    else:
        dur = f"0:0:{duration_secs}"
        reason = random.choice(ASA_TEARDOWN_REASONS)
        events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for inside:{src}/{sp} ({src}/{sp}) to inside:{dc_ip}/{dp} ({dc_ip}/{dp})")
        events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for inside:{src}/{sp} to inside:{dc_ip}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


# =============================================================================
# INTERNAL ACL DENY EVENTS
# =============================================================================

# Internal deny scenarios (misconfigurations, policy violations)
INTERNAL_DENY_SCENARIOS = [
    # (src_subnet, dst_ip, dst_port, description)
    ("user", "server", 1433, "Workstation trying direct SQL access"),
    ("user", "server", 3389, "Unauthorized RDP to server"),
    ("user", "server", 22, "SSH from non-admin workstation"),
    ("iot", "server", 445, "IoT device scanning SMB"),
    ("guest", "server", 80, "Guest network reaching internal server"),
    ("user", "dmz", 22, "SSH to DMZ from non-jumpbox"),
]


def asa_deny_internal(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate internal ACL deny event (policy violations, misconfigurations)."""
    ts = ts_syslog(base_date, day, hour, minute, second)

    scenario = random.choice(INTERNAL_DENY_SCENARIOS)
    src_type, dst_type, port, _ = scenario

    # Generate source IP based on type
    site = random.choice(["BOS", "ATL", "AUS"])
    prefix = {"BOS": "10.10", "ATL": "10.20", "AUS": "10.30"}[site]

    if src_type == "user":
        src = f"{prefix}.30.{random.randint(10, 200)}"
    elif src_type == "iot":
        src = f"{prefix}.60.{random.randint(10, 50)}"
    elif src_type == "guest":
        src = f"{prefix}.80.{random.randint(10, 50)}"
    else:
        src = get_internal_ip(site)

    # Generate destination IP
    if dst_type == "server":
        server = random.choice(list(SERVERS.values()))
        dst = server.ip
    elif dst_type == "dmz":
        dst = get_dmz_ip()
    else:
        dst = get_internal_ip()

    sport = random.randint(49152, 65535)
    acl = random.choice(ASA_INT_ACLS)

    pri4 = asa_pri(4)
    return f'{pri4}{ts} {ASA_HOSTNAME} %ASA-4-106023: Deny tcp src inside:{src}/{sport} dst inside:{dst}/{port} by access-group "{acl}" [0x0, 0x0]'


# =============================================================================
# SERVER TRAFFIC (SAP, BASTION)
# =============================================================================

# Server-specific traffic patterns
NEW_SERVER_TRAFFIC = [
    # (server_hostname, service_ports, description)
    ("SAP-PROD-01", [(3200, "TCP"), (3300, "TCP"), (8000, "TCP"), (50013, "TCP")], "SAP Application"),
    ("SAP-DB-01", [(30015, "TCP"), (30013, "TCP")], "SAP HANA DB"),
    ("BASTION-BOS-01", [(22, "TCP")], "SSH Jumpbox"),
    ("APP-BOS-01", [(443, "TCP"), (8443, "TCP")], "e-Commerce API"),
]

# Internal tier traffic: WEB → APP → SQL (3-tier e-commerce flow)
APP_SERVER_IP = "10.10.20.40"   # APP-BOS-01
SQL_SERVER_IP = "10.10.20.30"   # SQL-PROD-01


def asa_new_server_traffic(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate traffic to/from new infrastructure servers."""
    events = []

    server_entry = random.choice(NEW_SERVER_TRAFFIC)
    hostname, ports, desc = server_entry
    server = SERVERS.get(hostname)
    if not server:
        return events

    port_info = random.choice(ports)
    dp, proto = port_info

    # Source: internal workstation or server
    src_site = random.choice(["BOS", "ATL", "AUS"])
    src = get_internal_ip(src_site)
    sp = random.randint(49152, 65535)
    dst = server.ip

    cid = random.randint(100000, 999999)
    bytes_val = random.randint(1000, 200000)
    duration_secs = random.randint(1, 30)

    total_start_secs = minute * 60 + second
    total_end_secs = total_start_secs + duration_secs
    end_min = min(59, total_end_secs // 60)
    end_sec = total_end_secs % 60 if end_min < 59 else 59

    dur = f"0:0:{duration_secs}"
    reason = random.choice(ASA_TEARDOWN_REASONS)

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    # Bastion traffic gets special naming (management zone)
    if hostname.startswith("BASTION"):
        src_zone = "inside"
        dst_zone = "management"
    else:
        src_zone = "inside"
        dst_zone = "inside"

    pri6 = asa_pri(6)
    events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for {src_zone}:{src}/{sp} ({src}/{sp}) to {dst_zone}:{dst}/{dp} ({dst}/{dp})")
    events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for {src_zone}:{src}/{sp} to {dst_zone}:{dst}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


def asa_internal_app_traffic(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate internal 3-tier e-commerce traffic: WEB -> APP-BOS-01 -> SQL-PROD-01.

    Simulates the realistic data flow where web servers in the DMZ call the
    internal API server, which then queries the database. Generates a correlated
    pair of connections (WEB->APP + APP->SQL) to make the 3-tier architecture
    visible in Splunk.
    """
    events = []
    pri6 = asa_pri(6)

    # --- Leg 1: WEB-01/02 (DMZ) -> APP-BOS-01 (inside) on 443/8443 ---
    web_src = random.choice(WEB_SERVERS)  # 172.16.1.10 or .11
    web_sp = random.randint(49152, 65535)
    app_dp = random.choice([443, 8443])

    cid1 = random.randint(100000, 999999)
    bytes1 = random.randint(2000, 100000)  # API call (request + response)
    duration1 = random.randint(1, 5)  # Fast internal call

    total_start = minute * 60 + second
    total_end1 = total_start + duration1
    end_min1 = min(59, total_end1 // 60)
    end_sec1 = total_end1 % 60 if end_min1 < 59 else 59

    ts1_start = ts_syslog(base_date, day, hour, minute, second)
    ts1_end = ts_syslog(base_date, day, hour, end_min1, end_sec1)

    events.append(f"{pri6}{ts1_start} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid1} for dmz:{web_src}/{web_sp} ({web_src}/{web_sp}) to inside:{APP_SERVER_IP}/{app_dp} ({APP_SERVER_IP}/{app_dp})")
    events.append(f"{pri6}{ts1_end} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid1} for dmz:{web_src}/{web_sp} to inside:{APP_SERVER_IP}/{app_dp} duration 0:0:{duration1} bytes {bytes1} TCP FINs")

    # --- Leg 2: APP-BOS-01 (inside) -> SQL-PROD-01 (inside) on 1433 ---
    app_sp = random.randint(49152, 65535)

    cid2 = random.randint(100000, 999999)
    bytes2 = random.randint(500, 50000)  # DB query (smaller)
    duration2 = random.randint(1, 3)  # DB call is fast

    # Starts slightly after leg 1 (staggered by 1 second)
    second2 = min(59, second + 1)
    total_end2 = minute * 60 + second2 + duration2
    end_min2 = min(59, total_end2 // 60)
    end_sec2 = total_end2 % 60 if end_min2 < 59 else 59

    ts2_start = ts_syslog(base_date, day, hour, minute, second2)
    ts2_end = ts_syslog(base_date, day, hour, end_min2, end_sec2)

    events.append(f"{pri6}{ts2_start} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid2} for inside:{APP_SERVER_IP}/{app_sp} ({APP_SERVER_IP}/{app_sp}) to inside:{SQL_SERVER_IP}/1433 ({SQL_SERVER_IP}/1433)")
    events.append(f"{pri6}{ts2_end} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid2} for inside:{APP_SERVER_IP}/{app_sp} to inside:{SQL_SERVER_IP}/1433 duration 0:0:{duration2} bytes {bytes2} TCP FINs")

    return events


# =============================================================================
# ICMP BASELINE (Monitoring Health Checks)
# =============================================================================

def asa_icmp_ping(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate ICMP ping event (monitoring server health checks).

    MON-ATL-01 pings critical infrastructure. ASA logs permitted ICMP.
    """
    ts = ts_syslog(base_date, day, hour, minute, second)

    mon_ip = "10.20.20.30"  # MON-ATL-01

    # Ping targets: critical servers, DCs, web servers, network devices
    targets = [
        "10.10.20.10",   # DC-BOS-01
        "10.10.20.11",   # DC-BOS-02
        "10.10.20.30",   # SQL-PROD-01
        "172.16.1.10",   # WEB-01
        "172.16.1.11",   # WEB-02
        "10.10.20.60",   # SAP-PROD-01
        "10.10.20.61",   # SAP-DB-01
        "10.20.20.10",   # DC-ATL-01
        "10.20.20.20",   # BACKUP-ATL-01
    ]
    dst = random.choice(targets)

    pri6 = asa_pri(6)
    return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-302020: Built inbound ICMP connection for inside:{mon_ip}/0 ({mon_ip}/0) to inside:{dst}/0 ({dst}/0)"


# =============================================================================
# WEB-CORRELATED TRAFFIC (DMZ)
# =============================================================================

# Web server IPs in DMZ
WEB_SERVERS = ["172.16.1.10", "172.16.1.11"]  # WEB-01, WEB-02
WEB_PORTS = [80, 443]

def asa_web_session(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate web server session (inbound to DMZ)."""
    events = []

    cid = random.randint(100000, 999999)
    src = get_us_ip()  # External US visitor
    sp = random.randint(49152, 65535)
    dst = random.choice(WEB_SERVERS)
    dp = random.choice(WEB_PORTS)

    # Web traffic byte distribution:
    # 50% small (HTML/API): 1-50 KB
    # 30% medium (images): 50-500 KB
    # 15% large (assets): 500 KB-2 MB
    # 5% downloads: 2-10 MB
    category = random.randint(1, 100)
    if category <= 50:
        bytes_val = random.randint(1000, 50000)
    elif category <= 80:
        bytes_val = random.randint(50000, 500000)
    elif category <= 95:
        bytes_val = random.randint(500000, 2000000)
    else:
        bytes_val = random.randint(2000000, 10000000)

    # Duration based on bytes
    duration_secs = max(1, bytes_val // 500000 + random.randint(1, 10))

    total_start_secs = minute * 60 + second
    total_end_secs = total_start_secs + duration_secs
    end_min = min(59, total_end_secs // 60)
    end_sec = total_end_secs % 60 if end_min < 59 else 59

    dur_mins = duration_secs // 60
    dur_secs = duration_secs % 60
    dur = f"0:{dur_mins}:{dur_secs}"

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    reason = random.choice(ASA_TEARDOWN_REASONS)

    pri6 = asa_pri(6)
    events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for outside:{src}/{sp} ({src}/{sp}) to dmz:{dst}/{dp} ({dst}/{dp})")
    events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for outside:{src}/{sp} to dmz:{dst}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


def asa_web_nat(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate NAT for web server (public IP translation)."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    dst = random.choice(WEB_SERVERS)
    public_ip = "203.0.113.50" if dst == "172.16.1.10" else "203.0.113.51"
    dp = random.choice(WEB_PORTS)

    pri5 = asa_pri(5)
    return f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-305011: Built static TCP translation from outside:{public_ip}/{dp} to dmz:{dst}/{dp}"


# =============================================================================
# INTERNAL SITE-TO-SITE TRAFFIC
# =============================================================================

# Site prefixes
SITE_PREFIXES = {
    "BOS": "10.10",
    "ATL": "10.20",
    "AUS": "10.30",
}

# Common internal services and ports
INTERNAL_SERVICES = [
    (445, "SMB"),      # File shares
    (3389, "RDP"),     # Remote desktop
    (1433, "MSSQL"),   # SQL Server
    (3306, "MySQL"),   # MySQL
    (5432, "PostgreSQL"), # PostgreSQL
    (22, "SSH"),       # SSH
    (389, "LDAP"),     # LDAP
    (636, "LDAPS"),    # LDAPS
]

def get_site_ip(site: str, subnet: str = "30") -> str:
    """Get random IP from a site's user subnet."""
    prefix = SITE_PREFIXES.get(site, "10.10")
    return f"{prefix}.{subnet}.{random.randint(10, 200)}"


def asa_site_to_site(base_date: str, day: int, hour: int, minute: int, second: int) -> List[str]:
    """Generate inter-site traffic using hub-spoke model.

    BOS is the hub (70% of traffic involves BOS).
    ATL↔AUS direct traffic is only 30% (spoke-to-spoke via VPN).
    Most branch traffic goes BOS↔ATL or BOS↔AUS for DC/file/app access.
    """
    events = []

    # Hub-spoke: 70% involves BOS as either src or dst
    if random.random() < 0.70:
        # Hub traffic: BOS ↔ ATL or BOS ↔ AUS
        spoke = random.choices(["ATL", "AUS"], weights=[60, 40])[0]
        if random.random() < 0.6:
            # Spoke → Hub (branch users accessing BOS resources)
            src_site, dst_site = spoke, "BOS"
        else:
            # Hub → Spoke (replication, GPO push, etc.)
            src_site, dst_site = "BOS", spoke
    else:
        # Spoke-to-spoke: ATL ↔ AUS (30%)
        if random.random() < 0.5:
            src_site, dst_site = "ATL", "AUS"
        else:
            src_site, dst_site = "AUS", "ATL"

    cid = random.randint(100000, 999999)
    src = get_site_ip(src_site)
    sp = random.randint(49152, 65535)
    dst = get_site_ip(dst_site, "20" if random.random() < 0.3 else "30")  # 30% server, 70% user
    service = random.choice(INTERNAL_SERVICES)
    dp = service[0]

    # Internal traffic is typically smaller
    bytes_val = random.randint(5000, 500000)
    duration_secs = random.randint(1, 60)

    total_start_secs = minute * 60 + second
    total_end_secs = total_start_secs + duration_secs
    end_min = min(59, total_end_secs // 60)
    end_sec = total_end_secs % 60 if end_min < 59 else 59

    dur_mins = duration_secs // 60
    dur_secs = duration_secs % 60
    dur = f"0:{dur_mins}:{dur_secs}"

    start_ts = ts_syslog(base_date, day, hour, minute, second)
    teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

    reason = random.choice(ASA_TEARDOWN_REASONS)

    # Site-to-site goes through the ASA for inspection even with SD-WAN
    pri6 = asa_pri(6)
    events.append(f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for {src_site.lower()}:{src}/{sp} ({src}/{sp}) to {dst_site.lower()}:{dst}/{dp} ({dst}/{dp})")
    events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for {src_site.lower()}:{src}/{sp} to {dst_site.lower()}:{dst}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


# =============================================================================
# ADDITIONAL EVENT TYPES
# =============================================================================

def asa_http_inspect(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate HTTP inspection event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    src = get_us_ip()
    dst = random.choice(WEB_SERVERS)

    methods = ["GET", "POST", "PUT", "DELETE"]
    uris = ["/api/v1/orders", "/api/v1/products", "/checkout", "/cart", "/login"]

    pri6 = asa_pri(6)
    return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-302020: Built inbound HTTP connection for outside:{src} to dmz:{dst} method {random.choice(methods)} uri {random.choice(uris)}"


def asa_rate_limit(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate connection rate limiting event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    src = get_world_ip()
    rate = random.randint(100, 500)

    pri4 = asa_pri(4)
    return f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-733100: [outside:{src}] drop rate-1 exceeded. Current burst rate is {rate} per second, max configured rate is 100"


def asa_threat_detect(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate threat detection event (scanning)."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    src = get_world_ip()

    pri4 = asa_pri(4)
    return f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-733101: Host {src} is attacking. Current burst rate is {random.randint(20, 100)} per second, max configured rate is 10"


# =============================================================================
# OPERATIONAL EVENTS (scheduled maintenance, issues)
# =============================================================================

def asa_maintenance(base_date: str, day: int) -> List[str]:
    """Generate scheduled maintenance window events."""
    events = []
    pri5 = asa_pri(5)  # notice
    pri4 = asa_pri(4)  # warning

    ts = ts_syslog(base_date, day, 2, 0, 1)
    events.append(f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-111008: User 'noc-admin' executed the 'configure terminal' command")

    ts = ts_syslog(base_date, day, 2, 5, 15)
    events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-411001: Line protocol on Interface GigabitEthernet0/2, changed state to up")
    return events


def asa_capacity_warning(base_date: str, day: int) -> List[str]:
    """Generate CPU capacity warning events."""
    events = []
    pri4 = asa_pri(4)  # warning
    for h in [8, 9]:
        ts = ts_syslog(base_date, day, h, random.randint(30, 59), random.randint(0, 59))
        cpu = random.randint(65, 80)
        events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-733104: TD Syslog: ASA CPU usage {cpu} percent, limit 60 percent")
    return events


def asa_interface_flapping(base_date: str, day: int) -> List[str]:
    """Generate interface flapping events with NOC fix."""
    events = []
    base_min = 22
    pri4 = asa_pri(4)  # warning
    pri5 = asa_pri(5)  # notice

    # Flapping
    for i in range(1, 7):
        ts = ts_syslog(base_date, day, 3, base_min + i, random.randint(0, 59))
        state = "up" if i % 2 == 0 else "down"
        events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-411001: Line protocol on Interface GigabitEthernet0/1, changed state to {state}")

    # Duplex mismatch
    ts = ts_syslog(base_date, day, 3, 25, random.randint(5, 35))
    events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-412001: Duplex mismatch detected on interface GigabitEthernet0/1")

    # NOC fixes it (using Boston management subnet)
    ts = ts_syslog(base_date, day, 3, 30, random.randint(1, 10))
    events.append(f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-111010: User 'noc-admin', running 'CLI' from IP 10.10.10.50, executed 'interface GigabitEthernet0/1'")
    ts = ts_syslog(base_date, day, 3, 30, random.randint(15, 25))
    events.append(f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-111010: User 'noc-admin', running 'CLI' from IP 10.10.10.50, executed 'duplex full'")
    ts = ts_syslog(base_date, day, 3, 30, random.randint(30, 40))
    events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-411001: Line protocol on Interface GigabitEthernet0/1, changed state to up")

    return events


def asa_cert_warnings(base_date: str, day: int) -> List[str]:
    """Generate certificate warning events."""
    events = []
    pri3 = asa_pri(3)  # error

    ts = ts_syslog(base_date, day, 6, random.randint(0, 30), random.randint(0, 59))
    events.append(f"{pri3}{ts} {ASA_HOSTNAME} %ASA-3-717050: Certificate chain failed validation. Reason: certificate will expire in 7 days, serial number: 1A:2B:3C:4D:5E:6F, subject name: CN=*.{TENANT}")

    ts = ts_syslog(base_date, day, 0, random.randint(15, 45), random.randint(0, 59))
    events.append(f"{pri3}{ts} {ASA_HOSTNAME} %ASA-3-717050: Certificate chain failed validation. Reason: certificate has expired, serial number: 3A:4B:5C:6D:7E:8F, subject name: CN=vpn.{TENANT}")

    return events


def asa_vpn_issues(base_date: str, day: int) -> List[str]:
    """Generate VPN tunnel issue events."""
    events = []
    pri4 = asa_pri(4)  # warning
    pri5 = asa_pri(5)  # notice

    ts = ts_syslog(base_date, day, 2, 15, 33)
    events.append(f"{pri4}{ts} {ASA_HOSTNAME} %ASA-4-713903: Group = Site-to-Site-AWS, IP = 3.5.140.2, Error: Unable to remove PeerTblEntry")

    ts = ts_syslog(base_date, day, 2, 30, 1)
    events.append(f"{pri5}{ts} {ASA_HOSTNAME} %ASA-5-713041: Group = Site-to-Site-AWS, IP = 3.5.140.2, IKE Initiator: new SA established Phase 1")

    return events


def asa_failover(base_date: str, day: int) -> List[str]:
    """Generate failover events."""
    events = []
    pri1 = asa_pri(1)  # alert

    ts = ts_syslog(base_date, day, 4, 0, 1)
    events.append(f"{pri1}{ts} {ASA_HOSTNAME} %ASA-1-104001: (Primary) Switching to ACTIVE - Loss of Failover communications with standby")

    ts = ts_syslog(base_date, day, 4, 10, 1)
    events.append(f"{pri1}{ts} {ASA_HOSTNAME} %ASA-1-104004: (Primary) Switching to STANDBY - Loss of Failover communications resolved")

    return events


# =============================================================================
# NIGHTLY BACKUP TRAFFIC (BACKUP-ATL-01 -> FILE-BOS-01)
# =============================================================================

BACKUP_SRC = "10.20.20.20"   # BACKUP-ATL-01 (Atlanta)
BACKUP_DST = "10.10.20.20"   # FILE-BOS-01 (Boston)


def asa_backup_traffic(base_date: str, day: int, hour: int) -> List[str]:
    """Generate nightly backup traffic from BACKUP-ATL-01 to FILE-BOS-01.

    Scheduled window: 22:00-04:00 nightly (crosses midnight).
    Traffic pattern: SMB (port 445) large file transfers.
    - 22:00-23:00: Backup job starts, initial sync (3-5 sessions)
    - 00:00-02:00: Peak transfer (6-10 sessions per hour)
    - 03:00-04:00: Tail end, verification (2-3 sessions)
    """
    # Only active during backup window
    if hour >= 4 and hour < 22:
        return []

    events = []
    pri6 = asa_pri(6)

    # Determine session count based on phase
    if hour >= 22:
        # Start phase: initial sync
        session_count = random.randint(3, 5)
    elif hour <= 1:
        # Peak phase: bulk data transfer
        session_count = random.randint(6, 10)
    else:
        # Tail phase: verification and cleanup
        session_count = random.randint(2, 3)

    for _ in range(session_count):
        cid = random.randint(100000, 999999)
        sp = random.randint(49152, 65535)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)

        # Backup transfers are large and long-lived
        bytes_val = random.randint(50_000_000, 500_000_000)  # 50MB-500MB per session
        duration_secs = random.randint(120, 900)  # 2-15 minutes

        total_start_secs = minute * 60 + second
        total_end_secs = total_start_secs + duration_secs
        end_min = min(59, total_end_secs // 60)
        end_sec = total_end_secs % 60 if end_min < 59 else 59

        dur_mins = duration_secs // 60
        dur_secs = duration_secs % 60
        dur = f"0:{dur_mins}:{dur_secs}"

        start_ts = ts_syslog(base_date, day, hour, minute, second)
        teardown_ts = ts_syslog(base_date, day, hour, end_min, end_sec)

        # ATL -> BOS cross-site SMB backup traffic
        events.append(
            f"{pri6}{start_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP "
            f"connection {cid} for atl:{BACKUP_SRC}/{sp} ({BACKUP_SRC}/{sp}) "
            f"to bos:{BACKUP_DST}/445 ({BACKUP_DST}/445)"
        )
        events.append(
            f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP "
            f"connection {cid} for atl:{BACKUP_SRC}/{sp} to bos:{BACKUP_DST}/445 "
            f"duration {dur} bytes {bytes_val} TCP FINs"
        )

    return events


def generate_day_events(base_date: str, day: int) -> List[str]:
    """Generate operational events for a specific day."""
    events = []

    if day == 1:
        events.extend(asa_maintenance(base_date, day))
    elif day == 3:
        events.extend(asa_capacity_warning(base_date, day))
    elif day == 5:
        events.extend(asa_interface_flapping(base_date, day))
    elif day == 7:
        events.extend(asa_cert_warnings(base_date, day))
    elif day == 8:
        events.extend(asa_vpn_issues(base_date, day))
    elif day == 10:
        events.extend(asa_failover(base_date, day))

    return events


# =============================================================================
# WEB SESSION REGISTRY (1:1 correlation with access logs)
# =============================================================================

def load_web_session_registry() -> List[Dict]:
    """Load web sessions created by access generator.

    The access generator writes web_session_registry.json (NDJSON) with every
    web session's IP, timestamps, bytes, and destination server. ASA uses this
    to generate matching Built/Teardown events with the SAME source IP.

    Returns empty list if file doesn't exist (access not generated yet).
    Uses get_output_path() which respects --test mode automatically.
    """
    registry_path = get_output_path("web", "web_session_registry.json")
    sessions = []
    if registry_path.exists():
        with open(registry_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    sessions.append(json.loads(line))
    return sessions


def _parse_registry_hour(ts_str: str) -> int:
    """Extract hour from ISO 8601 timestamp string."""
    # Format: "2026-01-05T14:23:45Z"
    return int(ts_str[11:13])


def _parse_registry_day(ts_str: str, start_date: str) -> int:
    """Extract day offset from ISO 8601 timestamp string relative to start_date."""
    # Format: "2026-01-05T14:23:45Z"
    from datetime import datetime
    event_date = datetime.strptime(ts_str[:10], "%Y-%m-%d")
    start = datetime.strptime(start_date, "%Y-%m-%d")
    return (event_date - start).days


def asa_web_session_from_registry(base_date: str, session: Dict) -> List[str]:
    """Generate Built+Teardown from access session registry entry.

    Creates ASA firewall events that match EXACTLY with the access log session:
    same source IP, same destination web server, same timestamps.
    """
    events = []

    src = session["ip"]
    dst = session["dst"]
    dp = session["dst_port"]
    bytes_val = session.get("bytes", 5000)

    # Parse timestamps
    start_ts_str = session["start_ts"]
    end_ts_str = session["end_ts"]

    # Extract time components from start timestamp
    start_hour = int(start_ts_str[11:13])
    start_min = int(start_ts_str[14:16])
    start_sec = int(start_ts_str[17:19])

    # Extract time components from end timestamp
    end_hour = int(end_ts_str[11:13])
    end_min = int(end_ts_str[14:16])
    end_sec = int(end_ts_str[17:19])

    # Calculate duration
    start_total_sec = start_hour * 3600 + start_min * 60 + start_sec
    end_total_sec = end_hour * 3600 + end_min * 60 + end_sec
    duration_secs = max(1, end_total_sec - start_total_sec)
    dur_mins = duration_secs // 60
    dur_secs = duration_secs % 60
    dur = f"0:{dur_mins}:{dur_secs}"

    # Extract day from start timestamp to generate correct date
    day = _parse_registry_day(start_ts_str, base_date)

    # Connection ID and source port
    cid = random.randint(100000, 999999)
    sp = random.randint(49152, 65535)

    # Format ASA timestamps
    built_ts = ts_syslog(base_date, day, start_hour, start_min, start_sec)
    teardown_ts = ts_syslog(base_date, day, end_hour, end_min, end_sec)

    reason = random.choice(ASA_TEARDOWN_REASONS)
    pri6 = asa_pri(6)

    events.append(f"{pri6}{built_ts} {ASA_HOSTNAME} %ASA-6-302013: Built inbound TCP connection {cid} for outside:{src}/{sp} ({src}/{sp}) to dmz:{dst}/{dp} ({dst}/{dp})")
    events.append(f"{pri6}{teardown_ts} {ASA_HOSTNAME} %ASA-6-302014: Teardown TCP connection {cid} for outside:{src}/{sp} to dmz:{dst}/{dp} duration {dur} bytes {bytes_val} {reason}")

    return events


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int,
                           registry_sessions: List[Dict] = None) -> List[str]:
    """Generate baseline events for one hour.

    Event distribution (updated for perimeter + internal traffic):
    - 25% Web sessions (inbound to DMZ) - NOW registry-driven for 1:1 access correlation
    - 16% Outbound TCP sessions (users browsing)
    - 12% DNS queries (external)
    - 10% DC traffic (Kerberos, LDAP, DNS, SMB) — AD backbone
    - 9% Site-to-site traffic (hub-spoke: BOS=70%)
    - 7% NAT translations
    - 5% VPN sessions
    - 4% New server traffic (SAP, BASTION, APP-BOS-01)
    - 2% Internal app tier traffic (WEB->APP->SQL 3-tier flow)
    - 3% SSL handshakes
    - 3% ICMP health checks (monitoring)
    - 2% HTTP inspection events
    - 1% Admin commands
    - 1% Internal ACL denies

    When registry_sessions is provided, web sessions are generated from the registry
    (1:1 match with access logs) instead of random generation. The remaining 75%
    of event_count is filled with non-web traffic types.
    """
    events = []

    # --- Phase 1: Registry-driven web sessions (if available) ---
    registry_web_events = 0
    if registry_sessions:
        # Find sessions that start in this hour on this day
        hour_sessions = [s for s in registry_sessions
                         if _parse_registry_hour(s["start_ts"]) == hour
                         and _parse_registry_day(s["start_ts"], base_date) == day]
        for sess in hour_sessions:
            events.extend(asa_web_session_from_registry(base_date, sess))
            registry_web_events += 1  # Each produces 2 events (Built+Teardown)

    # --- Phase 2: Non-web baseline events ---
    # Calculate remaining events: total minus registry web events (2 events each)
    # The 25% web allocation is now handled by the registry, so we generate
    # the remaining 75% of event_count as non-web traffic.
    remaining_events = max(0, event_count - registry_web_events)

    # If no registry available, fall back to original behavior (including random web sessions)
    use_random_web = not registry_sessions

    for _ in range(remaining_events):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        event_type = random.randint(1, 100)

        if event_type <= 25:
            if use_random_web:
                # Fallback: random web sessions when no registry available
                events.extend(asa_web_session(base_date, day, hour, minute, second))
            else:
                # Registry handles web sessions; redistribute to outbound TCP
                events.extend(asa_tcp_session(base_date, day, hour, minute, second))
        elif event_type <= 41:
            # Outbound TCP sessions
            events.extend(asa_tcp_session(base_date, day, hour, minute, second))
        elif event_type <= 53:
            # DNS queries (external)
            events.extend(asa_dns_query(base_date, day, hour, minute, second))
        elif event_type <= 63:
            # DC traffic (Kerberos, LDAP, DNS, SMB)
            events.extend(asa_dc_traffic(base_date, day, hour, minute, second))
        elif event_type <= 72:
            # Site-to-site traffic (hub-spoke)
            events.extend(asa_site_to_site(base_date, day, hour, minute, second))
        elif event_type <= 79:
            # NAT translations
            events.append(asa_nat(base_date, day, hour, minute, second))
            # Also add web NAT occasionally
            if random.random() < 0.3:
                events.append(asa_web_nat(base_date, day, hour, minute, second))
        elif event_type <= 84:
            # VPN sessions
            events.append(asa_vpn(base_date, day, hour, minute, second))
        elif event_type <= 88:
            # New server traffic (SAP, BASTION, APP-BOS-01)
            events.extend(asa_new_server_traffic(base_date, day, hour, minute, second))
        elif event_type <= 90:
            # Internal app tier traffic (WEB->APP->SQL 3-tier flow)
            events.extend(asa_internal_app_traffic(base_date, day, hour, minute, second))
        elif event_type <= 93:
            # SSL handshakes
            events.append(asa_ssl(base_date, day, hour, minute, second))
        elif event_type <= 96:
            # ICMP health checks (monitoring pings)
            events.append(asa_icmp_ping(base_date, day, hour, minute, second))
        elif event_type <= 98:
            # HTTP inspection
            events.append(asa_http_inspect(base_date, day, hour, minute, second))
        elif event_type <= 99:
            # Admin commands
            events.append(asa_admin(base_date, day, hour, minute, second))
        else:
            # Internal ACL denies (policy violations)
            events.append(asa_deny_internal(base_date, day, hour, minute, second))

    # Background scan noise (scaled with traffic - more traffic = more scans)
    scan_count = max(1, event_count // 100)  # ~1% of traffic is scan attempts
    for _ in range(random.randint(scan_count, scan_count * 3)):
        events.append(asa_deny_external(base_date, day, hour, random.randint(0, 59), random.randint(0, 59)))

    # Occasional rate limiting and threat detection (during business hours)
    if 8 <= hour <= 18:
        if random.random() < 0.05:  # 5% chance per hour
            events.append(asa_rate_limit(base_date, day, hour, random.randint(0, 59), random.randint(0, 59)))
        if random.random() < 0.03:  # 3% chance per hour
            events.append(asa_threat_detect(base_date, day, hour, random.randint(0, 59), random.randint(0, 59)))

    return events


# =============================================================================
# SCENARIO INITIALIZATION
# =============================================================================

# Global scenario instances (initialized in generate_asa_logs)
_exfil_scenario = None
_memleak_scenario = None
_fw_misconfig_scenario = None
_ransomware_scenario = None
_ddos_attack_scenario = None
_time_utils = None


def init_scenarios(config: Config, company: Company, time_utils: TimeUtils):
    """Initialize scenario instances."""
    global _exfil_scenario, _memleak_scenario, _fw_misconfig_scenario, _ransomware_scenario, _cert_expiry_scenario, _ddos_attack_scenario, _cpu_runaway_scenario, _time_utils
    _time_utils = time_utils
    _exfil_scenario = ExfilScenario(config, company, time_utils)
    _memleak_scenario = MemoryLeakScenario(demo_id_enabled=config.demo_id_enabled)
    _fw_misconfig_scenario = FirewallMisconfigScenario(demo_id_enabled=config.demo_id_enabled)
    _ransomware_scenario = RansomwareAttemptScenario(demo_id_enabled=config.demo_id_enabled)
    _cert_expiry_scenario = CertificateExpiryScenario(demo_id_enabled=config.demo_id_enabled)
    _ddos_attack_scenario = DdosAttackScenario(demo_id_enabled=config.demo_id_enabled)
    _cpu_runaway_scenario = CpuRunawayScenario(demo_id_enabled=config.demo_id_enabled)


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_asa_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "exfil",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate ASA firewall logs."""

    # Initialize
    init_vpn_pool()

    # Initialize shared objects for scenarios
    config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
    company = Company()
    time_utils = TimeUtils(start_date)
    init_scenarios(config, company, time_utils)

    # Determine output path
    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("network", "cisco_asa/cisco_asa.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_exfil = "exfil" in active_scenarios
    include_memory_leak = "memory_leak" in active_scenarios
    include_fw_misconfig = "firewall_misconfig" in active_scenarios
    include_ransomware = "ransomware_attempt" in active_scenarios
    include_cert_expiry = "certificate_expiry" in active_scenarios
    include_ddos_attack = "ddos_attack" in active_scenarios
    include_cpu_runaway = "cpu_runaway" in active_scenarios

    # Load web session registry (for 1:1 correlation with access logs)
    # Registry is written by generate_access.py — if not available, ASA falls
    # back to generating random web sessions (original behavior).
    registry_sessions = load_web_session_registry()
    if not quiet and registry_sessions:
        print(f"  Loaded {len(registry_sessions):,} web sessions from access registry", file=sys.stderr)

    # Scale base events
    # 10x increase from 200 to 2000 to better reflect perimeter traffic
    # ASA sees ALL external traffic including web servers (WEB-01/02), VPN, etc.
    base_events_per_peak_hour = int(2000 * scale)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  ASA Log Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events = []

    for day in range(days):
        dt = date_add(start_date, day)
        date_str = dt.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [ASA] Day {day + 1}/{days} ({date_str})...", file=sys.stderr, end="\r")

        # Generate day-specific operational events
        all_events.extend(generate_day_events(start_date, day))

        for hour in range(24):
            # Calculate events for this hour using natural variation
            hour_events = calc_natural_events(base_events_per_peak_hour, start_date, day, hour, "firewall")

            # Generate baseline (with registry-driven web sessions if available)
            all_events.extend(generate_baseline_hour(start_date, day, hour, hour_events,
                                                     registry_sessions=registry_sessions))

            # Nightly backup traffic (BACKUP-ATL-01 -> FILE-BOS-01, 22:00-04:00)
            all_events.extend(asa_backup_traffic(start_date, day, hour))

            # Generate scenario events using new scenario classes
            if include_exfil:
                all_events.extend(_exfil_scenario.asa_hour(day, hour))

            if include_memory_leak:
                all_events.extend(_memleak_scenario.asa_generate_hour(day, hour, _time_utils))

            if include_fw_misconfig:
                all_events.extend(_fw_misconfig_scenario.generate_hour(day, hour, _time_utils))

            if include_ransomware:
                all_events.extend(_ransomware_scenario.asa_hour(day, hour, _time_utils))
                all_events.extend(_ransomware_scenario.asa_crosssite_hour(day, hour, _time_utils))

            if include_cert_expiry:
                all_events.extend(_cert_expiry_scenario.asa_hour(day, hour, _time_utils))

            if include_ddos_attack:
                all_events.extend(_ddos_attack_scenario.generate_hour(day, hour, _time_utils))

            if include_cpu_runaway:
                all_events.extend(_cpu_runaway_scenario.asa_get_events(day, hour, _time_utils))

        if not quiet:
            print(f"  [ASA] Day {day + 1}/{days} ({date_str})... done", file=sys.stderr)

    # Sort events by timestamp
    if not quiet:
        print("  [ASA] Sorting...", file=sys.stderr, end="\r")

    all_events.sort()

    if not quiet:
        print("  [ASA] Sorting... done", file=sys.stderr)

    # Write output
    with open(output_path, "w") as f:
        for event in all_events:
            f.write(event + "\n")

    event_count = len(all_events)

    if not quiet:
        print(f"  [ASA] Complete! {event_count:,} events written to {output_path}", file=sys.stderr)

    return event_count


def main():
    parser = argparse.ArgumentParser(description="Generate Cisco ASA firewall logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Number of days")
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE, help="Volume scale factor")
    parser.add_argument("--scenarios", default="exfil", help="Scenarios: none, exfil, all")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")

    args = parser.parse_args()

    count = generate_asa_logs(
        start_date=args.start_date,
        days=args.days,
        scale=args.scale,
        scenarios=args.scenarios,
        output_file=args.output,
        quiet=args.quiet,
    )

    print(count)


if __name__ == "__main__":
    main()
