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
- DNS queries
- NAT translations
- VPN sessions
- SSL handshakes
- Admin commands
- Background scan noise (external port scans DENIED)
- Operational events (maintenance, capacity, interface flapping, cert warnings)
- C2 beacon traffic (for exfil scenario)
- Large data transfer detection (for exfil scenario)

Usage:
    python3 generate_asa.py --days=14 --scale=1.0 --scenarios=exfil
"""

import argparse
import random
import sys
from pathlib import Path
from typing import List, TextIO

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import Config, DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import TimeUtils, ts_syslog, date_add, calc_natural_events
from shared.company import Company, ASA_PERIMETER, DNS_SERVERS, THREAT_IP, TENANT
from shared.company import (
    ASA_WEB_PORTS, ASA_SCAN_PORTS, ASA_TEARDOWN_REASONS, ASA_EXT_ACLS,
    VPN_USERS, USERS,
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
from scenarios.ops import MemoryLeakScenario
from scenarios.network import FirewallMisconfigScenario, CertificateExpiryScenario
from scenarios.registry import expand_scenarios, source_needed_for_scenarios


# =============================================================================
# VPN POOL (cached IPs per user for consistency)
# =============================================================================

VPN_POOL = {}

def init_vpn_pool():
    """Initialize VPN IP pool - assign 2-3 IPs per VPN user."""
    global VPN_POOL
    VPN_POOL = {}
    for username in VPN_USERS:
        num_ips = random.randint(2, 3)
        VPN_POOL[username] = [get_us_ip() for _ in range(num_ips)]


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
    """Generate VPN session event."""
    ts = ts_syslog(base_date, day, hour, minute, second)
    username = random.choice(VPN_USERS)
    ips = VPN_POOL.get(username, [get_us_ip()])
    ip = random.choice(ips)

    pri6 = asa_pri(6)  # info
    if random.random() > 0.33:
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-722022: Group <Remote-Workers> User <{username}@{TENANT}> IP <{ip}> TCP connection established without compression"
    else:
        dur = f"0:{random.randint(0, 59)}:{random.randint(0, 59)}"
        xmt = random.randint(1000000, 20000000)
        rcv = random.randint(1000000, 50000000)
        return f"{pri6}{ts} {ASA_HOSTNAME} %ASA-6-722023: Group <Remote-Workers> User <{username}@{TENANT}> IP <{ip}> Session disconnected. Session Type: SSL, Duration: {dur}, Bytes xmt: {xmt}, Bytes rcv: {rcv}"


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
    """Generate inter-site traffic (BOS↔ATL↔AUS via SD-WAN)."""
    events = []

    # Pick random site pair
    sites = ["BOS", "ATL", "AUS"]
    src_site = random.choice(sites)
    dst_site = random.choice([s for s in sites if s != src_site])

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


def generate_baseline_hour(base_date: str, day: int, hour: int, event_count: int) -> List[str]:
    """Generate baseline events for one hour.

    Event distribution (updated for perimeter traffic):
    - 30% Web sessions (inbound to DMZ) - correlates with access logs
    - 20% Outbound TCP sessions (users browsing)
    - 15% DNS queries
    - 12% Site-to-site traffic (BOS↔ATL↔AUS)
    - 8% NAT translations
    - 6% VPN sessions
    - 4% SSL handshakes
    - 3% HTTP inspection events
    - 2% Admin commands
    """
    events = []

    for _ in range(event_count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        event_type = random.randint(1, 100)

        if event_type <= 30:
            # Web sessions to DMZ (WEB-01/02)
            events.extend(asa_web_session(base_date, day, hour, minute, second))
        elif event_type <= 50:
            # Outbound TCP sessions
            events.extend(asa_tcp_session(base_date, day, hour, minute, second))
        elif event_type <= 65:
            # DNS queries
            events.extend(asa_dns_query(base_date, day, hour, minute, second))
        elif event_type <= 77:
            # Site-to-site traffic
            events.extend(asa_site_to_site(base_date, day, hour, minute, second))
        elif event_type <= 85:
            # NAT translations
            events.append(asa_nat(base_date, day, hour, minute, second))
            # Also add web NAT occasionally
            if random.random() < 0.3:
                events.append(asa_web_nat(base_date, day, hour, minute, second))
        elif event_type <= 91:
            # VPN sessions
            events.append(asa_vpn(base_date, day, hour, minute, second))
        elif event_type <= 95:
            # SSL handshakes
            events.append(asa_ssl(base_date, day, hour, minute, second))
        elif event_type <= 98:
            # HTTP inspection
            events.append(asa_http_inspect(base_date, day, hour, minute, second))
        else:
            # Admin commands
            events.append(asa_admin(base_date, day, hour, minute, second))

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
_time_utils = None


def init_scenarios(config: Config, company: Company, time_utils: TimeUtils):
    """Initialize scenario instances."""
    global _exfil_scenario, _memleak_scenario, _fw_misconfig_scenario, _ransomware_scenario, _cert_expiry_scenario, _time_utils
    _time_utils = time_utils
    _exfil_scenario = ExfilScenario(config, company, time_utils)
    _memleak_scenario = MemoryLeakScenario(demo_id_enabled=config.demo_id_enabled)
    _fw_misconfig_scenario = FirewallMisconfigScenario(demo_id_enabled=config.demo_id_enabled)
    _ransomware_scenario = RansomwareAttemptScenario(demo_id_enabled=config.demo_id_enabled)
    _cert_expiry_scenario = CertificateExpiryScenario(demo_id_enabled=config.demo_id_enabled)


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
        output_path = get_output_path("network", "cisco_asa.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_exfil = "exfil" in active_scenarios
    include_memory_leak = "memory_leak" in active_scenarios
    include_fw_misconfig = "firewall_misconfig" in active_scenarios
    include_ransomware = "ransomware_attempt" in active_scenarios
    include_cert_expiry = "certificate_expiry" in active_scenarios

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

            # Generate baseline
            all_events.extend(generate_baseline_hour(start_date, day, hour, hour_events))

            # Generate scenario events using new scenario classes
            if include_exfil:
                all_events.extend(_exfil_scenario.asa_hour(day, hour))

            if include_memory_leak:
                all_events.extend(_memleak_scenario.asa_generate_hour(day, hour, _time_utils))

            if include_fw_misconfig:
                all_events.extend(_fw_misconfig_scenario.generate_hour(day, hour, _time_utils))

            if include_ransomware:
                all_events.extend(_ransomware_scenario.asa_hour(day, hour, _time_utils))

            if include_cert_expiry:
                all_events.extend(_cert_expiry_scenario.asa_hour(day, hour, _time_utils))

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
