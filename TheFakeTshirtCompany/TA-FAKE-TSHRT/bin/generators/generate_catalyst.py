#!/usr/bin/env python3
"""
Cisco Catalyst IOS-XE syslog generator.

Generates 1 output file of IOS-XE syslog messages (RFC 3164 with PRI):
  - cisco_catalyst_syslog.log (~3K events/day)

Architecture: 3 Catalyst 9300-48UXM switches (distribution layer)
  - CAT-BOS-DIST-01 (10.10.10.30) - Boston primary
  - CAT-BOS-DIST-02 (10.10.10.31) - Boston secondary
  - CAT-ATL-DIST-01 (10.20.10.30) - Atlanta

Syslog format verified against Cisco IOS-XE 17.12 documentation.
PRI = Local7 (facility 23) + severity. Uses 'service timestamps log datetime msec year'.

Format: <PRI>seq: HOSTNAME: Mon DD YYYY HH:MM:SS.mmm: %FACILITY-SEV-MNEMONIC: Message
"""

import argparse
import hashlib
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
    USER_KEYS,
    SERVERS,
    TENANT,
    COMP_USER,
    COMP_WS_IP,
    LATERAL_USER,
    JESSICA_WS_IP,
    get_internal_ip,
    get_random_user,
)
from scenarios.registry import expand_scenarios, is_scenario_active_day

# =============================================================================
# CATALYST SWITCH CONFIGURATION
# =============================================================================

CATALYST_SWITCHES = {
    "CAT-BOS-DIST-01": {
        "ip": "10.10.10.30",
        "location": "BOS",
        "model": "C9300-48UXM",
        "ios_version": "17.12.4",
        "ports": 48,
        "uplink_ports": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"],
        "vlans": [10, 20, 30, 40, 50, 60, 70, 80, 100, 200],
        "role": "Distribution (primary)",
    },
    "CAT-BOS-DIST-02": {
        "ip": "10.10.10.31",
        "location": "BOS",
        "model": "C9300-48UXM",
        "ios_version": "17.12.4",
        "ports": 48,
        "uplink_ports": ["TenGigabitEthernet1/1/1", "TenGigabitEthernet1/1/2"],
        "vlans": [10, 20, 30, 40, 50, 60, 70, 80, 100, 200],
        "role": "Distribution (secondary)",
    },
    "CAT-ATL-DIST-01": {
        "ip": "10.20.10.30",
        "location": "ATL",
        "model": "C9300-48UXM",
        "ios_version": "17.12.4",
        "ports": 48,
        "uplink_ports": ["TenGigabitEthernet1/1/1"],
        "vlans": [10, 20, 30, 40, 50, 60, 70, 80],
        "role": "Distribution",
    },
}

SWITCH_NAMES = list(CATALYST_SWITCHES.keys())

# Network admin users (who can configure switches)
NET_ADMINS = [
    "patrick.gonzalez",   # Systems Administrator
    "stephanie.barnes",   # Network Administrator
    "keith.butler",       # Network Engineer (ATL)
    "jessica.brown",      # IT Administrator (ATL)
    "david.robinson",     # IT Director
]

# VTY source IPs (management workstations)
VTY_SOURCES = {
    "patrick.gonzalez": "10.10.30.182",
    "stephanie.barnes": "10.10.30.183",
    "keith.butler": "10.20.30.18",
    "jessica.brown": "10.20.30.15",
    "david.robinson": "10.10.30.180",
}

# Local7 facility (23) -- PRI = facility * 8 + severity
# Severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
_FACILITY_LOCAL7 = 23

def _pri(severity: int) -> int:
    """Calculate PRI value for Local7 facility + given severity."""
    return _FACILITY_LOCAL7 * 8 + severity

# PRI values by severity
PRI_EMERGENCY = _pri(0)  # 184
PRI_ALERT = _pri(1)      # 185
PRI_CRITICAL = _pri(2)   # 186
PRI_ERROR = _pri(3)      # 187
PRI_WARNING = _pri(4)    # 188
PRI_NOTICE = _pri(5)     # 189
PRI_INFO = _pri(6)       # 190
PRI_DEBUG = _pri(7)      # 191

# =============================================================================
# SYSLOG MESSAGE TEMPLATES
# =============================================================================

# Interface events (link up/down, line protocol changes)
INTERFACE_EVENTS = [
    # (mnemonic, severity, pri, message_template, weight)
    ("%LINEPROTO-5-UPDOWN", 5, PRI_NOTICE,
     "Line protocol on Interface {port}, changed state to {state}", 15),
    ("%LINK-3-UPDOWN", 3, PRI_ERROR,
     "Interface {port}, changed state to {state}", 8),
    ("%LINK-5-CHANGED", 5, PRI_NOTICE,
     "Interface {port}, changed state to administratively {state}", 3),
]

# 802.1X / Authentication events
AUTH_EVENTS = [
    ("%DOT1X-5-SUCCESS", 5, PRI_NOTICE,
     "Authentication successful for client ({mac}) on Interface {port} AuditSessionID {session_id}", 20),
    ("%DOT1X-5-FAIL", 5, PRI_NOTICE,
     "Authentication failed for client ({mac}) on Interface {port} AuditSessionID {session_id}", 3),
    ("%MAB-5-SUCCESS", 5, PRI_NOTICE,
     "Authentication successful for client ({mac}) on Interface {port} AuditSessionID {session_id}", 10),
    ("%MAB-5-FAIL", 5, PRI_NOTICE,
     "Authentication failed for client ({mac}) on Interface {port} AuditSessionID {session_id}", 2),
    ("%AUTHMGR-5-START", 5, PRI_NOTICE,
     "Starting 'dot1x' for client ({mac}) on Interface {port} AuditSessionID {session_id}", 15),
    ("%AUTHMGR-5-SUCCESS", 5, PRI_NOTICE,
     "Authorization succeeded for client ({mac}) on Interface {port} AuditSessionID {session_id}", 15),
]

# System events
SYSTEM_EVENTS = [
    ("%SYS-5-CONFIG_I", 5, PRI_NOTICE,
     "Configured from console by {admin} on vty0 ({admin_ip})", 5),
    ("%SYS-5-RESTART", 5, PRI_NOTICE,
     "System restarted --\nCisco IOS Software [Dublin], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {version}, RELEASE SOFTWARE", 1),
    ("%SYS-6-LOGGINGHOST_STARTSTOP", 6, PRI_INFO,
     "Logging to host 10.20.20.30 port 514 started - CLI initiated", 1),
    ("%SEC_LOGIN-5-LOGIN_SUCCESS", 5, PRI_NOTICE,
     "Login Success [user: {admin}] [Source: {admin_ip}] [localport: 22] at {timestamp}", 5),
    ("%SEC_LOGIN-4-LOGIN_FAILED", 4, PRI_WARNING,
     "Login failure [user: {admin}] [Source: {admin_ip}] [localport: 22] [Reason: Invalid password] at {timestamp}", 1),
]

# Spanning Tree events
STP_EVENTS = [
    ("%SPANTREE-5-TOPOTRAP", 5, PRI_NOTICE,
     "Topology change Trap for vlan {vlan}", 3),
    ("%SPANTREE-2-ROOTGUARD_BLOCK", 2, PRI_CRITICAL,
     "Root guard blocking port {port} on VLAN{vlan}", 1),
    ("%SPANTREE-5-EXTENDED_SYSID", 5, PRI_NOTICE,
     "Extended SysId enabled for type vlan", 1),
]

# Switch / Platform events
SWITCH_EVENTS = [
    ("%SW_MATM-4-MACFLAP_NOTIF", 4, PRI_WARNING,
     "Host {mac} in vlan {vlan} is flapping between port {port1} and port {port2}", 2),
    ("%PLATFORM_ENV-6-INLET", 6, PRI_INFO,
     "Switch 1: Inlet temperature normal ({temp}C)", 3),
    ("%ILPOWER-5-POWER_GRANTED", 5, PRI_NOTICE,
     "Interface {port}: Power granted ({watts}W)", 5),
    ("%ILPOWER-7-DETECT", 7, PRI_DEBUG,
     "Interface {port}: PD detected: IEEE PD", 3),
    ("%CDP-4-NATIVE_VLAN_MISMATCH", 4, PRI_WARNING,
     "Native VLAN mismatch discovered on {port} ({vlan1}), with {neighbor} {remote_port} ({vlan2})", 1),
    ("%STACKMGR-5-SWITCH_ADDED", 5, PRI_NOTICE,
     "Switch 1 has been added to the stack", 1),
]

# PoE events (for IP phones, APs, cameras)
POE_DEVICES = [
    "Cisco IP Phone", "Meraki MR46", "Meraki MV12",
    "Meraki MT10", "Desk Pro",
]


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _weighted_choice(items: list) -> Any:
    """Pick from items where last element is weight."""
    weights = [i[-1] for i in items]
    return random.choices(items, weights=weights, k=1)[0]


def _random_port(switch_name: str, access: bool = True) -> str:
    """Generate a random interface name."""
    switch = CATALYST_SWITCHES[switch_name]
    if access:
        slot = 1
        port_num = random.randint(1, switch["ports"])
        return f"GigabitEthernet1/0/{port_num}"
    else:
        # Uplink
        return random.choice(switch["uplink_ports"])


def _random_mac() -> str:
    """Generate a random MAC address (lowercase, colon-separated)."""
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def _random_vlan(switch_name: str) -> int:
    """Get a random VLAN for a switch."""
    return random.choice(CATALYST_SWITCHES[switch_name]["vlans"])


def _random_session_id() -> str:
    """Generate a random AuditSessionID (hex string)."""
    return f"{random.randint(0, 0xFFFFFFFF):08x}"


def _format_syslog_ts(start_date: str, day: int, hour: int,
                      minute: int = None, second: int = None,
                      ms: int = None) -> str:
    """Generate IOS-XE syslog timestamp: 'Mon DD YYYY HH:MM:SS.mmm'

    With 'service timestamps log datetime msec year':
        Jan  5 2026 14:23:45.326
    """
    if minute is None:
        minute = random.randint(0, 59)
    if second is None:
        second = random.randint(0, 59)
    if ms is None:
        ms = random.randint(0, 999)
    dt = date_add(start_date, day).replace(hour=hour, minute=minute, second=second)
    # IOS-XE uses space-padded day: "Jan  5" not "Jan 05"
    month = dt.strftime("%b")
    day_num = dt.day
    return f"{month} {day_num:2d} {dt.strftime('%Y %H:%M:%S')}.{ms:03d}"


def _build_syslog_line(pri: int, seq: int, hostname: str,
                       timestamp: str, message: str,
                       demo_id: str = "") -> str:
    """Build complete syslog line in IOS-XE format.

    Format: <PRI>seq: HOSTNAME: TIMESTAMP: MESSAGE demo_id=xxx
    """
    line = f"<{pri}>{seq}: {hostname}: {timestamp}: {message}"
    if demo_id:
        line += f" demo_id={demo_id}"
    return line


# =============================================================================
# EVENT GENERATORS
# =============================================================================

def _generate_interface_event(start_date: str, day: int, hour: int,
                              switch_name: str, seq: int,
                              demo_id: str = "") -> str:
    """Generate an interface up/down syslog event."""
    event = _weighted_choice(INTERFACE_EVENTS)
    mnemonic, severity, pri, template, _ = event

    port = _random_port(switch_name)
    state = random.choice(["up", "down"])

    # Most events are "up" (recovery after brief flap)
    if random.random() < 0.7:
        state = "up"

    ts = _format_syslog_ts(start_date, day, hour)
    msg = f"{mnemonic}: {template.format(port=port, state=state)}"
    return _build_syslog_line(pri, seq, switch_name, ts, msg, demo_id)


def _generate_auth_event(start_date: str, day: int, hour: int,
                         switch_name: str, seq: int,
                         mac_override: str = None,
                         port_override: str = None,
                         demo_id: str = "") -> str:
    """Generate an 802.1X/MAB authentication syslog event."""
    event = _weighted_choice(AUTH_EVENTS)
    mnemonic, severity, pri, template, _ = event

    mac = mac_override or _random_mac()
    port = port_override or _random_port(switch_name)
    session_id = _random_session_id()

    ts = _format_syslog_ts(start_date, day, hour)
    msg = f"{mnemonic}: {template.format(mac=mac, port=port, session_id=session_id)}"
    return _build_syslog_line(pri, seq, switch_name, ts, msg, demo_id)


def _generate_system_event(start_date: str, day: int, hour: int,
                           switch_name: str, seq: int,
                           demo_id: str = "") -> str:
    """Generate a system syslog event (config change, login, etc.)."""
    event = _weighted_choice(SYSTEM_EVENTS)
    mnemonic, severity, pri, template, _ = event

    admin = random.choice(NET_ADMINS)
    admin_ip = VTY_SOURCES.get(admin, "10.10.30.180")
    version = CATALYST_SWITCHES[switch_name]["ios_version"]

    ts_str = _format_syslog_ts(start_date, day, hour)
    msg = f"{mnemonic}: {template.format(admin=admin, admin_ip=admin_ip, version=version, timestamp=ts_str)}"
    return _build_syslog_line(pri, seq, switch_name, ts_str, msg, demo_id)


def _generate_stp_event(start_date: str, day: int, hour: int,
                        switch_name: str, seq: int,
                        demo_id: str = "") -> str:
    """Generate a spanning tree syslog event."""
    event = _weighted_choice(STP_EVENTS)
    mnemonic, severity, pri, template, _ = event

    vlan = _random_vlan(switch_name)
    port = _random_port(switch_name)

    ts = _format_syslog_ts(start_date, day, hour)
    msg = f"{mnemonic}: {template.format(vlan=vlan, port=port)}"
    return _build_syslog_line(pri, seq, switch_name, ts, msg, demo_id)


def _generate_switch_event(start_date: str, day: int, hour: int,
                           switch_name: str, seq: int,
                           demo_id: str = "") -> str:
    """Generate a switch platform syslog event (MAC flap, PoE, CDP, etc.)."""
    event = _weighted_choice(SWITCH_EVENTS)
    mnemonic, severity, pri, template, _ = event

    mac = _random_mac()
    vlan = _random_vlan(switch_name)
    port1 = _random_port(switch_name)
    port2 = _random_port(switch_name)
    temp = random.randint(32, 45)
    watts = random.choice([15, 30, 60])
    neighbor = random.choice(SWITCH_NAMES)
    remote_port = _random_port(neighbor)
    vlan1 = vlan
    vlan2 = random.choice([1, 10, 20])

    ts = _format_syslog_ts(start_date, day, hour)
    msg = f"{mnemonic}: {template.format(mac=mac, vlan=vlan, port=port1, port1=port1, port2=port2, temp=temp, watts=watts, neighbor=neighbor, remote_port=remote_port, vlan1=vlan1, vlan2=vlan2)}"
    return _build_syslog_line(pri, seq, switch_name, ts, msg, demo_id)


# Event type generators and their baseline weights
EVENT_GENERATORS = [
    (_generate_auth_event, 40),       # 802.1X is most common
    (_generate_interface_event, 20),   # Link state changes
    (_generate_switch_event, 15),      # PoE, MAC table, etc.
    (_generate_system_event, 10),      # Config, logins
    (_generate_stp_event, 5),          # STP topology
]


# =============================================================================
# SCENARIO INTEGRATION
# =============================================================================

def _generate_exfil_events(start_date: str, day: int, hour: int,
                           seq_counter: list) -> List[str]:
    """Generate Catalyst events for exfil scenario.

    Days 5-7: MAC flap on lateral movement, 802.1X events from stolen creds.
    """
    events = []

    if 5 <= day <= 7:
        # MAC flap: attacker laptop seen on multiple ports (lateral movement)
        if hour in (10, 14, 22) and random.random() < 0.5:
            switch = "CAT-BOS-DIST-01"
            mac = "02:00:de:ad:be:ef"  # Attacker MAC
            vlan = 30  # User VLAN
            port1 = f"GigabitEthernet1/0/{random.randint(1, 24)}"
            port2 = f"GigabitEthernet1/0/{random.randint(25, 48)}"
            ts = _format_syslog_ts(start_date, day, hour)
            msg = f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is flapping between port {port1} and port {port2}"
            seq_counter[0] += 1
            events.append(_build_syslog_line(PRI_WARNING, seq_counter[0], switch, ts, msg, "exfil"))

        # 802.1X with suspicious timing (after hours)
        if hour >= 20 and random.random() < 0.4:
            switch = random.choice(["CAT-BOS-DIST-01", "CAT-BOS-DIST-02"])
            port = f"GigabitEthernet1/0/{random.randint(1, 48)}"
            session_id = _random_session_id()
            ts = _format_syslog_ts(start_date, day, hour)
            msg = f"%DOT1X-5-SUCCESS: Authentication successful for client (02:00:de:ad:be:ef) on Interface {port} AuditSessionID {session_id}"
            seq_counter[0] += 1
            events.append(_build_syslog_line(PRI_NOTICE, seq_counter[0], switch, ts, msg, "exfil"))

    return events


def _generate_ddos_events(start_date: str, day: int, hour: int,
                          seq_counter: list) -> List[str]:
    """Generate Catalyst events for ddos_attack scenario.

    Days 17-18: Interface utilization warnings on uplink ports.
    """
    events = []

    if 17 <= day <= 18 and 10 <= hour <= 20:
        # Uplink interface flapping under load
        if random.random() < 0.3:
            switch = "CAT-BOS-DIST-01"
            uplink = random.choice(CATALYST_SWITCHES[switch]["uplink_ports"])
            ts = _format_syslog_ts(start_date, day, hour)

            # Link flap from overload
            msg = f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {uplink}, changed state to down"
            seq_counter[0] += 1
            events.append(_build_syslog_line(PRI_NOTICE, seq_counter[0], switch, ts, msg, "ddos_attack"))

            # Recovery a few seconds later
            ts2 = _format_syslog_ts(start_date, day, hour)
            msg2 = f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {uplink}, changed state to up"
            seq_counter[0] += 1
            events.append(_build_syslog_line(PRI_NOTICE, seq_counter[0], switch, ts2, msg2, "ddos_attack"))

    return events


def _generate_firewall_misconfig_events(start_date: str, day: int, hour: int,
                                        seq_counter: list) -> List[str]:
    """Generate Catalyst events for firewall_misconfig scenario.

    Day 6: STP reconvergence from network instability.
    """
    events = []

    if day == 6 and 10 <= hour <= 12:
        # STP reconvergence
        if random.random() < 0.6:
            for switch in SWITCH_NAMES:
                vlan = random.choice([10, 20, 30])
                ts = _format_syslog_ts(start_date, day, hour)
                msg = f"%SPANTREE-5-TOPOTRAP: Topology change Trap for vlan {vlan}"
                seq_counter[0] += 1
                events.append(_build_syslog_line(PRI_NOTICE, seq_counter[0], switch, ts, msg, "firewall_misconfig"))

    return events


# =============================================================================
# MAIN GENERATOR FUNCTION
# =============================================================================

def generate_catalyst_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:
    """Generate Cisco Catalyst IOS-XE syslog logs.

    Args:
        start_date: Start date in YYYY-MM-DD format
        days: Number of days to generate
        scale: Volume multiplier (1.0 = normal)
        scenarios: Comma-separated scenario names or "none"/"all"
        output_file: Override output path
        quiet: Suppress progress output

    Returns:
        int: Number of events generated
    """
    active_scenarios = expand_scenarios(scenarios)

    if output_file:
        output_path = Path(output_file)
    else:
        output_path = get_output_path("network", "cisco_catalyst/cisco_catalyst_syslog.log")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print("  Cisco Catalyst IOS-XE Syslog Generator", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Scale: {scale}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {output_path}", file=sys.stderr)
        print(f"  Switches: {', '.join(SWITCH_NAMES)}", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    all_events: List[str] = []
    demo_id_count = 0

    # ~125 events/hr peak across 3 switches -> ~3K/day
    base_events_per_hour = int(125 * scale)

    # Sequence counter per switch (shared across all events)
    seq_counters = {sw: [100] for sw in SWITCH_NAMES}  # Start at 100

    for day in range(days):
        day_date = date_add(start_date, day)
        date_str = day_date.strftime("%Y-%m-%d")

        if not quiet:
            print(f"  [Catalyst] Day {day + 1}/{days} ({date_str})...",
                  file=sys.stderr, end="\r")

        for hour in range(24):
            # Natural volume variation (auth-like pattern: business hours)
            hour_count = calc_natural_events(
                base_events_per_hour, start_date, day, hour, "auth"
            )

            # Distribute events across switches (BOS gets more)
            for _ in range(hour_count):
                # 45% BOS-01, 35% BOS-02, 20% ATL
                roll = random.random()
                if roll < 0.45:
                    switch = "CAT-BOS-DIST-01"
                elif roll < 0.80:
                    switch = "CAT-BOS-DIST-02"
                else:
                    switch = "CAT-ATL-DIST-01"

                # Pick event type
                gen_func, _ = _weighted_choice(
                    [(g, w) for g, w in EVENT_GENERATORS]
                )

                seq_counters[switch][0] += 1
                event = gen_func(start_date, day, hour, switch, seq_counters[switch][0])

                # Prepend sortable timestamp for ordering
                sort_key = _format_syslog_ts(start_date, day, hour)
                all_events.append(f"{sort_key}\t{event}")

            # Scenario events
            if "exfil" in active_scenarios and is_scenario_active_day("exfil", day):
                # Use BOS-01 seq counter for scenario events
                exfil_evts = _generate_exfil_events(start_date, day, hour, seq_counters["CAT-BOS-DIST-01"])
                for e in exfil_evts:
                    sort_key = _format_syslog_ts(start_date, day, hour)
                    all_events.append(f"{sort_key}\t{e}")
                demo_id_count += len(exfil_evts)

            if "ddos_attack" in active_scenarios and is_scenario_active_day("ddos_attack", day):
                ddos_evts = _generate_ddos_events(start_date, day, hour, seq_counters["CAT-BOS-DIST-01"])
                for e in ddos_evts:
                    sort_key = _format_syslog_ts(start_date, day, hour)
                    all_events.append(f"{sort_key}\t{e}")
                demo_id_count += len(ddos_evts)

            if "firewall_misconfig" in active_scenarios and is_scenario_active_day("firewall_misconfig", day):
                fw_evts = _generate_firewall_misconfig_events(start_date, day, hour, seq_counters["CAT-BOS-DIST-01"])
                for e in fw_evts:
                    sort_key = _format_syslog_ts(start_date, day, hour)
                    all_events.append(f"{sort_key}\t{e}")
                demo_id_count += len(fw_evts)

    # Sort by timestamp
    all_events.sort()

    # Write to file (strip sort prefix)
    with open(output_path, "w") as f:
        for ev in all_events:
            idx = ev.index("\t")
            f.write(ev[idx + 1:] + "\n")

    if not quiet:
        print(f"  [Catalyst] Complete! {len(all_events):,} events written",
              file=sys.stderr)
        if demo_id_count:
            print(f"          demo_id events: {demo_id_count:,}", file=sys.stderr)

    return len(all_events)


# =============================================================================
# CLI ENTRY POINT
# =============================================================================

def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate Cisco Catalyst IOS-XE syslog logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --days=7                    Generate 7 days of logs
  %(prog)s --days=14 --scenarios=exfil Generate with exfil scenario
  %(prog)s --scale=2.0                 Double the event volume
  %(prog)s --quiet                     Suppress progress output
        """
    )
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none")
    parser.add_argument("--output", help="Output file path override")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()

    count = generate_catalyst_logs(
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
