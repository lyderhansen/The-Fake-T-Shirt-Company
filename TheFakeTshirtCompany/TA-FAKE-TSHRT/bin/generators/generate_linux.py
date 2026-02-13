#!/usr/bin/env python3
"""
Linux System Metrics Generator + Auth Log Generator.
Generates CPU, memory, disk, and network metrics with natural variation.
Also generates auth.log events (SSH, sudo, cron, systemd) for Linux servers.

Includes scenario support:
  - exfil: High CPU/memory during staging, high network during exfiltration
  - memory_leak: Gradual memory increase on WEB-01 until OOM crash
"""

import argparse
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import Config, DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import TimeUtils, ts_linux, date_add, get_hour_activity_level, is_weekend, calc_natural_events
from shared.company import Company, LINUX_SERVERS, SERVERS, USERS, USER_KEYS, get_random_user
from scenarios.security import ExfilScenario
from scenarios.ops import MemoryLeakScenario
from scenarios.ops.disk_filling import DiskFillingScenario
from scenarios.network.ddos_attack import DdosAttackScenario
from scenarios.registry import expand_scenarios

# =============================================================================
# LINUX CONFIGURATION
# =============================================================================

LINUX_INTERVAL = 300  # 5 minutes
INTERVALS_PER_HOUR = 12
INTERVALS_PER_DAY = 288

# WEB-01 is 64GB, WEB-02 is 16GB
SERVER_RAM_MB = {
    "WEB-01": 65536,  # 64GB
    "WEB-02": 16384,  # 16GB
}


# =============================================================================
# METRIC GENERATORS
# =============================================================================

def get_hour_multiplier(hour: int, is_wknd: bool) -> float:
    """Get activity multiplier for hour."""
    activity = get_hour_activity_level(hour, is_wknd)
    return activity / 100.0


def cpu_metric(ts: str, host: str, cpu_min: int, cpu_max: int, hour_mult: float,
               cpu_adjustment: int = 0, demo_id: str = "") -> str:
    """Generate CPU metric."""
    # Adjust based on hour
    base_cpu = random.uniform(cpu_min, cpu_max)
    cpu = base_cpu * (0.6 + 0.4 * hour_mult)  # Scale between 60% and 100% based on activity

    # Add scenario adjustment
    cpu += cpu_adjustment

    cpu = min(100, max(1, cpu))

    line = f'{ts} host={host} cpu_count=4 CPU pctIdle={100-cpu:.1f} pctUser={cpu*0.7:.1f} pctSystem={cpu*0.2:.1f} pctIOWait={cpu*0.1:.1f}'
    if demo_id:
        line += f' demo_id={demo_id}'
    return line


def memory_metric(ts: str, host: str, ram_min: int, ram_max: int, hour_mult: float,
                  total_mb: int = 16384, mem_pct_override: Optional[int] = None,
                  swap_kb: int = 0, demo_id: str = "") -> str:
    """Generate memory metric."""
    if mem_pct_override is not None:
        ram = mem_pct_override
    else:
        base_ram = random.uniform(ram_min, ram_max)
        ram = base_ram * (0.7 + 0.3 * hour_mult)
        ram = min(95, max(20, ram))

    used_mb = int(total_mb * ram / 100)
    free_mb = total_mb - used_mb
    cached_mb = int(free_mb * 0.6)
    swap_mb = swap_kb // 1024

    line = f'{ts} host={host} memTotalMB={total_mb} memUsedMB={used_mb} memFreeMB={free_mb} memCachedMB={cached_mb} pctUsed={ram:.1f}'
    if swap_mb > 0:
        line += f' swapUsedMB={swap_mb}'
    if demo_id:
        line += f' demo_id={demo_id}'
    return line


def disk_metric(ts: str, host: str, demo_id: str = "",
                disk_pct_override: Optional[float] = None) -> str:
    """Generate disk metric."""
    total_gb = 500

    if disk_pct_override is not None:
        used_pct = disk_pct_override
    else:
        used_pct = random.uniform(40, 70)

    used_gb = int(total_gb * used_pct / 100)
    avail_gb = total_gb - used_gb

    line = f'{ts} host={host} mount=/ TotalGB={total_gb} UsedGB={used_gb} AvailGB={avail_gb} UsedPct={used_pct:.1f}'
    if demo_id:
        line += f' demo_id={demo_id}'
    return line


def iostat_metric(ts: str, host: str, hour_mult: float, demo_id: str = "") -> str:
    """Generate iostat metric."""
    read_kb = int(random.uniform(100, 5000) * hour_mult)
    write_kb = int(random.uniform(50, 2000) * hour_mult)
    await_ms = random.uniform(0.5, 10) * (2 - hour_mult)  # Higher wait when less active

    line = f'{ts} host={host} device=sda rkB_s={read_kb} wkB_s={write_kb} await={await_ms:.2f} pctUtil={random.uniform(5, 30):.1f}'
    if demo_id:
        line += f' demo_id={demo_id}'
    return line


def network_metric(ts: str, host: str, hour_mult: float,
                   network_multiplier: int = 100, demo_id: str = "") -> str:
    """Generate network interface metric."""
    base_rx_kb = int(random.uniform(500, 50000) * hour_mult)
    base_tx_kb = int(random.uniform(200, 20000) * hour_mult)

    # Apply scenario multiplier
    rx_kb = base_rx_kb * network_multiplier // 100
    tx_kb = base_tx_kb * network_multiplier // 100

    rx_packets = rx_kb * random.randint(10, 50)
    tx_packets = tx_kb * random.randint(10, 50)

    line = f'{ts} host={host} interface=eth0 rxKB_s={rx_kb} txKB_s={tx_kb} rxPackets={rx_packets} txPackets={tx_packets}'
    if demo_id:
        line += f' demo_id={demo_id}'
    return line


def generate_host_interval(base_date: str, day: int, hour: int, minute: int,
                           host: str, server: object, hour_mult: float,
                           exfil_scenario: Optional[ExfilScenario] = None,
                           memleak_scenario: Optional[MemoryLeakScenario] = None,
                           diskfill_scenario: Optional[DiskFillingScenario] = None,
                           ddos_scenario: Optional[DdosAttackScenario] = None) -> Dict[str, List[str]]:
    """Generate all metrics for one host at one interval."""
    ts = ts_linux(base_date, day, hour, minute, 0)

    # Default values
    cpu_adjustment = 0
    mem_pct_override = None
    disk_pct_override = None
    swap_kb = 0
    network_multiplier = 100

    # Per-metric demo_id tracking (scenarios can affect different metrics independently)
    cpu_demo_id = ""
    mem_demo_id = ""
    disk_demo_id = ""
    net_demo_id = ""

    total_mb = SERVER_RAM_MB.get(host, 16384)

    # Apply exfil scenario adjustments
    if exfil_scenario:
        cpu_spike = exfil_scenario.linux_cpu_anomaly(host, day, hour)
        mem_spike = exfil_scenario.linux_memory_anomaly(host, day, hour)
        net_mult = exfil_scenario.linux_network_anomaly(host, day, hour)

        if cpu_spike > 0:
            cpu_adjustment += cpu_spike
            cpu_demo_id = "exfil"
        if mem_spike > 0:
            mem_demo_id = "exfil"
        if net_mult != 100:
            network_multiplier = net_mult
            net_demo_id = "exfil"

    # Apply memory leak scenario adjustments
    # Always get memory metrics for target host (handles both active and resolved states)
    if memleak_scenario:
        mem_pct = memleak_scenario.get_memory_pct(host, day, hour)
        if mem_pct is not None:
            mem_pct_override = mem_pct
            # Only set demo_id during active phase
            if memleak_scenario.is_active(host, day, hour):
                mem_demo_id = "memory_leak"

        cpu_adj = memleak_scenario.get_cpu_adjustment(host, day, hour)
        if cpu_adj > 0:
            cpu_adjustment += cpu_adj
            cpu_demo_id = cpu_demo_id or "memory_leak"

        swap_kb = memleak_scenario.get_swap_kb(host, day, hour)

    # Apply disk filling scenario adjustments
    # Always get disk_pct for target host (handles both active and resolved states)
    if diskfill_scenario:
        disk_pct = diskfill_scenario.get_disk_pct(host, day, hour)
        if disk_pct is not None:
            disk_pct_override = disk_pct
            # Only set demo_id during active phase
            if diskfill_scenario.is_active(host, day, hour):
                disk_demo_id = "disk_filling"

        # Add I/O wait impact to CPU when disk is filling
        io_wait_adj = diskfill_scenario.get_io_wait_pct(host, day, hour)
        if io_wait_adj > 0:
            cpu_adjustment += int(io_wait_adj)
            cpu_demo_id = cpu_demo_id or "disk_filling"

    # Apply DDoS attack scenario adjustments (WEB-01: high CPU + network)
    if ddos_scenario:
        ddos_cpu_adj = ddos_scenario.linux_cpu_adjustment(host, day, hour)
        if ddos_cpu_adj > 0:
            cpu_adjustment += ddos_cpu_adj
            cpu_demo_id = cpu_demo_id or "ddos_attack"

        ddos_net_mult = ddos_scenario.linux_network_multiplier(host, day, hour)
        if ddos_net_mult != 100:
            network_multiplier = max(network_multiplier, ddos_net_mult)
            net_demo_id = net_demo_id or "ddos_attack"

    metrics = {
        "cpu": [cpu_metric(ts, host, server.cpu_baseline_min, server.cpu_baseline_max,
                          hour_mult, cpu_adjustment, cpu_demo_id or disk_demo_id)],
        "vmstat": [memory_metric(ts, host, server.ram_baseline_min, server.ram_baseline_max,
                                hour_mult, total_mb, mem_pct_override, swap_kb, mem_demo_id)],
        "df": [disk_metric(ts, host, disk_demo_id, disk_pct_override)],
        "iostat": [iostat_metric(ts, host, hour_mult, disk_demo_id or cpu_demo_id)],
        "interfaces": [network_metric(ts, host, hour_mult, network_multiplier, net_demo_id)],
    }

    return metrics


# =============================================================================
# AUTH.LOG CONFIGURATION
# =============================================================================

# SSH key types for publickey auth
SSH_KEY_TYPES = ["RSA", "ED25519", "ECDSA"]

# Linux admin/service users that SSH into servers
LINUX_ADMIN_USERS = ["root", "svc.deploy", "svc.monitor", "ansible"]

# Cron jobs per server (host -> list of (minute, user, command))
CRON_JOBS = {
    "WEB-01": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (5, "www-data", "/usr/local/bin/cleanup_sessions.sh"),
        (15, "root", "/usr/local/bin/ssl_check.sh"),
        (30, "root", "/usr/bin/certbot renew --quiet"),
    ],
    "WEB-02": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (5, "www-data", "/usr/local/bin/cleanup_sessions.sh"),
    ],
    "MON-ATL-01": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (5, "nagios", "/usr/local/nagios/bin/nagios -v /usr/local/nagios/etc/nagios.cfg"),
        (10, "root", "/usr/local/bin/backup_configs.sh"),
        (30, "root", "/usr/local/bin/disk_cleanup.sh"),
        (45, "root", "/usr/local/bin/health_report.sh"),
    ],
    "BASTION-BOS-01": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (15, "root", "/usr/local/bin/session_audit.sh"),
    ],
    "SAP-PROD-01": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (5, "sapadm", "/usr/sap/scripts/sapcontrol_check.sh"),
    ],
    "SAP-DB-01": [
        (0, "root", "/usr/sbin/logrotate /etc/logrotate.conf"),
        (5, "hdbadm", "/usr/sap/HDB/HDB00/exe/sapcontrol -prot NI_HTTP -nr 00 -function GetProcessList"),
        (30, "root", "/usr/local/bin/hana_backup_check.sh"),
    ],
}

# Systemd services per server
SYSTEMD_SERVICES = {
    "WEB-01": ["nginx", "php-fpm", "redis-server", "fail2ban"],
    "WEB-02": ["nginx", "php-fpm", "redis-server", "fail2ban"],
    "MON-ATL-01": ["nagios", "snmpd", "rsyslog", "prometheus-node-exporter"],
    "BASTION-BOS-01": ["sshd", "fail2ban", "auditd"],
    "SAP-PROD-01": ["sapstartsrv", "sapinit"],
    "SAP-DB-01": ["sapstartsrv", "sapinit", "hdbdaemon"],
}

# Sudo commands run by admins
SUDO_COMMANDS = [
    "systemctl status nginx",
    "systemctl restart php-fpm",
    "tail -100 /var/log/syslog",
    "journalctl -u nginx --since '1 hour ago'",
    "cat /etc/hosts",
    "netstat -tlnp",
    "df -h",
    "free -m",
    "top -bn1 | head -20",
    "cat /var/log/auth.log | tail -50",
    "iptables -L -n",
    "apt list --upgradable",
    "yum check-update",
    "docker ps",
    "ps aux | grep java",
]

# Failed SSH source IPs (internet scanners — low baseline noise)
SSH_SCANNER_IPS = [
    "45.227.255.10", "103.45.67.89", "198.51.100.42",
    "91.134.56.78", "185.156.73.44", "112.85.42.105",
]
SSH_SCANNER_USERS = [
    "root", "admin", "test", "ubuntu", "oracle", "postgres",
    "ftpuser", "mysql", "git", "deploy",
]

# Base auth events per peak hour per host
AUTH_BASE_EVENTS_PER_PEAK_HOUR = 8


# =============================================================================
# AUTH.LOG EVENT GENERATORS
# =============================================================================

def _auth_ts(base_date: str, day: int, hour: int, minute: int, second: int) -> str:
    """Generate auth.log timestamp: 'Jan  5 14:23:45'."""
    dt = date_add(base_date, day).replace(hour=hour, minute=minute, second=second)
    # Auth.log uses abbreviated month, space-padded day
    return dt.strftime("%b %e %H:%M:%S")


def auth_ssh_accepted(base_date: str, day: int, hour: int, minute: int, second: int,
                      host: str, user: str, source_ip: str,
                      auth_method: str = "publickey",
                      demo_id: str = "") -> str:
    """Generate successful SSH login event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    port = random.randint(49152, 65535)

    if auth_method == "publickey":
        key_type = random.choice(SSH_KEY_TYPES)
        key_fp = ":".join(f"{random.randint(0, 255):02x}" for _ in range(16))
        line = f"{ts} {host} sshd[{random.randint(1000, 30000)}]: Accepted publickey for {user} from {source_ip} port {port} ssh2: {key_type} SHA256:{key_fp}"
    else:
        line = f"{ts} {host} sshd[{random.randint(1000, 30000)}]: Accepted password for {user} from {source_ip} port {port} ssh2"

    if demo_id:
        line += f" demo_id={demo_id}"
    return line


def auth_ssh_failed(base_date: str, day: int, hour: int, minute: int, second: int,
                    host: str, user: str, source_ip: str,
                    demo_id: str = "") -> str:
    """Generate failed SSH login event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    port = random.randint(49152, 65535)
    line = f"{ts} {host} sshd[{random.randint(1000, 30000)}]: Failed password for {'invalid user ' if user in SSH_SCANNER_USERS else ''}{user} from {source_ip} port {port} ssh2"
    if demo_id:
        line += f" demo_id={demo_id}"
    return line


def auth_sudo(base_date: str, day: int, hour: int, minute: int, second: int,
              host: str, user: str, command: str,
              demo_id: str = "") -> str:
    """Generate sudo command execution event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    line = f"{ts} {host} sudo: {user} : TTY=pts/{random.randint(0, 5)} ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
    if demo_id:
        line += f" demo_id={demo_id}"
    return line


def auth_cron(base_date: str, day: int, hour: int, minute: int, second: int,
              host: str, user: str, command: str) -> str:
    """Generate cron job execution event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    return f"{ts} {host} CRON[{random.randint(10000, 50000)}]: ({user}) CMD ({command})"


def auth_systemd(base_date: str, day: int, hour: int, minute: int, second: int,
                 host: str, service: str, action: str) -> str:
    """Generate systemd service event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    if action == "started":
        return f"{ts} {host} systemd[1]: Started {service}.service - {service} service."
    elif action == "stopped":
        return f"{ts} {host} systemd[1]: Stopped {service}.service - {service} service."
    elif action == "reloaded":
        return f"{ts} {host} systemd[1]: Reloading {service}.service - {service} service..."
    return f"{ts} {host} systemd[1]: {service}.service: {action}"


def auth_session_open(base_date: str, day: int, hour: int, minute: int, second: int,
                      host: str, user: str, session_id: int) -> str:
    """Generate PAM session open event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    return f"{ts} {host} systemd-logind[{random.randint(500, 2000)}]: New session {session_id} of user {user}."


def auth_session_close(base_date: str, day: int, hour: int, minute: int, second: int,
                       host: str, user: str, session_id: int) -> str:
    """Generate PAM session close event."""
    ts = _auth_ts(base_date, day, hour, minute, second)
    return f"{ts} {host} systemd-logind[{random.randint(500, 2000)}]: Session {session_id} logged out. Waiting for processes to exit."


# =============================================================================
# AUTH.LOG BASELINE GENERATION
# =============================================================================

def generate_auth_hour(base_date: str, day: int, hour: int, host: str,
                       scale: float = 1.0) -> List[str]:
    """Generate auth.log events for one host for one hour.

    Event mix:
    - SSH accepted (publickey from admins/deploy) ~30%
    - SSH failed (internet scanners, low) ~10%
    - sudo commands ~20%
    - cron jobs (deterministic per-hour) ~20%
    - systemd service events ~10%
    - session open/close ~10%
    """
    events = []
    dt = date_add(base_date, day)
    is_wknd = is_weekend(dt)

    # Calculate event count with natural variation
    event_count = calc_natural_events(
        max(1, int(AUTH_BASE_EVENTS_PER_PEAK_HOUR * scale)),
        base_date, day, hour, "windows"  # use windows activity curve
    )

    session_counter = day * 100 + hour * 4 + random.randint(1, 10)

    # --- Cron jobs (deterministic — at specific minutes each hour) ---
    host_crons = CRON_JOBS.get(host, [])
    for cron_minute, cron_user, cron_cmd in host_crons:
        events.append(auth_cron(base_date, day, hour, cron_minute,
                                random.randint(0, 2), host, cron_user, cron_cmd))

    # --- SSH accepted (admin logins) ---
    ssh_count = max(0, int(event_count * 0.25))
    for _ in range(ssh_count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        # IT admins SSH into servers
        admin_user = random.choice(LINUX_ADMIN_USERS)
        # Source IP: internal management network
        source_ip = f"10.10.10.{random.randint(2, 50)}"

        events.append(auth_ssh_accepted(base_date, day, hour, minute, second,
                                        host, admin_user, source_ip, "publickey"))
        # Session open
        session_counter += 1
        events.append(auth_session_open(base_date, day, hour, minute,
                                        min(59, second + 1), host, admin_user,
                                        session_counter))

        # Session close (some time later)
        if random.random() < 0.6:
            close_minute = min(59, minute + random.randint(5, 30))
            events.append(auth_session_close(base_date, day, hour, close_minute,
                                             random.randint(0, 59), host,
                                             admin_user, session_counter))

    # --- SSH failed (internet scanner noise) ---
    # Only on hosts with external exposure (web servers, bastion)
    if host in ("WEB-01", "WEB-02", "BASTION-BOS-01"):
        # Low but consistent: 1-4 per hour, heavier at night
        if hour < 6 or hour > 22:
            fail_count = random.randint(2, 6)
        else:
            fail_count = random.randint(0, 3)

        for _ in range(fail_count):
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            scanner_ip = random.choice(SSH_SCANNER_IPS)
            scanner_user = random.choice(SSH_SCANNER_USERS)
            events.append(auth_ssh_failed(base_date, day, hour, minute, second,
                                          host, scanner_user, scanner_ip))

    # --- sudo commands ---
    sudo_count = max(0, int(event_count * 0.2))
    if is_wknd:
        sudo_count = max(0, sudo_count // 3)
    for _ in range(sudo_count):
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        admin_user = random.choice(LINUX_ADMIN_USERS[:2])  # root, svc.deploy
        cmd = random.choice(SUDO_COMMANDS)
        events.append(auth_sudo(base_date, day, hour, minute, second,
                                host, admin_user, cmd))

    # --- systemd service events ---
    host_services = SYSTEMD_SERVICES.get(host, [])
    if host_services:
        # Service restarts/reloads: rare
        if random.random() < 0.08:
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            service = random.choice(host_services)
            action = random.choice(["reloaded", "started"])
            events.append(auth_systemd(base_date, day, hour, minute, second,
                                       host, service, action))

    # Sort by timestamp (minute:second extracted from the auth.log timestamp)
    events.sort(key=lambda e: e.split(host)[0] if host in e else "")
    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_linux_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    quiet: bool = False,
) -> int:
    """Generate Linux system metrics."""

    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = get_output_path("linux", "").parent / "linux"

    out_dir.mkdir(parents=True, exist_ok=True)

    # Parse scenarios
    active_scenarios = expand_scenarios(scenarios)
    include_exfil = "exfil" in active_scenarios
    include_memory_leak = "memory_leak" in active_scenarios
    include_disk_filling = "disk_filling" in active_scenarios
    include_ddos_attack = "ddos_attack" in active_scenarios

    # Initialize scenarios if needed
    exfil_scenario = None
    memleak_scenario = None
    diskfill_scenario = None
    ddos_scenario = None

    if include_exfil:
        config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
        company = Company()
        time_utils = TimeUtils(start_date)
        exfil_scenario = ExfilScenario(config, company, time_utils)

    if include_memory_leak:
        memleak_scenario = MemoryLeakScenario(demo_id_enabled=True)

    if include_disk_filling:
        diskfill_scenario = DiskFillingScenario(demo_id_enabled=True)

    if include_ddos_attack:
        ddos_scenario = DdosAttackScenario(demo_id_enabled=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Linux Metrics Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days} | Hosts: {len(LINUX_SERVERS)}", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Output: {out_dir}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Initialize metric collections
    all_metrics = {
        "cpu": [],
        "vmstat": [],
        "df": [],
        "iostat": [],
        "interfaces": [],
    }

    # Auth.log events (separate collection)
    auth_events = []

    for day in range(days):
        dt = date_add(start_date, day)
        is_wknd = is_weekend(dt)

        if not quiet:
            print(f"  [Linux] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for hour in range(24):
            hour_mult = get_hour_multiplier(hour, is_wknd)

            # Generate at 5-minute intervals
            for interval in range(INTERVALS_PER_HOUR):
                minute = interval * 5

                for host in LINUX_SERVERS:
                    server = SERVERS[host]
                    metrics = generate_host_interval(start_date, day, hour, minute,
                                                     host, server, hour_mult,
                                                     exfil_scenario, memleak_scenario,
                                                     diskfill_scenario, ddos_scenario)

                    for metric_type, lines in metrics.items():
                        all_metrics[metric_type].extend(lines)

            # Auth.log events (once per hour, not per interval)
            for host in LINUX_SERVERS:
                auth_hour_events = generate_auth_hour(
                    start_date, day, hour, host, scale
                )
                auth_events.extend(auth_hour_events)

        if not quiet:
            print(f"  [Linux] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Write output files
    total_events = 0
    file_counts = {}
    for metric_type, lines in all_metrics.items():
        output_path = out_dir / f"{metric_type}.log"
        with open(output_path, "w") as f:
            for line in lines:
                f.write(line + "\n")
        rel_path = f"linux/{metric_type}.log"
        file_counts[rel_path] = len(lines)
        total_events += len(lines)

    # Write auth.log
    auth_path = out_dir / "auth.log"
    with open(auth_path, "w") as f:
        for line in auth_events:
            f.write(line + "\n")
    auth_count = len(auth_events)
    file_counts["linux/auth.log"] = auth_count
    total_events += auth_count

    if not quiet:
        print(f"  [Linux] Complete! {total_events:,} events ({total_events - auth_count:,} metrics + {auth_count:,} auth.log)", file=sys.stderr)

    return {"total": total_events, "files": file_counts}


def main():
    parser = argparse.ArgumentParser(description="Generate Linux system metrics")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--scenarios", default="none", help="Scenarios: none, exfil, memory_leak, all")
    parser.add_argument("--output-dir")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_linux_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        scenarios=args.scenarios, output_dir=args.output_dir, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
