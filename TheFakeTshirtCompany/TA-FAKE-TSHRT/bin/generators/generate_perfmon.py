#!/usr/bin/env python3
"""
Windows Performance Monitor Generator.
Generates CPU, memory, disk, and network metrics for Windows servers and clients.

Includes:
  - Processor (% Processor Time, % User Time, % Privileged Time, % Idle Time)
  - Memory (Available MBytes, % Committed Bytes In Use, Cache Bytes, Pages/sec)
  - LogicalDisk (% Free Space, Free Megabytes, % Disk Time, Current Disk Queue Length)
  - Network Interface (Bytes Received/sec, Bytes Sent/sec)
  - SQL Server counters on SQL-PROD-01 (Batch Requests/sec, Page Life Expectancy,
    Buffer Cache Hit Ratio, Lock Waits/sec)

Options:
  --clients N          Number of client workstations (default: 5, min: 5, max: 175)
  --client-interval N  Interval in minutes for non-scenario clients (default: 30, min: 5, max: 60)
  --full-metrics       Include Disk/Network metrics for clients (default: CPU/Memory only)
                       WARNING: Significantly increases output volume!

Scenario-relevant clients (alex.miller, jessica.brown, etc.) always use 5-minute intervals.
"""

import argparse
import random
import sys
from pathlib import Path
from typing import List, Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import ts_perfmon, date_add, get_hour_activity_level, is_weekend
from shared.company import WINDOWS_SERVERS, SERVERS, USERS, USER_KEYS, COMP_USER
from scenarios.registry import expand_scenarios
from scenarios.ops.cpu_runaway import CpuRunawayScenario
from scenarios.network.ddos_attack import DdosAttackScenario

# =============================================================================
# PERFMON CONFIGURATION
# =============================================================================

PERFMON_INTERVAL = 300  # 5 minutes
INTERVALS_PER_HOUR = 12

# Client configuration
DEFAULT_NUM_CLIENTS = 5
MIN_CLIENTS = 5
MAX_CLIENTS = 175  # All employees for full correlation
CLIENT_RAM_MB = 16384  # 16GB for clients

# Client interval configuration
DEFAULT_CLIENT_INTERVAL = 30  # 30 minutes for non-scenario clients
MIN_CLIENT_INTERVAL = 5
MAX_CLIENT_INTERVAL = 60
SCENARIO_CLIENT_INTERVAL = 5  # 5 minutes for scenario-relevant clients

# Scenario-relevant users (always use 5-minute intervals)
SCENARIO_USERS = {
    "alex.miller",      # exfil target (Finance)
    "jessica.brown",    # initial compromise (IT Admin)
    "john.smith",       # CEO - executive target
    "sarah.wilson",     # CFO - finance leadership
    "mike.johnson",     # CTO - IT leadership
}


# =============================================================================
# METRIC GENERATORS
# =============================================================================

def get_hour_multiplier(hour: int, is_wknd: bool) -> float:
    """Get activity multiplier for hour."""
    activity = get_hour_activity_level(hour, is_wknd)
    return activity / 100.0


def format_perfmon_event(ts: str, host: str, collection: str, obj: str,
                         counter: str, instance: str, value: float,
                         demo_id: str = None) -> str:
    """Format a single perfmon event in multiline key=value format."""
    event = f"""{ts}
collection="{collection}"
object={obj}
counter="{counter}"
instance={instance}
Value={value:.2f}
demo_host={host}"""
    if demo_id:
        event += f"\ndemo_id={demo_id}"
    return event


def processor_metric(ts: str, host: str, cpu_min: int, cpu_max: int, hour_mult: float,
                     demo_id: str = None, scenario_override: bool = False) -> List[str]:
    """Generate processor performance counters."""
    events = []
    base_cpu = random.uniform(cpu_min, cpu_max)
    # Don't apply hour_mult reduction for scenario-driven values
    if scenario_override:
        cpu = base_cpu
    else:
        cpu = base_cpu * (0.6 + 0.4 * hour_mult)
    cpu = min(100, max(1, cpu))

    # Total processor
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Processor Time", "_Total", cpu, demo_id))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% User Time", "_Total", cpu * 0.7, demo_id))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Privileged Time", "_Total", cpu * 0.2, demo_id))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Idle Time", "_Total", 100 - cpu, demo_id))

    return events


def memory_metric(ts: str, host: str, ram_min: int, ram_max: int,
                  total_mb: int, hour_mult: float, demo_id: str = None,
                  scenario_override: bool = False) -> List[str]:
    """Generate memory performance counters."""
    events = []
    base_ram = random.uniform(ram_min, ram_max)
    # Don't apply hour_mult reduction for scenario-driven values
    if scenario_override:
        ram = base_ram
    else:
        ram = base_ram * (0.7 + 0.3 * hour_mult)
    ram = min(95, max(20, ram))

    used_mb = int(total_mb * ram / 100)
    avail_mb = total_mb - used_mb
    committed_mb = int(used_mb * 1.1)
    cache_mb = int(avail_mb * 0.4)

    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "Available MBytes", "_Total", avail_mb, demo_id))
    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "% Committed Bytes In Use", "_Total", ram, demo_id))
    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "Cache Bytes", "_Total", cache_mb * 1024 * 1024, demo_id))

    # Pages/sec: indicates paging (memory pressure). Normal: 0-50. High: >100.
    pages_per_sec = random.uniform(0, 20) * (0.5 + 0.5 * hour_mult)
    if scenario_override and ram > 85:
        pages_per_sec = random.uniform(100, 500)  # Heavy paging during memory pressure
    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "Pages/sec", "_Total", pages_per_sec, demo_id))

    return events


def disk_metric(ts: str, host: str, total_gb: int, hour_mult: float,
                demo_id: str = None, disk_busy: bool = False, io_mult: int = 100) -> List[str]:
    """Generate logical disk performance counters."""
    events = []
    used_pct = random.uniform(40, 70)
    free_mb = int((total_gb * 1024) * (1 - used_pct / 100))

    read_bytes = int(random.uniform(100000, 5000000) * hour_mult * io_mult / 100)
    write_bytes = int(random.uniform(50000, 2000000) * hour_mult * io_mult / 100)
    disk_time = random.uniform(5, 40) * hour_mult
    if disk_busy:
        disk_time = min(95, disk_time * 3)  # High disk time during scenario

    # Current Disk Queue Length: 0-2 normal, >5 = bottleneck
    disk_queue = random.uniform(0, 2) * hour_mult
    if disk_busy:
        disk_queue = random.uniform(5, 20)  # Heavy queuing during scenario

    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "% Free Space", "C:", 100 - used_pct, demo_id))
    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "Free Megabytes", "C:", free_mb, demo_id))
    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "% Disk Time", "C:", disk_time, demo_id))
    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "Current Disk Queue Length", "C:", disk_queue, demo_id))

    return events


def network_metric(ts: str, host: str, hour_mult: float, demo_id: str = None) -> List[str]:
    """Generate network interface performance counters."""
    events = []
    rx_bytes = int(random.uniform(500000, 50000000) * hour_mult)
    tx_bytes = int(random.uniform(200000, 20000000) * hour_mult)
    bandwidth = 1000000000  # 1 Gbps

    events.append(format_perfmon_event(ts, host, "Network Interface", "Network Interface", "Bytes Received/sec", "Intel[R] Ethernet", rx_bytes, demo_id))
    events.append(format_perfmon_event(ts, host, "Network Interface", "Network Interface", "Bytes Sent/sec", "Intel[R] Ethernet", tx_bytes, demo_id))

    return events


def generate_host_interval(base_date: str, day: int, hour: int, minute: int,
                           host: str, server: object, hour_mult: float,
                           ram_mb: int, disk_gb: int,
                           cpu_runaway_scenario: CpuRunawayScenario = None,
                           ddos_scenario: Optional[DdosAttackScenario] = None) -> Dict[str, List[str]]:
    """Generate all metrics for one host at one interval."""
    ts = ts_perfmon(base_date, day, hour, minute, 0)

    # Get baseline values
    cpu_min = server.cpu_baseline_min
    cpu_max = server.cpu_baseline_max
    ram_min = server.ram_baseline_min
    ram_max = server.ram_baseline_max
    demo_id = None
    disk_busy = False
    io_mult = 100
    scenario_override = False

    # Apply cpu_runaway scenario adjustments for SQL-PROD-01
    if cpu_runaway_scenario and host == "SQL-PROD-01":
        cpu_min, cpu_max = cpu_runaway_scenario.adjusted_cpu(host, day, hour, minute, cpu_min, cpu_max)
        ram_min, ram_max = cpu_runaway_scenario.adjusted_memory(host, day, hour, minute, ram_min, ram_max)
        disk_busy_flag, io_mult = cpu_runaway_scenario.adjusted_disk(host, day, hour, minute)
        disk_busy = disk_busy_flag == 1
        demo_id = cpu_runaway_scenario.get_demo_id(day, hour) or None
        # When scenario is active, don't apply hour_mult reduction
        scenario_override = demo_id is not None

    # Apply DDoS attack downstream effects on APP-BOS-01
    # APP-BOS-01 (IIS/.NET) retries failed connections to overwhelmed WEB-01
    if ddos_scenario and host == "APP-BOS-01":
        ddos_cpu_adj = ddos_scenario.perfmon_cpu_adjustment(host, day, hour)
        if ddos_cpu_adj > 0:
            cpu_min = min(95, cpu_min + ddos_cpu_adj)
            cpu_max = min(100, cpu_max + ddos_cpu_adj)
            demo_id = demo_id or "ddos_attack"
            scenario_override = True

    proc_events = processor_metric(ts, host, cpu_min, cpu_max, hour_mult, demo_id, scenario_override)
    mem_events = memory_metric(ts, host, ram_min, ram_max, ram_mb, hour_mult, demo_id, scenario_override)
    disk_events = disk_metric(ts, host, disk_gb, hour_mult, demo_id, disk_busy, io_mult)
    net_events = network_metric(ts, host, hour_mult, demo_id)

    # SQL Server-specific counters (SQL-PROD-01 only)
    sql_events = sql_server_metrics(ts, host, hour_mult, demo_id, scenario_override)
    proc_events.extend(sql_events)  # Append SQL metrics to processor file

    metrics = {
        "processor": proc_events,
        "memory": mem_events,
        "disk": disk_events,
        "network": net_events,
    }

    return metrics


# =============================================================================
# SERVER CONFIGURATION
# =============================================================================

# RAM and disk sizes per server (overrides default 16GB / 256GB)
SERVER_RAM_MB = {
    "DC-BOS-01": 16384,
    "DC-BOS-02": 16384,
    "FILE-BOS-01": 32768,
    "SQL-PROD-01": 65536,
    "APP-BOS-01": 32768,
    "WSUS-BOS-01": 16384,
    "RADIUS-BOS-01": 8192,
    "PRINT-BOS-01": 8192,
    "DC-ATL-01": 16384,
    "BACKUP-ATL-01": 32768,
}

SERVER_DISK_GB = {
    "DC-BOS-01": 256,
    "DC-BOS-02": 256,
    "FILE-BOS-01": 2048,
    "SQL-PROD-01": 1024,
    "APP-BOS-01": 512,
    "WSUS-BOS-01": 1024,    # WSUS needs large disk for update packages
    "RADIUS-BOS-01": 128,
    "PRINT-BOS-01": 256,
    "DC-ATL-01": 256,
    "BACKUP-ATL-01": 4096,  # Backup server has large storage
}


# =============================================================================
# SQL SERVER COUNTERS (SQL-PROD-01 only)
# =============================================================================

def sql_server_metrics(ts: str, host: str, hour_mult: float,
                       demo_id: str = None, scenario_override: bool = False) -> List[str]:
    """Generate SQL Server-specific performance counters.

    Only applicable to SQL-PROD-01. Includes:
    - Batch Requests/sec: 50-500 (scales with activity)
    - Page Life Expectancy: 300-5000 (lower = memory pressure)
    - Buffer Cache Hit Ratio: 95-99.9% (healthy)
    - Lock Waits/sec: 0-5 (low in baseline)
    """
    events = []
    if host != "SQL-PROD-01":
        return events

    # Batch Requests/sec: scales with business activity
    base_batch = random.uniform(50, 200)
    if scenario_override:
        batch = base_batch * 3  # Higher during scenario
    else:
        batch = base_batch * (0.3 + 0.7 * hour_mult)
    events.append(format_perfmon_event(ts, host, "SQLServer:SQL Statistics",
                                        "SQLServer:SQL Statistics",
                                        "Batch Requests/sec", "_Total",
                                        batch, demo_id))

    # Page Life Expectancy: higher = healthier (300 is concerning)
    # Healthy baseline: 2000-5000. Lower during high activity.
    base_ple = random.uniform(2000, 5000)
    if scenario_override:
        ple = random.uniform(100, 500)  # Memory pressure during scenario
    else:
        ple = base_ple * (0.5 + 0.5 * (1.0 - hour_mult))  # Inverse: busier = lower PLE
    events.append(format_perfmon_event(ts, host, "SQLServer:Buffer Manager",
                                        "SQLServer:Buffer Manager",
                                        "Page life expectancy", "",
                                        max(100, ple), demo_id))

    # Buffer Cache Hit Ratio: 95-99.9% is healthy
    cache_hit = random.uniform(97.0, 99.9)
    if scenario_override:
        cache_hit = random.uniform(85.0, 95.0)  # Lower during scenario
    events.append(format_perfmon_event(ts, host, "SQLServer:Buffer Manager",
                                        "SQLServer:Buffer Manager",
                                        "Buffer cache hit ratio", "",
                                        cache_hit, demo_id))

    # Lock Waits/sec: 0-5 in baseline
    lock_waits = random.uniform(0, 3) * hour_mult
    if scenario_override:
        lock_waits = random.uniform(10, 50)  # High lock contention during scenario
    events.append(format_perfmon_event(ts, host, "SQLServer:Locks",
                                        "SQLServer:Locks",
                                        "Lock Waits/sec", "_Total",
                                        lock_waits, demo_id))

    return events


# =============================================================================
# CLIENT CONFIGURATION
# =============================================================================

def get_client_baselines(dept: str) -> tuple:
    """Get CPU/RAM baselines by department."""
    if dept in ("Engineering", "IT"):
        return (25, 55, 50, 75)  # cpu_min, cpu_max, ram_min, ram_max
    elif dept == "Finance":
        return (20, 45, 45, 65)
    else:
        return (15, 40, 40, 60)


def build_client_list(num_clients: int, client_interval: int = DEFAULT_CLIENT_INTERVAL) -> List[Dict]:
    """Build list of client workstations from USERS array.

    Args:
        num_clients: Number of client workstations to include
        client_interval: Interval in minutes for non-scenario clients (scenario clients always use 5 min)

    Returns:
        List of client dicts with hostname, username, baselines, and interval
    """
    clients = []
    seen_hostnames = set()

    # Validate inputs
    num_clients = max(MIN_CLIENTS, min(MAX_CLIENTS, num_clients))
    client_interval = max(MIN_CLIENT_INTERVAL, min(MAX_CLIENT_INTERVAL, client_interval))

    # Always add compromised user first (for attack scenario correlation)
    if COMP_USER in USERS:
        user = USERS[COMP_USER]
        hostname = user.device_name
        if hostname not in seen_hostnames:
            cpu_min, cpu_max, ram_min, ram_max = get_client_baselines(user.department)
            clients.append({
                "hostname": hostname,
                "username": COMP_USER,
                "cpu_min": cpu_min,
                "cpu_max": cpu_max,
                "ram_min": ram_min,
                "ram_max": ram_max,
                "interval": SCENARIO_CLIENT_INTERVAL,  # Always 5 min for scenario users
                "is_scenario_user": True,
            })
            seen_hostnames.add(hostname)

    # Add remaining users up to num_clients
    for username in USER_KEYS:
        if len(clients) >= num_clients:
            break
        if username == COMP_USER:
            continue

        user = USERS[username]
        hostname = user.device_name
        if hostname not in seen_hostnames:
            cpu_min, cpu_max, ram_min, ram_max = get_client_baselines(user.department)
            is_scenario = username in SCENARIO_USERS
            clients.append({
                "hostname": hostname,
                "username": username,
                "cpu_min": cpu_min,
                "cpu_max": cpu_max,
                "ram_min": ram_min,
                "ram_max": ram_max,
                "interval": SCENARIO_CLIENT_INTERVAL if is_scenario else client_interval,
                "is_scenario_user": is_scenario,
            })
            seen_hostnames.add(hostname)

    return clients


# =============================================================================
# CLIENT METRIC GENERATORS
# =============================================================================

def client_processor_metric(ts: str, host: str, cpu_min: int, cpu_max: int, hour_mult: float) -> List[str]:
    """Generate processor performance counters for client."""
    events = []
    base_cpu = random.uniform(cpu_min, cpu_max)
    cpu = base_cpu * (0.6 + 0.4 * hour_mult)
    cpu = min(95, max(5, cpu))

    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Processor Time", "_Total", cpu))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% User Time", "_Total", cpu * 0.75))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Privileged Time", "_Total", cpu * 0.15))
    events.append(format_perfmon_event(ts, host, "Processor", "Processor", "% Idle Time", "_Total", 100 - cpu))

    return events


def client_memory_metric(ts: str, host: str, ram_min: int, ram_max: int, hour_mult: float) -> List[str]:
    """Generate memory performance counters for client."""
    events = []
    base_ram = random.uniform(ram_min, ram_max)
    ram = base_ram * (0.7 + 0.3 * hour_mult)
    ram = min(95, max(30, ram))

    used_mb = int(CLIENT_RAM_MB * ram / 100)
    avail_mb = CLIENT_RAM_MB - used_mb
    cache_mb = int(avail_mb * 0.35)

    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "Available MBytes", "_Total", avail_mb))
    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "% Committed Bytes In Use", "_Total", ram))
    events.append(format_perfmon_event(ts, host, "Memory", "Memory", "Cache Bytes", "_Total", cache_mb * 1024 * 1024))

    return events


def client_disk_metric(ts: str, host: str, hour_mult: float) -> List[str]:
    """Generate logical disk performance counters for client."""
    events = []
    total_gb = 512  # Typical client SSD
    used_pct = random.uniform(40, 70)
    free_mb = int((total_gb * 1024) * (1 - used_pct / 100))
    disk_time = random.uniform(2, 25) * hour_mult

    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "% Free Space", "C:", 100 - used_pct))
    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "Free Megabytes", "C:", free_mb))
    events.append(format_perfmon_event(ts, host, "LogicalDisk", "LogicalDisk", "% Disk Time", "C:", disk_time))

    return events


def client_network_metric(ts: str, host: str, hour_mult: float) -> List[str]:
    """Generate network interface performance counters for client."""
    events = []
    rx_bytes = int(random.uniform(100000, 10000000) * hour_mult)
    tx_bytes = int(random.uniform(50000, 5000000) * hour_mult)

    events.append(format_perfmon_event(ts, host, "Network Interface", "Network Interface", "Bytes Received/sec", "Intel[R] Wi-Fi 6", rx_bytes))
    events.append(format_perfmon_event(ts, host, "Network Interface", "Network Interface", "Bytes Sent/sec", "Intel[R] Wi-Fi 6", tx_bytes))

    return events


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_perfmon_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_dir: str = None,
    num_clients: int = DEFAULT_NUM_CLIENTS,
    client_interval: int = DEFAULT_CLIENT_INTERVAL,
    full_metrics: bool = False,
    quiet: bool = False,
) -> int:
    """Generate Windows Performance Monitor logs.

    Args:
        num_clients: Number of client workstations (default: 5, min: 5, max: 175)
        client_interval: Interval in minutes for non-scenario clients (default: 30, min: 5, max: 60)
        full_metrics: Include Disk/Network metrics for clients (default: CPU/Memory only)
        scenarios: Scenario to apply (cpu_runaway affects BOS-SQL-PROD-01 on days 11-12)
    """

    if output_dir:
        out_dir = Path(output_dir)
    else:
        out_dir = get_output_path("windows", "").parent / "windows"

    out_dir.mkdir(parents=True, exist_ok=True)

    # Build client list with interval info
    clients = build_client_list(num_clients, client_interval)
    scenario_clients = [c for c in clients if c.get("is_scenario_user")]
    normal_clients = [c for c in clients if not c.get("is_scenario_user")]

    # Parse scenarios and initialize
    active_scenarios = expand_scenarios(scenarios)
    cpu_runaway_scenario = None
    ddos_scenario = None
    if "cpu_runaway" in active_scenarios:
        cpu_runaway_scenario = CpuRunawayScenario(demo_id_enabled=True)
    if "ddos_attack" in active_scenarios:
        ddos_scenario = DdosAttackScenario(demo_id_enabled=True)

    if not quiet:
        print("=" * 70, file=sys.stderr)
        print(f"  Windows Perfmon Generator (Python)", file=sys.stderr)
        print(f"  Start: {start_date} | Days: {days}", file=sys.stderr)
        print(f"  Servers: {len(WINDOWS_SERVERS)} | Clients: {len(clients)} ({len(scenario_clients)} scenario, {len(normal_clients)} normal)", file=sys.stderr)
        print(f"  Client interval: Scenario users=5min, Normal users={client_interval}min", file=sys.stderr)
        print(f"  Scenarios: {', '.join(active_scenarios) if active_scenarios else 'none'}", file=sys.stderr)
        print(f"  Full metrics: {'YES' if full_metrics else 'NO (clients: CPU/Memory only)'}", file=sys.stderr)
        print(f"  Output: {out_dir}/", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

    # Initialize metric collections
    all_metrics = {
        "processor": [],
        "memory": [],
        "disk": [],
        "network": [],
    }

    for day in range(days):
        dt = date_add(start_date, day)
        is_wknd = is_weekend(dt)

        if not quiet:
            print(f"  [Perfmon] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})...", file=sys.stderr, end="\r")

        for hour in range(24):
            hour_mult = get_hour_multiplier(hour, is_wknd)

            # Generate at 5-minute intervals
            for interval in range(INTERVALS_PER_HOUR):
                minute = interval * 5

                # ----- SERVERS -----
                for host in WINDOWS_SERVERS:
                    server = SERVERS[host]
                    ram_mb = SERVER_RAM_MB.get(host, 16384)
                    disk_gb = SERVER_DISK_GB.get(host, 256)

                    metrics = generate_host_interval(start_date, day, hour, minute,
                                                     host, server, hour_mult, ram_mb, disk_gb,
                                                     cpu_runaway_scenario, ddos_scenario)

                    for metric_type, lines in metrics.items():
                        all_metrics[metric_type].extend(lines)

                # ----- CLIENTS -----
                for client in clients:
                    # Check if this client should be sampled at this interval
                    # minute is 0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55
                    client_interval_mins = client.get("interval", DEFAULT_CLIENT_INTERVAL)

                    # Only sample if minute aligns with client's interval
                    # e.g., 30 min interval -> sample at minute 0 and 30
                    if minute % client_interval_mins != 0:
                        continue

                    ts = ts_perfmon(start_date, day, hour, minute, 0)
                    hostname = client["hostname"]

                    # CPU and Memory (always)
                    all_metrics["processor"].extend(
                        client_processor_metric(ts, hostname, client["cpu_min"], client["cpu_max"], hour_mult)
                    )
                    all_metrics["memory"].extend(
                        client_memory_metric(ts, hostname, client["ram_min"], client["ram_max"], hour_mult)
                    )

                    # Disk and Network (only with --full-metrics)
                    if full_metrics:
                        all_metrics["disk"].extend(client_disk_metric(ts, hostname, hour_mult))
                        all_metrics["network"].extend(client_network_metric(ts, hostname, hour_mult))

        if not quiet:
            print(f"  [Perfmon] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Write output files - events are multiline, separated by blank line
    total_events = 0
    for metric_type, lines in all_metrics.items():
        output_path = out_dir / f"perfmon_{metric_type}.log"
        with open(output_path, "w") as f:
            for line in lines:
                f.write(line + "\n")
        total_events += len(lines)

    if not quiet:
        print(f"  [Perfmon] Complete! {total_events:,} metric samples written", file=sys.stderr)

    return total_events


def main():
    parser = argparse.ArgumentParser(description="Generate Windows Perfmon logs")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE)
    parser.add_argument("--clients", type=int, default=DEFAULT_NUM_CLIENTS,
                        help=f"Number of client workstations (default: {DEFAULT_NUM_CLIENTS}, min: {MIN_CLIENTS}, max: {MAX_CLIENTS})")
    parser.add_argument("--client-interval", type=int, default=DEFAULT_CLIENT_INTERVAL,
                        help=f"Interval in minutes for non-scenario clients (default: {DEFAULT_CLIENT_INTERVAL}, min: {MIN_CLIENT_INTERVAL}, max: {MAX_CLIENT_INTERVAL})")
    parser.add_argument("--full-metrics", action="store_true",
                        help="Include Disk/Network metrics for clients (WARNING: increases volume!)")
    parser.add_argument("--output-dir")
    parser.add_argument("--quiet", "-q", action="store_true")

    args = parser.parse_args()
    count = generate_perfmon_logs(
        start_date=args.start_date, days=args.days, scale=args.scale,
        num_clients=args.clients, client_interval=args.client_interval,
        full_metrics=args.full_metrics,
        output_dir=args.output_dir, quiet=args.quiet,
    )
    print(count)


if __name__ == "__main__":
    main()
