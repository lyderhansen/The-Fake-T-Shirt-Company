#!/usr/bin/env python3
"""
Linux System Metrics Generator.
Generates CPU, memory, disk, and network metrics with natural variation.

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
from shared.time_utils import TimeUtils, ts_linux, date_add, get_hour_activity_level, is_weekend
from shared.company import Company, LINUX_SERVERS, SERVERS
from scenarios.security import ExfilScenario
from scenarios.ops import MemoryLeakScenario
from scenarios.ops.disk_filling import DiskFillingScenario
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
                           diskfill_scenario: Optional[DiskFillingScenario] = None) -> Dict[str, List[str]]:
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

    # Initialize scenarios if needed
    exfil_scenario = None
    memleak_scenario = None
    diskfill_scenario = None

    if include_exfil:
        config = Config(start_date=start_date, days=days, scale=scale, demo_id_enabled=True)
        company = Company()
        time_utils = TimeUtils(start_date)
        exfil_scenario = ExfilScenario(config, company, time_utils)

    if include_memory_leak:
        memleak_scenario = MemoryLeakScenario(demo_id_enabled=True)

    if include_disk_filling:
        diskfill_scenario = DiskFillingScenario(demo_id_enabled=True)

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
                                                     diskfill_scenario)

                    for metric_type, lines in metrics.items():
                        all_metrics[metric_type].extend(lines)

        if not quiet:
            print(f"  [Linux] Day {day + 1}/{days} ({dt.strftime('%Y-%m-%d')})... done", file=sys.stderr)

    # Write output files
    total_events = 0
    for metric_type, lines in all_metrics.items():
        output_path = out_dir / f"{metric_type}.log"
        with open(output_path, "w") as f:
            for line in lines:
                f.write(line + "\n")
        total_events += len(lines)

    if not quiet:
        print(f"  [Linux] Complete! {total_events:,} metric samples written", file=sys.stderr)

    return total_events


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
