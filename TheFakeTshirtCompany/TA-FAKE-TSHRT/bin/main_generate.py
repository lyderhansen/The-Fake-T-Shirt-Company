#!/usr/bin/env python3
"""
Main Log Generator - Orchestrates all log generators.
Generates coordinated logs across all sources with realistic volume patterns.

Usage:
    python3 main_generate.py --all                    # All sources
    python3 main_generate.py --sources=asa,entraid    # Specific sources
    python3 main_generate.py --days=7 --scale=0.5     # Custom settings
"""

import argparse
import os
import sys
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Callable

sys.path.insert(0, str(Path(__file__).parent))

# ANSI color codes for terminal output (disabled if not a TTY)
if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
    _C_RESET = "\033[0m"
    _C_DIM = "\033[2m"
    _C_CYAN = "\033[36m"
    _C_GREEN = "\033[32m"
    _C_YELLOW = "\033[33m"
else:
    _C_RESET = _C_DIM = _C_CYAN = _C_GREEN = _C_YELLOW = ""

# =============================================================================
# LIVE PROGRESS TRACKING
# =============================================================================

_progress_lock = threading.Lock()
_progress = {}          # {name: {"day": N, "days": N, "status": str, "start": float}}
_progress_stop = False  # Signal to stop the display thread
_progress_pause = threading.Event()  # Set when main thread is printing completion output


def _report_progress(name, day, days):
    """Called by generators to report current day progress (thread-safe)."""
    with _progress_lock:
        if name in _progress:
            _progress[name]["day"] = day


def _progress_display_thread(phase_total):
    """Background thread that refreshes a compact progress line every 0.5s."""
    global _progress_stop
    while not _progress_stop:
        # If main thread is printing completion output, skip this cycle
        if _progress_pause.is_set():
            time.sleep(0.1)
            continue

        with _progress_lock:
            running = [(n, p) for n, p in _progress.items() if p["status"] == "running"]
            done_count = sum(1 for p in _progress.values() if p["status"] == "done")

        if running:
            # Show only generators that have started their day loop (day > 0)
            active = [(n, p) for n, p in running if p["day"] > 0]
            queued = len(running) - len(active)
            parts = []
            for name, p in sorted(active):
                parts.append(f"{name} {p['day']}/{p['days']}")
            status = f"  {_C_DIM}[{done_count}/{phase_total}]{_C_RESET} "
            if parts:
                status += f" {_C_DIM}|{_C_RESET} ".join(parts)
            if queued > 0:
                status += f"  {_C_DIM}(+{queued} queued){_C_RESET}"
            print(f"\r{status: <120}", end="", flush=True)

        time.sleep(0.5)


from shared.config import (
    DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE,
    OUTPUT_BASE, OUTPUT_BASE_PRODUCTION, GENERATOR_OUTPUT_FILES,
    set_output_base,
)

# Import generators
from generators.generate_asa import generate_asa_logs
from generators.generate_aws import generate_aws_logs
from generators.generate_gcp import generate_gcp_logs
from generators.generate_entraid import generate_entraid_logs
from generators.generate_exchange import generate_exchange_logs
from generators.generate_access import generate_access_logs
from generators.generate_wineventlog import generate_wineventlog
from generators.generate_linux import generate_linux_logs
from generators.generate_perfmon import generate_perfmon_logs
from generators.generate_orders import generate_orders
from generators.generate_servicebus import generate_servicebus_logs
from generators.generate_meraki import generate_meraki_logs
from generators.generate_webex import generate_webex_logs
from generators.generate_webex_ta import generate_webex_ta_logs
from generators.generate_webex_api import generate_webex_api_logs
from generators.generate_mssql import generate_mssql_logs
from generators.generate_sysmon import generate_sysmon_logs
from generators.generate_servicenow import generate_servicenow_logs
from generators.generate_office_audit import generate_office_audit_logs
from generators.generate_sap import generate_sap_logs
from generators.generate_secure_access import generate_secure_access_logs
from generators.generate_catalyst import generate_catalyst_logs
from generators.generate_aci import generate_aci_logs
from generators.generate_catalyst_center import generate_catalyst_center_logs
from generators.generate_aws_guardduty import generate_aws_guardduty_logs
from generators.generate_aws_billing import generate_aws_billing_logs

# =============================================================================
# GENERATOR REGISTRY
# =============================================================================

GENERATORS: Dict[str, Callable] = {
    "asa": generate_asa_logs,
    "aws": generate_aws_logs,
    "gcp": generate_gcp_logs,
    "entraid": generate_entraid_logs,
    "exchange": generate_exchange_logs,
    "access": generate_access_logs,
    "wineventlog": generate_wineventlog,
    "linux": generate_linux_logs,
    "perfmon": generate_perfmon_logs,
    "orders": generate_orders,
    "servicebus": generate_servicebus_logs,
    "meraki": generate_meraki_logs,
    "webex": generate_webex_logs,
    "webex_ta": generate_webex_ta_logs,
    "webex_api": generate_webex_api_logs,
    "mssql": generate_mssql_logs,
    "sysmon": generate_sysmon_logs,
    "servicenow": generate_servicenow_logs,
    "office_audit": generate_office_audit_logs,
    "sap": generate_sap_logs,
    "secure_access": generate_secure_access_logs,
    "catalyst": generate_catalyst_logs,
    "aci": generate_aci_logs,
    "catalyst_center": generate_catalyst_center_logs,
    "aws_guardduty": generate_aws_guardduty_logs,
    "aws_billing": generate_aws_billing_logs,
}

# Width for aligning generator name column in output (longest name + 1)
_GEN_NAME_WIDTH = max(len(n) for n in GENERATORS) + 1

# Group sources for easy selection
SOURCE_GROUPS = {
    "all": list(GENERATORS.keys()),
    "cloud": ["aws", "aws_guardduty", "aws_billing", "gcp", "entraid", "secure_access"],
    "network": ["asa", "meraki", "catalyst", "aci"],
    "cisco": ["asa", "meraki", "secure_access", "catalyst", "aci", "catalyst_center"],
    "campus": ["catalyst", "catalyst_center"],
    "datacenter": ["aci"],
    "windows": ["wineventlog", "perfmon", "mssql", "sysmon"],
    "linux": ["linux"],
    "web": ["access"],
    "office": ["office_audit", "exchange"],
    "email": ["exchange"],
    "retail": ["orders", "servicebus"],
    "collaboration": ["webex", "webex_ta", "webex_api"],
    "itsm": ["servicenow"],
    "erp": ["sap"],
}

# Dependencies: These generators must run AFTER their dependencies
# orders and servicebus read from order_registry.json created by access
# meraki needs webex to populate shared meeting schedule for sensor/meeting correlation
# exchange needs webex to generate meeting invite/response emails from schedule
GENERATOR_DEPENDENCIES = {
    "orders": ["access"],
    "servicebus": ["access"],
    "asa": ["access"],        # ASA reads web_session_registry.json for 1:1 correlation
    "meraki": ["webex"],      # Meraki door sensors use Webex meeting schedule
    "exchange": ["webex"],    # Exchange calendar emails use Webex meeting schedule
    "webex_ta": ["webex"],    # Webex TA reads shared meeting schedule
    "webex_api": ["webex"],   # Webex API reads shared meeting schedule
    "sap": ["access"],        # SAP reads order_registry.json for sales order correlation
}

# =============================================================================
# PRE-RUN VOLUME AND TIME ESTIMATION
# =============================================================================
# Calibrated from 14-day run (scale=1.0, 5 clients, 30-min interval, no full-metrics,
# default orders ~224/day, scenarios=none). Values are per-day averages.
# Perfmon/sysmon counts are GENERATOR-REPORTED event counts (not file line counts).

_EVENTS_PER_DAY = {
    # Network
    "asa":              37_954,
    "meraki":           57_711,
    "catalyst":          1_003,
    "aci":               1_494,
    # Cloud/Security
    "aws":               1_627,
    "aws_guardduty":         6,
    "aws_billing":          17,
    "gcp":               1_215,
    "entraid":             800,
    "secure_access":    50_488,
    "catalyst_center":   1_476,
    "office_audit":      1_373,
    # Collaboration
    "exchange":          3_729,
    "webex":             1_829,
    "webex_ta":            372,
    "webex_api":           736,
    # Windows
    "perfmon":          37_776,    # 5 clients, 30-min interval, no full-metrics
    "wineventlog":         434,
    "sysmon":            2_304,
    "mssql":                96,
    # Linux
    "linux":             9_420,
    # Web/Retail
    "access":           20_155,    # ~224 orders/day default
    "orders":            1_643,    # depends on access
    "servicebus":        1_714,    # depends on access
    # ITSM / ERP
    "servicenow":          106,
    "sap":               2_319,    # depends on access
}

# Events/sec throughput per generator (single-thread, 14-day run on reference hardware).
# Used for time estimation. Conservative values to account for I/O contention.
_THROUGHPUT_EPS = {
    "asa":             100_000,
    "meraki":           90_000,
    "catalyst":         35_000,
    "aci":              35_000,
    "aws":              30_000,
    "aws_guardduty":     5_000,
    "aws_billing":       5_000,
    "gcp":              40_000,
    "entraid":          35_000,
    "secure_access":    60_000,
    "catalyst_center":  35_000,
    "office_audit":     45_000,
    "exchange":         45_000,
    "webex":           120_000,
    "webex_ta":         50_000,
    "webex_api":        10_000,
    "perfmon":         700_000,
    "wineventlog":      60_000,
    "sysmon":           40_000,
    "mssql":            60_000,
    "linux":           300_000,
    "access":           80_000,
    "orders":           75_000,
    "servicebus":       75_000,
    "servicenow":       70_000,
    "sap":              80_000,
}


def _estimate_run(sources, days, scale, orders_per_day, num_clients,
                  client_interval, full_metrics, health_interval,
                  mr_health, ms_health, parallel):
    """Estimate total events and execution time before running generators.

    Returns (total_events, estimated_seconds, per_gen_events).
    """
    per_gen = {}

    for gen in sources:
        base_per_day = _EVENTS_PER_DAY.get(gen, 1_000)
        est = base_per_day * days * scale

        # Generator-specific scaling
        if gen == "access" and orders_per_day:
            est = base_per_day * (orders_per_day / 224) * days * scale

        elif gen == "orders":
            if orders_per_day:
                est = base_per_day * (orders_per_day / 224) * days * scale
            # else use default base_per_day * days * scale

        elif gen == "servicebus":
            if orders_per_day:
                est = base_per_day * (orders_per_day / 224) * days * scale

        elif gen == "sap":
            if orders_per_day:
                # SAP has baseline + order-proportional events
                # At 224 orders/day: ~2319/day. Order lifecycle is ~3 events/order.
                baseline_per_day = 2_319 - (224 * 3)  # ~1647
                order_events = (orders_per_day * 3)
                est = (baseline_per_day + order_events) * days * scale

        elif gen == "asa":
            if orders_per_day:
                # ASA traffic partly driven by web traffic volume
                # ~38K/day at 224 orders. Web-driven portion is ~10%
                web_ratio = orders_per_day / 224
                est = base_per_day * (0.9 + 0.1 * web_ratio) * days * scale

        elif gen == "wineventlog":
            # WinEventLog: calibrated base is servers-only (434/day)
            # Each client workstation adds ~37 events/day (14-day average)
            client_events = max(0, num_clients) * 37
            est = (base_per_day + client_events) * days * scale

        elif gen == "sysmon":
            # Sysmon base: 2,304/day (servers + 20 sampled workstations)
            # With --clients>0: server-only base (~990/day) + ~18 events/client/day
            if num_clients > 0:
                server_base = 990
                client_events = num_clients * 18
                est = (server_base + client_events) * days * scale
            # else: use default base_per_day (2,304) which includes legacy 20 samples

        elif gen == "perfmon":
            # Perfmon: calibrated base includes servers + 5 default clients
            # Extra clients add ~340/day (no full-metrics) or ~610/day (full-metrics)
            # Scales linearly with 1/client_interval (default 30-min)
            interval_factor = 30 / max(client_interval or 30, 1)
            extra = max(0, num_clients - 5)
            if full_metrics:
                est = (base_per_day + 6_000 + extra * 610) * interval_factor * days * scale
            else:
                est = (base_per_day + extra * 340) * interval_factor * days * scale

        elif gen == "meraki":
            # Meraki = event-driven base (12,348/day) + health polling
            # Health at 15-min: MR=3,456/day, MS=42,240/day
            # Scales linearly with 15/interval (e.g., 5-min = 3x)
            hi = health_interval or 15
            health_factor = 15 / max(hi, 1)
            event_base = 12_348
            mr_health_day = int(3_456 * health_factor) if mr_health else 0
            ms_health_day = int(42_240 * health_factor) if ms_health else 0
            est = (event_base + mr_health_day + ms_health_day) * days * scale

        per_gen[gen] = int(est)

    total_events = sum(per_gen.values())

    # Time estimation: simulate parallel execution per phase
    phase1 = [g for g in sources if g not in GENERATOR_DEPENDENCIES]
    phase2 = [g for g in sources if g in GENERATOR_DEPENDENCIES]

    def _phase_time(phase_gens):
        if not phase_gens:
            return 0.0
        gen_times = []
        for g in phase_gens:
            events = per_gen.get(g, 0)
            throughput = _THROUGHPUT_EPS.get(g, 50_000)
            gen_times.append(events / max(throughput, 1))
        gen_times.sort(reverse=True)
        if len(gen_times) <= 1 or parallel <= 1:
            return sum(gen_times)
        # Longest generator + remaining distributed across (workers - 1)
        # Apply GIL/IO contention factor: parallel threads are ~2x slower than
        # single-thread due to Python GIL contention and disk I/O pressure
        contention = 1.8
        return gen_times[0] * contention + sum(gen_times[1:]) * contention / max(1, parallel - 1)

    est_seconds = _phase_time(phase1) + _phase_time(phase2)

    return total_events, est_seconds, per_gen


def parse_sources(sources_str: str) -> List[str]:
    """Parse source string into list of generator names."""
    if sources_str == "all":
        return SOURCE_GROUPS["all"]

    sources = []
    for item in sources_str.split(","):
        item = item.strip().lower()
        if item in SOURCE_GROUPS:
            sources.extend(SOURCE_GROUPS[item])
        elif item in GENERATORS:
            sources.append(item)
        else:
            print(f"Warning: Unknown source '{item}', skipping", file=sys.stderr)

    return list(set(sources))  # Remove duplicates


# Global column width for --show-files alignment (computed once from all known paths)
_FILE_COL_WIDTH = 0  # Set lazily on first call


def _get_file_col_width(output_label: str) -> int:
    """Compute global column width for aligned file count display."""
    global _FILE_COL_WIDTH
    if _FILE_COL_WIDTH == 0:
        max_len = 0
        for files in GENERATOR_OUTPUT_FILES.values():
            for f in files:
                path_len = len(f"{output_label}/{f}")
                if path_len > max_len:
                    max_len = path_len
        _FILE_COL_WIDTH = max_len + 3  # +3 for comfortable spacing before count
    return _FILE_COL_WIDTH


def _print_file_counts(result: Dict, output_base: Path, output_label: str):
    """Print per-file event counts for --show-files.

    Uses generator-reported file_counts (accurate event counts) when available,
    falls back to raw line counts for generators that return int.
    Counts are right-aligned to a fixed global column so they line up across all generators.
    """
    gen_name = result.get("name", "")
    file_counts = result.get("file_counts", {})
    files = GENERATOR_OUTPUT_FILES.get(gen_name, [gen_name])
    col_width = _get_file_col_width(output_label)

    prefix = f"       {_C_DIM}->{_C_RESET} {_C_DIM}{output_label}/"
    for f in files:
        file_path = output_base / f
        display_path = f"{output_label}/{f}"
        padding = " " * max(col_width - len(display_path), 1)
        if file_path.exists():
            if f in file_counts:
                count = file_counts[f]
            else:
                count = sum(1 for _ in open(file_path))
            print(f"{prefix}{f}{_C_RESET}{padding}{_C_CYAN}{count:>12,}{_C_RESET}")
        else:
            print(f"{prefix}{f}{_C_RESET}{padding}{_C_DIM}{'(not found)':>12}{_C_RESET}")


def run_generator(name: str, func: Callable, **kwargs) -> Dict:
    """Run a single generator and return results.

    Generators may return:
      - int: total event count (single-file generators)
      - dict: {"total": N, "files": {"rel/path": count, ...}} (multi-file generators)
    """
    start_time = time.time()
    try:
        result = func(**kwargs)
        duration = time.time() - start_time
        if isinstance(result, dict):
            count = result.get("total", 0)
            file_counts = result.get("files", {})
        else:
            count = result
            file_counts = {}
        return {
            "name": name,
            "success": True,
            "count": count,
            "file_counts": file_counts,
            "duration": duration,
        }
    except Exception as e:
        duration = time.time() - start_time
        return {
            "name": name,
            "success": False,
            "error": str(e),
            "duration": duration,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Generate coordinated Splunk demo logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main_generate.py --all                              # All sources (generates to tmp/, moves to output/)
  python3 main_generate.py --all --test                       # All sources (test mode, stays in output/tmp/)
  python3 main_generate.py --all --scenarios=all              # All sources, all scenarios
  python3 main_generate.py --sources=asa,entraid              # Specific sources
  python3 main_generate.py --sources=cloud                    # All cloud sources
  python3 main_generate.py --days=7 --scale=0.5               # 7 days, half volume
  python3 main_generate.py --scenarios=ransomware_attempt     # Single attack scenario
  python3 main_generate.py --scenarios=attack                 # All attack scenarios
  python3 main_generate.py --sources=perfmon --clients=20 --full-metrics
  python3 main_generate.py --all --show-files                 # Show output file paths in progress

Output Modes:
  (default)         Generate to output/tmp/, then move to output/ for Splunk ingestion
  --test            Generate to output/tmp/ only — safe for testing, no move to output/

Source Groups:
  all           - All sources (24 generators)
  cloud         - aws, aws_guardduty, aws_billing, gcp, entraid, secure_access
  network       - asa, meraki, catalyst, aci
  cisco         - asa, meraki, secure_access, catalyst, aci, catalyst_center
  campus        - catalyst, catalyst_center
  datacenter    - aci
  windows       - wineventlog, perfmon, mssql, sysmon
  linux         - linux
  web           - access
  office        - office_audit, exchange
  email         - exchange
  retail        - orders, servicebus
  collaboration - webex, webex_ta, webex_api
  itsm          - servicenow
  erp           - sap

Individual Sources:
  asa, aws, aws_guardduty, aws_billing, gcp, entraid, exchange, office_audit,
  access, wineventlog, linux, perfmon, mssql, sysmon, orders, servicebus, meraki,
  webex, webex_ta, webex_api, servicenow, sap, secure_access, catalyst, aci,
  catalyst_center

Scenarios:
  all              - All implemented scenarios (default)
  none             - No scenarios (baseline only)
  attack           - All attack scenarios (exfil, ransomware_attempt, phishing_test)
  ops              - All operational scenarios (memory_leak, cpu_runaway, disk_filling)
  network          - All network scenarios (firewall_misconfig, certificate_expiry)

  Note: Scenarios that start beyond --days are automatically skipped.
  E.g., --days=14 skips scenarios starting on Day 15+.

  Attack scenarios (--scenarios=attack or individual names):
    exfil              - APT-style data exfiltration (Day 1-14, multi-site)
                         Sources: asa, meraki, entraid, aws, gcp, exchange, wineventlog, perfmon, servicenow, mssql
    ransomware_attempt - Ransomware stopped by EDR (Day 8-9)
                         Sources: asa, exchange, wineventlog, meraki, servicenow, office_audit
    phishing_test      - IT phishing awareness campaign (Day 21-23)
                         Sources: exchange, entraid, wineventlog, office_audit, servicenow

  Ops scenarios (--scenarios=ops or individual names):
    memory_leak        - Application memory leak causing OOM (Day 7-10, Linux WEB-01)
                         Sources: perfmon, linux, asa, access, servicenow
    cpu_runaway        - SQL backup job stuck causing DB failures (Day 11-12)
                         Sources: perfmon, wineventlog, asa, access, servicenow, mssql
    disk_filling       - Server disk gradually filling up (Day 1-5, MON-ATL-01)
                         Sources: linux, access, servicenow
    dead_letter_pricing - ServiceBus dead-letter causes wrong prices (Day 16)
                         Sources: servicebus, orders, access, servicenow

  Network scenarios (--scenarios=network or individual names):
    firewall_misconfig - Firewall rule misconfiguration causing outage (Day 6)
                         Sources: asa, servicenow
    certificate_expiry - SSL certificate expires causing 7-hour outage (Day 13, 00:00-07:00)
                         Sources: asa, access, servicenow
    ddos_attack        - Volumetric HTTP flood targeting web servers (Day 18-19)
                         Sources: asa, meraki, access, linux, perfmon, servicenow

Perfmon Options:
  --clients N          Number of client workstations (default: 5, min: 5, max: 175)
  --client-interval N  Minutes between metrics for non-scenario clients (default: 30, min: 5, max: 60)
                       Scenario-relevant users always use 5 min intervals
  --full-metrics       Include Disk/Network metrics for clients (more volume)

Access/Orders Options:
  --orders-per-day N  Target orders per day (default: ~224, use 3000 for high-volume)

Output Directories:
  output/network/   - cisco_asa.log, meraki_mx_firewall.log, meraki_mr_ap.log,
                      meraki_ms_switch.log, meraki_mv_cam.log, meraki_mt_sensor.log
  output/cloud/     - aws, gcp, entraid, exchange, webex JSON files
  output/windows/   - perfmon_*.log, wineventlog_*.log, mssql_errorlog.log, sysmon_operational.log
  output/linux/     - vmstat, df, iostat, interfaces logs
  output/web/       - access_combined.log
  output/retail/    - orders.json
  output/servicebus/- servicebus messages
  output/itsm/      - servicenow_incidents.log, servicenow_cmdb.log, servicenow_change.log
        """,
    )

    parser.add_argument("--all", action="store_true", help="Generate all log sources")
    parser.add_argument("--tui", action="store_true", help="Launch interactive TUI interface")
    parser.add_argument("--test", action="store_true", default=False,
                        help="Test mode: generate to output/tmp/ only (no move to output/)")
    parser.add_argument("--sources", default="all", help="Comma-separated sources or groups")
    parser.add_argument("--start-date", default=DEFAULT_START_DATE, help="Start date (YYYY-MM-DD)")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS, help="Number of days")
    parser.add_argument("--scale", type=float, default=DEFAULT_SCALE, help="Volume scale factor")
    parser.add_argument("--scenarios", default="all",
                        help="Scenarios: none, all, attack, ops, network, or individual names (exfil, ransomware_attempt, memory_leak, cpu_runaway, disk_filling, dead_letter_pricing, firewall_misconfig, certificate_expiry, ddos_attack)")
    parser.add_argument("--parallel", type=int, default=4, help="Number of parallel generators")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress progress output")
    parser.add_argument("--show-files", action="store_true",
                        help="Show output file paths instead of generator names in progress")

    # Perfmon-specific options
    parser.add_argument("--clients", type=int, default=5,
                        help="Number of client workstations for perfmon (default: 5, min: 5, max: 175)")
    parser.add_argument("--client-interval", type=int, default=30,
                        help="Minutes between metrics for non-scenario clients (default: 30, min: 5, max: 60)")
    parser.add_argument("--full-metrics", action="store_true",
                        help="Include Disk/Network metrics for perfmon clients (increases volume)")

    # Access/Orders options
    parser.add_argument("--orders-per-day", type=int, default=None,
                        help="Target orders per day for access logs (default: ~224)")

    # Meraki health options
    parser.add_argument("--meraki-health-interval", type=int, default=15,
                        choices=[5, 10, 15, 30],
                        help="Minutes between Meraki health metric samples (default: 15, ~46K events/day)")
    parser.add_argument("--no-meraki-health", action="store_true",
                        help="Disable all Meraki health metrics generation")
    parser.add_argument("--no-mr-health", action="store_true",
                        help="Disable MR wireless AP health metrics (~3.5K events/day)")
    parser.add_argument("--no-ms-health", action="store_true",
                        help="Disable MS switch port health metrics (~42K events/day)")

    args = parser.parse_args()

    # Smart scenario filtering: skip scenarios that start beyond --days
    from scenarios.registry import expand_scenarios, filter_scenarios_by_days
    requested_scenarios = expand_scenarios(args.scenarios)
    active_scenarios = filter_scenarios_by_days(requested_scenarios, args.days)

    skipped_scenarios = set(requested_scenarios) - set(active_scenarios)
    if skipped_scenarios and not args.quiet:
        print(f"  Note: Skipping {len(skipped_scenarios)} scenario(s) beyond --days={args.days}: "
              f"{', '.join(sorted(skipped_scenarios))}")

    # Update args.scenarios with the filtered list for downstream generators
    if active_scenarios:
        args.scenarios = ",".join(active_scenarios)
    else:
        args.scenarios = "none"

    # Always generate to output/tmp/ first (safe staging area)
    # Files are moved to output/ after successful generation (unless --test)
    set_output_base(OUTPUT_BASE_PRODUCTION / "tmp")

    # Re-import OUTPUT_BASE after potential override
    from shared.config import OUTPUT_BASE as current_output_base

    # Label for show-files output (reflects test/prod mode)
    output_label = "output/tmp" if args.test else "output"

    # Launch TUI if requested
    if args.tui:
        from tui_generate import main as tui_main
        tui_main()
        sys.exit(0)

    # Determine sources to generate
    if args.all:
        sources = SOURCE_GROUPS["all"]
    else:
        sources = parse_sources(args.sources)

    if not sources:
        print("Error: No valid sources specified", file=sys.stderr)
        sys.exit(1)

    # Separate sources into two phases based on dependencies
    # Phase 1: sources with no dependencies OR are dependencies for others
    # Phase 2: sources that depend on phase 1
    phase1_sources = []
    phase2_sources = []

    for source in sources:
        if source in GENERATOR_DEPENDENCIES:
            # This source has dependencies
            deps = GENERATOR_DEPENDENCIES[source]
            # Check if all dependencies are in sources list
            missing_deps = [d for d in deps if d not in sources]
            if missing_deps:
                print(f"Warning: {source} requires {missing_deps} - adding to source list", file=sys.stderr)
                for d in missing_deps:
                    if d not in phase1_sources:
                        phase1_sources.append(d)
            phase2_sources.append(source)
        else:
            phase1_sources.append(source)

    # Deduplicate while preserving order
    phase1_sources = list(dict.fromkeys(phase1_sources))
    phase2_sources = list(dict.fromkeys(phase2_sources))

    # Print banner
    if not args.quiet:
        mode_label = "TEST (output/tmp/ only)" if args.test else "PRODUCTION (tmp/ → output/)"
        print("=" * 70)
        print("  Splunk Log Generator (Python)")
        print("=" * 70)
        print(f"  Mode:        {mode_label}")
        print(f"  Start Date:  {args.start_date}")
        print(f"  Days:        {args.days}")
        print(f"  Scale:       {args.scale}")
        print(f"  Scenarios:   {args.scenarios}")
        if phase2_sources:
            print(f"  Phase 1:     {', '.join(phase1_sources)}")
            print(f"  Phase 2:     {', '.join(phase2_sources)} (depends on phase 1)")
        else:
            print(f"  Sources:     {', '.join(phase1_sources)}")
        print(f"  Output:      {current_output_base}/")

        # Pre-run estimation
        all_sources = phase1_sources + phase2_sources
        mr_health = not args.no_meraki_health and not args.no_mr_health
        ms_health = not args.no_meraki_health and not args.no_ms_health
        est_events, est_seconds, _ = _estimate_run(
            sources=all_sources,
            days=args.days,
            scale=args.scale,
            orders_per_day=args.orders_per_day,
            num_clients=args.clients,
            client_interval=args.client_interval,
            full_metrics=args.full_metrics,
            health_interval=args.meraki_health_interval,
            mr_health=mr_health,
            ms_health=ms_health,
            parallel=args.parallel,
        )

        # Format event count
        if est_events >= 1_000_000:
            evt_str = f"~{est_events / 1_000_000:.1f}M events"
        elif est_events >= 10_000:
            evt_str = f"~{est_events / 1_000:.0f}K events"
        else:
            evt_str = f"~{est_events:,} events"

        # Format time
        if est_seconds < 60:
            time_str = f"~{est_seconds:.0f}s"
        elif est_seconds < 3600:
            time_str = f"~{est_seconds / 60:.1f} min"
        else:
            time_str = f"~{est_seconds / 3600:.1f} hr"

        est_line = f"  Estimated:   {evt_str}, {time_str}"

        # Show notes for non-default settings that significantly affect volume
        notes = []
        if args.orders_per_day and args.orders_per_day != 224:
            ratio = args.orders_per_day / 224
            notes.append(f"orders={args.orders_per_day} ({ratio:.1f}x)")
        if args.clients > 5:
            notes.append(f"clients={args.clients}")
        if args.full_metrics:
            notes.append("full-metrics")
        if args.meraki_health_interval != 15:
            notes.append(f"health-interval={args.meraki_health_interval}m")
        if args.scale != 1.0:
            notes.append(f"scale={args.scale}")

        if notes:
            est_line += f"  ({', '.join(notes)})"

        print(est_line)
        print("=" * 70)
        print(flush=True)

    # Prepare generator kwargs
    base_kwargs = {
        "start_date": args.start_date,
        "days": args.days,
        "scale": args.scale,
        "scenarios": args.scenarios,
        "quiet": True,  # Always quiet for parallel execution
        "progress_callback": _report_progress if not args.quiet else None,
    }

    # Perfmon-specific kwargs
    perfmon_kwargs = {
        **base_kwargs,
        "num_clients": args.clients,
        "client_interval": args.client_interval,
        "full_metrics": args.full_metrics,
    }

    # Access-specific kwargs
    access_kwargs = {
        **base_kwargs,
        "orders_per_day": args.orders_per_day,
    }

    # WinEventLog-specific kwargs
    wineventlog_kwargs = {
        **base_kwargs,
        "num_clients": args.clients,
    }

    # Sysmon-specific kwargs
    sysmon_kwargs = {
        **base_kwargs,
        "num_clients": args.clients,
    }

    # Meraki-specific kwargs
    mr_health = not args.no_meraki_health and not args.no_mr_health
    ms_health = not args.no_meraki_health and not args.no_ms_health
    meraki_kwargs = {
        **base_kwargs,
        "health_interval": args.meraki_health_interval,
        "mr_health_enabled": mr_health,
        "ms_health_enabled": ms_health,
    }

    # Run generators in two phases
    start_time = time.time()
    results = []

    def get_kwargs_for_generator(name: str) -> dict:
        """Get the appropriate kwargs for a generator."""
        if name == "perfmon":
            return perfmon_kwargs
        if name == "wineventlog":
            return wineventlog_kwargs
        if name == "sysmon":
            return sysmon_kwargs
        if name == "access":
            return access_kwargs
        if name == "meraki":
            return meraki_kwargs
        return base_kwargs

    def run_phase(phase_sources: List[str], phase_name: str = None):
        """Run a phase of generators."""
        global _progress_stop
        phase_results = []

        if phase_name and not args.quiet:
            print(f"\n  === {phase_name} ===")

        if args.parallel > 1 and len(phase_sources) > 1:
            # Register generators in progress tracker and start display thread
            display_thread = None
            if not args.quiet:
                with _progress_lock:
                    _progress.clear()
                    for name in phase_sources:
                        _progress[name] = {
                            "day": 0, "days": args.days,
                            "status": "running", "start": time.time(),
                        }
                _progress_stop = False
                _progress_pause.clear()
                display_thread = threading.Thread(
                    target=_progress_display_thread, args=(len(phase_sources),), daemon=True)
                display_thread.start()

            # Parallel execution
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                futures = {}
                for name in phase_sources:
                    func = GENERATORS[name]
                    kwargs = get_kwargs_for_generator(name)
                    future = executor.submit(run_generator, name, func, **kwargs)
                    futures[future] = name

                for future in as_completed(futures):
                    result = future.result()
                    phase_results.append(result)

                    # Mark as done in progress tracker
                    with _progress_lock:
                        if result["name"] in _progress:
                            _progress[result["name"]]["status"] = "done"

                    if not args.quiet:
                        # Pause display thread to prevent interleaving with file paths
                        _progress_pause.set()
                        time.sleep(0.05)  # Let display thread see the flag
                        # Clear the progress line before printing completion
                        print(f"\r{' ' * 120}\r", end="", flush=True)
                        count = result.get("count", 0)
                        dur = result["duration"]
                        if result["success"]:
                            print(f"  [{_C_GREEN}✓{_C_RESET}] {result['name']:{_GEN_NAME_WIDTH}} {_C_YELLOW}{count:>10,}{_C_RESET} events  {_C_DIM}({dur:.1f}s){_C_RESET}")
                        else:
                            print(f"  [✗] {result['name']:{_GEN_NAME_WIDTH}} {count:>10,} events  ({dur:.1f}s)")
                        if args.show_files:
                            _print_file_counts(result, current_output_base, output_label)
                        # Resume display thread
                        _progress_pause.clear()

            # Stop display thread
            if display_thread:
                _progress_stop = True
                display_thread.join(timeout=2)
                print(f"\r{' ' * 120}\r", end="", flush=True)

        else:
            # Sequential execution
            for name in phase_sources:
                func = GENERATORS[name]
                kwargs = get_kwargs_for_generator(name)
                if not args.quiet:
                    print(f"  Running {name}...", end="", flush=True)
                result = run_generator(name, func, **kwargs)
                phase_results.append(result)
                if not args.quiet:
                    count = result.get("count", 0)
                    if result["success"]:
                        print(f" [{_C_GREEN}✓{_C_RESET}] {_C_YELLOW}{count:,}{_C_RESET} events {_C_DIM}({result['duration']:.1f}s){_C_RESET}")
                    else:
                        print(f" [✗] {count:,} events ({result['duration']:.1f}s)")
                    if args.show_files:
                        _print_file_counts(result, current_output_base, output_label)

        return phase_results

    # Phase 1: Run independent generators (including access which creates order_registry.json)
    if phase1_sources:
        phase_name = "Phase 1: Independent generators" if phase2_sources else None
        results.extend(run_phase(phase1_sources, phase_name))

    # Phase 2: Run dependent generators (orders, servicebus - need order_registry.json)
    if phase2_sources:
        results.extend(run_phase(phase2_sources, "Phase 2: Dependent generators (using order_registry.json)"))

    # Summary
    total_time = time.time() - start_time
    total_events = sum(r.get("count", 0) for r in results if r["success"])
    successful = sum(1 for r in results if r["success"])
    failed = sum(1 for r in results if not r["success"])

    # Move files to production (output/) if not in test mode and all generators succeeded
    move_result = None
    if not args.test and failed == 0:
        if not args.quiet:
            print()
            print("  Moving files to output/ for Splunk ingestion...")
        from shared.config import move_output_to_production
        move_result = move_output_to_production(quiet=args.quiet)
        if not args.quiet:
            print(f"  Moved {len(move_result['moved'])} files to output/")
            if move_result['skipped']:
                print(f"  Skipped {len(move_result['skipped'])} files (not generated)")
            if move_result['errors']:
                for err in move_result['errors']:
                    print(f"  ERROR: {err}", file=sys.stderr)
    elif not args.test and failed > 0:
        if not args.quiet:
            print()
            print(f"  WARNING: {failed} generator(s) failed — files remain in output/tmp/")

    # Determine output location for summary
    if not args.test and failed == 0:
        output_summary = "output/ (ready for Splunk)"
    elif args.test:
        output_summary = "output/tmp/ (test mode)"
    else:
        output_summary = "output/tmp/ (not moved due to errors)"

    if not args.quiet:
        print()
        print("=" * 70)
        print(f"  {_C_GREEN}Complete!{_C_RESET}")
        print(f"  Total Events:  {_C_YELLOW}{total_events:,}{_C_RESET}")
        print(f"  Total Time:    {total_time:.1f}s")
        print(f"  Generators:    {_C_GREEN}{successful} successful{_C_RESET}, {failed} failed")
        print(f"  Throughput:    {total_events / total_time:,.0f} events/sec")
        print(f"  Output:        {output_summary}")
        print("=" * 70)

    # Print failures
    for result in results:
        if not result["success"]:
            print(f"Error in {result['name']}: {result.get('error', 'Unknown error')}", file=sys.stderr)

    # Return total event count
    print(total_events)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
