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
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Callable

sys.path.insert(0, str(Path(__file__).parent))

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
}

# Group sources for easy selection
SOURCE_GROUPS = {
    "all": list(GENERATORS.keys()),
    "cloud": ["aws", "gcp", "entraid"],
    "network": ["asa", "meraki"],
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
    "meraki": ["webex"],  # Meraki door sensors use Webex meeting schedule
    "exchange": ["webex"],  # Exchange calendar emails use Webex meeting schedule
    "sap": ["access"],     # SAP reads order_registry.json for sales order correlation
}


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


def run_generator(name: str, func: Callable, **kwargs) -> Dict:
    """Run a single generator and return results."""
    start_time = time.time()
    try:
        count = func(**kwargs)
        duration = time.time() - start_time
        return {
            "name": name,
            "success": True,
            "count": count,
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
  all           - All sources (19 generators)
  cloud         - aws, gcp, entraid
  network       - asa, meraki
  windows       - wineventlog, perfmon, mssql, sysmon
  linux         - linux
  web           - access
  email         - exchange
  retail        - orders, servicebus
  collaboration - webex, webex_ta, webex_api
  itsm          - servicenow

Individual Sources:
  asa, aws, gcp, entraid, exchange, access, wineventlog, linux,
  perfmon, mssql, sysmon, orders, servicebus, meraki, webex, webex_ta, webex_api, servicenow

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
    memory_leak        - Application memory leak causing OOM (Day 6-9, Linux WEB-01)
                         Sources: perfmon, linux, asa, access, servicenow
    cpu_runaway        - SQL backup job stuck causing DB failures (Day 11-12)
                         Sources: perfmon, wineventlog, asa, access, servicenow, mssql
    disk_filling       - Server disk gradually filling up (Day 1-5, MON-ATL-01)
                         Sources: linux, access, servicenow
    dead_letter_pricing - ServiceBus dead-letter causes wrong prices (Day 16)
                         Sources: servicebus, orders, access, servicenow

  Network scenarios (--scenarios=network or individual names):
    firewall_misconfig - Firewall rule misconfiguration causing outage (Day 7)
                         Sources: asa, servicenow
    certificate_expiry - SSL certificate expires causing 7-hour outage (Day 12, 00:00-07:00)
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
    parser.add_argument("--meraki-health-interval", type=int, default=5,
                        choices=[5, 10, 15, 30],
                        help="Minutes between Meraki health metric samples (default: 5, ~137K events/day)")
    parser.add_argument("--no-meraki-health", action="store_true",
                        help="Disable all Meraki health metrics generation")
    parser.add_argument("--no-mr-health", action="store_true",
                        help="Disable MR wireless AP health metrics (~10K events/day)")
    parser.add_argument("--no-ms-health", action="store_true",
                        help="Disable MS switch port health metrics (~127K events/day)")

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
        print("=" * 70)
        print()

    # Prepare generator kwargs
    base_kwargs = {
        "start_date": args.start_date,
        "days": args.days,
        "scale": args.scale,
        "scenarios": args.scenarios,
        "quiet": True,  # Always quiet for parallel execution
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
        if name == "access":
            return access_kwargs
        if name == "meraki":
            return meraki_kwargs
        return base_kwargs

    def run_phase(phase_sources: List[str], phase_name: str = None):
        """Run a phase of generators."""
        phase_results = []

        if phase_name and not args.quiet:
            print(f"\n  === {phase_name} ===")

        if args.parallel > 1 and len(phase_sources) > 1:
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
                    if not args.quiet:
                        status = "✓" if result["success"] else "✗"
                        count = result.get("count", 0)
                        dur = result["duration"]
                        print(f"  [{status}] {result['name']:12} {count:>10,} events  ({dur:.1f}s)")
                        if args.show_files:
                            files = GENERATOR_OUTPUT_FILES.get(result['name'], [result['name']])
                            for f in files:
                                file_path = current_output_base / f
                                if file_path.exists():
                                    line_count = sum(1 for _ in open(file_path))
                                    print(f"       → {output_label}/{f:45} {line_count:>10,}")
                                else:
                                    print(f"       → {output_label}/{f:45} {'(not created)':>10}")
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
                    status = "✓" if result["success"] else "✗"
                    count = result.get("count", 0)
                    print(f" [{status}] {count:,} events ({result['duration']:.1f}s)")
                    if args.show_files:
                        files = GENERATOR_OUTPUT_FILES.get(name, [name])
                        for f in files:
                            file_path = current_output_base / f
                            if file_path.exists():
                                line_count = sum(1 for _ in open(file_path))
                                print(f"       → {output_label}/{f:45} {line_count:>10,}")
                            else:
                                print(f"       → {output_label}/{f:45} {'(not created)':>10}")

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
        print(f"  Complete!")
        print(f"  Total Events:  {total_events:,}")
        print(f"  Total Time:    {total_time:.1f}s")
        print(f"  Generators:    {successful} successful, {failed} failed")
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
