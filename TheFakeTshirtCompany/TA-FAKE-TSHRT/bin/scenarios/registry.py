#!/usr/bin/env python3
"""
Scenario Registry - Central registry of all scenarios and their relationships.
Converted from scenarios/registry.sh
"""

from typing import List, Set, Optional, Dict
from dataclasses import dataclass


@dataclass
class ScenarioDefinition:
    """Definition of a scenario.

    Days are 0-indexed to match generator loops (range(days)):
        day 0 = first day of generation (e.g., Jan 1)
        day 13 = last day of a 14-day run (e.g., Jan 14)
    """
    name: str
    sources: List[str]
    category: str
    description: str
    demo_id: str
    start_day: int = 0
    end_day: int = 13
    server: Optional[str] = None
    implemented: bool = True


# =============================================================================
# AVAILABLE SOURCES
# =============================================================================
ALL_SOURCES = [
    "asa", "aws", "aws_guardduty", "aws_billing", "gcp", "entraid",
    "exchange", "office_audit", "access", "wineventlog", "sysmon", "perfmon",
    "mssql", "linux", "orders", "servicebus", "meraki", "webex", "webex_ta",
    "webex_api", "servicenow", "sap", "secure_access", "catalyst", "aci",
    "catalyst_center",
]

SOURCES_NETWORK = ["asa"]
SOURCES_CLOUD = ["entraid", "aws", "gcp", "exchange"]
SOURCES_WINDOWS = ["perfmon", "wineventlog"]
SOURCES_LINUX = ["linux"]
SOURCES_WEB = ["access"]


# =============================================================================
# SCENARIO DEFINITIONS
# =============================================================================
SCENARIOS: Dict[str, ScenarioDefinition] = {
    # Attack scenarios
    "exfil": ScenarioDefinition(
        name="exfil",
        sources=["asa", "entraid", "aws", "aws_guardduty", "aws_billing", "gcp", "perfmon", "wineventlog", "exchange", "office_audit", "servicenow", "mssql", "sysmon", "secure_access", "catalyst", "aci", "webex", "linux"],
        category="attack",
        description="APT-style data exfiltration over 14 days (phishing -> privilege abuse -> exfil)",
        demo_id="exfil",
        implemented=True
    ),
    "phishing_test": ScenarioDefinition(
        name="phishing_test",
        sources=["exchange", "entraid", "wineventlog", "office_audit", "servicenow", "secure_access"],
        category="attack",
        description="IT-run phishing awareness campaign after exfil incident (Day 21-23)",
        demo_id="phishing_test",
        start_day=20,
        end_day=22,
        implemented=True
    ),

    # Ops scenarios
    "disk_filling": ScenarioDefinition(
        name="disk_filling",
        sources=["linux", "access", "servicenow"],
        category="ops",
        description="Server disk gradually filling up, resolved Day 5 (MON-ATL-01)",
        demo_id="disk_filling",
        start_day=0,
        end_day=4,
        server="MON-ATL-01",
        implemented=True
    ),
    "memory_leak": ScenarioDefinition(
        name="memory_leak",
        sources=["linux", "asa", "access", "servicenow", "catalyst_center", "aws"],
        category="ops",
        description="Application memory leak causing OOM crash Day 10, restart (WEB-01)",
        demo_id="memory_leak",
        start_day=5,
        end_day=9,
        server="WEB-01",
        implemented=True
    ),
    "cpu_runaway": ScenarioDefinition(
        name="cpu_runaway",
        sources=["perfmon", "wineventlog", "asa", "access", "servicenow", "mssql", "aci", "catalyst_center", "aws", "gcp"],
        category="ops",
        description="SQL-PROD-01 backup job stuck causing cascading DB failures (Day 11-12)",
        demo_id="cpu_runaway",
        start_day=10,
        end_day=11,
        server="SQL-PROD-01",
        implemented=True
    ),

    # Ops scenarios (continued)
    "dead_letter_pricing": ScenarioDefinition(
        name="dead_letter_pricing",
        sources=["servicebus", "orders", "access", "servicenow"],
        category="ops",
        description="ServiceBus dead-letter queue causes wrong product prices on web store (Day 16, 4-6h)",
        demo_id="dead_letter_pricing",
        start_day=15,
        end_day=15,
        server="WEB-01",
        implemented=True
    ),

    # Network scenarios
    "ddos_attack": ScenarioDefinition(
        name="ddos_attack",
        sources=["asa", "meraki", "access", "perfmon", "linux", "servicenow", "catalyst", "aci", "catalyst_center", "aws", "aws_billing"],
        category="network",
        description="Volumetric HTTP flood targeting web servers (Day 18-19)",
        demo_id="ddos_attack",
        start_day=17,
        end_day=18,
        server="WEB-01",
        implemented=True
    ),
    "firewall_misconfig": ScenarioDefinition(
        name="firewall_misconfig",
        sources=["asa", "access", "servicenow", "catalyst"],
        category="network",
        description="Firewall rule misconfiguration causing outage (Day 6)",
        demo_id="firewall_misconfig",
        start_day=5,
        end_day=5,
        implemented=True
    ),
    "certificate_expiry": ScenarioDefinition(
        name="certificate_expiry",
        sources=["asa", "access", "servicenow"],
        category="network",
        description="SSL certificate expires causing 7-hour outage (Day 13, 00:00-07:00)",
        demo_id="certificate_expiry",
        start_day=12,
        end_day=12,
        implemented=True
    ),

    # Ransomware attempt - detected and stopped
    "ransomware_attempt": ScenarioDefinition(
        name="ransomware_attempt",
        sources=["asa", "exchange", "wineventlog", "meraki", "servicenow", "office_audit", "sysmon", "secure_access", "aws_guardduty"],
        category="attack",
        description="Ransomware attempt via phishing - detected and stopped by EDR (Day 8-9)",
        demo_id="ransomware_attempt",
        start_day=7,
        end_day=8,
        implemented=True
    ),
}

ALL_SCENARIOS = list(SCENARIOS.keys())
IMPLEMENTED_SCENARIOS = [name for name, s in SCENARIOS.items() if s.implemented]

CATEGORY_ATTACK = ["exfil", "phishing_test", "ransomware_attempt"]
CATEGORY_OPS = ["disk_filling", "memory_leak", "cpu_runaway", "dead_letter_pricing"]
CATEGORY_NETWORK = ["ddos_attack", "firewall_misconfig", "certificate_expiry"]


# =============================================================================
# ATTACK PHASES
# =============================================================================
def get_phase(day: int) -> Optional[str]:
    """
    Get the exfil attack phase for a given day.
    Returns None after the exfil scenario ends (day 14+).

    Phases (exfil scenario only):
        recon (Days 0-3): Reconnaissance and scanning
        initial_access (Day 4): Initial foothold
        lateral (Days 5-7): Lateral movement
        persistence (Days 8-10): Persistence and staging
        exfil (Days 11-13): Data exfiltration
        None (Day 14+): Exfil scenario complete (other scenarios may still be active)
    """
    if day <= 3:
        return "recon"
    elif day == 4:
        return "initial_access"
    elif day <= 7:
        return "lateral"
    elif day <= 10:
        return "persistence"
    elif day <= 13:
        return "exfil"
    else:
        return None  # Scenario complete


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def scenario_exists(scenario: str) -> bool:
    """Check if a scenario exists."""
    return scenario in SCENARIOS


def scenario_implemented(scenario: str) -> bool:
    """Check if a scenario is implemented."""
    return scenario in SCENARIOS and SCENARIOS[scenario].implemented


def get_scenario_sources(scenario: str) -> List[str]:
    """Get sources for a scenario."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].sources
    return []


def get_scenario_category(scenario: str) -> str:
    """Get category for a scenario."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].category
    return ""


def get_scenario_description(scenario: str) -> str:
    """Get description for a scenario."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].description
    return ""


def get_scenario_demo_id(scenario: str) -> str:
    """Get demo_id for a scenario."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].demo_id
    return ""


def get_scenario_start_day(scenario: str) -> int:
    """Get start day for a scenario (default: 1)."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].start_day
    return 1


def get_scenario_end_day(scenario: str) -> int:
    """Get end day for a scenario (default: 14)."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].end_day
    return 14


def get_scenario_server(scenario: str) -> Optional[str]:
    """Get target server for a scenario (if applicable)."""
    if scenario in SCENARIOS:
        return SCENARIOS[scenario].server
    return None


def is_scenario_active_day(scenario: str, day: int) -> bool:
    """Check if a day is within a scenario's active window."""
    start_day = get_scenario_start_day(scenario)
    end_day = get_scenario_end_day(scenario)
    return start_day <= day <= end_day


def get_category_scenarios(category: str) -> List[str]:
    """Get all scenarios in a category."""
    if category == "attack":
        return CATEGORY_ATTACK
    elif category == "ops":
        return CATEGORY_OPS
    elif category == "network":
        return CATEGORY_NETWORK
    return []


def expand_scenarios(spec: str) -> List[str]:
    """
    Expand scenario specification to list of scenarios.
    Handles: "all", "none", category names, comma-separated scenarios.
    """
    if spec == "all":
        return IMPLEMENTED_SCENARIOS.copy()
    if spec in ("none", ""):
        return []

    result = set()
    items = [item.strip() for item in spec.split(",")]

    for item in items:
        if item in ("attack", "ops", "network"):
            result.update(get_category_scenarios(item))
        elif scenario_implemented(item):
            result.add(item)
        elif scenario_exists(item):
            print(f"Warning: Scenario '{item}' is not yet implemented, skipping")

    return list(result)


def filter_scenarios_by_days(scenarios: List[str], days: int) -> List[str]:
    """Filter out scenarios whose start_day >= days (they won't generate any events).

    When running with --days=14, scenarios that start on day 15+ are excluded.
    This allows shorter generation runs to skip scenarios outside their window.
    """
    return [s for s in scenarios if SCENARIOS[s].start_day < days]


def get_required_sources(scenarios: List[str]) -> Set[str]:
    """Get all sources needed for a list of scenarios."""
    sources = set()
    for scenario in scenarios:
        sources.update(get_scenario_sources(scenario))
    return sources


def source_needed_for_scenarios(source: str, scenarios: List[str]) -> bool:
    """Check if a source is needed for any of the given scenarios."""
    required = get_required_sources(scenarios)
    return source in required


def filter_sources_for_scenarios(sources: List[str], scenarios: List[str]) -> List[str]:
    """Filter sources by what's needed for scenarios."""
    required = get_required_sources(scenarios)
    return [s for s in sources if s in required]


def print_scenario_matrix():
    """Print scenario matrix (for help/debug)."""
    print("Scenario Matrix:")
    print("================")
    print(f"{'Scenario':<20} {'Category':<8} {'ASA':<4} {'Entra':<6} {'AWS':<4} {'GCP':<4} {'Perf':<5} {'WinEv':<5} {'Linux':<5} {'Access':<6} {'Exch':<4}")
    print("-" * 90)

    for name, scenario in SCENARIOS.items():
        sources = scenario.sources
        display_name = name if scenario.implemented else f"{name}*"

        print(f"{display_name:<20} {scenario.category:<8} "
              f"{'X' if 'asa' in sources else '':<4} "
              f"{'X' if 'entraid' in sources else '':<6} "
              f"{'X' if 'aws' in sources else '':<4} "
              f"{'X' if 'gcp' in sources else '':<4} "
              f"{'X' if 'perfmon' in sources else '':<5} "
              f"{'X' if 'wineventlog' in sources else '':<5} "
              f"{'X' if 'linux' in sources else '':<5} "
              f"{'X' if 'access' in sources else '':<6} "
              f"{'X' if 'exchange' in sources else '':<4}")

    print("\n* = not yet implemented")


def print_available_scenarios():
    """Print available scenarios (for help text)."""
    print("Available Scenarios:\n")

    for category in ["attack", "ops", "network"]:
        print(f"  {category}:")
        scenarios = get_category_scenarios(category)
        for scenario in scenarios:
            desc = get_scenario_description(scenario)
            impl = "" if scenario_implemented(scenario) else " (not yet implemented)"
            print(f"    {scenario:<20} {desc}{impl}")
        print()


if __name__ == "__main__":
    print_scenario_matrix()
    print("\n")
    print_available_scenarios()
