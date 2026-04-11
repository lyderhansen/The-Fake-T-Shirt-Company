---
name: add-scenario
description: Create a new attack or operational scenario. Use when adding coordinated events across multiple log sources.
metadata:
    argument-hint: "<scenario-name> [attack|ops|network]"
---

# Create New Scenario

Scenarios generate coordinated events across multiple log sources to simulate realistic incidents. Project currently has **11 implemented scenarios** across 3 categories.

## Existing Scenarios (reference)

| Scenario | Category | Directory | Days |
|----------|----------|-----------|------|
| `exfil` | attack | `scenarios/security/exfil.py` | 1-14 |
| `ransomware_attempt` | attack | `scenarios/security/ransomware_attempt.py` | 8-9 |
| `phishing_test` | attack | `scenarios/security/phishing_test.py` | 21-23 |
| `ot_rogue_device` | attack | `scenarios/security/ot_rogue_device.py` | 8 |
| `memory_leak` | ops | `scenarios/ops/memory_leak.py` | 7-10 |
| `cpu_runaway` | ops | `scenarios/ops/cpu_runaway.py` | 11-12 |
| `disk_filling` | ops | `scenarios/ops/disk_filling.py` | 1-5 |
| `dead_letter_pricing` | ops | `scenarios/ops/dead_letter_pricing.py` | 16 |
| `ddos_attack` | network | `scenarios/network/ddos_attack.py` | 18-19 |
| `firewall_misconfig` | network | `scenarios/network/firewall_misconfig.py` | 6 |
| `certificate_expiry` | network | `scenarios/network/certificate_expiry.py` | 13 |

**Directory convention:** `scenarios/security/` (not `attack/`), `scenarios/ops/`, `scenarios/network/`. Category in the registry is the logical name; the directory is the physical location.

## Step 1: Register in `scenarios/registry.py`

Add to the `SCENARIOS` dict:

```python
SCENARIOS = {
    ...
    "my_scenario": ScenarioDefinition(
        name="my_scenario",
        sources=["asa", "entraid", "aws"],  # Which generators this affects
        category="attack",                   # "attack", "ops", or "network"
        description="Brief description of what happens",
        demo_id="my_scenario",              # Value for filtering in Splunk
        start_day=1,                        # When scenario starts (0-indexed)
        end_day=14,                         # When scenario ends (inclusive)
        implemented=True,
    ),
}
```

## Step 2: Create Scenario Class

**Location:**
- Security/attack scenarios → `scenarios/security/my_scenario.py`
- Ops scenarios → `scenarios/ops/my_scenario.py`
- Network scenarios → `scenarios/network/my_scenario.py`

```python
"""
My Scenario - Brief description

Timeline:
- Days 1-3: Initial activity
- Days 4-7: Escalation
- Days 8-14: Resolution
"""

from typing import List, Dict, Any


class MyScenario:
    def __init__(self, config, company, time_utils):
        self.config = config
        self.company = company
        self.time_utils = time_utils

        # Pre-calculate key parameters
        self.attacker_ip = "185.220.101.42"
        self.target_user = self.company.get_user("alex.miller")

    def _is_active(self, day: int, hour: int) -> bool:
        """Check if scenario is active for this day/hour."""
        if day < 1 or day > 14:
            return False
        return True

    def asa_hour(self, day: int, hour: int) -> List[str]:
        """Generate ASA firewall events for this hour (syslog strings)."""
        if not self._is_active(day, hour):
            return []

        events = []
        if day <= 3:
            events.extend(self._recon_events(day, hour))
        elif day <= 7:
            events.extend(self._attack_events(day, hour))
        return events

    def aws_hour(self, day: int, hour: int) -> List[Dict[str, Any]]:
        """Generate AWS CloudTrail events for this hour (JSON dicts)."""
        if not self._is_active(day, hour):
            return []
        return []

    def _recon_events(self, day: int, hour: int) -> List[str]:
        return []
```

**Convention:** one method per affected source, named `<source>_hour(day, hour)`. Return a list of events in whatever shape the generator expects (JSON dict for JSONL generators, pre-formatted string for syslog generators).

## Step 3: Integrate in Each Generator

For each source in the `sources` list:

```python
# At top of generator file
from scenarios.security.my_scenario import MyScenario   # or scenarios.ops / scenarios.network

# In generate_<source>_logs(), after expand_scenarios()
if "my_scenario" in active_scenarios:
    my_scenario = MyScenario(config, company, time_utils)
else:
    my_scenario = None

# In the hour loop
if my_scenario:
    all_events.extend(my_scenario.asa_hour(day, hour))  # use matching method name
```

## Scenario Categories

### Attack scenarios (`scenarios/security/`)
APT attacks, data exfiltration, ransomware, phishing, OT intrusion. Coordinate across firewall, auth, cloud, endpoints, OT (cybervision).
**Examples:** `exfil.py`, `ransomware_attempt.py`, `phishing_test.py`, `ot_rogue_device.py`

### Ops scenarios (`scenarios/ops/`)
Performance issues, memory leaks, runaway processes, disk filling, message queue failures. Coordinate across metrics, system logs, APM, ITSM tickets.
**Examples:** `cpu_runaway.py`, `memory_leak.py`, `disk_filling.py`, `dead_letter_pricing.py`

### Network scenarios (`scenarios/network/`)
Outages, misconfigurations, DDoS, certificate expiry. Coordinate across firewall, routing, application logs, ITSM.
**Examples:** `ddos_attack.py`, `firewall_misconfig.py`, `certificate_expiry.py`

## Event Tagging

**All scenario events MUST include `demo_id`** for Splunk filtering — this is how demos are navigated:

```python
# JSON events
event["demo_id"] = "my_scenario"

# Syslog events — append as key=value at end of line
line = f"{base_line} demo_id=my_scenario"
```

Baseline (non-scenario) events should leave `demo_id` empty or absent. Some sourcetypes (e.g. AWS Billing CSV) have dedicated props.conf rules to null out empty `demo_id`.

## Timeline Best Practices

1. **Start subtle** — reconnaissance, early warnings, gradual drift
2. **Build tension** — escalation, more events per hour, cross-source correlation
3. **Peak activity** — the incident itself (crash, breach, outage)
4. **Resolution** — recovery, discovery, ITSM ticket created

Keep scenario day ranges **inside** the default 14-day window (`start_day=0..13`) unless it's intentionally a late-window event like `dead_letter_pricing` (day 16) or `phishing_test` (days 21-23). Document non-default windows in the scenario docstring and in `docs/scenarios/<name>.md`.

## Testing

```bash
cd TheFakeTshirtCompany/TA-FAKE-TSHRT/bin

# Generate only your scenario (test mode by default)
python3 main_generate.py --sources=asa,aws --scenarios=my_scenario --days=14

# Find scenario events in test output
grep "demo_id=my_scenario" output/tmp/network/cisco_asa.log | head
grep "my_scenario" output/tmp/cloud/aws_cloudtrail.log | head
```

## Splunk Queries (use `FAKE:` sourcetype prefix)

```spl
# All events from scenario
index=fake_tshrt demo_id=my_scenario | stats count by sourcetype

# Timeline view
index=fake_tshrt demo_id=my_scenario | timechart span=1h count by sourcetype

# Attack correlation
index=fake_tshrt demo_id=my_scenario
| transaction demo_id maxspan=1h
| table _time, sourcetype, src, dest, user
```

## Documentation

After implementing a new scenario:
1. Add a narrative doc at `docs/scenarios/<name>.md` describing the timeline, affected users/assets, and demo talking points
2. Add an entry to `docs/CHANGEHISTORY.md` (date/time UTC, files touched, verification summary)
3. Update the scenario table in `CLAUDE.md`
