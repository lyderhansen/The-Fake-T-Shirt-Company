---
name: add-scenario
description: Create a new attack or operational scenario. Use when adding coordinated events across multiple log sources.
metadata:
    argument-hint: "<scenario-name> [attack|ops|network]"
---

# Create New Scenario

Scenarios generate coordinated events across multiple log sources to simulate realistic incidents.

## Step 1: Register in scenarios/registry.py

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
        end_day=14,                         # When scenario ends
        implemented=True,
    ),
}
```

## Step 2: Create Scenario Class

**Location:** `scenarios/<category>/my_scenario.py`

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
        # Add hour-specific logic if needed
        return True

    def asa_hour(self, day: int, hour: int) -> List[str]:
        """Generate ASA firewall events for this hour."""
        if not self._is_active(day, hour):
            return []

        events = []

        # Phase-specific events
        if day <= 3:
            # Reconnaissance phase
            events.extend(self._recon_events(day, hour))
        elif day <= 7:
            # Attack phase
            events.extend(self._attack_events(day, hour))

        return events

    def aws_hour(self, day: int, hour: int) -> List[Dict[str, Any]]:
        """Generate AWS CloudTrail events for this hour."""
        if not self._is_active(day, hour):
            return []

        events = []
        # ... generate events
        return events

    def _recon_events(self, day: int, hour: int) -> List[str]:
        """Generate reconnaissance phase events."""
        # Implementation
        return []
```

## Step 3: Integrate in Generators

For each generator in `sources` list:

```python
# At top of file
from scenarios.security.my_scenario import MyScenario

# In generate function, after parsing scenarios
if "my_scenario" in active_scenarios:
    my_scenario = MyScenario(config, company, time_utils)
else:
    my_scenario = None

# In hour loop
if my_scenario:
    all_events.extend(my_scenario.source_hour(day, hour))
```

## Scenario Categories

### Attack Scenarios (`scenarios/security/`)
- APT attacks, data exfiltration, lateral movement
- Coordinate across: firewall, auth, cloud, endpoints
- Example: `exfil.py`

### Ops Scenarios (`scenarios/ops/`)
- Performance issues, service outages
- Coordinate across: metrics, logs, alerts
- Examples: `cpu_runaway.py`, `memory_leak.py`, `disk_filling.py`

### Network Scenarios (`scenarios/network/`)
- Connectivity issues, misconfigurations
- Coordinate across: firewall, routing, services
- Example: `firewall_misconfig.py`

## Event Tagging

All scenario events MUST include `demo_id` for Splunk filtering:

```python
# JSON events
event["demo_id"] = "my_scenario"

# Syslog events (append to line)
line = f"{base_line} demo_id=my_scenario"
```

## Timeline Best Practices

1. **Start slow** - Reconnaissance/early signs
2. **Build tension** - Gradual escalation
3. **Peak activity** - Main incident
4. **Resolution** - Recovery or discovery

## Testing

```bash
cd TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin

# Generate with only your scenario
python3 main_generate.py --sources=asa,aws --scenarios=my_scenario --days=14

# Find scenario events
grep "demo_id=my_scenario" output/network/cisco_asa.log | head
```

## Splunk Queries

```spl
# All events from scenario
index=* demo_id=my_scenario | stats count by sourcetype

# Timeline view
index=* demo_id=my_scenario | timechart span=1h count by sourcetype

# Attack correlation
index=* demo_id=my_scenario
| transaction demo_id maxspan=1h
| table _time, sourcetype, src, dest, user
```
