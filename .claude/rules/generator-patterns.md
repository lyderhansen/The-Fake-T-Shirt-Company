---
paths:
  - "TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/generators/**/*.py"
---

# Generator Development Rules

These rules apply when working on log generator files.

## Required Function Signature

All generators MUST use this exact signature:

```python
def generate_<source>_logs(
    start_date: str = DEFAULT_START_DATE,
    days: int = DEFAULT_DAYS,
    scale: float = DEFAULT_SCALE,
    scenarios: str = "none",
    output_file: str = None,
    quiet: bool = False,
) -> int:  # Returns event count
```

## Required Imports

Every generator must import from shared modules:

```python
from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import ts_iso, calc_natural_events
from shared.company import USERS, get_internal_ip
from scenarios.registry import expand_scenarios
```

## Volume Calculation

Always use `calc_natural_events()` for realistic volume patterns:

```python
count = calc_natural_events(base_count, start_date, day, hour, "category")
```

Categories: `"firewall"`, `"cloud"`, `"auth"`, `"web"`, `"email"`

## Output Rules

1. Print progress to **stderr** (not stdout)
2. Return **integer** event count
3. Use `get_output_path()` for default paths
4. Create parent directories: `output_path.parent.mkdir(parents=True, exist_ok=True)`

## Scenario Integration

1. Parse scenarios: `active_scenarios = expand_scenarios(scenarios)`
2. Add `demo_id` field for scenario events
3. Implement `scenario.<source>_hour(day, hour)` methods

## Registration

After creating a generator:

1. Import in `main_generate.py`
2. Add to `GENERATORS` dict
3. Add to appropriate `SOURCE_GROUPS`

## Template

Use `TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/generators/_template_generator.py` as starting point for new generators.
