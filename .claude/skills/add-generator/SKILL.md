---
name: add-generator
description: Create a new log generator following project patterns. Use when adding support for a new log source like Palo Alto, CrowdStrike, Okta, etc.
argument-hint: "<source-name>"
---

# Create New Generator

Follow these steps to add a new log source generator.

## Step 1: Copy the Template

```bash
cp TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/generators/_template_generator.py \
   TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/generators/generate_<source>.py
```

## Step 2: Required Function Signature

**ALL generators MUST use this exact signature:**

```python
def generate_<source>_logs(
    start_date: str = DEFAULT_START_DATE,    # "2026-01-01"
    days: int = DEFAULT_DAYS,                # 14
    scale: float = DEFAULT_SCALE,            # 1.0
    scenarios: str = "none",                 # Comma-separated
    output_file: str = None,                 # Override path
    quiet: bool = False,                     # Suppress output
) -> int:                                    # Returns event count
```

## Step 3: Required Imports

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import DEFAULT_START_DATE, DEFAULT_DAYS, DEFAULT_SCALE, get_output_path
from shared.time_utils import ts_iso, ts_syslog, calc_natural_events, date_add
from shared.company import USERS, SERVERS, get_internal_ip, get_external_ip
from scenarios.registry import expand_scenarios
```

## Step 4: Standard Event Loop

```python
all_events = []
active_scenarios = expand_scenarios(scenarios)

for day in range(days):
    for hour in range(24):
        # Natural volume variation (weekends, time of day, etc.)
        count = calc_natural_events(base_count, start_date, day, hour, "category")

        # Generate baseline events
        for _ in range(count):
            event = generate_event(start_date, day, hour, ...)
            all_events.append(event)

        # Add scenario events (if applicable)
        if scenario_instance:
            all_events.extend(scenario_instance.source_hour(day, hour))

# Sort and write
all_events.sort(key=lambda x: x["timestamp"])
```

## Step 5: Output Handling

```python
# Determine path
output_path = Path(output_file) if output_file else get_output_path("category", "source.log")
output_path.parent.mkdir(parents=True, exist_ok=True)

# Write events
with open(output_path, "w") as f:
    for event in all_events:
        if isinstance(event, dict):
            f.write(json.dumps(event) + "\n")  # JSONL
        else:
            f.write(event + "\n")  # Plain text

return len(all_events)
```

## Step 6: Register in main_generate.py

1. **Import:**
   ```python
   from generators.generate_xxx import generate_xxx_logs
   ```

2. **Add to GENERATORS dict:**
   ```python
   GENERATORS = {
       ...
       "xxx": generate_xxx_logs,
   }
   ```

3. **Add to SOURCE_GROUPS:**
   ```python
   SOURCE_GROUPS = {
       ...
       "network": ["asa", "meraki", "xxx"],  # or appropriate group
   }
   ```

## Timestamp Formats

Use the appropriate formatter from `time_utils.py`:

| Function | Format | Use For |
|----------|--------|---------|
| `ts_iso()` | `2026-01-05T14:30:45Z` | JSON logs (AWS, GCP) |
| `ts_iso_ms()` | `2026-01-05T14:30:45.123Z` | JSON with milliseconds |
| `ts_syslog()` | `Jan 05 2026 14:30:45` | Syslog format (ASA, Meraki) |
| `ts_perfmon()` | `01/05/2026 14:30:45.123` | Windows Perfmon |

## Category Types for calc_natural_events()

Use the appropriate category for realistic volume patterns:

- `"firewall"` - Network traffic patterns
- `"cloud"` - Cloud API activity
- `"auth"` - Authentication events
- `"web"` - Web traffic patterns
- `"email"` - Email activity

## Demo ID Tagging

For scenario events, add `demo_id` field:

```python
if scenario_active:
    event["demo_id"] = "exfil"  # or scenario name
```

## Template Location

Full template file: `TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin/generators/_template_generator.py`

## Test Your Generator

```bash
cd TA-FAKE-TSHRT/TA-FAKE-TSHRT/bin
python3 generators/generate_xxx.py --days=1 --quiet
echo "Generated $(cat output/category/xxx.log | wc -l) events"
```
