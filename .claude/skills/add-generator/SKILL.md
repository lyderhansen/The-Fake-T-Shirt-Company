---
name: add-generator
description: Create a new log generator following project patterns. Use when adding support for a new log source like Palo Alto, CrowdStrike, Okta, etc.
metadata:
    argument-hint: "<source-name>"
---

# Create New Generator

Follow these steps to add a new log source generator.

## Step 1: Copy the Template

```bash
cp TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/_template_generator.py \
   TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/generate_<source>.py
```

> **Note:** The template is a minimal starting point. Real generators (e.g. `generate_asa.py`, `generate_catalyst.py`) include the `progress_callback` parameter shown below — add it when copying from the template.

## Step 2: Required Function Signature

**ALL generators MUST use this exact signature:**

```python
def generate_<source>_logs(
    start_date: str = DEFAULT_START_DATE,    # "2026-01-01"
    days: int = DEFAULT_DAYS,                # 14
    scale: float = DEFAULT_SCALE,            # 1.0
    scenarios: str = "none",                 # Comma-separated
    output_file: str = None,                 # Override path (or output_dir for multi-file)
    progress_callback=None,                  # fn(source_name, current_day, total_days)
    quiet: bool = False,                     # Suppress output
) -> int:                                    # Returns event count
```

Multi-file generators (e.g. Meraki, Linux, Cybervision) may return a dict: `{"total": N, "files": {...}}`.

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
    if progress_callback:
        progress_callback("<source>", day, days)

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

`get_output_path()` automatically honours the `--test` / `--no-test` flag from `main_generate.py` — test mode writes to `bin/output/tmp/<category>/`, production mode writes to `bin/output/<category>/`. Do **not** hard-code paths.

```python
output_path = Path(output_file) if output_file else get_output_path("category", "source.log")
output_path.parent.mkdir(parents=True, exist_ok=True)

with open(output_path, "w") as f:
    for event in all_events:
        if isinstance(event, dict):
            f.write(json.dumps(event) + "\n")  # JSONL
        else:
            f.write(event + "\n")  # Plain text / syslog

return len(all_events)
```

## Step 6: Register in main_generate.py

1. **Import:**
   ```python
   from generators.generate_xxx import generate_xxx_logs
   ```

2. **Add to `GENERATORS` dict:**
   ```python
   GENERATORS = {
       ...
       "xxx": generate_xxx_logs,
   }
   ```

3. **Add to `SOURCE_GROUPS`** (one or more of):
   `cloud`, `network`, `cisco`, `campus`, `datacenter`, `ot`, `windows`, `linux`, `web`, `office`, `email`, `retail`, `collaboration`, `itsm`, `erp`.

4. **Dependencies (optional):** If your generator reads `order_registry.json` or `web_session_registry.json`, add an entry to `GENERATOR_DEPENDENCIES` so it runs in Phase 2.

5. **Splunk integration:** Add sourcetype to `default/props.conf` (with `FAKE:` prefix at index time via `transforms.conf`) and `default/inputs.conf` monitor stanza for `output/<category>/<source>.log`.

## Timestamp Formats

| Function | Format | Use For |
|----------|--------|---------|
| `ts_iso()` | `2026-01-05T14:30:45Z` | JSON logs (AWS, GCP, cloud) |
| `ts_iso_ms()` | `2026-01-05T14:30:45.123Z` | JSON with milliseconds |
| `ts_syslog()` | `Jan 05 2026 14:30:45` | Syslog (ASA, Meraki, Catalyst) |
| `ts_perfmon()` | `01/05/2026 14:30:45.123` | Windows Perfmon |
| `ts_cef()` | CEF header format | Cyber Vision CEF syslog |

## Category Types for `calc_natural_events()`

Controls the hourly activity curve. Pick the closest match:

- `"firewall"` — network/perimeter traffic
- `"cloud"` — cloud API / automated jobs
- `"auth"` — authentication events
- `"web"` — web traffic / retail
- `"email"` — email/collaboration
- `"ot"` — industrial control (flatter curve, 24/7 production)

## Demo ID Tagging

For scenario events, add `demo_id` so they're filterable in Splunk:

```python
# JSON events
event["demo_id"] = "exfil"

# Syslog events (append as key=value)
line = f"{base_line} demo_id=exfil"
```

Never add `demo_id` to baseline events — leave it empty/null so `props.conf` can strip it.

## Template Location

Full template file: `TheFakeTshirtCompany/TA-FAKE-TSHRT/bin/generators/_template_generator.py`

## Test Your Generator

```bash
cd TheFakeTshirtCompany/TA-FAKE-TSHRT/bin

# Standalone smoke test (writes to output/tmp/)
python3 generators/generate_xxx.py --days=1 --quiet

# Via orchestrator (respects --test default)
python3 main_generate.py --sources=xxx --days=1 --quiet
wc -l output/tmp/<category>/xxx.log
```
