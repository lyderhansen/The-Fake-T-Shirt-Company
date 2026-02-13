# Dashboard Studio v2 Design Language Specification

> **Authoritative reference for all dashboard development in The Fake T-Shirt Company project.**
> All dashboards MUST conform to this specification. No exceptions.

---

## 1. Color Palette

### Backgrounds

| Token | Hex | Usage |
|-------|-----|-------|
| bg-canvas | `#0B0C10` | Dashboard background |
| bg-surface | `#13141A` | Card/panel backgrounds |
| bg-elevated | `#1A1B24` | Elevated surfaces |
| bg-highlight | `#2A1F3D` | Purple-tinted accent |

### Primary Colors

| Token | Hex | Usage |
|-------|-----|-------|
| primary-cyan | `#00D2FF` | Primary accent, KPI values, links |
| primary-purple | `#7B56DB` | Secondary accent, badges |
| primary-navy | `#0F1B3D` | Deep section backgrounds |

### Semantic Colors

| Token | Hex | Usage |
|-------|-----|-------|
| success | `#53A051` | Healthy, passing |
| warning | `#F8BE34` | Attention required |
| danger | `#DC4E41` | Critical alerts |
| info | `#009CEB` | Informational |
| neutral | `#7F8C9A` | Muted/disabled |

### Scenario Colors (immutable -- same across all dashboards)

| Scenario | Hex |
|----------|-----|
| exfil | `#DC4E41` |
| ransomware_attempt | `#F1813F` |
| memory_leak | `#F8BE34` |
| cpu_runaway | `#FF677B` |
| disk_filling | `#7B56DB` |
| firewall_misconfig | `#009CEB` |
| certificate_expiry | `#00CDAF` |

### Location Colors

| Location | Hex |
|----------|-----|
| Boston (BOS) | `#00D2FF` |
| Atlanta (ATL) | `#53A051` |
| Austin (AUS) | `#F8BE34` |

### Chart Series Palette

Use this ordered array whenever a chart displays multiple series without explicit field-to-color mapping:

```json
["#00D2FF", "#7B56DB", "#53A051", "#F8BE34", "#DC4E41", "#009CEB", "#00CDAF", "#F1813F", "#FF677B", "#AE8CFF"]
```

---

## 2. Layout Rules

- **Grid layout** for most dashboards (auto-sized, responsive).
- **Absolute layout** for floor plans, story-driven dashboards, or any dashboard needing overlapping elements / custom canvas size.
- Grid layout definition has ONLY `type` and `structure` -- NO `options`, `width`, `height`, `backgroundColor`, or `display`. Width 1200 in position values. Y-values are cumulative (no gaps).
- **Absolute layout REQUIRES `layoutDefinitions` + `tabs`** -- You CANNOT use `"type": "absolute"` directly in the top-level `layout` object. It causes a "CData section not finished" XML parse error in Splunk. Absolute layout MUST be wrapped inside `layoutDefinitions` with at least one tab, even for a single-view dashboard.
- Absolute layout supports `splunk.rectangle` for overlapping background panels (z-order = array position in structure). Grid does NOT support overlapping.
- Absolute layout `options`: `width` (default 1140), `height` (default 960), `display` (`auto-scale`/`actual-size`/`fit-to-width`), `backgroundColor` (hex), `backgroundImage` (`src`, `sizeType`: auto/contain/cover). These options are ONLY available in absolute layout.
- Every `ds.search` MUST have a `name` property.
- Every visualization MUST appear in `layout.structure` (grid) or `layoutDefinitions.*.structure` (absolute). Missing entries cause panels to silently not render.
- Default time range: epoch `1767225600` to `1769904000` (Jan 1 -- Feb 1, 2026).
- Tabs work with both layout types. Each `layoutDefinition` can use `"type": "grid"` or `"type": "absolute"` independently.
- **Reference**: `boston_-_floor_plan.xml` (working absolute layout with tabs) and `scenario_exfil_absolute.xml` (single-tab absolute story dashboard).
- **`splunk.markdown` does NOT support markdown tables** — Pipe-based table syntax (`| col1 | col2 |`) does not render in Dashboard Studio's `splunk.markdown` visualization. Use `splunk.table` with `| makeresults` or static data for tabular content instead.
- **Avoid problematic Unicode in dashboard JSON** — Splunk's XML parser can break CDATA sections with "CData section not finished" errors on certain non-ASCII characters. **Emojis are OK** (e.g., ☠, 🔍, 🎣, ✅, ⚠, 🛡). Avoid em-dashes (`---` U+2014), arrows (U+2192), middle dots (U+00B7), and similar typographic Unicode -- replace with ASCII: `--`, `->`, `|`.

### Grid Layout Skeleton

```json
{
  "layout": {
    "type": "grid",
    "globalInputs": ["input_global_trp"],
    "structure": [
      {
        "item": "viz_kpi_total",
        "type": "block",
        "position": { "x": 0, "y": 0, "w": 300, "h": 100 }
      }
    ]
  }
}
```

### Absolute Layout Skeleton

Uses `layoutDefinitions` + `tabs` -- even for a single view. DO NOT put `"type": "absolute"` in the top-level `layout` object.

```json
{
  "layout": {
    "globalInputs": ["input_global_trp"],
    "layoutDefinitions": {
      "layout_main": {
        "type": "absolute",
        "options": {
          "width": 1920,
          "height": 5500,
          "display": "auto-scale",
          "backgroundColor": "#0B0C10"
        },
        "structure": [
          {
            "item": "viz_bg_panel",
            "type": "block",
            "position": { "x": 0, "y": 0, "w": 1920, "h": 300 }
          },
          {
            "item": "viz_content",
            "type": "block",
            "position": { "x": 40, "y": 20, "w": 1840, "h": 260 }
          }
        ]
      }
    },
    "options": {},
    "tabs": {
      "items": [
        { "label": "Main", "layoutId": "layout_main" }
      ]
    }
  }
}
```

---

## 3. Naming Conventions

### Dashboard Titles

| Category | Pattern | Example |
|----------|---------|---------|
| Discovery | `Discovery - <topic>` | `Discovery - SOC Overview` |
| Scenario | `Scenario - <name>` | `Scenario - APT Data Exfiltration` |
| Source | `Source - <technology>` | `Source - Cisco ASA` |
| Overview | `Overview` | `Overview` |

### Filenames

| Category | Pattern | Example |
|----------|---------|---------|
| Discovery | `discovery_<topic>.xml` | `discovery_soc.xml` |
| Scenario | `scenario_<name>.xml` | `scenario_exfil.xml` |
| Source | `source_<technology>.xml` | `source_cisco_asa.xml` |
| Overview | `overview.xml` | `overview.xml` |

### JSON Object IDs

| Type | Prefix | Example |
|------|--------|---------|
| Data sources | `ds_` | `ds_total_events`, `ds_scenario_breakdown` |
| Visualizations | `viz_` | `viz_timeline`, `viz_kpi_total` |
| Inputs | `input_` | `input_global_trp`, `input_scenario` |

### ID Rules

- Alphanumeric and underscores only. **No hyphens.**
- Use `snake_case` for all identifiers.

---

## 4. Component Library (JSON Patterns)

Complete, copy-paste-ready JSON snippets. These are the building blocks for all dashboards.

### 4.1 KPI Card with Sparkline

```json
{
  "type": "splunk.singlevalue",
  "title": "Total Events",
  "dataSources": { "primary": "ds_total_events" },
  "options": {
    "majorValue": "> sparklineValues | lastPoint()",
    "trendValue": "> sparklineValues | delta(-2)",
    "sparklineValues": "> primary | seriesByName('count')",
    "sparklineDisplay": "below",
    "trendDisplay": "percent",
    "majorColor": "#00D2FF",
    "trendColor": "> trendValue | rangeValue(trendColorConfig)",
    "backgroundColor": "transparent",
    "showSparklineAreaGraph": true,
    "sparklineStrokeColor": "#00D2FF"
  },
  "context": {
    "trendColorConfig": [
      { "value": "#DC4E41", "to": 0 },
      { "value": "#53A051", "from": 0 }
    ]
  }
}
```

**Data source pattern:**
```spl
| tstats count WHERE index=fake_tshrt BY _time span=1h
```

### 4.2 KPI Card Simple (no sparkline)

```json
{
  "type": "splunk.singlevalue",
  "title": "Active Sourcetypes",
  "dataSources": { "primary": "ds_sourcetype_count" },
  "options": {
    "majorValue": "> primary | seriesByName('count') | lastPoint()",
    "majorColor": "#7B56DB",
    "backgroundColor": "transparent",
    "sparklineDisplay": "off"
  }
}
```

### 4.3 Range-Colored KPI (Health Score)

```json
{
  "type": "splunk.singlevalue",
  "title": "Health Score",
  "dataSources": { "primary": "ds_health" },
  "options": {
    "majorValue": "> primary | seriesByName('score') | lastPoint()",
    "majorColor": "> majorValue | rangeValue(majorColorConfig)",
    "sparklineDisplay": "off",
    "backgroundColor": "transparent"
  },
  "context": {
    "majorColorConfig": [
      { "to": 60, "value": "#DC4E41" },
      { "from": 60, "to": 85, "value": "#F8BE34" },
      { "from": 85, "value": "#53A051" }
    ]
  }
}
```

### 4.4 Stacked Area Chart (Event Timeline)

```json
{
  "type": "splunk.area",
  "title": "Event Volume Over Time",
  "dataSources": { "primary": "ds_timeline" },
  "options": {
    "stackMode": "stacked",
    "legendDisplay": "right",
    "nullValueDisplay": "zero",
    "areaOpacity": 0.7,
    "backgroundColor": "transparent",
    "xAxisTitleVisibility": "hide",
    "yAxisTitleText": "Events",
    "yAxisTitleVisibility": "show",
    "yAxisAbbreviation": "auto",
    "seriesColors": ["#00D2FF", "#7B56DB", "#53A051", "#F8BE34", "#DC4E41", "#009CEB", "#00CDAF", "#F1813F", "#FF677B", "#AE8CFF"]
  },
  "showProgressBar": true,
  "showLastUpdated": true
}
```

**Data source pattern:**
```spl
| tstats count WHERE index=fake_tshrt BY _time, sourcetype span=1h
```

### 4.5 Line Chart

```json
{
  "type": "splunk.line",
  "title": "Trend",
  "dataSources": { "primary": "ds_trend" },
  "options": {
    "legendDisplay": "right",
    "backgroundColor": "transparent",
    "xAxisTitleVisibility": "hide",
    "yAxisTitleVisibility": "show",
    "seriesColors": ["#00D2FF", "#7B56DB", "#53A051"]
  },
  "showProgressBar": true
}
```

### 4.6 Donut Chart (Breakdown)

```json
{
  "type": "splunk.pie",
  "title": "Distribution",
  "dataSources": { "primary": "ds_breakdown" },
  "options": {
    "labelDisplay": "valuesAndPercentage",
    "showDonutHole": true,
    "seriesColors": ["#00D2FF", "#7B56DB", "#53A051", "#F8BE34", "#DC4E41", "#009CEB", "#00CDAF", "#F1813F"]
  }
}
```

### 4.7 Horizontal Bar Chart (Top-N)

```json
{
  "type": "splunk.bar",
  "title": "Top Sources",
  "dataSources": { "primary": "ds_top_sources" },
  "options": {
    "seriesColors": ["#009CEB"],
    "legendDisplay": "off",
    "xAxisTitleVisibility": "hide",
    "yAxisTitleVisibility": "hide",
    "dataValuesDisplay": "all",
    "backgroundColor": "transparent",
    "orientation": "horizontal"
  }
}
```

### 4.8 Column Chart (Vertical Bar)

```json
{
  "type": "splunk.column",
  "title": "Events by Category",
  "dataSources": { "primary": "ds_categories" },
  "options": {
    "seriesColors": ["#00D2FF"],
    "legendDisplay": "off",
    "backgroundColor": "transparent",
    "dataValuesDisplay": "all"
  }
}
```

### 4.9 Data Table with Row Coloring

> **WARNING:** Do NOT use `matchValue()` — it causes `e.map is not a function`. Use `rangeValue()` with a numeric rank instead. Use `tableFormat` (not `columnFormat`) for whole-row coloring. Prefix the rank field with `_` (e.g., `_color_rank`) and set `"showInternalFields": false` to hide it from the table.

**SPL pattern:** Add an underscore-prefixed numeric rank field:
```spl
| eval _color_rank=case(field=="value1", 1, field=="value2", 2, field=="value3", 3)
```

**Table visualization:**
```json
{
  "type": "splunk.table",
  "title": "Recent Events",
  "dataSources": { "primary": "ds_events" },
  "options": {
    "count": 20,
    "showRowNumbers": false,
    "showInternalFields": false,
    "tableFormat": {
      "rowBackgroundColors": "> table | seriesByName(\"_color_rank\") | rangeValue(rowColorConfig)"
    }
  },
  "context": {
    "rowColorConfig": [
      { "from": 0, "to": 1.5, "value": "#DC4E41" },
      { "from": 1.5, "to": 2.5, "value": "#F1813F" },
      { "from": 2.5, "to": 3.5, "value": "#F8BE34" },
      { "from": 3.5, "to": 4.5, "value": "transparent" }
    ]
  },
  "showProgressBar": true,
  "showLastUpdated": true
}
```

### 4.10 Section Header (Markdown)

```json
{
  "type": "splunk.markdown",
  "options": {
    "markdown": "### Section Title\n\nDescriptive text about this section.",
    "fontColor": "#CCCCCC"
  }
}
```

### 4.11 Global Time Range Input

```json
{
  "input_global_trp": {
    "type": "input.timerange",
    "title": "Time Range",
    "options": {
      "token": "global_time",
      "defaultValue": "1767225600,1769904000"
    }
  }
}
```

### 4.12 Scenario Dropdown Filter

```json
{
  "input_scenario": {
    "type": "input.dropdown",
    "title": "Scenario Filter",
    "options": {
      "token": "scenario_filter",
      "defaultValue": "*",
      "items": [
        { "label": "All Events", "value": "*" },
        { "label": "All Scenarios", "value": "demo_id=*" },
        { "label": "Exfil (APT)", "value": "demo_id=exfil" },
        { "label": "Ransomware", "value": "demo_id=ransomware_attempt" },
        { "label": "Memory Leak", "value": "demo_id=memory_leak" },
        { "label": "CPU Runaway", "value": "demo_id=cpu_runaway" },
        { "label": "Disk Filling", "value": "demo_id=disk_filling" },
        { "label": "Firewall Misconfig", "value": "demo_id=firewall_misconfig" },
        { "label": "Certificate Expiry", "value": "demo_id=certificate_expiry" }
      ]
    }
  }
}
```

### 4.13 Location Dropdown Filter

```json
{
  "input_location": {
    "type": "input.dropdown",
    "title": "Location",
    "options": {
      "token": "location_filter",
      "defaultValue": "*",
      "items": [
        { "label": "All Locations", "value": "*" },
        { "label": "Boston (BOS)", "value": "BOS" },
        { "label": "Atlanta (ATL)", "value": "ATL" },
        { "label": "Austin (AUS)", "value": "AUS" }
      ]
    }
  }
}
```

### 4.14 Global Search Defaults

Apply this at the top level of the dashboard definition so all `ds.search` data sources inherit the global time range:

```json
{
  "defaults": {
    "dataSources": {
      "ds.search": {
        "options": {
          "queryParameters": {
            "earliest": "$global_time.earliest$",
            "latest": "$global_time.latest$"
          }
        }
      }
    }
  }
}
```

---

## 5. Dashboard Templates

### 5.1 Discovery Template

Purpose: Broad exploration of a domain (SOC, network, cloud, etc.).

**Structure (top to bottom):**

1. **Inputs row** -- Time range + Location + Scenario filter
2. **KPI row** -- 4 single values with sparklines (total events, unique hosts, unique users, scenario events)
3. **Primary chart** -- Full-width stacked area chart (event timeline by sourcetype)
4. **Secondary charts** -- 2-3 column layout mixing donut, bar, and column charts
5. **Detail table** -- Full-width table with row coloring and drilldown

**SPL patterns for discovery dashboards:**
```spl
-- KPI total events
| tstats count WHERE index=fake_tshrt BY _time span=1h

-- Timeline by sourcetype
| tstats count WHERE index=fake_tshrt BY _time, sourcetype span=1h

-- Scenario breakdown
index=fake_tshrt demo_id=* | stats count by demo_id
```

### 5.2 Scenario Template

Purpose: Walk through a specific scenario phase by phase.

**Structure:**

1. **Inputs row** -- Time range only (scenario is fixed by the dashboard)
2. **Scenario header** -- Markdown panel with scenario name, duration, severity, `demo_id` value, and a brief description
3. **Phase-by-phase sections** -- Each phase gets a markdown header, a timeline chart, and key evidence panels
4. **Cross-source correlation timeline** -- Full-width area or line chart showing events across all affected sourcetypes
5. **Key evidence table** -- Full-width table of notable events with timestamps, source, and description

**SPL patterns for scenario dashboards:**
```spl
-- All events for a scenario
index=fake_tshrt demo_id=exfil | timechart count by sourcetype

-- Phase timeline
index=fake_tshrt demo_id=exfil
| eval phase=case(
    _time < relative_time(now(), "-10d"), "Reconnaissance",
    _time < relative_time(now(), "-7d"), "Initial Access",
    _time < relative_time(now(), "-4d"), "Lateral Movement",
    true(), "Exfiltration")
| timechart count by phase
```

### 5.3 Source Template

Purpose: Deep dive into a single data source.

**Structure:**

1. **Inputs row** -- Time range
2. **Source info header** -- Markdown with sourcetype name, format description, and TA reference
3. **KPI row** -- Total events, unique hosts, unique users (3 single values)
4. **Event volume over time** -- Area chart by host or event type
5. **Key field breakdowns** -- 2-3 columns with donut/bar charts for top field values
6. **Ingestion guide** -- Markdown panel with `props.conf` and `transforms.conf` guidance

### 5.4 Overview Template

Purpose: Landing page for the entire app.

**Structure:**

1. **App header** -- Markdown with branding and description
2. **KPI row** -- Total events, active sourcetypes, scenario count, scenario event count (4 single values)
3. **Event distribution** -- Area chart + donut chart side by side
4. **Scenario summary table** -- Table listing all 7 scenarios with status, duration, and event counts
5. **Data source catalog table** -- Table listing all sourcetypes with event counts and sample hosts
6. **Quick navigation links** -- Markdown panel with links to discovery, scenario, and source dashboards

---

## 6. Scenario Color Map (JSON snippet)

For use in `seriesColorsByField` on any chart showing scenarios:

```json
"seriesColorsByField": {
  "exfil": "#DC4E41",
  "ransomware_attempt": "#F1813F",
  "memory_leak": "#F8BE34",
  "cpu_runaway": "#FF677B",
  "disk_filling": "#7B56DB",
  "firewall_misconfig": "#009CEB",
  "certificate_expiry": "#00CDAF"
}
```

This mapping is **immutable**. Every dashboard that displays scenario data MUST use these exact color assignments.

---

## 7. Data Index Reference

| Property | Value |
|----------|-------|
| **Index** | `fake_tshrt` |
| **Sourcetype prefix** | `FAKE:` |
| **Default epoch range** | `1767225600` to `1769904000` (Jan 1 -- Feb 1, 2026) |
| **Total events** | ~11.2M |
| **Total sourcetypes** | 40 |
| **Total hosts** | 511 |
| **Scenarios** | 7 (tagged with `demo_id` field) |

### Sourcetype Quick Reference

| Category | Sourcetypes |
|----------|-------------|
| Network | `FAKE:cisco:asa`, `FAKE:meraki:mx`, `FAKE:meraki:mr`, `FAKE:meraki:ms`, `FAKE:meraki:mv`, `FAKE:meraki:mt` |
| Cloud | `FAKE:aws:cloudtrail`, `FAKE:google:gcp:pubsub:message`, `FAKE:azure:aad:signin`, `FAKE:azure:aad:audit` |
| Collaboration | `FAKE:cisco:webex:events`, `FAKE:cisco:webex:meetings:history:*`, `FAKE:cisco:webex:*` |
| Email | `FAKE:ms:o365:reporting:messagetrace` |
| Audit | `FAKE:o365:management:activity` |
| Windows | `FAKE:perfmon`, `FAKE:WinEventLog`, `FAKE:WinEventLog:Sysmon` |
| Linux | `FAKE:linux:*` |
| Web/Retail | `FAKE:access_combined`, `FAKE:retail:orders`, `FAKE:azure:servicebus` |
| ITSM | `FAKE:servicenow:incident` |

---

## 8. Checklist for New Dashboards

Before submitting any new dashboard, verify the following:

- [ ] All colors match this specification (no ad-hoc hex values).
- [ ] Scenario colors use the immutable mapping from Section 6.
- [ ] Location colors use the mapping from Section 1.
- [ ] Chart series use the palette from Section 1 when not field-mapped.
- [ ] All IDs use `snake_case` (no hyphens).
- [ ] All data sources have a `name` property.
- [ ] All visualizations appear in `layout.structure`.
- [ ] Grid layout has no `options`, `width`, `height`, `backgroundColor`, or `display`.
- [ ] Default time range uses epochs `1767225600` to `1769904000`.
- [ ] Index is `fake_tshrt` in all searches.
- [ ] Sourcetypes use the `FAKE:` prefix.
- [ ] **No problematic Unicode** in dashboard JSON (emojis OK, but no em-dashes/arrows/middle dots -- use ASCII `--`, `->`, `|`).
- [ ] Dashboard filename follows naming conventions from Section 3.
- [ ] Dashboard title follows naming conventions from Section 3.
