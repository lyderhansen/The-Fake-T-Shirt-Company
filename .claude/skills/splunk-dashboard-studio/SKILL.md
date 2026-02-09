---
name: splunk-dashboard-studio
description: Use this skill when the user wants to create, edit, or generate Splunk Dashboard Studio dashboards (JSON-based, version 2). Triggers include any mention of "Dashboard Studio", "Splunk dashboard", "splunk.pie", "splunk.table", "splunk.singlevalue", "splunk.timeline", "splunk.parallelcoordinates", or requests to build Splunk visualizations, security dashboards, monitoring dashboards, or SOC dashboards. Also use when converting Simple XML dashboards to Dashboard Studio format, or when generating dashboard JSON definitions programmatically. Do NOT use for Classic Simple XML dashboards (version 1), Splunk Observability Cloud dashboards, or AppDynamics dashboards.
---

# Splunk Dashboard Studio — Skill Reference

This skill enables Claude to generate complete, valid Splunk Dashboard Studio dashboard definitions (JSON). All output is the JSON definition that goes inside the `<definition><![CDATA[ ... ]]></definition>` block of a Dashboard Studio `.xml` file.

---

## 1. Dashboard Definition Structure

A Dashboard Studio dashboard definition is a JSON object with these top-level keys:

```json
{
  "title": "My Dashboard",
  "description": "Optional description",
  "dataSources": {},
  "visualizations": {},
  "inputs": {},
  "defaults": {},
  "layout": {}
}
```

### 1.1 XML Envelope (for file deployment)

The JSON definition is wrapped in an XML envelope when saved as a `.xml` file:

```xml
<dashboard version="2" theme="dark">
  <label>My Dashboard</label>
  <description>Optional description</description>
  <definition><![CDATA[
    { ... JSON definition ... }
  ]]></definition>
</dashboard>
```

- `version="2"` marks it as Dashboard Studio (not classic Simple XML).
- `theme` can be `"light"` or `"dark"`.
- The JSON definition goes inside `<![CDATA[ ... ]]>`.

---

## 2. Data Sources (`dataSources`)

### 2.1 ds.search — SPL Search

> **IMPORTANT:** Every `ds.search` data source MUST include a `name` property. This is the human-readable name shown in the Dashboard Studio UI. Without it, searches may not display correctly in the visual editor. Use descriptive names like `"Failed Logins by Source"` rather than generic ones like `"Search_1"`.

```json
"dataSources": {
  "ds_search1": {
    "type": "ds.search",
    "name": "Events by Sourcetype",
    "options": {
      "query": "index=_internal | stats count by sourcetype",
      "queryParameters": {
        "earliest": "$global_time.earliest$",
        "latest": "$global_time.latest$"
      }
    }
  }
}
```

**Key options for ds.search:**

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | **YES** | Human-readable name shown in UI |
| `query` | string | YES | SPL query (use `\n` for newlines) |
| `queryParameters.earliest` | string | No | Earliest time (absolute or token) |
| `queryParameters.latest` | string | No | Latest time (absolute or token) |
| `refresh` | string | No | Auto-refresh interval, e.g. `"10s"`, `"1m"` |
| `refreshType` | string | No | `"delay"` (after completion) or `"interval"` (fixed) |

### 2.2 ds.chain — Chain Search (Post-process)

Chain searches reference a parent data source and apply additional SPL. They also require a `name`:

```json
"ds_chain1": {
  "type": "ds.chain",
  "name": "High Count Filter",
  "options": {
    "extend": "ds_search1",
    "query": "| where count > 100"
  }
}
```

### 2.3 ds.test — Mock Data (for prototyping)

```json
"ds_test1": {
  "type": "ds.test",
  "name": "Mock Category Data",
  "options": {
    "data": {
      "fields": [
        {"name": "category", "type": "string"},
        {"name": "count", "type": "number"}
      ],
      "columns": [
        ["web", "api", "db"],
        [120, 85, 45]
      ]
    }
  }
}
```

### 2.4 ds.savedSearch — Saved/Report Search

```json
"ds_saved1": {
  "type": "ds.savedSearch",
  "name": "My Saved Search",
  "options": {
    "ref": "my_saved_search_name"
  }
}
```

### 2.5 Base Search + Chain Pattern

A common pattern is one base search feeding multiple chain searches:

```json
"dataSources": {
  "ds_base": {
    "type": "ds.search",
    "name": "Firewall Base Search",
    "options": {
      "query": "index=firewall | stats count by src_ip, action, dest_port"
    }
  },
  "ds_allowed": {
    "type": "ds.chain",
    "name": "Allowed Traffic Top 10",
    "options": {
      "extend": "ds_base",
      "query": "| where action=\"allowed\" | sort -count | head 10"
    }
  },
  "ds_blocked": {
    "type": "ds.chain",
    "name": "Blocked Traffic Top 10",
    "options": {
      "extend": "ds_base",
      "query": "| where action=\"blocked\" | sort -count | head 10"
    }
  }
}
```

---

## 3. Visualization Types (`visualizations`)

Every visualization follows this structure:

```json
"viz_uniqueId": {
  "type": "splunk.<viztype>",
  "title": "Optional Title",
  "description": "Optional description",
  "dataSources": {
    "primary": "ds_search1"
  },
  "options": {},
  "context": {},
  "showProgressBar": false,
  "showLastUpdated": false,
  "eventHandlers": []
}
```

### 3.1 Complete Visualization Type Reference

#### Charts

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.line` | Line chart (time series) | `seriesColors`, `legendDisplay`, `yAxisTitleText`, `xAxisTitleText`, `stackMode`, `nullValueDisplay`, `lineDashStyle`, `markerDisplay` |
| `splunk.area` | Area chart | Same as line + `areaOpacity`, `showLines` |
| `splunk.column` | Vertical bar chart | `stackMode` (`stacked`, `stacked100`), `seriesColors`, `legendDisplay`, `dataValuesDisplay`, `columnSpacing`, `columnGrouping` |
| `splunk.bar` | Horizontal bar chart | Same as column + `barSpacing`, `legendReversed` |
| `splunk.pie` | Pie chart | `labelDisplay` (`valuesAndPercentage`, `values`, `percentage`, `off`), `showDonutHole` |
| `splunk.scatter` | Scatter plot | `seriesColors`, `legendDisplay`, `markerDisplay` |
| `splunk.bubble` | Bubble chart | `categoryField`, `sizeField`, `bubbleSizeMax`, `bubbleSizeMin`, `bubbleSizeMethod` (`area`, `diameter`) |
| `splunk.punchcard` | Punchcard chart | `seriesColors` |
| `splunk.parallelcoordinates` | Parallel coordinates | `seriesColors`, `legendDisplay`, `backgroundColor`, `lineOpacity` |
| `splunk.timeline` | Timeline (event lanes) | `category`, `seriesColors`, `legendDisplay`, `backgroundColor`, `dataColors` |

#### Single Value

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.singlevalue` | Single value with sparkline | `majorValue`, `trendValue`, `sparklineValues`, `sparklineDisplay`, `trendDisplay`, `unit`, `unitPosition`, `majorColor`, `trendColor`, `backgroundColor`, `sparklineStrokeColor` |
| `splunk.singlevalueicon` | Single value with icon | Same as singlevalue + `icon`, `iconColor`, `iconPosition` |
| `splunk.singlevalueradial` | Radial gauge single value | Same as singlevalue + `radialStrokeColor`, `radialBackgroundColor`, `gaugeRanges` |

#### Tables & Events

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.table` | Data table | `columnFormat`, `tableFormat`, `count`, `dataOverlayMode`, `showRowNumbers`, `showInternalFields` |
| `splunk.events` | Events viewer | `type` (`list`, `table`, `raw`), `fields`, `rowNumbers` |

#### Maps

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.map` | Cluster map (marker/bubble) | `center`, `zoom`, `layers` (array of layer objects), `baseLayerTileServer`, `baseLayerTileServerType`, `scaleUnit` |
| `splunk.choropleth.map` | Geographic choropleth map | `source` (`geo://default/world`, `geo://default/us`), `projection` (`mercator`, `equirectangular`), `fillColor`, `strokeColor` |
| `splunk.choropleth.svg` | SVG choropleth | `svg`, `areaIds`, `areaValues`, `areaColors` |

#### Gauges

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.fillergauge` | Filler/progress gauge | `gaugeColor`, `backgroundColor`, `orientation` (`vertical`, `horizontal`), `labelDisplay`, `valueDisplay`, `majorTickInterval` |
| `splunk.markergauge` | Marker gauge | `gaugeRanges` (array: `[{"from":0,"to":50,"value":"#green"},...]`), `orientation`, `labelDisplay`, `valueDisplay` |

#### Diagram & Flow

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.sankey` | Sankey diagram (flow) | `linkColorMode`, `linkColor` |
| `splunk.linkgraph` | Link/node graph | `fieldOrder`, `nodeColor`, `nodeHighlightColor`, `nodeWidth`, `nodeHeight`, `nodeSpacingX`, `nodeSpacingY`, `linkColor`, `showNodeCounts`, `showValueCounts` |

#### Layout & Decoration

| Type | Description | Key Options |
|------|-------------|-------------|
| `splunk.markdown` | Markdown text block | `markdown`, `fontColor`, `fontSize` (`extraSmall`, `small`, `default`, `large`, `extraLarge`), `customFontSize`, `fontFamily`, `backgroundColor`, `rotation` |
| `splunk.image` | Image display | `src`, `preserveAspectRatio` |
| `splunk.rectangle` | Rectangle shape | `fillColor`, `fillOpacity`, `strokeColor`, `strokeWidth`, `strokeDashStyle`, `strokeOpacity`, `cornerRadius` |
| `splunk.ellipse` | Ellipse shape | `fillColor`, `fillOpacity`, `strokeColor`, `strokeWidth`, `strokeDashStyle`, `strokeOpacity` |
| `splunk.line` (shape) | Line shape | `strokeColor`, `strokeWidth`, `strokeDasharray`, `strokeOpacity`, `toArrow`, `fromArrow` |
| `splunk.icon` | Icon element | `icon`, `color` |

#### Trellis

Any chart type can be rendered as a trellis layout by adding the `trellis` wrapper options.

---

### 3.2 Common Chart Options

These options apply to most chart types (line, area, column, bar, scatter, bubble):

```json
"options": {
  "backgroundColor": "#1a1a2e",
  "seriesColors": ["#00d2ff", "#ff6384", "#36a2eb", "#ffce56"],
  "seriesColorsByField": {"allowed": "#00ff00", "blocked": "#ff0000"},
  "legendDisplay": "right",
  "legendMode": "seriesCompare",
  "legendTruncation": "ellipsisEnd",
  "xAxisTitleText": "Time",
  "yAxisTitleText": "Count",
  "xAxisTitleVisibility": "show",
  "yAxisTitleVisibility": "show",
  "xAxisLabelRotation": -45,
  "xAxisLabelVisibility": "show",
  "yAxisLabelVisibility": "show",
  "yAxisScale": "linear",
  "yAxisAbbreviation": "auto",
  "stackMode": "stacked",
  "nullValueDisplay": "connect",
  "dataValuesDisplay": "all",
  "resultLimit": 50000,
  "showSplitSeries": false,
  "showIndependentYRanges": false
}
```

**stackMode values:** `"auto"` (default) | `"stacked"` | `"stacked100"`

**nullValueDisplay values:** `"gaps"` (default) | `"zero"` | `"connect"`

**legendDisplay values:** `"right"` (default) | `"left"` | `"top"` | `"bottom"` | `"off"`

**legendMode values:** `"standard"` (default) | `"seriesCompare"` (useful for comparing series)

#### Line-Specific Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `lineDashStyle` | string | `"solid"` | Dash style: `"solid"`, `"dash"`, `"dot"`, `"shortDash"`, `"longDash"`, `"dashDot"`, `"longDashDot"`, `"longDashDotDot"` |
| `lineDashStylesByField` | object | — | Per-field dash styles, e.g. `{"count": "dash", "avg": "dot"}` |
| `lineWidth` | number | `2` | Line width in pixels |
| `markerDisplay` | string | `"off"` | Data point markers: `"off"`, `"filled"`, `"outlined"` |
| `additionalTooltipFields` | string[] | `[]` | Extra fields shown in tooltips on hover |

#### Area-Specific Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `areaOpacity` | number | `0.75` | Area fill opacity (0–1) |
| `showLines` | boolean | `true` | Show lines on top of areas |

#### Annotation Options (Line, Area, Column)

| Option | Type | Description |
|--------|------|-------------|
| `annotationX` | string/number | Data source field for annotation x-position |
| `annotationLabel` | string | Label array, e.g. `["Event A", "Event B"]` |
| `annotationColor` | string | Color array, e.g. `["#FF0000", "#00FF00"]` |

#### Y2-Axis & Overlay Options (Line, Area, Column, Bar)

| Option | Type | Description |
|--------|------|-------------|
| `y2` | string | Data source for y2-axis |
| `y2Fields` | array/string | Fields mapped to y2-axis |
| `y2AxisTitleText` | string | Title for y2-axis |
| `overlayFields` | array/string | Fields shown as chart overlays |
| `showOverlayY2Axis` | boolean | Map overlay fields to y2-axis |

#### Default Color Palette (20 colors)

```
#7B56DB, #009CEB, #00CDAF, #DD9900, #FF677B,
#CB2196, #813193, #0051B5, #008C80, #99B100,
#FFA476, #FF6ACE, #AE8CFF, #00689D, #00490A,
#465D00, #9D6300, #F6540B, #FF969E, #E47BFE
```

#### Parallel Coordinates Options (`splunk.parallelcoordinates`)

Visualizes multidimensional patterns across vertical axes. Lines representing events connect dimensions.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backgroundColor` | string | theme default | Background color |
| `seriesColors` | string[] | default palette | Colors for lines |
| `lineOpacity` | number | — | Opacity of lines (0–1) |
| `legendDisplay` | string | `"right"` | Legend position |

**Data format:** Use `| stats count by <dim1>, <dim2>, ... <dimN> | fields - count`. Keep under 15 dimensions.

```json
"viz_parallel": {
  "type": "splunk.parallelcoordinates",
  "title": "Nutrient Comparison",
  "dataSources": { "primary": "ds_nutrients" },
  "options": {}
}
```

#### Timeline Options (`splunk.timeline`)

Shows events and activity intervals on horizontal lanes. Each resource gets its own lane.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `category` | string | — | DOS expression for category field, e.g. `"> primary \| seriesByName('attack_type')"` |
| `seriesColors` | string[] | default palette | Colors for event categories |
| `legendDisplay` | string | `"right"` | Legend position |
| `backgroundColor` | string | `"transparent"` | Background color |
| `dataColors` | string | — | Data-driven colors (use with `context.dataColorConfig` ranges) |

**Data format:** `| table _time <resource_field> [<color_field>] [<duration_field>]`

```json
"viz_timeline": {
  "type": "splunk.timeline",
  "title": "Attack Types Over Time",
  "dataSources": { "primary": "ds_attacks" },
  "options": {
    "category": "> primary | seriesByName('attack_type')",
    "legendDisplay": "right",
    "backgroundColor": "transparent",
    "seriesColors": ["#7B56DB", "#009CEB", "#00CDAF", "#DD9900", "#FF677B"]
  },
  "context": {
    "dataColorConfig": [
      {"to": 20, "value": "#D41F1F"},
      {"from": 20, "to": 50, "value": "#F4DF7A"},
      {"from": 50, "value": "#669922"}
    ]
  }
}
```

---

### 3.3 Single Value — Full Example

```json
"viz_singlevalue": {
  "type": "splunk.singlevalue",
  "title": "Total Events",
  "dataSources": {
    "primary": "ds_count"
  },
  "options": {
    "majorValue": "> sparklineValues | lastPoint()",
    "trendValue": "> sparklineValues | delta(-2)",
    "sparklineValues": "> primary | seriesByName('count')",
    "sparklineDisplay": "below",
    "trendDisplay": "percent",
    "unit": "events",
    "unitPosition": "after",
    "majorColor": "> majorValue | rangeValue(majorColorConfig)",
    "trendColor": "> trendValue | rangeValue(trendColorConfig)",
    "backgroundColor": "transparent",
    "showSparklineAreaGraph": true,
    "sparklineStrokeColor": "> trendColor"
  },
  "context": {
    "majorColorConfig": [
      {"value": "#DC4E41", "to": 100},
      {"value": "#F8BE34", "from": 100, "to": 500},
      {"value": "#53A051", "from": 500}
    ],
    "trendColorConfig": [
      {"value": "#DC4E41", "to": 0},
      {"value": "#53A051", "from": 0}
    ]
  }
}
```

### 3.4 Table — Column Formatting Example

```json
"viz_table": {
  "type": "splunk.table",
  "title": "Security Events",
  "dataSources": {
    "primary": "ds_events"
  },
  "options": {
    "count": 20,
    "showRowNumbers": true,
    "columnFormat": {
      "severity": {
        "rowBackgroundColors": "> table | seriesByName(\"severity\") | matchValue(severityColors)",
        "rowColors": "#ffffff"
      },
      "count": {
        "rowBackgroundColors": "> table | seriesByName(\"count\") | rangeValue(countColors)",
        "data": "> table | seriesByName(\"count\") | formatByType(countFormat)"
      },
      "sparkline": {
        "sparklineDisplay": "area",
        "sparklineColors": "> table | seriesByName('sparkline') | pick(sparklineColor)",
        "sparklineAreaColors": "> sparklineColors"
      }
    }
  },
  "context": {
    "severityColors": [
      {"match": "critical", "value": "#DC4E41"},
      {"match": "high", "value": "#F1813F"},
      {"match": "medium", "value": "#F8BE34"},
      {"match": "low", "value": "#53A051"},
      {"match": "info", "value": "#5794DE"}
    ],
    "countColors": [
      {"value": "#53A051", "to": 50},
      {"value": "#F8BE34", "from": 50, "to": 200},
      {"value": "#DC4E41", "from": 200}
    ],
    "countFormat": {
      "number": {"thousandSeparated": true, "precision": 0}
    },
    "sparklineColor": ["#7B56DB"]
  }
}
```

### 3.5 Map — Marker & Bubble Layers

```json
"viz_map": {
  "type": "splunk.map",
  "title": "Global Attack Origins",
  "dataSources": {
    "primary": "ds_geo"
  },
  "options": {
    "center": [20, 0],
    "zoom": 2,
    "layers": [
      {
        "type": "marker",
        "latitude": "> primary | seriesByName(\"lat\")",
        "longitude": "> primary | seriesByName(\"lon\")",
        "description": "> primary | seriesByName(\"src_ip\")",
        "dataColors": "> primary | seriesByName(\"count\") | rangeValue(markerColors)"
      }
    ]
  },
  "context": {
    "markerColors": [
      {"value": "#53A051", "to": 100},
      {"value": "#F8BE34", "from": 100, "to": 1000},
      {"value": "#DC4E41", "from": 1000}
    ]
  }
}
```

For **bubble maps**, the SPL uses `geostats`:

```json
{
  "type": "bubble",
  "latitude": "> primary | seriesByName(\"latitude\")",
  "longitude": "> primary | seriesByName(\"longitude\")"
}
```

### 3.6 Sankey Diagram

```json
"viz_sankey": {
  "type": "splunk.sankey",
  "title": "Network Traffic Flow",
  "dataSources": {
    "primary": "ds_flow"
  },
  "options": {
    "linkColorMode": "source"
  }
}
```

SPL must produce exactly 3 columns: `source`, `target`, `value`:
```
| stats sum(bytes) as value by src_zone, dest_zone
| rename src_zone as source, dest_zone as target
```

### 3.7 Choropleth SVG

```json
"viz_choropleth": {
  "type": "splunk.choropleth.svg",
  "title": "Regional Activity",
  "dataSources": {
    "primary": "ds_regions"
  },
  "options": {
    "svg": "<svg>...</svg>",
    "areaIds": "> primary | seriesByType('string')",
    "areaValues": "> primary | seriesByType('number')"
  }
}
```

### 3.8 Choropleth Map (Geographic)

```json
"viz_world_map": {
  "type": "splunk.choropleth.map",
  "title": "Events by Country",
  "dataSources": {
    "primary": "ds_geo"
  },
  "options": {
    "source": "geo://default/world",
    "projection": "mercator",
    "fillColor": "#EAEFF2",
    "strokeColor": "#689C8D"
  }
}
```

Sources: `"geo://default/world"` or `"geo://default/us"`. Projections: `"mercator"` or `"equirectangular"`.
```

---

## 4. Inputs (`inputs`)

### 4.1 Available Input Types

| Type | Description | Key Options |
|------|-------------|-------------|
| `input.timerange` | Time range picker | `token`, `defaultValue` |
| `input.dropdown` | Dropdown selector | `token`, `items` (static or DOS-generated), `defaultValue` |
| `input.multiselect` | Multi-select | `token`, `items`, `defaultValue` |
| `input.text` | Text input | `token`, `defaultValue` |
| `input.checkbox` | Checkbox group | `token`, `items` |
| `input.link` | Link/tab selector | `token`, `items` |

### 4.2 Global Time Range (always include)

```json
"inputs": {
  "input_global_trp": {
    "type": "input.timerange",
    "title": "Global Time Range",
    "options": {
      "token": "global_time",
      "defaultValue": "-24h@h,now"
    }
  }
}
```

### 4.3 Dropdown — Static Items

```json
"input_severity": {
  "type": "input.dropdown",
  "title": "Severity",
  "options": {
    "token": "severity_filter",
    "defaultValue": "*",
    "items": [
      {"label": "All", "value": "*"},
      {"label": "Critical", "value": "critical"},
      {"label": "High", "value": "high"},
      {"label": "Medium", "value": "medium"},
      {"label": "Low", "value": "low"}
    ]
  }
}
```

### 4.4 Dropdown — Dynamic (search-populated)

```json
"input_host": {
  "type": "input.dropdown",
  "title": "Host",
  "options": {
    "token": "host_filter",
    "defaultValue": "*",
    "items": "> frame(label, value) | prepend(prependItems)",
    "staticItems": "> prependItems"
  },
  "dataSources": {
    "primary": "ds_hosts"
  },
  "context": {
    "prependItems": [
      {"label": "All", "value": "*"}
    ]
  }
}
```

### 4.5 Multiselect Input

```json
"input_status": {
  "type": "input.multiselect",
  "title": "Status Codes",
  "options": {
    "token": "status",
    "items": "> frame(label, value) | prepend(prependItems)",
    "defaultValue": "*"
  },
  "dataSources": {
    "primary": "ds_statuses"
  },
  "context": {
    "prependItems": [
      {"label": "All", "value": "*"}
    ]
  }
}
```

### 4.6 Text Input

```json
"input_search_text": {
  "type": "input.text",
  "title": "Search Filter",
  "options": {
    "token": "search_text",
    "defaultValue": "*"
  }
}
```

---

## 5. Defaults (`defaults`)

The `defaults` section sets global defaults for data sources and tokens:

```json
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
  },
  "tokens": {
    "default": {
      "method": {
        "value": "POST"
      }
    }
  },
  "visualizations": {
    "splunk.table": {
      "options": {
        "count": 20
      }
    }
  }
}
```

This applies time range tokens to ALL `ds.search` data sources globally, avoiding repetition.

---

## 6. Layout (`layout`)

### 6.1 Absolute Layout (pixel-perfect)

```json
"layout": {
  "type": "absolute",
  "options": {
    "width": 1440,
    "height": 960,
    "display": "auto-scale",
    "backgroundColor": "#0B0C10",
    "backgroundImage": {
      "src": "",
      "sizeType": "cover",
      "x": 0,
      "y": 0
    },
    "showTitleAndDescription": true,
    "submitButton": false
  },
  "globalInputs": ["input_global_trp"],
  "structure": [
    {
      "item": "viz_header",
      "type": "block",
      "position": {"x": 0, "y": 0, "w": 1440, "h": 60}
    },
    {
      "item": "viz_singlevalue1",
      "type": "block",
      "position": {"x": 20, "y": 80, "w": 340, "h": 120}
    }
  ]
}
```

**display values:** `"auto-scale"` | `"actual-size"`

### 6.2 Grid Layout (responsive, auto-sized)

> **IMPORTANT:** Every visualization defined in the `visualizations` section **MUST** have a corresponding entry in `layout.structure`. If a visualization is missing from `structure`, it will not render. This is the most common cause of panels not appearing — especially for multi-row dashboards where it's easy to forget a panel.

> **CRITICAL — NO `options` block for grid layout.** Grid layout definitions must have ONLY `type` and `structure`. Do NOT add `width`, `height`, `backgroundColor`, `display`, or `gutterSize` — these are absolute-layout-only properties. Adding an `options` block to a grid layout causes only the first row of panels to render.

```json
"layout": {
  "type": "grid",
  "globalInputs": ["input_global_trp"],
  "structure": [
    {"item": "viz_chart1", "type": "block", "position": {"x": 0, "y": 0, "w": 600, "h": 300}},
    {"item": "viz_chart2", "type": "block", "position": {"x": 600, "y": 0, "w": 600, "h": 300}},
    {"item": "viz_chart3", "type": "block", "position": {"x": 0, "y": 300, "w": 1200, "h": 400}}
  ]
}
```

**Structure rules:**
- Every `viz_*` panel needs a `{"item": "viz_xxx", "type": "block", "position": {...}}` entry
- Grid width is always 1200. Common splits: 2 columns = 600+600, 3 columns = 400+400+400, 4 columns = 300+300+300+300
- **Y-values must be cumulative** — each row's y = previous row's y + previous row's h (no gaps). Example: row 1 at y=0 h=300, row 2 must start at y=300, not y=310
- Grid is always auto-sized vertically — do NOT set a total height

### 6.3 Tabbed Layout

```json
"layout": {
  "globalInputs": ["input_global_trp"],
  "tabs": {
    "items": [
      {"layoutId": "layout_overview", "label": "Overview"},
      {"layoutId": "layout_details", "label": "Details"},
      {"layoutId": "layout_threats", "label": "Threats"}
    ],
    "options": {
      "barPosition": "top",
      "showTabBar": true
    }
  },
  "layoutDefinitions": {
    "layout_overview": {
      "type": "grid",
      "structure": [
        {"item": "viz_1", "type": "block", "position": {"x": 0, "y": 0, "w": 1200, "h": 300}}
      ]
    },
    "layout_details": {
      "type": "grid",
      "structure": [
        {"item": "viz_2", "type": "block", "position": {"x": 0, "y": 0, "w": 1200, "h": 400}}
      ]
    }
  }
}
```

### 6.4 Line Connections (absolute layout only)

```json
{
  "item": "viz_line1",
  "type": "line",
  "position": {
    "from": {"item": "viz_box1", "port": "s"},
    "to": {"item": "viz_box2", "port": "n"}
  }
}
```

Ports: `"n"` (north), `"s"` (south), `"e"` (east), `"w"` (west)

---

## 7. Dynamic Options Syntax (DOS)

DOS is the expression language used in Dashboard Studio to dynamically configure visualization options based on data.

### 7.1 DOS Structure

```
"> <data_source> | <selector> | <formatter>"
```

Every DOS expression starts with `>` and uses pipes `|` to chain operations. The data source can be `primary`, `table`, or a reference to another option.

### 7.2 Selector Functions (pick data)

| Selector | Level | Description |
|----------|-------|-------------|
| `seriesByName("field")` | DataFrame → DataSeries | Select a column by name |
| `seriesByIndex(n)` | DataFrame → DataSeries | Select a column by index |
| `seriesByPrioritizedTypes("number","string")` | DataFrame | Select first column matching type |
| `firstPoint()` | DataSeries → DataPoint | First value in series |
| `lastPoint()` | DataSeries → DataPoint | Last value in series |
| `pointByIndex(n)` | DataSeries → DataPoint | Value at index n |
| `delta(n)` | DataSeries → DataPoint | Difference between last n points |
| `getField()` | DataPoint → string | Get field name |
| `getType()` | DataPoint → string | Get data type |
| `getValue()` | DataPoint → value | Get value |
| `pick(contextVar)` | any | Pick value from context |
| `frame(label, value)` | DataFrame | Create label/value pairs for inputs |

### 7.3 Formatting Functions (transform data)

| Formatter | Description | Example |
|-----------|-------------|---------|
| `rangeValue(config)` | Map numeric ranges to values (colors) | `rangeValue(colorConfig)` |
| `matchValue(config)` | Map exact string matches to values | `matchValue(severityColors)` |
| `formatByType(config)` | Format by data type (number, string) | `formatByType(numFormat)` |
| `prefix("str")` | Add prefix to each value | `prefix("$")` |
| `suffix("str")` | Add suffix to each value | `suffix(" ms")` |
| `prepend(items)` | Prepend items to a list | `prepend(staticItems)` |
| `multiFormat(config)` | Apply different formatters to columns | |
| `type()` | Return data type of each element | |

### 7.4 Context — Configuration Store

The `context` section of a visualization stores configuration objects used by DOS formatters:

```json
"context": {
  "colorConfig": [
    {"value": "#DC4E41", "to": 50},
    {"value": "#F8BE34", "from": 50, "to": 200},
    {"value": "#53A051", "from": 200}
  ],
  "matchConfig": [
    {"match": "error", "value": "#DC4E41"},
    {"match": "warning", "value": "#F8BE34"},
    {"match": "info", "value": "#53A051"}
  ]
}
```

### 7.5 Escaping in DOS

- Strings inside DOS use escaped quotes: `\"field_name\"`
- Single quotes also work: `'field_name'`
- Backslashes in strings need double escaping: `\\`

---

## 8. Interactions (Drilldown & Tokens)

### 8.1 Setting Tokens on Click (drilldown.setToken)

```json
"eventHandlers": [
  {
    "type": "drilldown.setToken",
    "options": {
      "tokens": [
        {
          "token": "selected_host",
          "key": "row.host.value"
        }
      ]
    }
  }
]
```

**Token key syntax:**
- `row.<field>.value` — value of clicked field in row
- `row._hidden.value` — value of hidden fields (prefixed with `_`)

### 8.2 Link to URL

```json
"eventHandlers": [
  {
    "type": "drilldown.customUrl",
    "options": {
      "url": "/app/search/target_dashboard?form.host=$selected_host|u$",
      "newTab": true
    }
  }
]
```

### 8.3 Link to Dashboard

```json
"eventHandlers": [
  {
    "type": "drilldown.linkToDashboard",
    "options": {
      "app": "search",
      "dashboard": "detail_view",
      "newTab": true,
      "tokens": {
        "form.src_ip": "$row.src_ip.value$"
      }
    }
  }
]
```

### 8.4 Link to Search

```json
"eventHandlers": [
  {
    "type": "drilldown.linkToSearch",
    "options": {
      "query": "index=main host=$row.host.value$",
      "earliest": "$global_time.earliest$",
      "latest": "$global_time.latest$",
      "newTab": true
    }
  }
]
```

### 8.5 Conditional Visibility

Visualizations can be shown/hidden based on token values using `encoding`:

```json
"encoding": {
  "drilldown": {
    "token": "show_details"
  }
}
```

### 8.6 Token Filters

Use `|u` for URL encoding, `|n` for no encoding, `|s` for search filter:
```
$token|u$   — URL encoded
$token|n$   — Raw (no encoding)
$token|s$   — Search filter safe
```

---

## 9. Standard Patterns & Templates

### 9.1 Minimal Dashboard Skeleton

```json
{
  "title": "Dashboard Title",
  "description": "",
  "dataSources": {
    "ds_search1": {
      "type": "ds.search",
      "name": "Events by Sourcetype",
      "options": {
        "query": "index=_internal | stats count by sourcetype"
      }
    }
  },
  "visualizations": {
    "viz_chart1": {
      "type": "splunk.column",
      "dataSources": {"primary": "ds_search1"},
      "title": "Events by Sourcetype"
    }
  },
  "inputs": {
    "input_global_trp": {
      "type": "input.timerange",
      "title": "Global Time Range",
      "options": {
        "token": "global_time",
        "defaultValue": "-24h@h,now"
      }
    }
  },
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
  },
  "layout": {
    "type": "grid",
    "options": {"width": 1200},
    "globalInputs": ["input_global_trp"],
    "structure": [
      {
        "item": "viz_chart1",
        "type": "block",
        "position": {"x": 0, "y": 0, "w": 1200, "h": 400}
      }
    ]
  }
}
```

### 9.2 Security SOC Dashboard Pattern

A typical SOC overview dashboard includes:
1. **Row 1:** 3-4 single value KPIs (total events, alerts, critical alerts, avg response time)
2. **Row 2:** Timeline chart (events over time by severity) + Pie chart (by category)
3. **Row 3:** Table of recent alerts with severity coloring
4. **Inputs:** Global time range + severity dropdown + host filter

Layout grid positions for this pattern (width=1200):

| Viz | x | y | w | h |
|-----|---|---|---|---|
| SV1 | 0 | 0 | 300 | 120 |
| SV2 | 300 | 0 | 300 | 120 |
| SV3 | 600 | 0 | 300 | 120 |
| SV4 | 900 | 0 | 300 | 120 |
| Timeline | 0 | 120 | 800 | 300 |
| Pie | 800 | 120 | 400 | 300 |
| Table | 0 | 420 | 1200 | 400 |

### 9.3 Color Conventions (Dark Theme)

| Purpose | Color | Hex |
|---------|-------|-----|
| Critical/High/Error | Red | `#DC4E41` |
| Warning/Medium | Orange | `#F1813F` |
| Caution/Medium | Yellow | `#F8BE34` |
| OK/Low/Success | Green | `#53A051` |
| Info | Blue | `#5794DE` |
| Accent 1 | Cyan | `#00D2FF` |
| Accent 2 | Purple | `#7B56DB` |
| Background (dark) | Dark blue | `#0B0C10` |
| Panel background | Slightly lighter | `#171D29` |
| Text on dark | Light gray | `#C3CBD4` |

---

## 10. Best Practices

1. **Always include a global time range input** and wire it through `defaults.dataSources.ds.search.options.queryParameters`.
2. **Use base+chain searches** when multiple visualizations need variations of the same data — avoids redundant searching.
3. **Use `ds.test`** for prototyping layouts before wiring real searches.
4. **Grid layout** for quick responsive dashboards; **absolute layout** for pixel-perfect designs with backgrounds and shapes. When using either layout, ensure **every visualization has a matching entry in `layout.structure`** — missing entries cause panels to silently not render.
5. **Unique IDs:** Data source IDs start with `ds_`, visualization IDs with `viz_`, input IDs with `input_`.
6. **Name all searches:** Every `ds.search` and `ds.chain` MUST have a descriptive `name` property. Use meaningful names like `"Failed Logins by Host"` instead of `"Search_1"`.
7. **Validate JSON** before deploying — Dashboard Studio provides limited validation.
8. **Dark theme** (`theme="dark"`) is preferred for SOC/monitoring dashboards.
9. **10,000 result limit** per visualization — use `| head 10000` or appropriate aggregation.
10. **Escaped quotes in DOS:** Use `\"` inside DOS strings, e.g., `seriesByName(\"field\")`.
11. **Token syntax:** Always `$tokenName$` with dollar signs. For time range tokens: `$global_time.earliest$` and `$global_time.latest$`.
12. **Use `seriesColorsByField`** instead of `seriesColors` when you need stable per-field colors (e.g., `{"allowed": "#53A051", "blocked": "#DC4E41"}`).
13. **Use `nullValueDisplay: "connect"`** for time series with gaps to avoid misleading gaps or zeroes.
14. **Quote rules:** Strings and options need quotes. Booleans and numbers do NOT need quotes in JSON options.

---

## 11. Common SPL Patterns for Dashboard Studio

```spl
# Single value — total count
index=main | stats count

# Single value with sparkline — timechart
index=main | timechart count

# Table — top sources
index=main | stats count by src_ip, action | sort -count | head 20

# Pie chart — distribution
index=main | stats count by category

# Line chart — time series with split
index=main | timechart span=1h count by severity

# Map — geo data
index=main | iplocation src_ip | geostats latfield=lat longfield=lon count

# Sankey — flow between fields
index=main | stats count as value by src_zone, dest_zone
| rename src_zone as source, dest_zone as target

# Table with sparkline column
index=main | stats count, sparkline(count, 1h) as sparkline by host
```

---

## 12. Output Checklist

When generating a Dashboard Studio dashboard, verify:

- [ ] Valid JSON (no trailing commas, properly escaped strings)
- [ ] All `ds.search` and `ds.chain` data sources have a descriptive `name` property
- [ ] All `dataSources` referenced by visualizations exist
- [ ] All `visualizations` referenced in `layout.structure` exist
- [ ] All `inputs` listed in `layout.globalInputs` exist
- [ ] `defaults` section includes time range token binding
- [ ] Token names are consistent (`$token$` syntax)
- [ ] DOS expressions start with `>` and use proper escaping
- [ ] Layout positions don't overlap (grid) or are intentional (absolute)
- [ ] `context` objects are defined for all DOS `rangeValue`/`matchValue` references
- [ ] Option names match official docs (e.g., `nullValueDisplay` not `nullValueMode`, `stackMode` default is `"auto"`)
- [ ] Booleans/numbers are unquoted; strings/options are quoted in JSON
