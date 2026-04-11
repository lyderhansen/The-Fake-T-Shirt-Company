---
name: discover-logformat
description: Analyze a log sample to produce a draft SPEC.yaml for adding a new data source. Use when you have raw log lines from a new source and want a structured format analysis before scaffolding a generator.
version: 0.1.0-mvp
metadata:
  argument-hint: "<source_id> --sample=<path>"
---

# discover-logformat — MVP (Plan v1)

Analyze a provided log sample and produce a draft `SPEC.yaml` plus minimal `REPORT.md` under `.planning/discover/<source_id>/`. This MVP version is **offline only** — it does not perform web research, ask confidence questions, or update `add-generator`. Those capabilities arrive in later plan iterations.

**What this skill does:**
1. Validates inputs and derives a normalized `source_id`.
2. Reads the sample file, detects the log format, and extracts a best-effort field list.
3. Writes a draft `SPEC.yaml`, a short `REPORT.md`, and copies the sample to `samples/user_provided.log`.

**What this skill does NOT do yet (deferred to later plan iterations):**
- Web research (Phase B)
- Confidence gates or interactive Q&A (Phase D)
- `props_draft.conf` generation
- Scenario suggestions
- Collision handling (v1 refuses to overwrite an existing directory — see Phase A)

**Source of truth for the full design:** `docs/superpowers/specs/2026-04-11-discover-logformat-design.md`

---

## Phase A — Input validation and normalization

Follow these instructions in order. Stop at the first failure and report it to the user.

### A.1 Parse arguments

Expected invocation shape: `/discover-logformat <source_id> --sample=<path>`

Required positional argument: `<source_id>`. If missing, respond:
> "Missing `source_id`. Usage: `/discover-logformat <source_id> --sample=<path>`"

Required flag: `--sample=<path>`. If missing, respond:
> "The MVP version of this skill requires `--sample=<path>`. Research, docs, and Splunkbase inputs are deferred to a later plan iteration. For now, provide a raw log file."

Any other flag (`--doc`, `--ta`, `--description`, `--interactive`, `--batch`, `--no-search`, `--threshold`, `--min-sources`, `--max-research-time`) is **not supported in the MVP**. If the user passes one of these flags, respond:
> "Flag `<flag>` is not supported in the MVP. Only `--sample=<path>` is available in Plan v1. See `docs/superpowers/plans/2026-04-11-discover-logformat.md` for the roadmap."

### A.2 Normalize `source_id`

- Lowercase the value.
- Replace every run of non-alphanumeric characters with a single underscore.
- Strip leading/trailing underscores.
- Reject if the result is empty or starts with a digit (respond: "source_id must start with a letter and contain at least one alphanumeric character").

The normalized value is the canonical `source_id` used for the rest of the run.

### A.3 Validate the sample file

- Resolve `--sample=<path>` relative to the current working directory.
- Fail with a clear error if the file does not exist, is not readable, or is empty.
- Read at most the first 500 lines. If the file is longer, continue but note the truncation in `REPORT.md` later.

### A.4 Check for collision

Check whether `.planning/discover/<source_id>/` already exists and is non-empty.

If it is, **refuse to proceed in the MVP** and respond:
> "Discovery artifacts already exist at `.planning/discover/<source_id>/`. The MVP version of this skill does not support overwrite or rerun. Delete the directory and try again, or wait for Plan v3 which adds collision handling."

If the directory does not exist or is empty, continue to Phase C.

## Phase C — Format analysis

Analyze the sample lines loaded in Phase A. Produce an in-memory `Findings` structure with format, sourcetype, field catalog, and sample events. No files are written in this phase.

### C.1 Detect format

Test each sample line against the patterns below in order. The first matching pattern wins. Count the fraction of lines that match, and record that as `format.confidence`.

| Order | Pattern (regex or predicate) | Format value |
|---|---|---|
| 1 | line starts with `{` and ends with `}` | `json` |
| 2 | `^CEF:\d` | `cef` |
| 3 | `^<\d+>` | `syslog` (RFC5424) |
| 4 | `^\w{3} \d+ \d+:\d+:\d+` | `syslog` (BSD) |
| 5 | `^\d+,.*,.*` | `csv` |
| 6 | `\w+=\S+( \w+=\S+)+` | `kv` |
| 7 | line starts with `<` | `xml` |
| 8 | none of the above | `unknown` |

If fewer than 10 lines are available, cap `format.confidence` at `0.7` regardless of the match fraction.

### C.2 Extract fields

Based on the detected format, extract a field catalog:

- **json:** parse each line as JSON, flatten nested objects with dot-path keys (e.g. `event.user.id`). Record each observed path with its value type (`string`, `integer`, `float`, `boolean`, `ipv4`, `ipv6`, `null`). Use `ipv4`/`ipv6` when a string value matches a dotted-quad or colon-separated hex pattern; otherwise `string`.
- **kv:** split each line on whitespace, then split each token on the first `=`. The left side is the field name; the right side is the value. Infer type from the value using the same rules as JSON.
- **csv:** treat the first line as the header if all values look like identifiers (alphanumeric + underscore, no spaces). Otherwise generate `col_1`, `col_2`, … as field names. Infer value types from the remaining rows.
- **cef:** parse the 7-field CEF header (`Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity`). Then parse the extension block as KV pairs.
- **syslog / xml / unknown:** record a single synthetic field `raw_line` of type `string`. Format detection still counts, but no detailed field extraction is performed in the MVP.

For each field, compute its **frequency**: the fraction of sample lines in which the field appears. Assign `confidence` as follows:
- frequency ≥ 0.8 → `1.0`
- 0.5 ≤ frequency < 0.8 → `0.8`
- 0.3 ≤ frequency < 0.5 → `0.6`
- frequency < 0.3 → `0.5`

Mark a field as `required: true` if frequency ≥ 0.9; otherwise `required: false`.

### C.3 Suggest a sourcetype name

Use the simple MVP rule: `<source_id>:events` (e.g. `custom_internal_app:events`). Assign `sourcetype.confidence = 0.6` — it is a heuristic, not derived from vendor knowledge.

### C.4 Guess a category

Use this lookup keyed on tokens in the `source_id` (first match wins):

| Token in `source_id` | category |
|---|---|
| `firewall`, `asa`, `fortinet`, `palo`, `cisco` | `network` |
| `aws`, `gcp`, `azure`, `entra`, `okta` | `cloud` |
| `wineventlog`, `sysmon`, `perfmon`, `mssql` | `windows` |
| `linux`, `syslog` | `linux` |
| `exchange`, `office`, `webex`, `teams` | `collaboration` |
| `sap`, `erp` | `erp` |
| `servicenow`, `itsm` | `itsm` |
| `cybervision`, `plc`, `scada`, `ot` | `ot` |
| `access`, `apache`, `nginx`, `web` | `web` |
| none of the above | `unknown` |

### C.5 Build the `Findings` struct (in memory)

At the end of Phase C, you have an in-memory object with:
- `format`: `{type, confidence}`
- `sourcetype`: `{name, confidence}`
- `category`
- `fields`: list of `{name, type, required, example, confidence}`
- `sample_events`: up to 3 original lines with their parsed representation
- `overall_confidence`: the mean of `format.confidence`, `sourcetype.confidence`, and the mean field confidence

This struct is the input to Phase E. Do not write any files yet.

## Phase E — Artifact writing

*(Populated in Task 5.)*
