---
name: discover-logformat
description: Analyze a log sample to produce a draft SPEC.yaml for adding a new data source. Use when you have raw log lines from a new source and want a structured format analysis before scaffolding a generator.
version: 0.2.0-research
metadata:
  argument-hint: "<source_id> [--sample=<path>] [--doc=<url>] [--description=<text>] [--no-search]"
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

Expected invocation shape: `/discover-logformat <source_id> [flags...]`

Required positional argument: `<source_id>`. If missing, respond:
> "Missing `source_id`. Usage: `/discover-logformat <source_id> [--sample=<path>] [--doc=<url>] [--description=<text>] [--no-search]`"

Recognized flags in v2:
- `--sample=<path>` — path to a raw log file. Optional.
- `--doc=<url>` — vendor doc URL, repeatable. Optional.
- `--description=<text>` — free-text description used as a search seed. Optional.
- `--no-search` — disable the WebSearch step. `--doc` URLs are still fetched.

At least one of `--sample`, `--doc`, or `--description` MUST be present. If all three are missing, respond:
> "I need at least one of `--sample`, `--doc`, or `--description` to work from. Please pick one:
>   • `--sample=<path>` if you have raw log lines
>   • `--doc=<url>` if you have a vendor documentation URL
>   • `--description=<text>` if you only have a free-text description
>
> You can combine them. Rerun with at least one of these flags."

Flags NOT yet supported in v2 (`--ta`, `--interactive`, `--batch`, `--threshold`, `--min-sources`, `--max-research-time`) should still be rejected:
> "Flag `<flag>` is not supported yet. Current version is v2 (research). See `docs/superpowers/plans/` for the roadmap."

Record which inputs were supplied — the result is an `ExplicitInputs` object:
`{sample_path: string|null, doc_urls: string[], description: string|null, no_search: bool}`

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

## Phase B — Research

Gather external context for the source. Runs by default; the only way to skip Phase B entirely is when `--no-search` is set AND no `--doc` URLs were provided. Phase B produces a `ResearchFindings` struct that is merged into Phase C's analysis.

### B.1 Decide whether Phase B runs

- If `ExplicitInputs.no_search` is true AND `ExplicitInputs.doc_urls` is empty → skip Phase B entirely. Proceed to Phase C with an empty `ResearchFindings` struct.
- Otherwise → proceed.

### B.2 Start the Phase B clock

Record the current UTC time as `phase_b_start`. The elapsed wall time between `phase_b_start` and the end of Phase B is recorded later as `research_metadata.total_research_time_sec`.

### B.3 Fetch explicit `--doc` URLs

For each URL in `ExplicitInputs.doc_urls`, call the `WebFetch` tool with a prompt like:

> "Extract the log format, vendor, product, and any example log events. Return the raw event examples verbatim and a short list of field names with descriptions if visible."

Record the URL in `sources_consulted` with `kind: explicit_doc`, `trust: 1.0`, and `retrieved_at` = current UTC ISO-8601 timestamp.

Hard cap: fetch at most 3 URLs total across Phase B (explicit docs + search results combined). If `doc_urls` already contains 3 entries, skip B.4 entirely.

### B.4 Seed WebSearch (unless `--no-search`)

If `ExplicitInputs.no_search` is true → skip B.4.

Otherwise, construct the search query:
- If `description` is present: query = `"<source_id> <description> log format"`
- If `description` is absent: query = `"<source_id> log format"`

Call `WebSearch` once with that query.

From the results, pick the top-ranked URLs whose domains look like vendor documentation (prefer `docs.<vendor>.com`, `help.<vendor>.com`, `<vendor>.com/*/docs/*` patterns; de-prioritize blog posts, Reddit, Stack Overflow). Fetch up to `(3 - len(doc_urls))` of them via `WebFetch` using the same extraction prompt as B.3.

Record each fetched URL in `sources_consulted` with `kind: search_result`, `trust: 0.7`, and `retrieved_at` = current UTC ISO-8601 timestamp.

### B.5 Extract findings from fetched pages

For each successfully fetched page, collect:

- **Sample log lines:** any monospaced, code-fenced, or otherwise clearly log-like lines shown as examples. Skip prose. Add each found line to `ResearchFindings.samples_found[]`, limited to at most 20 lines total across all sources.
- **Vendor hint:** the vendor name (e.g. "Fortinet"). Record the first non-empty value in `ResearchFindings.vendor_hint`.
- **Product hint:** the product name (e.g. "FortiGate"). Record the first non-empty value in `ResearchFindings.product_hint`.
- **Description hint:** a one-sentence description of what the source is. Record the first non-empty value in `ResearchFindings.description_hint`.
- **Field hints:** any explicit field-name tables or bullet lists with descriptions (e.g. "srcip — source IP address"). Record as `{name, description}` pairs in `ResearchFindings.field_hints[]`.

Failed fetches are not fatal — record them in `sources_consulted` with `kind: <same>`, `trust: 0.0`, and a `note: "fetch failed"` key. Phase B never aborts the run; it always returns whatever it has.

### B.6 Stop the Phase B clock and return

Compute `elapsed_sec = now_utc - phase_b_start`. Build the `ResearchFindings` struct:

```
ResearchFindings {
  samples_found: string[],
  vendor_hint: string|null,
  product_hint: string|null,
  description_hint: string|null,
  field_hints: [{name, description}],
  sources_consulted: [{url, kind, trust, retrieved_at, note?}],
  elapsed_sec: number
}
```

Pass this to Phase C.

## Phase C — Format analysis

Analyze whatever samples are available. In v2, samples can come from TWO sources:

1. **User-provided samples** — the file at `--sample=<path>`, if given. Loaded in Phase A.
2. **Research-found samples** — the `ResearchFindings.samples_found[]` list from Phase B.

Build the working sample set as the deduplicated union of both lists (order: user samples first, then research samples). Deduplicate by exact line match. Cap the combined set at 500 lines.

If the combined set is **non-empty**, run C.1 through C.5 as normal.

If the combined set is **empty** (user gave only `--description`, and research found no log lines — only field descriptions and vendor text), switch to **metadata-only mode**:
- Set `format.type = "unknown"` and `format.confidence = 0.0`.
- Skip C.1 entirely.
- Skip C.2 field extraction from samples. Instead, populate `fields[]` from `ResearchFindings.field_hints[]` — each hint becomes a field with `type: string`, `required: false`, `example: null`, `confidence: 0.7` (the hints came from vendor docs, not frequency analysis).
- Run C.3 sourcetype suggestion as normal.
- Run C.4 category lookup as normal.
- Run C.5 with an empty `sample_events[]`.

Produce the `Findings` struct either way.

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

Operate on the combined sample set defined in the Phase C preamble (user samples + research samples, deduplicated, capped at 500 lines).

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
- `format`: `{type, confidence}` — `type: "unknown"` and `confidence: 0.0` in metadata-only mode
- `sourcetype`: `{name, confidence}`
- `category`
- `fields`: list of `{name, type, required, example, confidence}` — may originate from samples OR from `ResearchFindings.field_hints[]` in metadata-only mode
- `sample_events`: up to 3 original lines with their parsed representation (empty in metadata-only mode)
- `vendor`: copied from `ResearchFindings.vendor_hint` if present, else `"unknown"`
- `product`: copied from `ResearchFindings.product_hint` if present, else `"unknown"`
- `vendor_description`: copied from `ResearchFindings.description_hint` if present, else a default generic paragraph
- `research`: the full `ResearchFindings` struct from Phase B (passed through for Phase E to read)
- `overall_confidence`: the mean of `format.confidence`, `sourcetype.confidence`, and the mean field confidence. In metadata-only mode, exclude `format.confidence` from the mean so a 0.0 does not tank the overall score.

This struct is the input to Phase E. Do not write any files yet.

## Phase E — Artifact writing

Convert the in-memory `Findings` from Phase C into three files on disk. All paths are relative to the current working directory.

### E.1 Create the output directory

Create the directory `.planning/discover/<source_id>/samples/` if it does not already exist. (Collision was already refused in A.4, so this directory is guaranteed empty here.)

### E.2 Copy the sample

Copy the file passed via `--sample=<path>` to `.planning/discover/<source_id>/samples/user_provided.log` byte-for-byte. Do not modify line endings, encoding, or content.

### E.3 Write `SPEC.yaml`

Write `.planning/discover/<source_id>/SPEC.yaml` using this template. Substitute the `{{ }}` placeholders with values from `Findings`. Use ISO-8601 UTC for `generated_at`. Preserve the ordering of top-level keys shown below.

```yaml
schema_version: 1
generated_at: "{{ now_utc_iso8601 }}"
generated_by: "discover-logformat v0.1.0-mvp"

source:
  id: {{ source_id }}
  display_name: "{{ source_id humanized — replace underscores with spaces and title-case }}"
  vendor: {{ findings.vendor or "unknown" }}
  product: {{ findings.product or "unknown" }}
  description: >
    {{ findings.vendor_description or ( "Draft discovery for " + source_id + " produced from a log sample of " + line_count + " lines." ) }}

category: {{ category }}
source_groups: []

format:
  type: {{ format.type }}
  line_break: "\n"
  timestamp:
    field: null
    format: null
  encoding: utf-8
  confidence: {{ format.confidence }}

sourcetype:
  name: "{{ sourcetype.name }}"
  category_path: "{{ category }}/{{ source_id }}.log"
  confidence: {{ sourcetype.confidence }}

fields:
{{# for each field in Findings.fields: }}
  - name: {{ field.name }}
    type: {{ field.type }}
    required: {{ field.required }}
    example: "{{ field.example }}"
    confidence: {{ field.confidence }}
{{# endfor }}

sample_events:
{{# for each event in Findings.sample_events (up to 3): }}
  - raw: |
      {{ event.raw }}
    parsed:
{{#   for each key, value in event.parsed: }}
      {{ key }}: "{{ value }}"
{{#   endfor }}
    source_url: null
{{# endfor }}

generator_hints:
  suggested_module_name: generate_{{ source_id }}
  suggested_function_name: generate_{{ source_id }}_logs
  volume_category: {{ category }}
  baseline_events_per_day: 1000
  dependencies: []
  multi_file: false
  scenarios:
    existing: []
    proposed: []

research_metadata:
  sources_consulted:
{{# for each source in findings.research.sources_consulted: }}
    - url: "{{ source.url }}"
      kind: {{ source.kind }}
      trust: {{ source.trust }}
      retrieved_at: "{{ source.retrieved_at }}"
{{#   if source.note: }}
      note: "{{ source.note }}"
{{#   endif }}
{{# endfor }}
  total_research_time_sec: {{ findings.research.elapsed_sec }}
  overall_confidence: {{ findings.overall_confidence }}
  unresolved_questions: []
```

### E.4 Write `REPORT.md`

Write `.planning/discover/<source_id>/REPORT.md` using this template. Substitute the `{{ }}` placeholders.

```markdown
# Discovery Report: {{ source_id }}

**Generated:** {{ now_utc_human }}
**Overall confidence:** {{ findings.overall_confidence }}
**Plan version:** v2 (research-enabled)

## Summary
Draft discovery produced from an offline log sample of {{ line_count }} lines. No external research was performed. This is the minimum-viable output — expect gaps in vendor metadata, CIM alignment, and scenario suggestions. Review SPEC.yaml and fill in manually before running `/add-generator`.

## Format
- **Type:** {{ format.type }}
- **Confidence:** {{ format.confidence }}
- **Evidence:** Pattern matched on {{ matched_line_count }} of {{ line_count }} sample lines.

## Sourcetype
- **Suggested:** `{{ sourcetype.name }}`
- **Confidence:** {{ sourcetype.confidence }}
- **Rationale:** Heuristic `<source_id>:events` — not derived from vendor docs or an existing TA.

## Fields (all {{ field_count }})
| Name | Type | Required | Confidence | Example |
|---|---|---|---|---|
{{# for each field in Findings.fields: }}
| {{ field.name }} | {{ field.type }} | {{ field.required }} | {{ field.confidence }} | {{ field.example }} |
{{# endfor }}

## Sources Consulted
{{# if findings.research.sources_consulted is empty: }}
None — run was offline (`--no-search` with no `--doc` URLs, or Phase B skipped).
{{# else: }}
| # | URL | Kind | Trust | Retrieved |
|---|---|---|---|---|
{{#   for i, source in enumerate(findings.research.sources_consulted): }}
| {{ i+1 }} | {{ source.url }} | {{ source.kind }} | {{ source.trust }} | {{ source.retrieved_at }} |
{{#   endfor }}

Total research time: {{ findings.research.elapsed_sec }} seconds.
{{# endif }}

## Next Steps
1. Review `SPEC.yaml` and correct any obviously wrong guesses (vendor, product, timestamp format, field types).
2. Run `/add-generator {{ source_id }}` to scaffold the Python generator.
3. If you want a more thorough draft, wait for Plan v2 which adds `--doc=<url>` and proactive research.
```

### E.5 Print the handoff message

After all three files are written, print this message to the user:

```
✅ Discovery complete for '{{ source_id }}' (Plan v1 MVP).

Artifacts written to .planning/discover/{{ source_id }}/:
  • SPEC.yaml       (machine-readable draft, schema_version 1)
  • REPORT.md       (human-readable summary)
  • samples/user_provided.log  (copy of the input sample)

Overall confidence: {{ findings.overall_confidence }}

Next step: review REPORT.md, edit SPEC.yaml if needed, then run:
  /add-generator {{ source_id }}
```
