# Design: discover-logformat skill

**Date:** 2026-04-11
**Status:** Draft — awaiting user review before implementation plan
**Author:** Brainstormed with Claude Code (superpowers:brainstorming)

---

## Context

The TA-FAKE-TSHRT project currently has three project-local skills for generating synthetic Splunk data: `add-generator`, `add-scenario`, and `generate-logs`. These skills are tightly coupled to the FAKE T-Shirt Company world (195 employees, specific IPs, specific servers) and to the project's directory layout.

The long-term vision is to evolve these skills into a reusable Claude Code plugin — an "A-to-Z" synthetic Splunk data generator that can be used against any fictional environment, not just FAKE T-Shirt.

This design covers the **first slice** of that plugin: a new skill called `discover-logformat` that takes a data source name (plus optional hints) and produces a structured specification that `add-generator` can consume to scaffold a generator. It is the *discovery* half of a pipeline.

**Scope decomposition:** The full plugin vision has at least six subsystems (framework core, onboarding wizard, data source catalog, data format discovery, behavioral layer, packaging). This spec covers only *data format discovery*. Other subsystems will be designed in later spec documents. The data format discovery skill was chosen first because:

1. It delivers immediate value in the existing TA-FAKE-TSHRT project — it can be used to add new sources tomorrow.
2. It forces an early definition of the generator contract (SPEC.yaml) that later informs the framework core.
3. It is small enough to ship standalone without requiring the rest of the plugin to exist.

## Goals

- Accept a wide range of inputs (log sample, vendor doc URL, Splunkbase TA ID, free-text description, or just a source name).
- Proactively search for relevant information when inputs are thin — the skill should not be a passive translator.
- Produce a machine-readable `SPEC.yaml` that the existing `add-generator` skill can consume.
- Produce a human-readable `REPORT.md` so users can fact-check the discovery before committing to code.
- Use confidence scoring on every derived fact, and escalate to the user when confidence is low.
- Run as a project-local skill in TA-FAKE-TSHRT first, then migrate to a global skill once the API has been validated against real sources.
- Be structured so that the expensive research phase can be moved to a subagent in v2 without touching other phases.

## Non-goals (v1)

- Writing Python generator code (that is `add-generator`'s job).
- Full CIM model alignment (deferred — will be added as an optional post-analysis pass later).
- Generating `props.conf`/`transforms.conf` embedded in SPEC.yaml (deferred — v1 writes a separate `props_draft.conf` file instead).
- Scraping GitHub for log samples (ruled out due to licensing grey area).
- Supporting exotic input types like OpenAPI schemas or PDF admin guides (deferred).

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  USER INVOCATION                                             │
│  /discover-logformat <source_id> [--sample=...] [--doc=...] │
│                      [--ta=...] [--description=...]         │
│                      [--interactive] [--batch] [--no-search]│
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  discover-logformat SKILL.md  (monolithic v1)                │
│                                                              │
│  Phase A — Input validation & normalization                  │
│     └─ parse flags, validate files, derive source_id slug    │
│                                                              │
│  Phase B — Research (v1: inline / v2: subagent)              │
│     ├─ read explicit inputs (samples, docs, TAs)             │
│     ├─ seed search (WebSearch)                               │
│     ├─ vendor doc fetch (WebFetch / Firecrawl fallback)      │
│     ├─ Splunkbase scrape (Firecrawl on app page)             │
│     ├─ community forums (last resort)                        │
│     └─ produce Findings struct                               │
│                                                              │
│  Phase C — Analysis                                          │
│     ├─ format detection (JSON/KV/CSV/CEF/syslog/XML)         │
│     ├─ field extraction                                      │
│     ├─ sourcetype suggestion                                 │
│     └─ category mapping                                      │
│                                                              │
│  Phase D — Confidence gates + interactive Q&A                │
│     ├─ part 1: auto-triggered gates for low-confidence areas │
│     └─ part 2: mandatory Q&A (baseline volume, scenarios)    │
│                                                              │
│  Phase E — Artifact writing                                  │
│     ├─ .planning/discover/<source_id>/SPEC.yaml              │
│     ├─ .planning/discover/<source_id>/REPORT.md              │
│     ├─ .planning/discover/<source_id>/samples/*.log          │
│     ├─ .planning/discover/<source_id>/props_draft.conf       │
│     └─ .planning/discover/<source_id>/research_trail.json    │
│                                                              │
│  Phase F — Handoff                                           │
│     └─ print summary and suggest /add-generator <source_id>  │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
                   (user reviews, approves)
                            │
                            ▼
              /add-generator <source_id>
                 (reads SPEC.yaml, scaffolds Python)
```

### Key architectural principles

1. **Phase B has a clean internal contract.** All research happens behind a `research(source_id, explicit_inputs, budget) → Findings` boundary. In v1 this runs inline in the main context. In v2 it can be lifted to a subagent (`~/.claude/agents/logformat-researcher.md`) without changing any other phase.
2. **Confidence scores live throughout.** Every derived fact (format, sourcetype, field, sample) carries a 0.0–1.0 score with evidence and source URL. Phase D is the only place that converts scores into user questions.
3. **Nothing is written to disk before Phase E.** Phases A–D are read-only. The skill can be safely interrupted mid-run without leaving half-written artifacts.
4. **All artifacts live under `.planning/discover/<source_id>/`.** One directory per source, git-friendly, easy to delete, easy to diff across re-runs.
5. **Migration note is explicit in SKILL.md.** A comment block in the research section documents exactly what to change when moving to a subagent in v2.

## Invocation & input flags

```
/discover-logformat <source_id> [inputs...] [flags...]
```

`source_id` is required. It is normalized to snake_case and used as the directory name under `.planning/discover/`.

### Input flags (0 or more)

| Flag | Type | Description |
|---|---|---|
| `--sample=<path>` | file | Raw log file. Max 500 lines read. Can be repeated. |
| `--doc=<url>` | URL | Vendor docs URL. Can be repeated. WebFetch first, Firecrawl fallback for JS-rendered pages. |
| `--ta=<id-or-url>` | text | Splunkbase app ID (e.g. `2846`) or full URL. |
| `--description=<text>` | text | Free-text seed for proactive search. |

If **no input flags** are given, the skill asks the user once at the start: *"Would you like to paste a log sample now, or should I rely on research only? [paste / research-only]"*

### Process flags

| Flag | Default | Description |
|---|---|---|
| `--interactive` | off | Force checkpoints at every decision point. |
| `--batch` | off | Never pause; use defaults silently, log them in REPORT.md as "assumed". |
| `--no-search` | off | Disable proactive web search. Use only explicit inputs. |
| `--min-sources=N` | `5` | Minimum research sources to consult (not a ceiling). |
| `--max-research-time=SEC` | `300` | Hard time budget for Phase B. |
| `--threshold=N` | `0.75` | Confidence threshold below which the skill escalates to the user. |

### Proactive search behavior

Unless `--no-search` is set, the skill **always** performs a lightweight seed search based on `source_id` + `--description` regardless of which other inputs were given. The skill iterates until all confidence scores reach the threshold, the minimum-sources count is met, the time budget is exhausted, or two consecutive searches produce no new information (diminishing returns).

## Research pipeline (Phase B)

### Research loop

```
findings = empty
sources_consulted = 0
started_at = now

while True:
    # Stop criteria
    if sources_consulted >= min_sources AND all_scores_above(findings, threshold):
        break
    if elapsed(started_at) > max_research_time:
        break
    if sources_consulted >= min_sources AND no_new_info_last_2_attempts:
        break

    # Pick next research step based on weakest area
    weakest = lowest_confidence_area(findings)
    next_action = plan_research_step(weakest, explicit_inputs, sources_consulted)

    # Execute
    new_evidence = execute(next_action)

    # Merge and re-score
    findings = merge_evidence(findings, new_evidence)
    sources_consulted += 1
```

### Research priority order

1. **Explicit inputs** — `--sample`, `--doc`, `--ta`. Highest trust (user chose them).
2. **Seed search** — `WebSearch "<vendor> <source> log format site:docs.<vendor>.com"`.
3. **Splunkbase scraping** — Firecrawl on `splunkbase.splunk.com/app/<id>` for TAs referenced by user or found via search. Extract README and props.conf from app page.
4. **Community forums** — Splunk Community, when vendor docs are thin.
5. **Fallback generic search** — unrestricted `WebSearch`, lower trust by default.

### Format detection

Pattern tests in order, tried against each sample line:

| Pattern | Format |
|---|---|
| starts with `{`, ends with `}` | JSON |
| `^CEF:\d` | CEF |
| `^<\d+>` | RFC5424 syslog |
| `^\w{3} \d+ \d+:\d+:\d+` | BSD syslog |
| `^\d+,.*,.*` | CSV |
| `\w+=\S+( \w+=\S+)+` | KV |
| starts with `<` | XML |
| otherwise | unknown/custom |

Confidence = `matches / samples_tested`, with a penalty cap of 0.7 when fewer than 10 samples are available.

### Sourcetype suggestion priority

1. Existing Splunkbase TA sourcetype (highest confidence).
2. CIM convention `vendor:product:datasource` (e.g. `fortinet:fortigate:traffic`).
3. Ad-hoc from `source_id` (lowest confidence).

### Field extraction

Per format:
- **JSON:** flatten recursively, record path + value type.
- **KV:** split on whitespace, then on `=`.
- **CEF:** standard CEF parser (header + extensions).
- **Syslog:** attempt KV parsing on message body; otherwise null.
- **CSV:** treat first row as header if values look like identifiers.

Per field confidence: frequency in samples (>80% = 1.0, <30% = 0.5) plus +0.2 bonus if confirmed by vendor docs.

## SPEC.yaml schema (v1)

The slim v1 schema. `splunk_config` and `cim` sections are deferred to later versions — v1 writes `props_draft.conf` as a separate file instead, and CIM alignment runs as an optional post-pass in a later version.

```yaml
schema_version: 1
generated_at: "2026-04-11T14:30:00Z"
generated_by: "discover-logformat v1"

source:
  id: fortigate                            # used in --sources=X
  display_name: "Fortinet FortiGate"
  vendor: Fortinet
  product: FortiGate
  description: >
    Traffic logs from Fortinet FortiGate NGFW. KV-formatted syslog
    with fields like srcip, dstip, action, service, policyid.

category: network                          # network|cloud|windows|linux|web|retail|erp|itsm|ot|collaboration
source_groups: [network]

format:
  type: kv                                 # json|kv|csv|cef|syslog|xml|unknown
  line_break: "\n"
  timestamp:
    field: date
    format: "%Y-%m-%d"
    auxiliary_field: time
    auxiliary_format: "%H:%M:%S"
  encoding: utf-8
  confidence: 0.92

sourcetype:
  name: "fortinet:fortigate:traffic"
  category_path: "network/fortigate_traffic.log"
  confidence: 0.88

fields:
  - name: srcip
    type: ipv4
    required: true
    example: "10.10.30.55"
    confidence: 0.95
  - name: dstip
    type: ipv4
    required: true
    example: "185.220.101.42"
    confidence: 0.95
  - name: action
    type: enum
    values: [accept, deny, drop, reset]
    required: true
    example: "deny"
    confidence: 0.90

sample_events:
  - raw: |
      date=2026-01-05 time=14:30:45 devname=FW-EDGE-01 srcip=10.10.30.55 dstip=185.220.101.42 action=deny policyid=47
    parsed:
      srcip: "10.10.30.55"
      dstip: "185.220.101.42"
      action: "deny"
    source_url: "https://docs.fortinet.com/..."

generator_hints:
  suggested_module_name: generate_fortigate
  suggested_function_name: generate_fortigate_logs
  volume_category: firewall                # passed to calc_natural_events()
  baseline_events_per_day: 1000            # default, confirmed/overridden in Q&A
  dependencies: []
  multi_file: false
  scenarios:
    existing: [exfil, ddos_attack]          # confirmed by user
    proposed:
      - name: fortigate_app_control_c2
        category: attack
        description: >
          C2 beaconing detected via Fortigate's app-control field.
        rationale: >
          Fortigate has a unique app-control field that other firewall
          sources lack, making this a natural fit.
        affected_sources: [fortigate, aws, entraid]
        suggested_days: "5-9"

research_metadata:
  sources_consulted:
    - url: "https://docs.fortinet.com/..."
      kind: vendor_doc
      trust: high
  total_research_time_sec: 187
  overall_confidence: 0.87
  unresolved_questions: []
```

### Why this shape

- **`schema_version: 1`** — allows breaking changes later without orphaning existing drafts.
- **Confidence at every level** — field, sourcetype, format each have their own score. `add-generator` can mark uncertain items as TODO in generated code.
- **`generator_hints`** — everything `add-generator` needs to produce a smarter skeleton than the generic template. `volume_category` feeds directly into `calc_natural_events()`.
- **`scenarios.proposed[]`** — lets the skill suggest *new* scenarios that don't exist yet. Downstream, `add-scenario` can consume these entries to stub out scenario modules.
- **`research_metadata`** — full audit trail. SPEC.yaml can be committed and the reader can always see *where* each fact came from.

## Confidence gates and interactive Q&A (Phase D)

Gates and mandatory questions are **merged into one numbered list** shown in a single message. The user answers everything at once.

### Auto-triggered gates

| Gate | Fires when | Example question |
|---|---|---|
| Format gate | `format.confidence < threshold` | "65% KV, 35% JSON. Which is it?" |
| Sourcetype gate | `sourcetype.confidence < threshold` | "Two reasonable candidates: `fortinet:fortigate:traffic` or `syslog:fortigate`. Which?" |
| Field gate | Any field `confidence < 0.5` | "`policyid` appeared in only 3 of 20 samples. Keep as optional or drop?" |
| Unresolved question gate | `unresolved_questions` non-empty | "Vendor doc says policyid is integer, but one sample showed `policyid=rule_47`. Integer or string?" |

### Mandatory Q&A

Always asked, regardless of confidence:

1. **Baseline volume.** Default: 1000 events per day. Weekend and hour-of-day variation is automatic via `calc_natural_events()`. Ask: *"Default is 1000 events/day with automatic weekend/time-of-day variation. OK, or another number?"*

2. **Scenarios — open discussion.** The skill reads `bin/scenarios/registry.py`, identifies scenarios plausibly applicable to this source based on category and field set, and proposes them with checkboxes. The user can confirm existing scenarios AND request entirely new ones. If the user describes a new scenario idea, the skill captures it under `generator_hints.scenarios.proposed[]` with name, category, description, rationale. The skill must remain open to implementing scenarios that do not yet exist.

### Batch mode behavior

When `--batch` is set, Phase D uses defaults silently and marks them in REPORT.md under a "User-confirmed defaults (from Q&A)" section annotated as "assumed". No crash. Rationale: batch mode is "give me a draft, I will clean up later," and crashing on missing input is unnecessary friction.

## Artifact layout (Phase E)

```
.planning/discover/<source_id>/
├── SPEC.yaml                # machine contract (for add-generator)
├── REPORT.md                # human-readable narrative + citations
├── samples/
│   ├── vendor_doc_01.log
│   ├── splunkbase_01.log
│   └── user_provided.log
├── props_draft.conf         # ready-to-paste props.conf snippet
└── research_trail.json      # full audit: every URL fetched, timestamp, tokens
```

### REPORT.md template

```markdown
# Discovery Report: <source_id>

**Generated:** <UTC timestamp>
**Overall confidence:** <score>

## Summary
<one-paragraph description of what was discovered and how confident>

## Format
- Type, timestamp format, confidence, evidence link

## Sourcetype
- Suggested name, confidence, rationale

## Fields (top N of M)
<markdown table>

## Sources Consulted
<numbered list with URLs, kind, trust>

## Unresolved Questions
<list or "None — all resolved during Q&A">

## User-confirmed defaults (from Q&A)
- baseline_events_per_day: <value>
- existing scenarios: <list>
- proposed scenarios: <list>

## Next Steps
1. Review SPEC.yaml and make any adjustments
2. Run /add-generator <source_id>
3. (Optional) Run /add-scenario <proposed_scenario_name>
```

### Handoff message (Phase F, printed in chat)

```
✅ Discovery complete for '<source_id>' (overall confidence: <score>)

Artifacts written to .planning/discover/<source_id>/:
  • SPEC.yaml (machine-readable, for add-generator)
  • REPORT.md (human-readable explanation)
  • samples/ (<N> log samples)
  • props_draft.conf (ready-to-paste props.conf snippet)

Next step: Review REPORT.md, then run:
  /add-generator <source_id>

Proposed follow-up (optional):
  /add-scenario <proposed_scenario_name>
```

## Collision handling

When the skill runs against a `source_id` that already has a non-empty `.planning/discover/<source_id>/` directory (checked at the start of Phase A), it interactively asks the user what to do before any research starts:

> "Discovery artifacts for `<source_id>` already exist from `<YYYY-MM-DD>`. What would you like to do?
>   1. **Overwrite** — replace old files (old ones are lost)
>   2. **Rerun** — save new files to `.planning/discover/<source_id>-rerun-<YYYYMMDD-HHMM>/` (both preserved, can be diffed)
>   3. **Abort** — do nothing"

Default when `--batch` is set: **rerun** (safe, no data loss).

## Testing strategy (v1)

### Canary sources for regression testing

1. **`aws_cloudtrail`** — existing generator provides ground truth. Run `/discover-logformat aws_cloudtrail` and compare SPEC.yaml against `generate_aws.py`. Expected: `format.type = json`, `sourcetype.name = aws:cloudtrail`, `category = cloud`.
2. **`fortigate`** — realistic new source. No ground truth, but Splunkbase TA 2846 is well-known. Verify research discovers it.
3. **`custom_internal_app`** — sample-only with `--no-search`. Verify the skill produces something reasonable purely from a provided log file.

### Smoke suite

A small bash wrapper runs the 3 canary cases with `--batch --threshold=0.5` and verifies each SPEC.yaml contains the minimum expected fields: `source.id`, `format.type`, `sourcetype.name`, at least one entry in `fields`.

### Manual review

After every meaningful change to the skill, run it against one new unknown source and manually evaluate the SPEC.yaml. Not automatable.

## Versioning

- `SKILL.md` has a `version:` field in frontmatter, bumped on every meaningful contract change.
- `SPEC.yaml` has `schema_version: 1`. `add-generator` must verify this and fail gracefully on unknown versions.
- CHANGELOG entry in `docs/CHANGEHISTORY.md` at each change (per project convention).

## Migration path to subagent (v2)

The v1 skill is designed to be migratable to a subagent without touching other phases. Checklist for the future migration:

1. Move all of Phase B (the research loop) to a new file: `~/.claude/agents/logformat-researcher.md`.
2. In SKILL.md, replace the inline research function with a single `Agent` tool call that passes `source_id`, `explicit_inputs`, and `budget` to the subagent.
3. The subagent returns the `Findings` struct (same schema) as structured JSON in its final message.
4. SKILL.md parses the return value and continues Phase C–F unchanged.

A migration note will be placed at the top of the research section in SKILL.md so it is not forgotten:

```markdown
<!-- MIGRATION NOTE: This entire "Phase B — Research" section is designed to be
     liftable to a subagent without touching other phases. The contract is:
     input = (source_id, explicit_inputs, budget), output = Findings struct.
     When context pollution from web-fetches becomes a real problem, move this
     section to ~/.claude/agents/logformat-researcher.md and replace the inline
     logic with an Agent tool call. No other phases should need changes. -->
```

## Open questions

None remaining after brainstorming.

## Out of scope for this spec

These will be designed in future spec documents:

- **Framework core** — the generic generator runtime, world-state config schema, and how sources register themselves. This spec assumes TA-FAKE-TSHRT's existing `main_generate.py` remains the orchestrator for v1.
- **Onboarding wizard** — the "create a new fictional world" UX. This spec assumes the world already exists (TA-FAKE-TSHRT's `shared/company.py`).
- **Full CIM alignment post-pass** — will be a separate feature once v1 is stable.
- **Behavioral layer** — temporal/causal/anomaly models from the three-layer architecture sketch. These live closer to the framework core.
- **Plugin packaging** — how skills + commands + templates are distributed as a Claude Code plugin. Requires the framework core first.

## Dependencies for implementation

- The `add-generator` skill must be updated to read `SPEC.yaml` as input and scaffold Python accordingly. This is a separate work item that will follow this spec's implementation.
- No new Python dependencies in the generators. Skills use Claude tooling only (WebSearch, WebFetch, Firecrawl MCP, file I/O).

## Change history entry (to be added after implementation)

A line will be added to `docs/CHANGEHISTORY.md` when the skill is created:

```
## 2026-MM-DD ~HH:MM UTC — Add discover-logformat skill
Files: .claude/skills/discover-logformat/SKILL.md, docs/superpowers/specs/2026-04-11-discover-logformat-design.md
Adds a new project-local skill that takes a data source name and produces
a SPEC.yaml draft for add-generator to consume. Pipeline: discover → review → add-generator.
```
