# discover-logformat Plan v2 — minimal research

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make web research a first-class input to `discover-logformat`. The skill must work usefully even when no log sample exists — research then becomes the primary source. Accept `--description=<text>`, `--doc=<url>`, and `--no-search` flags; make `--sample` optional; run Phase B research by default; use research-found samples and metadata to populate `SPEC.yaml` when user samples are absent or thin.

**Architecture:** Phase B is inserted between Phase A (input validation) and Phase C (format analysis). Phase A is extended to parse new flags AND to require at least one of `{--sample, --doc, --description}` so the skill always has *something* to work on. Phase B runs unconditionally unless `--no-search` is set and writes its findings (vendor-doc URLs, extracted sample lines, vendor metadata hints) into a `ResearchFindings` sub-struct. Phase C is updated to merge user-provided samples with research-found samples before running its existing detection logic, and to gracefully fall back to "metadata-only" mode when no samples exist at all. Phase E is updated to populate `research_metadata.sources_consulted` with real data and to prefer research-discovered `source.vendor`/`source.product`/`source.description` over the previous hard-coded `unknown` values. Version bumps `0.1.0-mvp` → `0.2.0-research`.

**Tech Stack:** Claude Code skill framework (markdown), WebSearch tool, WebFetch tool. No Python changes. No new dependencies.

**Relationship to other plans:**
- **Plan v1 (complete):** offline MVP — sample in, SPEC.yaml out
- **Plan v2 (this doc):** single-shot research — description + doc URL → enriched SPEC.yaml
- **Plan v3 (future):** iterative research loop with stop criteria, Splunkbase Firecrawl, `--ta=<id>`
- **Plan v4 (future):** community forum fallback, confidence-based source expansion
- **Plan v5 (future):** Phase D confidence gates + interactive Q&A
- **Plan v6 (future):** `add-generator` consumes SPEC.yaml
- **Plan v7 (future):** promote to global `~/.claude/skills/`

**Source of truth:** `docs/superpowers/specs/2026-04-11-discover-logformat-design.md` (Phase B section). This plan implements a simplified subset.

**Pre-requisites:** Plan v1 complete (commit `7932bff` or later).

---

## Scope — in and out

**In scope for Plan v2:**

*Input handling:*
- `--description=<text>` flag — free-text seed describing the source
- `--doc=<url>` flag — vendor doc URL, repeatable, each fetched via WebFetch
- `--no-search` flag — disable WebSearch entirely (does NOT disable `--doc` fetching)
- `--sample` is now **optional** — the skill must accept at least one of `{--sample, --doc, --description}`, otherwise it prompts the user for at least one
- Phase A rejects invocations where all three of `{--sample, --doc, --description}` are missing

*Research pipeline (new Phase B):*
- Runs by default. Skipped only when `--no-search` is set AND no `--doc` URLs were provided
- One WebSearch call using `<source_id> <description>` as query (skipped if `--no-search`, still runs if `--description` is absent — query is then just `<source_id> log format`)
- Up to 3 WebFetch calls total — prioritize explicit `--doc` URLs first, then top search results
- For each fetched page, extract: (a) any code-fenced or monospaced lines that look like log events, (b) vendor/product mentions, (c) any field-description lists
- Per-source `trust` score: `explicit-doc` = 1.0, `search-result` = 0.7
- Returns a `ResearchFindings` sub-struct: `{samples_found[], vendor_hint, product_hint, description_hint, sources_consulted[], elapsed_sec}`

*Phase C updates:*
- When `--sample` is provided AND research found additional samples: use BOTH in format detection (user samples + research samples, deduplicated)
- When `--sample` is absent but research found samples: run detection on research samples only
- When no samples exist from either source (e.g. `--description` alone, research found only field lists): fall back to **metadata-only mode** — skip format detection, mark `format.type = "unknown"` with `format.confidence = 0.0`, populate `fields[]` from any field-description lists research found, leave `sample_events[]` empty

*Phase E updates:*
- `research_metadata.sources_consulted` populated with real `{url, kind, retrieved_at, trust}`
- `research_metadata.total_research_time_sec` recorded as elapsed wall time for Phase B
- `source.vendor`, `source.product`, `source.description` prefer research hints over hard-coded `unknown`
- REPORT.md "Sources Consulted" section lists the real URLs with trust and kind

*Versioning & testing:*
- Frontmatter `version: 0.1.0-mvp` → `0.2.0-research`
- Canary: extend `custom_internal_app` test to ALSO run with `--no-search` and verify identical output to the v1 baseline (regression check on the offline path)
- Canary: add new structural test for `fortigate` with real research (`--description="Fortinet FortiGate traffic logs"` on a clean run, asserting: (a) SPEC.yaml is written, (b) `sources_consulted[]` has ≥ 1 entry, (c) `source.vendor` is NOT `unknown`, (d) the handoff message mentions the real source_id)

**Out of scope for Plan v2 (explicitly deferred):**
- Iterative research loop with confidence-driven stopping (Plan v3)
- `--min-sources`, `--max-research-time`, `--threshold` flags (Plan v3)
- Splunkbase scraping via Firecrawl MCP (Plan v3)
- `--ta=<splunkbase-id>` flag (Plan v3)
- Community forum fallback (Plan v4)
- Confidence gates + Q&A (Plan v5)
- Updating `add-generator` to consume SPEC.yaml (Plan v6)
- Global promotion to `~/.claude/skills/` (Plan v7)
- Research page-content truncation handling — v2 accepts whatever WebFetch returns
- Canary assertions on specific research content (non-deterministic) — v2 only asserts structural properties (files exist, non-empty lists, non-`unknown` values)

---

## File Structure

Files created or modified by this plan:

| Path | Purpose | Created/Modified |
|---|---|---|
| `.claude/skills/discover-logformat/SKILL.md` | Insert new `## Phase B — Research` section, extend Phase A flag handling, update Phase E metadata population, bump version | Modified |
| `.claude/skills/discover-logformat/canary/README.md` | Add second test case (`--no-search` regression) and record manual-run results for `fortigate` | Modified |
| `docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md` | This plan | Created (this commit) |

No new source files. Plan v2 is strictly additive markdown changes to two existing files.

---

## Task Index

- [ ] **Task 1 — Extend Phase A (new flags + input requirement) and bump version** *(pending content fill)*
- [ ] **Task 2 — Insert Phase B research pipeline section** *(pending content fill)*
- [ ] **Task 3 — Update Phase C to merge samples and support metadata-only fallback** *(pending content fill)*
- [ ] **Task 4 — Update Phase E to populate real research_metadata and enrich source fields** *(pending content fill)*
- [ ] **Task 5 — Canary: regression `--no-search` run + structural fortigate research run** *(pending content fill)*

Task bodies will be filled in across follow-up commits. When all four tasks are filled in, the plan is ready to execute.

---

## Tasks

### Task 1 — Extend Phase A with new flags, relax sample requirement, bump version

**Goal:** Replace the Phase A "A.1 Parse arguments" subsection with an updated flag parser that accepts `--description`, `--doc`, `--no-search`, makes `--sample` optional, and requires at least one input. Bump version in frontmatter.

**Files:**
- Modify: `.claude/skills/discover-logformat/SKILL.md` — frontmatter `version` and Phase A.1

- [ ] **Step 1: Bump version in frontmatter**

Use the Edit tool to replace `version: 0.1.0-mvp` with `version: 0.2.0-research` in the frontmatter.

Also replace the `argument-hint` line:

From: `argument-hint: "<source_id> --sample=<path>"`
To: `argument-hint: "<source_id> [--sample=<path>] [--doc=<url>] [--description=<text>] [--no-search]"`

- [ ] **Step 2: Replace Phase A.1**

Use the Edit tool to replace the entire `### A.1 Parse arguments` subsection (from the `### A.1 Parse arguments` line through and including the `### A.2 Normalize` heading's preceding blank line) with this content:

```markdown
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
```

- [ ] **Step 3: Verify**

Run:
```bash
grep -c "^version: 0.2.0-research" .claude/skills/discover-logformat/SKILL.md
```
Expected: `1`

```bash
grep -c "^version: 0.1.0-mvp" .claude/skills/discover-logformat/SKILL.md
```
Expected: `0`

```bash
grep -c "ExplicitInputs" .claude/skills/discover-logformat/SKILL.md
```
Expected: `1`

```bash
grep -c "At least one of" .claude/skills/discover-logformat/SKILL.md
```
Expected: `1`

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/discover-logformat/SKILL.md
git commit -m "$(cat <<'MSG'
feat(discover-logformat): v2 Phase A — new flags, sample optional

Task 1 of Plan v2. Adds --description, --doc, --no-search flags;
makes --sample optional (requiring at least one of sample/doc/description);
updates frontmatter to version 0.2.0-research and expands argument-hint.
Phase B and Phase C not yet updated — follow-up in later tasks.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md
MSG
)"
```

---

### Task 2 — Insert Phase B research pipeline

**Goal:** Insert a brand-new `## Phase B — Research` section between Phase A and Phase C. The section describes how the skill performs one WebSearch (unless `--no-search`), WebFetches up to 3 URLs (explicit `--doc` URLs first, then top search results), extracts research findings, and returns a `ResearchFindings` struct.

**Files:**
- Modify: `.claude/skills/discover-logformat/SKILL.md` — insert new section

- [ ] **Step 1: Find the insertion point**

Phase B must be inserted after the last line of Phase A (which ends after the A.4 collision-check description) and before the `## Phase C — Format analysis` heading. Use the `## Phase C — Format analysis` line as an anchor in your Edit's `old_string`.

- [ ] **Step 2: Insert Phase B**

Use the Edit tool to replace the line `## Phase C — Format analysis` with this block (Phase B content followed by the Phase C heading restored):

```markdown
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
```

- [ ] **Step 3: Verify**

Run:
```bash
grep -c "^## Phase B — Research" .claude/skills/discover-logformat/SKILL.md
```
Expected: `1`

```bash
grep -c "^### B\." .claude/skills/discover-logformat/SKILL.md
```
Expected: `6` (B.1 through B.6)

```bash
grep -c "ResearchFindings" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 4`

```bash
wc -l .claude/skills/discover-logformat/SKILL.md
```
Expected: approximately 340–380 lines.

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/discover-logformat/SKILL.md
git commit -m "$(cat <<'MSG'
feat(discover-logformat): v2 Phase B — research pipeline

Task 2 of Plan v2. Inserts new Phase B section with 6 subsections
(B.1 gate, B.2 clock start, B.3 fetch explicit docs, B.4 seed
WebSearch, B.5 extract findings, B.6 return ResearchFindings).
Runs by default; skipped only when --no-search AND no --doc URLs.
Hard cap of 3 WebFetch calls per invocation. Phase C still
unmodified — follow-up in Task 3.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md
MSG
)"
```

---

### Task 3 — Update Phase C to merge samples and support metadata-only fallback

**Goal:** Update Phase C so it uses the combined set of user-provided samples and research-found samples, and gracefully handles the case where no samples exist at all (metadata-only mode).

**Files:**
- Modify: `.claude/skills/discover-logformat/SKILL.md` — Phase C preamble and C.2/C.5

- [ ] **Step 1: Update the Phase C preamble**

Replace the short paragraph directly under `## Phase C — Format analysis` (the current text "Analyze the sample lines loaded in Phase A...") with this expanded preamble:

```markdown
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
```

- [ ] **Step 2: Update C.2 to note the combined sample set**

At the top of section `### C.2 Extract fields`, add a single sentence at the start (before the existing "Based on the detected format..." line):

```markdown
Operate on the combined sample set defined in the Phase C preamble (user samples + research samples, deduplicated, capped at 500 lines).
```

- [ ] **Step 3: Update C.5 Findings struct to include research metadata**

Replace the bullet list content of `### C.5 Build the Findings struct (in memory)` with this expanded version:

```markdown
At the end of Phase C, you have an in-memory `Findings` object with:
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
```

- [ ] **Step 4: Verify**

```bash
grep -c "metadata-only mode" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 3`

```bash
grep -c "combined sample set" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 2`

```bash
grep -c "ResearchFindings.field_hints" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 2`

```bash
wc -l .claude/skills/discover-logformat/SKILL.md
```
Expected: approximately 380–420 lines.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/discover-logformat/SKILL.md
git commit -m "$(cat <<'MSG'
feat(discover-logformat): v2 Phase C — merge samples, metadata-only mode

Task 3 of Plan v2. Updates Phase C to use the combined set of user
samples and research-found samples (deduplicated, capped at 500).
Adds metadata-only fallback for the case where no samples exist at
all — populates fields[] from ResearchFindings.field_hints, marks
format.type as unknown with 0.0 confidence, and excludes that 0.0
from the overall confidence mean. Extends the Findings struct to
carry vendor, product, vendor_description, and the full research
struct through to Phase E.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md
MSG
)"
```

---

### Task 4 — Update Phase E to populate real research_metadata and source fields

**Goal:** Update Phase E so the generated `SPEC.yaml` and `REPORT.md` reflect real research data instead of the v1 placeholders.

**Files:**
- Modify: `.claude/skills/discover-logformat/SKILL.md` — E.3 SPEC.yaml template and E.4 REPORT.md template

- [ ] **Step 1: Update the SPEC.yaml template**

Edit the SPEC.yaml template block inside E.3. Three changes:

**Change 1** — Replace the `source:` block (currently `vendor: unknown`, `product: unknown`, and the description that says "No external research was performed in the MVP") with:

```yaml
source:
  id: {{ source_id }}
  display_name: "{{ source_id humanized — replace underscores with spaces and title-case }}"
  vendor: {{ findings.vendor or "unknown" }}
  product: {{ findings.product or "unknown" }}
  description: >
    {{ findings.vendor_description or default_description }}
```

Where `default_description` is the v1 default sentence ("Draft discovery for {{ source_id }} produced from a log sample of {{ line_count }} lines.") — keep the v1 wording as the fallback.

**Change 2** — Replace the `research_metadata:` block (currently `sources_consulted: []`, `total_research_time_sec: 0`) with:

```yaml
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

**Change 3** — Nothing else in E.3 changes. Leave `generator_hints` alone.

- [ ] **Step 2: Update the REPORT.md template**

Edit the REPORT.md template block inside E.4. Replace the `## Sources Consulted` section (currently just says "None — offline MVP run. Web research is deferred to Plan v2.") with:

```markdown
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
```

Also update the `**Plan version:**` line in the REPORT.md template:

From: `**Plan version:** v1 MVP (offline only)`
To: `**Plan version:** v2 (research-enabled)`

- [ ] **Step 3: Verify**

```bash
grep -c "findings.vendor" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 2`

```bash
grep -c "findings.research.sources_consulted" .claude/skills/discover-logformat/SKILL.md
```
Expected: `≥ 2`

```bash
grep -c "v2 (research-enabled)" .claude/skills/discover-logformat/SKILL.md
```
Expected: `1`

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/discover-logformat/SKILL.md
git commit -m "$(cat <<'MSG'
feat(discover-logformat): v2 Phase E — populate real research_metadata

Task 4 of Plan v2. Updates the SPEC.yaml template to pull vendor,
product, and description from ResearchFindings hints (falling back
to "unknown" / v1 default description). Updates research_metadata
to emit real sources_consulted entries and actual elapsed time.
Updates the REPORT.md template with a Sources Consulted table that
lists URL, kind, trust, and retrieved timestamp. Plan version line
bumped to v2.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md
MSG
)"
```

---

### Task 5 — Canary: `--no-search` regression + structural fortigate research run

**Goal:** Verify (a) the v1 offline path still works under v2 by re-running `custom_internal_app` with `--no-search`, and (b) the new research path produces a non-empty SPEC.yaml with real sources for `fortigate`. Record both results in `canary/README.md`.

**Files:**
- Modify: `.claude/skills/discover-logformat/canary/README.md` — add new test case, update test runs table
- Create (during test): `.planning/discover/custom_internal_app/*` and `.planning/discover/fortigate/*` (deleted at end)

- [ ] **Step 1: Add the fortigate test case to `canary/README.md`**

Edit `canary/README.md` and insert a new test subsection after the existing `## Test: custom_internal_app (offline KV)` section, before `## Test runs`:

```markdown
## Test: fortigate (research-enabled, structural)

### Invocation

```
/discover-logformat fortigate --description="Fortinet FortiGate traffic logs"
```

This test runs Phase B with live WebSearch + WebFetch. Because search results are non-deterministic, assertions are STRUCTURAL only — we check that the pipeline ran and produced non-empty metadata, not that specific content was found.

### Expected assertions

| Check | Pass condition |
|---|---|
| Artifact layout | `SPEC.yaml`, `REPORT.md`, `research_trail.json`-optional, `samples/` directory must exist |
| `research_metadata.sources_consulted` | Non-empty list (`yq '.research_metadata.sources_consulted \| length' > 0`) |
| `source.vendor` | NOT equal to `unknown` (research must have found something) |
| `research_metadata.total_research_time_sec` | `> 0` |
| REPORT.md "Sources Consulted" section | Contains at least one table row with a URL |

### Failure modes

If the test fails on the vendor check, research may have failed to extract a vendor hint — inspect REPORT.md for what it did find and decide whether to iterate Phase B.5 extraction rules.
```

- [ ] **Step 2: Run the `--no-search` regression**

Delete any stale output:
```bash
rm -rf .planning/discover/custom_internal_app
```

Invoke the skill as Claude would when the user types:
```
/discover-logformat custom_internal_app --sample=.claude/skills/discover-logformat/canary/custom_internal_app.log --no-search
```

Read `.claude/skills/discover-logformat/SKILL.md` and perform Phases A, B, C, E step by step. With `--no-search` and no `--doc` URLs, Phase B should be entirely skipped (per B.1) — the result must be structurally identical to the v1 baseline: 6 required fields, format = kv, empty `sources_consulted`, `total_research_time_sec: 0`.

Verify with:
```bash
find .planning/discover/custom_internal_app -type f | sort
diff .claude/skills/discover-logformat/canary/custom_internal_app.log .planning/discover/custom_internal_app/samples/user_provided.log
grep -c "^  type: kv" .planning/discover/custom_internal_app/SPEC.yaml
grep -c "sources_consulted:" .planning/discover/custom_internal_app/SPEC.yaml
grep -c "total_research_time_sec: 0" .planning/discover/custom_internal_app/SPEC.yaml
grep -E "^  - name: (ts|level|component|user|action|result)$" .planning/discover/custom_internal_app/SPEC.yaml | wc -l
```

All of:
- diff = empty
- type kv = 1
- sources_consulted present = 1
- total_research_time_sec: 0 = 1
- required fields = 6

Must hold. If any fail, stop and debug.

- [ ] **Step 3: Run the fortigate research test**

Delete any stale output:
```bash
rm -rf .planning/discover/fortigate
```

Invoke the skill as Claude would when the user types:
```
/discover-logformat fortigate --description="Fortinet FortiGate traffic logs"
```

Read SKILL.md and perform all phases including live research. Phase B will:
1. Skip B.1 (research is NOT disabled — no `--no-search`).
2. Record start time.
3. Skip B.3 (no `--doc` URLs).
4. Execute B.4: WebSearch with query `fortigate Fortinet FortiGate traffic logs log format`. Fetch top 3 vendor-doc results.
5. Extract findings from each page.
6. Return ResearchFindings.

Then Phase C runs on any research-found samples (and the empty user-sample set) or falls back to metadata-only if no samples were found. Phase E writes artifacts.

Verify with:
```bash
test -f .planning/discover/fortigate/SPEC.yaml && echo "SPEC.yaml: present"
test -f .planning/discover/fortigate/REPORT.md && echo "REPORT.md: present"
grep -c "^  vendor:" .planning/discover/fortigate/SPEC.yaml
grep "vendor:" .planning/discover/fortigate/SPEC.yaml
grep -c "sources_consulted:" .planning/discover/fortigate/SPEC.yaml
grep -A 20 "sources_consulted:" .planning/discover/fortigate/SPEC.yaml
```

Structural pass conditions:
- SPEC.yaml and REPORT.md exist
- `vendor:` line in SPEC.yaml is NOT `vendor: unknown`
- `sources_consulted:` contains at least one `- url:` entry

If any of these fail, stop and investigate. Common causes:
- WebSearch returned nothing → try a different description
- All WebFetches failed → network issue
- Extraction logic missed the vendor field → iterate B.5 rules

- [ ] **Step 4: Record results in `canary/README.md`**

Get today's UTC date:
```bash
date -u +"%Y-%m-%d"
```

Append two new rows to the "## Test runs" table in `canary/README.md`, directly under the existing v1 row. Format:

```
| <YYYY-MM-DD> | PASS | v2 research | custom_internal_app --no-search regression |
| <YYYY-MM-DD> | PASS | v2 research | fortigate research (structural) — <N> sources found |
```

Where `<N>` is the actual count of entries in `sources_consulted[]` after the fortigate run.

- [ ] **Step 5: Commit**

```bash
git add .claude/skills/discover-logformat/canary/README.md
git commit -m "$(cat <<'MSG'
test(discover-logformat): v2 canary — regression + fortigate research

Task 5 of Plan v2. Adds the fortigate structural research test case
to canary/README.md with assertions on SPEC.yaml/REPORT.md existence,
non-empty sources_consulted, and vendor != unknown. Records PASS
rows for both the --no-search regression and the live fortigate run.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat-v2-research.md
MSG
)"
```

- [ ] **Step 6: Clean up scratch output**

```bash
rm -rf .planning/discover/custom_internal_app .planning/discover/fortigate
git status --short | grep -i discover
```

Expected: empty output.

---

## Plan completion criteria

Plan v2 is complete when:
1. All 5 task checkboxes above are filled in.
2. The two canary commits exist (`--no-search` regression and fortigate research).
3. `git status --short | grep discover` is empty.
4. The skill file at `.claude/skills/discover-logformat/SKILL.md` has `version: 0.2.0-research` in its frontmatter.
