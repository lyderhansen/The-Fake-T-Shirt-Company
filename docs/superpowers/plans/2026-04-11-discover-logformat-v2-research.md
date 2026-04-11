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

<!-- Task bodies added incrementally in follow-up commits. -->
