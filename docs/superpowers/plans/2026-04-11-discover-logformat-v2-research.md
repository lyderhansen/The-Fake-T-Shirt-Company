# discover-logformat Plan v2 — minimal research

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the smallest useful research capability to `discover-logformat` — accept `--description=<text>` and `--doc=<url>` flags, perform a single WebSearch seed, WebFetch up to 3 URLs, and populate `research_metadata.sources_consulted` in the resulting `SPEC.yaml`. After this plan, the skill can enrich a sample-based draft with vendor context found on the web.

**Architecture:** Additive — Phase B is inserted between Phase A (input validation) and Phase C (format analysis) in SKILL.md. Phase A is extended to parse the new flags. Phase C is unchanged. Phase E is updated only to populate `research_metadata` with real data instead of the placeholder empty lists. Version bumps `0.1.0-mvp` → `0.2.0-research`.

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
- `--description=<text>` flag (required if no sample, otherwise optional seed)
- `--doc=<url>` flag (optional, repeatable, each URL fetched via WebFetch)
- `--no-search` flag (opt out of WebSearch entirely, useful for offline runs)
- One WebSearch call using `<source_id> <description>` as query (skipped if `--no-search`)
- Up to 3 WebFetch calls total — prioritize explicit `--doc` URLs, then top search results
- Per-source `trust` score: `explicit-doc` = 1.0, `search-result` = 0.7
- `research_metadata.sources_consulted` populated with real `{url, kind, retrieved_at, trust}`
- `research_metadata.total_research_time_sec` recorded as elapsed wall time for Phase B
- `source.vendor`, `source.product`, `source.description` enriched from research content when available
- Version bump in frontmatter
- One new canary test: `custom_internal_app` re-run with `--no-search` (verifies flag gating works and existing path is unbroken)
- Manual smoke test with real network: `/discover-logformat fortigate --description="Fortinet FortiGate traffic logs"` — recorded in canary/README.md

**Out of scope for Plan v2 (explicitly deferred):**
- Iterative research loop (fetch-until-confidence-threshold)
- `--min-sources`, `--max-research-time`, `--threshold` flags (v3)
- Splunkbase scraping via Firecrawl MCP (v3)
- `--ta=<splunkbase-id>` flag (v3)
- Community forum fallback (v4)
- Confidence gates + Q&A (v5)
- Updating `add-generator` (v6)
- Global promotion (v7)
- Research that loops back into format detection (v3) — v2 research runs AFTER Phase C, not before
- Research truncation handling — v2 caps each WebFetch at the tool's default page size

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

- [ ] **Task 1 — Extend Phase A to parse new flags** *(pending content fill)*
- [ ] **Task 2 — Insert Phase B research section with minimal pipeline** *(pending content fill)*
- [ ] **Task 3 — Update Phase E to populate real research_metadata** *(pending content fill)*
- [ ] **Task 4 — Canary regression run (`--no-search`) + manual fortigate smoke test** *(pending content fill)*

Task bodies will be filled in across follow-up commits. When all four tasks are filled in, the plan is ready to execute.

---

## Tasks

<!-- Task bodies added incrementally in follow-up commits. -->
