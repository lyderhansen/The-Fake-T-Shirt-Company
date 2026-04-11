# discover-logformat Implementation Plan — MVP slice (Plan v1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the smallest useful version of the `discover-logformat` skill — an offline-only, project-local Claude Code skill that reads a provided log sample, detects its format, and writes a draft `SPEC.yaml` plus minimal `REPORT.md` to `.planning/discover/<source_id>/`.

**Architecture:** Monolithic markdown skill (`.claude/skills/discover-logformat/SKILL.md`) with only Phases A (input validation), C (format analysis), and E (artifact writing). Phases B (research), D (confidence gates + Q&A), and F (fancy handoff) are deferred to later plan documents. No Python is written — this is a Claude-instruction skill. Verification is a single manual canary run against a hand-crafted log fixture.

**Tech Stack:** Claude Code skill framework (markdown + YAML frontmatter), Bash (for directory setup only), Git (commit per task). No Python, no pytest, no external dependencies.

**Relationship to other plans:**
- **Plan v1 (this doc):** offline MVP — sample in, SPEC.yaml out.
- **Plan v2 (future):** add Phase B research (WebSearch/WebFetch/Firecrawl).
- **Plan v3 (future):** add Phase D confidence gates and interactive Q&A.
- **Plan v4 (future):** update `add-generator` skill to consume `SPEC.yaml`.
- **Plan v5 (future):** promote `discover-logformat` from project-local to global `~/.claude/skills/`.

**Source of truth:** `docs/superpowers/specs/2026-04-11-discover-logformat-design.md`. The spec describes the full six-phase skill; this plan only implements a subset.

---

## Scope — in and out

**In scope for Plan v1:**
- Project-local skill at `.claude/skills/discover-logformat/`
- Accepts only `--sample=<path>` (required in v1; no optional flags yet)
- Detects format: `json`, `kv`, `csv`, `cef`, `syslog`, `xml`, `unknown`
- Extracts a best-effort field list from samples
- Writes `.planning/discover/<source_id>/SPEC.yaml` with `schema_version: 1`
- Writes `.planning/discover/<source_id>/REPORT.md` with a short summary
- Writes the original sample to `.planning/discover/<source_id>/samples/user_provided.log`
- One canary smoke test: `custom_internal_app` (offline, hand-crafted fixture)

**Out of scope for Plan v1 (explicitly deferred):**
- Phase B: web research (`--doc`, `--ta`, `--description`, proactive search, `--min-sources`, `--max-research-time`, `--no-search`)
- Phase D: confidence gates, interactive Q&A, `--threshold`, `--interactive`, `--batch`
- `scenarios.existing` and `scenarios.proposed` inside `generator_hints` (written as empty lists)
- `props_draft.conf` file (deferred to Plan v4)
- `research_trail.json` (deferred — no research yet)
- CIM post-pass (`cim_hints.md`)
- Collision handling (interactive choice) — v1 simply refuses to overwrite and tells the user to delete the old directory
- add-generator integration — add-generator keeps its existing behavior
- CHANGEHISTORY.md entry — added once Plan v1 is complete
- Global skill sync — stays project-local

---

## File Structure

Files created or modified by this plan:

| Path | Purpose | Created/Modified |
|---|---|---|
| `.claude/skills/discover-logformat/SKILL.md` | The skill itself — frontmatter + Phases A, C, E | Created |
| `.claude/skills/discover-logformat/canary/custom_internal_app.log` | Hand-crafted KV-format sample for the smoke test | Created |
| `.claude/skills/discover-logformat/canary/README.md` | Success criteria for the canary smoke test | Created |
| `docs/superpowers/plans/2026-04-11-discover-logformat.md` | This plan | Created (this commit) |

No existing files are modified in Plan v1. The MVP is strictly additive.

---

## Task Index

- [ ] **Task 1 — Scaffold skill directory and SKILL.md frontmatter** *(pending content fill)*
- [ ] **Task 2 — Create canary fixture** *(pending content fill)*
- [ ] **Task 3 — Define canary success criteria** *(pending content fill)*
- [ ] **Task 4 — SKILL.md Phase A (input) + Phase C (format analysis)** *(pending content fill)*
- [ ] **Task 5 — SKILL.md Phase E (artifact writing)** *(pending content fill)*
- [ ] **Task 6 — Execute canary smoke test and record results** *(pending content fill)*

Task bodies will be filled in across subsequent plan-writing commits. When all six tasks are filled in, the plan moves to the "ready to execute" state.

---

## Tasks

<!-- Task bodies added incrementally in follow-up commits. Each task will specify exact files, exact content to write, and how to verify the result. -->
