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

*(Populated in Task 4.)*

## Phase C — Format analysis

*(Populated in Task 4.)*

## Phase E — Artifact writing

*(Populated in Task 5.)*
