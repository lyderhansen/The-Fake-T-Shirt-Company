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

- [ ] **Task 1 — Scaffold skill directory and SKILL.md frontmatter**
- [ ] **Task 2 — Create canary fixture**
- [ ] **Task 3 — Define canary success criteria** *(pending content fill)*
- [ ] **Task 4 — SKILL.md Phase A (input) + Phase C (format analysis)** *(pending content fill)*
- [ ] **Task 5 — SKILL.md Phase E (artifact writing)** *(pending content fill)*
- [ ] **Task 6 — Execute canary smoke test and record results** *(pending content fill)*

Task bodies will be filled in across subsequent plan-writing commits. When all six tasks are filled in, the plan moves to the "ready to execute" state.

---

## Tasks

### Task 1 — Scaffold skill directory and SKILL.md frontmatter

**Goal:** Create the skill directory and an empty-but-valid `SKILL.md` with frontmatter and the three phase section headers. After this task, running `/discover-logformat` would match as a skill but do nothing useful yet. This is the "hello world" shell.

**Files:**
- Create: `.claude/skills/discover-logformat/` (directory)
- Create: `.claude/skills/discover-logformat/SKILL.md`

- [ ] **Step 1: Verify skill directory does not already exist**

Run:
```bash
ls .claude/skills/discover-logformat/ 2>&1
```

Expected: `ls: .claude/skills/discover-logformat/: No such file or directory`

If the directory already exists, STOP and consult with the user — we must not accidentally overwrite existing work.

- [ ] **Step 2: Create the skill directory**

Run:
```bash
mkdir -p .claude/skills/discover-logformat
```

Expected: silent success. Verify with `ls .claude/skills/discover-logformat/` which should show an empty directory.

- [ ] **Step 3: Create `SKILL.md` with frontmatter and section headers**

Write the file `.claude/skills/discover-logformat/SKILL.md` with exactly this content:

````markdown
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
````

- [ ] **Step 4: Verify the file parses as a valid skill**

Run:
```bash
head -10 .claude/skills/discover-logformat/SKILL.md
```

Expected: the frontmatter between `---` markers is visible, starting with `name: discover-logformat`. Confirm the `name`, `description`, `version`, and `metadata.argument-hint` fields are present.

Run:
```bash
wc -l .claude/skills/discover-logformat/SKILL.md
```

Expected: approximately 35–45 lines.

- [ ] **Step 5: Commit**

Run:
```bash
git add .claude/skills/discover-logformat/SKILL.md
git commit -m "$(cat <<'MSG'
feat(discover-logformat): scaffold skill with frontmatter and phase headers

Task 1 of the discover-logformat MVP plan. Creates the skill directory
and an empty-but-valid SKILL.md containing frontmatter plus section
headers for Phase A, Phase C, and Phase E. Phases will be populated
in subsequent tasks. MVP is offline-only; research and Q&A deferred.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat.md
MSG
)"
```

Expected: single-file commit. Verify with `git log --oneline -1`.

---

### Task 2 — Create canary fixture

**Goal:** Hand-craft a small KV-format log file that represents a fictional internal application. This fixture is the only input the skill will process during the MVP canary run. Because it is hand-crafted, we know the exact ground truth: 6 fields, KV format, no timestamps inside the events.

**Files:**
- Create: `.claude/skills/discover-logformat/canary/custom_internal_app.log`

- [ ] **Step 1: Verify canary directory does not already exist**

Run:
```bash
ls .claude/skills/discover-logformat/canary/ 2>&1
```

Expected: `ls: .claude/skills/discover-logformat/canary/: No such file or directory`

- [ ] **Step 2: Create the canary directory**

Run:
```bash
mkdir -p .claude/skills/discover-logformat/canary
```

- [ ] **Step 3: Write the canary log fixture**

Write the file `.claude/skills/discover-logformat/canary/custom_internal_app.log` with exactly this content (12 lines, KV format, no header, LF line endings):

```
ts=2026-01-05T08:14:22Z level=info component=auth user=alice.reyes action=login result=success
ts=2026-01-05T08:14:27Z level=info component=auth user=bob.nguyen action=login result=success
ts=2026-01-05T08:15:03Z level=warn component=api user=alice.reyes action=export_csv result=denied reason=quota_exceeded
ts=2026-01-05T08:15:44Z level=info component=api user=bob.nguyen action=query_customers result=success rows=128
ts=2026-01-05T08:16:12Z level=error component=worker user=system action=enqueue_job result=failure reason=redis_timeout
ts=2026-01-05T08:16:58Z level=info component=auth user=carol.lee action=login result=success
ts=2026-01-05T08:17:31Z level=info component=api user=carol.lee action=upload_file result=success rows=1
ts=2026-01-05T08:18:05Z level=warn component=auth user=unknown action=login result=failure reason=bad_password
ts=2026-01-05T08:18:47Z level=info component=worker user=system action=dequeue_job result=success
ts=2026-01-05T08:19:22Z level=info component=api user=alice.reyes action=query_orders result=success rows=42
ts=2026-01-05T08:20:01Z level=info component=api user=bob.nguyen action=delete_record result=success
ts=2026-01-05T08:20:38Z level=error component=auth user=system action=rotate_keys result=failure reason=hsm_unreachable
```

Notes on the fixture design:
- Format is pure KV, space-separated, unquoted values.
- `ts` is an ISO-8601 timestamp embedded in the event (no syslog header).
- Six base fields appear in every line: `ts`, `level`, `component`, `user`, `action`, `result`.
- Two optional fields appear in some lines only: `reason` (errors/warnings) and `rows` (data queries).
- Values contain no spaces or escape characters — keeps the parser test simple.

- [ ] **Step 4: Verify the fixture**

Run:
```bash
wc -l .claude/skills/discover-logformat/canary/custom_internal_app.log
```

Expected: `12 .claude/skills/discover-logformat/canary/custom_internal_app.log`

Run:
```bash
head -1 .claude/skills/discover-logformat/canary/custom_internal_app.log
```

Expected: `ts=2026-01-05T08:14:22Z level=info component=auth user=alice.reyes action=login result=success`

- [ ] **Step 5: Commit**

Run:
```bash
git add .claude/skills/discover-logformat/canary/custom_internal_app.log
git commit -m "$(cat <<'MSG'
test(discover-logformat): add canary fixture custom_internal_app.log

Task 2 of the discover-logformat MVP plan. Hand-crafted 12-line KV-format
log fixture for the offline canary smoke test. Six base fields plus two
conditional fields (reason, rows). Pure KV, no syslog header, unquoted
values. Used as the sole input during Task 6 verification.

Plan: docs/superpowers/plans/2026-04-11-discover-logformat.md
MSG
)"
```
