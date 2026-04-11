# discover-logformat canary suite

Manual smoke test for the offline MVP of `discover-logformat`.

## Test: custom_internal_app (offline KV)

### Invocation (executed by a human or agent)

```
/discover-logformat custom_internal_app --sample=.claude/skills/discover-logformat/canary/custom_internal_app.log
```

### Expected artifact layout

After a successful run, the following files must exist:

```
.planning/discover/custom_internal_app/
├── SPEC.yaml
├── REPORT.md
└── samples/
    └── user_provided.log
```

### Expected SPEC.yaml contents (required fields)

Minimum assertions on `SPEC.yaml`:

| Field | Expected value |
|---|---|
| `schema_version` | `1` |
| `source.id` | `custom_internal_app` |
| `source.display_name` | any non-empty string |
| `category` | any value from the allowed list in the spec (the MVP may leave this as `unknown`) |
| `format.type` | `kv` |
| `format.confidence` | ≥ `0.8` |
| `sourcetype.name` | any non-empty string containing `custom_internal_app` or `internal:app` |
| `fields` | list with at least 6 entries |
| `fields[].name` must include | `ts`, `level`, `component`, `user`, `action`, `result` |
| `sample_events` | list with at least 1 entry, each with a non-empty `raw` |
| `generator_hints.suggested_module_name` | `generate_custom_internal_app` |
| `generator_hints.suggested_function_name` | `generate_custom_internal_app_logs` |
| `generator_hints.volume_category` | any non-empty string |
| `generator_hints.baseline_events_per_day` | `1000` |
| `generator_hints.scenarios.existing` | empty list `[]` (MVP has no scenario discovery) |
| `generator_hints.scenarios.proposed` | empty list `[]` |
| `research_metadata.sources_consulted` | empty list `[]` (offline MVP — no research) |
| `research_metadata.overall_confidence` | any value between `0.0` and `1.0` |

### Expected REPORT.md contents

Must contain:
- A top-level heading `# Discovery Report: custom_internal_app`
- A `## Format` section stating the format is `kv`
- A `## Fields` section listing at least the 6 required fields
- A `## Sources Consulted` section stating "None — offline MVP run"
- A `## Next Steps` section referencing `/add-generator custom_internal_app`

### Expected samples/user_provided.log

Must be a byte-identical copy of `.claude/skills/discover-logformat/canary/custom_internal_app.log` (12 lines, same content).

## Test runs

Update this section after each canary execution in Task 6.

| Date (UTC) | Result | Plan version | Notes |
|---|---|---|---|
| *(not yet run)* | — | v1 MVP | — |
