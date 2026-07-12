# Proposal: GRLA- prefix and provenance schema (Task 6)

Status: EXECUTED in v2.46.4 (2026-07-09). This is the reviewed design, kept for the record. The four fields were added to every check definition (618 at the time of execution; the catalog has grown since) and to the check DB, seven checks were classified `original`, and `Tests/Unit/ProvenanceSchema.Tests.ps1` gates the schema. Build-ahead remains empty (no build-ahead checks yet). The original proposal text follows as approved.

## 1. Goal

Introduce a first-class notion of a Guerrilla-original check and the provenance of every check, so the website's SCuBA view and the homepage build-ahead table read from data, never from a hand-maintained list. Four new fields, added everywhere from the start (not as a later migration):

| Field | Type | Nullable | Meaning |
|-------|------|----------|---------|
| `provenance` | enum: `baseline` \| `original` \| `build-ahead` | no (default `baseline`) | Where the check comes from. |
| `source_url` | string | yes | Where the roadmap or research that motivated the check was read. |
| `source_read_date` | ISO-8601 date | yes | When that source was read. |
| `official_id` | string | yes | The framework control ID once a baseline catches up (crosswalk target). |

`provenance` values:
- `baseline`: implements a control that a published baseline already defines (the check maps to NIST / MITRE / CIS / EIDSCA / SCuBA). This is the default for the entire catalog as it stood at the time of writing (618 checks).
- `original`: an attack path no baseline models yet (OAuth delegation takeover, super-admin sprawl, partner/GDAP delegated access). Carries no `official_id` because none exists.
- `build-ahead`: derived from a published baseline roadmap (an issue tracker, a release checklist) before the control ships. Carries `source_url` + `source_read_date` now, and gains `official_id` later when the control lands.

## 2. The GRLA- prefix

Guerrilla-original checks (`provenance` = `original` or `build-ahead`) get the ID prefix `GRLA-`, so an original check reads e.g. `GRLA-OAUTH-001`, distinct from baseline-derived families (`EIDCA-`, `ADACL-`, `GWS-...`). Rationale: the prefix makes originals self-identifying in the catalog, the DB, and report output, and lets the site filter them without a join.

Important: renaming an EXISTING check's ID is a breaking change (fixtures, crosswalks, report history, the golden-fixture filenames, and any customer risk-acceptance records key off the ID). So:
- New Guerrilla-original checks are BORN as `GRLA-...`.
- Existing checks that are conceptually original but already shipped under a family prefix are NOT renamed. Instead they are tagged `provenance = original` in place, and (optionally) carry an alias. We do not rewrite existing IDs.

## 3. Where the fields live

Two stores, kept in sync, DB is authoritative for the site:

1. `Data/AuditChecks/*.json` (module source of truth for definitions). Add the four keys to each check object. Default `provenance: "baseline"`, the other three `null`, unless the check is an original/build-ahead.
2. `psguerrilla_checks` (SQLite, what the website generator reads). Add four columns:
   ```sql
   ALTER TABLE psguerrilla_checks ADD COLUMN provenance TEXT NOT NULL DEFAULT 'baseline';
   ALTER TABLE psguerrilla_checks ADD COLUMN source_url TEXT;
   ALTER TABLE psguerrilla_checks ADD COLUMN source_read_date TEXT;
   ALTER TABLE psguerrilla_checks ADD COLUMN official_id TEXT;
   ```
   (SQLite ADD COLUMN is non-destructive and backfills the default.)

A `provenance` schema test (like the existing Zero Trust schema test) enforces: value in the enum; `original` has null `official_id`; `build-ahead` has a non-null `source_url` and `source_read_date`; `baseline` may map to frameworks. Red test blocks publish.

## 4. Migration plan for the existing catalog (618 checks at the time of writing; reviewable, staged)

Nothing is rewritten blindly. The migration is a backfill, run once, reviewable as a diff:

1. Set `provenance = 'baseline'` for every current check (the default). This is a no-op semantically and touches no IDs.
2. Reclassify the known originals to `provenance = 'original'` from an explicit, reviewed allow-list of check IDs (the ones the spec names: OAuth delegation takeover, super-admin sprawl, partner/GDAP delegated access, plus any others you confirm). This is a small hand-curated list, applied by ID, shown to you as a diff before it lands.
3. Leave `source_url` / `source_read_date` / `official_id` null for baseline and original checks.
4. `build-ahead`: none today. New build-ahead checks are added going forward with all four fields populated at creation.

The order matters: step 1 is a bulk default (safe), step 2 is a tiny reviewed reclassification (safe, by ID), and no ID is renamed. The full-catalog change is therefore one default backfill plus a handful of by-ID updates, not a mass rewrite.

## 5. How a build-ahead check gains its official_id later

When a standards body ships the control a build-ahead check anticipated:
1. Add the new framework mapping to the check's `frameworks` (e.g. `scuba:MS.AAD.X.Yv1`).
2. Set `official_id` to that control ID.
3. Optionally flip `provenance` from `build-ahead` to `baseline` (now that a baseline defines it), keeping `source_url` / `source_read_date` as the historical record that Guerrilla built it first.

This is a per-check, reviewed edit, and the crosswalk on the site updates automatically because it reads `official_id` + `frameworks`.

## 6. How the site reads these fields (no hand-maintained lists)

- SCuBA baseline view: already reads `frameworks` (`scuba:` entries). With `official_id`, a build-ahead check that pre-dates a SCuBA control shows up under that control the moment `official_id` is set, with a "built ahead of the baseline" note driven by `provenance` + `source_read_date`.
- Homepage build-ahead table: `SELECT check_id, name, provenance, source_url, source_read_date, official_id FROM psguerrilla_checks WHERE provenance = 'build-ahead'`. If the query returns nothing, the table renders empty with an honest line ("the first build-ahead checks are in development"). It can never overstate, because it can only show what the DB holds.
- Original checks: `WHERE provenance = 'original'` powers a "Guerrilla-original" section; no `official_id` is shown because none exists.

## 7. Copy tense (per the spec)

Homepage copy describes method and intent, not accomplished output: "standards bodies develop in public, and Guerrilla builds toward what is coming." The past-tense claim ("ships controls before the baselines do") is only earned per-check, once `official_id` is set and the crosswalk proves it. The build-ahead table is the evidence; the copy points at it rather than asserting ahead of it.

## 8. What I need from you before executing

1. Confirm the four fields + enum values as above.
2. Confirm the GRLA- prefix rule (new originals born GRLA-, existing checks tagged in place, no ID renames).
3. Provide / confirm the allow-list of existing check IDs to reclassify as `provenance = 'original'`.
4. Confirm the two-store approach (JSON + DB columns) and the provenance schema test as the gate.

On your go, I will: add the columns + JSON keys, run the staged backfill, add the schema test, and show you the full diff before anything publishes.
