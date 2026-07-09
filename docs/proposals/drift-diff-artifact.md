# Proposal: drift diff artifact for scheduled re-assessment alerting

Status: DESIGN ONLY. Nothing here ships in this pass. The purpose is to fix the
shape of two artifacts now so the drift work (targeted for a later release) does
not have to redesign them, and so a third party could consume them without our
help.

## The two principles this design adopts

1. **Structured, machine-readable run results are a first-class output.** A run
   emits a plain data artifact, not just console text or an HTML report. Any
   notifier can consume it: our own `Send-Signal`, a webhook, a SIEM ingest, or
   a CI step written by someone we will never meet. The output is the contract;
   the notifier is pluggable.
2. **Alert on change, not on state.** A control that has been failing for six
   months must not page anyone. A control that passed last run and fails this run
   must. The unit of alerting is the transition between two runs, not the current
   verdict.

## The one assumption this design refuses

That CI is the scheduler, the state store, and the notifier. That model presumes
the operator already has a pipeline. Ours often does not, which is the entire
reason `Register-Patrol` exists: the watcher is a scheduled task (Task Scheduler,
launchd, cron) that writes run results to a local ledger, and the notifier reads
the diff between the last two runs. The artifact format below is deliberately
neutral so that the same files could later be produced and consumed by a GitHub
Action with no change to their shape. The mechanism is swappable; the artifact is
the fixed point.

## Artifact 1: run-result.json (one per assessment run)

The output of running the fixture-proven checks against a real tenant. This is
the first-class structured output. It is derived, never hand-authored, and it
carries only what the run observed.

```jsonc
{
  "schemaVersion": 1,
  "tool": "Guerrilla",
  "moduleVersion": "2.46.4",
  "generatedAt": "2026-07-09T18:00:00Z",
  "runId": "<opaque id, e.g. the timestamp>",
  "scope": {
    // Non-sensitive identifiers only. A tenant hash, not a tenant name.
    "theaters": ["Reconnaissance", "Infiltration", "Fortification"],
    "targetHash": "<sha256 of the tenant/domain identifier>"
  },
  "results": [
    {
      "checkId": "EIDCA-003",
      "verdict": "FAIL",            // PASS | FAIL | WARN | "Not Assessed"
      "severity": "High",
      "theater": "Infiltration"
    }
    // ... one row per check that ran
  ],
  "summary": { "pass": 0, "fail": 0, "warn": 0, "notAssessed": 0, "total": 0 }
}
```

Notes:
- `verdict` uses the same four values the catalog and fixtures use, so a run
  result and a fixture scenario speak the same language.
- `Not Assessed` is a real, recorded verdict, not an omission. A control that
  became uncollectable is data, not silence. See the absence-of-evidence rule.
- Run results are written to a local ledger under the per-user data root
  (`.../Guerrilla/patrol/<runId>.json`). The ledger is the state store the CI
  model would otherwise assume.

## Artifact 2: drift.json (the diff the notifier reads)

Computed from the current run and the previous run in the ledger. Only
transitions appear. Steady state is summarized as a count, never enumerated, so
a long-failing control cannot generate noise.

```jsonc
{
  "schemaVersion": 1,
  "tool": "Guerrilla",
  "moduleVersion": "2.46.4",
  "generatedAt": "2026-07-09T18:00:00Z",
  "previousRun": { "runId": "...", "generatedAt": "..." },
  "currentRun":  { "runId": "...", "generatedAt": "..." },
  "changes": [
    {
      "checkId": "EIDCA-003",
      "severity": "High",
      "theater": "Infiltration",
      "from": "PASS",
      "to": "FAIL",
      "kind": "newly-failing"
    }
  ],
  "summary": {
    "newlyFailing": 0,      // PASS/WARN -> FAIL
    "regressed": 0,         // PASS -> WARN
    "resolved": 0,          // FAIL/WARN -> PASS
    "lostVisibility": 0,    // assessed -> Not Assessed
    "restoredVisibility": 0,// Not Assessed -> assessed
    "unchanged": 0          // count only; not enumerated
  },
  "baselineRun": false       // true when there is no previous run to diff against
}
```

### Transition taxonomy and default alert disposition

| kind | transition | default |
|------|-----------|---------|
| newly-failing | PASS or WARN to FAIL | alert |
| regressed | PASS to WARN | alert (configurable) |
| lost-visibility | assessed to Not Assessed | alert: you could see a control and now cannot |
| resolved | FAIL or WARN to PASS | informational, off by default |
| restored-visibility | Not Assessed to assessed | informational, off by default |
| unchanged | same verdict | never alerted |

The first run against a tenant has no previous run. It sets `baselineRun: true`
and emits no change alerts; it only establishes the baseline in the ledger. This
is the correct behavior: the first run is not a change.

## How the notifier consumes it

The notifier reads `drift.json` and applies a minimum-severity and
which-kinds filter (for example, alert on `newly-failing` and `lost-visibility`
at High and above). It never needs to understand how the run was scheduled or
where the ledger lives. `Send-Signal` becomes one such notifier; a GitHub Action
that posts to a PR could be another, reading the identical `drift.json`.

## What this buys, and what it deliberately leaves open

Buys: a stable contract so the drift feature can be built against a known shape,
and so external consumers are possible without a redesign.

Left open (on purpose, to be decided when the feature is built):
- The exact ledger retention policy and pruning.
- Whether `resolved` transitions are batched into a periodic digest.
- Config surface for per-kind, per-severity alert routing.

## Ground rules honored

Verify, do not assert. No third-party tool is named. No em dashes. Every number
in a run result is observed by the run, never stored ahead of it. Where a control
cannot be assessed, the run says `Not Assessed` rather than staying silent.
