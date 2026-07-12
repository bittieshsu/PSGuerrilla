## What this PR does

<!-- One or two sentences. If it implements a proposed check, link the issue. -->

## Checklist

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full expectations.

- [ ] Every check added or changed ships with fixtures: at minimum a clean
      `PASS`, a known-bad `FAIL` (or `WARN`), and an uncollectable
      `Not Assessed` case under `Tests/Fixtures/`.
- [ ] Checks with multiple verdict branches declare their `verdictPaths`, and a
      fixture exercises each declared path.
- [ ] Check definitions in `source/Data/AuditChecks/` declare a
      `zeroTrustPillar` and `zeroTrustWeight`, and only claim `compliance`
      mappings the check actually implements.
- [ ] A check never returns `PASS` for data it could not read; uncollectable
      input returns `SKIP` (rendered as Not Assessed).
- [ ] `pwsh Tests/Invoke-FixtureTests.ps1` is green, and the Pester Unit suite
      (`Tests/Unit/`) passes.
- [ ] No hand-edited counts anywhere: published numbers derive from the gating
      test run's artifact, never from manual edits.
- [ ] PSScriptAnalyzer is clean:
      `Invoke-ScriptAnalyzer -Path . -Recurse -Settings .PSScriptAnalyzerSettings.psd1`
