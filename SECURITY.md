# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and click **Report a vulnerability**. That creates a private
advisory only the maintainer can see. Please do not open a public issue for a
security problem, and do not include tenant data or credentials in a report.

## Scope

This policy covers the Guerrilla PowerShell module and everything in this
repository: the collectors, the check functions, the report generation, the
credential handling (safehouse/vault), the run-history store, and the release
tooling.

## What matters most

Guerrilla is read-only by design: it audits Active Directory, Entra ID, and
Google Workspace without installing agents or writing to the systems it
assesses. Findings that contradict that design are the highest-value reports:

- any code path that writes to, or modifies, an assessed environment,
- credential material leaking into reports, exports, logs, or the run history,
- a check that can be made to render a false PASS for state it did not read,
- injection through collected tenant data into the HTML report or exports.

Ordinary wrong-verdict bugs are welcome too, but those can go through the
public **Report a wrong verdict** issue template instead.

## What to expect

Reports are handled in good faith and answered as quickly as a single
maintainer reasonably can, normally within a few days. You will get an
acknowledgment, an assessment of whether it is reproducible and in scope, and
credit in the release notes for a confirmed report unless you ask not to be
named. Please allow a fix to ship before disclosing publicly.
