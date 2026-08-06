# CISA / SCuBA Coverage Roadmap

> Generated daily by `.github/workflows/cisa-roadmap.yml` (`scripts/roadmap/cisa-scan.py`). Do not edit by hand: changes are overwritten on the next scan. This is a deterministic diff of upstream CISA SCuBA baselines against the checks Guerrilla ships. No AI is involved.

Last scan: **2026-08-06 13:45 UTC**

## Upstream state

| Source | Latest | Notes |
|---|---|---|
| ScubaGear (M365 / Entra) | [v1.8.0](https://github.com/cisagov/ScubaGear/releases/tag/v1.8.0) (2026-05-07) | MS.* Secure Configuration Baselines |
| ScubaGoggles (Google Workspace) | [v1.0.1](https://github.com/cisagov/ScubaGoggles/releases/tag/v1.0.1) (2026-07-28) | GWS.* Secure Configuration Baselines |
| CISA KEV catalog | 2026.08.06 (2026-08-06) | 1661 known-exploited CVEs |
| CISA BOD 25-01 | [SCuBA mandate](https://www.cisa.gov/news-events/directives/binding-operational-directive-25-01) | Secure cloud baselines for FCEB M365 |

## SCuBA coverage summary

Coverage compares the base policy ID (version tag stripped) so a version bump does not read as a lost mapping; version drift is tracked separately.

| Baseline | Upstream policies | Covered by Guerrilla | Gap |
|---|---|---|---|
| ScubaGear MS.* | 170 | 79 | **91** |
| ScubaGoggles GWS.* | 137 | 95 | **42** |

Guerrilla references 80 MS.* and 95 GWS.* policy IDs today.

## ScubaGear (M365 / Entra) gaps

91 upstream policies have no Guerrilla check yet (candidate roadmap items):

- [ ] `MS.AAD.3.9`
- [ ] `MS.AAD.5.4`
- [ ] `MS.AAD.9.1`
- [ ] `MS.DEFENDER.1.4`
- [ ] `MS.DEFENDER.1.5`
- [ ] `MS.DEFENDER.2.3`
- [ ] `MS.DEFENDER.4.2`
- [ ] `MS.DEFENDER.4.3`
- [ ] `MS.DEFENDER.4.4`
- [ ] `MS.DEFENDER.4.5`
- [ ] `MS.DEFENDER.4.6`
- [ ] `MS.DEFENDER.6.2`
- [ ] `MS.EXO.10.1`
- [ ] `MS.EXO.10.2`
- [ ] `MS.EXO.10.3`
- [ ] `MS.EXO.11.1`
- [ ] `MS.EXO.11.2`
- [ ] `MS.EXO.11.3`
- [ ] `MS.EXO.12.1`
- [ ] `MS.EXO.12.2`
- [ ] `MS.EXO.14.1`
- [ ] `MS.EXO.14.2`
- [ ] `MS.EXO.14.3`
- [ ] `MS.EXO.15.1`
- [ ] `MS.EXO.15.2`
- [ ] `MS.EXO.15.3`
- [ ] `MS.EXO.16.1`
- [ ] `MS.EXO.16.2`
- [ ] `MS.EXO.17.1`
- [ ] `MS.EXO.17.2`
- [ ] `MS.EXO.17.3`
- [ ] `MS.EXO.2.1`
- [ ] `MS.EXO.8.1`
- [ ] `MS.EXO.8.2`
- [ ] `MS.EXO.8.3`
- [ ] `MS.EXO.8.4`
- [ ] `MS.EXO.9.1`
- [ ] `MS.EXO.9.2`
- [ ] `MS.EXO.9.3`
- [ ] `MS.EXO.9.4`
- [ ] `MS.EXO.9.5`
- [ ] `MS.POWERBI.1.1`
- [ ] `MS.POWERBI.2.1`
- [ ] `MS.POWERBI.3.1`
- [ ] `MS.POWERBI.4.1`
- [ ] `MS.POWERBI.4.2`
- [ ] `MS.POWERBI.5.1`
- [ ] `MS.POWERBI.6.1`
- [ ] `MS.POWERBI.7.1`
- [ ] `MS.POWERPLATFORM.4.1`
- [ ] `MS.POWERPLATFORM.5.1`
- [ ] `MS.POWERPLATFORM.6.1`
- [ ] `MS.SECURITYSUITE.1.1`
- [ ] `MS.SECURITYSUITE.1.2`
- [ ] `MS.SECURITYSUITE.1.3`
- [ ] `MS.SECURITYSUITE.1.4`
- [ ] `MS.SECURITYSUITE.15.2`
- [ ] `MS.SECURITYSUITE.2.1`
- [ ] `MS.SECURITYSUITE.2.2`
- [ ] `MS.SECURITYSUITE.2.3`
- [ ] `MS.SECURITYSUITE.2.4`
- [ ] `MS.SECURITYSUITE.3.1`
- [ ] `MS.SECURITYSUITE.3.2`
- [ ] `MS.SECURITYSUITE.3.3`
- [ ] `MS.SECURITYSUITE.3.4`
- [ ] `MS.SECURITYSUITE.3.5`
- [ ] `MS.SECURITYSUITE.4.1`
- [ ] `MS.SECURITYSUITE.4.2`
- [ ] `MS.SECURITYSUITE.5.1`
- [ ] `MS.SECURITYSUITE.5.2`
- [ ] `MS.SECURITYSUITE.6.1`
- [ ] `MS.SECURITYSUITE.6.2`
- [ ] `MS.SECURITYSUITE.7.1`
- [ ] `MS.SECURITYSUITE.7.2`
- [ ] `MS.SECURITYSUITE.7.3`
- [ ] `MS.SECURITYSUITE.8.1`
- [ ] `MS.SECURITYSUITE.8.2`
- [ ] `MS.SHAREPOINT.1.4`
- [ ] `MS.SHAREPOINT.3.3`
- [ ] `MS.SHAREPOINT.4.1`
- [ ] `MS.SHAREPOINT.4.2`
- [ ] `MS.TEAMS.1.4`
- [ ] `MS.TEAMS.1.5`
- [ ] `MS.TEAMS.3.1`
- [ ] `MS.TEAMS.4.1`
- [ ] `MS.TEAMS.6.1`
- [ ] `MS.TEAMS.6.2`
- [ ] `MS.TEAMS.7.1`
- [ ] `MS.TEAMS.7.2`
- [ ] `MS.TEAMS.8.1`
- [ ] `MS.TEAMS.8.2`

Version drift (Guerrilla references an older policy version than upstream):

- `MS.DEFENDER.4.1v1 -> MS.DEFENDER.4.1v2`

## ScubaGoggles (Google Workspace) gaps

42 upstream policies have no Guerrilla check yet (candidate roadmap items):

- [ ] `GWS.CALENDAR.3.2`
- [ ] `GWS.CHAT.5.1`
- [ ] `GWS.CHAT.5.2`
- [ ] `GWS.COMMONCONTROLS.10.1`
- [ ] `GWS.COMMONCONTROLS.10.2`
- [ ] `GWS.COMMONCONTROLS.11.1`
- [ ] `GWS.COMMONCONTROLS.12.1`
- [ ] `GWS.COMMONCONTROLS.13.1`
- [ ] `GWS.COMMONCONTROLS.14.1`
- [ ] `GWS.COMMONCONTROLS.14.2`
- [ ] `GWS.COMMONCONTROLS.16.3`
- [ ] `GWS.COMMONCONTROLS.16.4`
- [ ] `GWS.COMMONCONTROLS.17.1`
- [ ] `GWS.COMMONCONTROLS.18.1`
- [ ] `GWS.COMMONCONTROLS.18.2`
- [ ] `GWS.COMMONCONTROLS.2.1`
- [ ] `GWS.COMMONCONTROLS.3.1`
- [ ] `GWS.COMMONCONTROLS.3.2`
- [ ] `GWS.COMMONCONTROLS.6.1`
- [ ] `GWS.COMMONCONTROLS.6.2`
- [ ] `GWS.COMMONCONTROLS.7.1`
- [ ] `GWS.COMMONCONTROLS.8.3`
- [ ] `GWS.COMMONCONTROLS.9.1`
- [ ] `GWS.COMMONCONTROLS.9.2`
- [ ] `GWS.DRIVEDOCS.1.10`
- [ ] `GWS.DRIVEDOCS.1.11`
- [ ] `GWS.DRIVEDOCS.1.3`
- [ ] `GWS.DRIVEDOCS.1.4`
- [ ] `GWS.DRIVEDOCS.1.5`
- [ ] `GWS.DRIVEDOCS.1.7`
- [ ] `GWS.DRIVEDOCS.5.1`
- [ ] `GWS.DRIVEDOCS.5.2`
- [ ] `GWS.GMAIL.13.1`
- [ ] `GWS.GMAIL.17.1`
- [ ] `GWS.GMAIL.18.2`
- [ ] `GWS.GMAIL.18.3`
- [ ] `GWS.GMAIL.4.3`
- [ ] `GWS.GMAIL.4.4`
- [ ] `GWS.GMAIL.5.5`
- [ ] `GWS.GMAIL.7.6`
- [ ] `GWS.MEET.6.1`
- [ ] `GWS.MEET.6.2`

## Newest CISA KEV entries

Broader CISA context (CVE-level, not directly a config baseline):

- `CVE-2026-63077` JetBrains TeamCity Deserialization of Untrusted Data Vulnerability (added 2026-08-05)
- `CVE-2026-18556` N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability (added 2026-08-04)
- `CVE-2026-34486` Apache Tomcat Missing Encryption of Sensitive Data Vulnerability (added 2026-08-04)
- `CVE-2026-9198` IBM Langflow Code Injection Vulnerability (added 2026-08-04)
- `CVE-2026-18577` N-able N-central Authentication Bypass Using an Alternate Path or Channel Vulnerability (added 2026-08-03)

## Scan log

Most recent first. One entry per day the scanner ran.

### 2026-08-06
- KEV catalog 2026.08.04 -> 2026.08.06 (+1 entries, now 1661)

### 2026-08-05
- KEV catalog 2026.08.03 -> 2026.08.04 (+3 entries, now 1660)

### 2026-08-04
- KEV catalog 2026.07.29 -> 2026.08.03 (+1 entries, now 1657)

### 2026-08-03
- Initial CISA/SCuBA baseline snapshot captured: ScubaGear 170 MS.* policies, ScubaGoggles 137 GWS.* policies, KEV 1656 CVEs.
