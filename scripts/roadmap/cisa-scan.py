#!/usr/bin/env python3
"""
Deterministic CISA / SCuBA roadmap scanner.

No AI, no external packages: standard library only (urllib, json, re). It fetches
a fixed set of machine-readable CISA sources, compares them against the snapshot
stored in docs/roadmap/state/, and regenerates docs/roadmap/cisa-scuba-roadmap.md
as a live gap analysis of upstream SCuBA policies vs. the checks Guerrilla ships.

Sources (SCuBA core + broader CISA):
  - cisagov/ScubaGear      (M365 / Entra Secure Configuration Baselines, MS.* policy IDs)
  - cisagov/ScubaGoggles   (Google Workspace Secure Configuration Baselines, GWS.* policy IDs)
  - CISA Known Exploited Vulnerabilities (KEV) catalog feed
  - CISA BOD 25-01 (SCuBA mandate) reference pointer

Run from the repo root. Exit code is 0 on success, or if a single source is
transiently unreachable (the previous snapshot for that source is retained and
the outage is logged) so the daily job does not go red on a network blip.
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
AUDIT_DIR = os.path.join(REPO_ROOT, "source", "Data", "AuditChecks")
STATE_DIR = os.path.join(REPO_ROOT, "docs", "roadmap", "state")
ROADMAP_MD = os.path.join(REPO_ROOT, "docs", "roadmap", "cisa-scuba-roadmap.md")

UPSTREAM_STATE = os.path.join(STATE_DIR, "upstream.json")
SCANLOG_STATE = os.path.join(STATE_DIR, "scanlog.json")
SCANLOG_CAP = 120

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
NOW = datetime.now(timezone.utc)
TODAY = NOW.strftime("%Y-%m-%d")
NOW_STR = NOW.strftime("%Y-%m-%d %H:%M UTC")

MS_ID = re.compile(r"MS\.[A-Z0-9]+\.\d+\.\d+v\d+(?:\.\d+)*")
GWS_ID = re.compile(r"GWS\.[A-Z0-9]+\.\d+\.\d+v\d+(?:\.\d+)*")
BASE_OF = re.compile(r"(.*?)v\d+(?:\.\d+)*$")
VER_OF = re.compile(r"v(\d+(?:\.\d+)*)$")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BOD_2501_URL = "https://www.cisa.gov/news-events/directives/binding-operational-directive-25-01"


def base_id(full):
    """Strip the trailing version tag: MS.AAD.1.1v1 -> MS.AAD.1.1."""
    m = BASE_OF.match(full)
    return m.group(1) if m else full


def canonicalize(ids):
    """Collapse each policy to its highest upstream version.

    Baseline markdown mentions a policy's current version plus older versions in
    changelog tables; keep only the max version per base ID so the daily diff is
    stable and version drift is measured against the current upstream version.
    """
    best = {}
    for i in ids:
        m = VER_OF.search(i)
        if not m:
            continue
        ver = tuple(int(x) for x in m.group(1).split("."))
        b = base_id(i)
        if b not in best or ver > best[b][0]:
            best[b] = (ver, i)
    return {v[1] for v in best.values()}


def http(url, as_json=False, token=None, timeout=45):
    req = urllib.request.Request(url, headers={
        "User-Agent": "guerrilla-cisa-roadmap-scanner",
        "Accept": "application/vnd.github+json" if "api.github.com" in url else "*/*",
    })
    if token and "github" in url:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", "replace")
    return json.loads(raw) if as_json else raw


# --- sources -----------------------------------------------------------------

def latest_release(repo):
    """Return {tag, date, url} for a repo's latest release, or None on failure."""
    try:
        d = http(f"https://api.github.com/repos/{repo}/releases/latest", as_json=True, token=GITHUB_TOKEN)
        return {"tag": d.get("tag_name", "?"),
                "date": (d.get("published_at", "") or "")[:10],
                "url": d.get("html_url", "")}
    except Exception as e:
        print(f"  [warn] latest_release({repo}) failed: {e}", file=sys.stderr)
        return None


def baseline_ids(repo, id_re):
    """Walk the repo tree for baselines/*.md and extract policy IDs (with version)."""
    try:
        info = http(f"https://api.github.com/repos/{repo}", as_json=True, token=GITHUB_TOKEN)
        branch = info.get("default_branch", "main")
        tree = http(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1",
                    as_json=True, token=GITHUB_TOKEN)
        md_paths = [n["path"] for n in tree.get("tree", [])
                    if n.get("type") == "blob"
                    and "baseline" in n["path"].lower()
                    and n["path"].lower().endswith(".md")]
        ids = set()
        for path in md_paths:
            try:
                text = http(f"https://raw.githubusercontent.com/{repo}/{branch}/{path}")
                ids.update(id_re.findall(text))
            except Exception as e:
                print(f"  [warn] fetch {repo}/{path} failed: {e}", file=sys.stderr)
        return ids
    except Exception as e:
        print(f"  [warn] baseline_ids({repo}) failed: {e}", file=sys.stderr)
        return None


def kev_summary():
    try:
        d = http(KEV_URL, as_json=True)
        vulns = d.get("vulnerabilities", [])
        newest = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:5]
        return {"catalogVersion": d.get("catalogVersion", "?"),
                "count": d.get("count", len(vulns)),
                "date": d.get("dateReleased", "")[:10],
                "newest": [{"cve": v.get("cveID"), "name": v.get("vulnerabilityName", ""),
                            "added": v.get("dateAdded", "")} for v in newest]}
    except Exception as e:
        print(f"  [warn] kev_summary failed: {e}", file=sys.stderr)
        return None


def covered_ids(id_re):
    """SCuBA IDs already referenced by Guerrilla's shipped check definitions."""
    ids = set()
    if not os.path.isdir(AUDIT_DIR):
        return ids
    for fn in os.listdir(AUDIT_DIR):
        if not fn.endswith(".json"):
            continue
        try:
            text = open(os.path.join(AUDIT_DIR, fn), encoding="utf-8").read()
        except Exception:
            continue
        ids.update(id_re.findall(text))
    return ids


# --- state -------------------------------------------------------------------

def load_json(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


# --- diff & gap analysis -----------------------------------------------------

def gap_analysis(upstream_ids, covered):
    """Compare on base IDs; also surface version drift (covered vN < upstream vM)."""
    up_base = {base_id(i): i for i in sorted(upstream_ids)}
    cov_base = {base_id(i): i for i in sorted(covered)}
    gaps = sorted(b for b in up_base if b not in cov_base)          # upstream, not covered
    covered_hits = sorted(b for b in up_base if b in cov_base)      # covered
    drift = sorted(f"{cov_base[b]} -> {up_base[b]}"
                   for b in up_base if b in cov_base and cov_base[b] != up_base[b])
    orphan = sorted(cov_base[b] for b in cov_base if b not in up_base)  # covered id not in current upstream
    return {"upstream_total": len(up_base), "covered": len(covered_hits),
            "gap_count": len(gaps), "gaps": gaps, "drift": drift, "orphans": orphan}


def diff_sets(old, new):
    o, n = set(old or []), set(new or [])
    return sorted(n - o), sorted(o - n)  # added, removed


# --- main --------------------------------------------------------------------

def main():
    os.chdir(REPO_ROOT)
    print(f"CISA/SCuBA scan at {NOW_STR}")

    prev = load_json(UPSTREAM_STATE, {})
    scanlog = load_json(SCANLOG_STATE, [])

    # Fetch (fall back to previous snapshot on failure so a blip is not fatal).
    sg_rel = latest_release("cisagov/ScubaGear") or prev.get("scubagear", {}).get("release")
    gg_rel = latest_release("cisagov/ScubaGoggles") or prev.get("scubagoggles", {}).get("release")
    ms_ids = baseline_ids("cisagov/ScubaGear", MS_ID)
    gws_ids = baseline_ids("cisagov/ScubaGoggles", GWS_ID)
    kev = kev_summary() or prev.get("kev")

    unreachable = []
    if ms_ids is None:
        ms_ids = set(prev.get("scubagear", {}).get("ids", [])); unreachable.append("ScubaGear baselines")
    else:
        ms_ids = canonicalize(ms_ids)
    if gws_ids is None:
        gws_ids = set(prev.get("scubagoggles", {}).get("ids", [])); unreachable.append("ScubaGoggles baselines")
    else:
        gws_ids = canonicalize(gws_ids)
    if kev is None:
        unreachable.append("KEV feed")

    cov_ms = covered_ids(MS_ID)
    cov_gws = covered_ids(GWS_ID)
    ms_gap = gap_analysis(ms_ids, cov_ms)
    gws_gap = gap_analysis(gws_ids, cov_gws)

    # Compute changes vs previous snapshot.
    seed = not prev.get("scubagear", {}).get("ids")
    changes = []
    if seed:
        changes.append(f"Initial CISA/SCuBA baseline snapshot captured: "
                       f"ScubaGear {ms_gap['upstream_total']} MS.* policies, "
                       f"ScubaGoggles {gws_gap['upstream_total']} GWS.* policies, "
                       f"KEV {kev.get('count','?') if kev else '?'} CVEs.")
    else:
        p_sg = (prev.get("scubagear", {}).get("release") or {}).get("tag")
        if sg_rel and sg_rel.get("tag") != p_sg and p_sg is not None:
            changes.append(f"ScubaGear release {p_sg} -> {sg_rel['tag']} ({sg_rel.get('date','')})")
        p_gg = (prev.get("scubagoggles", {}).get("release") or {}).get("tag")
        if gg_rel and gg_rel.get("tag") != p_gg and p_gg is not None:
            changes.append(f"ScubaGoggles release {p_gg} -> {gg_rel['tag']} ({gg_rel.get('date','')})")

        ms_add, ms_rem = diff_sets(prev.get("scubagear", {}).get("ids"), sorted(ms_ids))
        if ms_add: changes.append(f"ScubaGear new policies: {', '.join(ms_add)}")
        if ms_rem: changes.append(f"ScubaGear removed policies: {', '.join(ms_rem)}")
        gws_add, gws_rem = diff_sets(prev.get("scubagoggles", {}).get("ids"), sorted(gws_ids))
        if gws_add: changes.append(f"ScubaGoggles new policies: {', '.join(gws_add)}")
        if gws_rem: changes.append(f"ScubaGoggles removed policies: {', '.join(gws_rem)}")

        p_kev = (prev.get("kev") or {}).get("catalogVersion")
        if kev and p_kev is not None and kev.get("catalogVersion") != p_kev:
            p_count = (prev.get("kev") or {}).get("count", 0)
            delta = kev.get("count", 0) - p_count
            changes.append(f"KEV catalog {p_kev} -> {kev.get('catalogVersion')} "
                           f"({'+' if delta >= 0 else ''}{delta} entries, now {kev.get('count')})")

    for u in unreachable:
        changes.append(f"NOTE: {u} unreachable this run; retained last known snapshot")

    # Scan-log entry every day (guarantees a daily commit even with no upstream change).
    entry = {"date": TODAY, "at": NOW_STR,
             "changes": changes if changes else ["No upstream changes detected."]}
    # Collapse same-day reruns into the latest entry.
    scanlog = [e for e in scanlog if e.get("date") != TODAY]
    scanlog.insert(0, entry)
    scanlog = scanlog[:SCANLOG_CAP]

    # Persist new snapshot.
    new_state = {
        "scubagear": {"release": sg_rel, "ids": sorted(ms_ids)},
        "scubagoggles": {"release": gg_rel, "ids": sorted(gws_ids)},
        "kev": kev,
        "generated": NOW_STR,
    }
    save_json(UPSTREAM_STATE, new_state)
    save_json(SCANLOG_STATE, scanlog)

    write_roadmap(sg_rel, gg_rel, kev, ms_gap, gws_gap, cov_ms, cov_gws, scanlog)
    print("Wrote", os.path.relpath(ROADMAP_MD, REPO_ROOT))
    if changes:
        print("Changes this run:")
        for c in changes:
            print("  -", c)


def write_roadmap(sg_rel, gg_rel, kev, ms_gap, gws_gap, cov_ms, cov_gws, scanlog):
    def rel(r):
        if not r: return "unknown"
        return f"[{r.get('tag','?')}]({r.get('url','')}) ({r.get('date','')})"

    L = []
    L.append("# CISA / SCuBA Coverage Roadmap")
    L.append("")
    L.append("> Generated daily by `.github/workflows/cisa-roadmap.yml` "
             "(`scripts/roadmap/cisa-scan.py`). Do not edit by hand: changes are overwritten "
             "on the next scan. This is a deterministic diff of upstream CISA SCuBA baselines "
             "against the checks Guerrilla ships. No AI is involved.")
    L.append("")
    L.append(f"Last scan: **{NOW_STR}**")
    L.append("")
    L.append("## Upstream state")
    L.append("")
    L.append("| Source | Latest | Notes |")
    L.append("|---|---|---|")
    L.append(f"| ScubaGear (M365 / Entra) | {rel(sg_rel)} | MS.* Secure Configuration Baselines |")
    L.append(f"| ScubaGoggles (Google Workspace) | {rel(gg_rel)} | GWS.* Secure Configuration Baselines |")
    if kev:
        L.append(f"| CISA KEV catalog | {kev.get('catalogVersion','?')} ({kev.get('date','')}) "
                 f"| {kev.get('count','?')} known-exploited CVEs |")
    L.append(f"| CISA BOD 25-01 | [SCuBA mandate]({BOD_2501_URL}) | Secure cloud baselines for FCEB M365 |")
    L.append("")
    L.append("## SCuBA coverage summary")
    L.append("")
    L.append("Coverage compares the base policy ID (version tag stripped) so a version bump "
             "does not read as a lost mapping; version drift is tracked separately.")
    L.append("")
    L.append("| Baseline | Upstream policies | Covered by Guerrilla | Gap |")
    L.append("|---|---|---|---|")
    L.append(f"| ScubaGear MS.* | {ms_gap['upstream_total']} | {ms_gap['covered']} | **{ms_gap['gap_count']}** |")
    L.append(f"| ScubaGoggles GWS.* | {gws_gap['upstream_total']} | {gws_gap['covered']} | **{gws_gap['gap_count']}** |")
    L.append("")
    L.append(f"Guerrilla references {len(cov_ms)} MS.* and {len(cov_gws)} GWS.* policy IDs today.")
    L.append("")

    def gap_section(title, gap):
        L.append(f"## {title}")
        L.append("")
        if gap["gaps"]:
            L.append(f"{len(gap['gaps'])} upstream policies have no Guerrilla check yet "
                     "(candidate roadmap items):")
            L.append("")
            for g in gap["gaps"]:
                L.append(f"- [ ] `{g}`")
        else:
            L.append("No gaps: every upstream policy in this baseline maps to a Guerrilla check.")
        L.append("")
        if gap["drift"]:
            L.append("Version drift (Guerrilla references an older policy version than upstream):")
            L.append("")
            for d in gap["drift"]:
                L.append(f"- `{d}`")
            L.append("")
        if gap["orphans"]:
            L.append("Guerrilla references these IDs that are not in the current upstream "
                     "baseline (renamed, retired, or ahead of upstream): "
                     + ", ".join(f"`{o}`" for o in gap["orphans"]))
            L.append("")

    gap_section("ScubaGear (M365 / Entra) gaps", ms_gap)
    gap_section("ScubaGoggles (Google Workspace) gaps", gws_gap)

    if kev and kev.get("newest"):
        L.append("## Newest CISA KEV entries")
        L.append("")
        L.append("Broader CISA context (CVE-level, not directly a config baseline):")
        L.append("")
        for v in kev["newest"]:
            L.append(f"- `{v.get('cve')}` {v.get('name','')} (added {v.get('added','')})")
        L.append("")

    L.append("## Scan log")
    L.append("")
    L.append("Most recent first. One entry per day the scanner ran.")
    L.append("")
    for e in scanlog:
        L.append(f"### {e['date']}")
        for c in e["changes"]:
            L.append(f"- {c}")
        L.append("")

    os.makedirs(os.path.dirname(ROADMAP_MD), exist_ok=True)
    with open(ROADMAP_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(L).rstrip() + "\n")


if __name__ == "__main__":
    main()
