-- PSGuerrilla golden-fixture test tracking schema.
-- Run once in the Supabase SQL editor (Dashboard -> SQL Editor -> New query).
--
-- Two tables:
--   guerrilla_test_runs    : one row per suite execution (summary)
--   guerrilla_test_results : one row per check/scenario (expected vs actual)
--
-- The publisher (Tests/Supabase/Publish-GuerrillaTestResults.ps1) inserts via
-- the PostgREST REST API using the service-role key.

create extension if not exists "pgcrypto";

create table if not exists public.guerrilla_test_runs (
    id            uuid primary key default gen_random_uuid(),
    created_at    timestamptz not null default now(),
    suite         text        not null default 'golden-fixtures',
    git_sha       text,
    git_branch    text,
    host          text,
    runner        text,                       -- user/CI identifier
    total         integer     not null,
    passed        integer     not null,
    failed        integer     not null,
    duration_ms   integer,
    module_version text
);

create table if not exists public.guerrilla_test_results (
    id              bigint generated always as identity primary key,
    run_id          uuid not null references public.guerrilla_test_runs(id) on delete cascade,
    created_at      timestamptz not null default now(),
    check_id        text not null,            -- e.g. ADPRIV-001
    family          text not null,            -- AD | Entra | GoogleWorkspace
    theater         text,                     -- Reconnaissance | Infiltration | Fortification
    scenario        text not null,            -- clean | known-bad | throttled | no-data
    severity        text,                     -- from the real check definition
    expected_status text not null,            -- PASS | FAIL | WARN | SKIP
    actual_status   text not null,
    passed          boolean not null,
    fixture_file    text,
    description     text
);

create index if not exists idx_gtr_run_id   on public.guerrilla_test_results (run_id);
create index if not exists idx_gtr_check_id on public.guerrilla_test_results (check_id);
create index if not exists idx_gtr_failed   on public.guerrilla_test_results (passed) where passed = false;

-- Convenience view: latest known status per check/scenario, for a coverage map.
create or replace view public.guerrilla_latest_results as
select distinct on (r.check_id, r.scenario)
       r.check_id, r.family, r.scenario, r.severity,
       r.expected_status, r.actual_status, r.passed, r.created_at
from public.guerrilla_test_results r
order by r.check_id, r.scenario, r.created_at desc;
