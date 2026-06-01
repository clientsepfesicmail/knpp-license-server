-- Tezhisab Central Platform — Phase 3 Migration
-- Run this ONCE in Supabase SQL Editor before deploying Phase 3 backend files.
-- Safe for the existing Phase 2.2 database: existing customers, licenses and app versions are preserved.

-- -------------------------------------------------------------------------
-- Keep Phase 2 central-cloud columns available in this consolidated migration.
-- -------------------------------------------------------------------------
alter table if exists app_versions add column if not exists storage_provider text not null default 'external';
alter table if exists app_versions add column if not exists storage_key text default '';
alter table if exists app_versions add column if not exists original_filename text default '';
alter table if exists app_versions add column if not exists content_type text default '';
alter table if exists app_versions add column if not exists size_bytes bigint not null default 0;
alter table if exists app_versions add column if not exists uploaded_by text default '';

create table if not exists download_logs (
  id bigserial primary key,
  version_id bigint references app_versions(id) on delete set null,
  customer_email text default '',
  license_key text default '',
  product_code text default '',
  channel_code text default '',
  ip_address text default '',
  user_agent text default '',
  downloaded_at timestamptz not null default now()
);

create index if not exists idx_download_logs_downloaded_at on download_logs(downloaded_at desc);
create index if not exists idx_download_logs_customer_email on download_logs(lower(customer_email));
create index if not exists idx_app_versions_storage_key on app_versions(storage_key);

-- -------------------------------------------------------------------------
-- Customer-specific product editions.
-- STANDARD edition remains represented by NULL edition_id for backward compatibility.
-- -------------------------------------------------------------------------
create table if not exists product_editions (
  id bigserial primary key,
  product_code text not null,
  edition_code text not null,
  edition_name text not null,
  release_scope text not null default 'customer_specific'
    check (release_scope in ('customer_specific','selected_customers')),
  customer_id bigint references customers(id) on delete set null,
  status text not null default 'active' check (status in ('active','inactive')),
  notes text default '',
  created_at timestamptz not null default now()
);

create unique index if not exists idx_product_editions_product_code_unique
  on product_editions(upper(product_code), upper(edition_code));
create index if not exists idx_product_editions_customer_id on product_editions(customer_id);

create table if not exists edition_customers (
  id bigserial primary key,
  edition_id bigint not null references product_editions(id) on delete cascade,
  customer_id bigint not null references customers(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique(edition_id, customer_id)
);

alter table if exists licenses add column if not exists edition_id bigint references product_editions(id) on delete set null;
alter table if exists app_versions add column if not exists edition_id bigint references product_editions(id) on delete set null;
create index if not exists idx_licenses_edition_id on licenses(edition_id);
create index if not exists idx_app_versions_edition_id on app_versions(edition_id);

-- Earlier versions may have enforced uniqueness using only channel_id + version.
-- Replace it with channel + edition + version so separate customer releases can use the same version number safely.
do $$
declare r record;
begin
  for r in
    select c.conname
    from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public'
      and t.relname = 'app_versions'
      and c.contype = 'u'
      and pg_get_constraintdef(c.oid) ilike '%channel_id%'
      and pg_get_constraintdef(c.oid) ilike '%version%'
  loop
    execute format('alter table public.app_versions drop constraint if exists %I', r.conname);
  end loop;
end $$;

drop index if exists idx_app_versions_channel_version;
do $$
declare r record;
begin
  for r in
    select indexname
    from pg_indexes
    where schemaname = 'public'
      and tablename = 'app_versions'
      and indexdef ilike '%unique%'
      and indexdef ilike '%channel_id%'
      and indexdef ilike '%version%'
      and indexname <> 'idx_app_versions_channel_edition_version'
  loop
    execute format('drop index if exists public.%I', r.indexname);
  end loop;
end $$;
create unique index if not exists idx_app_versions_channel_edition_version
  on app_versions(channel_id, coalesce(edition_id, 0), version);

-- -------------------------------------------------------------------------
-- Self-registration and requirement workflow.
-- -------------------------------------------------------------------------
alter table if exists customers add column if not exists approved_at timestamptz;
alter table if exists customers add column if not exists approved_by text default '';
alter table if exists customers add column if not exists rejection_reason text default '';
alter table if exists customers add column if not exists status text not null default 'active';
alter table if exists portal_users add column if not exists status text not null default 'active';

-- Allow self-registration statuses even if an earlier setup used a narrower CHECK constraint.
do $$
declare r record;
begin
  for r in
    select c.conname, t.relname
    from pg_constraint c
    join pg_class t on t.oid = c.conrelid
    join pg_namespace n on n.oid = t.relnamespace
    where n.nspname = 'public'
      and t.relname in ('customers','portal_users')
      and c.contype = 'c'
      and pg_get_constraintdef(c.oid) ilike '%status%'
  loop
    execute format('alter table public.%I drop constraint if exists %I', r.relname, r.conname);
  end loop;
end $$;

alter table if exists customers drop constraint if exists customers_status_phase3_check;
alter table if exists customers add constraint customers_status_phase3_check check (status in ('active','pending','rejected','inactive','suspended','disabled'));
alter table if exists portal_users drop constraint if exists portal_users_status_phase3_check;
alter table if exists portal_users add constraint portal_users_status_phase3_check check (status in ('active','pending','rejected','inactive','suspended','disabled'));

create table if not exists customer_requirements (
  id bigserial primary key,
  customer_id bigint references customers(id) on delete set null,
  submitted_by_email text not null default '',
  contact_name text default '',
  business_name text default '',
  phone text default '',
  product_code text default '',
  request_type text not null default 'software_requirement',
  title text not null default 'Software requirement',
  details text not null default '',
  status text not null default 'pending'
    check (status in ('pending','reviewing','approved','completed','rejected')),
  admin_notes text default '',
  reviewed_by text default '',
  reviewed_at timestamptz,
  attachment_storage_key text default '',
  attachment_filename text default '',
  attachment_content_type text default '',
  attachment_size_bytes bigint not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists idx_customer_requirements_customer_id on customer_requirements(customer_id);
create index if not exists idx_customer_requirements_status on customer_requirements(status);
create index if not exists idx_customer_requirements_created_at on customer_requirements(created_at desc);
create index if not exists idx_customer_requirements_email on customer_requirements(lower(submitted_by_email));

-- -------------------------------------------------------------------------
-- Tutorial video manager.
-- -------------------------------------------------------------------------
create table if not exists tutorial_videos (
  id bigserial primary key,
  title text not null,
  product_code text default '',
  category text default 'Tutorial',
  video_url text not null,
  thumbnail_url text default '',
  description text default '',
  visibility text not null default 'public'
    check (visibility in ('public','customer_only','selected_customer')),
  customer_id bigint references customers(id) on delete set null,
  sort_order integer not null default 100,
  status text not null default 'active' check (status in ('active','inactive')),
  created_at timestamptz not null default now()
);

create index if not exists idx_tutorial_videos_visibility on tutorial_videos(visibility, status);
create index if not exists idx_tutorial_videos_customer_id on tutorial_videos(customer_id);
create index if not exists idx_tutorial_videos_sort_order on tutorial_videos(sort_order);
