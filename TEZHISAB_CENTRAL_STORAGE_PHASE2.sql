-- Tezhisab Central Platform — Phase 2 Central Cloud Upload
-- Run this ONCE in Supabase SQL Editor before deploying the Phase 2 backend.
-- It preserves all existing users, licenses, products, channels and published versions.

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
