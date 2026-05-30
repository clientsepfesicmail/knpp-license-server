-- Tezhisab Central Platform — Phase 1
-- Run once in Supabase SQL Editor before deploying the upgraded license server.
-- This single script preserves the existing license data and adds portal tables.

create table if not exists licenses (
  key text primary key,
  product text not null default 'EEM',
  client_name text not null,
  client_phone text default '',
  client_email text default '',
  max_pcs integer not null default 3,
  machines jsonb not null default '[]'::jsonb,
  activated_on date not null default current_date,
  expires_on date not null default (current_date + interval '365 days')::date,
  last_verified date,
  status text not null default 'active',
  notes text default ''
);

alter table licenses add column if not exists product text not null default 'EEM';
alter table licenses add column if not exists client_phone text default '';
alter table licenses add column if not exists client_email text default '';
alter table licenses add column if not exists max_pcs integer not null default 3;
alter table licenses add column if not exists machines jsonb not null default '[]'::jsonb;
alter table licenses add column if not exists activated_on date not null default current_date;
alter table licenses add column if not exists expires_on date not null default (current_date + interval '365 days')::date;
alter table licenses add column if not exists last_verified date;
alter table licenses add column if not exists status text not null default 'active';
alter table licenses add column if not exists notes text default '';

create table if not exists products (
  id bigserial primary key,
  product_name text not null,
  product_code text not null unique,
  prefix_code text not null,
  default_limit integer not null default 3,
  status text not null default 'active',
  sort_order integer not null default 99,
  description text default '',
  auto_update_required boolean not null default true,
  customer_portal_visible boolean not null default true,
  created_at timestamptz not null default now()
);

alter table products add column if not exists description text default '';
alter table products add column if not exists auto_update_required boolean not null default true;
alter table products add column if not exists customer_portal_visible boolean not null default true;

insert into products (product_name, product_code, prefix_code, default_limit, status, sort_order, description)
values
  ('TallySync Pro', 'TSP', 'TSP', 3, 'active', 1, 'Tally invoice and voucher import automation.'),
  ('EPF & ESIC Manager', 'EEM', 'EEM', 3, 'active', 2, 'EPF and ESIC workflow automation.'),
  ('Bank Import Pro', 'BIP', 'BIP', 3, 'active', 3, 'Bank statement import and ledger mapping for Tally.'),
  ('TezHisab Prime / Invoice Management', 'THP', 'THP', 3, 'active', 4, 'Easy-to-use invoice and accounting management software.'),
  ('EDU PRIME', 'EDUPRIME', 'EDPR', 2, 'active', 5, 'Cloud-based school ERP with desktop, teacher and parent apps.')
on conflict (product_code) do nothing;

create table if not exists customers (
  id bigserial primary key,
  name text not null,
  email text not null unique,
  phone text default '',
  business_name text default '',
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists portal_users (
  id bigserial primary key,
  email text not null unique,
  password_hash text not null,
  role text not null check (role in ('admin','customer')),
  display_name text default '',
  customer_id bigint references customers(id) on delete set null,
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists update_channels (
  id bigserial primary key,
  product_code text not null,
  channel_code text not null,
  channel_name text not null,
  platform text default '',
  repo_owner text default '',
  repo_name text default '',
  manifest_url text default '',
  status text not null default 'active',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(product_code, channel_code)
);

create table if not exists app_versions (
  id bigserial primary key,
  channel_id bigint not null references update_channels(id) on delete cascade,
  version text not null,
  download_url text not null,
  notes text default '',
  mandatory boolean not null default false,
  published boolean not null default true,
  created_at timestamptz not null default now(),
  unique(channel_id, version)
);

create table if not exists activity_logs (
  id bigserial primary key,
  actor_email text default 'system',
  actor_role text default 'system',
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_licenses_client_email on licenses(lower(client_email));
create index if not exists idx_licenses_product on licenses(product);
create index if not exists idx_portal_users_email on portal_users(lower(email));
create index if not exists idx_update_channels_product on update_channels(product_code);
create index if not exists idx_app_versions_channel on app_versions(channel_id, created_at desc);
create index if not exists idx_activity_logs_created on activity_logs(created_at desc);

-- Initial update channels. Existing GitHub URLs can be mapped from the portal later.
insert into update_channels (product_code, channel_code, channel_name, platform, status)
values
  ('BIP', 'WINDOWSEXE', 'Windows Desktop — EXE', 'Windows Desktop', 'active'),
  ('EEM', 'WINDOWSEXE', 'Windows Desktop — EXE', 'Windows Desktop', 'active'),
  ('TSP', 'WINDOWSEXE', 'Windows Desktop — EXE', 'Windows Desktop', 'active'),
  ('THP', 'WINDOWSEXE', 'Windows Desktop — EXE', 'Windows Desktop', 'active'),
  ('EDUPRIME', 'WINDOWSEXE', 'EDU PRIME Desktop App — EXE', 'Windows Desktop', 'active'),
  ('EDUPRIME', 'ANDROIDTEACHERAPK', 'EDU PRIME Teacher App — APK', 'Android', 'active'),
  ('EDUPRIME', 'ANDROIDPARENTAPK', 'EDU PRIME Parent App — APK', 'Android', 'active')
on conflict (product_code, channel_code) do nothing;

-- Existing updater mappings detected from the current working applications.
update update_channels
set repo_owner = 'tezhisab-afk',
    repo_name = 'bank-import-pro-updates',
    manifest_url = 'https://raw.githubusercontent.com/tezhisab-afk/bank-import-pro-updates/main/version.json'
where product_code = 'BIP' and channel_code = 'WINDOWSEXE';

update update_channels
set repo_owner = 'clientsepfesicmail',
    repo_name = '-epf-esic-updates',
    manifest_url = 'https://clientsepfesicmail.github.io/-epf-esic-updates/version.json'
where product_code = 'EEM' and channel_code = 'WINDOWSEXE';

-- Preserve old data normalization where applicable.
update licenses set product = 'EEM' where product in ('EPF_ESIC', 'EPF', '');
update licenses set product = 'TSP' where product in ('TALLYSYNC_PRO');
