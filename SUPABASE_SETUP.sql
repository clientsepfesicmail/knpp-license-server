-- Run this in Supabase SQL Editor before using product management.

create table if not exists products (
  id bigserial primary key,
  product_name text not null,
  product_code text not null unique,
  prefix_code text not null,
  default_limit integer not null default 3,
  status text not null default 'active',
  sort_order integer not null default 99,
  created_at timestamptz not null default now()
);

insert into products (product_name, product_code, prefix_code, default_limit, status, sort_order)
values
  ('TallySync Pro', 'TSP', 'TSP', 3, 'active', 1),
  ('EPF & ESIC Manager', 'EEM', 'EEM', 3, 'active', 2)
on conflict (product_code) do nothing;

-- Optional: normalize old product codes in licenses table.
update licenses set product = 'EEM' where product in ('EPF_ESIC', 'EPF', '');
update licenses set product = 'TSP' where product in ('TALLYSYNC_PRO');
