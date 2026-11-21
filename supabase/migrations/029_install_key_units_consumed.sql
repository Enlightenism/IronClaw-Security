alter table public.install_key_records add column if not exists units_consumed integer not null default 0;
