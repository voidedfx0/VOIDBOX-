-- ZEC BOX administrator access and withdrawal review
-- Run in the Supabase SQL Editor. Then add your own auth user UUID to public.admin_users.
-- Never place a Supabase service-role key in the website.

begin;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
revoke all on table public.admin_users from public, anon, authenticated;

create or replace function public.is_current_user_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.admin_users au
     where au.user_id = auth.uid()
  );
$$;

revoke all on function public.is_current_user_admin() from public, anon;
grant execute on function public.is_current_user_admin() to authenticated;

create or replace function public.admin_list_withdrawals()
returns table (
  id uuid,
  user_id uuid,
  user_email text,
  currency text,
  amount numeric,
  wallet_address text,
  network text,
  status text,
  created_at timestamptz,
  reviewed_at timestamptz
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  if auth.uid() is null or not public.is_current_user_admin() then
    raise exception 'Administrator access required.';
  end if;

  return query
  select wr.id, wr.user_id, au.email::text, wr.currency, wr.amount,
         wr.wallet_address, wr.network, wr.status, wr.created_at, wr.reviewed_at
    from public.withdrawal_requests wr
    left join auth.users au on au.id = wr.user_id
   order by
     case wr.status when 'pending' then 0 when 'approved' then 1 else 2 end,
     wr.created_at desc
   limit 500;
end;
$$;

revoke all on function public.admin_list_withdrawals() from public, anon;
grant execute on function public.admin_list_withdrawals() to authenticated;

create or replace function public.admin_update_withdrawal_status(
  p_request_id uuid,
  p_status text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_request public.withdrawal_requests%rowtype;
  v_new_status text := lower(trim(coalesce(p_status, '')));
begin
  if auth.uid() is null or not public.is_current_user_admin() then
    raise exception 'Administrator access required.';
  end if;

  if p_request_id is null then
    raise exception 'Withdrawal request ID is required.';
  end if;

  if v_new_status not in ('approved', 'rejected', 'paid') then
    raise exception 'Choose Approved, Rejected, or Paid.';
  end if;

  select *
    into v_request
    from public.withdrawal_requests
   where id = p_request_id
   for update;

  if not found then
    raise exception 'Withdrawal request not found.';
  end if;

  if v_request.status = 'pending' and v_new_status not in ('approved', 'rejected') then
    raise exception 'Approve or reject a pending request first.';
  end if;

  if v_request.status = 'approved' and v_new_status not in ('paid', 'rejected') then
    raise exception 'An approved request can be marked paid or rejected.';
  end if;

  if v_request.status in ('paid', 'rejected') then
    raise exception 'This withdrawal is already finalized.';
  end if;

  update public.withdrawal_requests
     set status = v_new_status,
         reviewed_at = now()
   where id = p_request_id;

  return jsonb_build_object('success', true, 'request_id', p_request_id, 'status', v_new_status);
end;
$$;

revoke all on function public.admin_update_withdrawal_status(uuid, text) from public, anon;
grant execute on function public.admin_update_withdrawal_status(uuid, text) to authenticated;

commit;

-- To authorize yourself:
-- 1. Open Supabase Dashboard > Authentication > Users.
-- 2. Copy the UUID for your own account.
-- 3. Replace YOUR-USER-UUID below with that UUID and run this separately:
-- insert into public.admin_users (user_id)
-- values ('YOUR-USER-UUID'::uuid)
-- on conflict (user_id) do nothing;
