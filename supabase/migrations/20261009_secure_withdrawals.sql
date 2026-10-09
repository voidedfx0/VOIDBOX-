-- ZEC BOX secure withdrawals and transaction history
-- Run in the Supabase SQL Editor after the wallet_balances and wallet_transactions tables exist.
-- Requests reserve funds immediately. A rejected request refunds the user automatically.
-- No blockchain transfer is made automatically; an operator must review and pay requests.

create extension if not exists pgcrypto;

create table if not exists public.withdrawal_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  currency text not null check (currency in ('ZEC','USDT')),
  amount numeric(20,8) not null check (amount > 0),
  wallet_address text not null,
  network text not null,
  status text not null default 'pending' check (status in ('pending','approved','paid','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

alter table public.withdrawal_requests add column if not exists user_id uuid references auth.users(id) on delete cascade;
alter table public.withdrawal_requests add column if not exists currency text;
alter table public.withdrawal_requests add column if not exists amount numeric(20,8);
alter table public.withdrawal_requests add column if not exists wallet_address text;
alter table public.withdrawal_requests add column if not exists network text;
alter table public.withdrawal_requests add column if not exists status text not null default 'pending';
alter table public.withdrawal_requests add column if not exists created_at timestamptz not null default now();
alter table public.withdrawal_requests add column if not exists reviewed_at timestamptz;

alter table public.withdrawal_requests enable row level security;
drop policy if exists "Users can view their own withdrawal requests" on public.withdrawal_requests;
create policy "Users can view their own withdrawal requests"
  on public.withdrawal_requests for select to authenticated
  using (user_id = (select auth.uid()));

revoke insert, update, delete on public.withdrawal_requests from anon, authenticated;
grant select on public.withdrawal_requests to authenticated;

alter table public.wallet_transactions enable row level security;
drop policy if exists "Users can view their own wallet transactions" on public.wallet_transactions;
create policy "Users can view their own wallet transactions"
  on public.wallet_transactions for select to authenticated
  using (user_id = (select auth.uid()));
revoke insert, update, delete on public.wallet_transactions from anon, authenticated;
grant select on public.wallet_transactions to authenticated;

create or replace function public.create_withdrawal_request(
  p_currency text,
  p_amount numeric,
  p_wallet_address text,
  p_network text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_amount numeric(20,8);
  v_balance numeric(20,8);
  v_request_id uuid;
  v_currency text := upper(trim(coalesce(p_currency,'')));
  v_network text := upper(trim(coalesce(p_network,'')));
  v_address text := trim(coalesce(p_wallet_address,''));
begin
  if v_user_id is null then raise exception 'Sign in before requesting a withdrawal.'; end if;
  if v_currency not in ('ZEC','USDT') then raise exception 'Choose ZEC or USDT.'; end if;
  if p_amount is null or p_amount <= 0 or p_amount > 1000000000 then raise exception 'Enter a valid withdrawal amount.'; end if;
  v_amount := round(p_amount, 8);
  if v_amount <= 0 then raise exception 'Amount is too small.'; end if;
  if length(v_address) < 10 or length(v_address) > 256 then raise exception 'Enter a valid destination wallet address.'; end if;
  if v_currency = 'ZEC' and v_network <> 'ZEC' then raise exception 'Choose the ZEC network for ZEC withdrawals.'; end if;
  if v_currency = 'USDT' and v_network not in ('TRC20','ERC20','BEP20') then raise exception 'Choose a supported USDT network.'; end if;

  if v_currency = 'ZEC' then
    select zec_balance into v_balance from public.wallet_balances where user_id = v_user_id for update;
    if not found then raise exception 'Wallet is not ready. Refresh and try again.'; end if;
    if v_balance < v_amount then raise exception 'Insufficient available ZEC balance.'; end if;
    update public.wallet_balances set zec_balance = zec_balance - v_amount, updated_at = now() where user_id = v_user_id;
  else
    select usdt_balance into v_balance from public.wallet_balances where user_id = v_user_id for update;
    if not found then raise exception 'Wallet is not ready. Refresh and try again.'; end if;
    if v_balance < v_amount then raise exception 'Insufficient available USDT balance.'; end if;
    update public.wallet_balances set usdt_balance = usdt_balance - v_amount, updated_at = now() where user_id = v_user_id;
  end if;

  insert into public.withdrawal_requests(user_id,currency,amount,wallet_address,network,status)
  values(v_user_id,v_currency,v_amount,v_address,v_network,'pending')
  returning id into v_request_id;

  insert into public.wallet_transactions(user_id,amount,currency,transaction_type,status,reference)
  values(v_user_id,v_amount,v_currency,'withdrawal','pending','withdrawal:'||v_request_id::text);

  return jsonb_build_object('request_id',v_request_id,'status','pending');
end;
$$;

revoke all on function public.create_withdrawal_request(text,numeric,text,text) from public, anon;
grant execute on function public.create_withdrawal_request(text,numeric,text,text) to authenticated;

create or replace function public.refund_rejected_withdrawal()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.status = 'pending' and new.status = 'rejected' then
    if new.currency = 'ZEC' then
      update public.wallet_balances set zec_balance = zec_balance + new.amount, updated_at = now() where user_id = new.user_id;
    elsif new.currency = 'USDT' then
      update public.wallet_balances set usdt_balance = usdt_balance + new.amount, updated_at = now() where user_id = new.user_id;
    end if;
    update public.wallet_transactions
       set status = 'refunded'
     where user_id = new.user_id and reference = 'withdrawal:'||new.id::text and status = 'pending';
    new.reviewed_at := coalesce(new.reviewed_at,now());
  elsif old.status = 'pending' and new.status in ('approved','paid') then
    new.reviewed_at := coalesce(new.reviewed_at,now());
    update public.wallet_transactions
       set status = case when new.status = 'paid' then 'completed' else 'pending' end
     where user_id = new.user_id and reference = 'withdrawal:'||new.id::text;
  end if;
  return new;
end;
$$;

drop trigger if exists on_withdrawal_status_change on public.withdrawal_requests;
create trigger on_withdrawal_status_change
before update of status on public.withdrawal_requests
for each row execute function public.refund_rejected_withdrawal();
