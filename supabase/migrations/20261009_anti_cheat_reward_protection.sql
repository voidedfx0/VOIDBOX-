-- ZEC BOX anti-cheat and reward protection
-- Apply after the wallet, referral, ad-reward, and withdrawal migrations.
-- This migration removes direct client-side write access to reward/accounting tables.
-- Trusted SECURITY DEFINER RPCs and database triggers continue to perform approved writes.

begin;

-- Ensure all sensitive tables enforce row-level security.
alter table public.wallet_balances enable row level security;
alter table public.wallet_transactions enable row level security;
alter table public.ad_claims enable row level security;
alter table public.ad_reward_verifications enable row level security;
alter table public.referral_codes enable row level security;
alter table public.referrals enable row level security;
alter table public.withdrawal_requests enable row level security;

-- Remove existing policies on these tables so an older permissive policy cannot
-- accidentally grant broader access alongside the restrictive policies below.
do $$
declare
  p record;
begin
  for p in
    select schemaname, tablename, policyname
      from pg_policies
     where schemaname = 'public'
       and tablename in (
         'wallet_balances',
         'wallet_transactions',
         'ad_claims',
         'ad_reward_verifications',
         'referral_codes',
         'referrals',
         'withdrawal_requests'
       )
  loop
    execute format('drop policy if exists %I on %I.%I',
      p.policyname, p.schemaname, p.tablename);
  end loop;
end
$$;

-- Clients may read only records belonging to their authenticated account.
create policy zecbox_wallet_balances_select_own
  on public.wallet_balances for select to authenticated
  using (user_id = (select auth.uid()));

create policy zecbox_wallet_transactions_select_own
  on public.wallet_transactions for select to authenticated
  using (user_id = (select auth.uid()));

create policy zecbox_ad_claims_select_own
  on public.ad_claims for select to authenticated
  using (user_id = (select auth.uid()));

create policy zecbox_ad_verifications_select_own
  on public.ad_reward_verifications for select to authenticated
  using (user_id = (select auth.uid()));

create policy zecbox_referral_codes_select_own
  on public.referral_codes for select to authenticated
  using (user_id = (select auth.uid()));

create policy zecbox_referrals_select_involved
  on public.referrals for select to authenticated
  using (
    referrer_id = (select auth.uid())
    or referred_user_id = (select auth.uid())
  );

create policy zecbox_withdrawals_select_own
  on public.withdrawal_requests for select to authenticated
  using (user_id = (select auth.uid()));

-- Remove all direct client writes. SECURITY DEFINER RPCs / triggers are the
-- only intended paths for balance, reward, referral, transaction and withdrawal changes.
revoke all on table public.wallet_balances from public, anon, authenticated;
revoke all on table public.wallet_transactions from public, anon, authenticated;
revoke all on table public.ad_claims from public, anon, authenticated;
revoke all on table public.ad_reward_verifications from public, anon, authenticated;
revoke all on table public.referral_codes from public, anon, authenticated;
revoke all on table public.referrals from public, anon, authenticated;
revoke all on table public.withdrawal_requests from public, anon, authenticated;

grant select on table public.wallet_balances to authenticated;
grant select on table public.wallet_transactions to authenticated;
grant select on table public.ad_claims to authenticated;
grant select on table public.ad_reward_verifications to authenticated;
grant select on table public.referral_codes to authenticated;
grant select on table public.referrals to authenticated;
grant select on table public.withdrawal_requests to authenticated;

-- Explicitly keep privileged RPCs unavailable to anonymous callers.
revoke all on function public.claim_verified_ad_reward(uuid) from public, anon;
grant execute on function public.claim_verified_ad_reward(uuid) to authenticated;

revoke all on function public.claim_verified_referral_reward() from public, anon;
grant execute on function public.claim_verified_referral_reward() to authenticated;

revoke all on function public.get_my_referral_code() from public, anon;
grant execute on function public.get_my_referral_code() to authenticated;

revoke all on function public.create_withdrawal_request(text,numeric,text,text) from public, anon;
grant execute on function public.create_withdrawal_request(text,numeric,text,text) to authenticated;

commit;

-- Important: this blocks direct client-side writes, but it does not by itself
-- detect multi-account abuse. Add provider/server-side signals before enabling
-- ad rewards or paying out rewards at scale.
