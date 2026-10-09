-- ZEC BOX secure ad reward claim foundation
-- Apply this in Supabase SQL Editor only after reviewing it.
-- IMPORTANT: No frontend code can create a verified ad row. A trusted ad-provider
-- callback / Edge Function must insert one after verifying a genuine completed ad.
-- Until that provider verification is connected, claims will be rejected safely.

create table if not exists public.ad_reward_verifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  provider text not null,
  provider_event_id text not null,
  verified_at timestamptz not null default now(),
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  unique (provider, provider_event_id)
);

alter table public.ad_reward_verifications enable row level security;
revoke all on public.ad_reward_verifications from anon, authenticated;
grant select on public.ad_reward_verifications to authenticated;

drop policy if exists "Users can read own ad verifications" on public.ad_reward_verifications;
create policy "Users can read own ad verifications"
  on public.ad_reward_verifications for select
  to authenticated
  using (auth.uid() = user_id);

-- Fixed reward amount is server-controlled. The browser cannot set a user ID,
-- reward amount, provider, event ID, or claim status.
create or replace function public.claim_verified_ad_reward(p_verification_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_verification public.ad_reward_verifications%rowtype;
  v_claim_count integer;
  v_reward numeric(20,8) := 0.25000000;
  v_reference text := gen_random_uuid()::text;
begin
  if v_user_id is null then
    raise exception 'You must be signed in to claim a reward.';
  end if;

  -- Lock the user's wallet to serialize simultaneous claims and enforce the daily cap.
  perform 1
    from public.wallet_balances wb
   where wb.user_id = v_user_id
   for update;

  if not found then
    raise exception 'Wallet not found. Please sign out and sign in again.';
  end if;

  -- Only a trusted provider-verification backend may create these rows.
  select *
    into v_verification
    from public.ad_reward_verifications av
   where av.id = p_verification_id
     and av.user_id = v_user_id
   for update;

  if not found then
    raise exception 'Ad completion has not been verified. No reward was credited.';
  end if;

  if v_verification.consumed_at is not null then
    raise exception 'This ad reward has already been claimed.';
  end if;

  if v_verification.verified_at < now() - interval '10 minutes' then
    raise exception 'This ad verification has expired. Please watch another ad.';
  end if;

  -- Daily limit uses UTC calendar days.
  select count(*)::integer
    into v_claim_count
    from public.ad_claims ac
   where ac.user_id = v_user_id
     and ac.created_at >= date_trunc('day', now() at time zone 'UTC') at time zone 'UTC'
     and ac.created_at < (date_trunc('day', now() at time zone 'UTC') + interval '1 day') at time zone 'UTC';

  if v_claim_count >= 5 then
    raise exception 'Daily reward limit reached (5 claims per UTC day).';
  end if;

  update public.ad_reward_verifications
     set consumed_at = now()
   where id = v_verification.id;

  insert into public.ad_claims (user_id, reward_amount, status, created_at)
  values (v_user_id, v_reward, 'completed', now());

  update public.wallet_balances
     set zec_balance = zec_balance + v_reward,
         updated_at = now()
   where user_id = v_user_id;

  insert into public.wallet_transactions
    (user_id, amount, currency, transaction_type, status, reference, created_at)
  values
    (v_user_id, v_reward, 'ZEC', 'ad_reward', 'completed', v_reference, now());

  return jsonb_build_object(
    'success', true,
    'reward_amount', v_reward,
    'currency', 'ZEC',
    'claims_today', v_claim_count + 1,
    'daily_limit', 5
  );
end;
$$;

revoke all on function public.claim_verified_ad_reward(uuid) from public, anon;
grant execute on function public.claim_verified_ad_reward(uuid) to authenticated;

-- No provider verification rows are created by this script.
-- Rewards remain safely unavailable until a real ad provider's server-side
-- verification is integrated. Do not insert test rows into production.
