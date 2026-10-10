-- Temporary ZEC BOX timer reward mode.
-- This deliberately rewards a 5-second timer, NOT a provider-verified ad view.
-- Replace/disable this RPC once an approved provider callback is integrated.
-- Apply in Supabase SQL Editor. Server enforces the fixed reward and 5-per-UTC-day cap.

create or replace function public.claim_timer_ad_reward()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_claim_count integer;
  v_reward numeric(20,8) := 0.25000000;
  v_reference text := gen_random_uuid()::text;
begin
  if v_user_id is null then
    raise exception 'Sign in before claiming a ZEC reward.';
  end if;

  -- Serialize claims for this account before checking the cap.
  perform 1
    from public.wallet_balances wb
   where wb.user_id = v_user_id
   for update;

  if not found then
    raise exception 'Wallet not found. Please sign out and sign in again.';
  end if;

  select count(*)::integer
    into v_claim_count
    from public.ad_claims ac
   where ac.user_id = v_user_id
     and ac.created_at >= (date_trunc('day', now() at time zone 'UTC') at time zone 'UTC')
     and ac.created_at < ((date_trunc('day', now() at time zone 'UTC') + interval '1 day') at time zone 'UTC');

  if v_claim_count >= 5 then
    raise exception 'Daily reward limit reached (5 claims per UTC day).';
  end if;

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
    'daily_limit', 5,
    'mode', 'timer'
  );
end;
$$;

revoke all on function public.claim_timer_ad_reward() from public, anon;
grant execute on function public.claim_timer_ad_reward() to authenticated;
