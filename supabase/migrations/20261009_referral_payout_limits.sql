begin;

create or replace function public.claim_verified_referral_reward()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_referral public.referrals%rowtype;
  v_confirmed_at timestamptz;
  v_reward numeric(20,8) := 10.00000000;
  v_reference text := gen_random_uuid()::text;
  v_count integer := 0;
  v_day_start timestamptz := date_trunc('day', now() at time zone 'UTC') at time zone 'UTC';
begin
  if v_user_id is null then
    raise exception 'Sign in to verify your referral.';
  end if;

  select u.email_confirmed_at into v_confirmed_at
  from auth.users u where u.id = v_user_id;

  if v_confirmed_at is null then
    raise exception 'Confirm your email before completing referral verification.';
  end if;

  select r.* into v_referral
  from public.referrals r
  where r.referred_user_id = v_user_id and r.status = 'pending'
  for update;

  if not found then
    return jsonb_build_object('success', true, 'rewarded', false,
      'message', 'No pending referral reward was found.');
  end if;

  perform 1 from public.wallet_balances wb
  where wb.user_id = v_referral.referrer_id for update;

  if not found then
    raise exception 'Referrer wallet not found. Please contact support.';
  end if;

  select count(*)::integer into v_count
  from public.wallet_transactions wt
  where wt.user_id = v_referral.referrer_id
    and wt.transaction_type = 'referral_reward'
    and wt.created_at >= v_day_start
    and wt.created_at < v_day_start + interval '1 day';

  if v_count >= 5 then
    raise exception 'Daily referral reward limit reached. This reward remains pending; try again tomorrow.';
  end if;

  update public.wallet_balances
  set zec_balance = zec_balance + v_reward, updated_at = now()
  where user_id = v_referral.referrer_id;

  insert into public.wallet_transactions
    (user_id, amount, currency, transaction_type, status, reference, created_at)
  values
    (v_referral.referrer_id, v_reward, 'ZEC', 'referral_reward', 'completed', v_reference, now());

  update public.referrals
  set status = 'completed'
  where referred_user_id = v_user_id
    and referrer_id = v_referral.referrer_id
    and status = 'pending';

  return jsonb_build_object('success', true, 'rewarded', true,
    'reward_amount', v_reward, 'currency', 'ZEC', 'daily_referral_limit', 5);
end;
$$;

revoke all on function public.claim_verified_referral_reward() from public, anon;
grant execute on function public.claim_verified_referral_reward() to authenticated;

commit;
