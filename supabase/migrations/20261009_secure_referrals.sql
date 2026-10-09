-- ZEC BOX secure referral foundation
-- Apply after the existing wallet and secure ad-reward migrations.
-- Referral rewards are paid only when the referred account confirms its email.
-- A user cannot choose the referrer ID or reward amount from the browser.

create table if not exists public.referral_codes (
  user_id uuid primary key references auth.users(id) on delete cascade,
  code text not null unique,
  created_at timestamptz not null default now()
);

alter table public.referral_codes enable row level security;
revoke all on public.referral_codes from anon, authenticated;
grant select on public.referral_codes to authenticated;

drop policy if exists "Users can read own referral code" on public.referral_codes;
create policy "Users can read own referral code"
  on public.referral_codes for select
  to authenticated
  using (auth.uid() = user_id);

-- The code used by a referral is repeated for each referred account, so remove
-- any old single-column UNIQUE constraint on referrals.referral_code.
do $$
declare c record;
begin
  for c in
    select conname
      from pg_constraint
     where conrelid = 'public.referrals'::regclass
       and contype = 'u'
       and (
         select array_agg(a.attname order by a.attname)
           from unnest(conkey) as k(attnum)
           join pg_attribute a
             on a.attrelid = conrelid and a.attnum = k.attnum
       ) = array['referral_code']::name[]
  loop
    execute format('alter table public.referrals drop constraint %I', c.conname);
  end loop;
end $$;

create index if not exists referrals_referrer_id_idx on public.referrals(referrer_id);
create unique index if not exists referrals_referred_user_id_uidx
  on public.referrals(referred_user_id) where referred_user_id is not null;

create or replace function public.get_my_referral_code()
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_code text;
begin
  if v_user_id is null then
    raise exception 'Sign in to get your referral link.';
  end if;

  select rc.code into v_code
    from public.referral_codes rc
   where rc.user_id = v_user_id;

  if v_code is null then
    loop
      v_code := 'ZEC' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10));
      begin
        insert into public.referral_codes(user_id, code)
        values (v_user_id, v_code);
        exit;
      exception when unique_violation then
        v_code := null;
      end;
    end loop;
  end if;

  return v_code;
end;
$$;

revoke all on function public.get_my_referral_code() from public, anon;
grant execute on function public.get_my_referral_code() to authenticated;

create or replace function public.attach_referral_on_signup()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_code text;
  v_referrer uuid;
begin
  v_code := upper(trim(coalesce(new.raw_user_meta_data ->> 'referral_code', '')));
  if v_code = '' then
    return new;
  end if;

  select rc.user_id into v_referrer
    from public.referral_codes rc
   where upper(rc.code) = v_code
   limit 1;

  if v_referrer is null or v_referrer = new.id then
    return new;
  end if;

  insert into public.referrals(referrer_id, referred_user_id, referral_code, status, created_at)
  values (v_referrer, new.id, v_code, 'pending', now())
  on conflict do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_referral_created on auth.users;
create trigger on_auth_user_referral_created
  after insert on auth.users
  for each row execute function public.attach_referral_on_signup();

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
begin
  if v_user_id is null then
    raise exception 'Sign in to verify your referral.';
  end if;

  select u.email_confirmed_at into v_confirmed_at
    from auth.users u
   where u.id = v_user_id;

  if v_confirmed_at is null then
    raise exception 'Confirm your email before completing referral verification.';
  end if;

  select r.* into v_referral
    from public.referrals r
   where r.referred_user_id = v_user_id
     and r.status = 'pending'
   for update;

  if not found then
    return jsonb_build_object('success', true, 'rewarded', false, 'message', 'No pending referral reward was found.');
  end if;

  perform 1
    from public.wallet_balances wb
   where wb.user_id = v_referral.referrer_id
   for update;

  if not found then
    raise exception 'Referrer wallet not found. Please contact support.';
  end if;

  update public.wallet_balances
     set zec_balance = zec_balance + v_reward,
         updated_at = now()
   where user_id = v_referral.referrer_id;

  insert into public.wallet_transactions
    (user_id, amount, currency, transaction_type, status, reference, created_at)
  values
    (v_referral.referrer_id, v_reward, 'ZEC', 'referral_reward', 'completed', v_reference, now());

  update public.referrals
     set status = 'completed'
   where referred_user_id = v_user_id
     and referrer_id = v_referral.referrer_id;

  return jsonb_build_object('success', true, 'rewarded', true, 'reward_amount', v_reward, 'currency', 'ZEC');
end;
$$;

revoke all on function public.claim_verified_referral_reward() from public, anon;
grant execute on function public.claim_verified_referral_reward() to authenticated;

-- Existing accounts receive codes lazily through get_my_referral_code().
-- No referral rewards are granted just by installing this migration.
