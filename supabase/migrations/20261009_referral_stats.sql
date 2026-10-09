create or replace function public.get_my_referral_stats()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_total integer;
  v_completed integer;
begin
  if v_user_id is null then
    raise exception 'Sign in to view your referral statistics.';
  end if;
  select count(*)::integer,
         count(*) filter (where r.status = 'completed')::integer
    into v_total, v_completed
    from public.referrals r
   where r.referrer_id = v_user_id;
  return jsonb_build_object(
    'total_referrals', coalesce(v_total, 0),
    'successful_referrals', coalesce(v_completed, 0),
    'rewards_earned_zec', coalesce(v_completed, 0) * 10
  );
end;
$$;
revoke all on function public.get_my_referral_stats() from public, anon;
grant execute on function public.get_my_referral_stats() to authenticated;
