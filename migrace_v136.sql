-- =====================================================================
--  Studovna u Drobka · migrace na v1.36
--  Spusť celé najednou v Supabase → SQL Editor (běží v jedné transakci).
--  Skript je idempotentní: jde pustit opakovaně bez škody.
--
--  Co dělá:
--   1) heslo administrátora jako bcrypt hash v tabulce app_admin,
--      na kterou anon klíč nedosáhne
--   2) všechny admin operace jako SECURITY DEFINER funkce s ověřením hesla
--   3) placení lístku jako jedna atomická funkce (platba + síň slávy + lístek)
--   4) RLS: anon smí číst všechno, zapisovat jen do lístků (čárkování);
--      platby, síň slávy a nastavení jdou měnit jen přes funkce
--
--  !!! Po spuštění NASTAV HESLO – viz sekce „NASTAVENÍ / ZMĚNA HESLA“ úplně
--  dole. Dokud heslo nastavené není, administrace se nedá otevřít.
-- =====================================================================

begin;

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 0) Příprava: sloupec s čárkami musí být jsonb (funkce s ním počítají)
-- ---------------------------------------------------------------------
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema='public' and table_name='tabs'
               and column_name='marks' and data_type <> 'jsonb') then
    alter table public.tabs alter column marks type jsonb using marks::jsonb;
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 1) Heslo administrátora
-- ---------------------------------------------------------------------
create table if not exists public.app_admin (
  id         int primary key default 1 check (id = 1),
  pw_hash    text not null,
  updated_at timestamptz not null default now()
);
alter table public.app_admin enable row level security;   -- žádná politika = nikdo přes API
revoke all on public.app_admin from public, anon, authenticated;

-- Ověření hesla. Při chybě chvíli počká, ať se heslo nedá rychle hádat.
create or replace function public._admin_ok(p_pw text)
returns boolean
language plpgsql security definer
set search_path = public, extensions
as $$
declare h text;
begin
  select pw_hash into h from public.app_admin where id = 1;
  if h is not null and coalesce(p_pw, '') <> '' and extensions.crypt(p_pw, h) = h then
    return true;
  end if;
  perform pg_sleep(0.8);
  return false;
end $$;

create or replace function public._admin_require(p_pw text)
returns void
language plpgsql security definer
set search_path = public, extensions
as $$
begin
  if not public._admin_ok(p_pw) then
    raise exception 'Špatné heslo administrátora' using errcode = '28P01';
  end if;
end $$;

-- Aktuální čas v ms (stejná jednotka, jakou používá JS Date.now())
create or replace function public._now_ms()
returns bigint language sql stable
as $$ select (extract(epoch from clock_timestamp()) * 1000)::bigint $$;

-- Nastavení v tabulce suggestions: jeden řádek na klíč (period).
-- Smazání i vložení proběhne v jedné transakci, takže ostatní zařízení
-- nikdy neuvidí stav „záznam chybí“ (tak kdysi zmizel název sudu).
create or replace function public._set_setting(p_key text, p_val text)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  delete from public.suggestions where period = p_key;
  if p_val is not null then
    insert into public.suggestions(period, beer) values (p_key, p_val);
  end if;
end $$;

create or replace function public._get_setting(p_key text)
returns text language sql stable security definer
set search_path = public
as $$ select beer from public.suggestions where period = p_key limit 1 $$;

-- Přičtení do síně slávy (i záporné). Řádek s nulou se smaže.
create or replace function public._hall_add(p_name text, p_beers numeric, p_paid numeric)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  if p_name is null or p_name = '' then return; end if;
  insert into public.hall(name, beers, paid)
  values (p_name, greatest(0, round(p_beers, 1)), greatest(0, round(p_paid)))
  on conflict (name) do update
    set beers = greatest(0, round((coalesce(public.hall.beers, 0)::numeric + p_beers), 1)),
        paid  = greatest(0, round(coalesce(public.hall.paid, 0)::numeric + p_paid));
  delete from public.hall where name = p_name and coalesce(beers, 0) = 0 and coalesce(paid, 0) = 0;
end $$;

-- Pomocné funkce nejsou pro API
revoke all on function public._admin_ok(text)                      from public, anon, authenticated;
revoke all on function public._admin_require(text)                 from public, anon, authenticated;
revoke all on function public._set_setting(text, text)             from public, anon, authenticated;
revoke all on function public._get_setting(text)                   from public, anon, authenticated;
revoke all on function public._hall_add(text, numeric, numeric)    from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 2) Admin RPC (všechny berou heslo jako první parametr)
-- ---------------------------------------------------------------------

-- Přihlášení do administrace – jen ověří heslo
create or replace function public.admin_login(p_pw text)
returns boolean
language plpgsql security definer
set search_path = public
as $$ begin return public._admin_ok(p_pw); end $$;

-- Změna hesla z aplikace (staré heslo → nové)
create or replace function public.admin_change_password(p_pw text, p_new text)
returns void
language plpgsql security definer
set search_path = public, extensions
as $$
begin
  perform public._admin_require(p_pw);
  if length(coalesce(p_new, '')) < 6 then
    raise exception 'Nové heslo musí mít aspoň 6 znaků';
  end if;
  update public.app_admin
     set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 10)), updated_at = now()
   where id = 1;
end $$;

-- Cena piva
create or replace function public.admin_set_price(p_pw text, p_price int)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  perform public._admin_require(p_pw);
  if p_price is null or p_price < 1 or p_price > 9999 then
    raise exception 'Neplatná cena piva';
  end if;
  perform public._set_setting('__price__', p_price::text);
end $$;

-- Termín meetingu (ISO datum; null = zpět na výchozí středu 18:00)
create or replace function public.admin_set_session(p_pw text, p_iso text)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  perform public._admin_require(p_pw);
  if p_iso is not null then
    begin
      perform p_iso::timestamptz;
    exception when others then
      raise exception 'Neplatný termín meetingu';
    end;
  end if;
  perform public._set_setting('__session__', p_iso);
end $$;

-- Sud: p_new = true → nový sud (čas naražení = teď, starý se zapíše do historie),
--      p_new = false → jen oprava názvu a objemu, čas naražení zůstává.
-- p_log je JSON se souhrnem končícího sudu (počítá ho klient).
create or replace function public.admin_save_keg(p_pw text, p_name text, p_liters numeric,
                                                 p_new boolean, p_log text default null)
returns bigint
language plpgsql security definer
set search_path = public
as $$
declare
  v_ts  bigint;
  v_old text;
begin
  perform public._admin_require(p_pw);
  p_name := btrim(coalesce(p_name, ''));
  if p_name = '' or length(p_name) > 60 then
    raise exception 'Neplatný název piva';
  end if;
  if p_liters is null or p_liters <= 0 or p_liters > 1000 then
    raise exception 'Neplatný objem sudu';
  end if;

  if p_new then
    v_ts := public._now_ms();
    if p_log is not null then
      perform p_log::jsonb;                        -- jen validace
      insert into public.suggestions(period, beer) values ('__keg_log__', p_log);
    end if;
  else
    v_old := public._get_setting('__keg__');
    if v_old is null then
      raise exception 'Sud zatím není naražený';
    end if;
    if left(btrim(v_old), 1) = '{' then
      v_ts := (v_old::jsonb ->> 'ts')::bigint;
    else
      v_ts := btrim(v_old)::bigint;                 -- starší formát: jen timestamp
    end if;
  end if;

  perform public._set_setting('__keg__',
    jsonb_build_object('ts', v_ts, 'name', p_name, 'liters', p_liters)::text);
  return v_ts;
end $$;

-- Vynulování síně slávy
create or replace function public.admin_reset_hall(p_pw text)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  perform public._admin_require(p_pw);
  delete from public.hall where true;
  perform public._set_setting('__hall_since__', public._now_ms()::text);
end $$;

-- Smazání jedné platby. Ze síně slávy se odečte, jen když platba vznikla
-- po její poslední obnově. Počítadlo sudu se přepočítává z čárek plateb,
-- takže se platba sama odečte jen z toho sudu, do kterého její čárky patří.
create or replace function public.admin_delete_payment(p_pw text, p_raw text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ctid  tid;
  v_rec   jsonb;
  v_since bigint;
  v_eq    numeric;
  v_hall  boolean := false;
begin
  perform public._admin_require(p_pw);
  select ctid into v_ctid from public.suggestions
   where period = '__payment__' and beer = p_raw limit 1;
  if v_ctid is null then
    raise exception 'Platba nenalezena (možná už ji smazal někdo jiný)';
  end if;
  delete from public.suggestions where ctid = v_ctid;   -- jen jeden výskyt

  begin v_rec := p_raw::jsonb; exception when others then v_rec := null; end;
  if v_rec is not null then
    v_since := nullif(public._get_setting('__hall_since__'), '')::bigint;
    if v_since is null or coalesce((v_rec ->> 'ts')::bigint, 0) >= v_since then
      v_eq := coalesce(
        (v_rec ->> 'eq')::numeric,
        (select sum(case when m ->> 's' = 'small' then 0.6 else 1 end)
           from jsonb_array_elements(case when jsonb_typeof(v_rec -> 'mk') = 'array'
                                          then v_rec -> 'mk' else '[]'::jsonb end) m),
        (v_rec ->> 'beers')::numeric, 0);
      perform public._hall_add(v_rec ->> 'name', -v_eq, -coalesce((v_rec ->> 'amount')::numeric, 0));
      v_hall := true;
    end if;
  end if;
  return jsonb_build_object('hall', v_hall);
end $$;

-- ---------------------------------------------------------------------
-- 3) Placení lístku (běžný uživatel, bez hesla)
--    Atomicky: zapíše platbu do evidence, připíše do síně slávy
--    a z lístku odebere zaplacené čárky (ty přibylé mezitím zůstanou).
--    p_marks = čárky, na které byl vystaven QR kód, p_amount = částka z QR.
-- ---------------------------------------------------------------------
create or replace function public.pay_tab(p_name text, p_marks jsonb, p_amount int)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_cur   jsonb;
  v_c     int;
  v_small int;
  v_left  jsonb;
  v_eq    numeric;
  v_rec   jsonb;
begin
  if jsonb_typeof(p_marks) is distinct from 'array' then
    raise exception 'Neplatné čárky';
  end if;
  v_c := jsonb_array_length(p_marks);
  if v_c = 0 or v_c > 500 or p_amount is null or p_amount < 0 or p_amount > 100000 then
    raise exception 'Neplatná platba';
  end if;

  select marks into v_cur from public.tabs where name = p_name for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'gone');
  end if;

  select count(*) filter (where m ->> 's' = 'small') into v_small
    from jsonb_array_elements(p_marks) m;
  v_eq := round(v_c - v_small + v_small * 0.6, 1);

  -- Čárky se přidávají vždy na konec, zaplacené jsou tedy ty na začátku
  select coalesce(jsonb_agg(e order by i), '[]'::jsonb) into v_left
    from jsonb_array_elements(coalesce(v_cur, '[]'::jsonb)) with ordinality t(e, i)
   where i > v_c;

  v_rec := jsonb_build_object(
    'name', p_name, 'beers', v_c, 'small', v_small, 'large', v_c - v_small,
    'eq', v_eq, 'amount', p_amount, 'ts', public._now_ms(),
    'mk', (select jsonb_agg(jsonb_build_object(
                    't', coalesce((m ->> 't')::bigint, 0),
                    's', case when m ->> 's' = 'small' then 'small' else 'large' end) order by i)
             from jsonb_array_elements(p_marks) with ordinality t(m, i)));
  insert into public.suggestions(period, beer, name) values ('__payment__', v_rec::text, p_name);

  perform public._hall_add(p_name, v_eq, p_amount);

  if jsonb_array_length(v_left) > 0 then
    update public.tabs set marks = v_left, beers = jsonb_array_length(v_left) where name = p_name;
  else
    delete from public.tabs where name = p_name;
  end if;
  return jsonb_build_object('ok', true, 'left', jsonb_array_length(v_left));
end $$;

grant execute on function public.admin_login(text)                                    to anon, authenticated;
grant execute on function public.admin_change_password(text, text)                    to anon, authenticated;
grant execute on function public.admin_set_price(text, int)                           to anon, authenticated;
grant execute on function public.admin_set_session(text, text)                        to anon, authenticated;
grant execute on function public.admin_save_keg(text, text, numeric, boolean, text)   to anon, authenticated;
grant execute on function public.admin_reset_hall(text)                               to anon, authenticated;
grant execute on function public.admin_delete_payment(text, text)                     to anon, authenticated;
grant execute on function public.pay_tab(text, jsonb, int)                            to anon, authenticated;

-- Starou hall_credit už aplikace nevolá. Anon by přes ni mohl síň slávy
-- libovolně přepsat (i zápornými čísly), proto jí bereme práva.
do $$
declare f regprocedure;
begin
  for f in select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname = 'hall_credit' loop
    execute format('revoke all on function %s from public, anon, authenticated', f);
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- 4) RLS – staré politiky pryč, nové jen na čtení (+ lístky pro čárkování)
-- ---------------------------------------------------------------------
do $$
declare r record;
begin
  for r in select policyname, tablename from pg_policies
            where schemaname = 'public' and tablename in ('tabs', 'hall', 'suggestions') loop
    execute format('drop policy %I on public.%I', r.policyname, r.tablename);
  end loop;
end $$;

alter table public.tabs        enable row level security;
alter table public.hall        enable row level security;
alter table public.suggestions enable row level security;

-- Lístky: čárkování, zakládání a zavírání prázdného lístku dělá každý
create policy tabs_select on public.tabs for select to anon, authenticated using (true);
create policy tabs_insert on public.tabs for insert to anon, authenticated with check (true);
create policy tabs_update on public.tabs for update to anon, authenticated using (true) with check (true);
create policy tabs_delete on public.tabs for delete to anon, authenticated using (true);

-- Síň slávy a suggestions (nastavení, platby, sud): jen čtení
create policy hall_select        on public.hall        for select to anon, authenticated using (true);
create policy suggestions_select on public.suggestions for select to anon, authenticated using (true);

-- Pojistka i na úrovni práv (kdyby někdo omylem přidal povolující politiku)
revoke insert, update, delete, truncate on public.hall, public.suggestions from anon, authenticated;
grant  select on public.tabs, public.hall, public.suggestions to anon, authenticated;
grant  insert, update, delete on public.tabs to anon, authenticated;

-- ---------------------------------------------------------------------
-- 5) Klient už nezakládá chybějící nastavení sám (nemá práva zápisu),
--    tak datum síně slávy doplníme tady – podle nejstarší platby.
-- ---------------------------------------------------------------------
do $$
declare v_first bigint;
begin
  if public._get_setting('__hall_since__') is null then
    select min((beer::jsonb ->> 'ts')::bigint) into v_first
      from public.suggestions where period = '__payment__' and left(beer, 1) = '{';
    perform public._set_setting('__hall_since__', coalesce(v_first, public._now_ms())::text);
  end if;
end $$;

commit;

-- =====================================================================
--  NASTAVENÍ / ZMĚNA HESLA
--  Nahraď NOVE_HESLO skutečným heslem a spusť. Funguje pro první nastavení
--  i pro pozdější změnu (i když staré heslo nikdo nezná).
--  Heslo se ukládá jen jako bcrypt hash, v aplikaci ani v Gitu není.
-- =====================================================================
-- insert into public.app_admin (id, pw_hash)
-- values (1, extensions.crypt('NOVE_HESLO', extensions.gen_salt('bf', 10)))
-- on conflict (id) do update set pw_hash = excluded.pw_hash, updated_at = now();
