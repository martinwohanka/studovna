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
--   5) síň slávy eviduje i počty kusů (velká / malá), sloučení jmen,
--      samostatná cena malého piva, Realtime pro automatickou obnovu
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

-- Síň slávy si nově pamatuje i počty kusů. Při prvním spuštění je dopočítáme
-- z plateb od poslední obnovy síně slávy; přepočet na piva (beers) zůstává
-- beze změny a počty se k němu dorovnají (malé = 0,6 velkého).
do $$
declare v_since bigint;
begin
  if not exists (select 1 from information_schema.columns
                 where table_schema='public' and table_name='hall' and column_name='large') then
    alter table public.hall add column large int not null default 0,
                            add column small int not null default 0;
    select nullif(beer, '')::bigint into v_since from public.suggestions where period = '__hall_since__' limit 1;
    with p as (
      select beer::jsonb j from public.suggestions
       where period = '__payment__' and left(beer, 1) = '{'
    ), agg as (
      select j ->> 'name' as name,
             sum(coalesce((j ->> 'small')::int, 0)) as sm
        from p
       where coalesce((j ->> 'ts')::bigint, 0) >= coalesce(v_since, 0)
       group by 1
    )
    update public.hall h
       set small = least(coalesce(a.sm, 0), floor(coalesce(h.beers, 0)::numeric / 0.6)::int)
      from (select h2.name, a2.sm from public.hall h2 left join agg a2 on a2.name = h2.name) a
     where a.name = h.name;
    update public.hall
       set large = greatest(0, round(coalesce(beers, 0)::numeric - 0.6 * small))::int;
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
-- p_beers = přepočet na velká piva, p_large / p_small = počty kusů.
drop function if exists public._hall_add(text, numeric, numeric);
create or replace function public._hall_add(p_name text, p_beers numeric, p_paid numeric,
                                            p_large int, p_small int)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  if p_name is null or p_name = '' then return; end if;
  insert into public.hall(name, beers, paid, large, small)
  values (p_name, greatest(0, round(p_beers, 1)), greatest(0, round(p_paid)),
          greatest(0, p_large), greatest(0, p_small))
  on conflict (name) do update
    set beers = greatest(0, round((coalesce(public.hall.beers, 0)::numeric + p_beers), 1)),
        paid  = greatest(0, round(coalesce(public.hall.paid, 0)::numeric + p_paid)),
        large = greatest(0, coalesce(public.hall.large, 0) + p_large),
        small = greatest(0, coalesce(public.hall.small, 0) + p_small);
  delete from public.hall
   where name = p_name and coalesce(beers, 0) = 0 and coalesce(paid, 0) = 0
     and coalesce(large, 0) = 0 and coalesce(small, 0) = 0;
end $$;

-- Pomocné funkce nejsou pro API
revoke all on function public._admin_ok(text)                      from public, anon, authenticated;
revoke all on function public._admin_require(text)                 from public, anon, authenticated;
revoke all on function public._set_setting(text, text)             from public, anon, authenticated;
revoke all on function public._get_setting(text)                   from public, anon, authenticated;
revoke all on function public._hall_add(text, numeric, numeric, int, int) from public, anon, authenticated;

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

-- Cena velkého a malého piva (malé null = odvozené 3/5 z velkého, jako dřív)
drop function if exists public.admin_set_price(text, int);
create or replace function public.admin_set_price(p_pw text, p_price int, p_small int default null)
returns void
language plpgsql security definer
set search_path = public
as $$
begin
  perform public._admin_require(p_pw);
  if p_price is null or p_price < 1 or p_price > 9999 then
    raise exception 'Neplatná cena piva';
  end if;
  if p_small is not null and (p_small < 1 or p_small > 9999) then
    raise exception 'Neplatná cena malého piva';
  end if;
  perform public._set_setting('__price__', p_price::text);
  perform public._set_setting('__price_small__', p_small::text);
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

-- Sud: p_new = true → nový sud (starý se zapíše do historie),
--      p_new = false → oprava údajů stávajícího sudu.
-- p_ts = čas naražení v ms; null = teď (nový sud) / beze změny (oprava).
-- p_log je JSON se souhrnem končícího sudu (počítá ho klient).
drop function if exists public.admin_save_keg(text, text, numeric, boolean, text);
create or replace function public.admin_save_keg(p_pw text, p_name text, p_liters numeric,
                                                 p_new boolean, p_log text default null,
                                                 p_ts bigint default null)
returns bigint
language plpgsql security definer
set search_path = public
as $$
declare
  v_ts     bigint;
  v_old    text;
  v_old_ts bigint;
begin
  perform public._admin_require(p_pw);
  p_name := btrim(coalesce(p_name, ''));
  if p_name = '' or length(p_name) > 60 then
    raise exception 'Neplatný název piva';
  end if;
  if p_liters is null or p_liters <= 0 or p_liters > 1000 then
    raise exception 'Neplatný objem sudu';
  end if;

  if p_ts is not null and (p_ts <= 0 or p_ts > public._now_ms() + 300000) then
    raise exception 'Čas naražení nesmí být v budoucnosti';
  end if;

  v_old := public._get_setting('__keg__');
  if v_old is not null then
    if left(btrim(v_old), 1) = '{' then
      v_old_ts := (v_old::jsonb ->> 'ts')::bigint;
    else
      v_old_ts := btrim(v_old)::bigint;             -- starší formát: jen timestamp
    end if;
  end if;

  if p_new then
    v_ts := coalesce(p_ts, public._now_ms());
    if v_old_ts is not null and v_ts < v_old_ts then
      raise exception 'Nový sud nemůže být naražen dřív než ten předchozí';
    end if;
    if p_log is not null then
      perform p_log::jsonb;                        -- jen validace
      insert into public.suggestions(period, beer) values ('__keg_log__', p_log);
    end if;
  else
    if v_old_ts is null then
      raise exception 'Sud zatím není naražený';
    end if;
    v_ts := coalesce(p_ts, v_old_ts);
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
  v_small int;
  v_large int;
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
      v_small := coalesce((v_rec ->> 'small')::int, 0);
      v_large := coalesce((v_rec ->> 'large')::int, (v_rec ->> 'beers')::int - v_small, 0);
      perform public._hall_add(v_rec ->> 'name', -v_eq, -coalesce((v_rec ->> 'amount')::numeric, 0),
                               -v_large, -v_small);
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

  perform public._hall_add(p_name, v_eq, p_amount, v_c - v_small, v_small);

  if jsonb_array_length(v_left) > 0 then
    update public.tabs set marks = v_left, beers = jsonb_array_length(v_left) where name = p_name;
  else
    delete from public.tabs where name = p_name;
  end if;
  return jsonb_build_object('ok', true, 'left', jsonb_array_length(v_left));
end $$;

-- ---------------------------------------------------------------------
-- Sloučení jmen: všechno od p_from převede na p_to (platby, síň slávy,
-- otevřený lístek). Hodí se na „Lukas“ vs. „Lukáš“.
-- ---------------------------------------------------------------------
create or replace function public.admin_merge_names(p_pw text, p_from text, p_to text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_pay  int := 0;
  v_hall boolean := false;
  v_tab  text := 'none';
  h      record;
  v_fm   jsonb;
  v_tm   jsonb;
begin
  perform public._admin_require(p_pw);
  p_from := btrim(coalesce(p_from, ''));
  p_to   := btrim(coalesce(p_to, ''));
  if p_from = '' or p_to = '' or length(p_to) > 30 then
    raise exception 'Vyplň obě jména (cílové max. 30 znaků)';
  end if;
  if p_from = p_to then
    raise exception 'Zdroj a cíl jsou stejné jméno';
  end if;

  -- platby: sloupec name i jméno uvnitř JSON záznamu
  update public.suggestions
     set name = p_to,
         beer = case when left(beer, 1) = '{'
                     then jsonb_set(beer::jsonb, '{name}', to_jsonb(p_to))::text else beer end
   where period = '__payment__'
     and (name = p_from or (left(beer, 1) = '{' and beer::jsonb ->> 'name' = p_from));
  get diagnostics v_pay = row_count;

  -- síň slávy: přičíst k cíli, zdroj smazat
  select * into h from public.hall where name = p_from for update;
  if found then
    perform public._hall_add(p_to, coalesce(h.beers, 0)::numeric, coalesce(h.paid, 0)::numeric,
                             coalesce(h.large, 0), coalesce(h.small, 0));
    delete from public.hall where name = p_from;
    v_hall := true;
  end if;

  -- otevřený lístek: přejmenovat, nebo spojit čárky podle času
  select marks into v_fm from public.tabs where name = p_from for update;
  if found then
    select marks into v_tm from public.tabs where name = p_to for update;
    if found then
      select coalesce(jsonb_agg(e order by coalesce((e ->> 't')::bigint, 0)), '[]'::jsonb) into v_tm
        from jsonb_array_elements(coalesce(v_tm, '[]'::jsonb) || coalesce(v_fm, '[]'::jsonb)) e;
      update public.tabs set marks = v_tm, beers = jsonb_array_length(v_tm) where name = p_to;
      delete from public.tabs where name = p_from;
      v_tab := 'merged';
    else
      update public.tabs set name = p_to where name = p_from;
      v_tab := 'renamed';
    end if;
  end if;

  return jsonb_build_object('payments', v_pay, 'hall', v_hall, 'tab', v_tab);
end $$;

grant execute on function public.admin_login(text)                                    to anon, authenticated;
grant execute on function public.admin_change_password(text, text)                    to anon, authenticated;
grant execute on function public.admin_set_price(text, int, int)                      to anon, authenticated;
grant execute on function public.admin_merge_names(text, text, text)                  to anon, authenticated;
grant execute on function public.admin_set_session(text, text)                        to anon, authenticated;
grant execute on function public.admin_save_keg(text, text, numeric, boolean, text, bigint) to anon, authenticated;
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

-- ---------------------------------------------------------------------
-- 6) Realtime: změny v lístcích, síni slávy a nastavení se hned propíšou
--    na všechna otevřená zařízení (RLS platí i tady – čte se jen SELECT).
-- ---------------------------------------------------------------------
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['tabs', 'hall', 'suggestions'] loop
      if not exists (select 1 from pg_publication_tables
                      where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
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
