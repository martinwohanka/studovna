-- =====================================================================
--  Studovna u Drobka · migrace na v1.38 – atomické čárkování
--  Spusť celé najednou v Supabase → SQL Editor (běží v jedné transakci).
--  Předpoklad: už proběhla migrace_v136.sql. Jde spustit opakovaně.
--
--  Co dělá:
--   1) čárka, odebrání čárky a „Zpět“ jako funkce v databázi – každá je
--      jeden zápis, takže se při souběžném čárkování nic neztratí
--   2) čas i cenu čárky určuje server (cena z nastavení v adminu)
--   3) „Zpět“ vrací jen čárku, kterou mínus opravdu odebral (jednorázový kód),
--      nejde si tak vyrobit čárku s vlastní cenou
--   4) RLS: anon už nesmí lístky přepisovat přímo – smí jen založit prázdný
--      lístek a smazat prázdný lístek. Cizí lístek s pivy nikdo nesmaže.
--
--  POZOR: stránky otevřené ve verzi v1.37 a starší po spuštění nezačárkují,
--  dokud je lidi neobnoví (nová v1.38 funguje před i po migraci).
-- =====================================================================

begin;

-- ---------------------------------------------------------------------
-- 1) Cena čárky podle nastavení (stejně jako v aplikaci)
-- ---------------------------------------------------------------------
create or replace function public._price_of(p_size text)
returns int
language plpgsql stable security definer
set search_path = public
as $$
declare
  v  int;
  vs int;
begin
  begin v := nullif(btrim(public._get_setting('__price__')), '')::int;
  exception when others then v := null; end;
  if v is null or v < 1 then v := 40; end if;
  if p_size = 'small' then
    begin vs := nullif(btrim(public._get_setting('__price_small__')), '')::int;
    exception when others then vs := null; end;
    if vs is null or vs < 1 then vs := round(v * 3.0 / 5)::int; end if;   -- 3/5 velkého
    return vs;
  end if;
  return v;
end $$;
revoke all on function public._price_of(text) from public, anon, authenticated;

-- Odebrané čárky pro „Zpět“ (jen pro funkce, API k nim nemá přístup)
create table if not exists public.tab_undo (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  mark       jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.tab_undo enable row level security;
revoke all on public.tab_undo from public, anon, authenticated;

-- ---------------------------------------------------------------------
-- 2) Čárka (+ velké / + malé)
-- ---------------------------------------------------------------------
create or replace function public.tab_mark(p_name text, p_size text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_mark jsonb;
  v_cnt  int;
begin
  if p_size is null or p_size not in ('large', 'small') then
    raise exception 'Neplatná velikost piva';
  end if;
  v_mark := jsonb_build_object('t', public._now_ms(), 'p', public._price_of(p_size), 's', p_size);
  -- Jeden UPDATE = atomické připojení na konec; souběžná čárka počká na zámek řádku
  update public.tabs
     set marks = coalesce(marks, '[]'::jsonb) || jsonb_build_array(v_mark),
         beers = jsonb_array_length(coalesce(marks, '[]'::jsonb)) + 1
   where name = p_name
     and jsonb_array_length(coalesce(marks, '[]'::jsonb)) < 500
  returning jsonb_array_length(marks) into v_cnt;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'gone');
  end if;
  return jsonb_build_object('ok', true, 'count', v_cnt, 'mark', v_mark);
end $$;

-- ---------------------------------------------------------------------
-- 3) Mínus: odebere poslední čárku, vrátí ji a jednorázový kód pro „Zpět“
-- ---------------------------------------------------------------------
create or replace function public.tab_unmark(p_name text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_m    jsonb;
  v_n    int;
  v_last jsonb;
  v_id   uuid;
begin
  select coalesce(marks, '[]'::jsonb) into v_m from public.tabs where name = p_name for update;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'gone');
  end if;
  v_n := jsonb_array_length(v_m);
  if v_n = 0 then
    return jsonb_build_object('ok', true, 'removed', null, 'count', 0);
  end if;
  v_last := v_m -> (v_n - 1);
  update public.tabs set marks = v_m - (v_n - 1), beers = v_n - 1 where name = p_name;

  delete from public.tab_undo where created_at < now() - interval '1 day';   -- úklid
  insert into public.tab_undo(name, mark) values (p_name, v_last) returning id into v_id;
  return jsonb_build_object('ok', true, 'removed', v_last, 'count', v_n - 1, 'undo', v_id);
end $$;

-- ---------------------------------------------------------------------
-- 4) „Zpět“: vrátí přesně tu čárku, kterou mínus odebral (kód platí 10 min)
-- ---------------------------------------------------------------------
create or replace function public.tab_restore(p_undo uuid)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_name text;
  v_mark jsonb;
  v_cnt  int;
begin
  delete from public.tab_undo
   where id = p_undo and created_at > now() - interval '10 minutes'
  returning name, mark into v_name, v_mark;
  if v_name is null then
    return jsonb_build_object('ok', false, 'reason', 'expired');
  end if;
  update public.tabs
     set marks = coalesce(marks, '[]'::jsonb) || jsonb_build_array(v_mark),
         beers = jsonb_array_length(coalesce(marks, '[]'::jsonb)) + 1
   where name = v_name
  returning jsonb_array_length(marks) into v_cnt;
  if not found then
    return jsonb_build_object('ok', false, 'reason', 'gone');
  end if;
  return jsonb_build_object('ok', true, 'count', v_cnt, 'name', v_name);
end $$;

grant execute on function public.tab_mark(text, text) to anon, authenticated;
grant execute on function public.tab_unmark(text)     to anon, authenticated;
grant execute on function public.tab_restore(uuid)    to anon, authenticated;

-- ---------------------------------------------------------------------
-- 5) RLS lístků: jen čtení, založení prázdného a smazání prázdného lístku.
--    Čárky mění výhradně funkce výše, placení pay_tab, slučování admin.
-- ---------------------------------------------------------------------
drop policy if exists tabs_insert on public.tabs;
drop policy if exists tabs_update on public.tabs;
drop policy if exists tabs_delete on public.tabs;

create policy tabs_insert on public.tabs for insert to anon, authenticated
  with check (length(btrim(name)) between 1 and 30
              and coalesce(jsonb_array_length(marks), 0) = 0
              and coalesce(beers, 0) = 0);
create policy tabs_delete on public.tabs for delete to anon, authenticated
  using (coalesce(jsonb_array_length(marks), 0) = 0);

revoke update on public.tabs from anon, authenticated;
grant  select, insert, delete on public.tabs to anon, authenticated;

commit;

-- Ať API (PostgREST) nové funkce zná hned, ne až po obnovení své mezipaměti
notify pgrst, 'reload schema';
