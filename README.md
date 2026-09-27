# Studovna u Drobka

Jednostránková webová appka (rozpitá piva, síň slávy, sud, platby přes QR) — statický `index.html` napojený na Supabase.

## Verze

Číslo verze je v `index.html` v konstantě `APP_VERSION_CODE` (např. `"v1.36"`). **Při vydání změny ji zvyš ručně** – deploy si ji odtud přečte do `changelog.json` a patička i okno „Co je nového“ ji ukážou. Commity bez změny verze se v seznamu změn zařadí k nejbližší novější verzi. Česká znění položek seznamu změn jdou přepsat v `changelog-cs.json` (klíčem je krátký hash commitu).

## Databáze (Supabase)

Schéma, funkce a oprávnění jsou v SQL migracích – spouští se ručně v Supabase → SQL Editor, **v tomto pořadí**: `migrace_v136.sql` (heslo, admin funkce, RLS), `migrace_v138.sql` (atomické čárkování). Když spouštíš znovu v136, pusť po ní i v138, jinak zůstane povolený přímý zápis do lístků. Na web se SQL soubory nenahrávají. Heslo administrace je v databázi jen jako bcrypt hash; nastavení/změna hesla je popsaná na konci téhož souboru. Všechny admin operace jdou přes RPC funkce, které heslo ověřují; anon klíč smí jen číst a čárkovat.

## Automatický deploy na FTP

Při každém pushi do větve `main` se soubory automaticky nahrají na FTP server pomocí GitHub Actions (`.github/workflows/ftp-deploy.yml`).

Než to poběží, je potřeba v repozitáři nastavit **Settings → Secrets and variables → Actions → New repository secret**:

| Secret            | Popis                                              | Povinné |
|-------------------|-----------------------------------------------------|---------|
| `FTP_SERVER`      | Adresa FTP serveru, např. `ftp.example.cz`          | ano     |
| `FTP_USERNAME`    | Přihlašovací jméno na FTP                           | ano     |
| `FTP_PASSWORD`    | Heslo na FTP                                        | ano     |
| `FTP_SERVER_DIR`  | Cílová složka na serveru, např. `/www/` (výchozí `/`) | ne      |

Po nastavení secretů stačí pushnout změnu do `main` (nebo spustit workflow ručně přes záložku **Actions → Deploy na FTP → Run workflow**) a stránka se nahraje na server.
