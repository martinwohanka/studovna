# Studovna u Drobka

Jednostránková webová appka (hlasování o pivu, rozpitá piva, síň slávy, sud, platby přes QR) — statický `index.html` napojený na Supabase.

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
