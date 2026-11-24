# Darkwave Sweep

![license](https://img.shields.io/badge/license-MIT-blue)
![artex](https://img.shields.io/badge/ARTEX-geb%C3%BCndelt%20%C2%B7%20AGPL--3.0-lightgrey)
![platform](https://img.shields.io/badge/Debian%2012%20%7C%20Ubuntu%2022.04%2B-informational)

**Masscan-getriebener Internet-Sweeper mit Web-Konsole, der nicht bei „verwundbar" aufhört: Fingerprint, CVE-Verifikation, Code-Execution, Root, versteckte Persistenz, Logs wischen, Loot.**

Darkwave überstreicht Adressbereiche, fingerprintet jeden offenen Port, gleicht PHP-Server gegen die PHP2Shell-CVEs ab, baut einen RCE-Kanal, eskaliert auf uid 0, legt einen versteckten Root-Account an, der Reboots übersteht, tarnt ihn mit immutable Dateien und Cron-Beacons, räumt die Spuren in den Ziel-Logs und exportiert alles als Loot. Das läuft von einem selbst gehosteten Panel auf einem einzigen Debian-/Ubuntu-Host. Dazu kommen ein Stalker-/IPTV-Modul und ein Artex-Agent-Panel.

Keine Keys, Tokens oder Passwörter im Code. Das Web-Passwort wird bei der Installation gewählt.

## Die Kette

| Stufe | Was passiert |
|---|---|
| Sweep | Zwei unabhängige masscan-Lanes, Ports/Ranges/Rate aus dem UI, Ziele dedupliziert |
| Fingerprint | Server-Header, PHP-Version, Framework- und Appliance-Erkennung je Treffer |
| CVE-Abgleich | PHP2Shell (`CVE-2026-109618`, `CVE-2026-109619`) gegen die erkannte Versionsspanne |
| Verify | Wiederholbarer Beweislauf, `CONFIRMED` nur bei stabilem Output, versionstolerant |
| Ausführen | RCE-Kanal über den PHP2Shell-Multipart-/OOM-Bug, dazu 30 Appliance- und Framework-Vektoren |
| Deploy | Passwortgeschützter PHP-Drop, in ein web-beschreibbares Verzeichnis geschrieben und per HTTP geprüft |
| Eskalation | root: PwnKit, `sudo -u#-1`, schreibbares `/etc/passwd`, `sudoers.d`-Drop, Docker-Socket |
| Provisionierung | Versteckter uid-0-Account, SSH-Key, NOPASSWD-Regel, Cron-Keepalive, Reboot-Überleben |
| Persistenz | Beacon (öffentliche IP, Hostname, Interfaces) alle 10 Minuten ans Dashboard |
| Tarnung | PHP-Härtung, Webshell entfernen, Ziel-Logs wischen, Journal vacuum |
| Loot | Strukturierter Satz je übernommenem Host (SSH-Zugang, Passwort, OS, CPU, RAM, Disk, GPU, Keys) |

Scannen, Verifizieren und Ausnutzen sind getrennte Profile — recon-only, verify-only oder die volle Kette.

## Erkennung und Vektoren

Offene Ports kommen von masscan. Jeder Treffer wird klassifiziert: Web-Stack und PHP-Build, SSH, Telnet, Appliance-Familien. Zum Vektorsatz gehören:

- **Web / PHP** PHP2Shell (`CVE-2026-109618`, `CVE-2026-109619`), Apache `mod_cgi` (Shellshock), PHPUnit eval-stdin, Drupal, WordPress File Manager, Solr, Webmin, Spring Cloud Gateway, Jenkins, Confluence
- **Edge / Netzwerk** Citrix (`CVE-2019-19781`), PAN-OS (`CVE-2024-3400`), Ivanti (`CVE-2023-46805`, `CVE-2024-21887`), Fortinet, MikroTik, TP-Link, Drucker
- **Infrastruktur** Docker API, Redis, etcd, kubelet, RabbitMQ, vCenter
- **Java** Log4Shell (`CVE-2021-44228`) über den eingebauten LDAP-Catcher
- **Zugang** SSH-Key-Auth, SSH-Brute mit kleiner kuratierter Liste, Telnet-Werkslogins
- **Windows** WinRM-/SMB-Pfade, wo erreichbar

Vektoren mit Callback nutzen das Dashboard als Jump-Host (`/x/<token>`), keine Zusatzinfrastruktur nötig.

## Root-Eskalation

Sobald Code-Execution existiert, läuft die Eskalation der Reihe nach und stoppt beim ersten Erfolg:

1. bereits root oder `NOPASSWD`-sudo → fertig
2. `sudo -n -u#-1` (uid-Wrap in alten sudo-Builds)
3. **PwnKit** (`CVE-2021-4034`), wenn `pkexec` vorhanden ist
4. schreibbares `/etc/passwd` → uid-0-Account anhängen
5. schreibbares `/etc/sudoers.d` → Regel droppen
6. lesbares `docker.sock` → Alpine-Container mit `/:/host`-Bind

Jeder Pfad wird mit `id` bewiesen, nichts geraten.

## Was auf dem Ziel bleibt

Provisionierung läuft nur mit root oder sudo und wird vor der Meldung verifiziert. Alle Namen sind zufällig, beginnen mit `systemd-`, Pfade sind Dotfiles:

- **versteckter Root-Account** `systemd-xxxx` mit uid **0**, Home `/var/lib/.systemd-xxxx`, `useradd -o -u 0`, dazu ein 28-Hex-Passwort
- **SSH-Key** `dw.pub` in `~/.ssh/authorized_keys`, 700/600, Home auf 0:0
- **NOPASSWD-sudoers** `/etc/sudoers.d/.systemd-xxxx`, Modus 440
- **Cron** `@reboot` und `*/17 * * * *` legen den Account aus einem base64-Helfer unter `/usr/local/sbin/.systemd-xxxx-upd` neu an, per `chattr +i` **immutable**
- **Beacon** `~/.ipbeacon`, alle 10 Minuten öffentliche IP, Hostname und Interfaces ans Dashboard
- **Fallback** ohne `useradd`: Root-`authorized_keys`-Eintrag und neues Root-Passwort, per SSH-Login geprüft

Jeder Datensatz trägt den exakten SSH-Befehl und das Passwort.

## Anti-Forensik

Mit `wipe_logs` werden die Spuren nach der Provisionierung beseitigt:

- Apache-/httpd- und nginx-Access-/Error-Logs auf null
- `auth.log`, `secure`, `syslog`, `messages`, `daemon.log`, `kern.log`, `cron`, `maillog` leeren
- `wtmp`, `btmp`, `lastlog` löschen (`last`, `who`, `lastlog` bleiben leer)
- `journalctl --rotate` und `--vacuum-time=1s`
- frische PHP-`sess_*` unter `/tmp` entfernen
- `history -c`

Webshell-Drops werden wieder entfernt (`cleanup`), das PHP2Shell-Loch geschlossen (`patch`: `session.upload_progress.enabled=Off`, `memory_limit=256M` über `/etc/php/.w.ini`), danach wird die CVE erneut geprüft, um den Fix zu bestätigen.

## Loot und Audit

`loot/loot.jsonl` (maschinenlesbar) und `loot/loot.txt` (Bediener-Layout) je Host: Zeitstempel, IP, Port, SSH-Befehl, User, Passwort, Art, PHP-Version, OS, Virtualisierung, CPU, Kerne, RAM, Disk, GPU, gefundene API-Keys mit Live-Prüfung (Hugging Face, OpenAI, Anthropic, GitHub), Beacon-Token, Patch- und Log-Status. `loot/audit.jsonl` protokolliert jede Aktion pro Host.

## Stalker-/IPTV-Modul

Portal-Liste mit Status und Notizen, MAC-Import (`mac|serial|sn|sncut|dev1|dev2|expire`), Handshake und Bouquet-Liste, Gültigkeit und Ablauf, DE-Kategorie-Kennzeichnung, Browser-Player (MPEG-TS über mpegts.js, HLS über hls.js), TXT-Export je Portal und klare Behandlung von `456` / `512` / `459`.

## Dashboard

Live-Zähler, Audit-Ansicht pro Host, Loot-Feed, Portal-Editor, Config-Leiste (Modus stalker/voll, Ranges mit `100-130`-Syntax, Port-Presets, Rate, Worker, Exploit-/Patch-/Wipe-Schalter), optionaler Export an Artex.

## Artex

[ARTEX](https://github.com/BaaRai/ARTEX) liegt als gepinnter Quellstand bei (`vendor/`, Prüfsumme verifiziert, Commit in `vendor/ARTEX-VERSION.txt`), wird lokal gebaut und als zweites Panel auf Port 8787 gestartet. Gefundene Hosts gehen über `/opt/artex/feed.txt` über. Bei der Installation wird das Setup-Token für die `/setup`-Seite ausgegeben.

## Voraussetzungen

- Debian 12 oder Ubuntu 22.04+, root, öffentliche IPv4, Ports 9090 (UI) und 8787 (Artex) erreichbar
- 2 GB RAM, 20 GB Platte mit mindestens 8 GB frei (das Artex-Image ist groß)
- Docker samt `buildx` wird vom Installer eingerichtet; auf Debian 12 ggf. bookworm-backports aktivieren, falls `docker-buildx` fehlt
- masscan braucht die eigene NIC/IP; reine NAT-Setups sehen falsche Quellen

## Installation

```bash
unzip darkwave-sweep.zip && cd darkwave-sweep
sudo ./installer.sh
```

Der Installer fragt das Web-Passwort (min. 8 Zeichen), installiert Pakete, baut ein venv, legt systemd-Units an, startet das UI und baut das gebündelte Artex.

- UI `http://SERVER:9090`, Artex `http://SERVER:8787` (Admin-Passwort auf `/setup`)
- Passwortdatei `/root/darkwave-web-password.txt`
- Scan startet gestoppt: `systemctl start dwsweep dwsweep2`

## Erste Schritte

1. Einloggen, Leiste oben: Modus, Ranges, Port-Preset, Rate/Worker, anwenden
2. Feed beobachten; `owned`-Einträge tragen SSH-Zugang und Loot
3. Artex: Admin-Passwort per Setup-Token setzen, Feed-Datei importieren
4. Stalker: Portal- und MAC-Zeilen einfügen, prüfen, abspielen, exportieren

## Betrieb

- 2500 pps / 40 Worker sind ein ruhiger Default; erhöhen nur, solange die Kiste erreichbar bleibt
- masscan-Bursts können SSH aushungern — Rate über die Konsole senken, nicht per Reboot
- `456` = MAC bekannt, kein Stream-Recht, `512` = unbekannt/gesperrt, `459` = Token abgelehnt
- PHP-FPM und CLI-only-Hosts verhalten sich unterschiedlich; das Tool meldet, was es wirklich bekam

## Rückbau auf einem Ziel

```bash
chattr -i /usr/local/sbin/.systemd-xxxx-upd
crontab -l | grep -v systemd-xxxx | crontab -
userdel -r systemd-xxxx
rm -f /etc/sudoers.d/.systemd-xxxx
```

## Rechtliches

Keine Autorisierung inklusive. Nur Bereiche scannen, die erlaubt sind; Provisionierung und Log-Wischen verändern das Ziel.

## Struktur

```
installer.sh          Setup (Passwort, Dienste, gebündeltes Artex)
vendor/               gepinnter ARTEX-Quellstand, Lizenz, Version
dwsweep/dwscan/       Engine: Vektoren, Privesc, Persist, Stealth, Loot, Stalker
dwsweep/run_sweep.py  Lane-Runner
dwsweep/dash/         Flask-UI und Player
dwsweep/profiles/     sweep, recon, verify, full
```

## Lizenzen

Unser Code ist MIT (siehe `LICENSE`). Der ARTEX-Stand unter `vendor/` ist AGPL-3.0 und wird unverändert mitgeliefert (siehe `vendor/ARTEX-LICENSE`); wer ARTEX patcht und den Dienst öffentlich erreichbar macht, muss den geänderten Quelltext veröffentlichen. masscan und sqlmap sind AGPL-3.0- bzw. GPL-2.0-Tools, die als Binary aufgerufen werden. Details in `NOTICE`. Keine Gewähr.
