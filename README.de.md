# Darkwave Sweep

Selbst gehostete Recon-/Scan-Konsole mit Web-UI: masscan → Fingerprint → CVE-Check → optional Exploit/Deploy, dazu ein IPTV-/Stalker-Modul mit Wiedergabe und Text-Export. Artex (autonomer Pentest-Agent) wird als zweites Panel auf demselben Host installiert.

**Der ARTEX-Quellstand ist eingebettet und festgelegt** auf Commit `3cb06383fd99ffe7686abe1d375de11da7cfad54` vom 24.11.2026. Der Installer prüft die Prüfsumme und baut diesen Snapshot; er klont das Live-Repository nicht erneut. Details stehen in `vendor/ARTEX-VERSION.txt`. Docker benötigt für den Build weiterhin Zugriff auf Image- und Paket-Registries.

**Alles läuft auf einem Debian-/Ubuntu-Server. Keine Keys oder Passwörter im Code – das Web-Passwort wird bei der Installation gesetzt.**

## Funktionen

- Zwei unabhängige masscan-Lanes (getrennte Status-Ordner), Rate/Worker/Ports/Ranges über die Leiste im UI.
- Modi: *nur Stalker* (Portal-Erkennung + Metadaten, keine Shell-Versuche) oder *voll* (CVE-Vektoren, Verify, Exploit, Deploy).
- Audit pro Host (`loot/audit.jsonl`), Loot-Feed, Dashboard mit Live-Zählern.
- Stalker-Modul: Portal-Import, MAC-Listen (`mac|serial|sn|sncut|dev1|dev2|expire`), Prüfung auf Gültigkeit/Ablauf/DE-Kategorien, TXT-Export je Portal im eigenen Konsolen-Layout, Webplayer mit MPEG-TS/HLS.
- Optional: SSH-Brute, log4shell-LDAP-Catcher, sqlmap-Feeder, Artex-Feed (`/opt/artex/feed.txt`).

## Voraussetzungen

- Debian 12 oder Ubuntu 22.04+ (root), öffentliche IPv4, Ports 9090 (UI) und 8787 (Artex) erreichbar.
- 2 GB RAM, 20 GB Platte mit mindestens 8 GB frei (das Artex-Image ist groß). masscan braucht die eigene NIC/IP – kein reines NAT.
- Docker samt `buildx`-Plugin wird vom Installer eingerichtet (Artex braucht beides, dazu Postgres im Container). Auf Debian 12 ggf. bookworm-backports aktivieren, falls `docker-buildx` fehlt.

## Installation

```bash
unzip darkwave-sweep.zip && cd darkwave-sweep
sudo ./installer.sh
```

Das Skript fragt das Web-Passwort ab (min. 8 Zeichen), installiert Pakete, baut das Python-venv, legt systemd-Units an, startet das UI und installiert den eingebetteten ARTEX-Snapshot.

- UI: `http://SERVER:9090`
- Artex: `http://SERVER:8787` – Admin-Passwort auf `/setup` setzen, Token steht am Ende der Installation (auch `docker logs artex-artex-1 | grep "Setup token"`).
- Passwortdatei: `/root/darkwave-web-password.txt`

Der Scan startet gestoppt: `systemctl start dwsweep dwsweep2`.

## Erste Schritte

1. Einloggen, Leiste oben: **Modus** (`stalker`), Ranges (`13,23,34` oder `100-130`), Port-Preset, Rate/Worker, Anwenden.
2. Reiter *Stalker*: Portal eintragen (`http://host/c`), MAC-Zeilen einfügen, `PRÜFEN`. Treffer erscheinen je Portal mit Ablauf, SN/DEV und DE-Kennung; Klick auf MAC öffnet den Player.
3. Artex: Setup-Token, Ziele ergänzen; `feed_push.sh` sammelt gefundene Hosts nach `/opt/artex/feed.txt`.

## Hinweise

- Stalker-Antworten: `512` = MAC unbekannt/gesperrt, `456` = MAC bekannt, aber kein Stream-Recht, `459` = Token abgelehnt. Listen ohne Streams sind bei geteilten/Test-MACs normal.
- masscan mit hoher pps kann den SSH-Zugang blockieren; dann `rate`/`workers` senken.
- Scans sind standardmäßig nicht autorisiert – nur erlaubte Ranges scannen.

## Lizenzen

Unser Code ist MIT (siehe `LICENSE`). Der ARTEX-Stand unter `vendor/` ist AGPL-3.0 und wird unverändert mitgeliefert (siehe `vendor/ARTEX-LICENSE`); wer ARTEX patcht und den Dienst öffentlich erreichbar macht, muss den geänderten Quelltext veröffentlichen. masscan und sqlmap sind AGPL-3.0- bzw. GPL-2.0-Tools, die als Binary aufgerufen werden. Details in `NOTICE`.

## Struktur

```
installer.sh         Setup (fragt Passwort, richtet Dienste + Artex ein)
dwsweep/dwscan/      Scan-Engine (masscan-Auswertung, Vektoren, Stalker, Loot)
dwsweep/run_sweep.py Lane-Runner
dwsweep/dash/        Flask-UI (Dashboard, Stalker, Player)
dwsweep/profiles/    Scan-Profile
dwsweep/artex_up.sh  Artex-Installation (GitHub-Klon + Compose)
```

Englische Fassung: `README.md`. Keine Gewähr, keine Lizenzdatei enthalten.
