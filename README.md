# Darkwave Sweep

Self-hosted recon/scan console with web UI: masscan → fingerprint → CVE check → optional exploit/deploy, plus an IPTV/Stalker portal module with playback and text export. Artex (autonomous pentest agent) is installed as a second panel on the same host.

**ARTEX source is bundled and pinned** to commit `3cb06383fd99ffe7686abe1d375de11da7cfad54` (2026-11-24). The installer verifies the included archive checksum and builds from that snapshot; it does not clone the live repository. See `vendor/ARTEX-VERSION.txt`. Docker still needs access to image and package registries during the build.

**Everything runs on one Debian/Ubuntu server. No API keys or passwords are baked in; the web password is set during install.**

## What it does

- Two independent masscan lanes (separate state dirs), rate/worker/ports/ranges configurable from the UI bar.
- Modes: *stalker only* (portal detection + metadata, no shell attempts) or *full* (CVE vectors, verify, exploit, deploy).
- Per-host audit (`loot/audit.jsonl`), loot feed, dashboard with live counters.
- Stalker module: portal import, MAC list import (`mac|serial|sn|sncut|dev1|dev2|expire`), validity/expiry/DE-category detection, per-portal TXT export in the console's own layout, web player with MPEG-TS/HLS playback.
- Optional extras: SSH brute force, log4shell LDAP catcher, sqlmap feeder, Artex feed (`/opt/artex/feed.txt`).

## Requirements

- Debian 12 or Ubuntu 22.04+ (root), public IPv4, ports 9090 (UI) and 8787 (Artex) reachable.
- 2 GB RAM, 20 GB disk with at least 8 GB free (the Artex image is large). masscan needs the host's own NIC/IP; do not run behind NAT-only.
- Docker with the `buildx` plugin is installed by the installer (Artex needs it plus a Postgres container). On Debian 12 enable bookworm-backports if `docker-buildx` is not found.

## Install

```bash
unzip darkwave-sweep.zip && cd darkwave-sweep
sudo ./installer.sh
```

The script asks for the web UI password (min. 8 chars), installs packages, builds the Python venv, registers systemd units, starts the UI and installs the bundled ARTEX snapshot.

- UI: `http://SERVER:9090`
- Artex: `http://SERVER:8787` – create the admin password on `/setup`, the setup token is printed at the end of the install (also `docker logs artex-artex-1 | grep "Setup token"`).
- Password file: `/root/darkwave-web-password.txt`

Scanning starts stopped: `systemctl start dwsweep dwsweep2`.

## First run

1. Log in, top bar: pick **mode** (`stalker`), ranges (`13,23,34` or `100-130`), ports preset, rate/workers, Apply.
2. *Stalker* tab: paste a portal (`http://host/c`), add MAC lines, `PRÜFEN`. Hits appear grouped by portal with expiry, SN/DEV and German-category flag; click a MAC for the player.
3. Artex: `Setup` token, then add the same targets; `feed_push.sh` collects discovered hosts to `/opt/artex/feed.txt`.

## Notes

- Stalker answers: `512` = MAC unknown/blocked, `456` = MAC known but no stream right, `459` = token rejected. Lists without streams are normal for shared/test MACs.
- masscan at high pps can make the box unresponsive over SSH; lower `rate`/`workers` if that happens.
- Scans are unauthorized by default – only scan ranges you are allowed to.

## Licenses

Our code is MIT (see `LICENSE`). The ARTEX snapshot under `vendor/` is AGPL-3.0 and shipped unmodified (see `vendor/ARTEX-LICENSE`); if you patch ARTEX and expose it to users over the network, publish your modified source. masscan and sqlmap are AGPL-3.0 / GPL-2.0 tools invoked as binaries. Full details in `NOTICE`.

## Layout

```
installer.sh         setup (asks password, installs services + Artex)
dwsweep/dwscan/      scanner engine (masscan parsing, vectors, stalker, loot)
dwsweep/run_sweep.py lane runner
dwsweep/dash/        Flask UI (dashboard, stalker, player)
dwsweep/profiles/    scan profiles
dwsweep/artex_up.sh  Artex installation (GitHub clone + compose)
```

German version: `README.de.md`. No warranty, no license file included.
